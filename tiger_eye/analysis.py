"""LLM-based threat analysis pipeline.

Orchestrates: RAG retrieval -> NVD context -> LLM analysis -> normalisation -> persist.
"""

import asyncio
import json
import logging
import re
import time
import uuid
from datetime import UTC, datetime

from langchain_openai import ChatOpenAI
from sqlalchemy import text as sql_text

from tiger_eye.config import get_settings
from tiger_eye.database import (
    AnalysisEmbedding,
    AnalysisEntry,
    ArchiveEntry,
    get_db,
)
from tiger_eye.embedding import build_embedding_text, generate_embedding
from tiger_eye.metrics import (
    ENTRIES_FAILED,
    ENTRIES_SKIPPED,
    LLM_LATENCY,
    LLM_RETRIES,
)
from tiger_eye.rag import get_similar_analyses
from tiger_eye.tracing import get_tracer

log = logging.getLogger(__name__)
tracer = get_tracer()

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")

# Retry config for transient LLM failures
_LLM_MAX_RETRIES = 2
_LLM_RETRY_BASE_DELAY = 2.0

VALID_THREAT_TYPES = {
    "VULNERABILITY",
    "MALWARE",
    "APT_CAMPAIGN",
    "DATA_BREACH",
    "DDOS",
    "RANSOMWARE",
    "SUPPLY_CHAIN",
    "POLICY",
    "INFORMATIONAL",
    "OTHER",
}

VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"}

ANALYSIS_PROMPT = """You are a senior threat intelligence analyst. Analyse the following
OSINT feed entry and produce a structured threat assessment.

IMPORTANT — grounding rules:
- Only extract indicators, actors, TTPs, and CVEs that are EXPLICITLY mentioned
  or strongly implied by the text. Do NOT infer, speculate, or fabricate any of these.
- If the entry is not a threat report (e.g. product news, opinion piece, job posting,
  conference talk), set threat_type to INFORMATIONAL, severity_level to INFORMATIONAL,
  confidence to a low value, and leave array fields empty.

{retrieved_context}

{nvd_context}

== Feed Entry ==
Title: {title}
Link: {link}
Published: {published}
Author: {author}
Feed: {feed_title}
Categories: {categories}

Content:
{content}

Summary:
{summary}

== Instructions ==
Produce a JSON object with exactly these fields:

- threat_type: one of VULNERABILITY, MALWARE, APT_CAMPAIGN, DATA_BREACH, DDOS,
  RANSOMWARE, SUPPLY_CHAIN, POLICY, INFORMATIONAL, OTHER
- severity_level: one of CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
- confidence: integer 0-100 — how confident are you that this entry represents
  a real, actionable threat to enterprise networks? Low-signal or non-threat
  entries should score below 30.
- summary_impact: 2-3 sentence summary of the threat and its potential impact
- relevance: enterprise/organisational relevance assessment
- historical_context: links to known campaigns or historical patterns (only if
  explicitly referenced in the text — do not fabricate)
- additional_notes: anything else noteworthy (leave empty string if nothing)
- key_iocs: array of objects, each with "type" and "value" fields.
  type must be one of: ipv4, ipv6, domain, url, hash_md5, hash_sha1,
  hash_sha256, email, filename. Example: [{{"type": "domain", "value": "evil.com"}}]
  Only include IOCs explicitly present in the text.
- recommended_actions: array of recommended response actions AND mitigation steps
- affected_systems_sectors: array of affected systems/sectors
- potential_threat_actors: array of attributed or suspected actors (only those
  named or clearly implied in the text)
- cve_references: array of CVE IDs mentioned (e.g. "CVE-2024-1234"). Include
  any exploit advisory URLs as separate entries in this array.
- ttps: array of MITRE ATT&CK techniques as objects with "id" and "name" fields.
  Example: [{{"id": "T1566.001", "name": "Spearphishing Attachment"}}]
  If you can identify the technique but not the exact ID, use "name" only.
- tools_used: array of tools/frameworks mentioned (Cobalt Strike, Mimikatz, etc)
- malware_families: array of malware families mentioned (Emotet, LockBit, etc)
- target_geographies: array of targeted countries/regions

Return ONLY valid JSON. No markdown, no explanation."""


def _build_llm() -> ChatOpenAI:
    return ChatOpenAI(
        model="gpt-5.4-mini",
        temperature=0.0,
        api_key=get_settings().openai_api_key,
        model_kwargs={"response_format": {"type": "json_object"}},
    )


async def lookup_cve_context(text: str) -> str:
    """Extract CVE IDs from text and fetch CVSS/EPSS scores from cve_enriched."""
    cve_ids = list(set(CVE_PATTERN.findall(text or "")))
    if not cve_ids:
        return ""

    async with get_db() as db:
        result = await db.execute(
            sql_text("""
                SELECT cve_id, cvss_base, epss
                FROM cve_enriched
                WHERE cve_id = ANY(:ids)
            """),
            {"ids": cve_ids},
        )
        rows = result.fetchall()

    if not rows:
        return ""

    lines = ["== NVD Vulnerability Context =="]
    for row in rows:
        cvss = f"CVSS={row.cvss_base}" if row.cvss_base else "CVSS=N/A"
        epss = f"EPSS={row.epss}" if row.epss else "EPSS=N/A"
        lines.append(f"  {row.cve_id}: {cvss}, {epss}")
    return "\n".join(lines)


def normalise_analysis(result: dict) -> dict:
    """Enforce canonical types, severity, confidence, and field structure."""
    # threat_type
    tt = str(result.get("threat_type", "")).upper().strip()
    result["threat_type"] = tt if tt in VALID_THREAT_TYPES else "OTHER"

    # severity_level
    sev = str(result.get("severity_level", "")).upper().strip()
    result["severity_level"] = sev if sev in VALID_SEVERITIES else "INFORMATIONAL"

    # confidence
    try:
        conf = int(float(result.get("confidence", 0)))
        result["confidence"] = max(0, min(100, conf))
    except (ValueError, TypeError):
        result["confidence"] = 0

    # key_iocs — ensure list of {"type": ..., "value": ...} dicts
    raw_iocs = result.get("key_iocs")
    if isinstance(raw_iocs, list):
        cleaned = []
        for item in raw_iocs:
            if isinstance(item, dict) and "value" in item:
                cleaned.append(
                    {
                        "type": str(item.get("type", "unknown")).lower(),
                        "value": str(item["value"]),
                    }
                )
            elif isinstance(item, str) and item:
                cleaned.append({"type": "unknown", "value": item})
        result["key_iocs"] = cleaned
    else:
        result["key_iocs"] = []

    # ttps — ensure list of {"id": ..., "name": ...} dicts
    raw_ttps = result.get("ttps")
    if isinstance(raw_ttps, list):
        cleaned = []
        for item in raw_ttps:
            if isinstance(item, dict):
                cleaned.append(
                    {
                        "id": str(item.get("id", "")),
                        "name": str(item.get("name", "")),
                    }
                )
            elif isinstance(item, str) and item:
                cleaned.append({"id": "", "name": item})
        result["ttps"] = cleaned
    else:
        result["ttps"] = []

    # Text fields — coerce non-string values (LLM sometimes returns [] or null)
    text_fields = ["summary_impact", "relevance", "historical_context", "additional_notes"]
    for field in text_fields:
        val = result.get(field)
        if val is None or val == []:
            result[field] = ""
        elif not isinstance(val, str):
            result[field] = str(val)

    # Simple list fields — coerce to list of strings
    list_fields = [
        "recommended_actions",
        "affected_systems_sectors",
        "potential_threat_actors",
        "cve_references",
        "tools_used",
        "malware_families",
        "target_geographies",
    ]
    for field in list_fields:
        val = result.get(field)
        if val is None:
            result[field] = []
        elif isinstance(val, str):
            try:
                result[field] = json.loads(val)
            except json.JSONDecodeError:
                result[field] = [val] if val else []

    return result


async def analyse_and_persist(entry: ArchiveEntry) -> AnalysisEntry | None:
    """Full enrichment pipeline for a single archive entry.

    1. RAG retrieval (pgvector)
    2. NVD context lookup
    3. LLM analysis
    4. Normalisation
    5. Generate embedding
    6. Single-transaction persist (analysis + embedding)
    """
    content_text = entry.content or entry.summary or ""
    if not content_text.strip() and not entry.title:
        log.warning("Skipping entry — no content or title", extra={"guid": entry.guid})
        ENTRIES_SKIPPED.inc()
        return None

    with tracer.start_as_current_span("analyse_and_persist", attributes={"guid": entry.guid[:20]}):
        # 1. RAG context
        rag_context = await get_similar_analyses(
            title=entry.title,
            summary=entry.summary,
            content=entry.content,
        )
        if rag_context:
            rag_section = (
                "== Similar Past Analyses (for context — note if current entry relates "
                "to the same campaign or threat actor, but do not copy assessments) ==\n"
                f"{rag_context}"
            )
        else:
            rag_section = ""

        # 2. NVD context
        full_text = f"{entry.title} {entry.summary or ''} {content_text}"
        nvd_context = await lookup_cve_context(full_text)

        # 3. LLM analysis (with retry)
        prompt = ANALYSIS_PROMPT.format(
            retrieved_context=rag_section,
            nvd_context=nvd_context,
            title=entry.title,
            link=entry.link,
            published=entry.published or "N/A",
            author=entry.author or "N/A",
            feed_title=entry.feed_title or "N/A",
            categories=", ".join(entry.categories) if entry.categories else "N/A",
            content=content_text[:4000],
            summary=(entry.summary or "")[:2000],
        )

        llm = _build_llm()
        result = None
        for attempt in range(_LLM_MAX_RETRIES + 1):
            try:
                t0 = time.monotonic()
                response = await llm.ainvoke(prompt)
                LLM_LATENCY.observe(time.monotonic() - t0)
                result = json.loads(response.content)
                break
            except Exception:
                if attempt < _LLM_MAX_RETRIES:
                    LLM_RETRIES.inc()
                    delay = _LLM_RETRY_BASE_DELAY * (2**attempt)
                    log.warning(
                        "LLM attempt failed, retrying",
                        extra={"attempt": attempt + 1, "guid": entry.guid[:20], "delay_s": delay},
                    )
                    await asyncio.sleep(delay)
                else:
                    ENTRIES_FAILED.labels(stage="llm").inc()
                    log.exception("LLM analysis failed", extra={"guid": entry.guid, "title": entry.title})
                    return None

        # 4. Normalise
        if result is None:
            ENTRIES_FAILED.labels(stage="llm").inc()
            return None
        result = normalise_analysis(result)

        # 5. Build embedding text and generate vector
        embed_text = build_embedding_text(entry, result)
        try:
            vector = await generate_embedding(embed_text)
        except Exception:
            ENTRIES_FAILED.labels(stage="embedding").inc()
            log.exception("Embedding generation failed", extra={"guid": entry.guid})
            return None

        # 6. Single-transaction persist
        now = datetime.now(UTC)
        analysis_id = uuid.uuid4()

        analysis = AnalysisEntry(
            id=analysis_id,
            guid=entry.guid,
            threat_type=result["threat_type"],
            severity_level=result["severity_level"],
            confidence=result["confidence"],
            summary_impact=result.get("summary_impact"),
            relevance=result.get("relevance"),
            historical_context=result.get("historical_context"),
            additional_notes=result.get("additional_notes"),
            key_iocs=result.get("key_iocs"),
            recommended_actions=result.get("recommended_actions"),
            affected_systems_sectors=result.get("affected_systems_sectors"),
            potential_threat_actors=result.get("potential_threat_actors"),
            cve_references=result.get("cve_references"),
            ttps=result.get("ttps"),
            tools_used=result.get("tools_used"),
            malware_families=result.get("malware_families"),
            target_geographies=result.get("target_geographies"),
            entry_title=entry.title,
            source_name=entry.feed_title,
            source_url=entry.link,
            feed_title=entry.feed_title,
            feed_description=entry.feed_description,
            feed_language=entry.feed_language,
            feed_icon=entry.feed_icon,
            analysed_at=now,
            enriched_at=now,
            inserted_at=now,
            embedding_text=embed_text,
        )

        embedding = AnalysisEmbedding(
            analysis_id=analysis_id,
            embedding=vector,
            model=get_settings().embedding_model,
            created_at=now,
        )

        async with get_db() as db:
            db.add(analysis)
            db.add(embedding)
            await db.commit()

        log.info(
            "Enriched entry",
            extra={
                "guid": entry.guid[:20],
                "title": entry.title[:50],
                "threat_type": result["threat_type"],
                "severity": result["severity_level"],
                "confidence": result["confidence"],
            },
        )
        return analysis
