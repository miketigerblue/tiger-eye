"""Embedding generation — thin wrapper around OpenAI API.

No ChromaDB, no LangChain embedding wrappers. Direct API calls.
"""

import asyncio
import logging
import time

import openai

from tiger_eye.config import get_settings
from tiger_eye.metrics import EMBEDDING_LATENCY, EMBEDDING_RETRIES

log = logging.getLogger(__name__)

_client: openai.AsyncOpenAI | None = None

# Retry config for transient OpenAI failures (429, 500, 502, 503)
_MAX_RETRIES = 2
_RETRY_BASE_DELAY = 2.0  # seconds


def _get_client() -> openai.AsyncOpenAI:
    global _client
    if _client is None:
        _client = openai.AsyncOpenAI(api_key=get_settings().openai_api_key)
    return _client


async def generate_embedding(
    text: str,
    model: str | None = None,
) -> list[float]:
    """Generate a vector embedding for the given text.

    Retries up to _MAX_RETRIES times on transient OpenAI errors.
    """
    model = model or get_settings().embedding_model
    client = _get_client()
    last_err: Exception | None = None
    for attempt in range(_MAX_RETRIES + 1):
        try:
            t0 = time.monotonic()
            response = await client.embeddings.create(input=text, model=model)
            EMBEDDING_LATENCY.observe(time.monotonic() - t0)
            return list(response.data[0].embedding)
        except (openai.RateLimitError, openai.APIStatusError) as exc:
            last_err = exc
            if attempt < _MAX_RETRIES:
                EMBEDDING_RETRIES.inc()
                delay = _RETRY_BASE_DELAY * (2**attempt)
                log.warning(
                    "OpenAI embedding attempt %d failed (%s), retrying in %.0fs",
                    attempt + 1,
                    type(exc).__name__,
                    delay,
                )
                await asyncio.sleep(delay)
            else:
                raise
    raise last_err if last_err is not None else RuntimeError("unreachable")


def build_embedding_text(
    entry,
    result: dict,
) -> str:
    """Construct the document text that gets embedded.

    Accepts an ArchiveEntry (or any object with title/link/published/feed_title).
    Deterministic, reproducible — stored in analysis.embedding_text
    so we can re-embed without reconstructing from fields.
    """

    def join_flat(val) -> str:
        """Join a list of strings."""
        if isinstance(val, list):
            return ", ".join(str(v) for v in val)
        if isinstance(val, str):
            return val
        return str(val) if val else ""

    def join_iocs(val) -> str:
        """Join structured IOCs: [{"type": ..., "value": ...}]."""
        if not isinstance(val, list):
            return ""
        parts = []
        for item in val:
            if isinstance(item, dict) and "value" in item:
                parts.append(f"{item.get('type', 'unknown')}:{item['value']}")
            elif isinstance(item, str):
                parts.append(item)
        return ", ".join(parts)

    def join_ttps(val) -> str:
        """Join structured TTPs: [{"id": ..., "name": ...}]."""
        if not isinstance(val, list):
            return ""
        parts = []
        for item in val:
            if isinstance(item, dict):
                tid = item.get("id", "")
                name = item.get("name", "")
                parts.append(f"{tid} {name}".strip())
            elif isinstance(item, str):
                parts.append(item)
        return ", ".join(parts)

    title = entry.title if hasattr(entry, "title") else str(entry)
    link = getattr(entry, "link", "")
    published = getattr(entry, "published", "")
    feed_title = getattr(entry, "feed_title", "")

    parts = [
        f"Title: {title}",
        f"URL: {link}",
        f"Published: {published or ''}",
        f"Feed: {feed_title or ''}",
        f"Threat Type: {result.get('threat_type', '')}",
        f"Severity: {result.get('severity_level', '')}",
        f"Confidence: {result.get('confidence', '')}",
        f"Summary: {result.get('summary_impact', '')}",
        f"CVE References: {join_flat(result.get('cve_references', []))}",
        f"Key IOCs: {join_iocs(result.get('key_iocs', []))}",
        f"TTPs: {join_ttps(result.get('ttps', []))}",
        f"Threat Actors: {join_flat(result.get('potential_threat_actors', []))}",
        f"Malware Families: {join_flat(result.get('malware_families', []))}",
        f"Target Geographies: {join_flat(result.get('target_geographies', []))}",
        f"Tools Used: {join_flat(result.get('tools_used', []))}",
        f"Affected Sectors: {join_flat(result.get('affected_systems_sectors', []))}",
        f"Relevance: {result.get('relevance', '')}",
        f"Historical Context: {result.get('historical_context', '')}",
    ]
    return "\n".join(parts)
