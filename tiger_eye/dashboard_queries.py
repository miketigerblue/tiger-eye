"""Aggregate queries for the tiger-eye dashboard.

Produces a single JSON-serialisable dict powering every panel on the
/dashboard page. Runs all aggregates in parallel and caches the result
for DASHBOARD_TTL_SECONDS to protect the database from dashboard traffic.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import UTC, datetime
from typing import Any, cast

from sqlalchemy import text as sql_text

from tiger_eye.database import get_db

log = logging.getLogger(__name__)

DASHBOARD_TTL_SECONDS = 60

# ---------------------------------------------------------------------------
# SQL — each query returns JSON-friendly scalars / arrays
# ---------------------------------------------------------------------------

_SQL_KPI = """
WITH our_cves AS (
    SELECT DISTINCT jsonb_array_elements_text(cve_references) AS cve_id
    FROM analysis
    WHERE cve_references IS NOT NULL AND jsonb_typeof(cve_references) = 'array'
),
valid AS (
    SELECT cve_id FROM our_cves WHERE SUBSTRING(cve_id FROM 1 FOR 4) = 'CVE-'
),
latest_epss AS (
    SELECT cve_id, epss, percentile
    FROM epss_daily
    WHERE as_of = (SELECT MAX(as_of) FROM epss_daily)
)
SELECT
    (SELECT COUNT(*) FROM analysis)                                                     AS total_analyses,
    (SELECT COUNT(*) FROM analysis WHERE severity_level = 'CRITICAL')                   AS critical,
    (SELECT COUNT(*) FROM analysis WHERE severity_level = 'HIGH')                       AS high,
    (SELECT COUNT(*) FROM analysis WHERE severity_level = 'MEDIUM')                     AS medium,
    (SELECT COUNT(*) FROM analysis WHERE severity_level = 'LOW')                        AS low,
    (SELECT COUNT(*) FROM analysis WHERE severity_level = 'INFORMATIONAL')              AS info,
    (SELECT COUNT(*) FROM valid)                                                        AS distinct_cves,
    (SELECT COUNT(*) FROM valid v LEFT JOIN latest_epss l USING(cve_id) WHERE l.percentile >= 0.99) AS top_1pct,
    (SELECT COUNT(*) FROM valid v LEFT JOIN latest_epss l USING(cve_id) WHERE l.epss >= 0.9)        AS epss_over_90,
    (SELECT COUNT(DISTINCT source_name) FROM analysis WHERE source_name IS NOT NULL)    AS distinct_sources,
    (SELECT MAX(analysed_at)::date FROM analysis)                                       AS latest_analysis,
    (SELECT COALESCE(AVG(confidence), 0)::int FROM analysis)                            AS avg_confidence
"""

_SQL_TOP_CVES = """
WITH our AS (
    SELECT
        a.id                                    AS analysis_id,
        a.analysed_at                           AS analysed_at,
        jsonb_array_elements_text(a.cve_references) AS cve_id,
        a.severity_level,
        a.confidence,
        a.source_name
    FROM analysis a
    WHERE a.cve_references IS NOT NULL
      AND jsonb_typeof(a.cve_references) = 'array'
),
latest AS (
    SELECT cve_id, epss, percentile
    FROM epss_daily
    WHERE as_of = (SELECT MAX(as_of) FROM epss_daily)
),
-- One representative analysis per CVE: most-recent / highest-confidence.
rep AS (
    SELECT DISTINCT ON (cve_id)
        cve_id, analysis_id
    FROM our
    WHERE SUBSTRING(cve_id FROM 1 FOR 4) = 'CVE-'
    ORDER BY cve_id, analysed_at DESC NULLS LAST, confidence DESC NULLS LAST
),
agg AS (
    SELECT
        cve_id,
        COUNT(*)                                     AS mentions,
        MODE() WITHIN GROUP (ORDER BY severity_level) AS dominant_severity,
        MAX(confidence)                              AS max_confidence,
        (
            ARRAY_AGG(DISTINCT source_name ORDER BY source_name)
            FILTER (WHERE source_name IS NOT NULL)
        )[1:1]                                       AS primary_source,
        COUNT(DISTINCT source_name)                  AS n_sources
    FROM our
    WHERE SUBSTRING(cve_id FROM 1 FOR 4) = 'CVE-'
    GROUP BY cve_id
)
SELECT
    ag.cve_id,
    ROUND(l.epss::numeric, 4)::float       AS epss,
    ROUND(l.percentile::numeric, 4)::float AS percentile,
    ce.cvss_base::float                    AS cvss,
    ce.cvss_version                        AS cvss_version,
    ce.ssvc_exploitation                   AS ssvc_exploitation,
    ce.vuln_status                         AS vuln_status,
    ag.mentions,
    ag.max_confidence                      AS max_confidence,
    ag.dominant_severity                   AS sev,
    ag.primary_source[1]                   AS primary_source,
    ag.n_sources,
    rep.analysis_id::text                  AS analysis_id,
    -- KEV enrichment (PR #34 series) — fuels the priority badge
    (kv.cve_id IS NOT NULL)                AS kev_listed,
    kv.known_ransomware_use                AS kev_ransomware,
    kv.due_date                            AS kev_due_date,
    kv.vendor_project                      AS kev_vendor,
    kv.product                             AS kev_product
FROM agg ag
JOIN latest l ON l.cve_id = ag.cve_id
JOIN rep     ON rep.cve_id = ag.cve_id
LEFT JOIN cve_enriched ce ON ce.cve_id = ag.cve_id AND ce.source = 'NVD'
LEFT JOIN cve_kev kv ON kv.cve_id = ag.cve_id AND kv.withdrawn_at IS NULL
ORDER BY l.epss DESC NULLS LAST
LIMIT 20
"""

# ---------------------------------------------------------------------------
# Detail-drawer enrichment side-cars
# ---------------------------------------------------------------------------
# These run alongside _SQL_ANALYSIS_DETAIL when the drawer opens. They turn
# the raw jsonb arrays on the analysis row into entity-enriched chips:
#
#   "CVE-2024-3400"   -> { cve_id, cvss, epss, percentile, kev_*, vendor/product }
#   "TeamPCP"          -> { canonical_name, category, attribution_country }
#   "Vidar Stealer"    -> { canonical_name, category }
#
# Actor / malware enrichment routes through the analysis_actor /
# analysis_malware join tables (populated at write-time by
# tiger_eye.analysis._link_entities), so it inherits all the canonicaliser
# alias-collapse done in tiger_eye.entities.

_SQL_DETAIL_CVE_ENRICHMENT = """
WITH cves AS (
    SELECT DISTINCT upper((regexp_matches(ref, 'CVE-[0-9]{4}-[0-9]{4,7}', 'g'))[1]) AS cve_id
    FROM analysis a, LATERAL jsonb_array_elements_text(a.cve_references) AS ref
    WHERE a.id = :id
      AND a.cve_references IS NOT NULL
      AND jsonb_typeof(a.cve_references) = 'array'
)
SELECT
    c.cve_id,
    ce.cvss_base::float                       AS cvss,
    ce.cvss_version                           AS cvss_version,
    ce.ssvc_exploitation                      AS ssvc_exploitation,
    ce.vuln_status                            AS vuln_status,
    ROUND(le.epss::numeric, 4)::float         AS epss,
    ROUND(le.percentile::numeric, 4)::float   AS percentile,
    (kv.cve_id IS NOT NULL)                   AS kev_listed,
    COALESCE(kv.known_ransomware_use, FALSE)  AS kev_ransomware,
    kv.due_date                               AS kev_due_date,
    kv.vendor_project                         AS kev_vendor,
    kv.product                                AS kev_product
FROM cves c
LEFT JOIN cve_enriched ce ON ce.cve_id = c.cve_id AND ce.source = 'NVD'
LEFT JOIN LATERAL (
    SELECT epss, percentile FROM epss_daily
    WHERE cve_id = c.cve_id
    ORDER BY as_of DESC LIMIT 1
) le ON TRUE
LEFT JOIN cve_kev kv ON kv.cve_id = c.cve_id AND kv.withdrawn_at IS NULL
ORDER BY le.epss DESC NULLS LAST, c.cve_id
"""

_SQL_DETAIL_ACTOR_ENRICHMENT = """
SELECT
    aa.raw_mention                AS raw_mention,
    ta.canonical_name             AS canonical_name,
    ta.category                   AS category,
    ta.attribution_country        AS country
FROM analysis_actor aa
JOIN threat_actors ta ON ta.id = aa.actor_id
WHERE aa.analysis_id = :id
ORDER BY ta.canonical_name
"""

_SQL_DETAIL_MALWARE_ENRICHMENT = """
SELECT
    am.raw_mention                AS raw_mention,
    mf.canonical_name             AS canonical_name,
    mf.category                   AS category
FROM analysis_malware am
JOIN malware_families mf ON mf.id = am.family_id
WHERE am.analysis_id = :id
ORDER BY mf.canonical_name
"""

_SQL_THREAT_TYPES = """
SELECT threat_type AS type, COUNT(*) AS n
FROM analysis
WHERE threat_type IS NOT NULL
GROUP BY threat_type
ORDER BY n DESC
"""

_SQL_DAILY = """
SELECT
    analysed_at::date::text AS day,
    COUNT(*)                                                         AS total,
    COUNT(*) FILTER (WHERE severity_level = 'CRITICAL')              AS critical,
    COUNT(*) FILTER (WHERE severity_level = 'HIGH')                  AS high,
    COUNT(*) FILTER (WHERE severity_level = 'MEDIUM')                AS medium,
    COUNT(*) FILTER (WHERE severity_level IN ('LOW','INFORMATIONAL'))AS low_info
FROM analysis
WHERE analysed_at IS NOT NULL
  AND analysed_at >= now() - INTERVAL '30 days'
GROUP BY 1
ORDER BY 1
"""

_SQL_SOURCES = """
SELECT source_name AS source,
       COUNT(*)                                                       AS n,
       COUNT(*) FILTER (WHERE severity_level IN ('CRITICAL','HIGH'))  AS hi_sev
FROM analysis
WHERE source_name IS NOT NULL
GROUP BY source_name
ORDER BY n DESC
LIMIT 15
"""

# Noise terms we never want in the actor / malware panels — LLMs tend to
# produce these as "actors" because they're named in articles.
_ACTOR_STOPWORDS = [
    "",
    "unknown",
    "unspecified",
    "n/a",
    "various",
    "multiple",
    "none",
    "threat actors",
    "attackers",
    "attacker",
    "remote attacker",
    "unauthenticated attacker",
    "nation-state",
    "malicious cyber actors",
    "cybercriminals",
    "anthropic",
    "qualys",
]
_MALWARE_STOPWORDS = [
    "",
    "unknown",
    "unspecified",
    "n/a",
    "various",
    "multiple",
    "none",
    "ransomware",
]
_GEO_STOPWORDS = [
    "",
    "unknown",
    "global",
    "worldwide",
    "international",
    "various",
    "multiple",
    "n/a",
]

_SQL_ACTORS = """
WITH names AS (
    SELECT LOWER(TRIM(jsonb_array_elements_text(potential_threat_actors))) AS name
    FROM analysis
    WHERE potential_threat_actors IS NOT NULL
      AND jsonb_typeof(potential_threat_actors) = 'array'
)
SELECT name, COUNT(*) AS n
FROM names
WHERE NOT (name = ANY(:stopwords))
GROUP BY name
HAVING COUNT(*) >= 3
ORDER BY n DESC
LIMIT 12
"""

_SQL_MALWARE = """
WITH names AS (
    SELECT LOWER(TRIM(jsonb_array_elements_text(malware_families))) AS name
    FROM analysis
    WHERE malware_families IS NOT NULL
      AND jsonb_typeof(malware_families) = 'array'
)
SELECT name, COUNT(*) AS n
FROM names
WHERE NOT (name = ANY(:stopwords))
GROUP BY name
HAVING COUNT(*) >= 2
ORDER BY n DESC
LIMIT 12
"""

# TTPs: the LLM emits varied display names for the same ATT&CK ID (e.g.
# T1190 as "Exploit Public-Facing Application" 241 times AND "Path
# Traversal" a handful). We want the dominant name per ID, not whichever
# one the sort happens to grab. MODE() picks the most frequent value
# within each group.
_SQL_TTPS = """
WITH items AS (
    SELECT jsonb_array_elements(ttps) AS t
    FROM analysis
    WHERE ttps IS NOT NULL AND jsonb_typeof(ttps) = 'array'
),
with_names AS (
    SELECT
        t->>'id'   AS id,
        NULLIF(t->>'name', '') AS name
    FROM items
    WHERE t->>'id' IS NOT NULL AND t->>'id' <> ''
)
SELECT
    id,
    MODE() WITHIN GROUP (ORDER BY name) FILTER (WHERE name IS NOT NULL) AS name,
    COUNT(*) AS n
FROM with_names
GROUP BY id
ORDER BY n DESC
LIMIT 15
"""

_SQL_GEOS = """
WITH geos AS (
    SELECT LOWER(TRIM(jsonb_array_elements_text(target_geographies))) AS geo
    FROM analysis
    WHERE target_geographies IS NOT NULL
      AND jsonb_typeof(target_geographies) = 'array'
)
SELECT geo, COUNT(*) AS n
FROM geos
WHERE NOT (geo = ANY(:stopwords))
GROUP BY geo
HAVING COUNT(*) >= 3
ORDER BY n DESC
LIMIT 15
"""

_SQL_ANALYSIS_DETAIL = """
SELECT
    id::text                                                  AS id,
    guid,
    threat_type,
    severity_level                                            AS sev,
    confidence                                                AS conf,
    summary_impact,
    relevance,
    historical_context,
    additional_notes,
    key_iocs,
    recommended_actions,
    -- Restored in PR #22 (v3 schema): defensive controls + how-it-arrives
    -- + PoC/advisory URLs, all separated from the response-action list.
    mitigation_strategies,
    attack_vectors,
    affected_systems_sectors,
    potential_threat_actors,
    cve_references,
    exploit_references,
    ttps,
    tools_used,
    malware_families,
    target_geographies,
    entry_title                                               AS title,
    COALESCE(source_name, 'unknown')                          AS src,
    COALESCE(source_url, '')                                  AS url,
    feed_title,
    -- Provenance (PR #22) — surface for the detail drawer's footer.
    model_id,
    prompt_version,
    pipeline_version,
    prompt_tokens,
    response_tokens,
    latency_ms,
    encode(input_hash, 'hex')                                 AS input_hash,
    -- Pipeline run (PR #29) — links back to the cycle that produced this row.
    run_id::text                                              AS run_id,
    to_char(analysed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS analysed_at,
    EXTRACT(EPOCH FROM analysed_at)::bigint                   AS ts
FROM analysis
WHERE id = :id
"""


_SQL_FEED = """
SELECT
    id::text                                                     AS id,
    COALESCE(entry_title, '(no title)')                          AS title,
    severity_level                                               AS sev,
    threat_type,
    confidence                                                   AS conf,
    COALESCE(source_name, 'unknown')                             AS src,
    to_char(analysed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS t,
    EXTRACT(EPOCH FROM analysed_at)::bigint                      AS ts,
    COALESCE(source_url, '#')                                    AS url,
    COALESCE(summary_impact, '')                                 AS summary
FROM analysis
WHERE severity_level IN ('CRITICAL', 'HIGH')
  AND confidence >= 80
ORDER BY analysed_at DESC, confidence DESC
LIMIT 40
"""


# ---------------------------------------------------------------------------
# Aggregator
# ---------------------------------------------------------------------------


async def _rows(sql: str, params: dict | None = None) -> list[dict]:
    async with get_db() as db:
        result = await db.execute(sql_text(sql), params or {})
        return [dict(r._mapping) for r in result.fetchall()]


async def _one(sql: str, params: dict | None = None) -> dict:
    rows = await _rows(sql, params)
    return rows[0] if rows else {}


async def _build_dashboard() -> dict[str, Any]:
    """Run every panel query in parallel and assemble the payload."""
    # asyncio.gather's static return type widens element types; narrow the
    # heterogeneous tuple so callers see dict/list as appropriate.
    results = await asyncio.gather(
        _one(_SQL_KPI),
        _rows(_SQL_TOP_CVES),
        _rows(_SQL_THREAT_TYPES),
        _rows(_SQL_DAILY),
        _rows(_SQL_SOURCES),
        _rows(_SQL_ACTORS, {"stopwords": _ACTOR_STOPWORDS}),
        _rows(_SQL_MALWARE, {"stopwords": _MALWARE_STOPWORDS}),
        _rows(_SQL_TTPS),
        _rows(_SQL_GEOS, {"stopwords": _GEO_STOPWORDS}),
        _rows(_SQL_FEED),
    )
    kpi = cast("dict[str, Any]", results[0])
    cves, threat_types, daily, sources, actors, malware, ttps, geos, feed = (
        cast("list[dict[str, Any]]", r) for r in results[1:]
    )

    # `latest_analysis` comes back as a date; serialise to ISO string.
    latest = kpi.get("latest_analysis")
    if latest is not None and not isinstance(latest, str):
        kpi["latest_analysis"] = latest.isoformat()

    return {
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M"),
        "ttl_seconds": DASHBOARD_TTL_SECONDS,
        "kpi": kpi,
        "cves": cves,
        "threat_types": threat_types,
        "daily": daily,
        "sources": sources,
        "actors": actors,
        "malware": malware,
        "ttps": ttps,
        "geos": geos,
        "feed": feed,
    }


# ---------------------------------------------------------------------------
# Async-safe TTL cache
# ---------------------------------------------------------------------------
#
# Dashboard traffic is bursty (one ops engineer refreshes, three panels in
# the browser fire simultaneously). Without a lock, N concurrent misses
# would each run ~10 queries against Postgres. Serialise misses on a lock
# and re-check the cache after acquiring it — only the first caller pays.

_cached_payload: dict[str, Any] | None = None
_cache_expires_at: float = 0.0
_cache_lock = asyncio.Lock()


async def get_dashboard_data(force_refresh: bool = False) -> dict[str, Any]:
    """Return a cached dashboard payload, recomputing on miss or expiry."""
    global _cached_payload, _cache_expires_at

    now = time.monotonic()
    if not force_refresh and _cached_payload is not None and _cache_expires_at > now:
        return _cached_payload

    async with _cache_lock:
        now = time.monotonic()
        if not force_refresh and _cached_payload is not None and _cache_expires_at > now:
            return _cached_payload

        t0 = time.monotonic()
        data = await _build_dashboard()
        log.info(
            "Dashboard cache miss — rebuilt",
            extra={"duration_s": round(time.monotonic() - t0, 3)},
        )
        _cached_payload = data
        _cache_expires_at = time.monotonic() + DASHBOARD_TTL_SECONDS
        return data


async def get_analysis_detail(analysis_id: str) -> dict[str, Any] | None:
    """Fetch a single enriched analysis record by UUID for the detail drawer.

    Returns None when not found; callers should 404. Not cached — detail
    lookups are one-shot and low-volume compared to the aggregate payload.

    Pulls four queries in parallel:
      * the analysis row itself
      * per-CVE enrichment   (cvss, epss, kev, ransomware flag, due date)
      * per-actor enrichment (canonical name, category, country)
      * per-malware enrichment (canonical name, category)

    The three enrichment lists are merged into the response as
    `cves_enriched`, `actors_enriched`, `malware_enriched` so the drawer
    can render priority badges + entity chips without further round-trips.
    """
    base_task = _rows(_SQL_ANALYSIS_DETAIL, {"id": analysis_id})
    cve_task = _rows(_SQL_DETAIL_CVE_ENRICHMENT, {"id": analysis_id})
    actor_task = _rows(_SQL_DETAIL_ACTOR_ENRICHMENT, {"id": analysis_id})
    malware_task = _rows(_SQL_DETAIL_MALWARE_ENRICHMENT, {"id": analysis_id})

    base_rows, cves, actors, malware = await asyncio.gather(base_task, cve_task, actor_task, malware_task)
    if not base_rows:
        return None
    row = base_rows[0]
    row["cves_enriched"] = cves
    row["actors_enriched"] = actors
    row["malware_enriched"] = malware
    return row


def invalidate_cache() -> None:
    """Clear the cache (for tests / forced refresh)."""
    global _cached_payload, _cache_expires_at
    _cached_payload = None
    _cache_expires_at = 0.0
