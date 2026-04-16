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
from typing import Any

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
    SELECT jsonb_array_elements_text(a.cve_references) AS cve_id,
           a.severity_level, a.confidence, a.source_name
    FROM analysis a
    WHERE a.cve_references IS NOT NULL AND jsonb_typeof(a.cve_references) = 'array'
),
latest AS (
    SELECT cve_id, epss, percentile
    FROM epss_daily
    WHERE as_of = (SELECT MAX(as_of) FROM epss_daily)
),
agg AS (
    SELECT
        cve_id,
        COUNT(*) AS mentions,
        MODE() WITHIN GROUP (ORDER BY severity_level) AS dominant_severity,
        (
            ARRAY_AGG(DISTINCT source_name ORDER BY source_name)
            FILTER (WHERE source_name IS NOT NULL)
        )[1:1] AS primary_source,
        COUNT(DISTINCT source_name) AS n_sources
    FROM our
    WHERE SUBSTRING(cve_id FROM 1 FOR 4) = 'CVE-'
    GROUP BY cve_id
)
SELECT
    ag.cve_id,
    ROUND(l.epss::numeric, 4)::float       AS epss,
    ROUND(l.percentile::numeric, 4)::float AS percentile,
    ce.cvss_base::float                    AS cvss,
    ag.mentions,
    ag.dominant_severity                   AS sev,
    ag.primary_source[1]                   AS primary_source,
    ag.n_sources
FROM agg ag
JOIN latest l ON l.cve_id = ag.cve_id
LEFT JOIN cve_enriched ce ON ce.cve_id = ag.cve_id AND ce.source = 'NVD'
ORDER BY l.epss DESC NULLS LAST
LIMIT 20
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

# TTPs: the LLM sometimes emits the same ATT&CK ID twice under different
# names (e.g. "T1068 Exploitation for Privilege Escalation" and "T1068
# Privilege Escalation"). Collapse on ID so the panel stays clean.
_SQL_TTPS = """
WITH items AS (
    SELECT jsonb_array_elements(ttps) AS t
    FROM analysis
    WHERE ttps IS NOT NULL AND jsonb_typeof(ttps) = 'array'
)
SELECT
    t->>'id' AS id,
    (ARRAY_AGG(t->>'name' ORDER BY (
        CASE WHEN t->>'name' IS NULL OR t->>'name' = '' THEN 1 ELSE 0 END
    )))[1]   AS name,
    COUNT(*) AS n
FROM items
WHERE t->>'id' IS NOT NULL AND t->>'id' <> ''
GROUP BY t->>'id'
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

_SQL_FEED = """
SELECT
    id::text                                                  AS id,
    COALESCE(entry_title, '(no title)')                       AS title,
    severity_level                                            AS sev,
    threat_type,
    confidence                                                AS conf,
    COALESCE(source_name, 'unknown')                          AS src,
    to_char(analysed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI') AS t,
    COALESCE(source_url, '#')                                 AS url,
    COALESCE(summary_impact, '')                              AS summary
FROM analysis
WHERE severity_level IN ('CRITICAL', 'HIGH')
  AND confidence >= 80
ORDER BY analysed_at DESC, confidence DESC
LIMIT 25
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
    (
        kpi,
        cves,
        threat_types,
        daily,
        sources,
        actors,
        malware,
        ttps,
        geos,
        feed,
    ) = await asyncio.gather(
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

_cache: dict[str, Any] = {"value": None, "expires_at": 0.0}
_cache_lock = asyncio.Lock()


async def get_dashboard_data(force_refresh: bool = False) -> dict[str, Any]:
    """Return a cached dashboard payload, recomputing on miss or expiry."""
    now = time.monotonic()
    if not force_refresh and _cache["value"] is not None and _cache["expires_at"] > now:
        return _cache["value"]

    async with _cache_lock:
        now = time.monotonic()
        if not force_refresh and _cache["value"] is not None and _cache["expires_at"] > now:
            return _cache["value"]

        t0 = time.monotonic()
        data = await _build_dashboard()
        log.info(
            "Dashboard cache miss — rebuilt",
            extra={"duration_s": round(time.monotonic() - t0, 3)},
        )
        _cache["value"] = data
        _cache["expires_at"] = time.monotonic() + DASHBOARD_TTL_SECONDS
        return data


def invalidate_cache() -> None:
    """Clear the cache (for tests / forced refresh)."""
    _cache["value"] = None
    _cache["expires_at"] = 0.0
