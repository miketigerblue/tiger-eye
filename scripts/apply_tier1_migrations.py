"""One-shot apply script for the Tier-1 no-info-loss migrations.

Designed to run inside the tiger-eye container so it inherits the configured
DATABASE_URL — no credentials handled outside the container.

Idempotent: skips anything already recorded in _migrations / goose_db_version.

Usage (from the host):

    docker cp /Users/mike/tiger-eye/migrations/004_analysis_provenance_and_lost_fields.sql tiger-eye:/tmp/migrations/
    docker cp /Users/mike/tiger2go/migrations/20260511_create_cve_kev.sql                  tiger-eye:/tmp/migrations/
    docker cp /Users/mike/tiger2go/migrations/20260512_create_cve_enriched_history.sql      tiger-eye:/tmp/migrations/
    docker cp /Users/mike/tiger-eye/scripts/apply_tier1_migrations.py                       tiger-eye:/tmp/
    docker exec tiger-eye python /tmp/apply_tier1_migrations.py

Applies:
  1. 004_analysis_provenance_and_lost_fields.sql -> recorded in _migrations
  2. 20260511_create_cve_kev.sql                  -> recorded in goose_db_version
  3. 20260512_create_cve_enriched_history.sql     -> recorded in goose_db_version
"""

import asyncio
import hashlib
import re
import sys
from pathlib import Path

import asyncpg

from tiger_eye.config import get_settings


# Strip goose-style markers from a migration file: keep only the Up section,
# remove the +goose Up/Down/StatementBegin/StatementEnd lines.
GOOSE_DOWN_RE = re.compile(r"--\s*\+goose\s+Down\b.*", re.IGNORECASE | re.DOTALL)
GOOSE_LINE_RE = re.compile(r"^\s*--\s*\+goose\s+\w+.*$", re.IGNORECASE | re.MULTILINE)


def extract_goose_up(sql: str) -> str:
    """Return only the Up portion of a goose migration, with markers stripped."""
    up = GOOSE_DOWN_RE.sub("", sql)
    up = GOOSE_LINE_RE.sub("", up)
    return up.strip() + "\n"


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


async def apply_tigereye_migration(conn, sql_path: Path) -> bool:
    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS _migrations (
            filename    TEXT PRIMARY KEY,
            sha256      TEXT NOT NULL,
            applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        """
    )
    filename = sql_path.name
    already = await conn.fetchval("SELECT 1 FROM _migrations WHERE filename = $1", filename)
    if already:
        print(f"  [skip] {filename} already applied")
        return False

    sql = sql_path.read_text()
    digest = sha256(sql)
    async with conn.transaction():
        await conn.execute(sql)
        await conn.execute(
            "INSERT INTO _migrations (filename, sha256) VALUES ($1, $2)",
            filename,
            digest,
        )
    print(f"  [ OK ] {filename}  sha256={digest[:12]}")
    return True


async def apply_goose_migration(conn, sql_path: Path) -> bool:
    filename = sql_path.name
    m = re.match(r"^(\d+)_", filename)
    if not m:
        raise ValueError(f"Cannot derive goose version_id from filename: {filename}")
    version_id = int(m.group(1))

    already = await conn.fetchval(
        "SELECT 1 FROM goose_db_version WHERE version_id = $1 AND is_applied = TRUE",
        version_id,
    )
    if already:
        print(f"  [skip] {filename} (version {version_id}) already applied")
        return False

    raw = sql_path.read_text()
    up_sql = extract_goose_up(raw)

    async with conn.transaction():
        await conn.execute(up_sql)
        await conn.execute(
            "INSERT INTO goose_db_version (version_id, is_applied, tstamp) VALUES ($1, TRUE, now())",
            version_id,
        )
    print(f"  [ OK ] {filename} (version {version_id})")
    return True


async def main():
    s = get_settings()
    url = s.database_url.replace("postgresql+asyncpg://", "postgresql://")
    conn = await asyncpg.connect(url)
    try:
        print("== tiger-eye migrations ==")
        await apply_tigereye_migration(conn, Path("/tmp/migrations/004_analysis_provenance_and_lost_fields.sql"))

        print("\n== tiger2go migrations ==")
        await apply_goose_migration(conn, Path("/tmp/migrations/20260511_create_cve_kev.sql"))
        await apply_goose_migration(conn, Path("/tmp/migrations/20260512_create_cve_enriched_history.sql"))

        print("\n== Verification ==")
        for table in ("cve_kev", "cve_enriched_history"):
            n = await conn.fetchval(
                "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public' AND table_name=$1",
                table,
            )
            print(f"  {table}: {'present' if n else 'MISSING'}")

        new_cols = await conn.fetch(
            """
            SELECT column_name FROM information_schema.columns
            WHERE table_schema='public' AND table_name='analysis'
              AND column_name = ANY($1::text[])
            ORDER BY column_name
            """,
            [
                "model_id", "prompt_version", "pipeline_version",
                "prompt_tokens", "response_tokens", "latency_ms",
                "input_hash",
                "mitigation_strategies", "attack_vectors", "exploit_references",
            ],
        )
        print(f"  analysis new cols: {[r['column_name'] for r in new_cols]}")

        # Capacity check on cve_enriched.json trigger overhead
        # (informational only — actual cost depends on update frequency)
        size = await conn.fetchval(
            "SELECT pg_size_pretty(pg_total_relation_size('cve_enriched'))"
        )
        print(f"  cve_enriched size: {size} (history trigger now firing on writes)")
    finally:
        await conn.close()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()) or 0)
