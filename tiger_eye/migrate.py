"""Migration runner — applies SQL files in order against tiger2go Postgres.

Tracks applied migrations in a `_migrations` meta table.
Usage:
    python -m tiger_eye.migrate              # apply pending
    python -m tiger_eye.migrate --status     # show applied/pending
"""

import argparse
import asyncio
import hashlib
import os
from pathlib import Path

import asyncpg

from tiger_eye.config import get_settings

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"

CREATE_META_TABLE = """
CREATE TABLE IF NOT EXISTS _migrations (
    filename    TEXT PRIMARY KEY,
    sha256      TEXT NOT NULL,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
"""


async def _get_conn() -> asyncpg.Connection:
    s = get_settings()
    # asyncpg wants a plain postgres:// URL, not postgresql+asyncpg://
    url = s.database_url.replace("postgresql+asyncpg://", "postgresql://")
    return await asyncpg.connect(url)


def _sha256(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()


async def apply_migrations(dry_run: bool = False) -> list[str]:
    """Apply all pending migrations in filename order. Returns list of applied filenames."""
    conn = await _get_conn()
    try:
        await conn.execute(CREATE_META_TABLE)

        applied_rows = await conn.fetch("SELECT filename FROM _migrations ORDER BY filename")
        applied = {r["filename"] for r in applied_rows}

        sql_files = sorted(f for f in os.listdir(MIGRATIONS_DIR) if f.endswith(".sql") and f not in applied)

        if not sql_files:
            print("No pending migrations.")
            return []

        newly_applied = []
        for filename in sql_files:
            path = MIGRATIONS_DIR / filename
            content = path.read_text()
            digest = _sha256(content)

            if dry_run:
                print(f"  [dry-run] Would apply: {filename} ({digest[:12]})")
                newly_applied.append(filename)
                continue

            print(f"  Applying: {filename} ...", end=" ", flush=True)
            await conn.execute(content)
            await conn.execute(
                "INSERT INTO _migrations (filename, sha256) VALUES ($1, $2)",
                filename,
                digest,
            )
            print("OK")
            newly_applied.append(filename)

        return newly_applied
    finally:
        await conn.close()


async def show_status() -> None:
    """Print migration status."""
    conn = await _get_conn()
    try:
        await conn.execute(CREATE_META_TABLE)

        applied_rows = await conn.fetch("SELECT filename, sha256, applied_at FROM _migrations ORDER BY filename")
        applied = {r["filename"] for r in applied_rows}

        all_files = sorted(f for f in os.listdir(MIGRATIONS_DIR) if f.endswith(".sql"))

        print(f"\nMigrations directory: {MIGRATIONS_DIR}")
        print(f"{'File':<45} {'Status':<12} {'Applied At'}")
        print("-" * 90)

        for filename in all_files:
            if filename in applied:
                row = next(r for r in applied_rows if r["filename"] == filename)
                ts = row["applied_at"].strftime("%Y-%m-%d %H:%M:%S")
                print(f"{filename:<45} {'APPLIED':<12} {ts}")
            else:
                print(f"{filename:<45} {'PENDING':<12}")

        pending = [f for f in all_files if f not in applied]
        print(f"\n{len(applied)} applied, {len(pending)} pending.")
    finally:
        await conn.close()


def main():
    parser = argparse.ArgumentParser(description="tiger-eye migration runner")
    parser.add_argument("--status", action="store_true", help="show migration status")
    parser.add_argument("--dry-run", action="store_true", help="show what would be applied")
    args = parser.parse_args()

    if args.status:
        asyncio.run(show_status())
    else:
        applied = asyncio.run(apply_migrations(dry_run=args.dry_run))
        if applied:
            print(f"\nApplied {len(applied)} migration(s).")


if __name__ == "__main__":
    main()
