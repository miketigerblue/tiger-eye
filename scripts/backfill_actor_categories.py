"""Backfill threat_actors.category and attribution_country from entities.py maps.

The category / country columns on threat_actors are populated at entity
*creation* time from `tiger_eye.entities.actor_category()` and
`actor_country()`. When the maps in entities.py grow new entries, rows
that already exist for the newly-mapped canonical names stay NULL —
the upsert at enrichment time doesn't touch the columns once the row
exists.

Run this once after extending _ACTOR_CATEGORY / _ACTOR_COUNTRY to
backfill the historical rows.
"""

import asyncio
import sys

import asyncpg

from tiger_eye.config import get_settings
from tiger_eye.entities import actor_category, actor_country


async def main():
    s = get_settings()
    url = s.database_url.replace("postgresql+asyncpg://", "postgresql://")
    conn = await asyncpg.connect(url)
    try:
        rows = await conn.fetch(
            "SELECT id, canonical_name, category, attribution_country FROM threat_actors"
        )
        cat_updates = 0
        country_updates = 0
        for r in rows:
            new_cat = actor_category(r["canonical_name"])
            new_country = actor_country(r["canonical_name"])
            if new_cat and new_cat != r["category"]:
                await conn.execute(
                    "UPDATE threat_actors SET category = $1, updated_at = NOW() WHERE id = $2",
                    new_cat,
                    r["id"],
                )
                cat_updates += 1
            if new_country and new_country != r["attribution_country"]:
                await conn.execute(
                    "UPDATE threat_actors SET attribution_country = $1, updated_at = NOW() WHERE id = $2",
                    new_country,
                    r["id"],
                )
                country_updates += 1

        print(f"Category backfills:  {cat_updates}")
        print(f"Country backfills:   {country_updates}")
    finally:
        await conn.close()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()) or 0)
