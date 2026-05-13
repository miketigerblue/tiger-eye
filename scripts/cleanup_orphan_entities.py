"""Delete entity rows that now match the (tightened) generic-label filter.

Run after updating tiger_eye.entities to broaden generic patterns. The
existing entity rows aren't automatically removed when a pattern change
makes their canonical_name newly-generic — this script does that
cleanup. CASCADE on analysis_actor / analysis_malware removes the join
rows automatically.
"""

import asyncio
import sys

import asyncpg

from tiger_eye.config import get_settings
from tiger_eye.entities import canonicalise_actor, canonicalise_malware


async def main():
    s = get_settings()
    url = s.database_url.replace("postgresql+asyncpg://", "postgresql://")
    conn = await asyncpg.connect(url)
    try:
        actor_orphans = []
        for r in await conn.fetch("SELECT id, canonical_name FROM threat_actors"):
            canon, _ = canonicalise_actor(r["canonical_name"])
            if canon is None:
                actor_orphans.append(r["id"])

        family_orphans = []
        for r in await conn.fetch("SELECT id, canonical_name FROM malware_families"):
            canon, _ = canonicalise_malware(r["canonical_name"])
            if canon is None:
                family_orphans.append(r["id"])

        print(f"Orphan actors to delete:  {len(actor_orphans)}")
        print(f"Orphan families to delete: {len(family_orphans)}")

        if actor_orphans:
            async with conn.transaction():
                await conn.execute(
                    "DELETE FROM threat_actors WHERE id = ANY($1::uuid[])",
                    actor_orphans,
                )
        if family_orphans:
            async with conn.transaction():
                await conn.execute(
                    "DELETE FROM malware_families WHERE id = ANY($1::uuid[])",
                    family_orphans,
                )

        n_actors = await conn.fetchval("SELECT COUNT(*) FROM threat_actors")
        n_families = await conn.fetchval("SELECT COUNT(*) FROM malware_families")
        n_actor_links = await conn.fetchval("SELECT COUNT(*) FROM analysis_actor")
        n_family_links = await conn.fetchval("SELECT COUNT(*) FROM analysis_malware")
        print(f"\nAfter cleanup:")
        print(f"  threat_actors:   {n_actors}")
        print(f"  malware_families: {n_families}")
        print(f"  analysis_actor:   {n_actor_links}")
        print(f"  analysis_malware: {n_family_links}")
    finally:
        await conn.close()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()) or 0)
