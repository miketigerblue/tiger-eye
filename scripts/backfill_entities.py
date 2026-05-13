"""Backfill threat_actors / malware_families from existing analysis rows.

Reads every analysis row that has a non-empty potential_threat_actors or
malware_families jsonb array, canonicalises each entry via
`tiger_eye.entities`, and writes entity + join rows.

Idempotent — uses ON CONFLICT DO NOTHING on the join inserts and
ON CONFLICT DO UPDATE on the entity upserts, so re-runs are safe.

Run inside the tiger-eye container so DATABASE_URL is set:

    docker exec -e PYTHONPATH=/app tiger-eye python /tmp/backfill_entities.py

Prints a final summary: rows scanned / mentions canonicalised / mentions
filtered as generic / new entities created.
"""

import asyncio
import sys
from collections import Counter
from datetime import UTC, datetime

import asyncpg

from tiger_eye.config import get_settings
from tiger_eye.entities import (
    actor_category,
    actor_country,
    canonicalise_actor,
    canonicalise_malware,
    malware_category,
)

BATCH_SIZE = 200


async def main() -> int:
    s = get_settings()
    url = s.database_url.replace("postgresql+asyncpg://", "postgresql://")
    conn = await asyncpg.connect(url)

    stats = Counter()
    actor_id_by_key: dict[str, str] = {}
    family_id_by_key: dict[str, str] = {}

    try:
        total_rows = await conn.fetchval(
            """
            SELECT COUNT(*) FROM analysis
            WHERE (jsonb_typeof(potential_threat_actors) = 'array'
                   AND jsonb_array_length(potential_threat_actors) > 0)
               OR (jsonb_typeof(malware_families) = 'array'
                   AND jsonb_array_length(malware_families) > 0)
            """
        )
        print(f"Backfilling entities from {total_rows} analysis rows…")

        offset = 0
        while True:
            rows = await conn.fetch(
                """
                SELECT id, potential_threat_actors, malware_families
                FROM analysis
                WHERE (jsonb_typeof(potential_threat_actors) = 'array'
                       AND jsonb_array_length(potential_threat_actors) > 0)
                   OR (jsonb_typeof(malware_families) = 'array'
                       AND jsonb_array_length(malware_families) > 0)
                ORDER BY analysed_at
                LIMIT $1 OFFSET $2
                """,
                BATCH_SIZE,
                offset,
            )
            if not rows:
                break

            async with conn.transaction():
                for row in rows:
                    analysis_id = row["id"]
                    stats["rows"] += 1

                    actors = row["potential_threat_actors"] or []
                    if isinstance(actors, str):
                        # asyncpg returns jsonb columns as parsed objects, but
                        # be defensive if it ever comes back as raw text.
                        import json as _json
                        actors = _json.loads(actors)
                    families = row["malware_families"] or []
                    if isinstance(families, str):
                        import json as _json
                        families = _json.loads(families)

                    for raw in actors:
                        if not isinstance(raw, str):
                            continue
                        stats["actor_mentions"] += 1
                        canonical, norm_key = canonicalise_actor(raw)
                        if canonical is None:
                            stats["actor_filtered"] += 1
                            continue
                        if norm_key not in actor_id_by_key:
                            actor_id = await conn.fetchval(
                                """
                                INSERT INTO threat_actors
                                    (canonical_name, normalised_key, category, attribution_country)
                                VALUES ($1, $2, $3, $4)
                                ON CONFLICT (normalised_key)
                                  DO UPDATE SET updated_at = now()
                                RETURNING id
                                """,
                                canonical, norm_key,
                                actor_category(canonical), actor_country(canonical),
                            )
                            actor_id_by_key[norm_key] = actor_id
                            stats["actors_touched"] += 1
                        await conn.execute(
                            """
                            INSERT INTO analysis_actor (analysis_id, actor_id, raw_mention)
                            VALUES ($1, $2, $3)
                            ON CONFLICT DO NOTHING
                            """,
                            analysis_id, actor_id_by_key[norm_key], raw[:255],
                        )
                        stats["actor_links"] += 1

                    for raw in families:
                        if not isinstance(raw, str):
                            continue
                        stats["family_mentions"] += 1
                        canonical, norm_key = canonicalise_malware(raw)
                        if canonical is None:
                            stats["family_filtered"] += 1
                            continue
                        if norm_key not in family_id_by_key:
                            family_id = await conn.fetchval(
                                """
                                INSERT INTO malware_families
                                    (canonical_name, normalised_key, category)
                                VALUES ($1, $2, $3)
                                ON CONFLICT (normalised_key)
                                  DO UPDATE SET updated_at = now()
                                RETURNING id
                                """,
                                canonical, norm_key,
                                malware_category(canonical),
                            )
                            family_id_by_key[norm_key] = family_id
                            stats["families_touched"] += 1
                        await conn.execute(
                            """
                            INSERT INTO analysis_malware (analysis_id, family_id, raw_mention)
                            VALUES ($1, $2, $3)
                            ON CONFLICT DO NOTHING
                            """,
                            analysis_id, family_id_by_key[norm_key], raw[:255],
                        )
                        stats["family_links"] += 1

            offset += BATCH_SIZE
            if offset % (BATCH_SIZE * 5) == 0:
                print(f"  …{offset}/{total_rows} rows processed")

        # Final reconciliation: how many distinct entities are now in each table
        n_actors = await conn.fetchval("SELECT COUNT(*) FROM threat_actors")
        n_families = await conn.fetchval("SELECT COUNT(*) FROM malware_families")
        n_actor_links = await conn.fetchval("SELECT COUNT(*) FROM analysis_actor")
        n_family_links = await conn.fetchval("SELECT COUNT(*) FROM analysis_malware")

        print("\n=== Backfill summary ===")
        print(f"  Analysis rows scanned:      {stats['rows']}")
        print(f"  Actor mentions seen:        {stats['actor_mentions']}")
        print(f"    Generic-filtered:         {stats['actor_filtered']}")
        print(f"    Linked:                   {stats['actor_links']}")
        print(f"  Malware mentions seen:      {stats['family_mentions']}")
        print(f"    Generic-filtered:         {stats['family_filtered']}")
        print(f"    Linked:                   {stats['family_links']}")
        print()
        print(f"  Distinct threat_actors:     {n_actors}")
        print(f"  Distinct malware_families:  {n_families}")
        print(f"  analysis_actor rows:        {n_actor_links}")
        print(f"  analysis_malware rows:      {n_family_links}")
        print(f"  Completed at:               {datetime.now(UTC).isoformat()}")
    finally:
        await conn.close()

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
