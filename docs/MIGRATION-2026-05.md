# Migration: prod data lake → tiger2go (May 2026)

**Status:** Phases 1–4 complete. Phase 5 (comparison views) pending.
Phase 6 (optional re-enrichment) deferred.

This document captures the migration off the legacy fly.io-hosted prod
data lake — `tigerblue-db` on `metabrief-db` (Mike Harris / personal
org) — onto the local Go-based **tiger2go** stack. It pairs with the
CHANGELOG entries that record *what* shipped per PR; this document is
the *why* and the *plan*.

---

## 1. Background

The legacy stack was:

| Component | Tech | Role |
|---|---|---|
| `tigerfetch` | Rust | RSS / NVD / EPSS / CISA-KEV ingestor |
| `tigerblue-db` (fly.io managed PG) | Postgres 16.8 Percona | data lake |
| `signalkit` | Django app | multi-tenant analyst console |
| `inspector_findings` schema | (consumer unknown) | SBOM scan output |

The local stack (mid-build through 2026) is:

| Component | Tech | Role |
|---|---|---|
| `tigerfetch` (rewritten) | Go | ingestor — same external feeds |
| `tiger2go_postgres` | Postgres 16.13 + pgvector | data lake |
| `tiger-eye` | Python (FastAPI + async loop) | LLM enrichment of RSS into structured threat-intel |
| `tiger-watch` | Go | watchlist matcher |
| `T2` (née number-2) | Go | alerting / sitrep service |

The new data model is documented in
[`SYSTEM_DESIGN.md`](../SYSTEM_DESIGN.md). The deltas from prod are
substantial — see CHANGELOG `[0.2.0]` for the structured / observable
analysis model, the `cve_kev` first-class table, and the
`pipeline_runs` cost telemetry that prod never had.

---

## 2. Goal

Cut the dependency on the fly.io managed Postgres without losing the
historical data lake. The old corpus is **interesting** in its own
right — 12,463 articles enriched from October 2025 through May 2026
by SOTA LLMs of the period, with whatever errors and biases those
models brought. It's a time capsule. We didn't want to "fix" it; we
wanted to preserve it as-was, alongside the live system that does
things differently now.

Constraints:

- Bit-perfect preservation of the historical lake.
- Side-by-side queryability with the live model (for analyst comparison
  against the legacy corpus).
- No downtime on the live tiger2go / tiger-eye stack.
- Acceptable to lose fly.io as an endpoint — anything that depended on
  the live prod URL had to be migrated or formally retired.

---

## 3. Strategy: "Option D" — Archive + Side-by-Side

Considered four options:

| Option | What | Why not |
|---|---|---|
| A | `pg_dump` to cold storage only | Useful but not queryable from analytical tools |
| B | Read-only fly.io clone, downsized | Still costs $5–10/mo and original endpoint kept; useful if other consumers exist |
| C | Restore into tiger2go as `legacy` schema | Queryable, but if we lose the local box we lose the artefact |
| **D** | **A + C** — cold archive + warm side-by-side | Belt and braces; live SQL comparisons against the new model |

D won. R2 was chosen for cold storage (existing `osint-r2` rclone
remote, S3-compatible, no new account setup).

---

## 4. What was preserved

### 4.1 The cold archive

```
osint-r2:tigerblue-archive/
  tigerblue-prod-20260514T211257Z.tar.zst       441 MB
  tigerblue-prod-20260514T211257Z.tar.zst.meta  1.1 KB
  tigerblue-prod-20260514T211257Z.tar.zst.sha256 106 B
```

- Dump format: `pg_dump --format=directory --jobs=2 --compress=9`,
  packed as `tar | zstd -19`.
- SHA-256: `bf5fe1634eb78d2d4cad8fee38e8427b263a5595675a4873379fd5046d4d9a4b`
- Round-trip validated post-upload (`rclone cat | shasum`).
- Source DB total at dump time: 4,825 MB; compressed archive 441 MB
  (~9.1% of source — vectors and EPSS data have low entropy after zstd).
- Schemas captured: `public` (threat-intel core), `auth` (tenants /
  users), `signalkit` (Django analyst console — investigations,
  briefings, audit_log, RBAC), `inspector_findings` (SBOM scans).
- Schemas skipped: `pgbouncer` (PG internals), `pg_temp_*` (auto).

### 4.2 The warm copy (in tiger2go)

The threat-intel core landed under `legacy.*` in
`tiger2go_postgres.tiger2go`:

| `legacy.<table>` | rows | notes |
|---|---|---|
| `analysis` | 12,463 | every row enriched 2025-10-29 → 2026-05-04 |
| `cve_enriched` | 549,537 | NVD + 1,587 anti-pattern CISA-KEV "source" rows |
| `current` | 12,498 | live-feed entries at snapshot time |
| `archive` | 12,498 | all historical articles |
| `number2_analysis_embedding` | 12,026 | 1536-dim vectors with HNSW index |
| `epss_daily_*` partitions | ~7.9M | EPSS scores Oct'25 → May'26 |
| `epss_weekly_summary` | 625,633 | |
| `epss_monthly_summary` | 313,232 | |
| `number2_*` | various | hourly_sitrep, convergence_facets, html_reports, … |

Schemas **not** restored (documented but inert pending Phase 4b audit
which is moot now that fly.io is gone): `auth`, `signalkit`,
`inspector_findings`. They're still in the R2 dump.

The `auth/signalkit/inspector_findings` schemas had real product
content (Django app with investigations, briefings, audit_log, RBAC).
None of it depended on fly.io for *us* — but anything external that
read from fly.io is now also broken. Cold cutover was a deliberate
choice on 2026-05-16.

---

## 5. Execution log

| Phase | Date | PR / Artefact |
|---|---|---|
| 1 — `pg_dump` + push to R2 + checksum | 2026-05-14 | R2 archive (above) |
| 2 — Restore as `legacy.*` in tiger2go | 2026-05-14/15 | [`scripts/restore_legacy.sh`](../scripts/restore_legacy.sh) |
| 3 — Destroy fly.io postgres | 2026-05-16 | (manual via `fly` CLI) |
| 4a — EPSS materialisation | 2026-05-16 | tiger2go [PR #17](https://github.com/miketigerblue/tiger2go/pull/17) |
| 4b — Downstream-consumer audit | — | moot post-cutover |
| 4c — Provenance cohort backfill | 2026-05-16 | tiger-eye [PR #38](https://github.com/miketigerblue/tiger-eye/pull/38) |
| 4d — DLQ FK regression fix (bonus) | 2026-05-15/16 | tiger-eye [PR #37](https://github.com/miketigerblue/tiger-eye/pull/37) |
| 5 — Comparison views | pending | — |
| 6 — Optional history re-enrichment | deferred | — |

### Phase 2 — restore engineering notes

The restore was non-trivial. Sequence of issues encountered (all
documented in [`scripts/restore_legacy.sh`](../scripts/restore_legacy.sh)):

1. Container's psql 16.13 couldn't read PG-17.4 dump format (1.16) →
   used host's pg_restore 17.4 against container's exposed 5432.
2. Container template1/postgres had collation version 2.41 vs OS 2.36
   → `ALTER DATABASE ... REFRESH COLLATION VERSION` (safe — just
   bookkeeping, no data change).
3. `pg_restore --schema=public` into a scratch DB to filter
   auth/api/signalkit/inspector_findings out cleanly.
4. Filtered TOC dropped EXTENSION lines (postgis/pgaudit/pg_stat_monitor
   not installed locally) and PostGIS-typed objects
   (`spatial_ref_sys`, `geometry_columns`).
5. `ALTER SCHEMA public RENAME TO legacy_temp` in scratch — but then
   pg_dump qualified all extension function/type refs as
   `legacy_temp.uuid_generate_v4()` and `legacy_temp.vector(N)`,
   which don't exist in tiger2go (where uuid-ossp + vector live in
   `public`).
6. Python rewrite filter (BSD `sed` lacks reliable word boundaries) on
   the pg_dump stream: dynamically built from the actual extension
   contents — `pg_proc`/`pg_type`/`pg_opclass`/`pg_opfamily` rows that
   belong to uuid-ossp / vector — rewriting only those references
   back to `public.X`, catchall `legacy_temp.X → legacy.X` for our
   own tables.
7. `transaction_timeout` is a PG-17-only session param — stripped
   from the dump stream.

End state: bit-perfect restore, 24 minutes wall-clock through a
pg_dump → Python → psql pipeline.

---

## 6. Data-quality wins surfaced by the migration

Two were latent in tiger2go and only got fixed because the
side-by-side comparison made them obvious:

| Issue | Before | After | Fix |
|---|---|---|---|
| `cve_enriched.epss` populated | 0 / 351,080 (0%) | 333,455 / 351,080 (95%) | tiger2go PR #17 — `materialize_epss_to_cve_enriched()` function |
| Analyses with provenance | 60 / 2,503 (2.4%) | 2,503 / 2,503 (100%, with `legacy-pre-pr22` cohort tag for old rows) | tiger-eye PR #38 — cohort backfill |
| Enrichment loop alive | 0 of 153 cycles succeeding (FK violation) | back to green | tiger-eye PR #37 — split `pipeline_runs` insert into create/finalize |

---

## 7. Numbers worth quoting

For any future write-up:

- **Source database**: 4,825 MB → archive 441 MB (9.1% via zstd-19)
- **Schemas in prod**: 4 (`public`, `auth`, `signalkit`,
  `inspector_findings`) collapsed to 1 (`public`) in tiger2go's new
  model
- **Indexes on `analysis`**: 3 in prod → 17 in tiger2go (8 GIN on
  jsonb, 1 GIN on tsvector, 5 time-series + cohort btrees, 1 partial,
  1 dedup, 1 composite)
- **Entity normalisation** (the headline artefact):
  - Legacy: **19,902 raw threat-actor mentions** across **7,412
    distinct strings** in `legacy.analysis.potential_threat_actors`
    JSON arrays. Zero categorisation, zero country attribution.
  - New: **484 canonical entities** in `public.threat_actors` after
    aliasing + denylist + curation. 30 categorised, 19 with country.
  - 15× reduction in entity proliferation per article.
- **Pipeline cost attribution**: prod had zero. New stack tracks
  per-row `prompt_tokens` / `response_tokens` / `latency_ms` and
  per-batch totals in `pipeline_runs`. Future LLM-cost reporting
  becomes a SQL query.
- **KEV "demotion"**: prod stored 1,587 KEV entries as
  `cve_enriched(source='CISA-KEV')` — co-mingled with NVD rows, no
  KEV-specific columns. Tiger2go promoted KEV to a first-class table
  with `vendor_project`, `product`, `due_date`, `known_ransomware_use`,
  `cwes[]`, `withdrawn_at` — and indexes on each.

---

## 8. Remaining work

### Phase 5 — comparison views

Create three comparison views in tiger2go that demonstrate the
migration's impact:

- `v_analysis_comparison` — same `guid` enriched by legacy vs current
  (relevant once we re-enrich; currently the corpora don't overlap by
  guid since legacy ran Oct→May, new started Apr→ on different feeds)
- `v_actor_normalisation_demo` — concrete before/after counts
  (`legacy.analysis.potential_threat_actors` JSON vs
  `public.threat_actors` canonical entities)
- `v_kev_demotion` — `legacy.cve_enriched WHERE source='CISA-KEV'` vs
  `public.cve_kev`, showing the fields lost in the old "source"
  encoding

### Phase 6 — optional re-enrichment (deferred)

Replay the 12,463 legacy entries through current tiger-eye for
apples-to-apples comparison. Estimated cost: ~$15–50 in OpenAI usage
depending on prompt size and model. The *uncorrected* legacy corpus
has its own analytical value — it's a snapshot of how SOTA models of
the period responded to threat-intel feeds, warts and all — so the
re-enrichment isn't urgent.

---

## 9. Artefacts and pointers

| Type | Location |
|---|---|
| Cold archive | `osint-r2:tigerblue-archive/tigerblue-prod-20260514T211257Z.tar.zst` |
| Local warm copy | `tiger2go_postgres.tiger2go` schema `legacy.*` |
| Restore script | [`scripts/restore_legacy.sh`](../scripts/restore_legacy.sh) |
| EPSS materialiser | `tiger2go/migrations/20260516_materialize_epss_to_cve_enriched.sql` |
| Provenance backfill | [`scripts/backfill_provenance_legacy_cohort.sql`](../scripts/backfill_provenance_legacy_cohort.sql) |
| PRs (tiger-eye) | #37 (DLQ FK fix), #38 (provenance cohort) |
| PRs (tiger2go) | #15/#16 (KEV ingest fields), #17 (EPSS materialisation) |
| CHANGELOG | [`CHANGELOG.md`](../CHANGELOG.md) `[Unreleased]` |

---

*Compiled across sessions on 2026-05-14 / 15 / 16 by Mike Harris with
Claude Opus 4.7 (1M context).*
