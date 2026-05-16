# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

Post-`0.2.0` work — bug fixes, CI green-up, UI/UX surfacing of the v0.2.0
data model, and a critical regression in the pipeline_runs FK ordering.
Not yet tagged; will roll into `0.3.0` when ready.

### Added

#### UI / dashboard (PR #34, #35)
- Detail drawer now exposes the v0.2.0 analysis fields: `mitigation_strategies`,
  `attack_vectors`, `exploit_references`, `threat_type`, `entry_title`, and a
  provenance footer (`model_id` / `prompt_version` / `pipeline_version` /
  token counts / `latency_ms`).
- **Priority badges** (`P0`/`P1`/`P2`/`P3`) on the top-CVE table, derived
  from CVSS × EPSS × KEV × known-ransomware-use.
- **KEV / ransomware pills** on CVE rows referencing the KEV catalogue.
- **Enriched entity chips** in the drawer: `cves_enriched`, `actors_enriched`,
  `malware_enriched` arrays render with category + country-flag emoji.
- Sortable CVE table, feed filters, keyboard shortcuts.

### Changed

#### Entity curation (PR #36)
- New `_INDIVIDUAL_DENYLIST` in `tiger_eye/entities.py` for researcher /
  journalist names that the LLM occasionally tags as actors (Jann Horn,
  Tavis Ormandy, Brian Krebs, …). Wired into `canonicalise_actor`.
- `_VENDOR_DENYLIST` extended with security-research orgs (Project Zero,
  JFrog, IBM X-Force, Huntress, Wiz, Trustwave, Secureworks, Intel471,
  Dragos, Claroty, Armis), law-enforcement / national agencies (FBI,
  CISA, NSA, Europol, NCSC, national authorities), and forums
  (BreachForums, xss.is, exploit.in).
- `_GENERIC_ACTOR_PATTERNS` regex broadened to catch *X-linked / -nexus
  / -aligned hackers / threat actors / operators* across more countries.
- `_ACTOR_ALIASES` extended with ~25 groups: Turla / Snake / Venomous
  Bear, FamousSparrow, Silk Typhoon / Hafnium, Earth Lamia, UAT-10608,
  APT37 / InkySquid / Reaper, ScarCruft, Contagious Interview,
  MuddyWater, Handala, LAPSUS$, REvil / Sodinokibi (actor), BlackCat /
  ALPHV (actor), GandCrab, Qilin / Agenda, RansomHub, Interlock,
  Storm-1175, UNC6692, Intellexa, NSO Group, Candiru.
- New `hacktivist` and `commercial-spyware` actor categories.
- New `scripts/backfill_actor_categories.py` — one-shot backfill for
  `category` / `attribution_country` columns on existing rows.

### Fixed

#### Pipeline observability — FK ordering bug
- **Critical: `pipeline_runs` row is now created BEFORE analyses are
  persisted.** PR #29 added `analysis.run_id` with `FK → pipeline_runs`,
  but the loop wrote the `pipeline_runs` row only at cycle end — causing
  every `analyse_and_persist` to fail with `ForeignKeyViolationError` on
  `analysis_run_id_fkey`. Symptom in prod: 153 consecutive runs / 0
  enrichments / 500 DLQ failures.
- Split `_write_pipeline_run` into `_create_pipeline_run` (cycle start,
  inserts initial row with `run_id` + `started_at` + static metadata) and
  `_finalize_pipeline_run` (cycle end, UPDATEs with stats / token totals
  / latency percentiles). If the initial create fails, analyses fall back
  to `run_id=None` — the column is nullable specifically for this case.

#### CI green-up (PR #31, #32, #33)
- **Lint stage** green: ruff (`I001` import order, `UP041`
  `asyncio.TimeoutError` → builtin, `SIM105` `try/except: pass` →
  `contextlib.suppress`, `N812` annotated for `PIPELINE_VERSION` dunder
  source); ruff format; mypy.
- **Integration tests**: `test_analysis_table_schema` updated to assert
  that PR #22's restored fields (`attack_vectors`, `exploit_references`,
  `mitigation_strategies`) and PR #29's `run_id` / provenance columns are
  present.
- **Dependency audit**: upgrade pip before `pip-audit` (pip 26.0.1 has
  CVE-2026-3219 / CVE-2026-6357; pip-audit's self-scan was failing CI).

### Companion changes in `tigerfetch`
- **KEV ingestor bug fixed** (PR #15 / #16) — `KevVuln` struct was
  silently dropping `KnownRansomwareCampaignUse` and `CWEs` on JSON
  round-trip. After fix + rebuild + refresh: 318 ransomware-known +
  1,423 CVEs with CWE arrays populated in `tiger2go.public.cve_kev`.

### Pull requests
- #31 — fix(ci): make Lint stage green
- #32 — fix(tests): assert restored analysis columns
- #33 — fix(ci): upgrade pip before pip-audit
- #34 — feat(api): expose v0.2.0 analysis fields in detail drawer
- #35 — feat(ui): priority badges + KEV/ransomware indicators + entity chips
- #36 — chore(entities): pass-2 curation
- #37 — fix(loop): create pipeline_runs row before analyses persist
- _(this PR)_ — chore(provenance): mark pre-PR22 analyses with `legacy-pre-pr22` cohort tag

### Data-quality scripts
- `scripts/backfill_provenance_legacy_cohort.sql` — one-shot: 2,410
  pre-PR22 rows now carry `pipeline_version = prompt_version = 'legacy-pre-pr22'`
  so cohort queries (`SELECT pipeline_version, COUNT(*) FROM analysis GROUP BY 1`)
  cleanly separate v0.1.x output from v0.2.x. `model_id` and `input_hash`
  remain NULL on legacy rows — those values are genuinely unrecoverable.

---

## [0.2.0] - 2026-05-13

The "exceptionally awesome" release. Tier-1 of the no-info-loss / observability /
analyst-experience refit. Eleven items shipped across two sessions; the running
container went from v0.1.0 (loose JSON enrichment, polling-only loop, freeform
actor/malware strings) to v0.2.0 (schema-constrained outputs, sub-second
LISTEN/NOTIFY wakeups, canonical entity model, hybrid retrieval, per-run
observability).

### Added

#### Pipeline observability
- **`pipeline_runs` table** — one row per enrichment cycle with batch_size, enriched/failed counts, prompt/response token totals, p50/p95/max LLM latency, model_id, prompt_version, pipeline_version, wake_source ('notify'|'poll'|'initial'), consecutive_failures
- **`analysis.run_id`** FK linking each enriched row back to its run
- Three analyst-facing views: `v_pipeline_runs_recent`, `v_pipeline_cost_per_day`, `v_pipeline_by_prompt_version`
- **Per-row provenance** on `analysis`: `model_id`, `prompt_version`, `pipeline_version`, `prompt_tokens`, `response_tokens`, `latency_ms`
- **`input_hash`** — SHA-256 of normalised LLM input (title + content + summary). Detects silent feed re-edits and enables idempotent re-enrichment
- **Prometheus metrics**: `tiger_eye_llm_off_vocab_total{field}`, `tiger_eye_llm_tokens_total{model,direction}`, `tiger_eye_listener_notifies_total`, `tiger_eye_listener_connected`

#### Strict structured LLM output
- **OpenAI strict `json_schema` response_format** replaces the loose `json_object` mode. The schema enforces enums on `threat_type` / `severity_level` / IOC `type`, integer bounds on `confidence`, and 19 required fields with `additionalProperties: false`
- `tiger_eye.__version__ = "0.2.0"` captured per analysis row
- `PROMPT_VERSION = "v3"` — A/B-queryable: `SELECT prompt_version, COUNT(*) FROM analysis GROUP BY 1`

#### LISTEN/NOTIFY-driven enrichment
- New `tiger_eye/listener.py` — dedicated asyncpg connection LISTENs on `article_ingested`. Auto-reconnect with exponential backoff; 60s heartbeat probe
- `enrichment_loop` now waits on `asyncio.wait_for(event, timeout=enrich_interval)` — wakes sub-second on tigerfetch ingest, polls every 60s as safety net

#### First-class entity tables
- **`threat_actors`** and **`malware_families`** tables with canonical_name + normalised_key + category + (actors only) ISO 3166-1 attribution_country
- **`analysis_actor`** and **`analysis_malware`** join tables (FK CASCADE on analysis delete, raw_mention preserved for audit)
- **`tiger_eye/entities.py`** canonicaliser with ~80 curated aliases (Vidar / Vidar Stealer → Vidar; Cozy Bear / NOBELIUM → APT29; BlackCat → ALPHV/BlackCat) plus generic-label filter (Attacker, malicious cyber actors, ransomware, infostealer, etc.) and vendor/malware denylist (Anthropic, Qualys, Mirai, Filemanager)
- Five analyst-facing views: `v_top_threat_actors_30d`, `v_top_malware_families_30d`, `v_actor_malware_cooccurrence_90d`, `v_threat_actor_summary`, `v_malware_family_summary`
- Pre-seeded well-known APTs (Volt Typhoon, Lazarus, APT28/29/41, Sandworm, Salt/Flax Typhoon, FIN7, Scattered Spider) with categories + country

#### KEV / CVE change capture (companion in tiger2go)
- **`CveKev`** + **`CveEnrichedHistory`** SQLAlchemy read-only models for the tables tiger2go now provides
- KEV is now first-class — the `source='CISA-KEV'` anti-pattern in `cve_enriched` is dead

#### Restored intel fields
- `analysis.mitigation_strategies` — durable defensive controls (was folded into recommended_actions)
- `analysis.attack_vectors` — *how* the threat reaches the target (had no representation; was pure loss)
- `analysis.exploit_references` — PoC/advisory URLs (was inlined into cve_references)
- `recommended_actions` semantics tightened to *immediate* response only
- `cve_references` semantics tightened to bare CVE IDs only

#### Retrieval
- **Hybrid search** — new `hybrid_search()` SQL function fusing pgvector cosine ranking and Postgres FTS via Reciprocal Rank Fusion. Generated `search_tsv` tsvector (weighted A=entry_title, B=summary_impact, C=embedding_text) with GIN index. `simple` tokeniser so exact CVE IDs / product names / hashes survive intact. Python wrapper `tiger_eye.rag.hybrid_search()`
- **Recency-aware RAG** — `get_similar_analyses` now uses `_vector_search_recency_aware` which combines cosine similarity with `exp(-age_days/30)` recency. Equally-relevant matches rotate toward the newer; the LLM gets the analyst's freshest take on the topic
- Backwards-compatible: `_vector_search` and the `/internal/search/*` public APIs remain pure-semantic

### Changed
- `tiger_eye.recommended_actions` semantics changed (response-only). Existing rows preserved; new rows respect the split.
- `tiger_eye.cve_references` semantics changed (CVE IDs only). Existing rows preserved.
- `_build_llm()` now reads model name from `config.llm_model` instead of hardcoded `gpt-5.4-mini`. Captured as provenance.
- ANALYSIS_PROMPT updated: separates response actions from durable controls; separates CVE IDs from advisory URLs; introduces `attack_vectors` as first-class.

### Fixed
- Entity backfill orphan cleanup (`scripts/cleanup_orphan_entities.py`) — FK ordering bug fixed; analysis_actor / analysis_malware join rows now deleted before parent entity (FK is `ON DELETE RESTRICT`, deliberate).
- Vendor names (Anthropic, Qualys, Unit 42, Cisco Talos Blog) and pure-malware names (Mirai, GlassWorm, Filemanager) no longer leak into `threat_actors` from LLM extraction errors.
- Generic descriptors (`bad actor`, `cybercriminals`, `remote attacker`, `DPRK`, `(country) IT workers`) now filtered at canonicalisation.

### Companion changes in `tiger2go`
- Migration `20260511_create_cve_kev.sql` — first-class CISA KEV table
- Migration `20260512_create_cve_enriched_history.sql` — append-only change-capture log with PL/pgSQL trigger on `cve_enriched`
- Migration `20260513_archive_notify_trigger.sql` — `AFTER INSERT ON archive` fires `pg_notify('article_ingested', NEW.guid)`

### Pull requests
- #22 — Provenance, content-hash, restore lost intel fields
- #23 — LISTEN/NOTIFY listener
- #24 — Recency-aware RAG ranking
- #25 — Entity tables + canonicaliser + 5 views
- #26 — Entity cleanup-script FK fix + vendor/malware denylist
- #27 — Strict JSON-schema response_format with enum constraints
- #28 — Hybrid search (FTS + pgvector via RRF)
- #29 — `pipeline_runs` per-cycle observability

### Migrations
- `004_analysis_provenance_and_lost_fields.sql`
- `005_entity_tables.sql`
- `006_hybrid_search.sql`
- `007_pipeline_runs.sql`

---

## [0.1.0] - Initial

Original tiger-eye release: pgvector-native enrichment with LLM analysis,
RAG context injection, NVD/EPSS lookup, MITRE ATT&CK normalisation, retry
queue, Prometheus metrics, OpenTelemetry tracing, Grafana dashboard.
