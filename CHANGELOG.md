# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
