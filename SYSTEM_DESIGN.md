# Tiger-Eye System Design Specification

**Version:** 1.0  
**Date:** 2026-04-14  
**Status:** Live (processing against tiger2go dev stack)  
**Author:** Generated from codebase analysis  

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [System Context (C1)](#2-system-context-c1)
3. [Container View (C2)](#3-container-view-c2)
4. [Component View (C3)](#4-component-view-c3)
5. [Data Architecture](#5-data-architecture)
6. [Enrichment Pipeline](#6-enrichment-pipeline)
7. [RAG Subsystem](#7-rag-subsystem)
8. [LLM Integration](#8-llm-integration)
9. [Internal API](#9-internal-api)
10. [Observability](#10-observability)
11. [Deployment Architecture](#11-deployment-architecture)
12. [Migration System](#12-migration-system)
13. [Testing Strategy](#13-testing-strategy)
14. [Security Considerations](#14-security-considerations)
15. [Performance Characteristics](#15-performance-characteristics)
16. [Failure Modes & Resilience](#16-failure-modes--resilience)
17. [Appendix: Module Dependency Graph](#appendix-a-module-dependency-graph)
18. [Appendix: Database Schema](#appendix-b-database-schema)
19. [Appendix: Live System Snapshot](#appendix-c-live-system-snapshot)

---

## 1. Executive Summary

**Tiger-eye** is a pgvector-native threat intelligence enrichment service. It occupies the middle tier in a three-service pipeline:

```
tiger2go (Go) ──ingest──> Postgres <──enrich── tiger-eye (Python) ──export──> snow-tiger
```

The service reads raw OSINT feed entries from a shared PostgreSQL database, generates LLM-based threat assessments with RAG context from previously enriched entries, and writes structured intelligence back alongside 1536-dimensional vector embeddings -- all within Postgres using pgvector. There is no external vector store.

**Key design decisions:**

| Decision | Rationale |
|----------|-----------|
| pgvector over ChromaDB | Single database for relational + vector queries; ACID semantics; no operational overhead of a second data store |
| Shared database, separate tables | tiger2go owns `archive`/`current`/`cve_enriched`; tiger-eye owns `analysis`/`analysis_embedding`. Read-only access to upstream tables; clean ownership boundaries |
| Async-first (asyncio + asyncpg) | High concurrency on I/O-bound workloads (LLM calls, DB queries, embedding API); bounded by semaphore |
| Lazy configuration singletons | `@lru_cache` on `get_settings()`, `_get_engine()`, `_get_session_factory()` -- instantiation deferred to first call, enabling test isolation via import-time safety |
| Structured JSON logging + Prometheus + OpenTelemetry | Three-pillar observability from day one; all optional/degradable in dev |

**Codebase at a glance:**

| Metric | Value |
|--------|-------|
| Python source (tiger_eye/) | 1,535 lines across 10 modules |
| Test code (tests/) | 721 lines across 3 test files (37 tests) |
| SQL migrations | 87 lines |
| Total | 2,343 lines |

---

## 2. System Context (C1)

```
                          +-----------------+
                          |    RSS/Atom     |
                          |    Feeds (20+)  |
                          +--------+--------+
                                   |
                          +--------v--------+
                          |    tiger2go     |
                          |   (Go ingestor) |
                          |   Port: 9101    |
                          +--------+--------+
                                   |  writes
                          +--------v--------+
                          |                 |
                          |   PostgreSQL    |          +------------------+
                          |   16 + pgvector |          |     NVD / CISA   |
                          |   0.8.2         |<---------+     KEV / EPSS   |
                          |                 |  cve_enriched  (via tiger2go)
                          +----+-------+----+
                               |       |
                    reads      |       |  reads + writes
                  (archive,    |       |  (analysis, analysis_embedding)
                   cve_enriched)|       |
                          +----v-------v----+
                          |                 |
       +------------------+   tiger-eye     +------------------+
       |                  |   (Python)      |                  |
       |                  |   Port: 8080    |                  |
       |                  +--------+--------+                  |
       |                           |                           |
       v                           v                           v
+------+------+          +---------+---------+          +------+-------+
|   OpenAI    |          |    Prometheus     |          |  snow-tiger  |
|  Embeddings |          |    + Grafana      |          |  (downstream |
|  + LLM API  |          |    Port: 9090/3k  |          |   consumer)  |
+-------------+          +-------------------+          +--------------+
```

**External dependencies:**

| System | Protocol | Purpose | Failure impact |
|--------|----------|---------|----------------|
| PostgreSQL 16 + pgvector | TCP/5432 (asyncpg) | Data lake (shared with tiger2go) | Service cannot start; /health returns 503 |
| OpenAI API | HTTPS | text-embedding-3-small (1536d) + gpt-5.4-mini (analysis) | Enrichment fails with retry; existing data still queryable |
| Prometheus | HTTP scrape on /metrics | Metrics collection | Metrics not collected; service unaffected |
| OTLP Collector | gRPC (optional) | Distributed tracing export | Tracing silently disabled; service unaffected |

---

## 3. Container View (C2)

Tiger-eye runs as a **single container** with two concurrent execution paths:

```
                    tiger-eye container
           +--------------------------------+
           |                                |
           |  +--------------------------+  |
           |  |   FastAPI (uvicorn)      |  |
           |  |   Port 8080             |  |
           |  |                          |  |
           |  |  GET  /health            |  |
           |  |  POST /internal/search/* |  |
           |  |  GET  /internal/node/{id}|  |
           |  |  GET  /metrics           |  |
           |  +--------------------------+  |
           |                                |
           |  +--------------------------+  |
           |  |   Enrichment Loop        |  |
           |  |   (asyncio background    |  |
           |  |    task in lifespan)     |  |
           |  |                          |  |
           |  |  Poll every 60s          |  |
           |  |  Batch size: 20          |  |
           |  |  Concurrency: 5          |  |
           |  |  Exponential backoff     |  |
           |  +--------------------------+  |
           |                                |
           +--------------------------------+
                        |
              +---------+---------+
              |                   |
      +-------v------+   +-------v-------+
      |  PostgreSQL  |   |   OpenAI API  |
      |  (tiger2go)  |   |  Embeddings   |
      |  asyncpg     |   |  + LLM        |
      +--------------+   +---------------+
```

**Why a single container with background task (not a separate worker)?**
- The enrichment loop and API share the same database connection pool and settings
- No message broker needed; the database IS the queue (poll-based)
- Simplifies deployment: one container, one health check, one set of metrics
- The `asyncio.Semaphore(5)` provides backpressure without external coordination

---

## 4. Component View (C3)

### Module responsibilities and dependency flow

```
config.py ─────────────────────────────────────────────────────────┐
  EMBEDDING_DIMENSIONS = 1536                                      │
  Settings (pydantic-settings, @lru_cache)                         │
  get_settings()                                                   │
     │                                                             │
     ├──> database.py                                              │
     │      _get_engine() / _get_session_factory() (@lru_cache)    │
     │      get_db() -> async context manager -> AsyncSession      │
     │      ORM models: ArchiveEntry, AnalysisEntry,               │
     │                  AnalysisEmbedding, CveEnriched              │
     │           │                                                 │
     ├──> embedding.py                                             │
     │      generate_embedding() -> OpenAI text-embedding-3-small  │
     │      build_embedding_text() -> deterministic doc text       │
     │           │                                                 │
     ├──> rag.py                                                   │
     │      _vector_search() -> pgvector <=> cosine distance       │
     │      get_similar_analyses() -> RAG context for LLM prompt   │
     │      search_by_text() / search_by_vector() -> API use       │
     │           │                                                 │
     ├──> analysis.py                                              │
     │      ANALYSIS_PROMPT (grounded threat intel prompt)         │
     │      lookup_cve_context() -> CVSS/EPSS from cve_enriched   │
     │      normalise_analysis() -> validate + coerce LLM output   │
     │      analyse_and_persist() -> full 6-step pipeline          │
     │           │                                                 │
     ├──> main.py                                                  │
     │      FastAPI app + lifespan                                 │
     │      enrichment_loop() (background task)                    │
     │      API endpoints (/health, /internal/*)                   │
     │           │                                                 │
     ├──> metrics.py ── Prometheus counters/histograms/gauges      │
     ├──> logging_config.py ── structlog JSON configuration        │
     ├──> tracing.py ── OpenTelemetry TracerProvider + instruments  │
     └──> migrate.py ── standalone CLI migration runner            │
```

### Module coupling matrix

| Module | Imports from |
|--------|-------------|
| `config` | (none -- leaf) |
| `database` | `config` |
| `embedding` | `config`, `metrics` |
| `rag` | `database`, `embedding`, `metrics` |
| `analysis` | `config`, `database`, `embedding`, `rag`, `metrics`, `tracing` |
| `main` | `config`, `database`, `analysis`, `rag`, `metrics`, `logging_config`, `tracing` |
| `metrics` | (none -- leaf) |
| `logging_config` | (none -- leaf) |
| `tracing` | (none -- leaf) |
| `migrate` | `config` |

**Key insight:** `config`, `metrics`, `logging_config`, and `tracing` are leaf modules with zero internal dependencies. `analysis` is the most connected module (6 imports) because it orchestrates the entire enrichment pipeline.

---

## 5. Data Architecture

### 5.1 Ownership model

```
+------------------+     +-------------------+     +------------------+
|    tiger2go      |     |   tiger-eye       |     |   snow-tiger     |
|    (writer)      |     |   (reader+writer) |     |   (reader)       |
+------------------+     +-------------------+     +------------------+
        |                         |                         |
        v                         v                         v
  +-----------+           +-------------+            (reads analysis)
  | archive   | (read) -> | analysis    |
  | current   |           | analysis_   |
  | cve_raw   |           |  embedding  |
  | cve_enr.  | (read) -> |             |
  | epss_daily|           +-------------+
  +-----------+
```

### 5.2 Table details

#### `analysis` — LLM-enriched threat assessments

| Column group | Fields | Purpose |
|-------------|--------|---------|
| Identity | `id` (UUID PK), `guid` (UNIQUE, FK-like to archive) | Deduplication via guid; UUID for internal references |
| Classification | `threat_type`, `severity_level`, `confidence` | Threat taxonomy (10 types), 5-level severity, 0-100 confidence score |
| Narrative | `summary_impact`, `relevance`, `historical_context`, `additional_notes` | LLM-generated prose text fields |
| Structured Intel (JSONB) | `key_iocs`, `ttps`, `cve_references`, `potential_threat_actors`, `tools_used`, `malware_families`, `target_geographies`, `recommended_actions`, `affected_systems_sectors` | Machine-readable intelligence; GIN-indexed for containment queries |
| Source metadata | `entry_title`, `source_name`, `source_url`, `feed_*` | Provenance tracking back to original feed entry |
| Timestamps | `analysed_at`, `enriched_at`, `inserted_at` | Audit trail |
| Embedding source | `embedding_text` | Deterministic text used to generate the vector; stored for reproducibility |

**Index strategy:**
- B-tree on `guid` (UNIQUE), `threat_type`, `severity_level`, `analysed_at DESC`, `inserted_at DESC`
- GIN on `cve_references`, `key_iocs`, `ttps`, `potential_threat_actors` for JSONB `@>` containment queries

#### `analysis_embedding` — vector storage (1:1 with analysis)

| Field | Type | Notes |
|-------|------|-------|
| `analysis_id` | UUID (PK + FK) | CASCADE delete from analysis |
| `embedding` | vector(1536) | OpenAI text-embedding-3-small output |
| `model` | TEXT | Model identifier for reproducibility |
| `created_at` | TIMESTAMPTZ | Temporal queries |

**HNSW index:** `m=16`, `ef_construction=64`, `vector_cosine_ops` -- provides sub-millisecond approximate nearest-neighbor search at scale.

### 5.3 Why separate tables for embeddings?

1. **Query performance:** The 1536-dimension vector is ~6KB per row. Keeping it in a separate table means `SELECT * FROM analysis` doesn't drag vectors into memory
2. **HNSW index isolation:** The HNSW index only covers the embedding table; B-tree/GIN indexes on analysis aren't affected by vector operations
3. **Model versioning:** When switching embedding models, you can rebuild `analysis_embedding` without touching `analysis`
4. **CASCADE semantics:** Delete an analysis and the embedding is automatically cleaned up

---

## 6. Enrichment Pipeline

### 6.1 Lifecycle

```
        enrichment_loop() [main.py]
               |
               v
    +-----------------------+
    | SELECT archive        |
    | LEFT JOIN analysis    |
    | WHERE analysis IS NULL|  "find unprocessed entries"
    | ORDER BY inserted_at  |
    | LIMIT 20              |
    +-----------------------+
               |
               v
    +---------------------+
    | asyncio.Semaphore(5)|  bounded concurrency
    | asyncio.gather()    |
    +---------------------+
         |   |   |   |   |
         v   v   v   v   v
    analyse_and_persist() [analysis.py]  (x5 concurrent)
         |
         v  Step 1: RAG Context
    get_similar_analyses()
         |
         v  Step 2: NVD Context
    lookup_cve_context()
         |
         v  Step 3: LLM Analysis
    ChatOpenAI.ainvoke() [gpt-5.4-mini]
         |                  retry: 2 attempts
         |                  backoff: 2s, 4s
         v  Step 4: Normalisation
    normalise_analysis()
         |
         v  Step 5: Embedding
    generate_embedding() [text-embedding-3-small]
         |                  retry: 2 attempts
         v  Step 6: Persist
    db.add(analysis + embedding)
    db.commit()
```

### 6.2 Backoff strategy

The enrichment loop implements a **streak-based exponential backoff** to avoid hammering external APIs during outages:

```python
delay = min(2 ** consecutive_failures, 300)  # caps at 5 minutes
```

| Consecutive failures | Delay (seconds) |
|---------------------|-----------------|
| 0 | 0 (normal interval) |
| 1 | 2 |
| 2 | 4 |
| 3 | 8 |
| 5 | 32 |
| 8 | 256 |
| 9+ | 300 (cap) |

The streak resets to 0 as soon as any entry in a batch succeeds. This distinguishes between "OpenAI is down" (all fail, back off) and "some entries are malformed" (partial success, keep going).

### 6.3 Normalisation rules

The `normalise_analysis()` function enforces invariants on LLM output:

| Field | Rule | Default |
|-------|------|---------|
| `threat_type` | Must be one of 10 valid enum values | `"OTHER"` |
| `severity_level` | Must be one of 5 valid levels | `"INFORMATIONAL"` |
| `confidence` | Integer, clamped to 0-100 | `0` |
| `key_iocs` | List of `{"type": str, "value": str}` dicts | `[]` |
| `ttps` | List of `{"id": str, "name": str}` dicts | `[]` |
| Text fields | `None` or `[]` coerced to `""` | `""` |
| List fields | `None` coerced to `[]`; JSON strings parsed | `[]` |

This ensures the database schema contract is always met regardless of LLM output variability.

---

## 7. RAG Subsystem

### 7.1 Architecture

Tiger-eye uses **retrieval-augmented generation** to inject context from previously enriched entries into the LLM prompt. This enables the model to recognise recurring campaigns, link related IOCs, and provide more consistent severity assessments.

```
                     New entry to enrich
                           |
                           v
              +----------------------------+
              |  build query text from     |
              |  title + summary + content |
              |  (truncated to 8000 chars) |
              +----------------------------+
                           |
                           v
              +----------------------------+
              |  generate_embedding()      |
              |  text-embedding-3-small    |
              +----------------------------+
                           |
                           v
              +----------------------------+
              |  _vector_search()          |
              |  pgvector <=> cosine dist  |
              |  WHERE distance < 0.45     |
              |  LIMIT 3                   |
              +----------------------------+
                           |
                           v
              +----------------------------+
              |  Format as context block   |
              |  with token budget (1500)  |
              |  Inject into LLM prompt    |
              +----------------------------+
```

### 7.2 Distance threshold

`MAX_RAG_DISTANCE = 0.45` -- cosine distance. Anything above is considered noise and excluded. This prevents the LLM from being confused by tangentially related entries.

For reference, cosine distance thresholds with text-embedding-3-small:
- `< 0.15`: Near-duplicate content
- `0.15 - 0.30`: Same topic/vulnerability
- `0.30 - 0.45`: Related domain (e.g., same software vendor)
- `> 0.45`: Likely unrelated

### 7.3 Token budget

RAG context is allocated a **1500-token budget** (~6000 characters). Each similar entry is formatted as:

```
[Similar threat -- HIGH, confidence=85, distance=0.123]
{embedding_text snippet, max 400 tokens}
```

Entries are added in distance order until the budget is exhausted, ensuring the most relevant context always fits.

### 7.4 SQL query

```sql
SELECT a.id, a.guid, a.severity_level, a.confidence,
       a.summary_impact, a.source_name, a.source_url,
       a.analysed_at, a.embedding_text,
       e.embedding <=> CAST(:vec AS vector) AS distance
FROM analysis_embedding e
JOIN analysis a ON a.id = e.analysis_id
WHERE e.embedding <=> CAST(:vec AS vector) < :max_dist
ORDER BY e.embedding <=> CAST(:vec AS vector)
LIMIT :n
```

**Note:** Uses `CAST(:vec AS vector)` instead of `::vector` cast syntax due to asyncpg parameter binding conflict with PostgreSQL's `::` cast operator.

---

## 8. LLM Integration

### 8.1 Model configuration

| Parameter | Value |
|-----------|-------|
| Model | `gpt-5.4-mini` |
| Temperature | `0.0` (deterministic) |
| Response format | `{"type": "json_object"}` (enforced structured output) |
| Client | `langchain_openai.ChatOpenAI` |

### 8.2 Prompt design

The analysis prompt follows a **grounded extraction** pattern:

1. **Grounding rules** (prevent hallucination):
   - "Only extract indicators, actors, TTPs, and CVEs that are EXPLICITLY mentioned"
   - "If the entry is not a threat report, set threat_type to INFORMATIONAL"

2. **Context injection** (dynamic):
   - RAG context block (similar past analyses)
   - NVD context block (CVSS/EPSS scores for referenced CVEs)

3. **Source material**:
   - Entry metadata (title, link, published, author, feed, categories)
   - Content (truncated to 4000 chars) and summary (truncated to 2000 chars)

4. **Output specification** (18 fields):
   - Enumerated types for classification fields
   - Structured object formats for IOCs and TTPs with examples
   - "Return ONLY valid JSON. No markdown, no explanation."

### 8.3 Threat type taxonomy

| Type | Description |
|------|-------------|
| `VULNERABILITY` | CVE, exploit, vulnerability disclosure |
| `MALWARE` | Malware analysis, new strain discovery |
| `APT_CAMPAIGN` | Advanced persistent threat campaign |
| `DATA_BREACH` | Data leak, breach disclosure |
| `DDOS` | Distributed denial of service |
| `RANSOMWARE` | Ransomware operation |
| `SUPPLY_CHAIN` | Supply chain attack |
| `POLICY` | Security policy, regulation, guidance |
| `INFORMATIONAL` | Non-threat content (news, opinion, conference) |
| `OTHER` | Unclassifiable threat content |

### 8.4 Embedding strategy

The embedding text is deterministically constructed from the analysis result (not the raw entry content). This means the vector represents the **enriched intelligence**, not just the raw feed text:

```
Title: [webapps] Redis 8.0.2 - RCE
URL: https://www.exploit-db.com/exploits/52477
Published: 2025-03-11
Feed: Exploit-DB Updates
Threat Type: VULNERABILITY
Severity: HIGH
Confidence: 72
Summary: The Redis 8.0.2 vulnerability allows...
CVE References: CVE-2025-XXXXX
IOCs: domain:evil.example.com, hash_sha256:abc123...
TTPs: T1190 Exploit Public-Facing Application
Threat Actors: Unknown
...
```

This approach means searching for "Redis RCE" returns results ranked by their assessed threat profile, not just keyword similarity.

---

## 9. Internal API

### 9.1 Endpoints

| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| `GET` | `/health` | Liveness + readiness probe | None |
| `POST` | `/internal/search/text` | Semantic search by natural language query | None (internal) |
| `POST` | `/internal/search/vector` | Nearest-neighbor search by pre-computed embedding | None (internal) |
| `GET` | `/internal/node/{node_id}` | Retrieve single analysis by UUID | None (internal) |
| `GET` | `/metrics` | Prometheus metrics scrape endpoint | None |
| `GET` | `/docs` | Swagger UI (auto-generated) | None |

### 9.2 Health endpoint detail

```json
{
  "status": "ok",
  "analyses": 120,
  "embeddings": 120,
  "loop_running": true,
  "consecutive_failures": 0
}
```

Returns **503** if the database is unreachable. The `loop_running` and `consecutive_failures` fields expose enrichment pipeline health for external monitoring.

### 9.3 Search response shape

Both search endpoints return:

```json
[
  {
    "id": "uuid",
    "guid": "https://...",
    "severity_level": "HIGH",
    "confidence": 85,
    "summary_impact": "...",
    "source_name": "Exploit-DB Updates",
    "source_url": "https://...",
    "analysed_at": "2026-04-14T21:57:13Z",
    "embedding_text": "...",
    "distance": 0.123
  }
]
```

---

## 10. Observability

### 10.1 Three-pillar architecture

```
                  tiger-eye container
    +-----------------------------------------+
    |                                         |
    |  structlog ──> stdout (JSON)            |  LOGGING
    |      timestamp, level, event,           |
    |      logger, extras, exceptions         |
    |                                         |
    |  prometheus_client ──> /metrics         |  METRICS
    |      counters, histograms, gauges       |
    |                                         |
    |  opentelemetry ──> OTLP gRPC           |  TRACING
    |      (optional; console fallback)       |
    |      auto: FastAPI + SQLAlchemy         |
    |      manual: analyse_and_persist span   |
    |                                         |
    +-----------------------------------------+
           |              |              |
           v              v              v
    Docker logs      Prometheus       Jaeger/Tempo
    (or ELK/Loki)   + Grafana        (optional)
```

### 10.2 Prometheus metrics inventory

#### Enrichment pipeline

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `tiger_eye_entries_enriched_total` | Counter | `threat_type`, `severity_level` | Successfully enriched entries |
| `tiger_eye_entries_failed_total` | Counter | `stage` (llm/embedding/persist) | Failed entries by failure stage |
| `tiger_eye_entries_skipped_total` | Counter | -- | Entries skipped (no content) |
| `tiger_eye_batch_size` | Histogram | -- | Entries per enrichment cycle |
| `tiger_eye_consecutive_failures` | Gauge | -- | Current backoff streak |
| `tiger_eye_loop_running` | Gauge | -- | 1 if enrichment loop is active |

#### OpenAI API

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `tiger_eye_llm_latency_seconds` | Histogram | -- | LLM call duration (p50/p95/p99) |
| `tiger_eye_embedding_latency_seconds` | Histogram | -- | Embedding call duration |
| `tiger_eye_llm_retries_total` | Counter | -- | LLM retry count |
| `tiger_eye_embedding_retries_total` | Counter | -- | Embedding retry count |

#### RAG

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `tiger_eye_rag_queries_total` | Counter | -- | Total RAG queries issued |
| `tiger_eye_rag_hits_total` | Counter | -- | Queries that returned results |
| `tiger_eye_rag_empty_total` | Counter | -- | Queries with no results |

### 10.3 Grafana dashboard

A provisioned dashboard (`grafana/dashboards/tiger-eye.json`) provides 16 panels across 4 rows:

| Row | Panels |
|-----|--------|
| **Overview** | Loop status gauge, failure streak, enrichment rate (5m), lifetime totals, retry totals |
| **Enrichment Pipeline** | Enriched by threat type (stacked), by severity (color-coded), failures by stage, batch size distribution |
| **OpenAI Latency** | LLM p50/p95/p99, embedding p50/p95/p99, retry rate, backoff streak timeline |
| **RAG Pipeline** | Query volume, hit rate gauge (0-100%), threat type donut chart |

### 10.4 Structured logging

All log output is JSON-formatted via structlog, with consistent fields:

```json
{
  "event": "Enriched entry",
  "logger": "tiger_eye.analysis",
  "level": "info",
  "guid": "https://www.exploit-...",
  "title": "[webapps] Redis 8.0.2 - RCE",
  "threat_type": "VULNERABILITY",
  "severity": "HIGH",
  "confidence": 72,
  "timestamp": "2026-04-14T21:57:18.082439Z"
}
```

Noisy third-party loggers (`httpcore`, `httpx`, `openai`) are suppressed to WARNING level.

---

## 11. Deployment Architecture

### 11.1 Local development (current)

```
tiger2go stack (docker-compose)          tiger-eye stack (docker-compose)
+------------------------------------+   +---------------------------+
| db         (pgvector/pgvector:pg16)|   | tiger-eye                 |
| tigerfetch (Go binary)            |   |   (python:3.11-slim)     |
| prometheus (prom/prometheus)      |   |   joins tiger2go_net     |
| grafana    (grafana/grafana)      |   |   port: 8080             |
+------------------------------------+   +---------------------------+
         tiger2go_tiger2go_net (shared Docker bridge network)
```

### 11.2 Production (Fly.io)

Tiger-eye is deployed to **Fly.io Amsterdam (ams)** region, connecting to a managed PostgreSQL instance. The production enricher (osint-enricher) runs in the same region.

### 11.3 Container build

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt
COPY tiger_eye/ tiger_eye/
CMD ["python", "-m", "tiger_eye.main"]
```

Image size: ~393 MB (slim base + ML/AI libraries dominate)

### 11.4 .dockerignore

Excludes `.git/`, `.env`, `__pycache__/`, `venv/`, `tests/`, `*.md`, `Dockerfile`, `docker-compose.yml` -- keeps the build context minimal and prevents secret leakage into the image.

---

## 12. Migration System

### 12.1 Design

Custom migration runner (`tiger_eye/migrate.py`) using raw asyncpg (not SQLAlchemy):

```
migrations/
  001_analysis_pgvector.sql    CREATE EXTENSION vector; CREATE TABLE analysis, analysis_embedding
  ...
```

**Tracking table:** `_migrations` with columns `filename` (PK), `sha256`, `applied_at`.

**Safety features:**
- SHA-256 checksums detect post-apply modifications
- `--dry-run` mode previews pending migrations without executing
- `--status` shows applied/pending state for all migration files
- Files are applied in filename-sorted order
- Each migration runs in a transaction

### 12.2 Why not Alembic?

1. The schema is simple (2 tables) and unlikely to undergo frequent changes
2. Alembic adds complexity for auto-generation of pgvector DDL (vector types, HNSW indexes)
3. The tiger2go stack already uses Goose (Go); keeping a lightweight custom runner maintains consistency in philosophy
4. The `_migrations` table with SHA-256 verification provides sufficient auditability

---

## 13. Testing Strategy

### 13.1 Test pyramid

```
            +-------------------+
            |   Integration     |  7 tests
            |   (real Postgres  |  (auto-skip without DATABASE_URL)
            |    + pgvector)    |
            +-------------------+
           /                     \
    +-------------+    +-------------+
    |   API       |    |   Unit      |  22 tests (normalisation,
    |   (httpx    |    |   (pure     |   embedding text, etc.)
    |    ASGI)    |    |    logic)   |
    +-------------+    +-------------+
      8 tests
```

### 13.2 Test categories

**Unit tests** (`test_analysis.py`, 22 tests):
- `normalise_analysis()` -- threat type validation, severity validation, confidence clamping, IOC structuring, TTP structuring, list coercion, text field coercion
- `build_embedding_text()` -- field inclusion, empty field handling

**API tests** (`test_api.py`, 8 tests):
- Health endpoint (200 OK, 503 on DB failure)
- Node lookup (400 invalid UUID, 404 not found, 200 with embedding flag)
- Search text/vector (mock RAG, result passthrough)
- Validation (n_results bounds enforcement)

**Integration tests** (`test_integration.py`, 7 tests):
- DB connectivity, pgvector extension presence
- Schema verification (expected columns exist, dropped columns don't)
- ORM roundtrip (insert + read back all fields including JSONB)
- CASCADE delete verification
- Vector search accuracy (same vector = near-zero distance)
- Migration tracking table populated

### 13.3 CI-ready test harness

`docker-compose.test.yml` provides a self-contained test environment:

```yaml
services:
  postgres:
    image: pgvector/pgvector:pg16
    # ephemeral, no named volume
  test-runner:
    build: .
    command: >
      sh -c "pip install pytest pytest-asyncio httpx &&
             python -m tiger_eye.migrate &&
             python -m pytest tests/ -v --tb=short"
```

Usage: `docker compose -f docker-compose.test.yml up --build --abort-on-container-exit`

---

## 14. Security Considerations

### 14.1 Secrets management

| Secret | Storage | Notes |
|--------|---------|-------|
| `OPENAI_API_KEY` | `.env` file (gitignored) | Validated at startup via pydantic `model_validator` -- service refuses to start with empty key |
| `DATABASE_URL` | `.env` file (gitignored) | Contains credentials for Postgres |
| Docker image | `.dockerignore` excludes `.env` | Secrets never baked into image layers |

### 14.2 Input validation

- All LLM output goes through `normalise_analysis()` before database insertion
- Enum fields are validated against allowlists (threat_type, severity_level)
- Integer fields are bounded (confidence 0-100)
- JSONB fields are structurally normalised (IOCs, TTPs)
- Text fields from LLM are coerced from unexpected types (list -> string)

### 14.3 SQL injection prevention

- All queries use SQLAlchemy parameterised bindings (`:param` syntax with `sql_text()`)
- No string concatenation in SQL construction
- The `_SEARCH_SQL` query uses `CAST(:vec AS vector)` for safe type casting

### 14.4 Network isolation

- Tiger-eye joins the tiger2go Docker network (bridge mode)
- No ports are exposed except 8080 (internal API)
- The API is prefixed `/internal/` to signal it's not public-facing

---

## 15. Performance Characteristics

### 15.1 Throughput

| Operation | Latency (typical) | Concurrency |
|-----------|--------------------|-------------|
| LLM analysis (gpt-5.4-mini) | 2-5s per entry | 5 concurrent (semaphore) |
| Embedding generation | 0.2-0.5s per entry | Per-entry within pipeline |
| pgvector search (HNSW) | < 10ms | Shared connection pool |
| Database persist (analysis + embedding) | < 50ms | Single transaction |
| **Full pipeline per entry** | **~3-6s** | **Effective: ~20 entries in ~20s** |
| **Enrichment rate** | **~60 entries/min** | Limited by batch_size=20, interval=60s |

### 15.2 Database connection pool

| Parameter | Value |
|-----------|-------|
| `pool_size` | 10 |
| `max_overflow` | 20 |
| `pool_recycle` | 1800s (30 min) |
| Driver | asyncpg (binary protocol) |

### 15.3 HNSW index parameters

| Parameter | Value | Trade-off |
|-----------|-------|-----------|
| `m` | 16 | Higher = better recall, more memory |
| `ef_construction` | 64 | Higher = better index quality, slower build |
| Distance metric | Cosine (`vector_cosine_ops`) | Natural for normalised text embeddings |

---

## 16. Failure Modes & Resilience

| Failure | Impact | Mitigation |
|---------|--------|------------|
| **OpenAI API down** | All LLM + embedding calls fail | 2 retries per call with exponential backoff; batch-level streak backoff up to 5 min; /health still returns 200 |
| **OpenAI rate limit** | Temporary 429 errors | Retry with exponential backoff; semaphore(5) limits concurrent requests |
| **PostgreSQL down** | Service cannot read or write | /health returns 503; enrichment loop catches and logs; backoff engaged |
| **Malformed LLM output** | JSON parse failure or type mismatch | `normalise_analysis()` coerces all fields; try/except around JSON parse triggers retry |
| **pgvector query failure** | RAG context unavailable | Caught in `get_similar_analyses()`; enrichment continues without RAG context (graceful degradation) |
| **Entry has no content** | Nothing to analyse | Skipped with `ENTRIES_SKIPPED` counter; logged as warning |
| **Embedding dimension mismatch** | Insert fails with vector size error | `EMBEDDING_DIMENSIONS = 1536` is a single constant shared between config, ORM, and migration |
| **Migration checksum mismatch** | Detects post-apply SQL modification | Migration runner refuses to proceed; requires manual resolution |
| **Container OOM** | Process killed | Docker restart policy `unless-stopped`; stateless design means restart is safe |

### Graceful degradation hierarchy

```
Full pipeline:    RAG -> NVD -> LLM -> Embed -> Persist
No RAG data:      (skip) -> NVD -> LLM -> Embed -> Persist     (first entries have no context)
No CVE matches:   RAG -> (skip) -> LLM -> Embed -> Persist     (non-CVE entries)
No OTLP endpoint: Tracing silently disabled                     (always)
No Prometheus:    Metrics exposed but not scraped                (always)
```

---

## Appendix A: Module Dependency Graph

```
                    ┌──────────────┐
                    │   config.py  │
                    │  (settings)  │
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
       ┌──────v─────┐ ┌───v────┐ ┌─────v──────┐
       │ database.py│ │metrics │ │ migrate.py │
       │  (ORM +    │ │  .py   │ │  (CLI)     │
       │  sessions) │ │ (leaf) │ └────────────┘
       └──────┬─────┘ └───┬───┘
              │            │
       ┌──────v─────┐     │
       │embedding.py├─────┘
       │ (OpenAI)   │
       └──────┬─────┘
              │
       ┌──────v─────┐
       │  rag.py    │
       │ (pgvector) │
       └──────┬─────┘
              │
       ┌──────v──────┐     ┌──────────────┐   ┌───────────┐
       │ analysis.py │────>│ tracing.py   │   │logging_   │
       │ (pipeline)  │     │ (OTel, leaf) │   │config.py  │
       └──────┬──────┘     └──────────────┘   │ (leaf)    │
              │                                └─────┬─────┘
       ┌──────v──────┐                               │
       │  main.py    ├───────────────────────────────┘
       │ (FastAPI +  │
       │  loop)      │
       └─────────────┘
```

---

## Appendix B: Database Schema

### Entity-Relationship Diagram

```
+------------------+          +--------------------+
|    archive       |          |    analysis         |
|  (tiger2go owns) |          |  (tiger-eye owns)   |
+------------------+          +--------------------+
| id       UUID PK |          | id       UUID PK   |
| guid     TEXT UQ  |--guid-->| guid     TEXT UQ    |
| title    TEXT     |         | threat_type TEXT     |
| link     TEXT     |         | severity_level TEXT  |
| published TS     |         | confidence INT       |
| content  TEXT     |         | summary_impact TEXT  |
| summary  TEXT     |         | relevance TEXT       |
| author   TEXT     |         | historical_ctx TEXT  |
| categories TEXT[] |         | additional_notes TEXT|
| feed_url TEXT     |         | key_iocs JSONB      |
| feed_title TEXT   |         | ttps JSONB           |
| inserted_at TS   |         | cve_references JSONB |
+------------------+          | threat_actors JSONB  |
                              | tools_used JSONB     |
+------------------+          | malware_fam JSONB    |
|  cve_enriched    |          | target_geo JSONB     |
| (tiger2go owns)  |          | rec_actions JSONB    |
+------------------+          | affected_sys JSONB   |
| cve_id TEXT  PK  |          | embedding_text TEXT  |
| source TEXT  PK  |          | analysed_at TSTZ    |
| json   JSONB     |          | inserted_at TSTZ    |
| cvss_base NUM    |          +----------+----------+
| epss      NUM    |                     |
+------------------+                     | 1:1 (CASCADE)
                                         |
                              +----------v-----------+
                              |  analysis_embedding   |
                              +-----------------------+
                              | analysis_id UUID PK/FK|
                              | embedding vector(1536)|
                              | model TEXT             |
                              | created_at TSTZ        |
                              +-----------------------+
                                [HNSW cosine index]
```

---

## Appendix C: Live System Snapshot

*Captured 2026-04-14 while tiger-eye is actively enriching against the tiger2go dev stack.*

### Pipeline health

```json
{
  "status": "ok",
  "analyses": 120,
  "embeddings": 120,
  "loop_running": true,
  "consecutive_failures": 0
}
```

### Data volumes

| Table | Records | Notes |
|-------|---------|-------|
| `archive` | 1,352 | Feed entries from 20+ sources |
| `analysis` | 120 | 8.9% enriched (processing in progress) |
| `analysis_embedding` | 120 | 100% of analyses have embeddings |
| `cve_enriched` | 344,560 | NVD vulnerability data |
| `epss_daily` | ~2.7M | Partitioned by month (March + April 2026) |

### Enrichment distribution (live)

**By threat type:**

| Threat Type | Count | Avg Confidence |
|-------------|-------|----------------|
| VULNERABILITY | 80 | 85 |
| INFORMATIONAL | 32 | 14 |
| APT_CAMPAIGN | 9 | 85 |
| RANSOMWARE | 3 | 95 |
| MALWARE | 1 | 94 |

**By severity:**

| Severity | Count |
|----------|-------|
| HIGH | 39 |
| INFORMATIONAL | 32 |
| MEDIUM | 30 |
| LOW | 17 |
| CRITICAL | 7 |

### Observations

1. The model correctly assigns low confidence (avg 14) to INFORMATIONAL entries -- the grounding rules in the prompt are working
2. High-confidence entries (85-95) cluster around VULNERABILITY, APT_CAMPAIGN, and RANSOMWARE -- the most concrete threat types
3. 100% embedding coverage confirms the full pipeline (LLM + embedding + persist) is operational end-to-end
4. Zero consecutive failures indicates stable connectivity to both PostgreSQL and OpenAI APIs
