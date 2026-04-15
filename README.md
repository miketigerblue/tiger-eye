<p align="center">
  <img src="tiger-eye.png" alt="tiger-eye logo" width="360">
</p>

<h1 align="center">tiger-eye</h1>

<p align="center">
  pgvector-native threat intelligence enrichment service
</p>

<p align="center">
  <a href="https://github.com/miketigerblue/tiger-eye/actions/workflows/ci.yml"><img src="https://github.com/miketigerblue/tiger-eye/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/python-3.11-blue.svg" alt="Python 3.11">
  <img src="https://img.shields.io/badge/pgvector-HNSW-green.svg" alt="pgvector">
</p>

---

Reads OSINT feed entries from the [tiger2go](https://github.com/miketigerblue/tiger2go) ingestor database, runs LLM-based analysis with RAG context, and stores enriched results with vector embeddings -- all in Postgres.

Part of the tiger ecosystem: **tiger2go** (ingestor) &rarr; **tiger-eye** (enricher) &rarr; **snow-tiger** (export).

## Architecture

```
┌──────────────────────────────┐        ┌──────────────────────────────────────┐
│        TIGERFETCH            │        │             TIGEREYE                 │
│        (Go ingestor)         │        │        (enrichment service)          │
├──────────────────────────────┤        ├──────────────────────────────────────┤
│                              │        │                                      │
│  RSS / Atom Feeds            │        │  Enrichment Loop (async)             │
│          │                   │        │          │                           │
│          ▼                   │        │          ▼                           │
│  archive                     │───────▶│  Read unprocessed entries            │
│  current                     │ net    │          │                           │
│  cve_enriched                │───────▶│  RAG retrieval (pgvector)            │
│  epss_daily                  │        │          │                           │
│                              │        │          ▼                           │
│                              │        │  LLM analysis (OpenAI)               │
│                              │        │          │                           │
│                              │        │          ▼                           │
│                              │        │  Persist analysis + embedding        │
│                              │        │  (single transaction)                │
│                              │        │                                      │
│                              │        │  Internal API (:8080)                │
│                              │        │   • /health                          │
│                              │        │   • /internal/search/text            │
│                              │        │   • /internal/search/vector          │
│                              │        │   • /internal/node/{id}              │
│                              │        │   • /metrics                         │
└──────────────────────────────┘        └──────────────────────────────────────┘
```

## Features

- **Enrichment pipeline** -- batch-processes feed entries through LLM analysis with exponential backoff and semaphore-bounded concurrency
- **RAG context** -- pgvector cosine-distance retrieval injects similar past analyses into the LLM prompt, with token budgeting and distance thresholds
- **NVD context lookup** -- extracts CVE IDs from text and fetches live CVSS/EPSS scores from the `cve_enriched` table
- **ATT&CK normalisation** -- 260-entry lookup table auto-fills MITRE ATT&CK technique IDs during post-processing
- **Structured output** -- 18 intelligence fields per analysis: threat type, severity, confidence, IOCs, TTPs, actors, malware families, geographies, sectors, CVEs, tools, recommended actions
- **Three-pillar observability** -- structlog JSON logging, 13 Prometheus metrics, OpenTelemetry distributed tracing
- **Grafana dashboard** -- 16-panel provisioned dashboard (pipeline health, latency percentiles, RAG hit rates, threat distribution)
- **Custom migration runner** -- SHA-256 checksums, dry-run mode, status reporting

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Liveness probe with DB check, loop status, failure streak |
| `POST` | `/internal/search/text` | Semantic search by natural language |
| `POST` | `/internal/search/vector` | Nearest-neighbor search by embedding vector |
| `GET` | `/internal/node/{id}` | Fetch analysis by UUID |
| `GET` | `/metrics` | Prometheus scrape endpoint |
| `GET` | `/docs` | Swagger UI |

## Quick Start

```bash
# 1. Ensure tiger2go stack is running
cd ~/tiger2go && docker compose up -d

# 2. Start tiger-eye (joins tiger2go_net)
cd ~/tiger-eye && docker compose up -d

# 3. Check health
curl http://localhost:8080/health
```

## Configuration

Copy `.env.example` to `.env` and set your OpenAI API key. All other defaults point at the tiger2go Postgres container.

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql+asyncpg://...tiger2go_postgres:5432/tiger2go` | Async Postgres connection string |
| `OPENAI_API_KEY` | *(required)* | OpenAI API key for LLM + embeddings |
| `EMBEDDING_MODEL` | `text-embedding-3-small` | OpenAI embedding model |
| `EMBEDDING_DIMENSIONS` | `1536` | Vector dimensions |
| `ENRICH_INTERVAL` | `60` | Seconds between enrichment cycles |
| `ENRICH_BATCH_SIZE` | `20` | Entries per cycle |
| `LOG_LEVEL` | `INFO` | Logging level |
| `LOG_JSON` | `true` | JSON structured logging (disable for dev) |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | *(optional)* | OpenTelemetry OTLP gRPC endpoint |

## Development

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your OPENAI_API_KEY
python -m tiger_eye.main
```

### Running tests

```bash
# Unit + API tests (no database required)
pytest tests/test_analysis.py tests/test_api.py -v

# Integration tests (requires DATABASE_URL pointing at pgvector Postgres)
DATABASE_URL=postgresql+asyncpg://user:pass@localhost:5432/tiger2go pytest tests/test_integration.py -v

# Full suite via Docker
docker compose -f docker-compose.test.yml up --build --abort-on-container-exit
```

### Migrations

```bash
# Apply pending migrations
python -m tiger_eye.migrate

# Check status
python -m tiger_eye.migrate --status

# Preview without applying
python -m tiger_eye.migrate --dry-run
```

## Testing

37 tests across three layers:

| Layer | File | Tests | What it covers |
|-------|------|-------|----------------|
| Unit | `test_analysis.py` | 22 | Normaliser edge cases: threat types, severity, confidence clamping, IOC wrapping, TTP auto-fill, JSON parsing |
| API | `test_api.py` | 8 | Health (200/503), node lookup (400/404/200), text search, vector search, input validation |
| Integration | `test_integration.py` | 7 | Real Postgres+pgvector: DB connectivity, schema validation, ORM roundtrip, cascade delete, HNSW vector search, migrations |

Integration tests auto-skip without `DATABASE_URL` and run against real pgvector in CI via `docker-compose.test.yml`.

## CI/CD

5-stage pipeline with 8 jobs (`.github/workflows/ci.yml`):

| Stage | Jobs |
|-------|------|
| 1 (fast, parallel) | Lint (ruff + mypy), SAST (bandit + semgrep), Dependency Audit (pip-audit), Secret Scan (gitleaks) |
| 2 | Unit Tests (pytest + coverage) |
| 3 | Integration Tests (pgvector service container) |
| 4 | Container Scan (Trivy vuln scan + SBOM generation) |
| 5 | DAST (ZAP baseline scan against live container) |

Additional: CodeQL weekly cron, Dependabot across pip/docker/github-actions, pre-commit hooks (ruff, bandit, detect-secrets, gitleaks, no-commit-to-main).

## Observability

| Pillar | Technology | Detail |
|--------|-----------|--------|
| **Logging** | structlog | JSON to stdout, configurable level, noisy loggers suppressed |
| **Metrics** | prometheus_client | 13 instruments at `/metrics` -- enrichment rates, failure stages, LLM/embedding latency histograms, RAG hit rates |
| **Tracing** | OpenTelemetry | OTLP gRPC export, auto-instrumented FastAPI + SQLAlchemy, manual spans on batches and searches |
| **Dashboard** | Grafana | 16-panel provisioned JSON -- Overview, Pipeline, Latency (p50/p95/p99), RAG |
| **Health** | FastAPI | `GET /health` with active DB probe, loop status, consecutive failures |

<p align="center">
  <img src="grafana-1.png" alt="Grafana dashboard — Overview and Enrichment Pipeline" width="800"><br>
  <img src="grafana-2.png" alt="Grafana dashboard — OpenAI Latency and RAG Pipeline" width="800">
</p>

## Project Structure

```
tiger-eye/
├── tiger_eye/
│   ├── main.py              # FastAPI app + enrichment loop
│   ├── analysis.py           # LLM pipeline, prompt, normaliser, TTP lookup
│   ├── rag.py                # pgvector semantic search (RAG retrieval)
│   ├── embedding.py          # OpenAI embedding wrapper with retries
│   ├── database.py           # SQLAlchemy ORM (5 models), async sessions
│   ├── config.py             # pydantic-settings configuration
│   ├── metrics.py            # Prometheus metric definitions
│   ├── logging_config.py     # structlog JSON configuration
│   ├── tracing.py            # OpenTelemetry initialisation
│   └── migrate.py            # Custom migration runner CLI
├── migrations/
│   ├── 001_analysis_pgvector.sql   # Schema + HNSW index
│   └── 002_backfill_ttp_ids.sql    # Historical TTP ID backfill
├── grafana/dashboards/
│   └── tiger-eye.json        # 16-panel Grafana dashboard
├── tests/
│   ├── test_analysis.py      # 22 unit tests
│   ├── test_api.py           # 8 API tests
│   └── test_integration.py   # 7 integration tests
├── docker-compose.yml        # Production (joins tiger2go_net)
├── docker-compose.test.yml   # Integration test harness
├── Dockerfile
├── pyproject.toml            # ruff, mypy, pytest, bandit config
├── requirements.txt
├── SYSTEM_DESIGN.md          # 1000+ line architecture document
└── SECURITY.md               # Vulnerability disclosure policy
```

## Documentation

- **[SYSTEM_DESIGN.md](SYSTEM_DESIGN.md)** -- full architecture specification with C1/C2/C3 diagrams, failure mode matrix, performance characteristics, and live system snapshot
- **[SECURITY.md](SECURITY.md)** -- vulnerability disclosure policy (security@tigerblue.tech, 48h ack SLA, 30d fix SLA)

## License

[MIT](LICENSE)
