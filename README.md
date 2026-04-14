# tiger-eye

pgvector-native threat intelligence enrichment service. Reads OSINT feed entries
from the tiger2go ingestor database, runs LLM-based analysis with RAG context,
and stores enriched results with vector embeddings — all in Postgres.

Part of the tiger ecosystem: **tiger2go** (ingestor) → **tiger-eye** (enricher) → **snow-tiger** (export).

## Architecture

```
tiger2go (Go ingestor)          tiger-eye (this service)
┌───────────────┐               ┌──────────────────────────┐
│ RSS/Atom feeds│               │  Enrichment Loop         │
│       ↓       │               │    ↓                     │
│ archive table ├──tiger2go_net─┤  Read archive entries    │
│ current table │               │    ↓                     │
│ cve_enriched  │               │  RAG retrieval (pgvector)│
│ epss_daily    │               │    ↓                     │
└───────────────┘               │  LLM analysis (OpenAI)   │
                                │    ↓                     │
                                │  Write analysis +        │
                                │  analysis_embedding      │
                                │    (single transaction)  │
                                │                          │
                                │  Internal API (:8080)    │
                                │  /health                 │
                                │  /internal/search/text   │
                                │  /internal/search/vector │
                                │  /internal/node/{id}     │
                                └──────────────────────────┘
```

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

Copy `.env.example` to `.env` and set your OpenAI API key. All other defaults
point at the tiger2go Postgres container.

## Development

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your OPENAI_API_KEY
python -m tiger_eye.main
```
