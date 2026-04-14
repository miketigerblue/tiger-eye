"""Prometheus metrics for tiger-eye.

Exposes counters, histograms, and gauges for enrichment pipeline monitoring.
Metrics are served via the /metrics endpoint added by prometheus-fastapi-instrumentator.
"""

from prometheus_client import Counter, Gauge, Histogram

# ---------------------------------------------------------------------------
# Enrichment pipeline
# ---------------------------------------------------------------------------

ENTRIES_ENRICHED = Counter(
    "tiger_eye_entries_enriched_total",
    "Total entries successfully enriched",
    ["threat_type", "severity_level"],
)

ENTRIES_FAILED = Counter(
    "tiger_eye_entries_failed_total",
    "Total entries that failed enrichment",
    ["stage"],  # rag, llm, embedding, persist
)

ENTRIES_SKIPPED = Counter(
    "tiger_eye_entries_skipped_total",
    "Total entries skipped (no content)",
)

BATCH_SIZE = Histogram(
    "tiger_eye_batch_size",
    "Number of entries per enrichment cycle",
    buckets=[0, 1, 5, 10, 15, 20, 50],
)

BACKOFF_STREAK = Gauge(
    "tiger_eye_consecutive_failures",
    "Current consecutive failure streak",
)

LOOP_RUNNING = Gauge(
    "tiger_eye_loop_running",
    "Whether the enrichment loop is active (1=yes, 0=no)",
)

# ---------------------------------------------------------------------------
# OpenAI API
# ---------------------------------------------------------------------------

LLM_LATENCY = Histogram(
    "tiger_eye_llm_latency_seconds",
    "LLM analysis call duration",
    buckets=[0.5, 1, 2, 5, 10, 20, 30, 60],
)

EMBEDDING_LATENCY = Histogram(
    "tiger_eye_embedding_latency_seconds",
    "Embedding generation call duration",
    buckets=[0.1, 0.25, 0.5, 1, 2, 5],
)

LLM_RETRIES = Counter(
    "tiger_eye_llm_retries_total",
    "Total LLM call retries",
)

EMBEDDING_RETRIES = Counter(
    "tiger_eye_embedding_retries_total",
    "Total embedding call retries",
)

# ---------------------------------------------------------------------------
# RAG
# ---------------------------------------------------------------------------

RAG_QUERIES = Counter(
    "tiger_eye_rag_queries_total",
    "Total RAG similarity queries",
)

RAG_HITS = Counter(
    "tiger_eye_rag_hits_total",
    "RAG queries that returned at least one result",
)

RAG_EMPTY = Counter(
    "tiger_eye_rag_empty_total",
    "RAG queries that returned zero results",
)
