-- tiger-eye migration 003: failed_enrichment dead-letter table
--
-- Tracks archive entries whose enrichment pipeline failed so they can
-- be retried with back-off, inspected operationally, and excluded from
-- the main poll query once they exhaust max attempts.

CREATE TABLE IF NOT EXISTS failed_enrichment (
    guid              TEXT PRIMARY KEY,
    stage             TEXT NOT NULL,          -- rag | llm | embedding | persist | pipeline
    error_class       TEXT,                   -- exception class name, e.g. RateLimitError
    error_message     TEXT,                   -- truncated exception message
    attempts          INTEGER NOT NULL DEFAULT 1,
    first_failed_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_failed_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    next_retry_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Fast lookup: "give me entries I'm allowed to retry right now"
CREATE INDEX IF NOT EXISTS idx_failed_enrichment_next_retry
    ON failed_enrichment (next_retry_at);

-- Fast lookup by stage for dashboards
CREATE INDEX IF NOT EXISTS idx_failed_enrichment_stage
    ON failed_enrichment (stage);
