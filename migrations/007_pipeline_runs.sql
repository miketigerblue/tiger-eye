-- tiger-eye migration 007: pipeline_runs observability
--
-- One row per enrichment cycle. Together with the per-row provenance we
-- already write (model_id, prompt_tokens, response_tokens, latency_ms),
-- this gives us cost-per-feed, p50/p95 latency over time, and the
-- ability to answer "did the model bump cost more?" / "which run is
-- responsible for the spike at 14:00 yesterday?" cleanly.
--
-- An empty poll (batch_size = 0) does NOT write a row — the loop polls
-- on every wake and most of those find nothing to do. The default
-- "interesting" filter is batch_size >= 1.

CREATE TABLE IF NOT EXISTS pipeline_runs (
    run_id                  UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    started_at              TIMESTAMPTZ  NOT NULL DEFAULT now(),
    finished_at             TIMESTAMPTZ,
    duration_ms             INTEGER,

    -- What the cycle did
    batch_size              INTEGER      NOT NULL DEFAULT 0,
    enriched_count          INTEGER      NOT NULL DEFAULT 0,
    failed_count            INTEGER      NOT NULL DEFAULT 0,
    skipped_count           INTEGER      NOT NULL DEFAULT 0,

    -- Cost
    prompt_tokens_total     INTEGER,
    response_tokens_total   INTEGER,

    -- Latency (over per-row analyse_and_persist timings)
    llm_p50_ms              INTEGER,
    llm_p95_ms              INTEGER,
    llm_max_ms              INTEGER,

    -- Provenance snapshot for this run
    model_id                TEXT,
    prompt_version          TEXT,
    pipeline_version        TEXT,

    -- Loop state
    -- 'notify' = woken by listener; 'poll' = woken by timer; 'initial' = first cycle.
    wake_source             TEXT,
    consecutive_failures    INTEGER      NOT NULL DEFAULT 0,
    failure_reason          TEXT
);

CREATE INDEX IF NOT EXISTS ix_pipeline_runs_started_at
    ON pipeline_runs (started_at DESC);
CREATE INDEX IF NOT EXISTS ix_pipeline_runs_model_prompt
    ON pipeline_runs (model_id, prompt_version);

-- Link analysis rows back to the run that produced them. NULL for
-- existing rows (pre-007); populated by the writer going forward.
ALTER TABLE analysis
    ADD COLUMN IF NOT EXISTS run_id UUID
        REFERENCES pipeline_runs(run_id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS ix_analysis_run_id
    ON analysis (run_id) WHERE run_id IS NOT NULL;

COMMENT ON TABLE  pipeline_runs IS
    'One row per enrichment cycle that actually did work. Pairs with per-row provenance on analysis for cost / latency observability.';
COMMENT ON COLUMN pipeline_runs.wake_source IS
    'How the loop was woken: notify (listener), poll (timer), initial (first cycle)';

-- ---------------------------------------------------------------------------
-- Analyst-facing views
-- ---------------------------------------------------------------------------

-- Recent runs with summary metrics. Useful in dashboards.
CREATE OR REPLACE VIEW v_pipeline_runs_recent AS
SELECT
    run_id,
    started_at,
    duration_ms,
    batch_size,
    enriched_count,
    failed_count,
    prompt_tokens_total,
    response_tokens_total,
    (prompt_tokens_total + response_tokens_total)         AS tokens_total,
    llm_p50_ms,
    llm_p95_ms,
    model_id,
    prompt_version,
    pipeline_version,
    wake_source,
    consecutive_failures
FROM pipeline_runs
WHERE started_at >= now() - interval '24 hours'
ORDER BY started_at DESC;

-- Daily cost rollup — per-day token totals + run counts. The natural
-- "how much did the enricher cost yesterday?" query.
CREATE OR REPLACE VIEW v_pipeline_cost_per_day AS
SELECT
    date_trunc('day', started_at)::date                   AS day,
    model_id,
    COUNT(*)                                              AS runs,
    SUM(batch_size)                                       AS batch_total,
    SUM(enriched_count)                                   AS enriched_total,
    SUM(failed_count)                                     AS failed_total,
    SUM(prompt_tokens_total)                              AS prompt_tokens,
    SUM(response_tokens_total)                            AS response_tokens,
    SUM(prompt_tokens_total + response_tokens_total)      AS tokens_total,
    ROUND(AVG(llm_p50_ms)::numeric, 0)                    AS avg_p50_ms,
    ROUND(AVG(llm_p95_ms)::numeric, 0)                    AS avg_p95_ms
FROM pipeline_runs
WHERE prompt_tokens_total IS NOT NULL
GROUP BY 1, 2
ORDER BY day DESC, model_id;

-- Comparative breakdown by prompt_version — A/B-compare the impact of a
-- prompt bump. Answers "did v3 enrich more articles per run than v2?"
-- and "did v3 cost more per article?"
CREATE OR REPLACE VIEW v_pipeline_by_prompt_version AS
SELECT
    prompt_version,
    model_id,
    COUNT(*)                                              AS runs,
    SUM(enriched_count)                                   AS enriched_total,
    SUM(failed_count)                                     AS failed_total,
    ROUND(AVG(batch_size)::numeric, 1)                    AS avg_batch_size,
    ROUND(AVG(llm_p50_ms)::numeric, 0)                    AS avg_p50_ms,
    ROUND(AVG(llm_p95_ms)::numeric, 0)                    AS avg_p95_ms,
    SUM(prompt_tokens_total)                              AS total_prompt_tokens,
    SUM(response_tokens_total)                            AS total_response_tokens,
    -- Cost-per-enriched-article (tokens, not USD — convert outside if needed)
    ROUND(
        (SUM(prompt_tokens_total + response_tokens_total)::numeric
         / NULLIF(SUM(enriched_count), 0)),
        0
    )                                                     AS tokens_per_enrichment,
    MIN(started_at)::timestamp(0)                         AS first_run,
    MAX(started_at)::timestamp(0)                         AS last_run
FROM pipeline_runs
WHERE prompt_version IS NOT NULL
GROUP BY prompt_version, model_id
ORDER BY last_run DESC;
