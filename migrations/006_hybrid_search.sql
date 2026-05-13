-- tiger-eye migration 006: hybrid search (FTS + pgvector via RRF)
--
-- Adds a tsvector column over (entry_title, summary_impact, embedding_text)
-- with a GIN index, then exposes a hybrid_search() function that does
-- Reciprocal Rank Fusion between pgvector's nearest-neighbour ranking and
-- PostgreSQL FTS ranking.
--
-- Why hybrid: pure vector misses keyword-precise queries (\"CVE-2026-41940\"
-- can be in the corpus verbatim and still rank low if the surrounding
-- semantics are off). Pure FTS misses paraphrase (\"the cPanel zero-day\"
-- vs \"PAN-OS captive portal RCE\"). RRF gets the best of both.
--
-- Indexing config: `simple` rather than `english` — security articles are
-- full of exact-match tokens (CVE IDs, product names like PAN-OS, hash
-- values) where stemming and stop-word removal hurt more than they help.
-- Index size is slightly larger; recall on the things that matter is
-- materially better.

-- ---------------------------------------------------------------------------
-- Generated tsvector column (weighted: title > summary > embedding text)
-- ---------------------------------------------------------------------------

ALTER TABLE analysis
    ADD COLUMN IF NOT EXISTS search_tsv tsvector
    GENERATED ALWAYS AS (
        setweight(to_tsvector('simple', COALESCE(entry_title,     '')), 'A') ||
        setweight(to_tsvector('simple', COALESCE(summary_impact,  '')), 'B') ||
        setweight(to_tsvector('simple', COALESCE(embedding_text,  '')), 'C')
    ) STORED;

CREATE INDEX IF NOT EXISTS ix_analysis_search_tsv
    ON analysis USING GIN (search_tsv);

COMMENT ON COLUMN analysis.search_tsv IS
    'Weighted full-text index over entry_title (A), summary_impact (B), embedding_text (C). Uses simple tokeniser so exact CVE IDs / product names / hashes survive intact.';

-- ---------------------------------------------------------------------------
-- hybrid_search() — RRF fusion of pgvector + FTS
-- ---------------------------------------------------------------------------
--
-- Both rankings are computed independently, capped at `candidate_pool`,
-- then merged: each candidate gets contributions from whichever
-- ranking(s) it appeared in. Rows missing from one ranking are treated
-- as rank infinity for that side (effectively zero contribution).
--
-- RRF formula:
--   combined_score = sim_weight  / (rrf_k + rank_sim)
--                  + fts_weight  / (rrf_k + rank_fts)
--
-- with rrf_k defaulting to 60 (Cormack et al. recommendation).

-- +goose StatementBegin (kept for parity with tiger2go goose syntax; harmless to plain runner)
CREATE OR REPLACE FUNCTION hybrid_search(
    query_text       text,
    query_vec        vector,
    n_results        int     DEFAULT 10,
    sim_weight       float   DEFAULT 0.5,
    fts_weight       float   DEFAULT 0.5,
    candidate_pool   int     DEFAULT 50,
    max_distance     float   DEFAULT 0.65,
    rrf_k            int     DEFAULT 60
)
RETURNS TABLE (
    id              uuid,
    guid            text,
    severity_level  text,
    confidence      int,
    summary_impact  text,
    entry_title     text,
    source_name     text,
    source_url      text,
    analysed_at     timestamptz,
    distance        float,
    rank_sim        int,
    fts_score       float,
    rank_fts        int,
    combined_score  float
)
LANGUAGE sql
STABLE
AS $$
    WITH sem AS (
        SELECT
            a.id,
            (e.embedding <=> query_vec)::float AS distance,
            ROW_NUMBER() OVER (ORDER BY e.embedding <=> query_vec) AS rank_sim
        FROM analysis_embedding e
        JOIN analysis a ON a.id = e.analysis_id
        WHERE e.embedding <=> query_vec < max_distance
        ORDER BY e.embedding <=> query_vec
        LIMIT candidate_pool
    ),
    fts AS (
        SELECT
            a.id,
            ts_rank(a.search_tsv, websearch_to_tsquery('simple', query_text))::float AS fts_score,
            ROW_NUMBER() OVER (
                ORDER BY ts_rank(a.search_tsv, websearch_to_tsquery('simple', query_text)) DESC
            ) AS rank_fts
        FROM analysis a
        WHERE a.search_tsv @@ websearch_to_tsquery('simple', query_text)
        ORDER BY ts_rank(a.search_tsv, websearch_to_tsquery('simple', query_text)) DESC
        LIMIT candidate_pool
    ),
    fused AS (
        SELECT
            a.id, a.guid, a.severity_level, a.confidence,
            a.summary_impact, a.entry_title, a.source_name, a.source_url,
            a.analysed_at,
            sem.distance,
            sem.rank_sim::int,
            COALESCE(fts.fts_score, 0)::float AS fts_score,
            fts.rank_fts::int,
            (
              sim_weight * (1.0 / (rrf_k + COALESCE(sem.rank_sim, 1000000)))
            + fts_weight * (1.0 / (rrf_k + COALESCE(fts.rank_fts, 1000000)))
            )::float AS combined_score
        FROM analysis a
        LEFT JOIN sem ON sem.id = a.id
        LEFT JOIN fts ON fts.id = a.id
        WHERE sem.id IS NOT NULL OR fts.id IS NOT NULL
    )
    SELECT * FROM fused
    ORDER BY combined_score DESC
    LIMIT n_results
$$;
-- +goose StatementEnd

COMMENT ON FUNCTION hybrid_search(text, vector, int, float, float, int, float, int) IS
    'Reciprocal-rank-fusion search combining pgvector cosine distance and PostgreSQL FTS. sim_weight + fts_weight should sum to ~1.0. rrf_k=60 is the Cormack et al. default.';
