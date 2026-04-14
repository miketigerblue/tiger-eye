-- tiger-eye migration 001: analysis tables + pgvector
--
-- Creates the analysis and analysis_embedding tables owned by tiger-eye.
-- Requires pgvector extension (must be enabled by superuser if not already).
-- Run against the tiger2go database.

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS vector;

-- Analysis table — LLM-enriched threat assessments
CREATE TABLE IF NOT EXISTS analysis (
    id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    guid                    TEXT NOT NULL UNIQUE,

    -- Classification
    threat_type             TEXT,
    severity_level          TEXT,
    confidence              INTEGER,

    -- LLM output
    summary_impact          TEXT,
    relevance               TEXT,
    historical_context      TEXT,
    additional_notes        TEXT,

    -- Structured intelligence (JSONB for GIN indexing)
    -- key_iocs: [{"type": "ipv4|domain|url|hash_sha256|...", "value": "..."}]
    key_iocs                JSONB,
    -- recommended_actions: includes mitigations
    recommended_actions     JSONB,
    affected_systems_sectors JSONB,
    potential_threat_actors  JSONB,
    -- cve_references: includes exploit advisory URLs
    cve_references          JSONB,
    -- ttps: [{"id": "T1566.001", "name": "Spearphishing Attachment"}, ...]
    ttps                    JSONB,
    tools_used              JSONB,
    malware_families        JSONB,
    target_geographies      JSONB,

    -- Source metadata (denormalised from archive)
    entry_title             TEXT,
    source_name             TEXT,
    source_url              TEXT,
    feed_title              TEXT,
    feed_description        TEXT,
    feed_language           TEXT,
    feed_icon               TEXT,

    -- Timestamps
    analysed_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    enriched_at             TIMESTAMPTZ,
    inserted_at             TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Embedding source text
    embedding_text          TEXT
);

-- Indexes on analysis
CREATE INDEX IF NOT EXISTS ix_analysis_guid ON analysis (guid);
CREATE INDEX IF NOT EXISTS ix_analysis_threat_type ON analysis (threat_type);
CREATE INDEX IF NOT EXISTS ix_analysis_severity ON analysis (severity_level);
CREATE INDEX IF NOT EXISTS ix_analysis_analysed_at ON analysis (analysed_at DESC);
CREATE INDEX IF NOT EXISTS ix_analysis_inserted_at ON analysis (inserted_at DESC);

-- GIN indexes for JSONB containment queries
CREATE INDEX IF NOT EXISTS ix_analysis_cve_refs ON analysis USING GIN (cve_references);
CREATE INDEX IF NOT EXISTS ix_analysis_threat_actors ON analysis USING GIN (potential_threat_actors);
CREATE INDEX IF NOT EXISTS ix_analysis_ttps ON analysis USING GIN (ttps);
CREATE INDEX IF NOT EXISTS ix_analysis_iocs ON analysis USING GIN (key_iocs);

-- Analysis embedding table — pgvector storage, 1:1 with analysis
CREATE TABLE IF NOT EXISTS analysis_embedding (
    analysis_id     UUID PRIMARY KEY REFERENCES analysis(id) ON DELETE CASCADE,
    embedding       vector(1536) NOT NULL,
    model           TEXT NOT NULL DEFAULT 'text-embedding-3-small',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- HNSW index for cosine similarity
CREATE INDEX IF NOT EXISTS analysis_embedding_hnsw_cosine_idx
    ON analysis_embedding
    USING hnsw (embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 64);

CREATE INDEX IF NOT EXISTS ix_embedding_created
    ON analysis_embedding (created_at DESC);
