-- tiger-eye migration 004: provenance, content-addressable input, restored fields
--
-- Tier-1 of the no-info-loss migration. All additive — no drops, no NOT NULLs
-- without defaults, safe to apply on a live tiger2go DB.
--
-- Adds:
--   * Provenance (model, prompt version, token usage, latency, pipeline version)
--   * Content-addressable input_hash (SHA-256 of the LLM's input text) for
--     idempotent re-enrichment and silent-edit detection
--   * Three jsonb fields that were folded into recommended_actions /
--     cve_references in the v1 prompt: mitigation_strategies, attack_vectors,
--     exploit_references. Restoring them as first-class so they're queryable
--     without parsing the recommended_actions array.

-- ---------------------------------------------------------------------------
-- Provenance
-- ---------------------------------------------------------------------------

ALTER TABLE analysis
    ADD COLUMN IF NOT EXISTS model_id          TEXT,
    ADD COLUMN IF NOT EXISTS prompt_version    TEXT,
    ADD COLUMN IF NOT EXISTS pipeline_version  TEXT,
    ADD COLUMN IF NOT EXISTS prompt_tokens     INTEGER,
    ADD COLUMN IF NOT EXISTS response_tokens   INTEGER,
    ADD COLUMN IF NOT EXISTS latency_ms        INTEGER;

-- ---------------------------------------------------------------------------
-- Content-addressable input
-- ---------------------------------------------------------------------------
-- SHA-256 of the LLM input text (title + content + summary, normalised).
-- Lets us:
--   1. Detect when a feed silently edits a story under the same guid
--   2. Skip re-enrichment when the input hasn't actually changed
--   3. Group analyses sharing the same input across model/prompt versions

ALTER TABLE analysis
    ADD COLUMN IF NOT EXISTS input_hash BYTEA;

CREATE INDEX IF NOT EXISTS ix_analysis_input_hash ON analysis (input_hash);

-- ---------------------------------------------------------------------------
-- Restored fields (v1 prompt consolidated these; v2 splits them back out)
-- ---------------------------------------------------------------------------
-- mitigation_strategies: defensive controls and patches — previously folded
--   into recommended_actions ("array of recommended response actions AND
--   mitigation steps"). Separation lets dashboards distinguish "what to do
--   right now" from "what to put in place going forward".
-- attack_vectors: the *how* of the threat (e.g. spearphishing attachment,
--   exposed RDP, vulnerable web app). Not represented anywhere in v1 — pure
--   loss vs. the prod schema.
-- exploit_references: PoC / advisory URLs — previously inlined into
--   cve_references. Separation makes the cve_references list pure CVE IDs.

ALTER TABLE analysis
    ADD COLUMN IF NOT EXISTS mitigation_strategies JSONB,
    ADD COLUMN IF NOT EXISTS attack_vectors        JSONB,
    ADD COLUMN IF NOT EXISTS exploit_references    JSONB;

-- GIN indexes for jsonb containment / array-element queries
CREATE INDEX IF NOT EXISTS ix_analysis_attack_vectors
    ON analysis USING GIN (attack_vectors);
CREATE INDEX IF NOT EXISTS ix_analysis_mitigation_strategies
    ON analysis USING GIN (mitigation_strategies);
CREATE INDEX IF NOT EXISTS ix_analysis_exploit_references
    ON analysis USING GIN (exploit_references);

-- Helpful filter index for "find analyses from a given model+prompt combo"
CREATE INDEX IF NOT EXISTS ix_analysis_model_prompt
    ON analysis (model_id, prompt_version);

COMMENT ON COLUMN analysis.model_id          IS 'LLM model identifier (e.g. gpt-5.4-mini)';
COMMENT ON COLUMN analysis.prompt_version    IS 'Version tag of ANALYSIS_PROMPT used';
COMMENT ON COLUMN analysis.pipeline_version  IS 'tiger-eye package version at enrichment time';
COMMENT ON COLUMN analysis.prompt_tokens     IS 'Input token count reported by the LLM API';
COMMENT ON COLUMN analysis.response_tokens   IS 'Output token count reported by the LLM API';
COMMENT ON COLUMN analysis.latency_ms        IS 'End-to-end LLM call latency in milliseconds';
COMMENT ON COLUMN analysis.input_hash        IS 'SHA-256 of normalised input text (title|content|summary)';
COMMENT ON COLUMN analysis.mitigation_strategies IS 'Defensive controls — formerly inside recommended_actions';
COMMENT ON COLUMN analysis.attack_vectors    IS 'How the threat reaches the target — restored from v1 schema';
COMMENT ON COLUMN analysis.exploit_references IS 'PoC and exploit advisory URLs — formerly inside cve_references';
