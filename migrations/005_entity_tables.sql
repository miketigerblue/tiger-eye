-- tiger-eye migration 005: first-class threat actors + malware families
--
-- Replaces the freeform jsonb arrays on analysis.potential_threat_actors and
-- analysis.malware_families with canonical entity tables. The jsonb arrays
-- stay on the analysis row for backward compatibility — they're written as
-- the raw LLM output. The entity tables are populated by a canonicaliser
-- (tiger_eye.entities) that collapses casing, drops generic labels, and
-- maps known aliases to canonical names.
--
-- After this lands and the backfill runs, "Vidar" and "Vidar Stealer" both
-- resolve to the same `malware_families` row, "Mini Shai-Hulud" and "mini
-- Shai-Hulud" likewise, and `Attacker` / `unauthenticated attacker` get
-- filtered out of `threat_actors` entirely.

-- ---------------------------------------------------------------------------
-- threat_actors
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS threat_actors (
    id                      UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    canonical_name          TEXT        NOT NULL UNIQUE,
    -- normalised_key: lowercase, whitespace-collapsed form of canonical_name.
    -- Stored to keep the lookup index case-insensitive without functional indexes.
    normalised_key          TEXT        NOT NULL UNIQUE,
    category                TEXT,                       -- 'state-sponsored' | 'cybercrime' | 'hacktivist' | 'unknown'
    attribution_country     TEXT,                       -- ISO 3166-1 alpha-2
    description             TEXT,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_threat_actors_category
    ON threat_actors (category) WHERE category IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_threat_actors_country
    ON threat_actors (attribution_country) WHERE attribution_country IS NOT NULL;

COMMENT ON TABLE  threat_actors IS 'Canonical threat-actor entities. Populated from analysis output by tiger_eye.entities.canonicalise_actor';
COMMENT ON COLUMN threat_actors.normalised_key IS 'Lowercased, whitespace-collapsed form of canonical_name for case-insensitive lookups';

-- ---------------------------------------------------------------------------
-- malware_families
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS malware_families (
    id                      UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    canonical_name          TEXT        NOT NULL UNIQUE,
    normalised_key          TEXT        NOT NULL UNIQUE,
    category                TEXT,                       -- 'ransomware' | 'infostealer' | 'rat' | 'banking-trojan' | 'worm' | 'wiper' | 'backdoor' | 'loader' | 'botnet' | 'unknown'
    description             TEXT,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_malware_families_category
    ON malware_families (category) WHERE category IS NOT NULL;

COMMENT ON TABLE malware_families IS 'Canonical malware-family entities. Populated from analysis output by tiger_eye.entities.canonicalise_malware';

-- ---------------------------------------------------------------------------
-- Join tables — many-to-many analysis ↔ entity
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS analysis_actor (
    analysis_id     UUID        NOT NULL REFERENCES analysis(id)       ON DELETE CASCADE,
    actor_id        UUID        NOT NULL REFERENCES threat_actors(id)  ON DELETE RESTRICT,
    raw_mention     TEXT,                               -- original LLM string for audit
    linked_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (analysis_id, actor_id)
);

CREATE INDEX IF NOT EXISTS ix_analysis_actor_actor
    ON analysis_actor (actor_id);
CREATE INDEX IF NOT EXISTS ix_analysis_actor_linked_at
    ON analysis_actor (linked_at DESC);

CREATE TABLE IF NOT EXISTS analysis_malware (
    analysis_id     UUID        NOT NULL REFERENCES analysis(id)         ON DELETE CASCADE,
    family_id       UUID        NOT NULL REFERENCES malware_families(id) ON DELETE RESTRICT,
    raw_mention     TEXT,
    linked_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (analysis_id, family_id)
);

CREATE INDEX IF NOT EXISTS ix_analysis_malware_family
    ON analysis_malware (family_id);
CREATE INDEX IF NOT EXISTS ix_analysis_malware_linked_at
    ON analysis_malware (linked_at DESC);

-- ---------------------------------------------------------------------------
-- Views — the analyst-facing payoff
-- ---------------------------------------------------------------------------

-- Top threat actors in the last 30 days, with article counts and confidence.
-- Replaces the cleanup-heavy ad-hoc SQL we kept rewriting against the jsonb
-- arrays.
CREATE OR REPLACE VIEW v_top_threat_actors_30d AS
SELECT
    ta.canonical_name                                   AS actor,
    ta.category,
    ta.attribution_country                              AS country,
    COUNT(*)                                            AS mentions_30d,
    COUNT(DISTINCT a.guid)                              AS articles_30d,
    COUNT(DISTINCT a.source_name)                       AS sources_30d,
    ROUND(AVG(a.confidence)::numeric, 0)                AS avg_confidence,
    MIN(a.analysed_at)                                  AS first_seen_30d,
    MAX(a.analysed_at)                                  AS last_seen_30d
FROM threat_actors ta
JOIN analysis_actor aa  ON aa.actor_id = ta.id
JOIN analysis a         ON a.id = aa.analysis_id
WHERE a.analysed_at >= now() - interval '30 days'
GROUP BY ta.id, ta.canonical_name, ta.category, ta.attribution_country
ORDER BY mentions_30d DESC, articles_30d DESC;

CREATE OR REPLACE VIEW v_top_malware_families_30d AS
SELECT
    mf.canonical_name                                   AS family,
    mf.category,
    COUNT(*)                                            AS mentions_30d,
    COUNT(DISTINCT a.guid)                              AS articles_30d,
    COUNT(DISTINCT a.source_name)                       AS sources_30d,
    ROUND(AVG(a.confidence)::numeric, 0)                AS avg_confidence,
    MIN(a.analysed_at)                                  AS first_seen_30d,
    MAX(a.analysed_at)                                  AS last_seen_30d
FROM malware_families mf
JOIN analysis_malware am ON am.family_id = mf.id
JOIN analysis a          ON a.id = am.analysis_id
WHERE a.analysed_at >= now() - interval '30 days'
GROUP BY mf.id, mf.canonical_name, mf.category
ORDER BY mentions_30d DESC, articles_30d DESC;

-- Actor ↔ malware co-occurrence in the last 90 days. Surfaces operator
-- attribution: which actors are seen alongside which families.
CREATE OR REPLACE VIEW v_actor_malware_cooccurrence_90d AS
SELECT
    ta.canonical_name                                   AS actor,
    mf.canonical_name                                   AS family,
    ta.category                                         AS actor_category,
    mf.category                                         AS family_category,
    COUNT(*)                                            AS coincident_mentions,
    COUNT(DISTINCT a.guid)                              AS articles,
    MIN(a.analysed_at)                                  AS first_seen,
    MAX(a.analysed_at)                                  AS last_seen
FROM analysis_actor aa
JOIN analysis_malware am ON am.analysis_id = aa.analysis_id
JOIN analysis a          ON a.id = aa.analysis_id
JOIN threat_actors ta    ON ta.id = aa.actor_id
JOIN malware_families mf ON mf.id = am.family_id
WHERE a.analysed_at >= now() - interval '90 days'
GROUP BY ta.canonical_name, mf.canonical_name, ta.category, mf.category
ORDER BY coincident_mentions DESC;

-- Whole-corpus entity-level summary, with first/last-seen and lifetime
-- counts. Useful for the dashboard's entity browser.
CREATE OR REPLACE VIEW v_threat_actor_summary AS
SELECT
    ta.id,
    ta.canonical_name,
    ta.category,
    ta.attribution_country,
    COALESCE(stats.mention_count, 0)                    AS lifetime_mentions,
    COALESCE(stats.article_count, 0)                    AS lifetime_articles,
    stats.first_seen,
    stats.last_seen
FROM threat_actors ta
LEFT JOIN LATERAL (
    SELECT
        COUNT(*)                AS mention_count,
        COUNT(DISTINCT a.guid)  AS article_count,
        MIN(a.analysed_at)      AS first_seen,
        MAX(a.analysed_at)      AS last_seen
    FROM analysis_actor aa
    JOIN analysis a ON a.id = aa.analysis_id
    WHERE aa.actor_id = ta.id
) stats ON TRUE;

CREATE OR REPLACE VIEW v_malware_family_summary AS
SELECT
    mf.id,
    mf.canonical_name,
    mf.category,
    COALESCE(stats.mention_count, 0)                    AS lifetime_mentions,
    COALESCE(stats.article_count, 0)                    AS lifetime_articles,
    stats.first_seen,
    stats.last_seen
FROM malware_families mf
LEFT JOIN LATERAL (
    SELECT
        COUNT(*)                AS mention_count,
        COUNT(DISTINCT a.guid)  AS article_count,
        MIN(a.analysed_at)      AS first_seen,
        MAX(a.analysed_at)      AS last_seen
    FROM analysis_malware am
    JOIN analysis a ON a.id = am.analysis_id
    WHERE am.family_id = mf.id
) stats ON TRUE;
