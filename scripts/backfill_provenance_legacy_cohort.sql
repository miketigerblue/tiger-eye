-- One-shot backfill: mark pre-PR22 analyses with a cohort tag.
--
-- PR #22 (2026-05-13) added model_id / prompt_version / pipeline_version /
-- input_hash / token-count columns to public.analysis. Rows enriched before
-- that landed (2,410 of them) have NULL on all five.
--
-- For analytical queries that want to distinguish "what the v0.1.x pipeline
-- produced" from "what the v0.2.x pipeline produced" we set a cohort marker
-- on the legacy rows. model_id and input_hash stay NULL — we genuinely don't
-- know the model that was used, and the input text can change as feeds get
-- silently re-edited, so a retroactive SHA would be misleading.
--
-- Idempotent: only touches rows that still have NULL provenance.

UPDATE public.analysis
SET pipeline_version = 'legacy-pre-pr22',
    prompt_version   = 'legacy-pre-pr22'
WHERE pipeline_version IS NULL
  AND prompt_version IS NULL
  AND analysed_at < '2026-05-13'::timestamptz;

-- Sanity-check the cohort split after backfill
SELECT pipeline_version,
       prompt_version,
       COUNT(*)        AS analyses,
       MIN(analysed_at) AS earliest,
       MAX(analysed_at) AS latest
FROM public.analysis
GROUP BY 1, 2
ORDER BY analyses DESC;
