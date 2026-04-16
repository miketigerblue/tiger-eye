"""RAG retrieval via pgvector — SQL-native semantic search.

Replaces ChromaDB collection.query() with Postgres nearest-neighbour
queries that support full relational filtering.
"""

import logging

from sqlalchemy import text as sql_text

from tiger_eye.database import get_db
from tiger_eye.embedding import generate_embedding
from tiger_eye.metrics import RAG_EMPTY, RAG_ERRORS, RAG_HITS, RAG_QUERIES

log = logging.getLogger(__name__)

# Token budget for RAG context injected into LLM prompt
MAX_CONTEXT_TOKENS = 1500
MAX_QUERY_TOKENS = 2000
CHARS_PER_TOKEN = 4
MAX_RAG_DISTANCE = 0.45  # cosine distance threshold — anything above is noise


def _truncate(text: str, max_tokens: int) -> str:
    max_chars = max_tokens * CHARS_PER_TOKEN
    return text[:max_chars] if len(text) > max_chars else text


# ---------------------------------------------------------------------------
# Shared pgvector query
# ---------------------------------------------------------------------------

_SEARCH_SQL = """
    SELECT
        a.id, a.guid, a.severity_level, a.confidence,
        a.summary_impact, a.source_name, a.source_url,
        a.analysed_at, a.embedding_text,
        e.embedding <=> CAST(:vec AS vector) AS distance
    FROM analysis_embedding e
    JOIN analysis a ON a.id = e.analysis_id
    WHERE e.embedding <=> CAST(:vec AS vector) < :max_dist
    ORDER BY e.embedding <=> CAST(:vec AS vector)
    LIMIT :n
"""


async def _vector_search(
    vector: list[float],
    n_results: int = 10,
    max_distance: float = 1.0,
) -> list[dict]:
    """Core nearest-neighbour search against pgvector."""
    async with get_db() as db:
        result = await db.execute(
            sql_text(_SEARCH_SQL),
            {"vec": str(vector), "n": n_results, "max_dist": max_distance},
        )
        return [dict(r._mapping) for r in result.fetchall()]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def get_similar_analyses(
    title: str,
    summary: str | None,
    content: str | None,
    top_k: int = 3,
) -> str:
    """Retrieve similar past analyses for RAG context using pgvector.

    Returns a formatted string ready to inject into the LLM prompt.
    Only includes results within MAX_RAG_DISTANCE cosine distance.
    """
    query_text = f"{title} {summary or ''} {content or ''}"
    query_text = _truncate(query_text, MAX_QUERY_TOKENS)

    try:
        query_vector = await generate_embedding(query_text)
    except Exception:
        RAG_ERRORS.labels(stage="embedding").inc()
        log.exception(
            "Failed to generate query embedding for RAG — continuing without context",
            extra={"title": (title or "")[:80]},
        )
        return ""

    RAG_QUERIES.inc()
    try:
        rows = await _vector_search(query_vector, n_results=top_k, max_distance=MAX_RAG_DISTANCE)
    except Exception:
        RAG_ERRORS.labels(stage="search").inc()
        log.exception(
            "pgvector search failed for RAG — continuing without context",
            extra={"title": (title or "")[:80]},
        )
        return ""

    if not rows:
        RAG_EMPTY.inc()
        return ""

    RAG_HITS.inc()

    context_parts = []
    token_budget = MAX_CONTEXT_TOKENS
    for row in rows:
        snippet = _truncate(row["embedding_text"] or row["summary_impact"] or "", 400)
        token_cost = len(snippet) // CHARS_PER_TOKEN
        if token_cost > token_budget:
            break
        context_parts.append(
            f"[Similar threat — {row['severity_level']}, "
            f"confidence={row['confidence']}, distance={row['distance']:.3f}]\n{snippet}"
        )
        token_budget -= token_cost

    return "\n---\n".join(context_parts)


async def search_by_text(query_text: str, n_results: int = 10) -> list[dict]:
    """Semantic search by text — used by the internal API."""
    query_vector = await generate_embedding(query_text)
    return await _vector_search(query_vector, n_results=n_results)


async def search_by_vector(embedding: list[float], n_results: int = 10) -> list[dict]:
    """Nearest-neighbour search by pre-computed vector."""
    return await _vector_search(embedding, n_results=n_results)
