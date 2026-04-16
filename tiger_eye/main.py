"""tiger-eye — pgvector-native threat intelligence enricher.

Dual-mode: FastAPI internal API + background enrichment loop.
"""

import asyncio
import contextlib
import logging
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from uuid import UUID

import uvicorn
from fastapi import FastAPI, HTTPException
from prometheus_client import make_asgi_app as prometheus_asgi_app
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, or_, select

from tiger_eye.analysis import DLQ_MAX_ATTEMPTS, analyse_and_persist
from tiger_eye.config import get_settings
from tiger_eye.database import (
    AnalysisEmbedding,
    AnalysisEntry,
    ArchiveEntry,
    FailedEnrichment,
    _get_engine,
    get_db,
)
from tiger_eye.logging_config import configure_logging
from tiger_eye.metrics import (
    BACKOFF_STREAK,
    BATCH_SIZE,
    DLQ_DEPTH,
    ENTRIES_ENRICHED,
    ENTRIES_FAILED,
    LOOP_RUNNING,
)
from tiger_eye.rag import search_by_text, search_by_vector
from tiger_eye.tracing import get_tracer, init_tracing, instrument_app, instrument_db

log = logging.getLogger(__name__)
tracer = get_tracer()

# Backoff state for the enrichment loop
_consecutive_failures = 0
_MAX_BACKOFF = 300  # 5 minutes
_CONCURRENCY = 5  # max parallel enrichment tasks per batch


def _backoff_delay() -> float:
    """Exponential backoff: 2^failures seconds, capped at _MAX_BACKOFF."""
    return float(min(2**_consecutive_failures, _MAX_BACKOFF))


# ---------------------------------------------------------------------------
# Request/response models
# ---------------------------------------------------------------------------


class TextSearchQuery(BaseModel):
    query_text: str
    n_results: int = Field(default=10, ge=1, le=100)


class VectorSearchQuery(BaseModel):
    embeddings: list[float]
    n_results: int = Field(default=10, ge=1, le=100)


# ---------------------------------------------------------------------------
# Enrichment loop
# ---------------------------------------------------------------------------


async def enrichment_loop():
    """Poll for unenriched archive entries and process them."""
    global _consecutive_failures

    s = get_settings()
    log.info(
        "Enrichment loop started",
        extra={"interval": s.enrich_interval, "batch_size": s.enrich_batch_size},
    )
    LOOP_RUNNING.set(1)

    while True:
        try:
            async with get_db() as db:
                # Pick up entries that:
                #   - have no AnalysisEntry yet, AND
                #   - either aren't in the DLQ, OR are in it but eligible for retry:
                #       attempts < DLQ_MAX_ATTEMPTS AND next_retry_at <= now()
                now = datetime.now(UTC)
                stmt = (
                    select(ArchiveEntry)
                    .outerjoin(AnalysisEntry, AnalysisEntry.guid == ArchiveEntry.guid)
                    .outerjoin(FailedEnrichment, FailedEnrichment.guid == ArchiveEntry.guid)
                    .where(AnalysisEntry.guid.is_(None))
                    .where(
                        or_(
                            FailedEnrichment.guid.is_(None),
                            and_(
                                FailedEnrichment.attempts < DLQ_MAX_ATTEMPTS,
                                FailedEnrichment.next_retry_at <= now,
                            ),
                        )
                    )
                    .order_by(ArchiveEntry.inserted_at.asc())
                    .limit(s.enrich_batch_size)
                )
                result = await db.execute(stmt)
                entries = result.scalars().all()

            if not entries:
                log.debug("No new entries to enrich")
                _consecutive_failures = 0
                BACKOFF_STREAK.set(0)
            else:
                BATCH_SIZE.observe(len(entries))
                log.info("Found entries to enrich", extra={"count": len(entries)})

                sem = asyncio.Semaphore(_CONCURRENCY)

                async def _bounded_enrich(e, _sem=sem):
                    async with _sem:
                        return await analyse_and_persist(e)

                with tracer.start_as_current_span("enrichment_batch", attributes={"batch_size": len(entries)}):
                    results = await asyncio.gather(
                        *(_bounded_enrich(e) for e in entries),
                        return_exceptions=True,
                    )

                enriched = 0
                failures = 0
                for i, r in enumerate(results):
                    if isinstance(r, Exception):
                        failures += 1
                        ENTRIES_FAILED.labels(stage="pipeline").inc()
                        log.error(
                            "Entry enrichment raised",
                            extra={"guid": entries[i].guid[:20], "error": str(r)},
                        )
                    elif r is not None:
                        enriched += 1
                        ENTRIES_ENRICHED.labels(
                            threat_type=getattr(r, "threat_type", None) or "UNKNOWN",
                            severity_level=getattr(r, "severity_level", None) or "UNKNOWN",
                        ).inc()
                    else:
                        failures += 1

                log.info(
                    "Enrichment cycle complete",
                    extra={"enriched": enriched, "failed": failures, "total": len(entries)},
                )

                if failures == len(entries):
                    _consecutive_failures += 1
                    BACKOFF_STREAK.set(_consecutive_failures)
                    delay = _backoff_delay()
                    log.warning(
                        "All entries failed — backing off",
                        extra={"failures": len(entries), "delay_s": delay, "streak": _consecutive_failures},
                    )
                    await asyncio.sleep(delay)
                    continue
                else:
                    _consecutive_failures = 0
                    BACKOFF_STREAK.set(0)

        except asyncio.CancelledError:
            log.info("Enrichment loop cancelled — shutting down")
            LOOP_RUNNING.set(0)
            return
        except Exception:
            _consecutive_failures += 1
            BACKOFF_STREAK.set(_consecutive_failures)
            delay = _backoff_delay()
            log.exception(
                "Enrichment loop error",
                extra={"delay_s": delay, "streak": _consecutive_failures},
            )
            await asyncio.sleep(delay)
            continue

        await asyncio.sleep(s.enrich_interval)


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

_loop_task: asyncio.Task | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _loop_task

    s = get_settings()
    configure_logging(log_level=s.log_level, json_output=s.log_json)
    init_tracing()
    instrument_db(_get_engine())

    _loop_task = asyncio.create_task(enrichment_loop())
    yield
    _loop_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await _loop_task


app = FastAPI(title="tiger-eye", docs_url="/docs", lifespan=lifespan)
instrument_app(app)

# Mount Prometheus metrics at /metrics
metrics_app = prometheus_asgi_app()
app.mount("/metrics", metrics_app)


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------


@app.get("/health")
async def health():
    try:
        async with get_db() as db:
            result = await db.execute(select(func.count()).select_from(AnalysisEmbedding))
            embed_count = result.scalar() or 0
            result = await db.execute(select(func.count()).select_from(AnalysisEntry))
            analysis_count = result.scalar() or 0
            result = await db.execute(
                select(func.count())
                .select_from(FailedEnrichment)
                .where(FailedEnrichment.attempts < DLQ_MAX_ATTEMPTS)
            )
            dlq_retryable = result.scalar() or 0
            result = await db.execute(
                select(func.count())
                .select_from(FailedEnrichment)
                .where(FailedEnrichment.attempts >= DLQ_MAX_ATTEMPTS)
            )
            dlq_exhausted = result.scalar() or 0
    except Exception as exc:
        raise HTTPException(status_code=503, detail="database unavailable") from exc

    DLQ_DEPTH.labels(status="retryable").set(dlq_retryable)
    DLQ_DEPTH.labels(status="exhausted").set(dlq_exhausted)

    return {
        "status": "ok",
        "analyses": analysis_count,
        "embeddings": embed_count,
        "dlq_retryable": dlq_retryable,
        "dlq_exhausted": dlq_exhausted,
        "loop_running": _loop_task is not None and not _loop_task.done(),
        "consecutive_failures": _consecutive_failures,
    }


@app.post("/internal/search/text")
async def api_search_text(query: TextSearchQuery):
    with tracer.start_as_current_span("search_by_text"):
        results = await search_by_text(query.query_text, query.n_results)
    return {"results": results}


@app.post("/internal/search/vector")
async def api_search_vector(query: VectorSearchQuery):
    with tracer.start_as_current_span("search_by_vector"):
        results = await search_by_vector(query.embeddings, query.n_results)
    return {"results": results}


@app.get("/internal/node/{node_id}")
async def api_get_node(node_id: str):
    try:
        parsed_id = UUID(node_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="invalid UUID format") from exc

    async with get_db() as db:
        result = await db.execute(select(AnalysisEntry).where(AnalysisEntry.id == parsed_id))
        analysis = result.scalar_one_or_none()
        if not analysis:
            raise HTTPException(status_code=404, detail="not found")

        embed_result = await db.execute(select(AnalysisEmbedding).where(AnalysisEmbedding.analysis_id == analysis.id))
        embedding = embed_result.scalar_one_or_none()

    return {
        "id": str(analysis.id),
        "guid": analysis.guid,
        "severity_level": analysis.severity_level,
        "confidence": analysis.confidence,
        "summary_impact": analysis.summary_impact,
        "analysed_at": analysis.analysed_at.isoformat() if analysis.analysed_at else None,
        "has_embedding": embedding is not None,
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main():
    s = get_settings()
    uvicorn.run(
        "tiger_eye.main:app",
        host=s.api_host,
        port=s.api_port,
        log_level="info",
    )


if __name__ == "__main__":
    main()
