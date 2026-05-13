"""SQLAlchemy models for tiger-eye.

Read-only models (owned by tiger2go ingestor):
    ArchiveEntry, CurrentEntry, CveEnriched

Read-write models (owned by tiger-eye):
    AnalysisEntry, AnalysisEmbedding
"""

import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from functools import lru_cache

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    BigInteger,
    Boolean,
    CHAR,
    Column,
    Date,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    Numeric,
    Text,
    Uuid,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from tiger_eye.config import EMBEDDING_DIMENSIONS, get_settings


@lru_cache
def _get_engine():
    s = get_settings()
    return create_async_engine(
        s.database_url,
        pool_size=10,
        max_overflow=20,
        pool_recycle=1800,
        echo=False,
    )


@lru_cache
def _get_session_factory():
    return async_sessionmaker(_get_engine(), class_=AsyncSession, expire_on_commit=False)


@asynccontextmanager
async def get_db():
    factory = _get_session_factory()
    async with factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Read-only models — tables owned by tiger2go ingestor
# ---------------------------------------------------------------------------


class ArchiveEntry(Base):
    """Raw feed entries written by tigerfetch. Read-only for tiger-eye."""

    __tablename__ = "archive"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, server_default=text("uuid_generate_v4()"))
    guid: Mapped[str] = mapped_column(Text, nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    link: Mapped[str] = mapped_column(Text, nullable=False)
    published: Mapped[datetime | None] = mapped_column(DateTime)
    content: Mapped[str | None] = mapped_column(Text)
    summary: Mapped[str | None] = mapped_column(Text)
    author: Mapped[str | None] = mapped_column(Text)
    categories: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    entry_updated: Mapped[datetime | None] = mapped_column(DateTime)
    feed_url: Mapped[str] = mapped_column(Text, nullable=False)
    feed_title: Mapped[str | None] = mapped_column(Text)
    feed_description: Mapped[str | None] = mapped_column(Text)
    feed_language: Mapped[str | None] = mapped_column(Text)
    feed_icon: Mapped[str | None] = mapped_column(Text)
    feed_updated: Mapped[datetime | None] = mapped_column(DateTime)
    inserted_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=text("now()"))


class CurrentEntry(Base):
    """Latest state of each feed entry. Read-only for tiger-eye."""

    __tablename__ = "current"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, server_default=text("uuid_generate_v4()"))
    guid: Mapped[str] = mapped_column(Text, nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    link: Mapped[str] = mapped_column(Text, nullable=False)
    published: Mapped[datetime | None] = mapped_column(DateTime)
    content: Mapped[str | None] = mapped_column(Text)
    summary: Mapped[str | None] = mapped_column(Text)
    author: Mapped[str | None] = mapped_column(Text)
    categories: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    entry_updated: Mapped[datetime | None] = mapped_column(DateTime)
    feed_url: Mapped[str] = mapped_column(Text, nullable=False)
    feed_title: Mapped[str | None] = mapped_column(Text)
    feed_description: Mapped[str | None] = mapped_column(Text)
    feed_language: Mapped[str | None] = mapped_column(Text)
    feed_icon: Mapped[str | None] = mapped_column(Text)
    feed_updated: Mapped[datetime | None] = mapped_column(DateTime)
    inserted_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=text("now()"))


class CveEnriched(Base):
    """NVD-enriched CVE data. Read-only — populated by tigerfetch."""

    __tablename__ = "cve_enriched"

    cve_id: Mapped[str] = mapped_column(Text, primary_key=True)
    source: Mapped[str] = mapped_column(Text, primary_key=True, server_default=text("'NVD'"))
    json: Mapped[dict] = mapped_column(JSONB, nullable=False)
    cvss_base: Mapped[float | None] = mapped_column(Numeric)
    epss: Mapped[float | None] = mapped_column(Numeric)
    modified: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class CveKev(Base):
    """CISA Known Exploited Vulnerabilities catalogue. Read-only — populated by
    tigerfetch (or a future KEV ingestor). One row per CVE — first-class
    attribute, not a cve_enriched source.
    """

    __tablename__ = "cve_kev"

    cve_id: Mapped[str] = mapped_column(Text, primary_key=True)
    vulnerability_name: Mapped[str | None] = mapped_column(Text)
    vendor_project: Mapped[str | None] = mapped_column(Text)
    product: Mapped[str | None] = mapped_column(Text)
    short_description: Mapped[str | None] = mapped_column(Text)
    required_action: Mapped[str | None] = mapped_column(Text)
    date_added: Mapped[datetime | None] = mapped_column(Date)
    due_date: Mapped[datetime | None] = mapped_column(Date)
    known_ransomware_use: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("FALSE"))
    notes: Mapped[str | None] = mapped_column(Text)
    cwes: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    raw: Mapped[dict | None] = mapped_column(JSONB)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=text("now()"))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=text("now()"))
    withdrawn_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class CveEnrichedHistory(Base):
    """Append-only change-capture log for cve_enriched. Read-only — written by
    a Postgres trigger on the cve_enriched table.

    prev_* columns hold the OLD value (None on INSERT). Current state lives in
    cve_enriched; join history rows against it for the full timeline.
    """

    __tablename__ = "cve_enriched_history"

    history_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    cve_id: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(Text, nullable=False)
    captured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    op: Mapped[str] = mapped_column(CHAR(1), nullable=False)  # 'I' | 'U' | 'D'
    prev_json: Mapped[dict | None] = mapped_column(JSONB)
    prev_cvss_base: Mapped[float | None] = mapped_column(Numeric)
    prev_epss: Mapped[float | None] = mapped_column(Numeric)
    prev_modified: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    changed_fields: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, server_default=text("'{}'::text[]")
    )


# ---------------------------------------------------------------------------
# Read-write models — tables owned by tiger-eye
# ---------------------------------------------------------------------------


class AnalysisEntry(Base):
    """LLM-enriched threat analysis of an archive entry."""

    __tablename__ = "analysis"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    guid: Mapped[str] = mapped_column(Text, nullable=False, unique=True, index=True)

    # Classification
    threat_type: Mapped[str | None] = mapped_column(Text)
    severity_level: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[int | None] = mapped_column(Integer)

    # LLM output
    summary_impact: Mapped[str | None] = mapped_column(Text)
    relevance: Mapped[str | None] = mapped_column(Text)
    historical_context: Mapped[str | None] = mapped_column(Text)
    additional_notes: Mapped[str | None] = mapped_column(Text)

    # Structured intelligence (JSONB)
    # key_iocs: [{"type": "ipv4|domain|url|hash_sha256|...", "value": "..."}]
    key_iocs: Mapped[dict | None] = mapped_column(JSONB)
    # recommended_actions: ["patch X", "block Y", ...] — immediate response steps
    # (mitigation_strategies below now holds the durable defensive controls)
    recommended_actions: Mapped[dict | None] = mapped_column(JSONB)
    # Durable defensive controls (patches, segmentation, hardening) —
    # split from recommended_actions for cleaner querying
    mitigation_strategies: Mapped[dict | None] = mapped_column(JSONB)
    affected_systems_sectors: Mapped[dict | None] = mapped_column(JSONB)
    potential_threat_actors: Mapped[dict | None] = mapped_column(JSONB)
    # cve_references: ["CVE-2024-1234", ...] — pure CVE IDs only now
    cve_references: Mapped[dict | None] = mapped_column(JSONB)
    # exploit_references: PoC and advisory URLs — split from cve_references
    exploit_references: Mapped[dict | None] = mapped_column(JSONB)
    # attack_vectors: how the threat reaches the target (e.g. "spearphishing
    # attachment", "exposed RDP", "vulnerable web app"). Restored from v1 schema.
    attack_vectors: Mapped[dict | None] = mapped_column(JSONB)
    # ttps: [{"id": "T1566.001", "name": "Spearphishing Attachment"}, ...]
    ttps: Mapped[dict | None] = mapped_column(JSONB)
    tools_used: Mapped[dict | None] = mapped_column(JSONB)
    malware_families: Mapped[dict | None] = mapped_column(JSONB)
    target_geographies: Mapped[dict | None] = mapped_column(JSONB)

    # Source metadata (denormalised from archive entry)
    entry_title: Mapped[str | None] = mapped_column(Text)
    source_name: Mapped[str | None] = mapped_column(Text)
    source_url: Mapped[str | None] = mapped_column(Text)
    feed_title: Mapped[str | None] = mapped_column(Text)
    feed_description: Mapped[str | None] = mapped_column(Text)
    feed_language: Mapped[str | None] = mapped_column(Text)
    feed_icon: Mapped[str | None] = mapped_column(Text)

    # Timestamps
    analysed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )
    enriched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    inserted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )

    # Embedding source text (for re-embedding without reconstructing)
    embedding_text: Mapped[str | None] = mapped_column(Text)

    # ---- Provenance (Tier-1 no-info-loss migration) ------------------------
    # Which model / prompt / pipeline version produced this row.
    model_id: Mapped[str | None] = mapped_column(Text)
    prompt_version: Mapped[str | None] = mapped_column(Text)
    pipeline_version: Mapped[str | None] = mapped_column(Text)
    prompt_tokens: Mapped[int | None] = mapped_column(Integer)
    response_tokens: Mapped[int | None] = mapped_column(Integer)
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    # SHA-256 of the normalised LLM input text — lets us detect when a feed
    # silently re-edits an article and skip identical-input re-enrichment.
    input_hash: Mapped[bytes | None] = mapped_column(LargeBinary)

    # Optional link to the pipeline_runs row that produced this analysis.
    # NULL for analyses written before migration 007.
    run_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("pipeline_runs.run_id", ondelete="SET NULL")
    )

    # Relationship
    embedding: Mapped["AnalysisEmbedding | None"] = relationship(
        back_populates="analysis", uselist=False, cascade="all, delete-orphan"
    )


class AnalysisEmbedding(Base):
    """Vector embedding for an analysis entry. 1:1 with AnalysisEntry."""

    __tablename__ = "analysis_embedding"

    analysis_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("analysis.id", ondelete="CASCADE"), primary_key=True
    )
    embedding = Column(Vector(EMBEDDING_DIMENSIONS), nullable=False)
    model: Mapped[str] = mapped_column(Text, nullable=False, default="text-embedding-3-small")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )

    # Relationship
    analysis: Mapped["AnalysisEntry"] = relationship(back_populates="embedding")


class PipelineRun(Base):
    """One row per enrichment cycle that did work. Pairs with the per-row
    provenance on AnalysisEntry (model_id, prompt_tokens, latency_ms, …)
    to give run-level cost / latency observability.

    Empty polls (batch_size = 0) don't write a row.
    """

    __tablename__ = "pipeline_runs"

    run_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, server_default=text("uuid_generate_v4()"))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=text("now()"))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)

    batch_size: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    enriched_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failed_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    skipped_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    prompt_tokens_total: Mapped[int | None] = mapped_column(Integer)
    response_tokens_total: Mapped[int | None] = mapped_column(Integer)

    llm_p50_ms: Mapped[int | None] = mapped_column(Integer)
    llm_p95_ms: Mapped[int | None] = mapped_column(Integer)
    llm_max_ms: Mapped[int | None] = mapped_column(Integer)

    model_id: Mapped[str | None] = mapped_column(Text)
    prompt_version: Mapped[str | None] = mapped_column(Text)
    pipeline_version: Mapped[str | None] = mapped_column(Text)

    wake_source: Mapped[str | None] = mapped_column(Text)
    consecutive_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failure_reason: Mapped[str | None] = mapped_column(Text)


class ThreatActor(Base):
    """Canonical threat-actor entity. One row per actor; aliases live in the
    `tiger_eye.entities` curated maps, not in the DB.

    Populated by tiger_eye.entities.canonicalise_actor — generic labels
    (Attacker / unknown / suspected state-sponsored hackers) are filtered
    out and never get a row here.
    """

    __tablename__ = "threat_actors"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, server_default=text("uuid_generate_v4()"))
    canonical_name: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    normalised_key: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    category: Mapped[str | None] = mapped_column(Text)
    attribution_country: Mapped[str | None] = mapped_column(Text)  # ISO 3166-1 alpha-2
    description: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=text("now()"))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=text("now()"))


class MalwareFamily(Base):
    """Canonical malware-family entity. One row per family; aliases live in
    the `tiger_eye.entities` curated maps, not in the DB.

    Populated by tiger_eye.entities.canonicalise_malware — generic labels
    (`ransomware`, `infostealer`, `banking trojans`) are filtered out and
    never get a row here.
    """

    __tablename__ = "malware_families"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, server_default=text("uuid_generate_v4()"))
    canonical_name: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    normalised_key: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    category: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=text("now()"))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=text("now()"))


class AnalysisActor(Base):
    """Many-to-many: an analysis row references one or more threat actors."""

    __tablename__ = "analysis_actor"

    analysis_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("analysis.id", ondelete="CASCADE"), primary_key=True
    )
    actor_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("threat_actors.id", ondelete="RESTRICT"), primary_key=True
    )
    raw_mention: Mapped[str | None] = mapped_column(Text)
    linked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )


class AnalysisMalware(Base):
    """Many-to-many: an analysis row references one or more malware families."""

    __tablename__ = "analysis_malware"

    analysis_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("analysis.id", ondelete="CASCADE"), primary_key=True
    )
    family_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("malware_families.id", ondelete="RESTRICT"), primary_key=True
    )
    raw_mention: Mapped[str | None] = mapped_column(Text)
    linked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )


class FailedEnrichment(Base):
    """Dead-letter row for an archive entry whose enrichment pipeline failed.

    Written by analysis.analyse_and_persist on final failure. The main
    enrichment loop uses this table to (a) skip entries that have exhausted
    their retry budget and (b) avoid reprocessing entries whose next_retry_at
    is still in the future.
    """

    __tablename__ = "failed_enrichment"

    guid: Mapped[str] = mapped_column(Text, primary_key=True)
    stage: Mapped[str] = mapped_column(Text, nullable=False)
    error_class: Mapped[str | None] = mapped_column(Text)
    error_message: Mapped[str | None] = mapped_column(Text)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    first_failed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )
    last_failed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )
    next_retry_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )
