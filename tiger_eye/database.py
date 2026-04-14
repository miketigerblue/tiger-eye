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
    Column,
    DateTime,
    ForeignKey,
    Integer,
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
    # recommended_actions: ["patch X", "block Y", ...] (includes mitigations)
    recommended_actions: Mapped[dict | None] = mapped_column(JSONB)
    affected_systems_sectors: Mapped[dict | None] = mapped_column(JSONB)
    potential_threat_actors: Mapped[dict | None] = mapped_column(JSONB)
    # cve_references: ["CVE-2024-1234", ...] (includes exploit advisory URLs)
    cve_references: Mapped[dict | None] = mapped_column(JSONB)
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
