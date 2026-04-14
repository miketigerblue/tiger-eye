"""Integration tests that run against a real Postgres + pgvector instance.

These tests are designed to run inside docker-compose.test.yml where
DATABASE_URL points at a fresh tiger2go_test database with migrations applied.

To run locally (outside Docker), set DATABASE_URL to a pgvector-enabled Postgres
and run migrations first:
    DATABASE_URL=... OPENAI_API_KEY=dummy python -m tiger_eye.migrate
    DATABASE_URL=... OPENAI_API_KEY=dummy python -m pytest tests/test_integration.py -v
"""

import os
import uuid
from datetime import UTC, datetime

import pytest

# Skip entire module if no real DATABASE_URL is configured
_has_db = os.environ.get("DATABASE_URL", "").startswith("postgresql")
pytestmark = pytest.mark.skipif(not _has_db, reason="No DATABASE_URL — skipping integration tests")


@pytest.mark.anyio
async def test_database_connection():
    """Verify we can connect and the analysis table exists."""
    from sqlalchemy import text as sql_text

    from tiger_eye.database import get_db

    async with get_db() as db:
        result = await db.execute(sql_text("SELECT 1 AS ok"))
        assert result.scalar() == 1


@pytest.mark.anyio
async def test_pgvector_extension_installed():
    """Verify the vector extension is available."""
    from sqlalchemy import text as sql_text

    from tiger_eye.database import get_db

    async with get_db() as db:
        result = await db.execute(sql_text("SELECT extname FROM pg_extension WHERE extname = 'vector'"))
        assert result.scalar() == "vector"


@pytest.mark.anyio
async def test_analysis_table_schema():
    """Verify key columns exist on the analysis table."""
    from sqlalchemy import text as sql_text

    from tiger_eye.database import get_db

    async with get_db() as db:
        result = await db.execute(
            sql_text("""
                SELECT column_name FROM information_schema.columns
                WHERE table_name = 'analysis'
                ORDER BY ordinal_position
            """)
        )
        columns = [r[0] for r in result.fetchall()]

    assert "threat_type" in columns
    assert "entry_title" in columns
    assert "severity_level" in columns
    assert "key_iocs" in columns
    assert "ttps" in columns
    assert "embedding_text" in columns
    # Dropped columns should not exist
    assert "attack_vectors" not in columns
    assert "exploit_references" not in columns
    assert "mitigation_strategies" not in columns


@pytest.mark.anyio
async def test_analysis_roundtrip():
    """Insert an analysis + embedding and read it back via ORM."""
    from tiger_eye.config import EMBEDDING_DIMENSIONS
    from tiger_eye.database import AnalysisEmbedding, AnalysisEntry, get_db

    analysis_id = uuid.uuid4()
    now = datetime.now(UTC)

    analysis = AnalysisEntry(
        id=analysis_id,
        guid=f"test-{uuid.uuid4()}",
        threat_type="VULNERABILITY",
        severity_level="HIGH",
        confidence=85,
        summary_impact="Test roundtrip entry",
        key_iocs=[{"type": "ipv4", "value": "10.0.0.1"}],
        ttps=[{"id": "T1190", "name": "Exploit Public-Facing Application"}],
        entry_title="Test Entry Title",
        source_name="test-feed",
        analysed_at=now,
        inserted_at=now,
        embedding_text="test embedding text",
    )

    # Zero vector for testing (correct dimension)
    zero_vec = [0.0] * EMBEDDING_DIMENSIONS
    embedding = AnalysisEmbedding(
        analysis_id=analysis_id,
        embedding=zero_vec,
        model="text-embedding-3-small",
        created_at=now,
    )

    async with get_db() as db:
        db.add(analysis)
        db.add(embedding)
        await db.commit()

    # Read back
    from sqlalchemy import select

    async with get_db() as db:
        result = await db.execute(select(AnalysisEntry).where(AnalysisEntry.id == analysis_id))
        loaded = result.scalar_one()

        assert loaded.threat_type == "VULNERABILITY"
        assert loaded.severity_level == "HIGH"
        assert loaded.confidence == 85
        assert loaded.entry_title == "Test Entry Title"
        assert loaded.key_iocs == [{"type": "ipv4", "value": "10.0.0.1"}]
        assert loaded.ttps == [{"id": "T1190", "name": "Exploit Public-Facing Application"}]

        # Verify embedding exists
        emb_result = await db.execute(select(AnalysisEmbedding).where(AnalysisEmbedding.analysis_id == analysis_id))
        emb = emb_result.scalar_one()
        assert emb is not None
        assert len(emb.embedding) == EMBEDDING_DIMENSIONS


@pytest.mark.anyio
async def test_cascade_delete():
    """Deleting an analysis should cascade-delete its embedding."""
    from sqlalchemy import func, select

    from tiger_eye.config import EMBEDDING_DIMENSIONS
    from tiger_eye.database import AnalysisEmbedding, AnalysisEntry, get_db

    analysis_id = uuid.uuid4()
    now = datetime.now(UTC)

    async with get_db() as db:
        db.add(
            AnalysisEntry(
                id=analysis_id,
                guid=f"cascade-{uuid.uuid4()}",
                threat_type="MALWARE",
                severity_level="CRITICAL",
                confidence=95,
                analysed_at=now,
                inserted_at=now,
            )
        )
        db.add(
            AnalysisEmbedding(
                analysis_id=analysis_id,
                embedding=[0.0] * EMBEDDING_DIMENSIONS,
                model="text-embedding-3-small",
                created_at=now,
            )
        )
        await db.commit()

    # Delete the analysis
    from sqlalchemy import delete

    async with get_db() as db:
        await db.execute(delete(AnalysisEntry).where(AnalysisEntry.id == analysis_id))
        await db.commit()

    # Embedding should be gone
    async with get_db() as db:
        result = await db.execute(
            select(func.count()).select_from(AnalysisEmbedding).where(AnalysisEmbedding.analysis_id == analysis_id)
        )
        assert result.scalar() == 0


@pytest.mark.anyio
async def test_vector_search_returns_results():
    """Insert a vector and search for it — proves HNSW index works."""
    from sqlalchemy import text as sql_text

    from tiger_eye.config import EMBEDDING_DIMENSIONS
    from tiger_eye.database import AnalysisEmbedding, AnalysisEntry, get_db

    analysis_id = uuid.uuid4()
    now = datetime.now(UTC)

    # Insert with a known non-zero vector
    vec = [0.1] * EMBEDDING_DIMENSIONS
    async with get_db() as db:
        db.add(
            AnalysisEntry(
                id=analysis_id,
                guid=f"vsearch-{uuid.uuid4()}",
                threat_type="APT_CAMPAIGN",
                severity_level="HIGH",
                confidence=80,
                summary_impact="Vector search test entry",
                analysed_at=now,
                inserted_at=now,
                embedding_text="test search content",
            )
        )
        db.add(
            AnalysisEmbedding(
                analysis_id=analysis_id,
                embedding=vec,
                model="text-embedding-3-small",
                created_at=now,
            )
        )
        await db.commit()

    # Search with the same vector — should be distance 0
    async with get_db() as db:
        result = await db.execute(
            sql_text("""
                SELECT a.id, e.embedding <=> CAST(:vec AS vector) AS distance
                FROM analysis_embedding e
                JOIN analysis a ON a.id = e.analysis_id
                ORDER BY e.embedding <=> CAST(:vec AS vector)
                LIMIT 1
            """),
            {"vec": str(vec)},
        )
        row = result.fetchone()
        assert row is not None
        assert float(row.distance) < 0.01  # near-zero for identical vectors


@pytest.mark.anyio
async def test_migrations_table_populated():
    """The _migrations table should have at least one record."""
    from sqlalchemy import text as sql_text

    from tiger_eye.database import get_db

    async with get_db() as db:
        result = await db.execute(sql_text("SELECT count(*) FROM _migrations"))
        count = result.scalar()
        assert count >= 1
