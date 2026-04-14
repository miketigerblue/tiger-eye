"""Tests for FastAPI API endpoints.

Uses FastAPI TestClient with mocked database sessions.
"""

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from tiger_eye.main import app


@pytest.fixture
def anyio_backend():
    return "asyncio"


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_health_returns_ok_when_db_available():
    mock_result = MagicMock()
    mock_result.scalar.return_value = 5

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=mock_result)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    with patch("tiger_eye.main.get_db", return_value=mock_session):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/health")

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert "analyses" in body
    assert "embeddings" in body
    assert "loop_running" in body
    assert "consecutive_failures" in body


@pytest.mark.anyio
async def test_health_returns_503_on_db_failure():
    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(side_effect=ConnectionError("db down"))
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    with patch("tiger_eye.main.get_db", return_value=mock_session):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/health")

    assert resp.status_code == 503


# ---------------------------------------------------------------------------
# Node endpoint
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_get_node_invalid_uuid_returns_400():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/internal/node/not-a-uuid")
    assert resp.status_code == 400
    assert "invalid UUID" in resp.json()["detail"]


@pytest.mark.anyio
async def test_get_node_not_found_returns_404():
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=mock_result)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    test_uuid = str(uuid.uuid4())
    with patch("tiger_eye.main.get_db", return_value=mock_session):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get(f"/internal/node/{test_uuid}")

    assert resp.status_code == 404


@pytest.mark.anyio
async def test_get_node_returns_analysis():
    test_id = uuid.uuid4()
    mock_analysis = SimpleNamespace(
        id=test_id,
        guid="test-guid-123",
        severity_level="HIGH",
        confidence=85,
        summary_impact="Test impact",
        analysed_at=datetime(2026, 4, 14, tzinfo=UTC),
    )

    # First execute returns analysis, second returns embedding
    call_count = 0

    async def mock_execute(stmt):
        nonlocal call_count
        call_count += 1
        result = MagicMock()
        if call_count == 1:
            result.scalar_one_or_none.return_value = mock_analysis
        else:
            result.scalar_one_or_none.return_value = SimpleNamespace(analysis_id=test_id)
        return result

    mock_session = AsyncMock()
    mock_session.execute = mock_execute
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    with patch("tiger_eye.main.get_db", return_value=mock_session):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get(f"/internal/node/{test_id}")

    assert resp.status_code == 200
    body = resp.json()
    assert body["guid"] == "test-guid-123"
    assert body["severity_level"] == "HIGH"
    assert body["confidence"] == 85
    assert body["has_embedding"] is True


# ---------------------------------------------------------------------------
# Search endpoints
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_search_text_calls_rag():
    mock_results = [
        {
            "id": str(uuid.uuid4()),
            "guid": "g1",
            "severity_level": "HIGH",
            "confidence": 80,
            "summary_impact": "test",
            "source_name": "feed",
            "source_url": "https://example.com",
            "analysed_at": "2026-04-14",
            "distance": 0.15,
        }
    ]

    with patch("tiger_eye.main.search_by_text", new_callable=AsyncMock, return_value=mock_results):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/internal/search/text",
                json={"query_text": "ransomware attack", "n_results": 5},
            )

    assert resp.status_code == 200
    assert len(resp.json()["results"]) == 1


@pytest.mark.anyio
async def test_search_vector_calls_rag():
    mock_results = [
        {
            "id": str(uuid.uuid4()),
            "guid": "g2",
            "severity_level": "MEDIUM",
            "confidence": 60,
            "summary_impact": "test",
            "source_name": "feed",
            "source_url": "https://example.com",
            "analysed_at": "2026-04-14",
            "distance": 0.25,
        }
    ]

    with patch("tiger_eye.main.search_by_vector", new_callable=AsyncMock, return_value=mock_results):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/internal/search/vector",
                json={"embeddings": [0.1] * 10, "n_results": 5},
            )

    assert resp.status_code == 200
    assert len(resp.json()["results"]) == 1


@pytest.mark.anyio
async def test_search_text_validates_n_results_bounds():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/internal/search/text",
            json={"query_text": "test", "n_results": 200},
        )
    assert resp.status_code == 422  # Pydantic validation error
