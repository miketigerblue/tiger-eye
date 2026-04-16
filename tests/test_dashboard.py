"""Tests for the dashboard API + static HTML page.

- Cache: repeated calls within the TTL return the same payload without
  re-running the aggregate queries.
- API endpoint: JSON shape, force-refresh semantics.
- HTML endpoint: serves the static template.
"""

from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from tiger_eye import dashboard_queries
from tiger_eye.main import app


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def _clear_dashboard_cache():
    dashboard_queries.invalidate_cache()
    yield
    dashboard_queries.invalidate_cache()


# ---------------------------------------------------------------------------
# TTL cache
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_cache_rebuilds_only_once_per_ttl():
    fake_payload = {"kpi": {"total_analyses": 42}, "ttl_seconds": 60}
    build = AsyncMock(return_value=fake_payload)

    with patch.object(dashboard_queries, "_build_dashboard", build):
        first = await dashboard_queries.get_dashboard_data()
        second = await dashboard_queries.get_dashboard_data()
        third = await dashboard_queries.get_dashboard_data()

    assert first is fake_payload
    assert second is fake_payload
    assert third is fake_payload
    # Three callers, one aggregate run.
    assert build.await_count == 1


@pytest.mark.anyio
async def test_force_refresh_bypasses_cache():
    payload_a = {"kpi": {"total_analyses": 1}, "ttl_seconds": 60}
    payload_b = {"kpi": {"total_analyses": 2}, "ttl_seconds": 60}
    build = AsyncMock(side_effect=[payload_a, payload_b])

    with patch.object(dashboard_queries, "_build_dashboard", build):
        first = await dashboard_queries.get_dashboard_data()
        second = await dashboard_queries.get_dashboard_data(force_refresh=True)

    assert first is payload_a
    assert second is payload_b
    assert build.await_count == 2


# ---------------------------------------------------------------------------
# API endpoint
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_api_dashboard_returns_payload():
    fake_payload = {
        "generated_at": "2026-04-16 22:30",
        "ttl_seconds": 60,
        "kpi": {"total_analyses": 1473, "critical": 40},
        "cves": [],
        "threat_types": [],
        "daily": [],
        "sources": [],
        "actors": [],
        "malware": [],
        "ttps": [],
        "geos": [],
        "feed": [],
    }
    with patch("tiger_eye.main.get_dashboard_data", AsyncMock(return_value=fake_payload)) as mock_fn:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/api/dashboard")

    assert resp.status_code == 200
    body = resp.json()
    assert body["kpi"]["total_analyses"] == 1473
    assert body["ttl_seconds"] == 60
    mock_fn.assert_awaited_once_with(force_refresh=False)


@pytest.mark.anyio
async def test_api_dashboard_refresh_flag_forwarded():
    fake_payload = {"kpi": {}, "ttl_seconds": 60}
    with patch("tiger_eye.main.get_dashboard_data", AsyncMock(return_value=fake_payload)) as mock_fn:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/api/dashboard?refresh=1")

    assert resp.status_code == 200
    mock_fn.assert_awaited_once_with(force_refresh=True)


# ---------------------------------------------------------------------------
# HTML page
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_dashboard_page_serves_html():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/dashboard")

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    text = resp.text
    # Smoke-check a few hallmarks of our template so nobody accidentally
    # swaps in an unrelated page without updating the tests.
    assert "TIGER-EYE" in text
    assert "/api/dashboard" in text
    assert "loading-overlay" in text
