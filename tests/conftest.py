"""Shared test fixtures for tiger-eye."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def mock_entry():
    """Factory for fake ArchiveEntry-like objects."""

    def _make(**overrides):
        defaults = {
            "title": "Test Alert",
            "link": "https://example.com/alert",
            "published": "2026-04-14",
            "feed_title": "Test Feed",
            "guid": "test-guid-abc123",
            "content": "Test content about a security vulnerability.",
            "summary": "A critical vulnerability was found.",
            "author": "Test Author",
            "categories": ["security", "cve"],
            "feed_description": "Test feed description",
            "feed_language": "en",
            "feed_icon": None,
        }
        defaults.update(overrides)
        return SimpleNamespace(**defaults)

    return _make


@pytest.fixture
def sample_analysis_result():
    """A normalised analysis result dict."""
    return {
        "threat_type": "VULNERABILITY",
        "severity_level": "HIGH",
        "confidence": 85,
        "summary_impact": "Critical RCE vulnerability in widely-used library.",
        "relevance": "High relevance — affects enterprise web stacks.",
        "historical_context": "Related to Log4Shell-class JNDI injection.",
        "additional_notes": "",
        "key_iocs": [
            {"type": "domain", "value": "evil.com"},
            {"type": "ipv4", "value": "1.2.3.4"},
        ],
        "recommended_actions": ["Patch immediately", "Block IOCs at firewall"],
        "affected_systems_sectors": ["technology", "finance"],
        "potential_threat_actors": ["APT29"],
        "cve_references": ["CVE-2024-1234"],
        "ttps": [{"id": "T1190", "name": "Exploit Public-Facing Application"}],
        "tools_used": ["Cobalt Strike"],
        "malware_families": [],
        "target_geographies": ["United States", "United Kingdom"],
    }


@pytest.fixture
def mock_db_session():
    """An AsyncMock masquerading as a get_db() context manager."""
    session = AsyncMock()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    return session


@pytest.fixture
def mock_db_session_with_scalar(mock_db_session):
    """DB session that returns a configurable scalar value."""

    def _configure(scalar_value):
        result = MagicMock()
        result.scalar.return_value = scalar_value
        result.scalar_one_or_none.return_value = scalar_value
        mock_db_session.execute = AsyncMock(return_value=result)
        return mock_db_session

    return _configure
