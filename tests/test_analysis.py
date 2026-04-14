"""Unit tests for analysis normalisation and embedding text construction."""

from types import SimpleNamespace

from tiger_eye.analysis import normalise_analysis
from tiger_eye.embedding import build_embedding_text


def _make_entry(**kwargs):
    defaults = {
        "title": "Test Alert",
        "link": "https://example.com",
        "published": "2026-04-14",
        "feed_title": "Test Feed",
    }
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


# ---------------------------------------------------------------------------
# normalise_analysis — threat_type
# ---------------------------------------------------------------------------


def test_normalise_threat_type_valid():
    result = normalise_analysis({"threat_type": "ransomware", "severity_level": "HIGH", "confidence": 80})
    assert result["threat_type"] == "RANSOMWARE"


def test_normalise_threat_type_invalid_defaults_to_other():
    result = normalise_analysis({"threat_type": "banana", "severity_level": "HIGH", "confidence": 50})
    assert result["threat_type"] == "OTHER"


def test_normalise_threat_type_missing_defaults_to_other():
    result = normalise_analysis({"severity_level": "HIGH", "confidence": 50})
    assert result["threat_type"] == "OTHER"


# ---------------------------------------------------------------------------
# normalise_analysis — severity
# ---------------------------------------------------------------------------


def test_normalise_severity_uppercase():
    result = normalise_analysis({"threat_type": "MALWARE", "severity_level": "high", "confidence": 80})
    assert result["severity_level"] == "HIGH"


def test_normalise_severity_invalid_defaults_to_informational():
    result = normalise_analysis({"threat_type": "MALWARE", "severity_level": "banana", "confidence": 50})
    assert result["severity_level"] == "INFORMATIONAL"


# ---------------------------------------------------------------------------
# normalise_analysis — confidence
# ---------------------------------------------------------------------------


def test_normalise_confidence_clamped():
    result = normalise_analysis({"threat_type": "MALWARE", "severity_level": "LOW", "confidence": 150})
    assert result["confidence"] == 100


def test_normalise_confidence_from_float_string():
    result = normalise_analysis({"threat_type": "MALWARE", "severity_level": "MEDIUM", "confidence": "72.8"})
    assert result["confidence"] == 72


def test_normalise_confidence_invalid_defaults_to_zero():
    result = normalise_analysis({"threat_type": "MALWARE", "severity_level": "LOW", "confidence": "not-a-number"})
    assert result["confidence"] == 0


# ---------------------------------------------------------------------------
# normalise_analysis — structured IOCs
# ---------------------------------------------------------------------------


def test_normalise_iocs_structured_passthrough():
    result = normalise_analysis(
        {
            "threat_type": "MALWARE",
            "severity_level": "HIGH",
            "confidence": 80,
            "key_iocs": [{"type": "ipv4", "value": "1.2.3.4"}, {"type": "domain", "value": "evil.com"}],
        }
    )
    assert result["key_iocs"] == [
        {"type": "ipv4", "value": "1.2.3.4"},
        {"type": "domain", "value": "evil.com"},
    ]


def test_normalise_iocs_plain_strings_wrapped():
    result = normalise_analysis(
        {
            "threat_type": "MALWARE",
            "severity_level": "HIGH",
            "confidence": 80,
            "key_iocs": ["1.2.3.4", "evil.com"],
        }
    )
    assert result["key_iocs"] == [
        {"type": "unknown", "value": "1.2.3.4"},
        {"type": "unknown", "value": "evil.com"},
    ]


def test_normalise_iocs_none_becomes_empty():
    result = normalise_analysis(
        {
            "threat_type": "MALWARE",
            "severity_level": "HIGH",
            "confidence": 80,
            "key_iocs": None,
        }
    )
    assert result["key_iocs"] == []


# ---------------------------------------------------------------------------
# normalise_analysis — structured TTPs
# ---------------------------------------------------------------------------


def test_normalise_ttps_structured_passthrough():
    result = normalise_analysis(
        {
            "threat_type": "APT_CAMPAIGN",
            "severity_level": "HIGH",
            "confidence": 80,
            "ttps": [{"id": "T1566.001", "name": "Spearphishing Attachment"}],
        }
    )
    assert result["ttps"] == [{"id": "T1566.001", "name": "Spearphishing Attachment"}]


def test_normalise_ttps_plain_strings_wrapped():
    result = normalise_analysis(
        {
            "threat_type": "APT_CAMPAIGN",
            "severity_level": "HIGH",
            "confidence": 80,
            "ttps": ["phishing", "credential dumping"],
        }
    )
    assert result["ttps"] == [
        {"id": "", "name": "phishing"},
        {"id": "", "name": "credential dumping"},
    ]


def test_normalise_ttps_none_becomes_empty():
    result = normalise_analysis(
        {
            "threat_type": "MALWARE",
            "severity_level": "HIGH",
            "confidence": 80,
            "ttps": None,
        }
    )
    assert result["ttps"] == []


# ---------------------------------------------------------------------------
# normalise_analysis — simple list fields
# ---------------------------------------------------------------------------


def test_normalise_list_fields_none_becomes_empty_list():
    result = normalise_analysis(
        {
            "threat_type": "MALWARE",
            "severity_level": "HIGH",
            "confidence": 50,
            "cve_references": None,
            "recommended_actions": None,
        }
    )
    assert result["cve_references"] == []
    assert result["recommended_actions"] == []


def test_normalise_list_fields_string_json_parsed():
    result = normalise_analysis(
        {
            "threat_type": "VULNERABILITY",
            "severity_level": "HIGH",
            "confidence": 50,
            "cve_references": '["CVE-2024-1234", "CVE-2024-5678"]',
        }
    )
    assert result["cve_references"] == ["CVE-2024-1234", "CVE-2024-5678"]


# ---------------------------------------------------------------------------
# build_embedding_text
# ---------------------------------------------------------------------------


def test_build_embedding_text_includes_new_fields():
    result = {
        "threat_type": "RANSOMWARE",
        "severity_level": "CRITICAL",
        "confidence": 95,
        "summary_impact": "Major ransomware campaign",
        "cve_references": ["CVE-2024-1234"],
        "key_iocs": [{"type": "ipv4", "value": "192.168.1.1"}, {"type": "domain", "value": "evil.com"}],
        "ttps": [{"id": "T1566.001", "name": "Spearphishing Attachment"}],
        "potential_threat_actors": ["APT29"],
        "malware_families": ["LockBit"],
        "target_geographies": ["United Kingdom"],
        "tools_used": ["Cobalt Strike"],
        "affected_systems_sectors": ["healthcare"],
        "relevance": "High relevance to NHS",
        "historical_context": "Continuation of 2024 campaign",
    }
    entry = _make_entry(title="Test Alert Title")
    text = build_embedding_text(entry, result)
    assert "Title: Test Alert Title" in text
    assert "Threat Type: RANSOMWARE" in text
    assert "Severity: CRITICAL" in text
    assert "Confidence: 95" in text
    assert "CVE-2024-1234" in text
    assert "ipv4:192.168.1.1" in text
    assert "domain:evil.com" in text
    assert "T1566.001 Spearphishing Attachment" in text
    assert "APT29" in text
    assert "LockBit" in text
    assert "healthcare" in text


def test_build_embedding_text_handles_empty_fields():
    entry = _make_entry(title="Minimal Entry")
    text = build_embedding_text(entry, {})
    assert "Title: Minimal Entry" in text
    assert "Threat Type: " in text
    assert "Severity: " in text
