import uuid
from datetime import datetime
from app import models
from app.main import indicator_to_stix

def test_stix_21_indicator_structure():
    """Verify STIX 2.1 indicator object complies with OASIS specification."""
    indicator = models.Indicator(
        id=uuid.uuid4(),
        value="198.51.100.23",
        type="ip",
        severity_score=90,
        confidence=95,
        status="active",
        created_at=datetime.utcnow()
    )
    stix_obj = indicator_to_stix(indicator)

    assert stix_obj["type"] == "indicator"
    assert stix_obj["spec_version"] == "2.1"
    assert stix_obj["id"].startswith("indicator--")
    assert stix_obj["pattern_type"] == "stix"
    assert stix_obj["pattern"] == "[ipv4-addr:value = '198.51.100.23']"
    assert stix_obj["confidence"] == 95
    assert stix_obj["custom_properties"]["x_threatlens_severity"] == 90

def test_stix_pattern_generation_by_type():
    """Verify STIX pattern syntax for various IOC types."""
    test_cases = [
        ("domain", "evil.com", "[domain-name:value = 'evil.com']"),
        ("url", "http://evil.com/drop", "[url:value = 'http://evil.com/drop']"),
        ("hash_sha256", "b"*64, f"[file:hashes.'SHA-256' = '{'b'*64}']"),
        ("cve", "CVE-2024-21413", "[vulnerability:name = 'CVE-2024-21413']"),
    ]
    for ioc_type, val, expected_pattern in test_cases:
        ind = models.Indicator(
            id=uuid.uuid4(),
            value=val,
            type=ioc_type,
            severity_score=80,
            confidence=85,
            created_at=datetime.utcnow()
        )
        stix = indicator_to_stix(ind)
        assert stix["pattern"] == expected_pattern

