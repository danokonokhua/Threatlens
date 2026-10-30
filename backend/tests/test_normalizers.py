import pytest
from app.feeds.threatfox import ThreatFoxParser
from app.feeds.cisa_kev import CISAKEVParser
from app.feeds.feodo import FeodoParser
from app.feeds.malwarebazaar import MalwareBazaarParser
from app.feeds.urlhaus import URLHausParser
from app.feeds.alienvault_otx import AlienVaultOTXParser
from app.feeds.openphish import OpenPhishParser

def test_threatfox_normalization_ip_port():
    """Verify ThreatFox parser strips ports from ip:port indicators."""
    parser = ThreatFoxParser(db=None, feed=None)
    raw = {
        "id": "1001",
        "ioc": "198.51.100.45:8080",
        "ioc_type": "ip:port",
        "threat_type": "botnet_cc",
        "confidence_level": 100
    }
    normalized = parser.normalize(raw)
    assert normalized["value"] == "198.51.100.45"
    assert normalized["type"] == "ip"
    assert normalized["severity_score"] == 90
    assert normalized["confidence"] == 100

def test_threatfox_normalization_hashes_and_domains():
    """Verify ThreatFox maps hashes and domains to canonical types."""
    parser = ThreatFoxParser(db=None, feed=None)
    raw_hash = {"id": "1002", "ioc": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "ioc_type": "sha256_hash", "confidence_level": 85}
    norm_hash = parser.normalize(raw_hash)
    assert norm_hash["type"] == "hash_sha256"

    raw_domain = {"id": "1003", "ioc": "c2-command-stager.com", "ioc_type": "domain", "confidence_level": 75}
    norm_domain = parser.normalize(raw_domain)
    assert norm_domain["type"] == "domain"
    assert norm_domain["severity_score"] == 70

def test_cisa_kev_normalization_ransomware_flag():
    """Verify CISA KEV parser assigns critical severity to actively exploited ransomware CVEs."""
    parser = CISAKEVParser(db=None, feed=None)
    raw_ransomware = {
        "cveID": "CVE-2023-38606",
        "knownRansomwareCampaignUse": "Known"
    }
    norm_ransomware = parser.normalize(raw_ransomware)
    assert norm_ransomware["value"] == "CVE-2023-38606"
    assert norm_ransomware["type"] == "cve"
    assert norm_ransomware["severity_score"] == 95

    raw_non_ransomware = {
        "cveID": "CVE-2024-1001",
        "knownRansomwareCampaignUse": "Unknown"
    }
    norm_non_ransomware = parser.normalize(raw_non_ransomware)
    assert norm_non_ransomware["severity_score"] == 85

def test_feodo_tracker_normalization():
    """Verify Feodo parser normalizes botnet C2 IP addresses."""
    parser = FeodoParser(db=None, feed=None)
    raw = {"ip_address": "185.220.101.5"}
    normalized = parser.normalize(raw)
    assert normalized["value"] == "185.220.101.5"
    assert normalized["type"] == "ip"
    assert normalized["severity_score"] == 90

def test_malwarebazaar_normalization():
    """Verify MalwareBazaar parser normalizes SHA256 hashes."""
    parser = MalwareBazaarParser(db=None, feed=None)
    raw = {"sha256_hash": "a"*64, "id": "mb_1"}
    normalized = parser.normalize(raw)
    assert normalized["value"] == "a"*64
    assert normalized["type"] == "hash_sha256"

def test_urlhaus_normalization_online_vs_offline():
    """Verify URLhaus parser elevates severity for online URLs."""
    parser = URLHausParser(db=None, feed=None)
    raw_online = {"url": "http://evil.com/payload.exe", "url_status": "online", "id": 1}
    assert parser.normalize(raw_online)["severity_score"] == 80

    raw_offline = {"url": "http://evil.com/old.exe", "url_status": "offline", "id": 2}
    assert parser.normalize(raw_offline)["severity_score"] == 50

def test_alienvault_otx_normalization():
    """Verify AlienVault OTX parser maps pulse types correctly."""
    parser = AlienVaultOTXParser(db=None, feed=None)
    raw_ip = {"indicator": "45.154.255.88", "type": "IPv4", "id": 101}
    assert parser.normalize(raw_ip)["type"] == "ip"

    raw_domain = {"indicator": "bad-stager.net", "type": "domain", "id": 102}
    assert parser.normalize(raw_domain)["type"] == "domain"

def test_openphish_normalization():
    """Verify OpenPhish parser extracts and normalizes phishing URLs."""
    parser = OpenPhishParser(db=None, feed=None)
    raw = {"url": "https://secure-login-account-update.com/login", "id": "op_0"}
    normalized = parser.normalize(raw)
    assert normalized["value"] == "https://secure-login-account-update.com/login"
    assert normalized["type"] == "url"
    assert normalized["confidence"] == 90

