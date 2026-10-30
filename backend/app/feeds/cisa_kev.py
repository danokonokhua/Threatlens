import httpx
from typing import List, Dict, Any
from .base import BaseFeedParser

class CISAKEVParser(BaseFeedParser):
    """
    CISA Known Exploited Vulnerabilities (KEV) Catalog parser.
    Ingests CVE identifiers actively exploited by adversaries and ransomware groups in the wild.
    """
    async def fetch_data(self) -> List[Dict[str, Any]]:
        headers = {
            "User-Agent": "ThreatLens-CTI-Platform/1.0"
        }
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                    headers=headers,
                    timeout=15.0
                )
                response.raise_for_status()
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                # Return most recent 100 vulnerabilities to keep ingestion lightweight
                return vulnerabilities[-100:] if len(vulnerabilities) > 100 else vulnerabilities
        except Exception as e:
            print(f"⚠️ CISA KEV fetch error: {e}")
            return []

    def normalize(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        cve_id = raw_data.get("cveID", "").strip()
        ransomware_use = raw_data.get("knownRansomwareCampaignUse", "").lower() == "known"
        
        # Actively exploited CVEs in ransomware campaigns receive critical severity
        severity = 95 if ransomware_use else 85

        return {
            "value": cve_id,
            "type": "cve",
            "severity_score": severity,
            "confidence": 95,
            "external_id": cve_id
        }

