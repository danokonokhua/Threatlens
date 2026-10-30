import httpx
from typing import List, Dict, Any
from .base import BaseFeedParser

class ThreatFoxParser(BaseFeedParser):
    """
    ThreatFox feed parser (abuse.ch).
    Ingests fresh multi-type IOCs (IPs, domains, URLs, malware hashes)
    associated with known malware families and botnet C2s.
    """
    async def fetch_data(self) -> List[Dict[str, Any]]:
        headers = {
            "User-Agent": "ThreatLens-CTI-Platform/1.0",
            "Content-Type": "application/json"
        }
        payload = {
            "query": "get_iocs",
            "days": 1
        }
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    "https://threatfox-api.abuse.ch/api/v1/",
                    json=payload,
                    headers=headers,
                    timeout=15.0
                )
                response.raise_for_status()
                data = response.json()
                if data.get("query_status") == "ok":
                    return data.get("data", [])
                return []
        except Exception as e:
            print(f"⚠️ ThreatFox fetch error: {e}")
            return []

    def normalize(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        raw_type = raw_data.get("ioc_type", "").lower()
        ioc_value = raw_data.get("ioc", "")
        
        # Map ThreatFox ioc_type to ThreatLens canonical types
        if raw_type == "ip:port":
            type_normalized = "ip"
            # Strip port if present
            if ":" in ioc_value:
                ioc_value = ioc_value.split(":")[0]
        elif raw_type == "domain":
            type_normalized = "domain"
        elif raw_type == "url":
            type_normalized = "url"
        elif raw_type in ("sha256_hash", "hash_sha256"):
            type_normalized = "hash_sha256"
        elif raw_type in ("md5_hash", "hash_md5"):
            type_normalized = "hash_md5"
        else:
            type_normalized = raw_type or "domain"

        confidence = raw_data.get("confidence_level", 75)
        # Higher confidence threats get higher base severity
        severity = 90 if confidence >= 80 else 70

        return {
            "value": ioc_value.strip(),
            "type": type_normalized,
            "severity_score": severity,
            "confidence": confidence,
            "external_id": str(raw_data.get("id", ""))
        }

