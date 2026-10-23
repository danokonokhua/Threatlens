import httpx
from typing import List, Dict, Any
from .base import BaseFeedParser

class FeodoParser(BaseFeedParser):
    async def fetch_data(self) -> List[Dict[str, Any]]:
        headers = {
            "User-Agent": "ThreatLens-CTI-Platform/1.0"
        }
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
                    headers=headers,
                    timeout=10.0
                )
                response.raise_for_status()
                return response.json()
        except Exception as e:
            print(f"⚠️ Feodo error: {e}")
            return []

    def normalize(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        ip = raw_data.get("ip_address", "")
        return {
            "value": ip,
            "type": "ip",
            "severity_score": 90,
            "confidence": 95,
            "external_id": ip
        }