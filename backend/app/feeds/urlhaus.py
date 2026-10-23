import httpx
from typing import List, Dict, Any
from .base import BaseFeedParser

class URLHausParser(BaseFeedParser):
    async def fetch_data(self) -> List[Dict[str, Any]]:
        headers = {
            "User-Agent": "ThreatLens-CTI-Platform/1.0"
        }
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    "https://urlhaus-api.abuse.ch/v1/urls/recent/",
                    headers=headers,
                    timeout=10.0
                )
                response.raise_for_status()
                return response.json().get("urls", [])
        except Exception as e:
            print(f"⚠️ URLhaus error: {e}")
            return []

    def normalize(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "value": raw_data.get("url", ""),
            "type": "url",
            "severity_score": 80 if raw_data.get("url_status") == "online" else 50,
            "confidence": 90,
            "external_id": str(raw_data.get("id"))
        }