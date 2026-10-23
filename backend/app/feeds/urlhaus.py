import httpx
from typing import List, Dict, Any
from .base import BaseFeedParser

class URLHausParser(BaseFeedParser):
    async def fetch_data(self) -> List[Dict[str, Any]]:
        # URLhaus recent URLs API (No API key required for basic tier)
        async with httpx.AsyncClient() as client:
            response = await client.get("https://urlhaus-api.abuse.ch/v1/urls/recent/")
            response.raise_for_status()
            return response.json().get("urls", [])

    def normalize(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        # Map URLhaus fields to our canonical schema
        return {
            "value": raw_data.get("url", ""),
            "type": "url",
            "severity_score": 80 if raw_data.get("url_status") == "online" else 50,
            "confidence": 90,
            "external_id": str(raw_data.get("id"))
        }