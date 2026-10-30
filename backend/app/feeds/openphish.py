import httpx
from typing import List, Dict, Any
from .base import BaseFeedParser

class OpenPhishParser(BaseFeedParser):
    """
    OpenPhish / PhishTank Feed Parser.
    Ingests zero-hour verified phishing URLs.
    """
    async def fetch_data(self) -> List[Dict[str, Any]]:
        headers = {
            "User-Agent": "ThreatLens-CTI-Platform/1.0"
        }
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    "https://openphish.com/feed.txt",
                    headers=headers,
                    timeout=15.0
                )
                if response.status_code == 200:
                    lines = [line.strip() for line in response.text.splitlines() if line.strip()]
                    return [{"url": url, "id": f"op_{idx}"} for idx, url in enumerate(lines[:100])]
                return []
        except Exception as e:
            print(f"⚠️ OpenPhish fetch error: {e}")
            return []

    def normalize(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        url = raw_data.get("url", "").strip()
        return {
            "value": url,
            "type": "url",
            "severity_score": 80,
            "confidence": 90,
            "external_id": raw_data.get("id")
        }

