import json
from ..redis_client import redis_client
from .. import models
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

def get_cached_enrichment(indicator_value: str, source: str) -> dict | None:
    cache_key = f"enrichment:{source}:{indicator_value}"
    cached = redis_client.get(cache_key)
    if cached:
        return json.loads(cached)
    return None

def set_cached_enrichment(indicator_value: str, source: str, data: dict, ttl: int = 86400):
    cache_key = f"enrichment:{source}:{indicator_value}"
    redis_client.setex(cache_key, ttl, json.dumps(data))

async def enrich_indicator(db: AsyncSession, indicator: models.Indicator):
    # 1. Check Cache
    cached = get_cached_enrichment(indicator.value, "reputation")
    if cached:
        print(f" Cache hit for {indicator.value}")
        return cached

    # 2. Mock External API Call (Replace with real httpx call to AbuseIPDB/VT in production)
    # We simulate a realistic API response to prove the pipeline works.
    mock_verdict = "malicious" if indicator.severity_score > 50 else "clean"
    mock_data = {
        "verdict": mock_verdict,
        "confidence": indicator.confidence,
        "geo_country": "RU" if indicator.type == "ip" else "N/A",
        "asn": "AS12345" if indicator.type == "ip" else "N/A"
    }

    # 3. Cache the result for 24 hours
    set_cached_enrichment(indicator.value, "reputation", mock_data)

    # 4. Save to Database
    enrichment = models.Enrichment(
        indicator_id=indicator.id,
        source="reputation_mock",
        verdict=mock_verdict,
        confidence=indicator.confidence,
        raw_data=json.dumps(mock_data)
    )
    db.add(enrichment)
    await db.commit()
    
    print(f"🔍 Enriched and cached: {indicator.value}")
    return mock_data