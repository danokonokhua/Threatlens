from ..services.es_sync import sync_indicator_to_es
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from .. import models
from ..services.scoring import calculate_severity_score
from ..services.enrichment import enrich_indicator
from datetime import datetime

class BaseFeedParser(ABC):
    def __init__(self, db: AsyncSession, feed: models.Feed):
        self.db = db
        self.feed = feed

    @abstractmethod
    async def fetch_data(self) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    def normalize(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        pass

    async def process(self):
        raw_data = await self.fetch_data()
        for item in raw_data:
            normalized = self.normalize(item)
            await self.upsert_and_enrich(normalized)

    async def upsert_and_enrich(self, data: Dict[str, Any]):
        # FIX: Extract external_id so it doesn't crash the Indicator model
        external_id = data.pop("external_id", None)

        # 1. Deduplication Check
        result = await self.db.execute(
            select(models.Indicator).where(
                models.Indicator.value == data["value"],
                models.Indicator.type == data["type"]
            )
        )
        indicator = result.scalar_one_or_none()

        if not indicator:
            # Create new indicator (data now only contains valid columns)
            indicator = models.Indicator(**data)
            self.db.add(indicator)
            await self.db.flush() # Flush to get the ID
            is_new = True
        else:
            # Update existing
            indicator.last_seen = datetime.utcnow()
            is_new = False

        # 2. Calculate Multi-Source Count for Scoring
        source_count_result = await self.db.execute(
            select(func.count(models.IndicatorSource.indicator_id)).where(
                models.IndicatorSource.indicator_id == indicator.id
            )
        )
        source_count = source_count_result.scalar() + 1

        # 3. Apply Scoring Engine
        indicator.severity_score = calculate_severity_score(
            base_severity=data.get("severity_score", 50),
            source_confidence=data.get("confidence", 50),
            last_seen=indicator.last_seen,
            source_count=source_count
        )

        # 4. Add Provenance (IndicatorSource)
        source = models.IndicatorSource(
            indicator_id=indicator.id,
            feed_id=self.feed.id,
            external_id=external_id,
            last_seen=datetime.utcnow()
        )
        self.db.add(source)
        await self.db.commit()
                # 6. Sync to Elasticsearch for immediate searchability
        # Build a flat dict for ES
        es_doc = {
            "id": str(indicator.id),
            "value": indicator.value,
            "type": indicator.type,
            "severity_score": indicator.severity_score,
            "confidence": indicator.confidence,
            "status": indicator.status,
            "first_seen": indicator.first_seen.isoformat() if indicator.first_seen else None,
            "last_seen": indicator.last_seen.isoformat() if indicator.last_seen else None,
            "sources": [self.feed.name] # Simplified for MVP; in prod, aggregate all sources
        }
        await sync_indicator_to_es(es_doc)

        # 5. Trigger Enrichment (Only if new)
        if is_new:
            await enrich_indicator(self.db, indicator)