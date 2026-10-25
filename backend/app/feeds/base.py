from abc import ABC, abstractmethod
from typing import List, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from .. import models
from ..services.scoring import calculate_severity_score
from ..services.enrichment import enrich_indicator
from ..services.alert_engine import AlertRuleEngine
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
        print(f"📥 Fetched {len(raw_data)} items from {self.feed.name}")
        
        for item in raw_data:
            normalized = self.normalize(item)
            await self.upsert_and_enrich(normalized)

    async def upsert_and_enrich(self, data: Dict[str, Any]):
        # 1. Extract external_id so it doesn't crash the Indicator model
        external_id = data.pop("external_id", None)

        # 2. Deduplication Check
        result = await self.db.execute(
            select(models.Indicator).where(
                models.Indicator.value == data["value"],
                models.Indicator.type == data["type"]
            )
        )
        indicator = result.scalar_one_or_none()
        is_new = False

        if not indicator:
            indicator = models.Indicator(**data)
            self.db.add(indicator)
            await self.db.flush()
            is_new = True
        else:
            indicator.last_seen = datetime.utcnow()

        # 3. Calculate Multi-Source Count for Scoring
        source_count_result = await self.db.execute(
            select(func.count(models.IndicatorSource.indicator_id)).where(
                models.IndicatorSource.indicator_id == indicator.id
            )
        )
        source_count = source_count_result.scalar() + 1

        # 4. Apply Scoring Engine
        indicator.severity_score = calculate_severity_score(
            base_severity=data.get("severity_score", 50),
            source_confidence=data.get("confidence", 50),
            last_seen=indicator.last_seen,
            source_count=source_count
        )

        # 5. Add Provenance (IndicatorSource)
        source = models.IndicatorSource(
            indicator_id=indicator.id,
            feed_id=self.feed.id,
            external_id=external_id,
            last_seen=datetime.utcnow()
        )
        self.db.add(source)
        await self.db.commit()

        # 6. Sync to Elasticsearch
        from ..services.es_sync import sync_indicator_to_es
        es_doc = {
            "id": str(indicator.id),
            "value": indicator.value,
            "type": indicator.type,
            "severity_score": indicator.severity_score,
            "confidence": indicator.confidence,
            "status": indicator.status,
            "first_seen": indicator.first_seen.isoformat() if indicator.first_seen else None,
            "last_seen": indicator.last_seen.isoformat() if indicator.last_seen else None,
            "sources": [self.feed.name]
        }
        await sync_indicator_to_es(es_doc)

        # 7. Evaluate Alert Rules (THE CRITICAL STEP)
        if is_new or indicator.severity_score >= 80:
            alert_engine = AlertRuleEngine(self.db)
            alerts = await alert_engine.evaluate_indicator(indicator)
            if alerts:
                print(f"🚨 Created {len(alerts)} alert(s) for indicator {indicator.value}")
                await self.db.commit()