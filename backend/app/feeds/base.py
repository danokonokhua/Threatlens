from abc import ABC, abstractmethod
from typing import List, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from .. import models
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
            await self.upsert_indicator(normalized)

    async def upsert_indicator(self, data: Dict[str, Any]):
        # 1. Try to find existing indicator (Deduplication)
        result = await self.db.execute(
            select(models.Indicator).where(
                models.Indicator.value == data["value"],
                models.Indicator.type == data["type"]
            )
        )
        indicator = result.scalar_one_or_none()

        if not indicator:
            # Create new
            indicator = models.Indicator(**data)
            self.db.add(indicator)
            await self.db.flush() # Flush to get the ID
        else:
            # Update existing
            indicator.last_seen = datetime.utcnow()
            if data["severity_score"] > indicator.severity_score:
                indicator.severity_score = data["severity_score"]

        # 2. Add Provenance (IndicatorSource)
        source = models.IndicatorSource(
            indicator_id=indicator.id,
            feed_id=self.feed.id,
            external_id=data.get("external_id"),
            last_seen=datetime.utcnow()
        )
        self.db.add(source)
        
        # FIXED: This must be indented inside the method!
        await self.db.commit() 