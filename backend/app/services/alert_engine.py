from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from .. import models
import redis
import json
from datetime import datetime

class AlertRuleEngine:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.redis_client = redis.Redis.from_url(
            "redis://redis:6379/0", 
            decode_responses=True
        )

    async def evaluate_indicator(self, indicator: models.Indicator) -> list:
        """Evaluate an indicator against all active alert rules."""
        alerts_to_create = []
        
        # Fetch all active alert rules
        result = await self.db.execute(
            select(models.AlertRule).where(models.AlertRule.is_active == True)
        )
        rules = result.scalars().all()
        
        for rule in rules:
            if self._matches_rule(indicator, rule):
                alert = await self._create_alert(indicator, rule)
                alerts_to_create.append(alert)
        
        # Auto-alert on high severity (score > 85) even without a rule
        if indicator.severity_score > 85:
            alert = await self._create_auto_alert(indicator)
            alerts_to_create.append(alert)
        
        return alerts_to_create

    def _matches_rule(self, indicator: models.Indicator, rule: models.AlertRule) -> bool:
        """Check if indicator matches rule conditions."""
        if rule.min_severity_score and indicator.severity_score < rule.min_severity_score:
            return False
        
        if rule.indicator_type and rule.indicator_type != indicator.type:
            return False
        
        return True

    async def _create_alert(self, indicator: models.Indicator, rule: models.AlertRule) -> models.Alert:
        """Create an alert from a matched rule."""
        alert = models.Alert(
            indicator_id=indicator.id,
            rule_id=rule.id,
            severity=rule.severity_level or "high",
            status="new",
            title=f"Alert: {indicator.type} {indicator.value[:50]}",
            description=f"Indicator matched rule '{rule.name}'",
            created_at=datetime.utcnow()
        )
        self.db.add(alert)
        await self.db.flush()
        
        # FIX: Removed 'await' because _publish_alert_event is synchronous
        self._publish_alert_event(alert, "alerts.new")
        
        return alert

    async def _create_auto_alert(self, indicator: models.Indicator) -> models.Alert:
        """Create automatic alert for high-severity indicators."""
        alert = models.Alert(
            indicator_id=indicator.id,
            rule_id=None,
            severity="critical" if indicator.severity_score > 90 else "high",
            status="new",
            title=f"High Severity Indicator: {indicator.value[:50]}",
            description=f"Auto-generated alert for indicator with score {indicator.severity_score}",
            created_at=datetime.utcnow()
        )
        self.db.add(alert)
        await self.db.flush()
        
        # FIX: Removed 'await' here too
        self._publish_alert_event(alert, "alerts.new")
        
        return alert

    def _publish_alert_event(self, alert: models.Alert, event_type: str):
        """Publish alert event to Redis for real-time broadcast."""
        event = {
            "type": event_type,
            "alert_id": str(alert.id),
            "indicator_id": str(alert.indicator_id),
            "severity": alert.severity,
            "status": alert.status,
            "title": alert.title,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        channel = "alerts.new" if event_type == "alerts.new" else "alerts.updated"
        self.redis_client.publish(channel, json.dumps(event))
        print(f"📢 Published alert event to {channel}")