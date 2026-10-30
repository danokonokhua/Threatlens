import uuid
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .. import models

async def log_audit_event(
    db: AsyncSession,
    action: str,
    resource: str,
    user_id: Optional[uuid.UUID] = None,
    details: Optional[str] = None
) -> models.AuditLog:
    """
    FR-27: Records an immutable audit log entry for authentication
    and state-changing actions (alerts, incidents, feeds, hunt executions).
    """
    entry = models.AuditLog(
        user_id=user_id,
        action=action,
        resource=resource,
        details=details
    )
    db.add(entry)
    await db.commit()
    return entry

