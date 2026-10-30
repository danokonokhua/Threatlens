import uuid
from app import models

def test_audit_log_model_fields():
    """Verify AuditLog structure adheres to FR-27 compliance requirements."""
    test_user_id = uuid.uuid4()
    log = models.AuditLog(
        id=uuid.uuid4(),
        user_id=test_user_id,
        action="alert_resolved",
        resource="alert:12345",
        details="Resolved by senior SOC analyst"
    )
    assert log.action == "alert_resolved"
    assert log.resource == "alert:12345"
    assert log.user_id == test_user_id
    assert "Resolved" in log.details

