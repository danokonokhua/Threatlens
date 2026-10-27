from sqlalchemy import Column, String, Integer, Boolean, DateTime, Enum, ForeignKey, Text, UniqueConstraint
from sqlalchemy.orm import relationship 
from sqlalchemy.dialects.postgresql import UUID
import uuid
from datetime import datetime
from .database import Base
import enum

class RoleEnum(str, enum.Enum):
    admin = "admin"
    security_engineer = "security_engineer"
    incident_responder = "incident_responder"
    threat_hunter = "threat_hunter"
    soc_analyst = "soc_analyst"
    executive = "executive"

class User(Base):
    __tablename__ = "users"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(Enum(RoleEnum), default=RoleEnum.soc_analyst, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class Indicator(Base):
    __tablename__ = "indicators"
    __table_args__ = (
        UniqueConstraint('value', 'type', name='uq_indicator_value_type'),
    )
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    value = Column(String, nullable=False)
    type = Column(String, nullable=False) # ip, domain, url, hash_md5, hash_sha256
    severity_score = Column(Integer, default=0)
    confidence = Column(Integer, default=0)
    status = Column(String, default="active")
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)

class AuditLog(Base):
    __tablename__ = "audit_log"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    action = Column(String, nullable=False)
    resource = Column(String, nullable=False)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

class Feed(Base):
    __tablename__ = "feeds"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, unique=True, nullable=False)
    url = Column(String, nullable=False)
    feed_type = Column(String, nullable=False) # e.g., 'urlhaus', 'otx'
    is_active = Column(Boolean, default=True)

class IndicatorSource(Base):
    __tablename__ = "indicator_sources"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    indicator_id = Column(UUID(as_uuid=True), ForeignKey("indicators.id"), nullable=False)
    feed_id = Column(UUID(as_uuid=True), ForeignKey("feeds.id"), nullable=False)
    external_id = Column(String, nullable=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

class Enrichment(Base):
    __tablename__ = "enrichments"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    indicator_id = Column(UUID(as_uuid=True), ForeignKey("indicators.id"), nullable=False)
    source = Column(String, nullable=False) # e.g., 'abuseipdb', 'virustotal'
    verdict = Column(String, nullable=True) # e.g., 'malicious', 'clean'
    confidence = Column(Integer, nullable=True)
    raw_data = Column(Text, nullable=True) # Store JSON response as string
    created_at = Column(DateTime, default=datetime.utcnow)

class AlertRule(Base):
    __tablename__ = "alert_rules"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    min_severity_score = Column(Integer, nullable=True)
    indicator_type = Column(String, nullable=True)  # ip, domain, url, hash
    required_tag = Column(String, nullable=True)
    severity_level = Column(String, default="medium")  # low, medium, high, critical
    is_active = Column(Boolean, default=True)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    indicator_id = Column(UUID(as_uuid=True), ForeignKey("indicators.id"), nullable=False)
    rule_id = Column(UUID(as_uuid=True), ForeignKey("alert_rules.id"), nullable=True)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id"), nullable=True) # Added for Incident linking
    severity = Column(String, nullable=False)  # low, medium, high, critical
    status = Column(String, default="new")  # new, acknowledged, in-progress, resolved, closed
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    assigned_to = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    acknowledged_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    indicator = relationship("Indicator", backref="alerts")
    rule = relationship("AlertRule", backref="alerts")
    incident = relationship("Incident", back_populates="alerts") # Added for Incident linking

class Incident(Base):
    __tablename__ = "incidents"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String, default="open")  # open, investigating, resolved, closed
    severity = Column(String, default="medium")
    assigned_to = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationship to alerts
    alerts = relationship("Alert", back_populates="incident", lazy="selectin")