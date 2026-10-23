from sqlalchemy import Column, String, Integer, Boolean, DateTime, Enum, ForeignKey, Text, UniqueConstraint
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