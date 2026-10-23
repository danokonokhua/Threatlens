from sqlalchemy import Column, String, Integer, Boolean, DateTime, Enum, ForeignKey, Text
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
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    value = Column(String, unique=True, index=True, nullable=False)
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