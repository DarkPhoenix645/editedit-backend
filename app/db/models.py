from sqlalchemy import (
    Boolean,
    Column,
    String,
    Float,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    BigInteger,
    Text,
    Index,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB, INET
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid

from app.db.base import Base
from app.core.rbac import UserRole

class Organization(Base):
    __tablename__ = "organizations"
    __table_args__ = (UniqueConstraint("slug", name="uq_organizations_slug"),)

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, nullable=False, index=True)
    slug = Column(String, nullable=False)
    description = Column(String, nullable=True)
    is_active = Column(Boolean, nullable=False, server_default=text("true"))
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class HealthCheck(Base):
    __tablename__ = "health_check"

    id = Column(Integer, primary_key=True, index=True)
    status = Column(String, nullable=False)

class User(Base):
    __tablename__ = "users"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String, unique=True, index=True, nullable=False)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    name = Column(String, nullable=False)
    is_active = Column(Boolean, nullable=False, server_default=text("true"))
    role = Column(String, nullable=False, default=UserRole.INVESTIGATOR.value)
    last_login = Column(DateTime(timezone=True), nullable=True)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    cases = relationship("ForensicCase", back_populates="investigator")
    audit_logs = relationship("AccessAuditLog", back_populates="user")
    decisions = relationship("InvestigatorDecision", back_populates="investigator")
    refresh_tokens = relationship("RefreshToken", back_populates="user")
    password_reset_tokens = relationship("PasswordResetToken", back_populates="user")

class ForensicCase(Base):
    __tablename__ = "forensic_cases"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_name = Column(String, nullable=False)
    description = Column(String)
    investigator_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    status = Column(String, default="open")
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    investigator = relationship("User", back_populates="cases")
    hypotheses = relationship("ForensicHypothesis", back_populates="case")

class ForensicHypothesis(Base):
    __tablename__ = "forensic_hypotheses"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("forensic_cases.id"))
    generation_source = Column(String)
    anomaly_score = Column(Float)
    confidence_score = Column(Float)
    hypotheses = Column(Text)
    status = Column(String, server_default="pending")
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    case = relationship("ForensicCase", back_populates="hypotheses")
    evidence_links = relationship("HypothesisEvidenceMap", back_populates="hypothesis")

class LogSource(Base):
    __tablename__ = "log_sources"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id = Column(String, unique=True, index=True, nullable=False)
    source_name = Column(String, nullable=False)
    static_trust_level = Column(String, index=True, nullable=False)
    dynamic_trust_score = Column(Float, server_default="1.0", nullable=False)
    provider_type = Column(String, nullable=False)
    os_type = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class AccessAuditLog(Base):
    __tablename__ = "access_audit_log"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    action = Column(String)
    resource_type = Column(String)
    ip_address = Column(INET)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="audit_logs")


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    hashed_token = Column(String, nullable=False, unique=True, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked = Column(Boolean, nullable=False, server_default=text("false"))
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    user = relationship("User", back_populates="refresh_tokens")

class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    hashed_token = Column(String, nullable=False, unique=True, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    user = relationship("User", back_populates="password_reset_tokens")
    
class SealedBlock(Base):
    __tablename__ = "sealed_blocks"
    __table_args__ = (
        UniqueConstraint("source_id", "sequence_number", name="uq_sealed_blocks_source_sequence"),
        Index("ix_sealed_blocks_source_window", "source_id", "window_start", "window_end"),
        Index("ix_sealed_blocks_authoritative_time", "authoritative_time"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_id = Column(UUID(as_uuid=True), ForeignKey("log_sources.id"), nullable=False)
    sequence_number = Column(BigInteger, nullable=False)
    window_start = Column(DateTime(timezone=True), nullable=False)
    window_end = Column(DateTime(timezone=True), nullable=False)
    log_count = Column(Integer, nullable=False)
    payload_hash = Column(LargeBinary, nullable=False)
    chain_hash = Column(LargeBinary, nullable=False)
    tsa_token = Column(LargeBinary, nullable=False)
    authoritative_time = Column(DateTime(timezone=True), nullable=False)
    rsa_signature = Column(LargeBinary, nullable=False)
    signing_key_id = Column(String, nullable=False)
    storage_uri = Column(String, nullable=False)

    traces = relationship("HotColdTrace", back_populates="block")
    cold_payload = relationship(
        "ColdStoredBlock",
        back_populates="block",
        uselist=False,
        cascade="all, delete-orphan",
    )

class ColdStoredBlock(Base):
    __tablename__ = "cold_stored_blocks"

    block_id = Column(UUID(as_uuid=True), ForeignKey("sealed_blocks.id"), primary_key=True)
    source_id = Column(UUID(as_uuid=True), ForeignKey("log_sources.id"), nullable=False, index=True)
    object_bucket = Column(String, nullable=False)
    object_key = Column(String, nullable=False, index=True)
    object_version_id = Column(String, nullable=True)
    object_etag = Column(String, nullable=False)
    object_sha256_hex = Column(String, nullable=False, index=True)
    object_size_bytes = Column(BigInteger, nullable=False)
    object_retention_mode = Column(String, nullable=False)
    object_retention_until = Column(DateTime(timezone=True), nullable=False)
    object_legal_hold = Column(Boolean, nullable=False, server_default=text("false"))
    leaf_hashes = Column(JSONB, nullable=False)
    merkle_root_hex = Column(String, nullable=False, index=True)
    chain_hash_hex = Column(String, nullable=False, index=True)
    timestamp_proof = Column(JSONB, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    block = relationship("SealedBlock", back_populates="cold_payload")

class HotColdTrace(Base):
    __tablename__ = "hot_cold_trace"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    elastic_event_id = Column(String, unique=True, index=True, nullable=False)
    block_id = Column(UUID(as_uuid=True), ForeignKey("sealed_blocks.id"), index=True, nullable=False)

    block = relationship("SealedBlock", back_populates="traces")

class InvestigatorDecision(Base):
    __tablename__ = "investigator_decisions"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("forensic_cases.id"))
    investigator_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    action_type = Column(String)
    hypothesis_id = Column(UUID(as_uuid=True), ForeignKey("forensic_hypotheses.id"), nullable=True)
    reasoning_notes = Column(String)
    ui_state_snapshot = Column(JSONB)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    investigator = relationship("User", back_populates="decisions")

class HypothesisEvidenceMap(Base):
    __tablename__ = "hypothesis_evidence_map"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    hypothesis_id = Column(UUID(as_uuid=True), ForeignKey("forensic_hypotheses.id"))
    elastic_event_id = Column(String)
    evidence_weight = Column(Float)

    hypothesis = relationship("ForensicHypothesis", back_populates="evidence_links")
    
class VirtualOCSFNormalization(Base):
    __tablename__ = "virtual_ocsf_normalization"
    class_name = Column(String, primary_key=True) 
    category_name = Column(String)
    severity = Column(String)
    raw_data_map = Column(JSONB)