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
)
from sqlalchemy.dialects.postgresql import UUID, JSONB, INET
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid

from app.db.base import Base

class HealthCheck(Base):
    __tablename__ = "health_check"

    id = Column(Integer, primary_key=True, index=True)
    status = Column(String, nullable=False)

class User(Base):
    __tablename__ = "users"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    name = Column(String, nullable=False)
    role = Column(String, default="user", nullable=False)

    cases = relationship("ForensicCase", back_populates="investigator")
    audit_logs = relationship("AccessAuditLog", back_populates="user")
    decisions = relationship("InvestigatorDecision", back_populates="investigator")

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
    decisions = relationship("InvestigatorDecision", back_populates="case")

class ForensicHypothesis(Base):
    __tablename__ = "forensic_hypotheses"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("forensic_cases.id"))
    generation_source = Column(String)
    anomaly_score = Column(Float)
    confidence_score = Column(Float)
    trust_weight = Column(Float, nullable=True)
    pattern_severity = Column(Float, nullable=True)
    rule_trace = Column(JSONB, nullable=True)
    fusion_policy_hash = Column(String(64), nullable=True)
    title = Column(String(512), nullable=True)
    description = Column(Text, nullable=True)
    hypothesis_uid = Column(String(64), nullable=True, index=True)
    evidence_ids = Column(JSONB, nullable=True)
    hypotheses = Column(Text)
    status = Column(String, server_default="pending")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    event_trust_tier = Column(String(32), nullable=True)
    event_action = Column(String(255), nullable=True)
    event_metadata = Column(JSONB, nullable=True)
    mitre_technique_id = Column(String(20), nullable=True)
    mitre_technique_name = Column(String(200), nullable=True)
    mitre_tactic = Column(String(100), nullable=True)

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
    merkle_root = Column(LargeBinary, nullable=False)
    chain_hash = Column(LargeBinary, nullable=False)
    tsa_token = Column(LargeBinary, nullable=False)
    authoritative_time = Column(DateTime(timezone=True), nullable=False)
    rsa_signature = Column(LargeBinary, nullable=False)
    signing_key_id = Column(String, nullable=False)
    storage_uri = Column(String, nullable=False)
    logstash_config_version = Column(String, nullable=False, server_default="v2.1.0")

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
    events = Column(JSONB, nullable=False)
    leaf_hashes = Column(JSONB, nullable=False)
    merkle_root_hex = Column(String, nullable=False, index=True)
    chain_hash_hex = Column(String, nullable=False, index=True)
    timestamp_proof = Column(JSONB, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    block = relationship("SealedBlock", back_populates="cold_payload")

class LogEvent(Base):
    """Persisted events for RAG recovery (ML ingest)."""

    __tablename__ = "log_events"

    event_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_id = Column(UUID(as_uuid=True), ForeignKey("log_sources.id", ondelete="SET NULL"), nullable=True)
    event_json = Column(JSONB, nullable=False)
    event_time = Column(DateTime(timezone=True), nullable=False)
    ingested_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    source = relationship("LogSource", foreign_keys=[source_id])


class ModelSnapshot(Base):
    __tablename__ = "model_snapshots"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    model_type = Column(String, nullable=False)
    events_seen = Column(BigInteger, nullable=False)
    is_calibrating = Column(Boolean, nullable=False)
    checkpoint_path = Column(String, nullable=True)
    config_hash = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class HotColdTrace(Base):
    __tablename__ = "hot_cold_traces"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    event_fingerprint = Column(String, unique=True, index=True, nullable=False)
    elastic_event_id = Column(String, unique=True, index=True, nullable=True)
    cold_offset = Column(Integer, nullable=False)
    storage_uri = Column(String, nullable=False)
    block_id = Column(UUID(as_uuid=True), ForeignKey("sealed_blocks.id"), index=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    block = relationship("SealedBlock", back_populates="traces")

class InvestigatorDecision(Base):
    __tablename__ = "investigator_decisions"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("forensic_cases.id"))
    investigator_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    action_type = Column(String)
    hypothesis_id = Column(UUID(as_uuid=True), ForeignKey("forensic_hypotheses.id"), nullable=True)
    reasoning_notes = Column(String)
    evidence_ids = Column(JSONB, server_default="[]", nullable=False)
    ai_citation = Column(Text, nullable=True)
    ui_state_snapshot = Column(JSONB)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    case = relationship("ForensicCase", foreign_keys=[case_id])
    investigator = relationship("User", back_populates="decisions")

class HypothesisEvidenceMap(Base):
    __tablename__ = "hypothesis_evidence_map"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    hypothesis_id = Column(UUID(as_uuid=True), ForeignKey("forensic_hypotheses.id"))
    elastic_event_id = Column(String)
    event_fingerprint = Column(String, index=True, nullable=True)
    evidence_weight = Column(Float)

    hypothesis = relationship("ForensicHypothesis", back_populates="evidence_links")
    
class VirtualOCSFNormalization(Base):
    __tablename__ = "virtual_ocsf_normalization"
    class_name = Column(String, primary_key=True) 
    category_name = Column(String)
    severity = Column(String)
    raw_data_map = Column(JSONB)