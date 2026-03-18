from sqlalchemy import Column, String, Float, DateTime, ForeignKey, Integer, LargeBinary, BigInteger
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

class ForensicHypothesis(Base):
    __tablename__ = "forensic_hypotheses"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("forensic_cases.id"))
    generation_source = Column(String)
    anomaly_score = Column(Float)
    confidence_score = Column(Float)
    hypotheses = Column(String)
    status = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    case = relationship("ForensicCase", back_populates="hypotheses")
    evidence_links = relationship("HypothesisEvidenceMap", back_populates="hypothesis")

class LogSource(Base):
    __tablename__ = "log_sources"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id = Column(String)
    source_name = Column(String)
    static_trust_level = Column(String)
    dynamic_trust_score = Column(Float)
    provider_type = Column(String)
    os_type = Column(String)
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
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_id = Column(UUID(as_uuid=True), ForeignKey("log_sources.id"))
    sequence_number = Column(BigInteger, nullable=False)
    window_start = Column(DateTime(timezone=True))
    window_end = Column(DateTime(timezone=True))
    log_count = Column(Integer)
    payload_hash = Column(LargeBinary)
    chain_hash = Column(LargeBinary)
    tsa_token = Column(LargeBinary, nullable=True)
    authoritative_time = Column(DateTime(timezone=True))
    rsa_signature = Column(LargeBinary)
    signing_key_id = Column(String)
    storage_uri = Column(String)

    traces = relationship("HotColdTrace", back_populates="block")

class HotColdTrace(Base):
    __tablename__ = "hot_cold_trace"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    elastic_event_id = Column(String, index=True)
    block_id = Column(UUID(as_uuid=True), ForeignKey("sealed_blocks.id"))

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