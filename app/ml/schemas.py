"""Phase 5 Pydantic schemas — hot path inference and evidence contracts."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class TrustTier(str, Enum):
    KERNEL = "kernel"
    IAM = "iam"
    OS = "os"
    APPLICATION = "application"
    CLOUD = "cloud"
    IOT = "iot"
    UNKNOWN = "unknown"


class HypothesisStatus(str, Enum):
    ACTIVE = "active"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


class LogEvent(BaseModel):
    event_id: str
    timestamp: datetime
    source_ip: str
    dest_ip: Optional[str] = None
    user_id: str
    action: str
    resource: Optional[str] = None
    outcome: Optional[str] = Field(None, description="e.g. success | failure")
    source_id: Optional[str] = Field(None, description="UUID of log_sources row")
    message: Optional[str] = None
    fingerprint: Optional[str] = Field(None, description="Upstream event fingerprint/hash")
    trust_tier: TrustTier = TrustTier.APPLICATION
    metadata: dict[str, Any] = Field(default_factory=dict)


class Hypothesis(BaseModel):
    hypothesis_id: str
    title: str
    description: str
    score: float = Field(..., ge=0.0, le=1.0)
    anomaly_score: float = Field(..., ge=0.0, le=1.0)
    trust_weight: float = Field(..., ge=0.0, le=1.0)
    pattern_severity: float = Field(..., ge=0.0, le=2.0)
    rule_trace: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    status: HypothesisStatus = HypothesisStatus.ACTIVE
    created_at: datetime = Field(default_factory=datetime.utcnow)
    mitre_techniques: list[str] = Field(default_factory=list)
    case_id: Optional[UUID] = None
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    mitre_tactic: Optional[str] = None
    cryptographic_evidence_snippet: Optional[str] = None
    neuro_symbolic_reasoning_chain: list[str] = Field(default_factory=list)
    scenario_id: Optional[str] = None
    scenario_title: Optional[str] = None
    neural_score: Optional[float] = None
    symbolic_risk_score: Optional[float] = None
    decision_threshold: Optional[float] = None


class MitreTechniqueOut(BaseModel):
    id: str
    name: str
    tactic: str
    tactic_id: str
    description: str
    keywords: list[str] = Field(default_factory=list)


class InferEventRequest(BaseModel):
    events: list[LogEvent]
    case_id: Optional[UUID] = Field(
        default=None,
        description="When set, hypotheses are stored under this investigation; "
        "ingest must be filtered to the case's attached log sources.",
    )


class InferEventResponse(BaseModel):
    hypotheses: list[Hypothesis]
    events_processed: int
    graph_nodes: int
    graph_edges: int
    block_id: Optional[str] = None
    calibrating: bool = False
    rag_ingest_ok: bool = True
    processing_time_ms: int = 0


class InferAckResponse(BaseModel):
    """Async ack for Logstash HTTP push (job queued)."""

    job_id: str
    status: str
    case_id: Optional[UUID] = None
    case_auto_generated: bool = False
    events_received: int


class InferJobStatusResponse(BaseModel):
    job_id: str
    status: str
    case_id: Optional[UUID] = None
    case_auto_generated: bool = False
    events_received: int
    events_processed: int = 0
    hypotheses_emitted: int = 0
    error: Optional[str] = None
    result: dict[str, Any] = Field(default_factory=dict)


class VerificationRequest(BaseModel):
    block_id: str
    chain_hash: str


class VerificationResult(BaseModel):
    block_id: str
    verified: bool
    message: str
    tsa_compliant: bool = False


class CounterfactualRequest(BaseModel):
    hypothesis_id: str
    modify_attribute: str
    modify_value: Any


class CounterfactualResponse(BaseModel):
    original_score: float
    modified_score: float
    delta: float
    explanation: str


class RAGQueryRequest(BaseModel):
    query: str
    context_event_ids: Optional[list[str]] = None
    strict_critic: bool = False


class RAGQueryResponse(BaseModel):
    answer: str
    cited_event_ids: list[str] = Field(default_factory=list)
    confidence: float = 0.0


class EvidenceItem(BaseModel):
    event_fingerprint: Optional[str] = None
    elastic_event_id: Optional[str] = None
    block_id: Optional[UUID] = None
    cold_offset: Optional[int] = None
    storage_uri: Optional[str] = None
    raw_log_line: Optional[str] = None
    object_key: Optional[str] = None
    object_version: Optional[str] = None
    object_bucket: Optional[str] = None
    leaf_index: Optional[int] = None
    proof_available: bool = False


class HypothesisOut(BaseModel):
    id: UUID
    hypothesis_uid: Optional[str] = None
    title: str = ""
    anomaly_score: float = 0.0
    confidence_score: float = 0.0
    severity: str = "LOW"
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    mitre_tactic: Optional[str] = None
    rule_id: Optional[str] = None
    status: str = "pending"
    created_at: datetime
    evidence_count: int = 0
    case_id: Optional[UUID] = None
    scenario_id: Optional[str] = None
    scenario_title: Optional[str] = None


class HypothesisDetail(BaseModel):
    """Full hypothesis for UI: listing row + reasoning, MITRE, WORM evidence."""

    id: UUID
    hypothesis_uid: Optional[str] = None
    case_id: Optional[UUID] = None
    title: str = ""
    description: Optional[str] = None
    hypotheses_legacy: Optional[str] = None
    anomaly_score: float = 0.0
    confidence_score: float = 0.0
    severity: str = "LOW"
    neural_anomaly_score: float = 0.0
    symbolic_risk_score: float = 0.0
    trust_weight: float = 0.0
    pattern_severity: float = 1.0
    rule_trace: list[str] = Field(default_factory=list)
    reasoning_chain: list[str] = Field(default_factory=list)
    cryptographic_evidence_snippet: Optional[str] = None
    neuro_symbolic_reasoning_chain: list[str] = Field(default_factory=list)
    fusion_policy_hash: Optional[str] = None
    evidence_ids: Optional[list[Any]] = None
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_techniques: list[str] = Field(default_factory=list)
    rule_id: Optional[str] = None
    status: str = "pending"
    event_trust_tier: Optional[str] = None
    event_action: Optional[str] = None
    event_metadata: Optional[dict[str, Any]] = None
    created_at: datetime
    evidence: list[EvidenceItem] = Field(default_factory=list)
    scenario_id: Optional[str] = None
    scenario_title: Optional[str] = None
    decision_threshold: float = 0.3


class ScenarioTimelineItem(BaseModel):
    scenario_id: str
    scenario_title: Optional[str] = None
    case_id: Optional[UUID] = None
    case_title: Optional[str] = None
    case_origin: Optional[str] = None
    auto_generated: bool = False
    aggregate_start_ts: datetime
    aggregate_end_ts: datetime
    hypotheses: list[HypothesisOut] = Field(default_factory=list)


class HypothesisCaseAttachRequest(BaseModel):
    case_id: UUID


class CounterfactualModifiersBody(BaseModel):
    modifiers: dict[str, Any]


class CounterfactualModifiersResponse(BaseModel):
    original_score: float
    modified_score: float
    would_fire: bool
    explanation: str = ""
