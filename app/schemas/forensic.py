from pydantic import BaseModel, ConfigDict, Field
from uuid import UUID
from datetime import datetime
from typing import Optional, List

class ForensicCaseBase(BaseModel):
    case_name: str
    description: Optional[str] = None
    status: str = "open"

class ForensicCaseCreate(BaseModel):
    case_name: str
    description: Optional[str] = None
    investigator_id: UUID

class ForensicCase(ForensicCaseBase):
    id: UUID
    investigator_id: UUID
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class ForensicHypothesisBase(BaseModel):
    case_id: UUID
    generation_source: str
    anomaly_score: float = 0.0
    confidence_score: float = 0.0
    hypotheses: str
    status: str

class ForensicHypothesis(ForensicHypothesisBase):
    id: UUID
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class EvidenceMap(BaseModel):
    id: UUID
    hypothesis_id: UUID
    elastic_event_id: str
    evidence_weight: float
    model_config = ConfigDict(from_attributes=True)