from pydantic import BaseModel, ConfigDict, IPvAnyAddress
from uuid import UUID
from datetime import datetime
from typing import Optional, Any

class AccessAuditLog(BaseModel):
    id: UUID
    user_id: UUID
    action: str
    resource_type: str
    ip_address: IPvAnyAddress
    timestamp: datetime
    model_config = ConfigDict(from_attributes=True)

class InvestigatorDecisionCreate(BaseModel):
    case_id: UUID
    investigator_id: UUID
    action_type: str
    hypothesis_id: Optional[UUID] = None
    reasoning_notes: Optional[str] = None
    ui_state_snapshot: Optional[dict] = None

class InvestigatorDecision(InvestigatorDecisionCreate):
    id: UUID
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)