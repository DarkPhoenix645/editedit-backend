from pydantic import BaseModel, ConfigDict, Field
from uuid import UUID
from datetime import datetime
from typing import Optional

class LogSourceBase(BaseModel):
    agent_id: str
    source_name: str
    static_trust_level: str
    dynamic_trust_score: float = 0.0
    provider_type: str
    os_type: str

class LogSourceCreate(LogSourceBase):
    pass

class LogSource(LogSourceBase):
    id: UUID
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class ColdIngestResponse(BaseModel):
    sealed: bool
    block_id: Optional[str] = None
    reason: Optional[str] = None