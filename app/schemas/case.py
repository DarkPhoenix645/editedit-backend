from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class CaseCreate(BaseModel):
    case_name: str = Field(..., min_length=1, max_length=512)
    description: Optional[str] = Field(None, max_length=10000)
    status: str = Field(default="open", max_length=64)
    investigator_id: Optional[UUID] = Field(
        default=None,
        description="Admin/IT only: assign investigator; defaults to current user",
    )


class CaseUpdate(BaseModel):
    case_name: Optional[str] = Field(None, min_length=1, max_length=512)
    description: Optional[str] = Field(None, max_length=10000)
    status: Optional[str] = Field(None, max_length=64)
    investigator_id: Optional[UUID] = None


class CaseOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    case_name: str
    description: Optional[str]
    investigator_id: Optional[UUID]
    status: Optional[str]
    created_at: Optional[datetime]


class CaseListResponse(BaseModel):
    items: list[CaseOut]
    total: int
    skip: int
    limit: int


class LogSourceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    agent_id: str
    source_name: str
    static_trust_level: str
    dynamic_trust_score: float
    provider_type: str
    os_type: str
    created_at: Optional[datetime]


class LogSourceListResponse(BaseModel):
    items: list[LogSourceOut]
    total: int
    skip: int
    limit: int


class CaseViewerOut(BaseModel):
    """A VIEWER user granted read access to an investigation."""

    model_config = ConfigDict(from_attributes=True)

    user_id: UUID
    email: EmailStr
    username: str
    name: str
