import re
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

_SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")

class OrganizationBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    slug: str = Field(..., min_length=3, max_length=64)
    description: str | None = Field(None, max_length=2000)

    @field_validator("name")
    @classmethod
    def name_stripped(cls, v: str) -> str:
        s = v.strip()
        if not s:
            raise ValueError("name cannot be empty")
        return s

    @field_validator("slug")
    @classmethod
    def slug_normalized(cls, v: str) -> str:
        s = v.strip().lower()
        if not _SLUG_RE.match(s):
            raise ValueError(
                "slug must be lowercase alphanumeric with single hyphens between segments"
            )
        return s

    @field_validator("description")
    @classmethod
    def description_stripped(cls, v: str | None) -> str | None:
        if v is None:
            return None
        s = v.strip()
        return s or None

class OrganizationCreate(OrganizationBase):
    pass

class OrganizationUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    slug: str | None = Field(None, min_length=3, max_length=64)
    description: str | None = Field(None, max_length=2000)
    is_active: bool | None = None

    @field_validator("name")
    @classmethod
    def name_stripped(cls, v: str | None) -> str | None:
        if v is None:
            return None
        s = v.strip()
        if not s:
            raise ValueError("name cannot be empty")
        return s

    @field_validator("slug")
    @classmethod
    def slug_normalized(cls, v: str | None) -> str | None:
        if v is None:
            return None
        s = v.strip().lower()
        if not _SLUG_RE.match(s):
            raise ValueError(
                "slug must be lowercase alphanumeric with single hyphens between segments"
            )
        return s

    @field_validator("description")
    @classmethod
    def description_stripped(cls, v: str | None) -> str | None:
        if v is None:
            return None
        s = v.strip()
        return s or None

class OrganizationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    slug: str
    description: str | None
    is_active: bool
    created_at: datetime
    updated_at: datetime

class OrganizationListResponse(BaseModel):
    items: list[OrganizationOut]
    total: int
    skip: int
    limit: int