import re
from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator
from app.core.rbac import UserRole

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{2,31}$")

class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: EmailStr
    username: str
    role: UserRole
    is_active: bool
    created_at: datetime
    updated_at: datetime
    last_login: Optional[datetime] = None

    @field_validator("role", mode="before")
    @classmethod
    def normalize_role(cls, v: object) -> object:
        if isinstance(v, str):
            if v.strip().upper() == "USER":
                return UserRole.INVESTIGATOR
            legacy = {"ANALYST": UserRole.INVESTIGATOR, "AUDITOR": UserRole.IT_STAFF}
            if v.upper() in legacy:
                return legacy[v.upper()]
        return v

class UserCreateAdmin(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=8, max_length=256)
    role: UserRole
    is_active: bool = True
    name: str | None = Field(
        None,
        max_length=255,
        description="Display name; defaults to username if omitted",
    )

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        s = v.strip()
        if not _USERNAME_RE.match(s):
            raise ValueError(
                "username must start with alphanumeric and may contain alphanumeric, '.', '_' or '-'"
            )
        return s

class UserUpdateAdmin(BaseModel):
    email: EmailStr | None = None
    username: str | None = Field(default=None, min_length=3, max_length=32)
    role: UserRole | None = None
    is_active: bool | None = None

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str | None) -> str | None:
        if v is None:
            return None
        s = v.strip()
        if not _USERNAME_RE.match(s):
            raise ValueError(
                "username must start with alphanumeric and may contain alphanumeric, '.', '_' or '-'"
            )
        return s

class UserUpdateProfile(BaseModel):
    email: EmailStr | None = None
    username: str | None = Field(default=None, min_length=3, max_length=32)

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str | None) -> str | None:
        if v is None:
            return None
        s = v.strip()
        if not _USERNAME_RE.match(s):
            raise ValueError(
                "username must start with alphanumeric and may contain alphanumeric, '.', '_' or '-'"
            )
        return s

class UserListResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    items: list[UserOut]
    total: int
    skip: int
    limit: int
