from pydantic import BaseModel, EmailStr
from uuid import UUID

class UserOut(BaseModel):
    id: UUID
    email: EmailStr
    name: str
    role: str

    class Config:
        from_attributes = True
