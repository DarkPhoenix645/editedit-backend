from pydantic import BaseModel, EmailStr, validator
import re

def validate_strong_password(v: str) -> str:
    if len(v) < 8:
        raise ValueError("Password must be at least 8 characters long")
    if not re.search(r"[A-Z]", v):
        raise ValueError("Password must contain at least one uppercase letter")
    if not re.search(r"[a-z]", v):
        raise ValueError("Password must contain at least one lowercase letter")
    if not re.search(r"[0-9]", v):
        raise ValueError("Password must contain at least one digit")
    return v

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    name: str

    @validator("password")
    def validate_password(cls, v):
        return validate_strong_password(v)

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class RefreshRequest(BaseModel):
    refresh_token: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ForgotPasswordResponse(BaseModel):
    detail: str = "If the account exists, password reset instructions have been sent."

class ResetPasswordConfirmRequest(BaseModel):
    token: str
    new_password: str

    @validator("new_password")
    def validate_new_password(cls, v):
        return validate_strong_password(v)

class ResetPasswordConfirmResponse(BaseModel):
    detail: str = "Password has been reset successfully"