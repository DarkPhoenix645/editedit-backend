from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from app.db.session import get_db
from app.db.models import User
from app.schemas.auth import LoginRequest, RegisterRequest, TokenResponse
from app.core.rbac import UserRole
from app.core.security import (
    get_password_hash,
    verify_password,
    create_access_token
)
from app.services.audit_service import record_access_audit

router = APIRouter()

@router.post("/register", response_model=TokenResponse)
def register(
    request: Request,
    payload: RegisterRequest,
    db: Session = Depends(get_db),
):
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    username = payload.name.strip()
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(status_code=400, detail="Username already registered")
    
    existing_users = db.query(User.id).first() is not None
    role = UserRole.INVESTIGATOR if existing_users else UserRole.ADMIN

    user = User(
        email=payload.email,
        username=username,
        hashed_password=get_password_hash(payload.password),
        name=payload.name,
        role=role.value,
        is_active=True,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_access_token(str(user.id))
    record_access_audit(
        db,
        actor=user,
        action="auth.register",
        resource_type="user",
        request=request,
    )
    return {"access_token": token}


@router.post("/login", response_model=TokenResponse)
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.email == form_data.username).first()

    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if hasattr(user, "is_active") and user.is_active is False:
        raise HTTPException(status_code=403, detail="Inactive account")
    user.last_login = datetime.now(timezone.utc)
    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_access_token(str(user.id))

    record_access_audit(
        db,
        actor=user,
        action="auth.login",
        resource_type="user",
        request=request,
    )
    return {"access_token": token, "token_type": "bearer"}