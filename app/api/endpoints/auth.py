from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import datetime, timezone
from jose import jwt, JWTError
from uuid import UUID

from app.db.session import get_db
from app.db.models import User
from app.schemas.auth import (
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    RefreshRequest,
    RegisterRequest,
    ResetPasswordConfirmRequest,
    ResetPasswordConfirmResponse,
    TokenResponse,
)
from app.core.rbac import UserRole
from app.core.config import settings
from app.core.security import (
    get_password_hash,
    verify_password,
    create_access_token,
    create_refresh_token,
)
from app.services.audit_service import record_access_audit
from app.services import notification_service, password_reset_service, refresh_token_service, user_service

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

    access_token = create_access_token(str(user.id))
    refresh_token = create_refresh_token(str(user.id))
    refresh_token_service.revoke_user_refresh_tokens(db, user_id=user.id)
    refresh_token_service.store_refresh_token(db, user=user, raw_token=refresh_token)

    record_access_audit(
        db,
        actor=user,
        action="auth.register",
        resource_type="user",
        request=request,
    )
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


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

    access_token = create_access_token(str(user.id))
    refresh_token = create_refresh_token(str(user.id))
    refresh_token_service.revoke_user_refresh_tokens(db, user_id=user.id)
    refresh_token_service.store_refresh_token(db, user=user, raw_token=refresh_token)

    record_access_audit(
        db,
        actor=user,
        action="auth.login",
        resource_type="user",
        request=request,
    )
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post("/refresh", response_model=TokenResponse)
def refresh(
    request: Request,
    payload: RefreshRequest,
    db: Session = Depends(get_db),
):
    try:
        decoded = jwt.decode(
            payload.refresh_token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
        )
        token_type = decoded.get("typ")
        if token_type != "refresh":
            raise JWTError("not a refresh token")
        user_id = decoded.get("sub")
        if user_id is None:
            raise JWTError("missing sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token") from None

    user = db.query(User).filter(User.id == UUID(user_id)).first()
    if not user or getattr(user, "is_active", True) is False:
        raise HTTPException(status_code=401, detail="Invalid refresh token") from None

    record = refresh_token_service.get_active_refresh_token(
        db, user_id=user.id, raw_token=payload.refresh_token
    )
    if not record:
        record_access_audit(
            db,
            actor=user,
            action="auth.refresh.denied",
            resource_type="refresh_token",
            request=request,
        )
        raise HTTPException(status_code=401, detail="Refresh token revoked or expired") from None

    now = datetime.now(timezone.utc)
    if record.expires_at < now:
        refresh_token_service.revoke_refresh_token_record(db, record=record)
        record_access_audit(
            db,
            actor=user,
            action="auth.refresh.denied",
            resource_type="refresh_token.expired",
            request=request,
        )
        raise HTTPException(status_code=401, detail="Refresh token expired") from None

    # Rotation: revoke the used token and issue a new refresh token.
    refresh_token_service.revoke_refresh_token_record(db, record=record)

    access_token = create_access_token(str(user.id))
    new_refresh_token = create_refresh_token(str(user.id))
    refresh_token_service.store_refresh_token(
        db, user=user, raw_token=new_refresh_token
    )

    record_access_audit(
        db,
        actor=user,
        action="auth.refresh",
        resource_type="refresh_token",
        request=request,
    )
    return {
        "access_token": access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer",
    }

@router.post("/forgot-password", response_model=ForgotPasswordResponse, status_code=202)
def forgot_password(
    request: Request,
    payload: ForgotPasswordRequest,
    db: Session = Depends(get_db),
):
    user = user_service.get_user_by_email(db, payload.email)
    if user and user.is_active:
        token = password_reset_service.issue_password_reset_token(db, user=user)
        notification_service.send_password_reset_email(email=user.email, token=token)
        record_access_audit(
            db,
            actor=user,
            action="auth.password_reset.request",
            resource_type="password_reset_token",
            request=request,
        )
    else:
        record_access_audit(
            db,
            actor=None,
            action="auth.password_reset.request",
            resource_type="password_reset_token",
            request=request,
        )
    return ForgotPasswordResponse()

@router.post("/reset-password", response_model=ResetPasswordConfirmResponse)
def reset_password(
    request: Request,
    payload: ResetPasswordConfirmRequest,
    db: Session = Depends(get_db),
):
    user = password_reset_service.reset_password_with_token(
        db,
        raw_token=payload.token,
        new_password_hash=get_password_hash(payload.new_password),
    )
    if user is None:
        record_access_audit(
            db,
            actor=None,
            action="auth.password_reset.confirm.denied",
            resource_type="password_reset_token",
            request=request,
        )
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")

    refresh_token_service.revoke_user_refresh_tokens(db, user_id=user.id)
    record_access_audit(
        db,
        actor=user,
        action="auth.password_reset.confirm",
        resource_type="user_credentials",
        request=request,
    )
    return ResetPasswordConfirmResponse()