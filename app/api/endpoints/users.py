from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from uuid import UUID

from app.core.middleware import get_current_user
from app.core.rbac import (
    UserRole,
    can_create_users,
    can_delete_users,
    can_read_users,
    can_update_own_profile,
    can_update_users,
    user_role_from_db,
)
from app.db.models import User
from app.db.session import get_db
from app.schemas.user import (
    UserCreateAdmin,
    UserListResponse,
    UserOut,
    UserUpdateAdmin,
    UserUpdateProfile,
)
from app.services.audit_service import record_access_audit
from app.services import user_service

router = APIRouter()

def _role(current_user: User) -> UserRole:
    return user_role_from_db(getattr(current_user, "role", None)) or UserRole.INVESTIGATOR

def _enforce(db: Session, *, request: Request, actor: User, allowed: bool, action: str) -> None:
    if allowed:
        return
    # Record denied access for auditability.
    record_access_audit(
        db,
        actor=actor,
        action=action + ".denied",
        resource_type="user",
        request=request,
    )
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")

def _maybe_audit_read(*, db: Session, request: Request, actor: User, action: str, role: UserRole) -> None:
    if role in {UserRole.ADMIN, UserRole.AUDITOR}:
        record_access_audit(
            db,
            actor=actor,
            action=action,
            resource_type="user",
            request=request,
        )

@router.get("/me", response_model=UserOut)
def read_me(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    role = _role(current_user)
    _maybe_audit_read(db=db, request=request, actor=current_user, action="user.read.me", role=role)
    return current_user


@router.get("", response_model=UserListResponse)
def list_users(
    request: Request,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=user_service.MAX_PAGE_LIMIT),
    include_inactive: bool = Query(False),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    role = _role(current_user)
    _enforce(db, request=request, actor=current_user, allowed=can_read_users(role), action="user.list")

    include_inactive_effective = include_inactive if role == UserRole.ADMIN else False
    items, total = user_service.list_users(
        db, skip=skip, limit=limit, include_inactive=include_inactive_effective
    )
    _maybe_audit_read(db=db, request=request, actor=current_user, action="user.read.list", role=role)
    return UserListResponse(items=items, total=total, skip=skip, limit=limit)


@router.get("/{user_id}", response_model=UserOut)
def get_user_by_id(
    request: Request,
    user_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    role = _role(current_user)
    _enforce(db, request=request, actor=current_user, allowed=can_read_users(role), action="user.get")

    user = user_service.get_user(db, user_id)
    if not user or (getattr(user, "is_active", True) is False and role != UserRole.ADMIN):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    _maybe_audit_read(db=db, request=request, actor=current_user, action="user.read.detail", role=role)
    return user


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    request: Request,
    payload: UserCreateAdmin,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    role = _role(current_user)
    _enforce(db, request=request, actor=current_user, allowed=can_create_users(role), action="user.create")

    if user_service.get_user_by_email(db, payload.email):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )
    if user_service.get_user_by_username(db, payload.username):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already taken",
        )

    try:
        return user_service.create_user_admin(
            db,
            actor=current_user,
            email=payload.email,
            username=payload.username,
            password=payload.password,
            role=payload.role,
            is_active=payload.is_active,
            name=payload.name,
        )
    except IntegrityError:
        db.rollback()
        record_access_audit(
            db,
            actor=current_user,
            action="user.create.failed",
            resource_type="user",
            request=request,
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User already exists (constraint conflict)",
        ) from None

@router.patch("/me", response_model=UserOut)
def update_own_profile(
    request: Request,
    payload: UserUpdateProfile,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    role = _role(current_user)
    _enforce(
        db,
        request=request,
        actor=current_user,
        allowed=can_update_own_profile(role),
        action="user.update_own",
    )

    if payload.model_dump(exclude_unset=True) == {}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No fields provided")

    try:
        return user_service.update_own_profile(
            db,
            actor=current_user,
            user=current_user,
            email=payload.email,
            username=payload.username,
        )
    except IntegrityError:
        db.rollback()
        record_access_audit(
            db,
            actor=current_user,
            action="user.update_own.failed",
            resource_type="user",
            request=request,
        )
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User conflict") from None

@router.patch("/{user_id}", response_model=UserOut)
def update_user_admin(
    request: Request,
    user_id: UUID,
    payload: UserUpdateAdmin,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    role = _role(current_user)
    _enforce(db, request=request, actor=current_user, allowed=can_update_users(role), action="user.update")

    user = user_service.get_user(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    data = payload.model_dump(exclude_unset=True)

    try:
        updated = user_service.update_user_admin(
            db,
            actor=current_user,
            user=user,
            email=data.get("email"),
            username=data.get("username"),
            role=data.get("role"),
            is_active=data.get("is_active"),
        )
        record_access_audit(
            db,
            actor=current_user,
            action="user.update.success",
            resource_type="user",
            request=request,
        )
        return updated
    except IntegrityError:
        db.rollback()
        record_access_audit(
            db,
            actor=current_user,
            action="user.update.failed",
            resource_type="user",
            request=request,
        )
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User conflict") from None

@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    request: Request,
    user_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    role = _role(current_user)
    _enforce(db, request=request, actor=current_user, allowed=can_delete_users(role), action="user.delete")

    user = user_service.get_user(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user_service.delete_user_admin(db, actor=current_user, user=user)
    record_access_audit(
        db,
        actor=current_user,
        action="user.delete.success",
        resource_type="user",
        request=request,
    )
    return None