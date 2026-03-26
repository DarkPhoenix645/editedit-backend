from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.security import get_password_hash
from app.core.rbac import UserRole
from app.db.models import User

DEFAULT_PAGE_LIMIT = 50
MAX_PAGE_LIMIT = 100

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)

def get_user(db: Session, user_id: UUID) -> User | None:
    return db.get(User, user_id)

def get_user_by_email(db: Session, email: str) -> User | None:
    return db.scalar(select(User).where(User.email == email))

def get_user_by_username(db: Session, username: str) -> User | None:
    return db.scalar(select(User).where(User.username == username))

def list_users(
    db: Session, *, skip: int = 0, limit: int = DEFAULT_PAGE_LIMIT, include_inactive: bool = False
) -> tuple[list[User], int]:
    base = select(User)
    count_base = select(func.count()).select_from(User)

    if not include_inactive:
        base = base.where(User.is_active.is_(True))
        count_base = count_base.where(User.is_active.is_(True))

    total = db.scalar(count_base) or 0
    rows = db.scalars(
        base.order_by(User.created_at.desc()).offset(skip).limit(limit)
    ).all()
    return list(rows), total

def create_user_admin(
    db: Session,
    *,
    actor: User,
    email: str,
    username: str,
    password: str,
    role: UserRole,
    is_active: bool = True,
    name: str | None = None,
) -> User:
    display_name = (name.strip() if name else "") or username
    user = User(
        email=email,
        username=username,
        hashed_password=get_password_hash(password),
        name=display_name,
        is_active=is_active,
        role=role.value,
        created_by=actor.id,
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise
    db.refresh(user)
    return user

def update_user_admin(
    db: Session,
    *,
    actor: User,
    user: User,
    email: Optional[str] = None,
    username: Optional[str] = None,
    role: Optional[UserRole] = None,
    is_active: Optional[bool] = None,
) -> User:
    
    if email is not None:
        user.email = email
    if username is not None:
        user.username = username
    if role is not None:
        user.role = role.value
    if is_active is not None:
        user.is_active = is_active

    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise
    db.refresh(user)
    return user

def update_own_profile(
    db: Session,
    *,
    actor: User,
    user: User,
    email: Optional[str] = None,
    username: Optional[str] = None,
) -> User:
    if email is not None:
        user.email = email
    if username is not None:
        user.username = username

    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise
    db.refresh(user)
    return user

def delete_user_admin(db: Session, *, actor: User, user: User) -> None:
    db.delete(user)
    db.commit()

def set_last_login(db: Session, *, user: User) -> User:
    user.last_login = _utc_now()
    db.add(user)
    db.commit()
    db.refresh(user)
    return user