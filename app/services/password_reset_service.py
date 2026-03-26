from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import PasswordResetToken, User

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)

def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

def _expires_at(now: datetime | None = None) -> datetime:
    if now is None:
        now = _utc_now()
    return now + timedelta(minutes=settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES)

def issue_password_reset_token(db: Session, *, user: User) -> str:
    now = _utc_now()
    db.execute(
        update(PasswordResetToken)
        .where(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.used_at.is_(None),
            PasswordResetToken.expires_at > now,
        )
        .values(used_at=now)
    )

    raw_token = secrets.token_urlsafe(48)
    record = PasswordResetToken(
        user_id=user.id,
        hashed_token=_hash_token(raw_token),
        expires_at=_expires_at(now),
    )
    db.add(record)
    db.commit()
    return raw_token

def consume_password_reset_token(db: Session, *, raw_token: str) -> User | None:
    now = _utc_now()
    record = db.scalar(
        select(PasswordResetToken).where(
            PasswordResetToken.hashed_token == _hash_token(raw_token),
            PasswordResetToken.used_at.is_(None),
            PasswordResetToken.expires_at > now,
        )
    )
    if record is None:
        return None

    user = db.get(User, record.user_id)
    if user is None or user.is_active is False:
        record.used_at = now
        db.add(record)
        db.commit()
        return None

    record.used_at = now
    db.add(record)
    db.commit()
    return user

def reset_password_with_token(
    db: Session, *, raw_token: str, new_password_hash: str
) -> User | None:
    now = _utc_now()
    record = db.scalar(
        select(PasswordResetToken).where(
            PasswordResetToken.hashed_token == _hash_token(raw_token),
            PasswordResetToken.used_at.is_(None),
            PasswordResetToken.expires_at > now,
        )
    )
    if record is None:
        return None

    user = db.get(User, record.user_id)
    if user is None or user.is_active is False:
        record.used_at = now
        db.add(record)
        db.commit()
        return None

    user.hashed_password = new_password_hash
    record.used_at = now
    db.add(user)
    db.add(record)
    db.commit()
    db.refresh(user)
    return user