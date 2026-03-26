from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import RefreshToken, User


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def refresh_expires_at(now: datetime | None = None) -> datetime:
    if now is None:
        now = datetime.now(timezone.utc)
    return now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

def revoke_user_refresh_tokens(db: Session, *, user_id: UUID) -> None:
    # Revoke all currently active tokens for "log in" / "register" flows.
    db.execute(
        update(RefreshToken).where(
            RefreshToken.user_id == user_id, RefreshToken.revoked.is_(False)
        ).values(revoked=True)
    )
    db.commit()

def get_active_refresh_token(
    db: Session, *, user_id: UUID, raw_token: str
) -> RefreshToken | None:
    hashed = hash_refresh_token(raw_token)
    return db.scalar(
        select(RefreshToken).where(
            RefreshToken.user_id == user_id,
            RefreshToken.hashed_token == hashed,
            RefreshToken.revoked.is_(False),
        )
    )

def store_refresh_token(
    db: Session,
    *,
    user: User,
    raw_token: str,
) -> RefreshToken:
    expires_at = refresh_expires_at()
    hashed = hash_refresh_token(raw_token)
    record = RefreshToken(
        user_id=user.id,
        hashed_token=hashed,
        expires_at=expires_at,
        revoked=False,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record

def revoke_refresh_token_record(db: Session, *, record: RefreshToken) -> None:
    record.revoked = True
    db.add(record)
    db.commit()
    db.refresh(record)