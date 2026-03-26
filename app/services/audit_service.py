from __future__ import annotations
from typing import Any

from fastapi import Request
from sqlalchemy.orm import Session
from app.db.models import AccessAuditLog, User

def _client_ip(request: Request) -> str | None:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    xri = request.headers.get("x-real-ip")
    if xri:
        return xri.strip()
    if request.client and request.client.host:
        return request.client.host
    return None

def record_access_audit(
    db: Session,
    *,
    actor: User | None,
    action: str,
    resource_type: str,
    request: Request,
) -> AccessAuditLog:
    ip = _client_ip(request)
    entry = AccessAuditLog(
        user_id=actor.id if actor is not None else None,
        action=action,
        resource_type=resource_type,
        ip_address=ip,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry

def record_access_audit_fire_and_forget(
    db: Session,
    *,
    actor: User | None,
    action: str,
    resource_type: str,
    request: Request,
) -> None:
    ip = _client_ip(request)
    entry = AccessAuditLog(
        user_id=actor.id if actor is not None else None,
        action=action,
        resource_type=resource_type,
        ip_address=ip,
    )
    db.add(entry)