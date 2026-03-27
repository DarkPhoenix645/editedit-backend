from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.deps import get_current_user
from app.core.rbac import UserRole, can_read_audit_logs, user_role_from_db
from app.db.session import get_db
from app.db.models import AccessAuditLog
from app.schemas.audit import AccessAuditLogListResponse

router = APIRouter()

def _role_from_current_user(current_user) -> UserRole:
    role = user_role_from_db(getattr(current_user, "role", None))
    return role or UserRole.INVESTIGATOR

def _require_audit_logs_access(current_user=Depends(get_current_user)) -> None:
    role = _role_from_current_user(current_user)
    if not can_read_audit_logs(role):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")

@router.get("/", response_model=AccessAuditLogListResponse)
def list_audit_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    action: str | None = Query(default=None),
    resource_type: str | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    _require_audit_logs_access(current_user)
    base = select(AccessAuditLog).order_by(AccessAuditLog.timestamp.desc()).offset(skip).limit(limit)
    count_base = select(func.count()).select_from(AccessAuditLog)

    if action is not None:
        base = base.where(AccessAuditLog.action == action)
        count_base = count_base.where(AccessAuditLog.action == action)
    if resource_type is not None:
        base = base.where(AccessAuditLog.resource_type == resource_type)
        count_base = count_base.where(AccessAuditLog.resource_type == resource_type)

    total = db.scalar(count_base) or 0
    items = db.scalars(base).all()
    return AccessAuditLogListResponse(items=items, total=total, skip=skip, limit=limit)

