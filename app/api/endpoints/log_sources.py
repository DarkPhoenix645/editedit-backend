from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.core.deps import get_current_user
from app.core.rbac import UserRole, can_read_cases, user_role_from_db
from app.db.models import User
from app.db.session import get_db
from app.schemas.case import LogSourceListResponse, LogSourceOut
from app.services import case_service
from app.services.audit_service import record_access_audit
from sqlalchemy.orm import Session

router = APIRouter()


def _role(user: User) -> UserRole:
    return user_role_from_db(getattr(user, "role", None)) or UserRole.INVESTIGATOR


@router.get("", response_model=LogSourceListResponse)
def list_log_sources(
    request: Request,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=case_service.MAX_PAGE_LIMIT),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    role = _role(current_user)
    if not can_read_cases(role):
        record_access_audit(
            db,
            actor=current_user,
            action="log_sources.list.denied",
            resource_type="log_source",
            request=request,
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")

    items, total = case_service.list_log_sources(db, skip=skip, limit=limit)
    return LogSourceListResponse(
        items=[LogSourceOut.model_validate(x) for x in items],
        total=total,
        skip=skip,
        limit=limit,
    )
