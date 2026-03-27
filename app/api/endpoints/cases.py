from __future__ import annotations

from uuid import UUID
from uuid import uuid4
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.deps import get_current_user
from app.core.rbac import UserRole, can_read_cases, can_write_cases, is_full_access, user_role_from_db
from app.db.models import ForensicCase, User
from app.db.session import get_db
from app.schemas.case import (
    CaseCreate,
    CaseListResponse,
    CaseOut,
    CaseUpdate,
    CaseViewerOut,
    LogSourceOut,
)
from app.services import case_service
from app.services.audit_service import record_access_audit
from app.services.dossier_service import build_case_dossier, build_case_dossier_pdf

router = APIRouter()
_DOSSIER_JOBS: dict[str, dict] = {}


def _role(user: User) -> UserRole:
    return user_role_from_db(getattr(user, "role", None)) or UserRole.INVESTIGATOR


def _enforce_read(request: Request, db: Session, actor: User, allowed: bool, action: str) -> None:
    if allowed:
        return
    record_access_audit(
        db,
        actor=actor,
        action=action + ".denied",
        resource_type="forensic_case",
        request=request,
    )
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")


def _enforce_write(request: Request, db: Session, actor: User, allowed: bool, action: str) -> None:
    if allowed:
        return
    record_access_audit(
        db,
        actor=actor,
        action=action + ".denied",
        resource_type="forensic_case",
        request=request,
    )
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")


def _can_read_case_row(
    db,
    *,
    role: UserRole,
    current_user: User,
    case_row: ForensicCase,
) -> bool:
    """Single-case read: admin/IT see any; investigator sees own; viewer only if explicitly assigned."""
    if is_full_access(role):
        return True
    if role == UserRole.INVESTIGATOR:
        return case_row.investigator_id == current_user.id
    if role == UserRole.VIEWER:
        return case_service.viewer_has_access(db, case_row.id, current_user.id)
    return False


def _can_write_case_row(*, role: UserRole, current_user: User, case_row: ForensicCase) -> bool:
    if is_full_access(role):
        return True
    if role == UserRole.INVESTIGATOR:
        return case_row.investigator_id == current_user.id
    return False


def _can_manage_case_viewers(*, role: UserRole, current_user: User, case_row: ForensicCase) -> bool:
    """Grant/revoke viewer access: admin/IT or owning investigator."""
    if is_full_access(role):
        return True
    if role == UserRole.INVESTIGATOR:
        return case_row.investigator_id == current_user.id
    return False


@router.get("", response_model=CaseListResponse)
def list_cases(
    request: Request,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=case_service.MAX_PAGE_LIMIT),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    role = _role(current_user)
    _enforce_read(
        request,
        db,
        current_user,
        can_read_cases(role),
        "case.list",
    )
    items, total = case_service.list_cases_for_user(
        db, current_user_id=current_user.id, role=role, skip=skip, limit=limit
    )
    return CaseListResponse(
        items=[CaseOut.model_validate(x) for x in items],
        total=total,
        skip=skip,
        limit=limit,
    )


@router.post("", response_model=CaseOut, status_code=status.HTTP_201_CREATED)
def create_case(
    request: Request,
    payload: CaseCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    role = _role(current_user)
    _enforce_write(request, db, current_user, can_write_cases(role), "case.create")

    investigator_id = current_user.id
    if payload.investigator_id is not None:
        if not is_full_access(role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only administrators may assign a different investigator",
            )
        investigator_id = payload.investigator_id

    row = case_service.create_case(
        db,
        case_name=payload.case_name.strip(),
        description=payload.description.strip() if payload.description else None,
        status=payload.status.strip(),
        investigator_id=investigator_id,
    )
    record_access_audit(
        db,
        actor=current_user,
        action="case.create",
        resource_type="forensic_case",
        request=request,
    )
    return CaseOut.model_validate(row)


@router.get("/{case_id}", response_model=CaseOut)
def get_case(
    request: Request,
    case_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    role = _role(current_user)
    _enforce_read(request, db, current_user, can_read_cases(role), "case.get")
    row = case_service.get_case(db, case_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    if not _can_read_case_row(db, role=role, current_user=current_user, case_row=row):
        _enforce_read(request, db, current_user, False, "case.get")
    return CaseOut.model_validate(row)


@router.patch("/{case_id}", response_model=CaseOut)
def update_case(
    request: Request,
    case_id: UUID,
    payload: CaseUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    role = _role(current_user)
    _enforce_write(request, db, current_user, can_write_cases(role), "case.update")
    row = case_service.get_case(db, case_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    if not _can_write_case_row(role=role, current_user=current_user, case_row=row):
        _enforce_write(request, db, current_user, False, "case.update")

    if payload.investigator_id is not None and not is_full_access(role):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators may reassign investigator",
        )

    data = payload.model_dump(exclude_unset=True)
    if data == {}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No fields provided")

    updated = case_service.update_case(
        db,
        row,
        case_name=data.get("case_name"),
        description=data.get("description"),
        status=data.get("status"),
        investigator_id=data.get("investigator_id"),
    )
    record_access_audit(
        db,
        actor=current_user,
        action="case.update",
        resource_type="forensic_case",
        request=request,
    )
    return CaseOut.model_validate(updated)


@router.delete("/{case_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_case(
    request: Request,
    case_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    role = _role(current_user)
    _enforce_write(request, db, current_user, can_write_cases(role), "case.delete")
    row = case_service.get_case(db, case_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    if not _can_write_case_row(role=role, current_user=current_user, case_row=row):
        _enforce_write(request, db, current_user, False, "case.delete")

    if case_service.case_has_blocking_children(db, case_id):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Case has hypotheses or investigator decisions; remove or reassign them first",
        )

    case_service.delete_case(db, row)
    record_access_audit(
        db,
        actor=current_user,
        action="case.delete",
        resource_type="forensic_case",
        request=request,
    )
    return None


@router.get("/{case_id}/log-sources", response_model=list[LogSourceOut])
def list_case_log_sources(
    request: Request,
    case_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    role = _role(current_user)
    _enforce_read(request, db, current_user, can_read_cases(role), "case.log_sources.list")
    row = case_service.get_case(db, case_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    if not _can_read_case_row(db, role=role, current_user=current_user, case_row=row):
        _enforce_read(request, db, current_user, False, "case.log_sources.list")
    sources = case_service.list_case_log_sources(db, case_id)
    return [LogSourceOut.model_validate(s) for s in sources]


@router.post(
    "/{case_id}/log-sources/{log_source_id}",
    response_model=LogSourceOut,
    status_code=status.HTTP_201_CREATED,
)
def attach_case_log_source(
    request: Request,
    case_id: UUID,
    log_source_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    role = _role(current_user)
    _enforce_write(request, db, current_user, can_write_cases(role), "case.log_sources.attach")
    case_row = case_service.get_case(db, case_id)
    if not case_row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    if not _can_write_case_row(role=role, current_user=current_user, case_row=case_row):
        _enforce_write(request, db, current_user, False, "case.log_sources.attach")

    ls = case_service.get_log_source(db, log_source_id)
    if not ls:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Log source not found")

    try:
        case_service.attach_log_source(db, case_id=case_id, log_source_id=log_source_id)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Log source already attached to this case",
        ) from None

    record_access_audit(
        db,
        actor=current_user,
        action="case.log_sources.attach",
        resource_type="forensic_case",
        request=request,
    )
    return LogSourceOut.model_validate(ls)


@router.delete(
    "/{case_id}/log-sources/{log_source_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def detach_case_log_source(
    request: Request,
    case_id: UUID,
    log_source_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    role = _role(current_user)
    _enforce_write(request, db, current_user, can_write_cases(role), "case.log_sources.detach")
    case_row = case_service.get_case(db, case_id)
    if not case_row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    if not _can_write_case_row(role=role, current_user=current_user, case_row=case_row):
        _enforce_write(request, db, current_user, False, "case.log_sources.detach")

    ok = case_service.detach_log_source(db, case_id=case_id, log_source_id=log_source_id)
    if not ok:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Attachment not found")

    record_access_audit(
        db,
        actor=current_user,
        action="case.log_sources.detach",
        resource_type="forensic_case",
        request=request,
    )
    return None


@router.get("/{case_id}/viewers", response_model=list[CaseViewerOut])
def list_case_viewers(
    request: Request,
    case_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    role = _role(current_user)
    _enforce_read(request, db, current_user, can_read_cases(role), "case.viewers.list")
    row = case_service.get_case(db, case_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    if not _can_read_case_row(db, role=role, current_user=current_user, case_row=row):
        _enforce_read(request, db, current_user, False, "case.viewers.list")
    users = case_service.list_case_viewers(db, case_id)
    return [
        CaseViewerOut(
            user_id=u.id,
            email=u.email,
            username=u.username,
            name=u.name,
        )
        for u in users
    ]


@router.post(
    "/{case_id}/viewers/{viewer_user_id}",
    response_model=CaseViewerOut,
    status_code=status.HTTP_201_CREATED,
)
def grant_case_viewer(
    request: Request,
    case_id: UUID,
    viewer_user_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    role = _role(current_user)
    _enforce_write(request, db, current_user, can_write_cases(role), "case.viewers.grant")
    case_row = case_service.get_case(db, case_id)
    if not case_row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    if not _can_manage_case_viewers(role=role, current_user=current_user, case_row=case_row):
        _enforce_write(request, db, current_user, False, "case.viewers.grant")

    target = db.get(User, viewer_user_id)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if user_role_from_db(target.role) != UserRole.VIEWER:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only users with VIEWER role can be granted read access",
        )

    try:
        case_service.grant_viewer_access(db, case_id=case_id, viewer_user_id=viewer_user_id)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Viewer already has access to this case",
        ) from None

    record_access_audit(
        db,
        actor=current_user,
        action="case.viewers.grant",
        resource_type="forensic_case",
        request=request,
    )
    return CaseViewerOut(
        user_id=target.id,
        email=target.email,
        username=target.username,
        name=target.name,
    )


@router.delete(
    "/{case_id}/viewers/{viewer_user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def revoke_case_viewer(
    request: Request,
    case_id: UUID,
    viewer_user_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    role = _role(current_user)
    _enforce_write(request, db, current_user, can_write_cases(role), "case.viewers.revoke")
    case_row = case_service.get_case(db, case_id)
    if not case_row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    if not _can_manage_case_viewers(role=role, current_user=current_user, case_row=case_row):
        _enforce_write(request, db, current_user, False, "case.viewers.revoke")

    ok = case_service.revoke_viewer_access(db, case_id=case_id, viewer_user_id=viewer_user_id)
    if not ok:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Viewer access not found")

    record_access_audit(
        db,
        actor=current_user,
        action="case.viewers.revoke",
        resource_type="forensic_case",
        request=request,
    )
    return None


@router.post("/{case_id}/dossier", status_code=status.HTTP_202_ACCEPTED)
def start_case_dossier(
    request: Request,
    case_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    role = _role(current_user)
    _enforce_read(request, db, current_user, can_read_cases(role), "case.dossier.create")
    case_row = case_service.get_case(db, case_id)
    if not case_row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    if not _can_read_case_row(db, role=role, current_user=current_user, case_row=case_row):
        _enforce_read(request, db, current_user, False, "case.dossier.create")

    job_id = f"dossier-{uuid4().hex[:16]}"
    payload = build_case_dossier(db, case_id)
    pdf_bytes = build_case_dossier_pdf(payload)
    _DOSSIER_JOBS[job_id] = {
        "job_id": job_id,
        "case_id": str(case_id),
        "status": "done",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "payload": payload,
        "pdf_bytes": pdf_bytes,
    }
    return {
        "job_id": job_id,
        "case_id": str(case_id),
        "status": "done",
    }


@router.get("/{case_id}/dossier/{job_id}")
def get_case_dossier_status(
    request: Request,
    case_id: UUID,
    job_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    role = _role(current_user)
    _enforce_read(request, db, current_user, can_read_cases(role), "case.dossier.status")
    case_row = case_service.get_case(db, case_id)
    if not case_row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    if not _can_read_case_row(db, role=role, current_user=current_user, case_row=case_row):
        _enforce_read(request, db, current_user, False, "case.dossier.status")
    row = _DOSSIER_JOBS.get(job_id)
    if row is None or row.get("case_id") != str(case_id):
        raise HTTPException(status_code=404, detail="Dossier job not found")
    return {
        "job_id": row["job_id"],
        "case_id": row["case_id"],
        "status": row["status"],
        "created_at": row["created_at"],
        "download_url": f"/api/cases/{case_id}/dossier/{job_id}/download",
    }


@router.get("/{case_id}/dossier/{job_id}/download")
def download_case_dossier(
    request: Request,
    case_id: UUID,
    job_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    role = _role(current_user)
    _enforce_read(request, db, current_user, can_read_cases(role), "case.dossier.download")
    case_row = case_service.get_case(db, case_id)
    if not case_row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    if not _can_read_case_row(db, role=role, current_user=current_user, case_row=case_row):
        _enforce_read(request, db, current_user, False, "case.dossier.download")
    row = _DOSSIER_JOBS.get(job_id)
    if row is None or row.get("case_id") != str(case_id):
        raise HTTPException(status_code=404, detail="Dossier job not found")
    if row.get("status") != "done":
        raise HTTPException(status_code=409, detail="Dossier not ready")
    return Response(
        content=row["pdf_bytes"],
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="case-{case_id}-dossier.pdf"'},
    )
