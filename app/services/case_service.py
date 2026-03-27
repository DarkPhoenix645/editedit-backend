from __future__ import annotations

from uuid import UUID
from datetime import datetime, timezone

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.rbac import UserRole
from app.db.models import (
    ForensicCase,
    ForensicCaseLogSource,
    ForensicCaseViewerAccess,
    ForensicHypothesis,
    InvestigatorDecision,
    LogSource,
    User,
)

DEFAULT_PAGE_LIMIT = 50
MAX_PAGE_LIMIT = 100

# Terminal investigation statuses (not "ongoing") — compared case-insensitively after trim.
TERMINAL_INVESTIGATION_STATUSES = frozenset({"closed", "archived", "resolved"})
SYSTEM_CASE_ORIGIN = "ml_infer_system"


def _ongoing_case_predicate():
    """SQL predicate: investigation is ongoing (not closed/archived/resolved)."""
    lowered = func.lower(func.trim(ForensicCase.status))
    return or_(
        ForensicCase.status.is_(None),
        ~lowered.in_(tuple(TERMINAL_INVESTIGATION_STATUSES)),
    )


def get_case(db: Session, case_id: UUID) -> ForensicCase | None:
    return db.get(ForensicCase, case_id)


def get_or_create_system_case(
    db: Session,
    *,
    source_label: str,
) -> ForensicCase:
    """Return an open auto-generated case for ML infer, creating one when absent."""
    lowered = func.lower(func.trim(ForensicCase.status))
    row = (
        db.query(ForensicCase)
        .filter(
            ForensicCase.auto_generated.is_(True),
            ForensicCase.origin == SYSTEM_CASE_ORIGIN,
            or_(
                ForensicCase.status.is_(None),
                ~lowered.in_(tuple(TERMINAL_INVESTIGATION_STATUSES)),
            ),
        )
        .order_by(ForensicCase.created_at.desc())
        .first()
    )
    if row:
        return row

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    row = ForensicCase(
        case_name=f"Auto Case {now} [{source_label}]",
        description="System-generated investigation from ML inference pipeline.",
        status="open",
        investigator_id=None,
        origin=SYSTEM_CASE_ORIGIN,
        auto_generated=True,
    )
    db.add(row)
    db.flush()
    return row


def viewer_has_access(db: Session, case_id: UUID, user_id: UUID) -> bool:
    row = db.scalar(
        select(ForensicCaseViewerAccess).where(
            ForensicCaseViewerAccess.case_id == case_id,
            ForensicCaseViewerAccess.user_id == user_id,
        )
    )
    return row is not None


def viewer_case_ids(db: Session, user_id: UUID) -> list[UUID]:
    rows = db.scalars(
        select(ForensicCaseViewerAccess.case_id).where(
            ForensicCaseViewerAccess.user_id == user_id
        )
    ).all()
    return list(rows)


def list_cases_for_user(
    db: Session,
    *,
    current_user_id: UUID,
    role: UserRole,
    skip: int = 0,
    limit: int = DEFAULT_PAGE_LIMIT,
) -> tuple[list[ForensicCase], int]:
    if role == UserRole.INVESTIGATOR:
        base = select(ForensicCase).where(ForensicCase.investigator_id == current_user_id)
        count_base = (
            select(func.count()).select_from(ForensicCase).where(
                ForensicCase.investigator_id == current_user_id
            )
        )
    elif role in (UserRole.ADMIN, UserRole.IT_STAFF):
        pred = _ongoing_case_predicate()
        base = select(ForensicCase).where(pred)
        count_base = select(func.count()).select_from(ForensicCase).where(pred)
    elif role == UserRole.VIEWER:
        fca = ForensicCaseViewerAccess
        base = (
            select(ForensicCase)
            .join(fca, fca.case_id == ForensicCase.id)
            .where(fca.user_id == current_user_id)
        )
        count_base = (
            select(func.count())
            .select_from(ForensicCase)
            .join(fca, fca.case_id == ForensicCase.id)
            .where(fca.user_id == current_user_id)
        )
    else:
        return [], 0

    total = db.scalar(count_base) or 0
    rows = db.scalars(
        base.order_by(ForensicCase.created_at.desc()).offset(skip).limit(limit)
    ).all()
    return list(rows), total


def create_case(
    db: Session,
    *,
    case_name: str,
    description: str | None,
    status: str,
    investigator_id: UUID,
) -> ForensicCase:
    row = ForensicCase(
        case_name=case_name,
        description=description,
        status=status,
        investigator_id=investigator_id,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def update_case(
    db: Session,
    row: ForensicCase,
    *,
    case_name: str | None = None,
    description: str | None = None,
    status: str | None = None,
    investigator_id: UUID | None = None,
) -> ForensicCase:
    if case_name is not None:
        row.case_name = case_name.strip()
    if description is not None:
        row.description = description
    if status is not None:
        row.status = status
    if investigator_id is not None:
        row.investigator_id = investigator_id
    db.commit()
    db.refresh(row)
    return row


def delete_case(db: Session, row: ForensicCase) -> None:
    db.delete(row)
    db.commit()


def case_has_blocking_children(db: Session, case_id: UUID) -> bool:
    h = (
        db.query(func.count())
        .select_from(ForensicHypothesis)
        .where(ForensicHypothesis.case_id == case_id)
        .scalar()
        or 0
    )
    if h > 0:
        return True
    d = (
        db.query(func.count())
        .select_from(InvestigatorDecision)
        .where(InvestigatorDecision.case_id == case_id)
        .scalar()
        or 0
    )
    return d > 0


def get_log_source(db: Session, log_source_id: UUID) -> LogSource | None:
    return db.get(LogSource, log_source_id)


def list_log_sources(
    db: Session, *, skip: int = 0, limit: int = DEFAULT_PAGE_LIMIT
) -> tuple[list[LogSource], int]:
    count_base = select(func.count()).select_from(LogSource)
    total = db.scalar(count_base) or 0
    rows = db.scalars(
        select(LogSource).order_by(LogSource.created_at.desc()).offset(skip).limit(limit)
    ).all()
    return list(rows), total


def allowed_log_source_id_strs(db: Session, case_id: UUID) -> set[str]:
    rows = db.scalars(
        select(ForensicCaseLogSource.log_source_id).where(
            ForensicCaseLogSource.case_id == case_id
        )
    ).all()
    return {str(x) for x in rows}


def attach_log_source(db: Session, *, case_id: UUID, log_source_id: UUID) -> ForensicCaseLogSource:
    link = ForensicCaseLogSource(case_id=case_id, log_source_id=log_source_id)
    db.add(link)
    db.commit()
    db.refresh(link)
    return link


def detach_log_source(db: Session, *, case_id: UUID, log_source_id: UUID) -> bool:
    row = db.scalar(
        select(ForensicCaseLogSource).where(
            ForensicCaseLogSource.case_id == case_id,
            ForensicCaseLogSource.log_source_id == log_source_id,
        )
    )
    if row is None:
        return False
    db.delete(row)
    db.commit()
    return True


def list_case_log_sources(db: Session, case_id: UUID) -> list[LogSource]:
    q = (
        select(LogSource)
        .join(
            ForensicCaseLogSource,
            ForensicCaseLogSource.log_source_id == LogSource.id,
        )
        .where(ForensicCaseLogSource.case_id == case_id)
        .order_by(LogSource.source_name)
    )
    return list(db.scalars(q).all())


def grant_viewer_access(
    db: Session, *, case_id: UUID, viewer_user_id: UUID
) -> ForensicCaseViewerAccess:
    row = ForensicCaseViewerAccess(case_id=case_id, user_id=viewer_user_id)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def revoke_viewer_access(db: Session, *, case_id: UUID, viewer_user_id: UUID) -> bool:
    row = db.scalar(
        select(ForensicCaseViewerAccess).where(
            ForensicCaseViewerAccess.case_id == case_id,
            ForensicCaseViewerAccess.user_id == viewer_user_id,
        )
    )
    if row is None:
        return False
    db.delete(row)
    db.commit()
    return True


def list_case_viewers(db: Session, case_id: UUID) -> list[User]:
    q = (
        select(User)
        .join(ForensicCaseViewerAccess, ForensicCaseViewerAccess.user_id == User.id)
        .where(ForensicCaseViewerAccess.case_id == case_id)
        .order_by(User.email)
    )
    return list(db.scalars(q).all())
