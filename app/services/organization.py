from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models import Organization

DEFAULT_PAGE_LIMIT = 50
MAX_PAGE_LIMIT = 100

def get_by_id(db: Session, org_id: UUID) -> Organization | None:
    return db.get(Organization, org_id)

def get_by_slug(db: Session, slug: str) -> Organization | None:
    return db.scalar(select(Organization).where(Organization.slug == slug))

def slug_exists(db: Session, slug: str, exclude_id: UUID | None = None) -> bool:
    q = select(func.count()).select_from(Organization).where(Organization.slug == slug)
    if exclude_id is not None:
        q = q.where(Organization.id != exclude_id)
    return (db.scalar(q) or 0) > 0

def list_organizations(
    db: Session, *, skip: int = 0, limit: int = DEFAULT_PAGE_LIMIT, include_inactive: bool = False
) -> tuple[list[Organization], int]:
    base = select(Organization)
    count_base = select(func.count()).select_from(Organization)
    if not include_inactive:
        base = base.where(Organization.is_active.is_(True))
        count_base = count_base.where(Organization.is_active.is_(True))
    total = db.scalar(count_base) or 0
    rows = db.scalars(
        base.order_by(Organization.created_at.desc()).offset(skip).limit(limit)
    ).all()
    return list(rows), total

def create_organization(db: Session, *, name: str, slug: str, description: str | None) -> Organization:
    org = Organization(name=name, slug=slug, description=description)
    db.add(org)
    db.commit()
    db.refresh(org)
    return org

def update_organization(
    db: Session,
    org: Organization,
    *,
    name: str | None = None,
    slug: str | None = None,
    description: str | None = None,
    is_active: bool | None = None,
) -> Organization:
    if name is not None:
        org.name = name
    if slug is not None:
        org.slug = slug
    if description is not None:
        org.description = description
    if is_active is not None:
        org.is_active = is_active
    db.commit()
    db.refresh(org)
    return org

def delete_organization(db: Session, org: Organization) -> None:
    db.delete(org)
    db.commit()