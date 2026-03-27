from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.deps import get_current_user
from app.core.rbac import UserRole, can_manage_organizations, can_read_organizations, user_role_from_db
from app.db.models import User
from app.db.session import get_db
from app.schemas.organization import (
    OrganizationCreate,
    OrganizationListResponse,
    OrganizationOut,
    OrganizationUpdate,
)
from app.services import organization as org_service
from app.services.audit_service import record_access_audit

router = APIRouter()


def _role(current_user: User) -> UserRole:
    return user_role_from_db(getattr(current_user, "role", None)) or UserRole.INVESTIGATOR


def _enforce(
    db: Session,
    *,
    request: Request,
    actor: User,
    allowed: bool,
    action: str,
) -> None:
    if allowed:
        return
    record_access_audit(
        db,
        actor=actor,
        action=action + ".denied",
        resource_type="organization",
        request=request,
    )
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")


def _conflict_slug() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="An organization with this slug already exists",
    )


@router.post("", response_model=OrganizationOut, status_code=status.HTTP_201_CREATED)
def create_organization(
    request: Request,
    payload: OrganizationCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    role = _role(current_user)
    _enforce(
        db,
        request=request,
        actor=current_user,
        allowed=can_manage_organizations(role),
        action="organization.create",
    )
    if org_service.slug_exists(db, payload.slug):
        raise _conflict_slug()
    try:
        return org_service.create_organization(
            db,
            name=payload.name,
            slug=payload.slug,
            description=payload.description,
        )
    except IntegrityError:
        db.rollback()
        raise _conflict_slug() from None


@router.get("", response_model=OrganizationListResponse)
def list_organizations(
    request: Request,
    skip: int = Query(0, ge=0),
    limit: int = Query(
        org_service.DEFAULT_PAGE_LIMIT,
        ge=1,
        le=org_service.MAX_PAGE_LIMIT,
    ),
    include_inactive: bool = Query(False),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    role = _role(current_user)
    _enforce(
        db,
        request=request,
        actor=current_user,
        allowed=can_read_organizations(role),
        action="organization.list",
    )
    items, total = org_service.list_organizations(
        db, skip=skip, limit=limit, include_inactive=include_inactive
    )
    return OrganizationListResponse(
        items=items,
        total=total,
        skip=skip,
        limit=limit,
    )


@router.get("/slug/{slug}", response_model=OrganizationOut)
def get_organization_by_slug(
    request: Request,
    slug: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    role = _role(current_user)
    _enforce(
        db,
        request=request,
        actor=current_user,
        allowed=can_read_organizations(role),
        action="organization.get_by_slug",
    )
    org = org_service.get_by_slug(db, slug.strip().lower())
    if not org:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
    return org


@router.get("/{org_id}", response_model=OrganizationOut)
def get_organization(
    request: Request,
    org_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    role = _role(current_user)
    _enforce(
        db,
        request=request,
        actor=current_user,
        allowed=can_read_organizations(role),
        action="organization.get",
    )
    org = org_service.get_by_id(db, org_id)
    if not org:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
    return org


@router.patch("/{org_id}", response_model=OrganizationOut)
def update_organization(
    request: Request,
    org_id: UUID,
    payload: OrganizationUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    role = _role(current_user)
    _enforce(
        db,
        request=request,
        actor=current_user,
        allowed=can_manage_organizations(role),
        action="organization.update",
    )
    org = org_service.get_by_id(db, org_id)
    if not org:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")

    data = payload.model_dump(exclude_unset=True)
    new_slug = data.get("slug")
    if new_slug is not None and new_slug != org.slug and org_service.slug_exists(
        db, new_slug, exclude_id=org.id
    ):
        raise _conflict_slug()

    try:
        return org_service.update_organization(
            db,
            org,
            name=data.get("name"),
            slug=data.get("slug"),
            description=data.get("description"),
            is_active=data.get("is_active"),
        )
    except IntegrityError:
        db.rollback()
        raise _conflict_slug() from None


@router.delete("/{org_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_organization(
    request: Request,
    org_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    role = _role(current_user)
    _enforce(
        db,
        request=request,
        actor=current_user,
        allowed=can_manage_organizations(role),
        action="organization.delete",
    )
    org = org_service.get_by_id(db, org_id)
    if not org:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
    org_service.delete_organization(db, org)
    return None
