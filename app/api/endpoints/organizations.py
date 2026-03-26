from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.middleware import get_current_user
from app.db.session import get_db
from app.schemas.organization import (
    OrganizationCreate,
    OrganizationListResponse,
    OrganizationOut,
    OrganizationUpdate,
)
from app.services import organization as org_service

router = APIRouter()

def _conflict_slug() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="An organization with this slug already exists",
    )

@router.post("", response_model=OrganizationOut, status_code=status.HTTP_201_CREATED)
def create_organization(
    payload: OrganizationCreate,
    db: Session = Depends(get_db),
    _current_user=Depends(get_current_user),
):
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
    skip: int = Query(0, ge=0),
    limit: int = Query(
        org_service.DEFAULT_PAGE_LIMIT,
        ge=1,
        le=org_service.MAX_PAGE_LIMIT,
    ),
    include_inactive: bool = Query(False),
    db: Session = Depends(get_db),
    _current_user=Depends(get_current_user),
):
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
    slug: str,
    db: Session = Depends(get_db),
    _current_user=Depends(get_current_user),
):
    org = org_service.get_by_slug(db, slug.strip().lower())
    if not org:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
    return org

@router.get("/{org_id}", response_model=OrganizationOut)
def get_organization(
    org_id: UUID,
    db: Session = Depends(get_db),
    _current_user=Depends(get_current_user),
):
    org = org_service.get_by_id(db, org_id)
    if not org:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
    return org

@router.patch("/{org_id}", response_model=OrganizationOut)
def update_organization(
    org_id: UUID,
    payload: OrganizationUpdate,
    db: Session = Depends(get_db),
    _current_user=Depends(get_current_user),
):
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
    org_id: UUID,
    db: Session = Depends(get_db),
    _current_user=Depends(get_current_user),
):
    org = org_service.get_by_id(db, org_id)
    if not org:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
    org_service.delete_organization(db, org)
    return None
