"""Links, releases, feature flags, and status page routes.

Four routers in one module (the coordinator registers each in
``app/main.py``):

* ``links_router``    — ``/api/v1/links`` (cross-module entity links)
* ``releases_router`` — ``/api/v1/releases``
* ``flags_router``    — ``/api/v1/feature-flags``
* ``status_router``   — ``/api/v1/status`` (incl. the PUBLIC status page)

Permissions: ``links:read`` / ``links:manage`` / ``releases:read`` /
``releases:manage`` / ``statuspage:read`` / ``statuspage:manage`` all
exist in the org permission catalog; ``links:manage`` is held by the
Organization Administrator role (``*`` template) and grants link
create/delete.

The public status-page read (``GET /api/v1/status/public/{org_slug}``)
takes no auth: it resolves the slug through the SECURITY DEFINER
function ``status_page_org_id_by_slug`` (migration 0017), scopes the
session to that org, and returns ONLY incident data — no org
internals, no user data, no ticket data.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.database import set_rls_context
from app.deps import Principal, get_db, require_permission
from app.models.linking import (
    RELEASE_STATUSES,
    STATUS_PAGE_INCIDENT_STATUSES,
    EntityLink,
    FeatureFlag,
    Release,
    StatusPageIncident,
    StatusPageIncidentUpdate,
)
from app.services import linking_service

UTC = timezone.utc

links_router = APIRouter(prefix="/api/v1/links", tags=["links"])
releases_router = APIRouter(prefix="/api/v1/releases", tags=["releases"])
flags_router = APIRouter(prefix="/api/v1/feature-flags", tags=["feature-flags"])
status_router = APIRouter(prefix="/api/v1/status", tags=["status-page"])

# NOTE (coordinator): "links:manage" is not in app/permissions.py yet.
# Link create/delete below require it; add
#   ("links:manage", "links", "Manage cross-module links")
# to PERMISSIONS and re-seed before these endpoints work for any role.
LINKS_MANAGE = "links:manage"

FLAG_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")


# --- Schemas (local: app/schemas.py belongs to another workstream) --------


class LinkCreate(BaseModel):
    source_type: str
    source_id: uuid.UUID
    target_type: str
    target_id: uuid.UUID
    link_type: str


class LinkedEntityOut(BaseModel):
    entity_type: str
    id: str
    label: str
    status: str | None


class LinkOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    source_type: str
    source_id: uuid.UUID
    target_type: str
    target_id: uuid.UUID
    link_type: str
    created_at: datetime


class GraphLinkOut(BaseModel):
    id: uuid.UUID
    direction: str  # outgoing | incoming
    link_type: str
    entity: LinkedEntityOut
    created_at: datetime


class GraphOut(BaseModel):
    entity: LinkedEntityOut
    links: list[GraphLinkOut]


class ReleaseCreate(BaseModel):
    version: str = Field(min_length=1, max_length=50)
    title: str = Field(min_length=1, max_length=255)
    notes: str = ""
    status: str = "draft"
    scheduled_at: datetime | None = None


class ReleaseUpdate(BaseModel):
    title: str | None = None
    notes: str | None = None
    status: str | None = None
    scheduled_at: datetime | None = None


class ReleaseOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    version: str
    title: str
    notes: str
    status: str
    scheduled_at: datetime | None
    released_at: datetime | None
    created_at: datetime
    updated_at: datetime


class FlagCreate(BaseModel):
    key: str = Field(min_length=1, max_length=100)
    description: str = ""
    enabled: bool = True
    rollout_percentage: int = 100


class FlagUpdate(BaseModel):
    description: str | None = None
    enabled: bool | None = None
    rollout_percentage: int | None = None


class FlagOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    key: str
    description: str
    enabled: bool
    rollout_percentage: int
    created_at: datetime
    updated_at: datetime


class FlagEvaluationOut(BaseModel):
    key: str
    enabled: bool
    flag_enabled: bool
    rollout_percentage: int
    bucket: int


class IncidentUpdateCreate(BaseModel):
    status: str
    message: str = Field(min_length=1)


class IncidentUpdateOut(BaseModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    status: str
    message: str
    created_at: datetime


class IncidentCreate(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    description: str = ""
    status: str = "investigating"
    started_at: datetime | None = None


class IncidentUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    status: str | None = None


class IncidentOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    title: str
    description: str
    status: str
    started_at: datetime | None
    resolved_at: datetime | None
    created_at: datetime
    updated_at: datetime
    updates: list[IncidentUpdateOut] = []


class PublicIncidentOut(BaseModel):
    id: uuid.UUID
    title: str
    description: str
    status: str
    started_at: datetime | None
    resolved_at: datetime | None
    created_at: datetime
    updated_at: datetime
    updates: list[IncidentUpdateOut] = []


class PublicStatusOut(BaseModel):
    organization_slug: str
    incidents: list[PublicIncidentOut]


# --- Helpers ----------------------------------------------------------------


def _audit(
    session: Session,
    principal: Principal,
    action: str,
    resource_type: str,
    resource_id: str,
    metadata: dict | None = None,
):
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome="success",
        metadata=metadata or {},
    )


def _link_out(link: EntityLink) -> LinkOut:
    return LinkOut(
        id=link.id,
        organization_id=link.organization_id,
        source_type=link.source_type,
        source_id=link.source_id,
        target_type=link.target_type,
        target_id=link.target_id,
        link_type=link.link_type,
        created_at=link.created_at,
    )


def _release_out(r: Release) -> ReleaseOut:
    return ReleaseOut(
        id=r.id,
        organization_id=r.organization_id,
        version=r.version,
        title=r.title,
        notes=r.notes,
        status=r.status,
        scheduled_at=r.scheduled_at,
        released_at=r.released_at,
        created_at=r.created_at,
        updated_at=r.updated_at,
    )


def _flag_out(f: FeatureFlag) -> FlagOut:
    return FlagOut(
        id=f.id,
        organization_id=f.organization_id,
        key=f.key,
        description=f.description,
        enabled=f.enabled,
        rollout_percentage=f.rollout_percentage,
        created_at=f.created_at,
        updated_at=f.updated_at,
    )


def _incident_updates(session: Session, incident_id: uuid.UUID) -> list[IncidentUpdateOut]:
    rows = (
        session.execute(
            select(StatusPageIncidentUpdate)
            .where(StatusPageIncidentUpdate.incident_id == incident_id)
            .order_by(StatusPageIncidentUpdate.created_at)
        )
        .scalars()
        .all()
    )
    return [
        IncidentUpdateOut(
            id=u.id, incident_id=u.incident_id, status=u.status, message=u.message, created_at=u.created_at
        )
        for u in rows
    ]


def _incident_out(session: Session, i: StatusPageIncident) -> IncidentOut:
    return IncidentOut(
        id=i.id,
        organization_id=i.organization_id,
        title=i.title,
        description=i.description,
        status=i.status,
        started_at=i.started_at,
        resolved_at=i.resolved_at,
        created_at=i.created_at,
        updated_at=i.updated_at,
        updates=_incident_updates(session, i.id),
    )


def _get_incident(session: Session, org_id: uuid.UUID, incident_id: uuid.UUID) -> StatusPageIncident:
    incident = session.get(StatusPageIncident, incident_id)
    if incident is None or incident.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    return incident


def _validate_link_ends(session: Session, org_id: uuid.UUID, body: LinkCreate) -> None:
    if body.source_type not in linking_service.ENTITY_TYPES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Unknown source_type: {body.source_type}")
    if body.target_type not in linking_service.ENTITY_TYPES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Unknown target_type: {body.target_type}")
    if body.link_type not in linking_service.LINK_TYPES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Unknown link_type: {body.link_type}")
    try:
        linking_service.validate_entity(session, org_id, body.source_type, body.source_id)
    except linking_service.EntityNotFound as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    try:
        linking_service.validate_entity(session, org_id, body.target_type, body.target_id)
    except linking_service.EntityNotFound as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


# --- Entity links -----------------------------------------------------------


@links_router.get("", response_model=list[LinkOut])
def list_links(
    source_type: str | None = None,
    source_id: uuid.UUID | None = None,
    target_type: str | None = None,
    target_id: uuid.UUID | None = None,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("links:read")),
):
    query = select(EntityLink).where(EntityLink.organization_id == principal.organization_id)
    if source_type is not None:
        query = query.where(EntityLink.source_type == source_type)
    if source_id is not None:
        query = query.where(EntityLink.source_id == source_id)
    if target_type is not None:
        query = query.where(EntityLink.target_type == target_type)
    if target_id is not None:
        query = query.where(EntityLink.target_id == target_id)
    rows = session.execute(query.order_by(EntityLink.created_at.desc())).scalars().all()
    return [_link_out(link) for link in rows]


@links_router.post("", response_model=LinkOut, status_code=status.HTTP_201_CREATED)
def create_link(
    body: LinkCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission(LINKS_MANAGE)),
):
    _validate_link_ends(session, principal.organization_id, body)
    link = EntityLink(
        organization_id=principal.organization_id,
        source_type=body.source_type,
        source_id=body.source_id,
        target_type=body.target_type,
        target_id=body.target_id,
        link_type=body.link_type,
        created_by_id=principal.user_id,
    )
    session.add(link)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="An identical link already exists")
    _audit(
        session,
        principal,
        audit_mod.ENTITY_LINK_CREATED,
        "entity_link",
        str(link.id),
        {
            "source_type": body.source_type,
            "source_id": str(body.source_id),
            "target_type": body.target_type,
            "target_id": str(body.target_id),
            "link_type": body.link_type,
        },
    )
    out = _link_out(link)
    session.commit()
    return out


@links_router.get("/graph", response_model=GraphOut)
def linked_graph(
    entity_type: str,
    entity_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("links:read")),
):
    try:
        row = linking_service.validate_entity(session, principal.organization_id, entity_type, entity_id)
    except linking_service.UnknownEntityType as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except linking_service.EntityNotFound as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    outgoing = (
        session.execute(
            select(EntityLink).where(
                EntityLink.organization_id == principal.organization_id,
                EntityLink.source_type == entity_type,
                EntityLink.source_id == entity_id,
            )
        )
        .scalars()
        .all()
    )
    incoming = (
        session.execute(
            select(EntityLink).where(
                EntityLink.organization_id == principal.organization_id,
                EntityLink.target_type == entity_type,
                EntityLink.target_id == entity_id,
            )
        )
        .scalars()
        .all()
    )
    links: list[GraphLinkOut] = []
    for link in outgoing:
        target = linking_service.validate_entity(session, principal.organization_id, link.target_type, link.target_id)
        links.append(
            GraphLinkOut(
                id=link.id,
                direction="outgoing",
                link_type=link.link_type,
                entity=LinkedEntityOut(**linking_service.entity_identity(link.target_type, target)),
                created_at=link.created_at,
            )
        )
    for link in incoming:
        source = linking_service.validate_entity(session, principal.organization_id, link.source_type, link.source_id)
        links.append(
            GraphLinkOut(
                id=link.id,
                direction="incoming",
                link_type=link.link_type,
                entity=LinkedEntityOut(**linking_service.entity_identity(link.source_type, source)),
                created_at=link.created_at,
            )
        )
    links.sort(key=lambda item: item.created_at)
    return GraphOut(entity=LinkedEntityOut(**linking_service.entity_identity(entity_type, row)), links=links)


@links_router.delete("/{link_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_link(
    link_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission(LINKS_MANAGE)),
):
    link = session.get(EntityLink, link_id)
    if link is None or link.organization_id != principal.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Link not found")
    session.delete(link)
    session.flush()
    _audit(session, principal, audit_mod.ENTITY_LINK_DELETED, "entity_link", str(link.id), {})
    session.commit()
    return None


# --- Releases ---------------------------------------------------------------


@releases_router.get("", response_model=list[ReleaseOut])
def list_releases(
    status_filter: str | None = None,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("releases:read")),
):
    query = select(Release).where(Release.organization_id == principal.organization_id)
    if status_filter is not None:
        if status_filter not in RELEASE_STATUSES:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid release status")
        query = query.where(Release.status == status_filter)
    rows = session.execute(query.order_by(Release.created_at.desc())).scalars().all()
    return [_release_out(r) for r in rows]


@releases_router.post("", response_model=ReleaseOut, status_code=status.HTTP_201_CREATED)
def create_release(
    body: ReleaseCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("releases:manage")),
):
    if body.status not in RELEASE_STATUSES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid release status")
    release = Release(
        organization_id=principal.organization_id,
        version=body.version,
        title=body.title,
        notes=body.notes,
        status=body.status,
        scheduled_at=body.scheduled_at,
        released_at=datetime.now(UTC) if body.status == "released" else None,
        created_by_id=principal.user_id,
    )
    session.add(release)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=f"Release version {body.version} already exists"
        )
    _audit(
        session,
        principal,
        audit_mod.RELEASE_CREATED,
        "release",
        str(release.id),
        {"version": body.version, "status": body.status},
    )
    out = _release_out(release)
    session.commit()
    return out


@releases_router.get("/{release_id}", response_model=ReleaseOut)
def get_release(
    release_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("releases:read")),
):
    release = session.get(Release, release_id)
    if release is None or release.organization_id != principal.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Release not found")
    return _release_out(release)


@releases_router.patch("/{release_id}", response_model=ReleaseOut)
def update_release(
    release_id: uuid.UUID,
    body: ReleaseUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("releases:manage")),
):
    release = session.get(Release, release_id)
    if release is None or release.organization_id != principal.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Release not found")
    if body.status is not None:
        if body.status not in RELEASE_STATUSES:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid release status")
        if body.status == "released" and release.status != "released" and release.released_at is None:
            release.released_at = datetime.now(UTC)
        release.status = body.status
    if body.title is not None:
        release.title = body.title
    if body.notes is not None:
        release.notes = body.notes
    if body.scheduled_at is not None:
        release.scheduled_at = body.scheduled_at
    session.flush()
    _audit(
        session,
        principal,
        audit_mod.RELEASE_UPDATED,
        "release",
        str(release.id),
        {"version": release.version, "status": release.status},
    )
    out = _release_out(release)
    session.commit()
    return out


@releases_router.delete("/{release_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_release(
    release_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("releases:manage")),
):
    release = session.get(Release, release_id)
    if release is None or release.organization_id != principal.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Release not found")
    version = release.version
    session.delete(release)
    session.flush()
    _audit(session, principal, audit_mod.RELEASE_DELETED, "release", str(release.id), {"version": version})
    session.commit()
    return None


# --- Feature flags ----------------------------------------------------------


@flags_router.get("", response_model=list[FlagOut])
def list_flags(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("releases:read"))
):
    rows = (
        session.execute(
            select(FeatureFlag)
            .where(FeatureFlag.organization_id == principal.organization_id)
            .order_by(FeatureFlag.key)
        )
        .scalars()
        .all()
    )
    return [_flag_out(f) for f in rows]


@flags_router.post("", response_model=FlagOut, status_code=status.HTTP_201_CREATED)
def create_flag(
    body: FlagCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("releases:manage")),
):
    if not FLAG_KEY_RE.match(body.key):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Flag key must be lowercase letters, digits, '_' , '-' or '.'",
        )
    if not 0 <= body.rollout_percentage <= 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="rollout_percentage must be between 0 and 100"
        )
    flag = FeatureFlag(
        organization_id=principal.organization_id,
        key=body.key,
        description=body.description,
        enabled=body.enabled,
        rollout_percentage=body.rollout_percentage,
        created_by_id=principal.user_id,
    )
    session.add(flag)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Flag {body.key} already exists")
    _audit(
        session,
        principal,
        audit_mod.FEATURE_FLAG_CREATED,
        "feature_flag",
        str(flag.id),
        {"key": body.key, "enabled": body.enabled, "rollout_percentage": body.rollout_percentage},
    )
    out = _flag_out(flag)
    session.commit()
    return out


@flags_router.get("/{key}", response_model=FlagOut)
def get_flag(
    key: str,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("releases:read")),
):
    flag = session.execute(
        select(FeatureFlag).where(
            FeatureFlag.organization_id == principal.organization_id, FeatureFlag.key == key
        )
    ).scalar_one_or_none()
    if flag is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Flag not found")
    return _flag_out(flag)


@flags_router.get("/{key}/evaluate", response_model=FlagEvaluationOut)
def evaluate_flag_endpoint(
    key: str,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("releases:read")),
):
    flag = session.execute(
        select(FeatureFlag).where(
            FeatureFlag.organization_id == principal.organization_id, FeatureFlag.key == key
        )
    ).scalar_one_or_none()
    if flag is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Flag not found")
    return FlagEvaluationOut(**linking_service.evaluate_flag(flag, principal.organization_id))


@flags_router.patch("/{key}", response_model=FlagOut)
def update_flag(
    key: str,
    body: FlagUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("releases:manage")),
):
    flag = session.execute(
        select(FeatureFlag).where(
            FeatureFlag.organization_id == principal.organization_id, FeatureFlag.key == key
        )
    ).scalar_one_or_none()
    if flag is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Flag not found")
    if body.rollout_percentage is not None and not 0 <= body.rollout_percentage <= 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="rollout_percentage must be between 0 and 100"
        )
    if body.description is not None:
        flag.description = body.description
    if body.enabled is not None:
        flag.enabled = body.enabled
    if body.rollout_percentage is not None:
        flag.rollout_percentage = body.rollout_percentage
    session.flush()
    _audit(
        session,
        principal,
        audit_mod.FEATURE_FLAG_UPDATED,
        "feature_flag",
        str(flag.id),
        {"key": flag.key, "enabled": flag.enabled, "rollout_percentage": flag.rollout_percentage},
    )
    out = _flag_out(flag)
    session.commit()
    return out


@flags_router.delete("/{key}", status_code=status.HTTP_204_NO_CONTENT)
def delete_flag(
    key: str,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("releases:manage")),
):
    flag = session.execute(
        select(FeatureFlag).where(
            FeatureFlag.organization_id == principal.organization_id, FeatureFlag.key == key
        )
    ).scalar_one_or_none()
    if flag is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Flag not found")
    session.delete(flag)
    session.flush()
    _audit(session, principal, audit_mod.FEATURE_FLAG_DELETED, "feature_flag", str(flag.id), {"key": key})
    session.commit()
    return None


# --- Status page ------------------------------------------------------------


@status_router.get("/incidents", response_model=list[IncidentOut])
def list_incidents(
    status_filter: str | None = None,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("statuspage:read")),
):
    query = select(StatusPageIncident).where(StatusPageIncident.organization_id == principal.organization_id)
    if status_filter is not None:
        if status_filter not in STATUS_PAGE_INCIDENT_STATUSES:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid incident status")
        query = query.where(StatusPageIncident.status == status_filter)
    rows = session.execute(query.order_by(StatusPageIncident.created_at.desc())).scalars().all()
    return [_incident_out(session, i) for i in rows]


@status_router.post("/incidents", response_model=IncidentOut, status_code=status.HTTP_201_CREATED)
def create_incident(
    body: IncidentCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("statuspage:manage")),
):
    if body.status not in STATUS_PAGE_INCIDENT_STATUSES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid incident status")
    incident = StatusPageIncident(
        organization_id=principal.organization_id,
        title=body.title,
        description=body.description,
        status=body.status,
        started_at=body.started_at or datetime.now(UTC),
        resolved_at=datetime.now(UTC) if body.status == "resolved" else None,
        created_by_id=principal.user_id,
    )
    session.add(incident)
    session.flush()
    _audit(
        session,
        principal,
        audit_mod.STATUS_INCIDENT_CREATED,
        "status_page_incident",
        str(incident.id),
        {"title": body.title, "status": body.status},
    )
    out = _incident_out(session, incident)
    session.commit()
    return out


@status_router.get("/incidents/{incident_id}", response_model=IncidentOut)
def get_incident(
    incident_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("statuspage:read")),
):
    return _incident_out(session, _get_incident(session, principal.organization_id, incident_id))


@status_router.patch("/incidents/{incident_id}", response_model=IncidentOut)
def update_incident(
    incident_id: uuid.UUID,
    body: IncidentUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("statuspage:manage")),
):
    incident = _get_incident(session, principal.organization_id, incident_id)
    if body.status is not None:
        if body.status not in STATUS_PAGE_INCIDENT_STATUSES:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid incident status")
        if body.status == "resolved" and incident.status != "resolved" and incident.resolved_at is None:
            incident.resolved_at = datetime.now(UTC)
        incident.status = body.status
    if body.title is not None:
        incident.title = body.title
    if body.description is not None:
        incident.description = body.description
    session.flush()
    _audit(
        session,
        principal,
        audit_mod.STATUS_INCIDENT_UPDATED,
        "status_page_incident",
        str(incident.id),
        {"title": incident.title, "status": incident.status},
    )
    out = _incident_out(session, incident)
    session.commit()
    return out


@status_router.post(
    "/incidents/{incident_id}/updates",
    response_model=IncidentUpdateOut,
    status_code=status.HTTP_201_CREATED,
)
def create_incident_update(
    incident_id: uuid.UUID,
    body: IncidentUpdateCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("statuspage:manage")),
):
    incident = _get_incident(session, principal.organization_id, incident_id)
    if body.status not in STATUS_PAGE_INCIDENT_STATUSES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid incident status")
    update = StatusPageIncidentUpdate(
        organization_id=principal.organization_id,
        incident_id=incident.id,
        status=body.status,
        message=body.message,
        created_by_id=principal.user_id,
    )
    session.add(update)
    # The timeline drives the incident: the update's status becomes the
    # incident's status.
    if body.status == "resolved" and incident.status != "resolved" and incident.resolved_at is None:
        incident.resolved_at = datetime.now(UTC)
    incident.status = body.status
    session.flush()
    _audit(
        session,
        principal,
        audit_mod.STATUS_INCIDENT_UPDATE_CREATED,
        "status_page_incident_update",
        str(update.id),
        {"incident_id": str(incident.id), "status": body.status},
    )
    out = IncidentUpdateOut(
        id=update.id,
        incident_id=update.incident_id,
        status=update.status,
        message=update.message,
        created_at=update.created_at,
    )
    session.commit()
    return out


@status_router.delete("/incidents/{incident_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_incident(
    incident_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("statuspage:manage")),
):
    incident = _get_incident(session, principal.organization_id, incident_id)
    title = incident.title
    session.delete(incident)
    session.flush()
    _audit(
        session,
        principal,
        audit_mod.STATUS_INCIDENT_DELETED,
        "status_page_incident",
        str(incident.id),
        {"title": title},
    )
    session.commit()
    return None


@status_router.get("/public/{org_slug}", response_model=PublicStatusOut)
def public_status_page(org_slug: str, session: Session = Depends(get_db), limit: int = 20):
    """Public status page for one org — no auth, incident data only.

    The slug resolves to an org id through a SECURITY DEFINER function
    (it reveals nothing else); the session is then scoped to that org
    and the response carries only incident fields. Unknown slugs 404.
    """
    if limit < 1 or limit > 100:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="limit must be between 1 and 100")
    org_id = session.execute(
        text("SELECT status_page_org_id_by_slug(:slug)"), {"slug": org_slug}
    ).scalar_one_or_none()
    if org_id is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Status page not found")
    set_rls_context(session, uuid.UUID(str(org_id)), None)
    rows = (
        session.execute(
            select(StatusPageIncident)
            .where(StatusPageIncident.organization_id == uuid.UUID(str(org_id)))
            .order_by(StatusPageIncident.created_at.desc())
            .limit(limit)
        )
        .scalars()
        .all()
    )
    return PublicStatusOut(
        organization_slug=org_slug,
        incidents=[
            PublicIncidentOut(
                id=i.id,
                title=i.title,
                description=i.description,
                status=i.status,
                started_at=i.started_at,
                resolved_at=i.resolved_at,
                created_at=i.created_at,
                updated_at=i.updated_at,
                updates=_incident_updates(session, i.id),
            )
            for i in rows
        ],
    )
