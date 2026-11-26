"""CMDB routes: configuration items, relationships, dependency graph.

Permissions: ``cmdb:read`` / ``cmdb:manage``. Cross-org access returns
404 (never reveal another org's rows). Every mutating endpoint writes an
audit row. Responses are built before ``session.commit()`` (see
docs/DECISIONS.md).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.audit import (
    CMDB_ITEM_CREATED,
    CMDB_ITEM_DELETED,
    CMDB_ITEM_UPDATED,
    CMDB_RELATIONSHIP_CREATED,
    CMDB_RELATIONSHIP_DELETED,
)
from app.deps import Principal, get_db, require_permission
from app.models.cmdb_network import CiRelationship, ConfigurationItem
from app.models.endpoints import Endpoint
from app.models.identity_assets import Asset
from app.services import cmdb_service

router = APIRouter(prefix="/api/v1/cmdb", tags=["cmdb"])


# --- Schemas (local: app/schemas.py belongs to another workstream) --------


class CiCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    ci_type: str = "other"
    status: str = "active"
    owner_id: uuid.UUID | None = None
    asset_id: uuid.UUID | None = None
    endpoint_id: uuid.UUID | None = None
    attributes: dict = Field(default_factory=dict)


class CiUpdate(BaseModel):
    name: str | None = None
    ci_type: str | None = None
    status: str | None = None
    owner_id: uuid.UUID | None = None
    asset_id: uuid.UUID | None = None
    endpoint_id: uuid.UUID | None = None
    attributes: dict | None = None


class CiOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    ci_type: str
    status: str
    owner_id: uuid.UUID | None
    asset_id: uuid.UUID | None
    endpoint_id: uuid.UUID | None
    attributes: dict
    created_at: str
    updated_at: str


class RelationshipCreate(BaseModel):
    target_ci_id: uuid.UUID
    relationship_type: str


class RelationshipOut(BaseModel):
    id: uuid.UUID
    source_ci_id: uuid.UUID
    target_ci_id: uuid.UUID
    relationship_type: str
    direction: str | None = None
    created_at: str


class CiDetailOut(CiOut):
    asset: dict | None = None
    endpoint: dict | None = None
    relationships: list[RelationshipOut] = Field(default_factory=list)


class GraphNodeOut(BaseModel):
    id: uuid.UUID
    name: str
    ci_type: str
    status: str


class GraphEdgeOut(BaseModel):
    id: uuid.UUID
    source_ci_id: uuid.UUID
    target_ci_id: uuid.UUID
    relationship_type: str


class GraphOut(BaseModel):
    nodes: list[GraphNodeOut]
    edges: list[GraphEdgeOut]


# --- Helpers ----------------------------------------------------------------


def _ci_out(ci: ConfigurationItem) -> CiOut:
    return CiOut(
        id=ci.id,
        organization_id=ci.organization_id,
        name=ci.name,
        ci_type=ci.ci_type,
        status=ci.status,
        owner_id=ci.owner_id,
        asset_id=ci.asset_id,
        endpoint_id=ci.endpoint_id,
        attributes=ci.attributes or {},
        created_at=ci.created_at.isoformat(),
        updated_at=ci.updated_at.isoformat(),
    )


def _rel_out(rel: CiRelationship, direction: str | None = None) -> RelationshipOut:
    return RelationshipOut(
        id=rel.id,
        source_ci_id=rel.source_ci_id,
        target_ci_id=rel.target_ci_id,
        relationship_type=rel.relationship_type,
        direction=direction,
        created_at=rel.created_at.isoformat(),
    )


def _get_ci_or_404(session: Session, org_id: uuid.UUID, ci_id: uuid.UUID) -> ConfigurationItem:
    try:
        return cmdb_service.get_ci(session, org_id, ci_id)
    except cmdb_service.NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


def _ci_detail_out(session: Session, org_id: uuid.UUID, ci: ConfigurationItem) -> CiDetailOut:
    out = CiDetailOut(**_ci_out(ci).model_dump())
    if ci.asset_id is not None:
        asset = session.get(Asset, ci.asset_id)
        if asset is not None and asset.organization_id == org_id:
            out.asset = {"id": str(asset.id), "asset_tag": asset.asset_tag, "name": asset.name, "type": asset.type}
    if ci.endpoint_id is not None:
        endpoint = session.get(Endpoint, ci.endpoint_id)
        if endpoint is not None and endpoint.organization_id == org_id:
            out.endpoint = {
                "id": str(endpoint.id),
                "hostname": endpoint.hostname,
                "status": endpoint.status,
            }
    rels = cmdb_service.list_relationships(session, org_id, ci.id)
    out.relationships = [_rel_out(r, direction="outgoing" if r.source_ci_id == ci.id else "incoming") for r in rels]
    return out


def _audit(
    session: Session,
    principal: Principal,
    action: str,
    resource_type: str,
    resource_id: str,
    metadata: dict | None = None,
) -> None:
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


# --- Configuration items ----------------------------------------------------


@router.get("/items", response_model=list[CiOut])
def list_items(
    ci_type: str | None = Query(default=None),
    status: str | None = Query(default=None),
    owner_id: uuid.UUID | None = Query(default=None),
    search: str | None = Query(default=None),
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("cmdb:read")),
):
    rows = cmdb_service.list_cis(
        session,
        principal.organization_id,
        ci_type=ci_type,
        status=status,
        owner_id=owner_id,
        search=search,
    )
    return [_ci_out(ci) for ci in rows]


@router.post("/items", response_model=CiOut, status_code=status.HTTP_201_CREATED)
def create_item(
    body: CiCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("cmdb:manage")),
):
    try:
        ci = cmdb_service.create_ci(
            session,
            principal.organization_id,
            name=body.name,
            ci_type=body.ci_type,
            status=body.status,
            owner_id=body.owner_id,
            asset_id=body.asset_id,
            endpoint_id=body.endpoint_id,
            attributes=body.attributes,
        )
    except cmdb_service.NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except cmdb_service.ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    _audit(session, principal, CMDB_ITEM_CREATED, "configuration_item", str(ci.id), {"name": ci.name})
    out = _ci_out(ci)
    session.commit()
    return out


@router.get("/items/{ci_id}", response_model=CiDetailOut)
def get_item(
    ci_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("cmdb:read")),
):
    ci = _get_ci_or_404(session, principal.organization_id, ci_id)
    return _ci_detail_out(session, principal.organization_id, ci)


@router.patch("/items/{ci_id}", response_model=CiOut)
def update_item(
    ci_id: uuid.UUID,
    body: CiUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("cmdb:manage")),
):
    ci = _get_ci_or_404(session, principal.organization_id, ci_id)
    try:
        cmdb_service.update_ci(
            session,
            principal.organization_id,
            ci,
            name=body.name,
            ci_type=body.ci_type,
            status=body.status,
            owner_id=body.owner_id,
            asset_id=body.asset_id,
            endpoint_id=body.endpoint_id,
            attributes=body.attributes,
        )
    except cmdb_service.NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except cmdb_service.ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    _audit(session, principal, CMDB_ITEM_UPDATED, "configuration_item", str(ci.id), {"name": ci.name})
    out = _ci_out(ci)
    session.commit()
    return out


@router.delete("/items/{ci_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_item(
    ci_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("cmdb:manage")),
):
    ci = _get_ci_or_404(session, principal.organization_id, ci_id)
    cmdb_service.delete_ci(session, ci)
    _audit(session, principal, CMDB_ITEM_DELETED, "configuration_item", str(ci.id), {"name": ci.name})
    session.commit()
    return None


# --- Relationships ----------------------------------------------------------


@router.post("/items/{ci_id}/relationships", response_model=RelationshipOut, status_code=status.HTTP_201_CREATED)
def create_relationship(
    ci_id: uuid.UUID,
    body: RelationshipCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("cmdb:manage")),
):
    source = _get_ci_or_404(session, principal.organization_id, ci_id)
    try:
        rel = cmdb_service.create_relationship(
            session,
            principal.organization_id,
            source,
            target_ci_id=body.target_ci_id,
            relationship_type=body.relationship_type,
        )
    except cmdb_service.NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except cmdb_service.ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    _audit(
        session,
        principal,
        CMDB_RELATIONSHIP_CREATED,
        "ci_relationship",
        str(rel.id),
        {"source_ci_id": str(source.id), "target_ci_id": str(body.target_ci_id)},
    )
    out = _rel_out(rel, direction="outgoing")
    session.commit()
    return out


@router.get("/items/{ci_id}/relationships", response_model=list[RelationshipOut])
def list_relationships(
    ci_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("cmdb:read")),
):
    ci = _get_ci_or_404(session, principal.organization_id, ci_id)
    rels = cmdb_service.list_relationships(session, principal.organization_id, ci.id)
    return [_rel_out(r, direction="outgoing" if r.source_ci_id == ci.id else "incoming") for r in rels]


@router.delete("/relationships/{rel_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_relationship(
    rel_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("cmdb:manage")),
):
    try:
        rel = cmdb_service.get_relationship(session, principal.organization_id, rel_id)
    except cmdb_service.NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    cmdb_service.delete_relationship(session, rel)
    _audit(session, principal, CMDB_RELATIONSHIP_DELETED, "ci_relationship", str(rel.id))
    session.commit()
    return None


# --- Graph ------------------------------------------------------------------


@router.get("/items/{ci_id}/graph", response_model=GraphOut)
def get_graph(
    ci_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("cmdb:read")),
):
    try:
        graph = cmdb_service.ci_graph(session, principal.organization_id, ci_id)
    except cmdb_service.NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    return GraphOut(
        nodes=[GraphNodeOut(id=n.id, name=n.name, ci_type=n.ci_type, status=n.status) for n in graph["nodes"]],
        edges=[
            GraphEdgeOut(
                id=e.id,
                source_ci_id=e.source_ci_id,
                target_ci_id=e.target_ci_id,
                relationship_type=e.relationship_type,
            )
            for e in graph["edges"]
        ],
    )
