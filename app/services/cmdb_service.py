"""CMDB service: configuration items, relationships, dependency graph.

Pure data logic over the Phase 3 ``configuration_items`` /
``ci_relationships`` tables. Routers translate the exceptions raised here
into HTTP statuses; nothing in this module knows about HTTP.
"""

from __future__ import annotations

import uuid
from collections import deque

from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.cmdb_network import CiRelationship, ConfigurationItem
from app.models.endpoints import Endpoint
from app.models.identity_assets import Asset
from app.models.platform import Membership

CI_TYPES = {"server", "workstation", "network_device", "application", "service", "database", "other"}
CI_STATUSES = {"active", "inactive", "retired"}
RELATIONSHIP_TYPES = {"depends_on", "runs_on", "hosts", "connects_to", "uses", "manages"}
GRAPH_MAX_DEPTH = 2


class NotFoundError(Exception):
    """A row does not exist in this organization (surfaced as 404)."""


class ValidationError(Exception):
    """Caller input is invalid (surfaced as 400)."""


def get_ci(session: Session, org_id: uuid.UUID, ci_id: uuid.UUID) -> ConfigurationItem:
    """Fetch one CI, scoped to the org; 404 when missing or foreign."""
    ci = session.get(ConfigurationItem, ci_id)
    if ci is None or ci.organization_id != org_id:
        raise NotFoundError(f"Configuration item {ci_id} not found")
    return ci


def validate_ci_links(
    session: Session,
    org_id: uuid.UUID,
    *,
    owner_id: uuid.UUID | None,
    asset_id: uuid.UUID | None,
    endpoint_id: uuid.UUID | None,
) -> None:
    """Validate the optional links on a CI.

    Asset / endpoint must exist in this org (404 otherwise, per spec);
    an owner must be an active member of this org (400 otherwise).
    """
    if owner_id is not None:
        membership = session.execute(
            select(Membership).where(
                Membership.organization_id == org_id,
                Membership.user_id == owner_id,
                Membership.status == "active",
            )
        ).scalar_one_or_none()
        if membership is None:
            raise ValidationError("Owner is not an active member of this organization")
    if asset_id is not None:
        asset = session.get(Asset, asset_id)
        if asset is None or asset.organization_id != org_id:
            raise NotFoundError(f"Asset {asset_id} not found")
    if endpoint_id is not None:
        endpoint = session.get(Endpoint, endpoint_id)
        if endpoint is None or endpoint.organization_id != org_id:
            raise NotFoundError(f"Endpoint {endpoint_id} not found")


def list_cis(
    session: Session,
    org_id: uuid.UUID,
    *,
    ci_type: str | None = None,
    status: str | None = None,
    owner_id: uuid.UUID | None = None,
    search: str | None = None,
) -> list[ConfigurationItem]:
    stmt = select(ConfigurationItem).where(ConfigurationItem.organization_id == org_id)
    if ci_type is not None:
        stmt = stmt.where(ConfigurationItem.ci_type == ci_type)
    if status is not None:
        stmt = stmt.where(ConfigurationItem.status == status)
    if owner_id is not None:
        stmt = stmt.where(ConfigurationItem.owner_id == owner_id)
    if search:
        stmt = stmt.where(ConfigurationItem.name.ilike(f"%{search}%"))
    return list(session.execute(stmt.order_by(ConfigurationItem.created_at.desc())).scalars())


def create_ci(
    session: Session,
    org_id: uuid.UUID,
    *,
    name: str,
    ci_type: str,
    status: str,
    owner_id: uuid.UUID | None,
    asset_id: uuid.UUID | None,
    endpoint_id: uuid.UUID | None,
    attributes: dict,
) -> ConfigurationItem:
    if ci_type not in CI_TYPES:
        raise ValidationError(f"Invalid ci_type: {ci_type}")
    if status not in CI_STATUSES:
        raise ValidationError(f"Invalid status: {status}")
    validate_ci_links(session, org_id, owner_id=owner_id, asset_id=asset_id, endpoint_id=endpoint_id)
    ci = ConfigurationItem(
        organization_id=org_id,
        name=name,
        ci_type=ci_type,
        status=status,
        owner_id=owner_id,
        asset_id=asset_id,
        endpoint_id=endpoint_id,
        attributes=attributes or {},
    )
    session.add(ci)
    session.flush()
    return ci


def update_ci(
    session: Session,
    org_id: uuid.UUID,
    ci: ConfigurationItem,
    *,
    name: str | None,
    ci_type: str | None,
    status: str | None,
    owner_id: uuid.UUID | None,
    asset_id: uuid.UUID | None,
    endpoint_id: uuid.UUID | None,
    attributes: dict | None,
) -> ConfigurationItem:
    if ci_type is not None and ci_type not in CI_TYPES:
        raise ValidationError(f"Invalid ci_type: {ci_type}")
    if status is not None and status not in CI_STATUSES:
        raise ValidationError(f"Invalid status: {status}")
    if owner_id is not None or asset_id is not None or endpoint_id is not None:
        validate_ci_links(
            session,
            org_id,
            owner_id=owner_id if owner_id is not None else ci.owner_id,
            asset_id=asset_id if asset_id is not None else ci.asset_id,
            endpoint_id=endpoint_id if endpoint_id is not None else ci.endpoint_id,
        )
    if name is not None:
        ci.name = name
    if ci_type is not None:
        ci.ci_type = ci_type
    if status is not None:
        ci.status = status
    if owner_id is not None:
        ci.owner_id = owner_id
    if asset_id is not None:
        ci.asset_id = asset_id
    if endpoint_id is not None:
        ci.endpoint_id = endpoint_id
    if attributes is not None:
        ci.attributes = attributes
    session.flush()
    return ci


def delete_ci(session: Session, ci: ConfigurationItem) -> None:
    """Delete a CI; its relationships cascade via the FK (ondelete=CASCADE)."""
    session.delete(ci)
    session.flush()


def get_relationship(session: Session, org_id: uuid.UUID, rel_id: uuid.UUID) -> CiRelationship:
    rel = session.get(CiRelationship, rel_id)
    if rel is None or rel.organization_id != org_id:
        raise NotFoundError(f"Relationship {rel_id} not found")
    return rel


def create_relationship(
    session: Session,
    org_id: uuid.UUID,
    source: ConfigurationItem,
    *,
    target_ci_id: uuid.UUID,
    relationship_type: str,
) -> CiRelationship:
    if relationship_type not in RELATIONSHIP_TYPES:
        raise ValidationError(f"Invalid relationship_type: {relationship_type}")
    if target_ci_id == source.id:
        raise ValidationError("A configuration item cannot relate to itself")
    target = session.get(ConfigurationItem, target_ci_id)
    if target is None or target.organization_id != org_id:
        raise NotFoundError(f"Configuration item {target_ci_id} not found")
    existing = session.execute(
        select(CiRelationship).where(
            CiRelationship.organization_id == org_id,
            CiRelationship.source_ci_id == source.id,
            CiRelationship.target_ci_id == target_ci_id,
            CiRelationship.relationship_type == relationship_type,
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise ValidationError("Relationship already exists")
    rel = CiRelationship(
        organization_id=org_id,
        source_ci_id=source.id,
        target_ci_id=target_ci_id,
        relationship_type=relationship_type,
    )
    session.add(rel)
    try:
        session.flush()
    except IntegrityError as exc:
        session.rollback()
        raise ValidationError("Relationship already exists") from exc
    return rel


def list_relationships(session: Session, org_id: uuid.UUID, ci_id: uuid.UUID) -> list[CiRelationship]:
    """All edges touching a CI, either direction."""
    stmt = (
        select(CiRelationship)
        .where(
            CiRelationship.organization_id == org_id,
            or_(
                CiRelationship.source_ci_id == ci_id,
                CiRelationship.target_ci_id == ci_id,
            ),
        )
        .order_by(CiRelationship.created_at)
    )
    return list(session.execute(stmt).scalars())


def delete_relationship(session: Session, rel: CiRelationship) -> None:
    session.delete(rel)
    session.flush()


def ci_graph(session: Session, org_id: uuid.UUID, ci_id: uuid.UUID, depth: int = GRAPH_MAX_DEPTH) -> dict:
    """Breadth-first neighborhood of a CI up to ``depth`` hops.

    Traversal is undirected (a dependency edge is walkable both ways);
    the returned edges keep their stored direction. Only edges whose
    endpoints are both inside the visited set are returned.
    """
    root = get_ci(session, org_id, ci_id)
    visited: dict[uuid.UUID, ConfigurationItem] = {root.id: root}
    queue: deque[tuple[uuid.UUID, int]] = deque([(root.id, 0)])
    edges: dict[uuid.UUID, CiRelationship] = {}
    while queue:
        current_id, current_depth = queue.popleft()
        if current_depth >= depth:
            continue
        for rel in list_relationships(session, org_id, current_id):
            edges[rel.id] = rel
            neighbor_id = rel.target_ci_id if rel.source_ci_id == current_id else rel.source_ci_id
            if neighbor_id not in visited:
                neighbor = session.get(ConfigurationItem, neighbor_id)
                if neighbor is not None and neighbor.organization_id == org_id:
                    visited[neighbor_id] = neighbor
                    queue.append((neighbor_id, current_depth + 1))
    return {
        "nodes": list(visited.values()),
        "edges": [e for e in edges.values() if e.source_ci_id in visited and e.target_ci_id in visited],
    }
