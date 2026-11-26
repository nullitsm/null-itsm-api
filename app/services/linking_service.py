"""Cross-module linking + feature-flag evaluation (Phase 4 workstream D).

``ENTITY_TYPES`` is the allow-list of linkable entity types. Every entry
maps to a real table; link creation validates that BOTH ends exist in
the SAME org (404 otherwise — never across orgs, never to a nonexistent
record). ``entity_identity`` gives the linked graph its basic identity
per entity: a human label plus the entity's own status, nothing more.
"""

from __future__ import annotations

import hashlib
import uuid

from sqlalchemy.orm import Session

from app.models.endpoints import Endpoint
from app.models.identity_assets import Asset
from app.models.itsm import Change
from app.models.linking import FeatureFlag
from app.models.patching import PatchDeployment
from app.models.ticket import Ticket
from app.models.vulnerabilities import VulnerabilityFinding

# Entity type -> ORM model. Keep in sync with the router's allow-list.
ENTITY_TYPES: dict[str, type] = {
    "ticket": Ticket,
    "vulnerability_finding": VulnerabilityFinding,
    "endpoint": Endpoint,
    "patch_deployment": PatchDeployment,
    "asset": Asset,
    "change": Change,
}

# Allowed link semantics.
LINK_TYPES = {"remediates", "caused_by", "verifies", "affects", "assigned_to", "relates_to"}


class UnknownEntityType(ValueError):
    """Raised when a caller names an entity type outside the allow-list."""


class EntityNotFound(ValueError):
    """Raised when a named entity does not exist in the calling org."""


def validate_entity(session: Session, org_id: uuid.UUID, entity_type: str, entity_id: uuid.UUID):
    """Return the entity row, or raise.

    ``UnknownEntityType`` for a type outside the allow-list (router maps
    to 400); ``EntityNotFound`` when no row with that id exists in this
    org (router maps to 404 — cross-org ids are 404, never 403).
    The session is already RLS-scoped to the org, and the org check is
    repeated explicitly so the guarantee does not depend on RLS alone.
    """
    model = ENTITY_TYPES.get(entity_type)
    if model is None:
        raise UnknownEntityType(f"Unknown entity type: {entity_type}")
    row = session.get(model, entity_id)
    if row is None or row.organization_id != org_id:
        raise EntityNotFound(f"{entity_type} not found: {entity_id}")
    return row


def entity_identity(entity_type: str, row) -> dict:
    """Basic identity for a linked entity: type, id, label, status."""
    label: str
    if entity_type == "ticket":
        label = f"{row.number} — {row.title}"
    elif entity_type == "vulnerability_finding":
        label = row.cve_id
    elif entity_type == "endpoint":
        label = row.hostname
    elif entity_type == "patch_deployment":
        label = row.name
    elif entity_type == "asset":
        label = f"{row.asset_tag} — {row.name}"
    elif entity_type == "change":
        label = f"{row.number} — {row.title}"
    else:  # pragma: no cover - allow-list prevents this
        label = str(row.id)
    return {
        "entity_type": entity_type,
        "id": str(row.id),
        "label": label,
        "status": getattr(row, "status", None),
    }


def evaluate_flag(flag: FeatureFlag, org_id: uuid.UUID) -> dict:
    """Evaluate a feature flag for one org, deterministically.

    The org's bucket (0–99) is a stable hash of (org id, flag key), so
    the same org always gets the same answer for the same flag. The
    flag is on only when it is enabled AND the org's bucket falls
    inside the rollout percentage. A disabled flag is off for every
    org; a 100% rollout is on for every org (when enabled).
    """
    digest = hashlib.sha256(f"{org_id}:{flag.key}".encode()).hexdigest()
    bucket = int(digest, 16) % 100
    enabled = bool(flag.enabled) and bucket < flag.rollout_percentage
    return {
        "key": flag.key,
        "enabled": enabled,
        "flag_enabled": bool(flag.enabled),
        "rollout_percentage": flag.rollout_percentage,
        "bucket": bucket,
    }
