"""Patching service (Phase 3).

Applies agent job results for patch scans and patch deployments. These
functions are called by workstream A's agent job-result endpoint via a
lazy import inside its handler — never imported at that module's top.

Rules:
- Patches exist only because a scan reported them; nothing is invented.
- A patch is claimed installed only when a scan or a job result says so.
- A completed patch scan is treated as a full inventory of the
  endpoint's missing patches: a previously-missing finding for a patch
  the scan does NOT report is flipped to ``installed`` (the scan says it
  is no longer missing). A patch the scan DOES report missing is
  (re-)opened.
- Both apply functions tolerate malformed job output: they record the
  problem in the returned dict and leave state unchanged — they never
  raise into the agent result call.
- Neither function commits; the caller owns the transaction. They flush
  so ids are available to the caller.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.endpoints import AgentJob
from app.models.patching import (
    Patch,
    PatchDeployment,
    PatchDeploymentItem,
    PatchFinding,
    PatchScan,
)

UTC = timezone.utc

TERMINAL_ITEM_STATUSES = {"succeeded", "failed", "skipped"}


def _now() -> datetime:
    return datetime.now(UTC)


def _parse_output(job: AgentJob) -> tuple[dict | None, str | None]:
    """Parse ``job.output`` as JSON. Returns (data, error)."""
    raw = job.output
    if raw is None:
        return None, "job output is empty"
    if isinstance(raw, dict):
        return raw, None
    if not isinstance(raw, str) or not raw.strip():
        return None, "job output is empty"
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        return None, f"job output is not valid JSON: {exc}"
    if not isinstance(data, dict):
        return None, "job output JSON is not an object"
    return data, None


def _parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _find_or_create_patch(
    session: Session,
    org_id: uuid.UUID,
    entry: dict,
) -> Patch | None:
    """Find-or-create the Patch row for one reported missing patch.

    Match on (organization_id, kb_id) when kb_id is present, else on
    (organization_id, title, vendor). Returns None when the entry has no
    usable title.
    """
    title = entry.get("title")
    if not isinstance(title, str) or not title.strip():
        return None
    title = title.strip()
    vendor = entry.get("vendor")
    vendor = vendor.strip() if isinstance(vendor, str) and vendor.strip() else None
    kb_id = entry.get("kb_id")
    kb_id = kb_id.strip() if isinstance(kb_id, str) and kb_id.strip() else None
    severity = entry.get("severity")
    severity = severity.strip() if isinstance(severity, str) and severity.strip() else "medium"
    cve_ids = entry.get("cve_ids")
    if not isinstance(cve_ids, list):
        cve_ids = []

    patch: Patch | None = None
    if kb_id is not None:
        patch = session.execute(
            select(Patch).where(Patch.organization_id == org_id, Patch.kb_id == kb_id)
        ).scalar_one_or_none()
    if patch is None:
        if vendor is None:
            patch = session.execute(
                select(Patch).where(
                    Patch.organization_id == org_id,
                    Patch.title == title,
                    Patch.vendor.is_(None),
                )
            ).scalar_one_or_none()
        else:
            patch = session.execute(
                select(Patch).where(
                    Patch.organization_id == org_id,
                    Patch.title == title,
                    Patch.vendor == vendor,
                )
            ).scalar_one_or_none()
    if patch is None:
        patch = Patch(
            id=uuid.uuid4(),
            organization_id=org_id,
            title=title,
            vendor=vendor,
            kb_id=kb_id,
            severity=severity,
            category=entry.get("category") if isinstance(entry.get("category"), str) else None,
            cve_ids=cve_ids,
            os_family=entry.get("os_family") if isinstance(entry.get("os_family"), str) else None,
        )
        session.add(patch)
        session.flush()
    return patch


def _upsert_finding(
    session: Session,
    org_id: uuid.UUID,
    endpoint_id: uuid.UUID,
    patch: Patch,
    scan: PatchScan,
    now: datetime,
) -> str:
    """Upsert the open finding for (endpoint, patch). Returns "new" or "updated"."""
    existing = (
        session.execute(
            select(PatchFinding)
            .where(
                PatchFinding.organization_id == org_id,
                PatchFinding.endpoint_id == endpoint_id,
                PatchFinding.patch_id == patch.id,
            )
            .order_by(PatchFinding.created_at.desc())
        )
        .scalars()
        .all()
    )
    for row in existing:
        if row.status == "missing":
            row.scan_id = scan.id
            row.detected_at = now
            return "updated"
    for row in existing:
        if row.status == "installed":
            row.status = "missing"
            row.scan_id = scan.id
            row.detected_at = now
            row.installed_at = None
            return "updated"
    finding = PatchFinding(
        id=uuid.uuid4(),
        organization_id=org_id,
        endpoint_id=endpoint_id,
        patch_id=patch.id,
        scan_id=scan.id,
        status="missing",
        detected_at=now,
    )
    session.add(finding)
    session.flush()
    return "new"


def _verify_deployments_for_scan(session: Session, org_id: uuid.UUID, scan: PatchScan) -> None:
    """Recompute verification for deployments proven by this scan.

    Passed when NO missing findings remain for the deployment's
    (endpoint, patch) items; failed otherwise. The deployment status
    itself is left unchanged.

    Flush first: the session runs with autoflush off, and the queries
    below filter on ``status`` in SQL, so pending in-memory flips must
    reach the database before they run.
    """
    session.flush()
    deployments = (
        session.execute(
            select(PatchDeployment).where(
                PatchDeployment.organization_id == org_id,
                PatchDeployment.verification_scan_id == scan.id,
            )
        )
        .scalars()
        .all()
    )
    for deployment in deployments:
        items = (
            session.execute(select(PatchDeploymentItem).where(PatchDeploymentItem.deployment_id == deployment.id))
            .scalars()
            .all()
        )
        still_missing = False
        for item in items:
            open_finding = session.execute(
                select(PatchFinding).where(
                    PatchFinding.organization_id == org_id,
                    PatchFinding.endpoint_id == item.endpoint_id,
                    PatchFinding.patch_id == item.patch_id,
                    PatchFinding.status == "missing",
                )
            ).scalar_one_or_none()
            if open_finding is not None:
                still_missing = True
                break
        deployment.verification_status = "failed" if still_missing else "passed"


def apply_patch_scan_result(session: Session, org_id: uuid.UUID, job: AgentJob) -> dict:
    """Apply a ``patch_scan`` agent job result.

    ``job.output`` JSON: ``{"missing_patches": [{title, vendor?, kb_id?,
    severity, category?, cve_ids?, os_family?}], "scanned_at": iso}``.
    Idempotent per job: re-applying the same job returns
    ``{"status": "already_applied"}`` without duplicating anything.
    """
    data, error = _parse_output(job)
    if error is not None:
        return {"status": "malformed_output", "error": error}
    missing = data.get("missing_patches")
    if missing is None:
        return {"status": "malformed_output", "error": "missing_patches is required"}
    if not isinstance(missing, list):
        return {"status": "malformed_output", "error": "missing_patches must be a list"}

    now = _now()
    existing_scan = session.execute(select(PatchScan).where(PatchScan.job_id == job.id)).scalar_one_or_none()
    if existing_scan is not None and existing_scan.status == "completed":
        return {"status": "already_applied", "scan_id": str(existing_scan.id)}

    if existing_scan is not None:
        scan = existing_scan
    else:
        scan = PatchScan(
            id=uuid.uuid4(),
            organization_id=org_id,
            endpoint_id=job.endpoint_id,
            job_id=job.id,
            status="pending",
        )
        session.add(scan)
    scan.status = "completed"
    scan.finished_at = now
    scan.missing_count = len(missing)
    if scan.started_at is None:
        scan.started_at = _parse_iso(data.get("scanned_at")) or now
    session.flush()

    new_findings = 0
    updated_findings = 0
    reported_patch_ids: set[uuid.UUID] = set()
    for entry in missing:
        if not isinstance(entry, dict):
            continue
        patch = _find_or_create_patch(session, org_id, entry)
        if patch is None:
            continue
        reported_patch_ids.add(patch.id)
        outcome = _upsert_finding(session, org_id, job.endpoint_id, patch, scan, now)
        if outcome == "new":
            new_findings += 1
        else:
            updated_findings += 1

    # A completed scan is a full inventory of missing patches for this
    # endpoint: previously-missing findings for patches the scan did not
    # report are no longer missing — the scan says they are installed.
    # Flush first (autoflush is off): the query below filters on status
    # in SQL and must see the upserts above.
    session.flush()
    open_findings = (
        session.execute(
            select(PatchFinding).where(
                PatchFinding.organization_id == org_id,
                PatchFinding.endpoint_id == job.endpoint_id,
                PatchFinding.status == "missing",
            )
        )
        .scalars()
        .all()
    )
    for finding in open_findings:
        if finding.patch_id not in reported_patch_ids:
            finding.status = "installed"
            finding.installed_at = now

    _verify_deployments_for_scan(session, org_id, scan)
    session.flush()
    return {
        "status": "applied",
        "scan_id": str(scan.id),
        "missing_count": len(missing),
        "new_findings": new_findings,
        "updated_findings": updated_findings,
    }


def _roll_up_deployment(session: Session, deployment: PatchDeployment) -> None:
    """Set the deployment status from its items, when all are terminal."""
    session.flush()
    items = (
        session.execute(select(PatchDeploymentItem).where(PatchDeploymentItem.deployment_id == deployment.id))
        .scalars()
        .all()
    )
    if not items:
        return
    if not all(item.status in TERMINAL_ITEM_STATUSES for item in items):
        return
    if all(item.status in ("succeeded", "skipped") for item in items):
        deployment.status = "completed"
    else:
        deployment.status = "failed"


def apply_patch_deploy_result(session: Session, org_id: uuid.UUID, job: AgentJob) -> dict:
    """Apply a ``patch_deploy`` agent job result.

    ``job.output`` JSON: ``{"patch_id": str, "status": "installed" |
    "failed", "detail"?: str}``. Idempotent per item: re-applying a job
    whose item is already terminal returns
    ``{"status": "already_applied"}``.
    """
    data, error = _parse_output(job)
    if error is not None:
        return {"status": "malformed_output", "error": error}
    patch_id_raw = data.get("patch_id")
    result_status = data.get("status")
    if not isinstance(patch_id_raw, str) or not patch_id_raw.strip():
        return {"status": "malformed_output", "error": "patch_id is required"}
    if result_status not in ("installed", "failed"):
        return {"status": "malformed_output", "error": "status must be 'installed' or 'failed'"}
    try:
        patch_id = uuid.UUID(patch_id_raw)
    except ValueError:
        return {"status": "malformed_output", "error": "patch_id is not a valid UUID"}

    item = session.execute(select(PatchDeploymentItem).where(PatchDeploymentItem.job_id == job.id)).scalar_one_or_none()
    if item is None:
        return {"status": "no_item", "patch_id": str(patch_id)}
    if item.status in TERMINAL_ITEM_STATUSES:
        return {"status": "already_applied", "item_id": str(item.id)}

    now = _now()
    detail = data.get("detail")
    item.status = "succeeded" if result_status == "installed" else "failed"
    item.result = detail if isinstance(detail, str) else None

    if result_status == "installed":
        finding = session.execute(
            select(PatchFinding).where(
                PatchFinding.organization_id == org_id,
                PatchFinding.endpoint_id == job.endpoint_id,
                PatchFinding.patch_id == patch_id,
                PatchFinding.status == "missing",
            )
        ).scalar_one_or_none()
        if finding is not None:
            finding.status = "installed"
            finding.installed_at = now

    deployment = session.get(PatchDeployment, item.deployment_id)
    if deployment is not None:
        _roll_up_deployment(session, deployment)
    session.flush()
    return {
        "status": "applied",
        "item_id": str(item.id),
        "item_status": item.status,
        "deployment_id": str(item.deployment_id),
        "deployment_status": deployment.status if deployment is not None else None,
    }
