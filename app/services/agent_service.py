"""Agent-facing service logic (Phase 3, contract §9).

Job-result handler registry
---------------------------
Workstreams B (patching) and C (vulnerabilities) land their handler
modules in parallel, so the registry maps job types to
``"module:function"`` dotted paths and the import is LAZY — inside
:func:`dispatch_job_result`, never at module top. If the target module
has not landed yet (ImportError / AttributeError), the result itself
is still recorded and an ``agent.job_result_unapplied`` audit row is
written; the result call does NOT fail.

Job types and the output JSON shapes their handlers consume (for B/C):

- ``patch_scan`` output: ``{"missing_patches": [{title, vendor?, kb_id?,
  severity, category?, cve_ids?, os_family?}], "scanned_at": iso}``
- ``patch_deploy`` output: ``{"patch_id": str, "status":
  "installed" | "failed", "detail"?: str}``
- ``vuln_scan`` output: ``{"results": [{host, cve_id?, plugin_name?,
  plugin_output?, severity}]}``

Results arrive as JSON in the result body and are stored as a JSON
string in ``agent_jobs.output`` (a Text column); handlers parse it
with ``json.loads(job.output)``.
"""

from __future__ import annotations

import importlib
import json
import uuid
from datetime import datetime

from sqlalchemy import text
from sqlalchemy.orm import Session

from app import audit as audit_mod

# Job types the backend may issue (contract §9.5 allowlist). Anything
# else is rejected with 400 at issue time and must be rejected by the
# agent with status "rejected" if it ever arrives.
JOB_TYPES = {"patch_scan", "inventory_refresh", "config_apply", "patch_deploy", "vuln_scan", "restart", "shutdown"}

# Job type -> permission required to issue it (user-facing side).
JOB_TYPE_PERMISSIONS = {
    "patch_scan": "endpoints:scan",
    "inventory_refresh": "endpoints:scan",
    "vuln_scan": "endpoints:scan",
    "config_apply": "endpoints:deploy",
    "patch_deploy": "endpoints:deploy",
    "restart": "endpoints:deploy",
    "shutdown": "endpoints:deploy",
}

# Job type -> "module:function" handler for the reported result.
# Lazy-imported inside dispatch_job_result (B/C modules land in parallel).
JOB_RESULT_HANDLERS: dict[str, str] = {
    "patch_scan": "app.services.patching_service:apply_patch_scan_result",
    "patch_deploy": "app.services.patching_service:apply_patch_deploy_result",
    "vuln_scan": "app.services.vuln_service:apply_vuln_scan_result",
}


def parse_version(version: str) -> tuple[int, ...]:
    """Parse a dotted-numeric version (``1.2.3``) for comparison.

    Non-numeric segments compare as 0; missing segments are absent
    (tuple comparison treats a shorter prefix as smaller).
    """
    parts: list[int] = []
    for segment in str(version).strip().split("."):
        try:
            parts.append(int(segment))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def find_newer_release(session: Session, current_version: str, os_name: str, arch: str) -> dict | None:
    """Newest ACTIVE agent release for (os, arch) newer than current.

    Returns the release row as a dict, or None when no newer release
    exists. ``download_url`` is deliberately None: no artifact storage
    is configured, so no URL is invented (see the updates/check route).
    """
    current = parse_version(current_version)
    rows = session.execute(
        text("SELECT * FROM agent_releases WHERE os = :os AND arch = :arch AND is_active = true"),
        {"os": os_name, "arch": arch},
    ).mappings()
    best: dict | None = None
    best_version: tuple[int, ...] = ()
    for row in rows:
        candidate = dict(row)
        version = parse_version(candidate["version"])
        if version > current and (best is None or version > best_version):
            best, best_version = candidate, version
    return best


def expire_pending_jobs(session: Session, endpoint_id: uuid.UUID, now: datetime) -> int:
    """Mark pending jobs past ``expires_at`` as expired (never delivered).

    Returns the number of jobs expired. Uses a single UPDATE so the
    sweep is atomic with the caller's transaction.
    """
    result = session.execute(
        text(
            "UPDATE agent_jobs SET status = 'expired' "
            "WHERE endpoint_id = :eid AND status = 'pending' "
            "AND expires_at IS NOT NULL AND expires_at < :now"
        ),
        {"eid": str(endpoint_id), "now": now},
    )
    return result.rowcount or 0


def pending_jobs_count(session: Session, endpoint_id: uuid.UUID) -> int:
    """Count of pending (deliverable) jobs for a device."""
    return session.execute(
        text("SELECT count(*) FROM agent_jobs WHERE endpoint_id = :eid AND status = 'pending'"),
        {"eid": str(endpoint_id)},
    ).scalar_one()


def dispatch_job_result(session: Session, org_id: uuid.UUID, job) -> bool:
    """Dispatch a closed job's result to its registered handler.

    Returns True when a handler ran, False when the job type has no
    handler, the handler module has not landed yet, or the handler
    itself failed. The device's result is ground truth and is already
    recorded before this runs: a failing downstream apply must NOT roll
    it back, so handler exceptions are audited
    (``agent.job_result_handler_failed``) and swallowed — the apply
    functions are idempotent, so the result can be re-applied later.
    Only the not-landed-yet case writes ``agent.job_result_unapplied``.
    """
    target = JOB_RESULT_HANDLERS.get(job.type)
    if target is None:
        return False
    module_path, _, fn_name = target.rpartition(":")
    try:
        module = importlib.import_module(module_path)
        handler = getattr(module, fn_name)
    except (ImportError, AttributeError):
        audit_mod.write_audit(
            session,
            organization_id=org_id,
            actor_id=None,
            action=audit_mod.AGENT_JOB_RESULT_UNAPPLIED,
            resource_type="agent_job",
            resource_id=str(job.id),
            outcome="success",
            metadata={"job_type": job.type, "handler": target, "reason": "handler module not available"},
        )
        return False
    try:
        handler(session, org_id, job)
    except Exception as exc:  # noqa: BLE001 — the result must survive a bad apply.
        audit_mod.write_audit(
            session,
            organization_id=org_id,
            actor_id=None,
            action=audit_mod.AGENT_JOB_RESULT_HANDLER_FAILED,
            resource_type="agent_job",
            resource_id=str(job.id),
            outcome="failure",
            metadata={"job_type": job.type, "handler": target, "error": str(exc)},
        )
        return False
    return True


def serialize_job_output(output) -> str | None:
    """Store a result ``output`` (dict/list/str) as text on the job row."""
    if output is None:
        return None
    if isinstance(output, str):
        return output
    return json.dumps(output)
