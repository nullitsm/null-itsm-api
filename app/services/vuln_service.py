"""Vulnerability management service (Phase 3).

Shared correlation path for every scan source — agent job results
(:func:`apply_vuln_scan_result`, called lazily by workstream A's
agent job-result endpoint), manual imports, and Greenbone report
polling (:func:`poll_greenbone_scan`). Findings come only from real
engine results plus real CVE/KEV catalog data; nothing here invents a
finding.

Key rules
---------
* ``scan_results`` rows are append-only raw evidence; the working set
  is ``vulnerability_findings`` (one open row per endpoint+CVE).
* Severity is enriched from ``cve_catalog`` only when the result
  severity is missing/unknown — a real engine severity is never
  overwritten by the catalog.
* A finding becomes ``verified`` only when a verification scan's
  results contain no row for its (endpoint, CVE).
* The CVE/KEV sync fetches BOTH feeds before writing anything, so a
  failed fetch leaves the catalog unchanged.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.endpoints import AgentJob, Endpoint
from app.models.patching import Patch
from app.models.ticket import Ticket
from app.models.vulnerabilities import (
    CveCatalog,
    RemediationTicket,
    ScanResult,
    VulnEngine,
    VulnerabilityFinding,
    VulnScan,
)
from app.services.greenbone import GreenboneClient, GreenboneError

logger = logging.getLogger("null.vuln")

UTC = timezone.utc

SEVERITIES = {"critical", "high", "medium", "low", "none"}
# Severities a result may carry that mean "no real severity was reported".
_GENERIC_SEVERITIES = {"", "unknown", "n/a", "na", "none"}
OPEN_FINDING_STATUSES = ("open", "in_progress")
KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# One bounded NVD page per run; full backfill is a scheduled job, not a
# single run (NVD paginates and rate-limits).
NVD_PAGE_SIZE = 2000


def _now() -> datetime:
    return datetime.now(UTC)


def normalize_severity(value: object) -> str | None:
    """Normalise a reported severity to a band, or None when unusable."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        from app.services.greenbone import severity_from_score

        return severity_from_score(float(value))
    text = str(value).strip().lower()
    if not text or text in _GENERIC_SEVERITIES:
        return None
    if text in SEVERITIES:
        return text
    try:
        from app.services.greenbone import severity_from_score

        return severity_from_score(float(text))
    except ValueError:
        return None


# --- Endpoint / catalog lookups ------------------------------------------


def resolve_endpoint(session: Session, org_id: uuid.UUID, host: str | None) -> Endpoint | None:
    """Match a scan host to an enrolled endpoint by hostname or IP.

    Hostnames are not unique (enrollment allows two machines to share one),
    so a host can match several endpoints: take the most recently seen one
    — the scan result most plausibly describes the live machine, and the
    choice is deterministic. When nothing matches, the finding stays
    host-only (``host_label``) rather than being dropped.
    """
    if not host:
        return None
    return session.execute(
        select(Endpoint)
        .where(
            Endpoint.organization_id == org_id,
            (Endpoint.hostname == host) | (Endpoint.ip_address == host),
        )
        .order_by(Endpoint.last_seen_at.desc().nulls_last(), Endpoint.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def catalog_severity(session: Session, cve_id: str | None) -> str | None:
    """Catalog severity for a CVE, or None when the CVE is unknown."""
    if not cve_id:
        return None
    row = session.execute(select(CveCatalog).where(CveCatalog.cve_id == cve_id)).scalar_one_or_none()
    return row.severity if row is not None else None


# --- Shared correlation path ---------------------------------------------


def correlate_scan_results(session: Session, org_id: uuid.UUID, scan: VulnScan, results: list[dict]) -> dict:
    """Store raw results and correlate them into findings.

    Used by agent job results, manual imports, and Greenbone polling —
    the logic lives here exactly once. Returns counts
    ``{results_applied, findings_created, findings_updated}``.
    """
    now = _now()
    results_applied = 0
    findings_created = 0
    findings_updated = 0
    for raw in results:
        if not isinstance(raw, dict):
            continue
        host = str(raw.get("host") or "").strip() or None
        cve_id = str(raw.get("cve_id") or "").strip().upper() or None
        reported_severity = normalize_severity(raw.get("severity"))
        severity = reported_severity or catalog_severity(session, cve_id) or "medium"
        endpoint = resolve_endpoint(session, org_id, host)
        session.add(
            ScanResult(
                organization_id=org_id,
                scan_id=scan.id,
                endpoint_id=endpoint.id if endpoint else None,
                host=host,
                cve_id=cve_id,
                plugin_name=(str(raw.get("plugin_name") or "").strip() or None),
                plugin_output=(str(raw.get("plugin_output") or "").strip() or None),
                severity=severity,
                detected_at=now,
            )
        )
        results_applied += 1
        if not cve_id:
            continue
        existing = _find_finding(session, org_id, endpoint.id if endpoint else None, cve_id)
        if existing is None:
            session.add(
                VulnerabilityFinding(
                    organization_id=org_id,
                    endpoint_id=endpoint.id if endpoint else None,
                    cve_id=cve_id,
                    severity=severity,
                    status="open",
                    first_seen_at=now,
                    last_seen_at=now,
                    scan_id=scan.id,
                )
            )
            findings_created += 1
            continue
        if existing.status in OPEN_FINDING_STATUSES:
            existing.last_seen_at = now
            existing.scan_id = scan.id
            if reported_severity or catalog_severity(session, cve_id):
                existing.severity = severity
            findings_updated += 1
        elif existing.status in ("remediated", "verified"):
            # The CVE is back: reopen as a new occurrence.
            existing.status = "open"
            existing.last_seen_at = now
            existing.scan_id = scan.id
            existing.severity = severity
            existing.verified_at = None
            existing.verification_scan_id = None
            findings_updated += 1
        else:  # false_positive / accepted_risk: record the sighting only.
            existing.last_seen_at = now
            findings_updated += 1
    session.flush()
    return {
        "results_applied": results_applied,
        "findings_created": findings_created,
        "findings_updated": findings_updated,
    }


def _find_finding(
    session: Session, org_id: uuid.UUID, endpoint_id: uuid.UUID | None, cve_id: str
) -> VulnerabilityFinding | None:
    """The working finding for (endpoint, CVE), if one exists.

    The partial unique index covers open/in_progress rows only, and
    NULL endpoint ids are distinct under a unique index, so the lookup
    is done in application code. Preference order: an open/in_progress
    row, else a remediated/verified row (re-detection reopens it),
    else the most recent false_positive/accepted_risk row.
    """
    query = select(VulnerabilityFinding).where(
        VulnerabilityFinding.organization_id == org_id,
        VulnerabilityFinding.cve_id == cve_id,
    )
    if endpoint_id is None:
        query = query.where(VulnerabilityFinding.endpoint_id.is_(None))
    else:
        query = query.where(VulnerabilityFinding.endpoint_id == endpoint_id)
    rows = session.execute(query.order_by(VulnerabilityFinding.created_at)).scalars().all()
    for status_group in (OPEN_FINDING_STATUSES, ("remediated", "verified"), ("false_positive", "accepted_risk")):
        for row in rows:
            if row.status in status_group:
                return row
    return None


def apply_verification(session: Session, org_id: uuid.UUID, scan: VulnScan) -> int:
    """Verify remediated findings whose CVE is absent from this scan.

    A finding with ``verification_scan_id == scan.id`` and status
    ``remediated`` flips to ``verified`` when no result in this scan
    names its (endpoint, CVE); its remediation link rows flip too.
    Returns the number of findings verified.
    """
    now = _now()
    present: set[tuple[uuid.UUID | None, str]] = set()
    rows = session.execute(
        select(ScanResult.endpoint_id, ScanResult.cve_id).where(
            ScanResult.organization_id == org_id,
            ScanResult.scan_id == scan.id,
            ScanResult.cve_id.is_not(None),
        )
    ).all()
    for endpoint_id, cve_id in rows:
        present.add((endpoint_id, cve_id))
    candidates = session.execute(
        select(VulnerabilityFinding).where(
            VulnerabilityFinding.organization_id == org_id,
            VulnerabilityFinding.verification_scan_id == scan.id,
            VulnerabilityFinding.status == "remediated",
        )
    ).scalars()
    verified = 0
    for finding in candidates:
        if (finding.endpoint_id, finding.cve_id) in present:
            continue
        finding.status = "verified"
        finding.verified_at = now
        links = session.execute(
            select(RemediationTicket).where(
                RemediationTicket.organization_id == org_id,
                RemediationTicket.finding_id == finding.id,
                RemediationTicket.status.in_(("open", "in_progress", "remediated")),
            )
        ).scalars()
        for link in links:
            link.status = "verified"
            link.verification_scan_id = scan.id
        verified += 1
    session.flush()
    return verified


# --- Agent job-result contract (workstream A) ------------------------------


def apply_vuln_scan_result(session: Session, org_id: uuid.UUID, job: AgentJob) -> dict:
    """Apply an agent ``vuln_scan`` job result (workstream A contract).

    ``session`` is already RLS-scoped to the job's org. ``job.output``
    is JSON: ``{"results": [{host, cve_id?, plugin_name?,
    plugin_output?, severity}]}``. Idempotent: a ``VulnScan`` whose
    ``engine_scan_id`` is ``f"agent-job:{job.id}"`` means this job was
    already applied. Malformed output returns an error dict and leaves
    state unchanged — it never raises into the agent result call.

    Verification hook: when the issued job's payload carries
    ``verify_finding_id``, the scan is linked as that finding's
    verification scan (only when the finding is ``remediated`` and has
    no verification scan yet — the verify endpoint marks it remediated
    when it issues the job). ``apply_verification`` below then flips it
    to ``verified`` when the CVE is absent from this scan's results, or
    the correlation step reopens it when the CVE is still present.
    """
    marker = f"agent-job:{job.id}"
    existing_scan = session.execute(
        select(VulnScan).where(VulnScan.organization_id == org_id, VulnScan.engine_scan_id == marker)
    ).scalar_one_or_none()
    if existing_scan is not None:
        return {
            "status": "already_applied",
            "scan_id": str(existing_scan.id),
            "results_applied": 0,
            "findings_created": 0,
            "findings_updated": 0,
            "verified": 0,
        }
    try:
        payload = job.output
        if isinstance(payload, str):
            payload = json.loads(payload)
        if not isinstance(payload, dict):
            raise ValueError("job output is not a JSON object")
        results = payload.get("results")
        if not isinstance(results, list):
            raise ValueError("job output has no 'results' list")
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        logger.warning("Ignoring malformed vuln_scan output for job %s: %s", job.id, exc)
        return {
            "status": "error",
            "error": f"malformed job output: {exc}",
            "results_applied": 0,
            "findings_created": 0,
            "findings_updated": 0,
            "verified": 0,
        }
    now = _now()
    scan = VulnScan(
        organization_id=org_id,
        engine_id=None,
        engine_scan_id=marker,
        name=f"Agent vulnerability scan ({job.id})",
        target=None,
        status="completed",
        started_at=now,
        finished_at=now,
        result_count=len(results),
    )
    session.add(scan)
    session.flush()
    # Verification hook (see docstring): link this scan to the finding
    # the job was issued to verify, so apply_verification below can
    # judge it. A finding that is not remediated (or already has a
    # verification scan) is left alone.
    verify_finding_id = (job.payload or {}).get("verify_finding_id") if isinstance(job.payload, dict) else None
    if verify_finding_id:
        try:
            verify_finding_uuid = uuid.UUID(str(verify_finding_id))
        except (ValueError, TypeError):
            verify_finding_uuid = None
        if verify_finding_uuid is not None:
            verify_finding = session.execute(
                select(VulnerabilityFinding).where(
                    VulnerabilityFinding.organization_id == org_id,
                    VulnerabilityFinding.id == verify_finding_uuid,
                )
            ).scalar_one_or_none()
            if (
                verify_finding is not None
                and verify_finding.status == "remediated"
                and verify_finding.verification_scan_id is None
            ):
                verify_finding.verification_scan_id = scan.id
    counts = correlate_scan_results(session, org_id, scan, results)
    verified = apply_verification(session, org_id, scan)
    session.flush()
    return {
        "status": "ok",
        "scan_id": str(scan.id),
        "results_applied": counts["results_applied"],
        "findings_created": counts["findings_created"],
        "findings_updated": counts["findings_updated"],
        "verified": verified,
    }


# --- Greenbone ------------------------------------------------------------


def get_engine_client(engine: VulnEngine) -> GreenboneClient:
    """Build the driver client for a configured engine.

    Raises ValueError for manual engines (no driver) and GreenboneError
    when the engine has no host. The stored password is Fernet-decrypted
    (lazy import — crypto fails closed with no field key configured).
    """
    if engine.engine_type == "manual":
        raise ValueError("manual engines accept imported results only")
    if engine.engine_type not in ("greenbone", "openvas"):
        raise ValueError(f"unsupported engine type: {engine.engine_type}")
    if not engine.host:
        raise GreenboneError("engine unreachable: no host configured")
    password = None
    if engine.password_encrypted:
        from app.crypto import decrypt

        password = decrypt(engine.password_encrypted)
    return GreenboneClient(
        host=engine.host,
        port=engine.port or 9390,
        username=engine.username,
        password=password,
    )


def poll_greenbone_scan(session: Session, org_id: uuid.UUID, scan: VulnScan) -> dict:
    """Poll one engine scan: import its report when the task is done.

    Returns ``{"status": <scan status>, "report_id": ...}`` plus the
    correlation counts when a report was imported. Raises
    GreenboneError when the engine cannot be reached (the scan row is
    left untouched — the next poll retries honestly).
    """
    engine = session.get(VulnEngine, scan.engine_id) if scan.engine_id else None
    if engine is None:
        raise GreenboneError("no engine configured for this scan")
    client = get_engine_client(engine)
    try:
        with client:
            task_status = client.get_task_status(scan.engine_scan_id or "")
            status = task_status.get("status") or "Unknown"
            report_id = task_status.get("report_id")
            if status not in ("Done", "Stopped", "Stop Requested"):
                return {"status": "running", "engine_status": status, "report_id": report_id}
            if not report_id:
                scan.status = "failed"
                scan.finished_at = _now()
                session.flush()
                return {"status": "failed", "engine_status": status, "report_id": None}
            results = client.get_report(report_id)
    except GreenboneError:
        raise
    counts = correlate_scan_results(session, org_id, scan, results)
    verified = apply_verification(session, org_id, scan)
    scan.status = "completed"
    scan.finished_at = _now()
    scan.result_count = counts["results_applied"]
    session.flush()
    return {
        "status": "completed",
        "engine_status": status,
        "report_id": report_id,
        **counts,
        "verified": verified,
    }


# --- Remediation ------------------------------------------------------------


_SEVERITY_PRIORITY = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "none": "low"}


def create_remediation_ticket(
    session: Session,
    org_id: uuid.UUID,
    finding: VulnerabilityFinding,
    actor_id: uuid.UUID | None,
    patch_id: uuid.UUID | None = None,
) -> tuple[Ticket, RemediationTicket]:
    """Create a REAL ticket for a finding and link it (caller commits).

    Reuses the existing ticket numbering (``routers.tickets``) and SLA
    stamping (``sla_service``) — ticket creation is not duplicated here.
    The finding flips to ``in_progress``.
    """
    from app.routers.tickets import _next_number as _next_ticket_number
    from app.services import sla_service

    if patch_id is not None:
        patch = session.get(Patch, patch_id)
        if patch is None or patch.organization_id != org_id:
            raise ValueError("Patch not found")
    host_label = None
    if finding.endpoint_id is not None:
        endpoint = session.get(Endpoint, finding.endpoint_id)
        host_label = endpoint.hostname if endpoint else None
    host_label = host_label or "unenrolled host"
    ticket = Ticket(
        organization_id=org_id,
        number=_next_ticket_number(session, org_id),
        title=f"Remediate {finding.cve_id} on {host_label}",
        description=(
            f"Vulnerability {finding.cve_id} (severity {finding.severity}) detected on {host_label}. "
            "Remediate the vulnerability and run a verification scan to confirm it is gone."
        ),
        priority=_SEVERITY_PRIORITY.get(finding.severity, "medium"),
        category="Vulnerability",
        requester_id=actor_id,
        status="open",
    )
    session.add(ticket)
    session.flush()
    sla_service.stamp_sla_state(session, org_id, ticket)
    link = RemediationTicket(
        organization_id=org_id,
        finding_id=finding.id,
        ticket_id=ticket.id,
        patch_id=patch_id,
        status="open",
    )
    session.add(link)
    finding.status = "in_progress"
    finding.remediation_ticket_id = ticket.id
    finding.remediation_patch_id = patch_id
    session.flush()
    return ticket, link


# --- CVE / KEV sync ----------------------------------------------------------


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    try:
        if len(text) == 10:  # KEV YYYY-MM-DD
            return datetime.strptime(text, "%Y-%m-%d").replace(tzinfo=UTC)
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def _cvss_from_nvd(metrics: dict) -> tuple[float | None, str | None, str | None]:
    """Best CVSS (v3.1 > v3.0 > v2.0) from an NVD metrics block."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV20"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData") or {}
            score = data.get("baseScore")
            return (
                float(score) if score is not None else None,
                data.get("vectorString"),
                (data.get("baseSeverity") or "").lower() or None,
            )
    return None, None, None


def sync_cve_kev(session: Session, transport=None) -> dict:
    """Sync the CISA KEV feed (full) + NVD (one bounded page).

    ``session`` needs no RLS context: ``cve_catalog`` is global. Both
    feeds are fetched BEFORE anything is written, so a fetch failure
    leaves the catalog unchanged (the exception propagates to the
    caller, which logs it). ``transport`` is an injectable
    ``httpx.BaseTransport`` for tests — never a live fetch in tests.
    """
    import httpx

    with httpx.Client(timeout=30.0, transport=transport) as client:
        kev_resp = client.get(KEV_FEED_URL)
        kev_resp.raise_for_status()
        kev_data = kev_resp.json()
        nvd_resp = client.get(
            NVD_API_URL,
            params={"resultsPerPage": NVD_PAGE_SIZE, "startIndex": 0},
        )
        nvd_resp.raise_for_status()
        nvd_data = nvd_resp.json()

    kev_created = kev_updated = 0
    for item in kev_data.get("vulnerabilities") or []:
        cve_id = str(item.get("cveID") or "").strip().upper()
        if not cve_id:
            continue
        row = session.execute(select(CveCatalog).where(CveCatalog.cve_id == cve_id)).scalar_one_or_none()
        fields = {
            "kev": True,
            "kev_added_date": _parse_date(item.get("dateAdded")),
            "kev_due_date": _parse_date(item.get("dueDate")),
            "kev_vendor": item.get("vendorProject"),
            "kev_product": item.get("product"),
            "kev_description": item.get("shortDescription"),
            "kev_ransomware_use": str(item.get("knownRansomwareCampaignUse") or "").lower() == "known",
        }
        if row is None:
            row = CveCatalog(cve_id=cve_id, description=item.get("shortDescription"), references=[])
            session.add(row)
            kev_created += 1
        else:
            kev_updated += 1
            if not row.description:
                row.description = item.get("shortDescription")
        for key, value in fields.items():
            setattr(row, key, value)
    session.flush()

    nvd_created = nvd_updated = 0
    for entry in nvd_data.get("vulnerabilities") or []:
        cve = entry.get("cve") or {}
        cve_id = str(cve.get("id") or "").strip().upper()
        if not cve_id:
            continue
        description = None
        for desc in cve.get("descriptions") or []:
            if desc.get("lang") == "en":
                description = desc.get("value")
                break
        score, vector, severity = _cvss_from_nvd(cve.get("metrics") or {})
        references = [ref.get("url") for ref in cve.get("references") or [] if ref.get("url")]
        row = session.execute(select(CveCatalog).where(CveCatalog.cve_id == cve_id)).scalar_one_or_none()
        if row is None:
            row = CveCatalog(cve_id=cve_id, references=references)
            session.add(row)
            nvd_created += 1
        else:
            nvd_updated += 1
        row.description = description or row.description
        row.cvss_score = score if score is not None else row.cvss_score
        row.cvss_vector = vector or row.cvss_vector
        row.severity = severity or row.severity
        row.published_date = _parse_date(cve.get("published")) or row.published_date
        row.last_modified_date = _parse_date(cve.get("lastModified")) or row.last_modified_date
        row.references = references or row.references
    session.flush()
    return {
        "kev_created": kev_created,
        "kev_updated": kev_updated,
        "nvd_created": nvd_created,
        "nvd_updated": nvd_updated,
        "nvd_page_size": NVD_PAGE_SIZE,
        "note": "NVD sync covers one bounded page per run; full backfill is a scheduled job, not a single run.",
    }


def vuln_summary(session: Session, org_id: uuid.UUID) -> dict:
    """Counts by severity and status + open KEV count, derived live."""
    by_severity = {
        row[0]: row[1]
        for row in session.execute(
            select(VulnerabilityFinding.severity, func.count())
            .where(VulnerabilityFinding.organization_id == org_id)
            .group_by(VulnerabilityFinding.severity)
        ).all()
    }
    by_status = {
        row[0]: row[1]
        for row in session.execute(
            select(VulnerabilityFinding.status, func.count())
            .where(VulnerabilityFinding.organization_id == org_id)
            .group_by(VulnerabilityFinding.status)
        ).all()
    }
    open_kev = session.execute(
        select(func.count())
        .select_from(VulnerabilityFinding)
        .join(CveCatalog, CveCatalog.cve_id == VulnerabilityFinding.cve_id)
        .where(
            VulnerabilityFinding.organization_id == org_id,
            VulnerabilityFinding.status.in_(OPEN_FINDING_STATUSES),
            CveCatalog.kev.is_(True),
        )
    ).scalar_one()
    return {
        "by_severity": by_severity,
        "by_status": by_status,
        "open_kev": open_kev,
        "total_open": sum(by_status.get(s, 0) for s in OPEN_FINDING_STATUSES),
    }
