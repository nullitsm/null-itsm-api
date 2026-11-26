"""Vulnerability routes: engines, CVE catalog, scans, findings,
remediation, summary.

Permissions: ``vulnerabilities:read`` / ``vulnerabilities:manage`` /
``vulnerabilities:remediate``. Cross-org ids are 404, never 403.
Engine passwords are Fernet-encrypted and never returned.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.audit import (
    AGENT_JOB_ISSUED,
    VULN_ENGINE_CREATED,
    VULN_ENGINE_DEFAULT_SET,
    VULN_ENGINE_DELETED,
    VULN_ENGINE_UPDATED,
    VULN_FINDING_UPDATED,
    VULN_FINDING_VERIFICATION_STARTED,
    VULN_REMEDIATION_CREATED,
    VULN_SCAN_CANCELLED,
    VULN_SCAN_CREATED,
    VULN_SCAN_POLLED,
    VULN_SCAN_RESULTS_IMPORTED,
)
from app.deps import Principal, get_db, require_permission
from app.models.endpoints import Endpoint
from app.models.ticket import Ticket
from app.models.vulnerabilities import (
    CveCatalog,
    RemediationTicket,
    ScanResult,
    VulnEngine,
    VulnerabilityFinding,
    VulnScan,
)
from app.services import endpoint_service, vuln_service
from app.services.greenbone import GreenboneError
from app.services.identity_service import SecretStorageError, encrypt_secret

UTC = timezone.utc

router = APIRouter(prefix="/api/v1/vulnerabilities", tags=["vulnerabilities"])

ENGINE_TYPES = {"greenbone", "openvas", "manual"}
ENGINE_STATUSES = {"active", "inactive", "error"}
FINDING_PATCHABLE_STATUSES = {"open", "in_progress", "false_positive", "accepted_risk"}


# --- Schemas (local: app/schemas.py belongs to another workstream) --------


class EngineCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    engine_type: str
    host: str | None = None
    port: int | None = None
    username: str | None = None
    password: str | None = None
    is_default: bool = False


class EngineUpdate(BaseModel):
    name: str | None = None
    host: str | None = None
    port: int | None = None
    username: str | None = None
    password: str | None = None
    status: str | None = None
    is_default: bool | None = None


class EngineOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    engine_type: str
    host: str | None
    port: int | None
    username: str | None
    has_password: bool
    is_default: bool
    status: str
    last_sync_at: datetime | None
    last_error: str | None
    created_at: datetime
    updated_at: datetime


class CveOut(BaseModel):
    cve_id: str
    description: str | None
    cvss_score: float | None
    cvss_vector: str | None
    severity: str | None
    published_date: datetime | None
    last_modified_date: datetime | None
    kev: bool
    kev_added_date: datetime | None
    kev_due_date: datetime | None
    kev_vendor: str | None
    kev_product: str | None
    kev_description: str | None
    kev_ransomware_use: bool
    references: list


class ScanResultIn(BaseModel):
    host: str | None = None
    cve_id: str | None = None
    plugin_name: str | None = None
    plugin_output: str | None = None
    severity: str | None = None


class ScanCreate(BaseModel):
    engine_id: uuid.UUID | None = None
    name: str = Field(min_length=1, max_length=255)
    target: str | None = None


class ScanResultOut(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    endpoint_id: uuid.UUID | None
    host: str | None
    cve_id: str | None
    plugin_name: str | None
    plugin_output: str | None
    severity: str
    detected_at: datetime | None
    created_at: datetime


class ScanOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    engine_id: uuid.UUID | None
    engine_scan_id: str | None
    name: str
    target: str | None
    status: str
    started_at: datetime | None
    finished_at: datetime | None
    result_count: int
    created_at: datetime
    updated_at: datetime
    results: list[ScanResultOut] | None = None


class ImportResultsIn(BaseModel):
    results: list[ScanResultIn]


class FindingUpdate(BaseModel):
    status: str


class RemediateIn(BaseModel):
    patch_id: uuid.UUID | None = None


class RemediationOut(BaseModel):
    id: uuid.UUID
    finding_id: uuid.UUID
    ticket_id: uuid.UUID
    ticket_number: str
    patch_id: uuid.UUID | None
    status: str
    created_at: datetime


class FindingOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    endpoint_id: uuid.UUID | None
    cve_id: str
    severity: str
    status: str
    first_seen_at: datetime | None
    last_seen_at: datetime | None
    scan_id: uuid.UUID | None
    remediation_ticket_id: uuid.UUID | None
    remediation_patch_id: uuid.UUID | None
    verified_at: datetime | None
    verification_scan_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime
    catalog: CveOut | None = None
    remediation: list[RemediationOut] = []


# --- Helpers ----------------------------------------------------------------


def _engine_out(e: VulnEngine) -> EngineOut:
    return EngineOut(
        id=e.id,
        organization_id=e.organization_id,
        name=e.name,
        engine_type=e.engine_type,
        host=e.host,
        port=e.port,
        username=e.username,
        has_password=bool(e.password_encrypted),
        is_default=e.is_default,
        status=e.status,
        last_sync_at=e.last_sync_at,
        last_error=e.last_error,
        created_at=e.created_at,
        updated_at=e.updated_at,
    )


def _get_engine(session: Session, org_id: uuid.UUID, engine_id: uuid.UUID) -> VulnEngine:
    engine = session.get(VulnEngine, engine_id)
    if engine is None or engine.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Engine not found")
    return engine


def _cve_out(row: CveCatalog) -> CveOut:
    return CveOut(
        cve_id=row.cve_id,
        description=row.description,
        cvss_score=float(row.cvss_score) if row.cvss_score is not None else None,
        cvss_vector=row.cvss_vector,
        severity=row.severity,
        published_date=row.published_date,
        last_modified_date=row.last_modified_date,
        kev=row.kev,
        kev_added_date=row.kev_added_date,
        kev_due_date=row.kev_due_date,
        kev_vendor=row.kev_vendor,
        kev_product=row.kev_product,
        kev_description=row.kev_description,
        kev_ransomware_use=row.kev_ransomware_use,
        references=row.references or [],
    )


def _scan_result_out(r: ScanResult) -> ScanResultOut:
    return ScanResultOut(
        id=r.id,
        scan_id=r.scan_id,
        endpoint_id=r.endpoint_id,
        host=r.host,
        cve_id=r.cve_id,
        plugin_name=r.plugin_name,
        plugin_output=r.plugin_output,
        severity=r.severity,
        detected_at=r.detected_at,
        created_at=r.created_at,
    )


def _scan_out(scan: VulnScan, results: list[ScanResult] | None = None) -> ScanOut:
    return ScanOut(
        id=scan.id,
        organization_id=scan.organization_id,
        engine_id=scan.engine_id,
        engine_scan_id=scan.engine_scan_id,
        name=scan.name,
        target=scan.target,
        status=scan.status,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        result_count=scan.result_count,
        created_at=scan.created_at,
        updated_at=scan.updated_at,
        results=[_scan_result_out(r) for r in results] if results is not None else None,
    )


def _scan_results(session: Session, scan_id: uuid.UUID) -> list[ScanResult]:
    return (
        session.execute(select(ScanResult).where(ScanResult.scan_id == scan_id).order_by(ScanResult.created_at))
        .scalars()
        .all()
    )


def _remediation_out(session: Session, link: RemediationTicket) -> RemediationOut:
    ticket = session.get(Ticket, link.ticket_id)
    return RemediationOut(
        id=link.id,
        finding_id=link.finding_id,
        ticket_id=link.ticket_id,
        ticket_number=ticket.number if ticket else "",
        patch_id=link.patch_id,
        status=link.status,
        created_at=link.created_at,
    )


def _finding_out(session: Session, f: VulnerabilityFinding) -> FindingOut:
    catalog = session.execute(select(CveCatalog).where(CveCatalog.cve_id == f.cve_id)).scalar_one_or_none()
    links = (
        session.execute(
            select(RemediationTicket).where(RemediationTicket.finding_id == f.id).order_by(RemediationTicket.created_at)
        )
        .scalars()
        .all()
    )
    return FindingOut(
        id=f.id,
        organization_id=f.organization_id,
        endpoint_id=f.endpoint_id,
        cve_id=f.cve_id,
        severity=f.severity,
        status=f.status,
        first_seen_at=f.first_seen_at,
        last_seen_at=f.last_seen_at,
        scan_id=f.scan_id,
        remediation_ticket_id=f.remediation_ticket_id,
        remediation_patch_id=f.remediation_patch_id,
        verified_at=f.verified_at,
        verification_scan_id=f.verification_scan_id,
        created_at=f.created_at,
        updated_at=f.updated_at,
        catalog=_cve_out(catalog) if catalog else None,
        remediation=[_remediation_out(session, link) for link in links],
    )


def _get_finding(session: Session, org_id: uuid.UUID, finding_id: uuid.UUID) -> VulnerabilityFinding:
    finding = session.get(VulnerabilityFinding, finding_id)
    if finding is None or finding.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return finding


def _get_scan(session: Session, org_id: uuid.UUID, scan_id: uuid.UUID) -> VulnScan:
    scan = session.get(VulnScan, scan_id)
    if scan is None or scan.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan


def _encrypt_password(password: str | None) -> str | None:
    if password is None:
        return None
    try:
        return encrypt_secret(password)
    except SecretStorageError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc))


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


# --- Engines ----------------------------------------------------------------


@router.get("/engines", response_model=list[EngineOut])
def list_engines(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("vulnerabilities:read"))
):
    rows = (
        session.execute(
            select(VulnEngine)
            .where(VulnEngine.organization_id == principal.organization_id)
            .order_by(VulnEngine.created_at)
        )
        .scalars()
        .all()
    )
    return [_engine_out(e) for e in rows]


@router.post("/engines", response_model=EngineOut, status_code=status.HTTP_201_CREATED)
def create_engine(
    body: EngineCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("vulnerabilities:manage")),
):
    if body.engine_type not in ENGINE_TYPES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid engine type")
    encrypted = _encrypt_password(body.password)
    if body.is_default:
        others = session.execute(
            select(VulnEngine).where(
                VulnEngine.organization_id == principal.organization_id, VulnEngine.is_default.is_(True)
            )
        ).scalars()
        for other in others:
            other.is_default = False
    engine = VulnEngine(
        organization_id=principal.organization_id,
        name=body.name,
        engine_type=body.engine_type,
        host=body.host,
        port=body.port,
        username=body.username,
        password_encrypted=encrypted,
        is_default=body.is_default,
        created_by_id=principal.user_id,
    )
    session.add(engine)
    session.flush()
    _audit(session, principal, VULN_ENGINE_CREATED, "vuln_engine", str(engine.id), {"name": body.name})
    out = _engine_out(engine)
    session.commit()
    return out


@router.get("/engines/{engine_id}", response_model=EngineOut)
def get_engine(
    engine_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("vulnerabilities:read")),
):
    return _engine_out(_get_engine(session, principal.organization_id, engine_id))


@router.patch("/engines/{engine_id}", response_model=EngineOut)
def update_engine(
    engine_id: uuid.UUID,
    body: EngineUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("vulnerabilities:manage")),
):
    engine = _get_engine(session, principal.organization_id, engine_id)
    if body.name is not None:
        engine.name = body.name
    if body.host is not None:
        engine.host = body.host
    if body.port is not None:
        engine.port = body.port
    if body.username is not None:
        engine.username = body.username
    if body.password is not None:
        engine.password_encrypted = _encrypt_password(body.password)
    if body.status is not None:
        if body.status not in ENGINE_STATUSES:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid engine status")
        engine.status = body.status
    if body.is_default is True:
        others = session.execute(
            select(VulnEngine).where(
                VulnEngine.organization_id == principal.organization_id,
                VulnEngine.is_default.is_(True),
                VulnEngine.id != engine.id,
            )
        ).scalars()
        for other in others:
            other.is_default = False
        engine.is_default = True
    elif body.is_default is False:
        engine.is_default = False
    session.flush()
    _audit(session, principal, VULN_ENGINE_UPDATED, "vuln_engine", str(engine.id), {"name": engine.name})
    out = _engine_out(engine)
    session.commit()
    return out


@router.delete("/engines/{engine_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_engine(
    engine_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("vulnerabilities:manage")),
):
    engine = _get_engine(session, principal.organization_id, engine_id)
    was_default = engine.is_default
    session.delete(engine)
    session.flush()
    if was_default:
        nxt = session.execute(
            select(VulnEngine)
            .where(VulnEngine.organization_id == principal.organization_id)
            .order_by(VulnEngine.created_at)
            .limit(1)
        ).scalar_one_or_none()
        if nxt is not None:
            nxt.is_default = True
    _audit(session, principal, VULN_ENGINE_DELETED, "vuln_engine", str(engine.id), {"name": engine.name})
    session.commit()
    return None


@router.post("/engines/{engine_id}/set-default", response_model=EngineOut)
def set_default_engine(
    engine_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("vulnerabilities:manage")),
):
    engine = _get_engine(session, principal.organization_id, engine_id)
    others = session.execute(
        select(VulnEngine).where(
            VulnEngine.organization_id == principal.organization_id,
            VulnEngine.is_default.is_(True),
            VulnEngine.id != engine.id,
        )
    ).scalars()
    for other in others:
        other.is_default = False
    engine.is_default = True
    session.flush()
    _audit(session, principal, VULN_ENGINE_DEFAULT_SET, "vuln_engine", str(engine.id), {"name": engine.name})
    out = _engine_out(engine)
    session.commit()
    return out


# --- CVE catalog ------------------------------------------------------------


@router.get("/cves", response_model=list[CveOut])
def list_cves(
    cve_id: str | None = None,
    severity: str | None = None,
    kev: bool | None = None,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("vulnerabilities:read")),
):
    query = select(CveCatalog)
    if cve_id:
        query = query.where(CveCatalog.cve_id.ilike(f"%{cve_id.strip().upper()}%"))
    if severity:
        if severity not in vuln_service.SEVERITIES:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid severity")
        query = query.where(CveCatalog.severity == severity)
    if kev is not None:
        query = query.where(CveCatalog.kev.is_(kev))
    rows = session.execute(query.order_by(CveCatalog.cve_id)).scalars().all()
    return [_cve_out(r) for r in rows]


@router.get("/cves/{cve_id}", response_model=CveOut)
def get_cve(
    cve_id: str,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("vulnerabilities:read")),
):
    row = session.execute(select(CveCatalog).where(CveCatalog.cve_id == cve_id.strip().upper())).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="CVE not found")
    return _cve_out(row)


# --- Scans ------------------------------------------------------------------


@router.get("/scans", response_model=list[ScanOut])
def list_scans(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("vulnerabilities:read"))
):
    rows = (
        session.execute(
            select(VulnScan)
            .where(VulnScan.organization_id == principal.organization_id)
            .order_by(VulnScan.created_at.desc())
        )
        .scalars()
        .all()
    )
    return [_scan_out(s) for s in rows]


@router.post("/scans", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
def create_scan(
    body: ScanCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("vulnerabilities:manage")),
):
    if body.engine_id is not None:
        engine = _get_engine(session, principal.organization_id, body.engine_id)
    else:
        engine = session.execute(
            select(VulnEngine)
            .where(VulnEngine.organization_id == principal.organization_id)
            .order_by(VulnEngine.is_default.desc(), VulnEngine.created_at)
        ).scalar_one_or_none()
    if engine is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="no engine configured")
    now = datetime.now(UTC)
    scan = VulnScan(
        organization_id=principal.organization_id,
        engine_id=engine.id,
        name=body.name,
        target=body.target,
        status="queued",
        created_by_id=principal.user_id,
    )
    if engine.engine_type == "manual":
        session.add(scan)
        session.flush()
        _audit(session, principal, VULN_SCAN_CREATED, "vuln_scan", str(scan.id), {"name": body.name})
        out = _scan_out(scan)
        session.commit()
        return out
    try:
        client = vuln_service.get_engine_client(engine)
        with client:
            target_id = client.create_target(body.name, body.target or "")
            task_id = client.create_task(body.name, target_id)
            client.start_task(task_id)
    except GreenboneError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"engine unreachable: {exc}")
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    scan.engine_scan_id = task_id
    scan.status = "running"
    scan.started_at = now
    session.add(scan)
    session.flush()
    _audit(session, principal, VULN_SCAN_CREATED, "vuln_scan", str(scan.id), {"name": body.name})
    out = _scan_out(scan)
    session.commit()
    return out


@router.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(
    scan_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("vulnerabilities:read")),
):
    scan = _get_scan(session, principal.organization_id, scan_id)
    return _scan_out(scan, _scan_results(session, scan.id))


@router.post("/scans/{scan_id}/import-results", response_model=dict)
def import_scan_results(
    scan_id: uuid.UUID,
    body: ImportResultsIn,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("vulnerabilities:manage")),
):
    scan = _get_scan(session, principal.organization_id, scan_id)
    engine = session.get(VulnEngine, scan.engine_id) if scan.engine_id else None
    # A queued verification scan (created by POST .../findings/{id}/verify for
    # an unenrolled endpoint, engine_id None) exists precisely to receive an
    # operator-imported rescan: its results are the verification evidence.
    is_verification_scan = (
        session.execute(
            select(VulnerabilityFinding).where(VulnerabilityFinding.verification_scan_id == scan.id).limit(1)
        ).scalar_one_or_none()
        is not None
    )
    if (engine is None or engine.engine_type != "manual") and not is_verification_scan:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Results can only be imported into manual-engine scans"
        )
    if scan.status in ("completed", "cancelled", "failed"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Scan is already {scan.status}")
    counts = vuln_service.correlate_scan_results(
        session, principal.organization_id, scan, [r.model_dump() for r in body.results]
    )
    verified = vuln_service.apply_verification(session, principal.organization_id, scan)
    scan.status = "completed"
    scan.finished_at = datetime.now(UTC)
    scan.result_count = counts["results_applied"]
    session.flush()
    _audit(session, principal, VULN_SCAN_RESULTS_IMPORTED, "vuln_scan", str(scan.id), counts)
    out = {"scan_id": str(scan.id), "status": scan.status, **counts, "verified": verified}
    session.commit()
    return out


@router.post("/scans/{scan_id}/poll", response_model=dict)
def poll_scan(
    scan_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("vulnerabilities:manage")),
):
    scan = _get_scan(session, principal.organization_id, scan_id)
    if scan.status in ("completed", "cancelled", "failed"):
        return {"scan_id": str(scan.id), "status": scan.status}
    if scan.engine_scan_id is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scan has no engine task to poll")
    try:
        result = vuln_service.poll_greenbone_scan(session, principal.organization_id, scan)
    except GreenboneError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"engine unreachable: {exc}")
    session.flush()
    _audit(session, principal, VULN_SCAN_POLLED, "vuln_scan", str(scan.id), {"status": result.get("status")})
    out = {"scan_id": str(scan.id), **result}
    session.commit()
    return out


@router.post("/scans/{scan_id}/cancel", response_model=ScanOut)
def cancel_scan(
    scan_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("vulnerabilities:manage")),
):
    scan = _get_scan(session, principal.organization_id, scan_id)
    if scan.status not in ("queued", "running"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Cannot cancel a {scan.status} scan")
    scan.status = "cancelled"
    scan.finished_at = datetime.now(UTC)
    session.flush()
    _audit(session, principal, VULN_SCAN_CANCELLED, "vuln_scan", str(scan.id), {"name": scan.name})
    out = _scan_out(scan)
    session.commit()
    return out


# --- Findings ---------------------------------------------------------------


@router.get("/summary", response_model=dict)
def get_summary(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("vulnerabilities:read"))
):
    return vuln_service.vuln_summary(session, principal.organization_id)


@router.get("/findings", response_model=list[FindingOut])
def list_findings(
    endpoint_id: uuid.UUID | None = None,
    severity: str | None = None,
    status: str | None = None,
    kev: bool | None = None,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("vulnerabilities:read")),
):
    query = select(VulnerabilityFinding).where(VulnerabilityFinding.organization_id == principal.organization_id)
    if endpoint_id is not None:
        query = query.where(VulnerabilityFinding.endpoint_id == endpoint_id)
    if severity is not None:
        if severity not in vuln_service.SEVERITIES:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid severity")
        query = query.where(VulnerabilityFinding.severity == severity)
    if status is not None:
        query = query.where(VulnerabilityFinding.status == status)
    if kev is not None:
        query = query.join(CveCatalog, CveCatalog.cve_id == VulnerabilityFinding.cve_id).where(CveCatalog.kev.is_(kev))
    rows = session.execute(query.order_by(VulnerabilityFinding.created_at.desc())).scalars().all()
    return [_finding_out(session, f) for f in rows]


@router.get("/findings/{finding_id}", response_model=FindingOut)
def get_finding(
    finding_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("vulnerabilities:read")),
):
    return _finding_out(session, _get_finding(session, principal.organization_id, finding_id))


@router.patch("/findings/{finding_id}", response_model=FindingOut)
def update_finding(
    finding_id: uuid.UUID,
    body: FindingUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("vulnerabilities:manage")),
):
    finding = _get_finding(session, principal.organization_id, finding_id)
    if body.status not in FINDING_PATCHABLE_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Status can only be set to open, in_progress, false_positive, or accepted_risk "
            "(remediated/verified are set only by the verification flow)",
        )
    finding.status = body.status
    session.flush()
    _audit(
        session,
        principal,
        VULN_FINDING_UPDATED,
        "vulnerability_finding",
        str(finding.id),
        {"cve_id": finding.cve_id, "status": body.status},
    )
    out = _finding_out(session, finding)
    session.commit()
    return out


@router.post("/findings/{finding_id}/remediate", response_model=RemediationOut, status_code=status.HTTP_201_CREATED)
def remediate_finding(
    finding_id: uuid.UUID,
    body: RemediateIn,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("vulnerabilities:remediate")),
):
    finding = _get_finding(session, principal.organization_id, finding_id)
    if finding.status not in ("open", "in_progress"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot remediate a finding with status {finding.status}",
        )
    open_link = session.execute(
        select(RemediationTicket).where(
            RemediationTicket.finding_id == finding.id,
            RemediationTicket.status.in_(("open", "in_progress")),
        )
    ).scalar_one_or_none()
    if open_link is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Finding already has an open remediation ticket"
        )
    try:
        ticket, link = vuln_service.create_remediation_ticket(
            session, principal.organization_id, finding, principal.user_id, body.patch_id
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    _audit(session, principal, audit_mod.TICKET_CREATED, "ticket", str(ticket.id), {"number": ticket.number})
    _audit(
        session,
        principal,
        VULN_REMEDIATION_CREATED,
        "remediation_ticket",
        str(link.id),
        {"finding_id": str(finding.id), "ticket_id": str(ticket.id)},
    )
    out = _remediation_out(session, link)
    session.commit()
    return out


@router.post("/findings/{finding_id}/verify", response_model=dict)
def verify_finding(
    finding_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("vulnerabilities:manage")),
):
    """Start rescan verification for a finding (closes the remediate →
    verify gap: PATCH forbids setting ``remediated`` directly, so this
    endpoint is the only path that produces that state).

    The finding must be ``in_progress`` with an open remediation link
    (or already ``remediated``, to retry verification). It flips to
    ``remediated`` and its open remediation links flip with it. Then:
    * when the finding's endpoint is agent-enrolled, a ``vuln_scan``
      agent job is issued with ``verify_finding_id`` in its payload —
      the job-result apply hook links the resulting scan as this
      finding's verification scan, and the finding flips to ``verified``
      only when that scan's results contain no row for its (endpoint,
      CVE). The job issuance is authorized by this endpoint's
      ``vulnerabilities:manage`` permission (the verification action),
      not by a separate ``endpoints:scan`` grant.
    * otherwise (no enrolled endpoint), a queued verification scan is
      created and linked immediately; it runs via manual import or an
      engine poll.
    """
    finding = _get_finding(session, principal.organization_id, finding_id)
    if finding.status not in ("in_progress", "remediated"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot verify a finding with status {finding.status} — remediate it first",
        )
    open_link = session.execute(
        select(RemediationTicket).where(
            RemediationTicket.finding_id == finding.id,
            RemediationTicket.status.in_(("open", "in_progress")),
        )
    ).scalar_one_or_none()
    if finding.status == "in_progress" and open_link is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Finding has no open remediation to verify",
        )
    finding.status = "remediated"
    links = session.execute(
        select(RemediationTicket).where(
            RemediationTicket.finding_id == finding.id,
            RemediationTicket.status.in_(("open", "in_progress")),
        )
    ).scalars()
    for link in links:
        link.status = "remediated"
    job_id: uuid.UUID | None = None
    scan_id: uuid.UUID | None = None
    endpoint = session.get(Endpoint, finding.endpoint_id) if finding.endpoint_id else None
    if endpoint is not None and endpoint.status != "unenrolled" and endpoint.token_revoked_at is None:
        job = endpoint_service.issue_job(
            session,
            org_id=principal.organization_id,
            endpoint=endpoint,
            job_type="vuln_scan",
            payload={"verify_finding_id": str(finding.id)},
            expires_in_minutes=60,
            issued_by_id=principal.user_id,
        )
        job_id = job.id
        _audit(
            session,
            principal,
            AGENT_JOB_ISSUED,
            "agent_job",
            str(job.id),
            {"job_type": "vuln_scan", "finding_id": str(finding.id)},
        )
    else:
        host = endpoint.hostname if endpoint is not None else "unenrolled host"
        scan = VulnScan(
            organization_id=principal.organization_id,
            engine_id=None,
            name=f"Verification scan — {finding.cve_id} on {host}",
            target=host,
            status="queued",
        )
        session.add(scan)
        session.flush()
        finding.verification_scan_id = scan.id
        scan_id = scan.id
    _audit(
        session,
        principal,
        VULN_FINDING_VERIFICATION_STARTED,
        "vulnerability_finding",
        str(finding.id),
        {"job_id": str(job_id) if job_id else None, "scan_id": str(scan_id) if scan_id else None},
    )
    out = _finding_out(session, finding)
    session.commit()
    return {"finding": out, "job_id": str(job_id) if job_id else None, "scan_id": str(scan_id) if scan_id else None}
