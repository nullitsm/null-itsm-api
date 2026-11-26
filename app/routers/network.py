"""Network operations routes: devices, interfaces, topology, service
dependencies, metrics, health, events, certificates, discovery.

Permissions: ``network:read`` / ``network:manage`` / ``network:discover``.
Cross-org access returns 404 (never reveal another org's rows). Every
mutating endpoint writes an audit row. SNMP community strings are never
returned. Responses are built before ``session.commit()`` (see
docs/DECISIONS.md).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from functools import wraps

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.audit import (
    NETWORK_CERTIFICATE_CREATED,
    NETWORK_CERTIFICATE_DELETED,
    NETWORK_CERTIFICATE_UPDATED,
    NETWORK_DEVICE_CREATED,
    NETWORK_DEVICE_DELETED,
    NETWORK_DEVICE_UPDATED,
    NETWORK_DISCOVERY_COMPLETED,
    NETWORK_EVENT_ACKNOWLEDGED,
    NETWORK_EVENT_CREATED,
    NETWORK_INTERFACE_CREATED,
    NETWORK_INTERFACE_DELETED,
    NETWORK_INTERFACE_UPDATED,
    NETWORK_METRICS_INGESTED,
    NETWORK_SERVICE_DEPENDENCY_CREATED,
    NETWORK_SERVICE_DEPENDENCY_DELETED,
    NETWORK_SERVICE_DEPENDENCY_UPDATED,
    NETWORK_TOPOLOGY_LINK_CREATED,
    NETWORK_TOPOLOGY_LINK_DELETED,
)
from app.deps import Principal, get_db, require_permission
from app.models.cmdb_network import (
    Certificate,
    NetworkDevice,
    NetworkEvent,
    NetworkInterface,
    NetworkMetric,
    ServiceDependency,
    TopologyLink,
)
from app.services import network_service

router = APIRouter(prefix="/api/v1/network", tags=["network"])


# --- Schemas (local: app/schemas.py belongs to another workstream) --------


class DeviceCreate(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    ip_address: str | None = None
    device_type: str = "other"
    vendor: str | None = None
    model: str | None = None
    os_version: str | None = None
    snmp_community: str | None = None
    snmp_version: str | None = None


class DeviceUpdate(BaseModel):
    hostname: str | None = None
    ip_address: str | None = None
    device_type: str | None = None
    vendor: str | None = None
    model: str | None = None
    os_version: str | None = None
    status: str | None = None
    snmp_community: str | None = None
    clear_snmp_community: bool = False
    snmp_version: str | None = None


class DeviceOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    hostname: str
    ip_address: str | None
    device_type: str
    vendor: str | None
    model: str | None
    os_version: str | None
    snmp_version: str | None
    has_snmp_community: bool
    status: str
    last_seen_at: datetime | None
    created_at: datetime
    updated_at: datetime


class InterfaceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    if_index: int | None = None
    ip_address: str | None = None
    mac_address: str | None = None
    speed_mbps: int | None = None
    status: str = "unknown"


class InterfaceUpdate(BaseModel):
    name: str | None = None
    if_index: int | None = None
    ip_address: str | None = None
    mac_address: str | None = None
    speed_mbps: int | None = None
    status: str | None = None


class InterfaceOut(BaseModel):
    id: uuid.UUID
    device_id: uuid.UUID
    name: str
    if_index: int | None
    ip_address: str | None
    mac_address: str | None
    speed_mbps: int | None
    status: str
    created_at: datetime
    updated_at: datetime


class TopologyLinkCreate(BaseModel):
    source_device_id: uuid.UUID
    source_interface_id: uuid.UUID | None = None
    target_device_id: uuid.UUID
    target_interface_id: uuid.UUID | None = None
    link_type: str | None = None


class TopologyLinkOut(BaseModel):
    id: uuid.UUID
    source_device_id: uuid.UUID
    source_interface_id: uuid.UUID | None
    target_device_id: uuid.UUID
    target_interface_id: uuid.UUID | None
    link_type: str | None
    created_at: datetime


class TopologyOut(BaseModel):
    devices: list[DeviceOut]
    links: list[TopologyLinkOut]


class ServiceDependencyCreate(BaseModel):
    service_name: str = Field(min_length=1, max_length=255)
    ci_id: uuid.UUID | None = None
    dependency_type: str = "depends_on"
    criticality: str = "medium"


class ServiceDependencyUpdate(BaseModel):
    service_name: str | None = None
    ci_id: uuid.UUID | None = None
    dependency_type: str | None = None
    criticality: str | None = None


class ServiceDependencyOut(BaseModel):
    id: uuid.UUID
    service_name: str
    ci_id: uuid.UUID | None
    dependency_type: str
    criticality: str
    created_at: datetime


class MetricSample(BaseModel):
    device_id: uuid.UUID
    interface_id: uuid.UUID | None = None
    metric_type: str
    value: float
    recorded_at: datetime | None = None


class MetricBatch(BaseModel):
    samples: list[MetricSample] = Field(min_length=1)


class MetricOut(BaseModel):
    id: uuid.UUID
    device_id: uuid.UUID
    interface_id: uuid.UUID | None
    metric_type: str
    value: float
    recorded_at: datetime | None
    created_at: datetime


class HealthOut(BaseModel):
    device_id: uuid.UUID
    hostname: str
    status: str
    last_seen_at: datetime | None
    latest_metrics: dict
    unacknowledged_critical_events: int


class EventCreate(BaseModel):
    device_id: uuid.UUID | None = None
    event_type: str
    severity: str = "info"
    message: str = Field(min_length=1)
    source_ip: str | None = None
    occurred_at: datetime | None = None


class EventOut(BaseModel):
    id: uuid.UUID
    device_id: uuid.UUID | None
    event_type: str
    severity: str
    message: str
    source_ip: str | None
    occurred_at: datetime | None
    acknowledged_at: datetime | None
    acknowledged_by_id: uuid.UUID | None
    created_at: datetime


class CertificateCreate(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    issuer: str | None = None
    expires_at: datetime | None = None
    status: str = "valid"


class CertificateUpdate(BaseModel):
    hostname: str | None = None
    issuer: str | None = None
    expires_at: datetime | None = None
    status: str | None = None


class CertificateOut(BaseModel):
    id: uuid.UUID
    hostname: str
    issuer: str | None
    expires_at: datetime | None
    status: str
    last_checked_at: datetime | None
    created_at: datetime


class DiscoverRequest(BaseModel):
    cidr: str = Field(min_length=1, max_length=43)
    timeout_seconds: int = Field(default=2, ge=1, le=10)


class DiscoverOut(BaseModel):
    discovered: int
    updated: int
    unreachable: int
    snmp_available: bool
    snmp_note: str | None = None
    probe_method: str


# --- Helpers ----------------------------------------------------------------


def _device_out(device: NetworkDevice) -> DeviceOut:
    return DeviceOut(
        id=device.id,
        organization_id=device.organization_id,
        hostname=device.hostname,
        ip_address=device.ip_address,
        device_type=device.device_type,
        vendor=device.vendor,
        model=device.model,
        os_version=device.os_version,
        snmp_version=device.snmp_version,
        has_snmp_community=bool(device.snmp_community_encrypted),
        status=device.status,
        last_seen_at=device.last_seen_at,
        created_at=device.created_at,
        updated_at=device.updated_at,
    )


def _iface_out(iface: NetworkInterface) -> InterfaceOut:
    return InterfaceOut(
        id=iface.id,
        device_id=iface.device_id,
        name=iface.name,
        if_index=iface.if_index,
        ip_address=iface.ip_address,
        mac_address=iface.mac_address,
        speed_mbps=iface.speed_mbps,
        status=iface.status,
        created_at=iface.created_at,
        updated_at=iface.updated_at,
    )


def _link_out(link: TopologyLink) -> TopologyLinkOut:
    return TopologyLinkOut(
        id=link.id,
        source_device_id=link.source_device_id,
        source_interface_id=link.source_interface_id,
        target_device_id=link.target_device_id,
        target_interface_id=link.target_interface_id,
        link_type=link.link_type,
        created_at=link.created_at,
    )


def _dep_out(dep: ServiceDependency) -> ServiceDependencyOut:
    return ServiceDependencyOut(
        id=dep.id,
        service_name=dep.service_name,
        ci_id=dep.ci_id,
        dependency_type=dep.dependency_type,
        criticality=dep.criticality,
        created_at=dep.created_at,
    )


def _metric_out(metric: NetworkMetric) -> MetricOut:
    return MetricOut(
        id=metric.id,
        device_id=metric.device_id,
        interface_id=metric.interface_id,
        metric_type=metric.metric_type,
        value=float(metric.value),
        recorded_at=metric.recorded_at,
        created_at=metric.created_at,
    )


def _event_out(event: NetworkEvent) -> EventOut:
    return EventOut(
        id=event.id,
        device_id=event.device_id,
        event_type=event.event_type,
        severity=event.severity,
        message=event.message,
        source_ip=event.source_ip,
        occurred_at=event.occurred_at,
        acknowledged_at=event.acknowledged_at,
        acknowledged_by_id=event.acknowledged_by_id,
        created_at=event.created_at,
    )


def _cert_out(cert: Certificate) -> CertificateOut:
    return CertificateOut(
        id=cert.id,
        hostname=cert.hostname,
        issuer=cert.issuer,
        expires_at=cert.expires_at,
        status=cert.status,
        last_checked_at=cert.last_checked_at,
        created_at=cert.created_at,
    )


def _get_device_or_404(session: Session, org_id: uuid.UUID, device_id: uuid.UUID) -> NetworkDevice:
    try:
        return network_service.get_device(session, org_id, device_id)
    except network_service.NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


def _translate_errors(func):
    """Decorator: map service exceptions to HTTP statuses.

    ``functools.wraps`` preserves the endpoint signature so FastAPI can
    still resolve the ``Depends`` parameters through ``__wrapped__``.
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except network_service.NotFoundError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
        except network_service.ValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
        except network_service.EncryptionUnavailableError as exc:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc))

    return wrapper


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


# --- Devices ----------------------------------------------------------------


@router.get("/devices", response_model=list[DeviceOut])
def list_devices(
    device_type: str | None = Query(default=None),
    status: str | None = Query(default=None),
    search: str | None = Query(default=None),
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("network:read")),
):
    rows = network_service.list_devices(
        session, principal.organization_id, device_type=device_type, status=status, search=search
    )
    return [_device_out(d) for d in rows]


@router.post("/devices", response_model=DeviceOut, status_code=status.HTTP_201_CREATED)
@_translate_errors
def create_device(
    body: DeviceCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("network:manage")),
):
    device = network_service.create_device(
        session,
        principal.organization_id,
        hostname=body.hostname,
        ip_address=body.ip_address,
        device_type=body.device_type,
        vendor=body.vendor,
        model=body.model,
        os_version=body.os_version,
        snmp_community=body.snmp_community,
        snmp_version=body.snmp_version,
    )
    _audit(
        session,
        principal,
        NETWORK_DEVICE_CREATED,
        "network_device",
        str(device.id),
        {"hostname": device.hostname},
    )
    out = _device_out(device)
    session.commit()
    return out


@router.get("/devices/{device_id}", response_model=DeviceOut)
def get_device(
    device_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("network:read")),
):
    return _device_out(_get_device_or_404(session, principal.organization_id, device_id))


@router.patch("/devices/{device_id}", response_model=DeviceOut)
@_translate_errors
def update_device(
    device_id: uuid.UUID,
    body: DeviceUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("network:manage")),
):
    device = _get_device_or_404(session, principal.organization_id, device_id)
    network_service.update_device(
        session,
        device,
        hostname=body.hostname,
        ip_address=body.ip_address,
        device_type=body.device_type,
        vendor=body.vendor,
        model=body.model,
        os_version=body.os_version,
        status=body.status,
        snmp_community=body.snmp_community,
        clear_snmp_community=body.clear_snmp_community,
        snmp_version=body.snmp_version,
    )
    _audit(
        session,
        principal,
        NETWORK_DEVICE_UPDATED,
        "network_device",
        str(device.id),
        {"hostname": device.hostname},
    )
    out = _device_out(device)
    session.commit()
    return out


@router.delete("/devices/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_device(
    device_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("network:manage")),
):
    device = _get_device_or_404(session, principal.organization_id, device_id)
    network_service.delete_device(session, device)
    _audit(
        session,
        principal,
        NETWORK_DEVICE_DELETED,
        "network_device",
        str(device.id),
        {"hostname": device.hostname},
    )
    session.commit()
    return None


# --- Interfaces -------------------------------------------------------------


@router.get("/devices/{device_id}/interfaces", response_model=list[InterfaceOut])
def list_interfaces(
    device_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("network:read")),
):
    device = _get_device_or_404(session, principal.organization_id, device_id)
    return [_iface_out(i) for i in network_service.list_interfaces(session, device)]


@router.post("/devices/{device_id}/interfaces", response_model=InterfaceOut, status_code=status.HTTP_201_CREATED)
@_translate_errors
def create_interface(
    device_id: uuid.UUID,
    body: InterfaceCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("network:manage")),
):
    device = _get_device_or_404(session, principal.organization_id, device_id)
    iface = network_service.create_interface(
        session,
        principal.organization_id,
        device,
        name=body.name,
        if_index=body.if_index,
        ip_address=body.ip_address,
        mac_address=body.mac_address,
        speed_mbps=body.speed_mbps,
        status=body.status,
    )
    _audit(
        session,
        principal,
        NETWORK_INTERFACE_CREATED,
        "network_interface",
        str(iface.id),
        {"device_id": str(device.id), "name": iface.name},
    )
    out = _iface_out(iface)
    session.commit()
    return out


@router.patch("/interfaces/{interface_id}", response_model=InterfaceOut)
@_translate_errors
def update_interface(
    interface_id: uuid.UUID,
    body: InterfaceUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("network:manage")),
):
    try:
        iface = network_service.get_interface(session, principal.organization_id, interface_id)
    except network_service.NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    network_service.update_interface(
        session,
        iface,
        name=body.name,
        if_index=body.if_index,
        ip_address=body.ip_address,
        mac_address=body.mac_address,
        speed_mbps=body.speed_mbps,
        status=body.status,
    )
    _audit(session, principal, NETWORK_INTERFACE_UPDATED, "network_interface", str(iface.id))
    out = _iface_out(iface)
    session.commit()
    return out


@router.delete("/interfaces/{interface_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_interface(
    interface_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("network:manage")),
):
    try:
        iface = network_service.get_interface(session, principal.organization_id, interface_id)
    except network_service.NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    network_service.delete_interface(session, iface)
    _audit(session, principal, NETWORK_INTERFACE_DELETED, "network_interface", str(iface.id))
    session.commit()
    return None


# --- Topology ---------------------------------------------------------------


@router.get("/topology", response_model=TopologyOut)
def get_topology(
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("network:read")),
):
    devices, links = network_service.list_topology(session, principal.organization_id)
    return TopologyOut(devices=[_device_out(d) for d in devices], links=[_link_out(li) for li in links])


@router.post("/topology/links", response_model=TopologyLinkOut, status_code=status.HTTP_201_CREATED)
@_translate_errors
def create_topology_link(
    body: TopologyLinkCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("network:manage")),
):
    link = network_service.create_topology_link(
        session,
        principal.organization_id,
        source_device_id=body.source_device_id,
        source_interface_id=body.source_interface_id,
        target_device_id=body.target_device_id,
        target_interface_id=body.target_interface_id,
        link_type=body.link_type,
    )
    _audit(session, principal, NETWORK_TOPOLOGY_LINK_CREATED, "topology_link", str(link.id))
    out = _link_out(link)
    session.commit()
    return out


@router.delete("/topology/links/{link_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_topology_link(
    link_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("network:manage")),
):
    try:
        link = network_service.get_topology_link(session, principal.organization_id, link_id)
    except network_service.NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    network_service.delete_topology_link(session, link)
    _audit(session, principal, NETWORK_TOPOLOGY_LINK_DELETED, "topology_link", str(link.id))
    session.commit()
    return None


# --- Service dependencies ---------------------------------------------------


@router.get("/service-dependencies", response_model=list[ServiceDependencyOut])
def list_service_dependencies(
    service_name: str | None = Query(default=None),
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("network:read")),
):
    rows = network_service.list_service_dependencies(session, principal.organization_id, service_name=service_name)
    return [_dep_out(d) for d in rows]


@router.post("/service-dependencies", response_model=ServiceDependencyOut, status_code=status.HTTP_201_CREATED)
@_translate_errors
def create_service_dependency(
    body: ServiceDependencyCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("network:manage")),
):
    dep = network_service.create_service_dependency(
        session,
        principal.organization_id,
        service_name=body.service_name,
        ci_id=body.ci_id,
        dependency_type=body.dependency_type,
        criticality=body.criticality,
    )
    _audit(
        session,
        principal,
        NETWORK_SERVICE_DEPENDENCY_CREATED,
        "service_dependency",
        str(dep.id),
        {"service_name": dep.service_name},
    )
    out = _dep_out(dep)
    session.commit()
    return out


@router.patch("/service-dependencies/{dep_id}", response_model=ServiceDependencyOut)
@_translate_errors
def update_service_dependency(
    dep_id: uuid.UUID,
    body: ServiceDependencyUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("network:manage")),
):
    try:
        dep = network_service.get_service_dependency(session, principal.organization_id, dep_id)
    except network_service.NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    network_service.update_service_dependency(
        session,
        dep,
        principal.organization_id,
        service_name=body.service_name,
        ci_id=body.ci_id,
        dependency_type=body.dependency_type,
        criticality=body.criticality,
    )
    _audit(session, principal, NETWORK_SERVICE_DEPENDENCY_UPDATED, "service_dependency", str(dep.id))
    out = _dep_out(dep)
    session.commit()
    return out


@router.delete("/service-dependencies/{dep_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_service_dependency(
    dep_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("network:manage")),
):
    try:
        dep = network_service.get_service_dependency(session, principal.organization_id, dep_id)
    except network_service.NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    network_service.delete_service_dependency(session, dep)
    _audit(session, principal, NETWORK_SERVICE_DEPENDENCY_DELETED, "service_dependency", str(dep.id))
    session.commit()
    return None


# --- Metrics + health -------------------------------------------------------


@router.post("/metrics", response_model=list[MetricOut], status_code=status.HTTP_201_CREATED)
@_translate_errors
def ingest_metrics(
    body: MetricBatch,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("network:manage")),
):
    rows = network_service.ingest_metrics(
        session,
        principal.organization_id,
        [s.model_dump() for s in body.samples],
    )
    _audit(
        session,
        principal,
        NETWORK_METRICS_INGESTED,
        "network_metric",
        str(rows[0].id),
        {"samples": len(rows)},
    )
    out = [_metric_out(r) for r in rows]
    session.commit()
    return out


@router.get("/devices/{device_id}/metrics", response_model=list[MetricOut])
def list_device_metrics(
    device_id: uuid.UUID,
    metric_type: str | None = Query(default=None),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("network:read")),
):
    device = _get_device_or_404(session, principal.organization_id, device_id)
    rows = network_service.list_device_metrics(
        session, principal.organization_id, device, metric_type=metric_type, since=since, until=until
    )
    return [_metric_out(r) for r in rows]


@router.get("/devices/{device_id}/health", response_model=HealthOut)
def get_device_health(
    device_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("network:read")),
):
    device = _get_device_or_404(session, principal.organization_id, device_id)
    health = network_service.device_health(session, principal.organization_id, device)
    return HealthOut(
        device_id=health["device_id"],
        hostname=health["hostname"],
        status=health["status"],
        last_seen_at=datetime.fromisoformat(health["last_seen_at"]) if health["last_seen_at"] else None,
        latest_metrics=health["latest_metrics"],
        unacknowledged_critical_events=health["unacknowledged_critical_events"],
    )


# --- Events -----------------------------------------------------------------


@router.post("/events", response_model=EventOut, status_code=status.HTTP_201_CREATED)
@_translate_errors
def create_event(
    body: EventCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("network:manage")),
):
    event = network_service.create_event(
        session,
        principal.organization_id,
        device_id=body.device_id,
        event_type=body.event_type,
        severity=body.severity,
        message=body.message,
        source_ip=body.source_ip,
        occurred_at=body.occurred_at,
    )
    _audit(
        session,
        principal,
        NETWORK_EVENT_CREATED,
        "network_event",
        str(event.id),
        {"event_type": event.event_type, "severity": event.severity},
    )
    out = _event_out(event)
    session.commit()
    return out


@router.get("/events", response_model=list[EventOut])
def list_events(
    device_id: uuid.UUID | None = Query(default=None),
    event_type: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    acknowledged: bool | None = Query(default=None),
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("network:read")),
):
    rows = network_service.list_events(
        session,
        principal.organization_id,
        device_id=device_id,
        event_type=event_type,
        severity=severity,
        acknowledged=acknowledged,
    )
    return [_event_out(e) for e in rows]


@router.post("/events/{event_id}/acknowledge", response_model=EventOut)
@_translate_errors
def acknowledge_event(
    event_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("network:manage")),
):
    try:
        event = network_service.get_event(session, principal.organization_id, event_id)
    except network_service.NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    network_service.acknowledge_event(session, event, actor_id=principal.user_id)
    _audit(session, principal, NETWORK_EVENT_ACKNOWLEDGED, "network_event", str(event.id))
    out = _event_out(event)
    session.commit()
    return out


# --- Certificates -----------------------------------------------------------


@router.get("/certificates/expiring", response_model=list[CertificateOut])
def list_expiring_certificates(
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("network:read")),
):
    rows = network_service.expiring_certificates(session, principal.organization_id)
    return [_cert_out(c) for c in rows]


@router.get("/certificates", response_model=list[CertificateOut])
def list_certificates(
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("network:read")),
):
    rows = network_service.list_certificates(session, principal.organization_id)
    return [_cert_out(c) for c in rows]


@router.post("/certificates", response_model=CertificateOut, status_code=status.HTTP_201_CREATED)
@_translate_errors
def create_certificate(
    body: CertificateCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("network:manage")),
):
    cert = network_service.create_certificate(
        session,
        principal.organization_id,
        hostname=body.hostname,
        issuer=body.issuer,
        expires_at=body.expires_at,
        status=body.status,
    )
    _audit(
        session,
        principal,
        NETWORK_CERTIFICATE_CREATED,
        "certificate",
        str(cert.id),
        {"hostname": cert.hostname},
    )
    out = _cert_out(cert)
    session.commit()
    return out


@router.patch("/certificates/{cert_id}", response_model=CertificateOut)
@_translate_errors
def update_certificate(
    cert_id: uuid.UUID,
    body: CertificateUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("network:manage")),
):
    try:
        cert = network_service.get_certificate(session, principal.organization_id, cert_id)
    except network_service.NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    network_service.update_certificate(
        session,
        cert,
        hostname=body.hostname,
        issuer=body.issuer,
        expires_at=body.expires_at,
        status=body.status,
    )
    _audit(session, principal, NETWORK_CERTIFICATE_UPDATED, "certificate", str(cert.id))
    out = _cert_out(cert)
    session.commit()
    return out


@router.delete("/certificates/{cert_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_certificate(
    cert_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("network:manage")),
):
    try:
        cert = network_service.get_certificate(session, principal.organization_id, cert_id)
    except network_service.NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    network_service.delete_certificate(session, cert)
    _audit(session, principal, NETWORK_CERTIFICATE_DELETED, "certificate", str(cert.id))
    session.commit()
    return None


# --- Discovery --------------------------------------------------------------


@router.post("/discover", response_model=DiscoverOut)
@_translate_errors
def discover(
    body: DiscoverRequest,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("network:discover")),
):
    result = network_service.discover_network(
        session,
        principal.organization_id,
        cidr=body.cidr,
        timeout_seconds=body.timeout_seconds,
    )
    _audit(
        session,
        principal,
        NETWORK_DISCOVERY_COMPLETED,
        "network_discovery",
        body.cidr,
        {"cidr": body.cidr, **result},
    )
    out = DiscoverOut(**result)
    session.commit()
    return out
