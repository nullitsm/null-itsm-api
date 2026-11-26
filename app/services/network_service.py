"""Network operations service: devices, interfaces, topology, service
dependencies, metrics, events, certificates, and discovery.

Pure data logic over the Phase 3 ``network_*`` / ``certificates`` tables.
Routers translate the exceptions raised here into HTTP statuses; nothing
in this module knows about HTTP.

Discovery: a real ICMP ping sweep (system ``ping`` via subprocess) over a
bounded CIDR. This VM/container has no CAP_NET_RAW and its
``ping_group_range`` does not cover the app user, so ICMP is unavailable
here — when the ping binary itself fails with a socket-permission error,
the sweep falls back to a TCP connect probe against common service ports
and reports which probe was used. A host is only recorded when it
actually responds; nothing is invented. SNMP enrichment is best-effort
only: pysnmp is not installed, so enrichment is honestly unavailable.
"""

from __future__ import annotations

import importlib.util
import ipaddress
import logging
import socket
import subprocess
import uuid
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.cmdb_network import (
    Certificate,
    ConfigurationItem,
    NetworkDevice,
    NetworkEvent,
    NetworkInterface,
    NetworkMetric,
    ServiceDependency,
    TopologyLink,
)

logger = logging.getLogger("null.services.network")

UTC = timezone.utc

DEVICE_TYPES = {"switch", "router", "firewall", "server", "access_point", "other"}
DEVICE_STATUSES = {"up", "down", "unknown"}
INTERFACE_STATUSES = {"up", "down", "unknown"}
METRIC_TYPES = {"cpu", "memory", "bandwidth_in", "bandwidth_out", "latency", "availability"}
EVENT_TYPES = {"syslog", "outage", "cert_expiry", "dns", "dhcp", "snmp_trap", "other"}
EVENT_SEVERITIES = {"info", "warning", "critical"}
CERT_STATUSES = {"valid", "expiring", "expired", "error"}
DEPENDENCY_TYPES = {"depends_on", "hosts", "uses"}
CRITICALITIES = {"low", "medium", "high", "critical"}

# Ports tried by the TCP fallback probe (only when ICMP is unavailable in
# the environment). A connect success is real evidence of a live host.
TCP_PROBE_PORTS = (22, 80, 443, 445, 3389, 5432, 6379, 8000, 8080, 8443)
MAX_DISCOVERY_HOSTS = 256
DISCOVERY_OVERALL_TIMEOUT_SECONDS = 60


class NotFoundError(Exception):
    """A row does not exist in this organization (surfaced as 404)."""


class ValidationError(Exception):
    """Caller input is invalid (surfaced as 400)."""


class EncryptionUnavailableError(Exception):
    """No field-encryption key is configured (surfaced as 503)."""


# --- Shared helpers ---------------------------------------------------------


def encrypt_community(community: str) -> str:
    """Fernet-encrypt an SNMP community string; fail closed with 503."""
    from app.services import identity_service

    try:
        return identity_service.encrypt_secret(community)
    except identity_service.SecretStorageError as exc:
        raise EncryptionUnavailableError(str(exc)) from exc


# --- Devices ----------------------------------------------------------------


def get_device(session: Session, org_id: uuid.UUID, device_id: uuid.UUID) -> NetworkDevice:
    device = session.get(NetworkDevice, device_id)
    if device is None or device.organization_id != org_id:
        raise NotFoundError(f"Network device {device_id} not found")
    return device


def list_devices(
    session: Session,
    org_id: uuid.UUID,
    *,
    device_type: str | None = None,
    status: str | None = None,
    search: str | None = None,
) -> list[NetworkDevice]:
    stmt = select(NetworkDevice).where(NetworkDevice.organization_id == org_id)
    if device_type is not None:
        stmt = stmt.where(NetworkDevice.device_type == device_type)
    if status is not None:
        stmt = stmt.where(NetworkDevice.status == status)
    if search:
        stmt = stmt.where(
            or_(
                NetworkDevice.hostname.ilike(f"%{search}%"),
                NetworkDevice.ip_address.ilike(f"%{search}%"),
            )
        )
    return list(session.execute(stmt.order_by(NetworkDevice.created_at.desc())).scalars())


def create_device(
    session: Session,
    org_id: uuid.UUID,
    *,
    hostname: str,
    ip_address: str | None,
    device_type: str,
    vendor: str | None,
    model: str | None,
    os_version: str | None,
    snmp_community: str | None,
    snmp_version: str | None,
) -> NetworkDevice:
    if device_type not in DEVICE_TYPES:
        raise ValidationError(f"Invalid device_type: {device_type}")
    if snmp_version is not None and snmp_version not in ("v1", "v2c", "v3"):
        raise ValidationError(f"Invalid snmp_version: {snmp_version}")
    if ip_address is not None:
        try:
            ipaddress.ip_address(ip_address)
        except ValueError as exc:
            raise ValidationError(f"Invalid ip_address: {ip_address}") from exc
    encrypted = encrypt_community(snmp_community) if snmp_community else None
    device = NetworkDevice(
        organization_id=org_id,
        hostname=hostname,
        ip_address=ip_address,
        device_type=device_type,
        vendor=vendor,
        model=model,
        os_version=os_version,
        snmp_community_encrypted=encrypted,
        snmp_version=snmp_version or "v2c",
    )
    session.add(device)
    session.flush()
    return device


def update_device(
    session: Session,
    device: NetworkDevice,
    *,
    hostname: str | None,
    ip_address: str | None,
    device_type: str | None,
    vendor: str | None,
    model: str | None,
    os_version: str | None,
    status: str | None,
    snmp_community: str | None,
    clear_snmp_community: bool,
    snmp_version: str | None,
) -> NetworkDevice:
    if device_type is not None and device_type not in DEVICE_TYPES:
        raise ValidationError(f"Invalid device_type: {device_type}")
    if status is not None and status not in DEVICE_STATUSES:
        raise ValidationError(f"Invalid status: {status}")
    if snmp_version is not None and snmp_version not in ("v1", "v2c", "v3"):
        raise ValidationError(f"Invalid snmp_version: {snmp_version}")
    if ip_address is not None:
        try:
            ipaddress.ip_address(ip_address)
        except ValueError as exc:
            raise ValidationError(f"Invalid ip_address: {ip_address}") from exc
    if hostname is not None:
        device.hostname = hostname
    if ip_address is not None:
        device.ip_address = ip_address
    if device_type is not None:
        device.device_type = device_type
    if vendor is not None:
        device.vendor = vendor
    if model is not None:
        device.model = model
    if os_version is not None:
        device.os_version = os_version
    if status is not None:
        device.status = status
    if snmp_version is not None:
        device.snmp_version = snmp_version
    if clear_snmp_community:
        device.snmp_community_encrypted = None
    elif snmp_community:
        device.snmp_community_encrypted = encrypt_community(snmp_community)
    session.flush()
    return device


def delete_device(session: Session, device: NetworkDevice) -> None:
    session.delete(device)
    session.flush()


# --- Interfaces -------------------------------------------------------------


def get_interface(session: Session, org_id: uuid.UUID, interface_id: uuid.UUID) -> NetworkInterface:
    iface = session.get(NetworkInterface, interface_id)
    if iface is None or iface.organization_id != org_id:
        raise NotFoundError(f"Network interface {interface_id} not found")
    return iface


def list_interfaces(session: Session, device: NetworkDevice) -> list[NetworkInterface]:
    stmt = select(NetworkInterface).where(NetworkInterface.device_id == device.id).order_by(NetworkInterface.name)
    return list(session.execute(stmt).scalars())


def create_interface(
    session: Session,
    org_id: uuid.UUID,
    device: NetworkDevice,
    *,
    name: str,
    if_index: int | None,
    ip_address: str | None,
    mac_address: str | None,
    speed_mbps: int | None,
    status: str,
) -> NetworkInterface:
    if status not in INTERFACE_STATUSES:
        raise ValidationError(f"Invalid status: {status}")
    if ip_address is not None:
        try:
            ipaddress.ip_address(ip_address)
        except ValueError as exc:
            raise ValidationError(f"Invalid ip_address: {ip_address}") from exc
    iface = NetworkInterface(
        organization_id=org_id,
        device_id=device.id,
        name=name,
        if_index=if_index,
        ip_address=ip_address,
        mac_address=mac_address,
        speed_mbps=speed_mbps,
        status=status,
    )
    session.add(iface)
    session.flush()
    return iface


def update_interface(
    session: Session,
    iface: NetworkInterface,
    *,
    name: str | None,
    if_index: int | None,
    ip_address: str | None,
    mac_address: str | None,
    speed_mbps: int | None,
    status: str | None,
) -> NetworkInterface:
    if status is not None and status not in INTERFACE_STATUSES:
        raise ValidationError(f"Invalid status: {status}")
    if ip_address is not None:
        try:
            ipaddress.ip_address(ip_address)
        except ValueError as exc:
            raise ValidationError(f"Invalid ip_address: {ip_address}") from exc
    if name is not None:
        iface.name = name
    if if_index is not None:
        iface.if_index = if_index
    if ip_address is not None:
        iface.ip_address = ip_address
    if mac_address is not None:
        iface.mac_address = mac_address
    if speed_mbps is not None:
        iface.speed_mbps = speed_mbps
    if status is not None:
        iface.status = status
    session.flush()
    return iface


def delete_interface(session: Session, iface: NetworkInterface) -> None:
    session.delete(iface)
    session.flush()


# --- Topology ---------------------------------------------------------------


def list_topology(session: Session, org_id: uuid.UUID) -> tuple[list[NetworkDevice], list[TopologyLink]]:
    devices = list_devices(session, org_id)
    links = list(
        session.execute(
            select(TopologyLink).where(TopologyLink.organization_id == org_id).order_by(TopologyLink.created_at)
        ).scalars()
    )
    return devices, links


def create_topology_link(
    session: Session,
    org_id: uuid.UUID,
    *,
    source_device_id: uuid.UUID,
    source_interface_id: uuid.UUID | None,
    target_device_id: uuid.UUID,
    target_interface_id: uuid.UUID | None,
    link_type: str | None,
) -> TopologyLink:
    source = session.get(NetworkDevice, source_device_id)
    if source is None or source.organization_id != org_id:
        raise NotFoundError(f"Network device {source_device_id} not found")
    target = session.get(NetworkDevice, target_device_id)
    if target is None or target.organization_id != org_id:
        raise NotFoundError(f"Network device {target_device_id} not found")
    if source_device_id == target_device_id:
        raise ValidationError("A device cannot link to itself")
    source_iface = None
    if source_interface_id is not None:
        source_iface = session.get(NetworkInterface, source_interface_id)
        if source_iface is None or source_iface.organization_id != org_id:
            raise NotFoundError(f"Network interface {source_interface_id} not found")
        if source_iface.device_id != source_device_id:
            raise ValidationError("source_interface_id does not belong to the source device")
    target_iface = None
    if target_interface_id is not None:
        target_iface = session.get(NetworkInterface, target_interface_id)
        if target_iface is None or target_iface.organization_id != org_id:
            raise NotFoundError(f"Network interface {target_interface_id} not found")
        if target_iface.device_id != target_device_id:
            raise ValidationError("target_interface_id does not belong to the target device")
    # A link is undirected for duplicate purposes: A->B duplicates B->A.
    duplicate = session.execute(
        select(TopologyLink).where(
            TopologyLink.organization_id == org_id,
            (
                (
                    (TopologyLink.source_device_id == source_device_id)
                    & (TopologyLink.source_interface_id == source_interface_id)
                    & (TopologyLink.target_device_id == target_device_id)
                    & (TopologyLink.target_interface_id == target_interface_id)
                )
                | (
                    (TopologyLink.source_device_id == target_device_id)
                    & (TopologyLink.source_interface_id == target_interface_id)
                    & (TopologyLink.target_device_id == source_device_id)
                    & (TopologyLink.target_interface_id == source_interface_id)
                )
            ),
        )
    ).scalar_one_or_none()
    if duplicate is not None:
        raise ValidationError("Topology link already exists")
    link = TopologyLink(
        organization_id=org_id,
        source_device_id=source_device_id,
        source_interface_id=source_interface_id,
        target_device_id=target_device_id,
        target_interface_id=target_interface_id,
        link_type=link_type,
    )
    session.add(link)
    try:
        session.flush()
    except IntegrityError as exc:
        session.rollback()
        raise ValidationError("Topology link already exists") from exc
    return link


def get_topology_link(session: Session, org_id: uuid.UUID, link_id: uuid.UUID) -> TopologyLink:
    link = session.get(TopologyLink, link_id)
    if link is None or link.organization_id != org_id:
        raise NotFoundError(f"Topology link {link_id} not found")
    return link


def delete_topology_link(session: Session, link: TopologyLink) -> None:
    session.delete(link)
    session.flush()


# --- Service dependencies ---------------------------------------------------


def get_service_dependency(session: Session, org_id: uuid.UUID, dep_id: uuid.UUID) -> ServiceDependency:
    dep = session.get(ServiceDependency, dep_id)
    if dep is None or dep.organization_id != org_id:
        raise NotFoundError(f"Service dependency {dep_id} not found")
    return dep


def list_service_dependencies(
    session: Session, org_id: uuid.UUID, *, service_name: str | None = None
) -> list[ServiceDependency]:
    stmt = select(ServiceDependency).where(ServiceDependency.organization_id == org_id)
    if service_name:
        stmt = stmt.where(ServiceDependency.service_name.ilike(f"%{service_name}%"))
    return list(session.execute(stmt.order_by(ServiceDependency.created_at.desc())).scalars())


def create_service_dependency(
    session: Session,
    org_id: uuid.UUID,
    *,
    service_name: str,
    ci_id: uuid.UUID | None,
    dependency_type: str,
    criticality: str,
) -> ServiceDependency:
    if dependency_type not in DEPENDENCY_TYPES:
        raise ValidationError(f"Invalid dependency_type: {dependency_type}")
    if criticality not in CRITICALITIES:
        raise ValidationError(f"Invalid criticality: {criticality}")
    if ci_id is not None:
        ci = session.get(ConfigurationItem, ci_id)
        if ci is None or ci.organization_id != org_id:
            raise NotFoundError(f"Configuration item {ci_id} not found")
    dep = ServiceDependency(
        organization_id=org_id,
        service_name=service_name,
        ci_id=ci_id,
        dependency_type=dependency_type,
        criticality=criticality,
    )
    session.add(dep)
    session.flush()
    return dep


def update_service_dependency(
    session: Session,
    dep: ServiceDependency,
    org_id: uuid.UUID,
    *,
    service_name: str | None,
    ci_id: uuid.UUID | None,
    dependency_type: str | None,
    criticality: str | None,
) -> ServiceDependency:
    if dependency_type is not None and dependency_type not in DEPENDENCY_TYPES:
        raise ValidationError(f"Invalid dependency_type: {dependency_type}")
    if criticality is not None and criticality not in CRITICALITIES:
        raise ValidationError(f"Invalid criticality: {criticality}")
    if ci_id is not None:
        ci = session.get(ConfigurationItem, ci_id)
        if ci is None or ci.organization_id != org_id:
            raise NotFoundError(f"Configuration item {ci_id} not found")
        dep.ci_id = ci_id
    if service_name is not None:
        dep.service_name = service_name
    if dependency_type is not None:
        dep.dependency_type = dependency_type
    if criticality is not None:
        dep.criticality = criticality
    session.flush()
    return dep


def delete_service_dependency(session: Session, dep: ServiceDependency) -> None:
    session.delete(dep)
    session.flush()


# --- Metrics ----------------------------------------------------------------


def ingest_metrics(
    session: Session,
    org_id: uuid.UUID,
    samples: list[dict],
) -> list[NetworkMetric]:
    """Append metric samples. Every device is validated in-org first, so a
    bad batch inserts nothing. Each sample is a new row (append-only);
    there is no update path. Each touched device's last_seen_at is
    refreshed to now."""
    devices: dict[uuid.UUID, NetworkDevice] = {}
    for sample in samples:
        device_id = sample["device_id"]
        if device_id not in devices:
            devices[device_id] = get_device(session, org_id, device_id)
        interface_id = sample.get("interface_id")
        if interface_id is not None:
            iface = session.get(NetworkInterface, interface_id)
            if iface is None or iface.organization_id != org_id:
                raise NotFoundError(f"Network interface {interface_id} not found")
            if iface.device_id != device_id:
                raise ValidationError("interface_id does not belong to the sample's device")
        if sample["metric_type"] not in METRIC_TYPES:
            raise ValidationError(f"Invalid metric_type: {sample['metric_type']}")
    now = datetime.now(UTC)
    rows: list[NetworkMetric] = []
    for sample in samples:
        row = NetworkMetric(
            organization_id=org_id,
            device_id=sample["device_id"],
            interface_id=sample.get("interface_id"),
            metric_type=sample["metric_type"],
            value=sample["value"],
            recorded_at=sample.get("recorded_at") or now,
        )
        session.add(row)
        rows.append(row)
    for device in devices.values():
        device.last_seen_at = now
    session.flush()
    return rows


def list_device_metrics(
    session: Session,
    org_id: uuid.UUID,
    device: NetworkDevice,
    *,
    metric_type: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
) -> list[NetworkMetric]:
    stmt = select(NetworkMetric).where(
        NetworkMetric.organization_id == org_id,
        NetworkMetric.device_id == device.id,
    )
    if metric_type is not None:
        stmt = stmt.where(NetworkMetric.metric_type == metric_type)
    if since is not None:
        stmt = stmt.where(NetworkMetric.recorded_at >= since)
    if until is not None:
        stmt = stmt.where(NetworkMetric.recorded_at <= until)
    stmt = stmt.order_by(NetworkMetric.recorded_at.desc(), NetworkMetric.created_at.desc())
    return list(session.execute(stmt).scalars())


def device_health(session: Session, org_id: uuid.UUID, device: NetworkDevice) -> dict:
    """Derived health: latest metric per type + device status + count of
    unacknowledged critical events. Nothing here is stored."""
    metrics = list_device_metrics(session, org_id, device)
    latest: dict[str, dict] = {}
    for metric in metrics:
        # Rows arrive newest-first; keep the first seen per type.
        if metric.metric_type not in latest:
            latest[metric.metric_type] = {
                "value": float(metric.value),
                "recorded_at": metric.recorded_at.isoformat() if metric.recorded_at else None,
            }
    unack_critical = session.execute(
        select(func.count())
        .select_from(NetworkEvent)
        .where(
            NetworkEvent.organization_id == org_id,
            NetworkEvent.device_id == device.id,
            NetworkEvent.severity == "critical",
            NetworkEvent.acknowledged_at.is_(None),
        )
    ).scalar_one()
    return {
        "device_id": device.id,
        "hostname": device.hostname,
        "status": device.status,
        "last_seen_at": device.last_seen_at.isoformat() if device.last_seen_at else None,
        "latest_metrics": latest,
        "unacknowledged_critical_events": unack_critical,
    }


# --- Events -----------------------------------------------------------------


def create_event(
    session: Session,
    org_id: uuid.UUID,
    *,
    device_id: uuid.UUID | None,
    event_type: str,
    severity: str,
    message: str,
    source_ip: str | None,
    occurred_at: datetime | None,
) -> NetworkEvent:
    if event_type not in EVENT_TYPES:
        raise ValidationError(f"Invalid event_type: {event_type}")
    if severity not in EVENT_SEVERITIES:
        raise ValidationError(f"Invalid severity: {severity}")
    if device_id is not None:
        get_device(session, org_id, device_id)
    event = NetworkEvent(
        organization_id=org_id,
        device_id=device_id,
        event_type=event_type,
        severity=severity,
        message=message,
        source_ip=source_ip,
        occurred_at=occurred_at or datetime.now(UTC),
    )
    session.add(event)
    session.flush()
    return event


def list_events(
    session: Session,
    org_id: uuid.UUID,
    *,
    device_id: uuid.UUID | None = None,
    event_type: str | None = None,
    severity: str | None = None,
    acknowledged: bool | None = None,
) -> list[NetworkEvent]:
    stmt = select(NetworkEvent).where(NetworkEvent.organization_id == org_id)
    if device_id is not None:
        stmt = stmt.where(NetworkEvent.device_id == device_id)
    if event_type is not None:
        stmt = stmt.where(NetworkEvent.event_type == event_type)
    if severity is not None:
        stmt = stmt.where(NetworkEvent.severity == severity)
    if acknowledged is True:
        stmt = stmt.where(NetworkEvent.acknowledged_at.is_not(None))
    elif acknowledged is False:
        stmt = stmt.where(NetworkEvent.acknowledged_at.is_(None))
    return list(session.execute(stmt.order_by(NetworkEvent.occurred_at.desc())).scalars())


def get_event(session: Session, org_id: uuid.UUID, event_id: uuid.UUID) -> NetworkEvent:
    event = session.get(NetworkEvent, event_id)
    if event is None or event.organization_id != org_id:
        raise NotFoundError(f"Network event {event_id} not found")
    return event


def acknowledge_event(session: Session, event: NetworkEvent, *, actor_id: uuid.UUID) -> NetworkEvent:
    if event.acknowledged_at is not None:
        raise ValidationError("Event is already acknowledged")
    event.acknowledged_at = datetime.now(UTC)
    event.acknowledged_by_id = actor_id
    session.flush()
    return event


# --- Certificates -----------------------------------------------------------


def get_certificate(session: Session, org_id: uuid.UUID, cert_id: uuid.UUID) -> Certificate:
    cert = session.get(Certificate, cert_id)
    if cert is None or cert.organization_id != org_id:
        raise NotFoundError(f"Certificate {cert_id} not found")
    return cert


def list_certificates(session: Session, org_id: uuid.UUID) -> list[Certificate]:
    stmt = select(Certificate).where(Certificate.organization_id == org_id).order_by(Certificate.expires_at)
    return list(session.execute(stmt).scalars())


def create_certificate(
    session: Session,
    org_id: uuid.UUID,
    *,
    hostname: str,
    issuer: str | None,
    expires_at: datetime | None,
    status: str,
) -> Certificate:
    if status not in CERT_STATUSES:
        raise ValidationError(f"Invalid status: {status}")
    cert = Certificate(
        organization_id=org_id,
        hostname=hostname,
        issuer=issuer,
        expires_at=expires_at,
        status=status,
    )
    session.add(cert)
    session.flush()
    return cert


def update_certificate(
    session: Session,
    cert: Certificate,
    *,
    hostname: str | None,
    issuer: str | None,
    expires_at: datetime | None,
    status: str | None,
) -> Certificate:
    if status is not None and status not in CERT_STATUSES:
        raise ValidationError(f"Invalid status: {status}")
    if hostname is not None:
        cert.hostname = hostname
    if issuer is not None:
        cert.issuer = issuer
    if expires_at is not None:
        cert.expires_at = expires_at
    if status is not None:
        cert.status = status
    session.flush()
    return cert


def delete_certificate(session: Session, cert: Certificate) -> None:
    session.delete(cert)
    session.flush()


def expiring_certificates(session: Session, org_id: uuid.UUID, *, within_days: int = 30) -> list[Certificate]:
    """Derived: certificates expiring within ``within_days`` whose status
    is not already ``expired``. Nothing is stored by this query."""
    now = datetime.now(UTC)
    stmt = (
        select(Certificate)
        .where(
            Certificate.organization_id == org_id,
            Certificate.status != "expired",
            Certificate.expires_at.is_not(None),
            Certificate.expires_at <= now + timedelta(days=within_days),
        )
        .order_by(Certificate.expires_at)
    )
    return list(session.execute(stmt).scalars())


# --- Discovery --------------------------------------------------------------


def snmp_available() -> bool:
    """True only when pysnmp is importable. It is not installed, so this
    is honestly False in the current environment."""
    return importlib.util.find_spec("pysnmp") is not None


def snmp_sysdescr(host: str, community: str = "public", timeout: int = 2) -> str | None:
    """Best-effort SNMP sysDescr read. Returns None whenever pysnmp is
    missing or the query fails — enrichment must never block discovery."""
    if not snmp_available():
        return None
    try:
        from pysnmp.hlapi import (  # type: ignore[import-not-found]
            CommunityData,
            ContextData,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            getCmd,
        )

        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),
            UdpTransportTarget((host, 161), timeout=timeout, retries=0),
            ContextData(),
            ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)),
        )
        error_indication, error_status, _, var_binds = next(iterator)
        if error_indication or error_status:
            return None
        return str(var_binds[0][1]) if var_binds else None
    except Exception:
        logger.debug("SNMP sysDescr lookup failed for %s", host, exc_info=True)
        return None


def _ping_available() -> bool:
    """Probe whether this environment can do ICMP at all (system ping
    against loopback). Returns False when the ping binary fails with a
    socket-permission error — the case in containers without CAP_NET_RAW."""
    try:
        proc = subprocess.run(
            ["ping", "-c", "1", "-W", "1", "127.0.0.1"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False
    if proc.returncode == 0:
        return True
    stderr = (proc.stderr or "").lower()
    if "operation not permitted" in stderr or "permission denied" in stderr:
        return False
    return True


def _ping_host(host: str, timeout_seconds: int) -> bool:
    """One ICMP echo via the system ping binary. True when it answers."""
    try:
        proc = subprocess.run(
            ["ping", "-c", "1", "-W", str(max(1, timeout_seconds)), host],
            capture_output=True,
            text=True,
            timeout=timeout_seconds + 2,
        )
    except (subprocess.TimeoutExpired, OSError):
        return False
    return proc.returncode == 0


def _tcp_probe(host: str) -> bool:
    """TCP connect probe (ICMP-unavailable fallback). True when any common
    service port accepts a connection — real evidence of a live host."""
    for port in TCP_PROBE_PORTS:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            continue
    return False


def _reverse_dns(host: str) -> str | None:
    try:
        name, _, _ = socket.gethostbyaddr(host)
        return name
    except (socket.herror, socket.gaierror, OSError, UnicodeError):
        return None


def discover_network(
    session: Session,
    org_id: uuid.UUID,
    *,
    cidr: str,
    timeout_seconds: int = 2,
) -> dict:
    """Ping-sweep a CIDR (max /24, 256 hosts) and upsert responding hosts
    as network devices. Returns discovery counts plus which probe was
    used and whether SNMP enrichment was available."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ValidationError(f"Invalid CIDR: {cidr}") from exc
    if network.prefixlen < 24:
        raise ValidationError("CIDR larger than /24 is not supported (max 256 hosts)")
    if timeout_seconds < 1 or timeout_seconds > 10:
        raise ValidationError("timeout_seconds must be between 1 and 10")

    hosts = [str(ip) for ip in network]
    use_icmp = _ping_available()
    probe_method = "icmp" if use_icmp else "tcp"

    def probe(host: str) -> bool:
        return _ping_host(host, timeout_seconds) if use_icmp else _tcp_probe(host)

    now = datetime.now(UTC)
    discovered = 0
    updated = 0
    unreachable = 0
    with ThreadPoolExecutor(max_workers=32) as pool:
        futures = {pool.submit(probe, host): host for host in hosts}
        done, _ = wait(futures, timeout=DISCOVERY_OVERALL_TIMEOUT_SECONDS)
        results: dict[str, bool] = {}
        for future in done:
            host = futures[future]
            try:
                results[host] = bool(future.result())
            except Exception:
                results[host] = False
        for host in hosts:
            if host not in results:
                results[host] = False  # overall cap hit: treat as unreachable

    for host, alive in results.items():
        if not alive:
            unreachable += 1
            continue
        existing = session.execute(
            select(NetworkDevice)
            .where(
                NetworkDevice.organization_id == org_id,
                NetworkDevice.ip_address == host,
            )
            # IPs are reused over time (DHCP): take the most recently seen
            # device for the address rather than raising on duplicates.
            .order_by(NetworkDevice.last_seen_at.desc().nulls_last(), NetworkDevice.created_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        if existing is not None:
            existing.status = "up"
            existing.last_seen_at = now
            updated += 1
            continue
        hostname = _reverse_dns(host) or host
        sysdescr = snmp_sysdescr(host)
        device = NetworkDevice(
            organization_id=org_id,
            hostname=hostname,
            ip_address=host,
            device_type="other",
            os_version=sysdescr,
            status="up",
            last_seen_at=now,
        )
        session.add(device)
        discovered += 1
    session.flush()
    return {
        "discovered": discovered,
        "updated": updated,
        "unreachable": unreachable,
        "snmp_available": snmp_available(),
        "snmp_note": None if snmp_available() else "snmp_unavailable",
        "probe_method": probe_method,
    }
