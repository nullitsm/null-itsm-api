"""CMDB + network operations models (Phase 3, migration 0012).

Every table here is tenant-owned: ``organization_id`` FK to organizations
(CASCADE, NOT NULL, indexed) plus ``created_at`` / ``updated_at``.
Row-Level Security policies live in migration 0012 (standard org-scoped
ALL policy, except ``network_metrics`` which is append-only telemetry:
SELECT + INSERT only).

CMDB: ``configuration_items`` are the managed entities (servers,
workstations, network devices, applications, services, databases); they
link to Phase 2 ``assets`` and Phase 3 ``endpoints`` where those exist.
``ci_relationships`` is the dependency graph (source depends on / runs
on / hosts / connects to / uses / manages target) — a CI never relates
to itself (enforced by a CHECK constraint).

Network ops: ``network_devices`` + ``network_interfaces`` are the
monitored inventory; ``topology_links`` the discovered topology;
``service_dependencies`` maps named services to the CIs they depend on;
``network_metrics`` is append-only telemetry (CPU, memory, bandwidth,
latency, availability); ``network_events`` records syslog / outage /
certificate / DNS / DHCP events; ``certificates`` tracks TLS certificate
expiry per hostname.

SNMP community strings that must be reversible are Fernet-encrypted
through ``app.crypto`` (imported lazily in the services that need it);
storing one fails closed with an honest error when no field-encryption
key is configured.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, created_at_col, tz_col, updated_at_col, uuid_pk


def _org_fk() -> Mapped[uuid.UUID]:
    return mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )


def _user_fk(nullable: bool = True) -> Mapped[uuid.UUID | None]:
    return mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=nullable)


class ConfigurationItem(Base):
    """A CMDB configuration item."""

    __tablename__ = "configuration_items"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # server | workstation | network_device | application | service |
    # database | other
    ci_type: Mapped[str] = mapped_column(String(50), nullable=False, server_default="other")
    # active | inactive | retired
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="active")
    owner_id: Mapped[uuid.UUID | None] = _user_fk()
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    endpoint_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("endpoints.id", ondelete="SET NULL"), nullable=True, index=True
    )
    attributes: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class CiRelationship(Base):
    """One edge in the CMDB dependency graph."""

    __tablename__ = "ci_relationships"
    __table_args__ = (
        UniqueConstraint("source_ci_id", "target_ci_id", "relationship_type", name="uq_ci_rel_source_target_type"),
        CheckConstraint("source_ci_id <> target_ci_id", name="ck_ci_rel_no_self_link"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    source_ci_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("configuration_items.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_ci_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("configuration_items.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # depends_on | runs_on | hosts | connects_to | uses | manages
    relationship_type: Mapped[str] = mapped_column(String(50), nullable=False)
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class NetworkDevice(Base):
    """A monitored network device (switch, router, firewall, server, AP)."""

    __tablename__ = "network_devices"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    # switch | router | firewall | server | access_point | other
    device_type: Mapped[str] = mapped_column(String(50), nullable=False, server_default="other")
    vendor: Mapped[str | None] = mapped_column(String(100), nullable=True)
    model: Mapped[str | None] = mapped_column(String(100), nullable=True)
    os_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    # Fernet-encrypted (app.crypto, lazy import); never plaintext.
    snmp_community_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    snmp_version: Mapped[str | None] = mapped_column(String(20), nullable=True, server_default="v2c")
    # up | down | unknown
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="unknown")
    last_seen_at: Mapped[datetime | None] = tz_col()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class NetworkInterface(Base):
    """One interface on a monitored network device."""

    __tablename__ = "network_interfaces"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("network_devices.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    if_index: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    mac_address: Mapped[str | None] = mapped_column(String(17), nullable=True)
    speed_mbps: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # up | down | unknown
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="unknown")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class TopologyLink(Base):
    """One discovered link between two network devices (optionally between
    specific interfaces)."""

    __tablename__ = "topology_links"
    __table_args__ = (
        UniqueConstraint(
            "source_device_id",
            "source_interface_id",
            "target_device_id",
            "target_interface_id",
            name="uq_topology_link_devices_interfaces",
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    source_device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("network_devices.id", ondelete="CASCADE"), nullable=False, index=True
    )
    source_interface_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("network_interfaces.id", ondelete="SET NULL"), nullable=True, index=True
    )
    target_device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("network_devices.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_interface_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("network_interfaces.id", ondelete="SET NULL"), nullable=True, index=True
    )
    link_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class ServiceDependency(Base):
    """A named service's dependency on a configuration item."""

    __tablename__ = "service_dependencies"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    service_name: Mapped[str] = mapped_column(String(255), nullable=False)
    ci_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("configuration_items.id", ondelete="CASCADE"), nullable=True, index=True
    )
    # depends_on | hosts | uses
    dependency_type: Mapped[str] = mapped_column(String(50), nullable=False, server_default="depends_on")
    # low | medium | high | critical
    criticality: Mapped[str] = mapped_column(String(20), nullable=False, server_default="medium")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class NetworkMetric(Base):
    """One telemetry sample. Append-only (SELECT + INSERT only)."""

    __tablename__ = "network_metrics"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("network_devices.id", ondelete="CASCADE"), nullable=False, index=True
    )
    interface_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("network_interfaces.id", ondelete="SET NULL"), nullable=True, index=True
    )
    # cpu | memory | bandwidth_in | bandwidth_out | latency | availability
    metric_type: Mapped[str] = mapped_column(String(50), nullable=False)
    value: Mapped[float] = mapped_column(Numeric, nullable=False)
    recorded_at: Mapped[datetime | None] = tz_col()
    created_at: Mapped[datetime] = created_at_col()


class NetworkEvent(Base):
    """A network event: syslog line, outage, certificate expiry, DNS/DHCP
    notice, SNMP trap, or other. Events are recorded, never invented —
    an outage row exists only because a monitor or a collector reported
    it (or an admin recorded it).
    """

    __tablename__ = "network_events"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("network_devices.id", ondelete="SET NULL"), nullable=True, index=True
    )
    # syslog | outage | cert_expiry | dns | dhcp | snmp_trap | other
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    # info | warning | critical
    severity: Mapped[str] = mapped_column(String(20), nullable=False, server_default="info")
    message: Mapped[str] = mapped_column(Text, nullable=False)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    occurred_at: Mapped[datetime | None] = tz_col()
    acknowledged_at: Mapped[datetime | None] = tz_col()
    acknowledged_by_id: Mapped[uuid.UUID | None] = _user_fk()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class Certificate(Base):
    """A TLS certificate tracked for expiry monitoring."""

    __tablename__ = "certificates"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    issuer: Mapped[str | None] = mapped_column(String(255), nullable=True)
    expires_at: Mapped[datetime | None] = tz_col()
    # valid | expiring | expired | error
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="valid")
    last_checked_at: Mapped[datetime | None] = tz_col()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()
