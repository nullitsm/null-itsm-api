"""Identity / directory + asset-lifecycle models (Phase 2, migration 0007).

Every table here is tenant-owned: ``organization_id`` FK to organizations
(CASCADE, NOT NULL, indexed) plus ``created_at`` / ``updated_at``.
Row-Level Security policies live in migration 0007 (standard org-scoped
ALL policy, except ``asset_lifecycle_events`` which is append-only:
SELECT + INSERT only, like the audit log).

Secrets: SCIM tokens, service-account credentials, and API credentials are
stored ONLY as SHA-256 hashes — the raw secret is shown once at creation
and never persisted. IdP / license secrets that must be reversible are
Fernet-encrypted through ``app.crypto`` (imported lazily in the services
that need it; that module lands with migration 0006 — until it exists,
storing an encrypted secret fails closed with an honest error).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, created_at_col, tz_col, updated_at_col, uuid_pk


def _org_fk() -> Mapped[uuid.UUID]:
    return mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )


def _user_fk(nullable: bool = True) -> Mapped[uuid.UUID | None]:
    return mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=nullable)


# --- Identity providers ----------------------------------------------------


class IdentityProvider(Base):
    __tablename__ = "identity_providers"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    # saml | oidc
    type: Mapped[str] = mapped_column(String(20), nullable=False)
    # active | inactive
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="active")
    saml_entity_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    saml_sso_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    saml_certificate: Mapped[str | None] = mapped_column(Text, nullable=True)
    oidc_issuer: Mapped[str | None] = mapped_column(String(500), nullable=True)
    oidc_client_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Fernet-encrypted (app.crypto, lazy import); never plaintext.
    oidc_client_secret_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_xml: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_default: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    created_by_id: Mapped[uuid.UUID | None] = _user_fk()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class ScimToken(Base):
    __tablename__ = "scim_tokens"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    # SHA-256 hex of the raw token. The raw token is shown once at creation.
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    scopes: Mapped[list] = mapped_column(JSONB, nullable=False, server_default='["users:read", "users:write"]')
    expires_at: Mapped[datetime | None] = tz_col()
    revoked_at: Mapped[datetime | None] = tz_col()
    last_used_at: Mapped[datetime | None] = tz_col()
    created_by_id: Mapped[uuid.UUID | None] = _user_fk()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class DirectorySyncRun(Base):
    __tablename__ = "directory_sync_runs"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    provider_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("identity_providers.id", ondelete="SET NULL"), nullable=True, index=True
    )
    # entra | ad | ldap | scim
    source: Mapped[str] = mapped_column(String(20), nullable=False)
    # running | completed | failed
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="running")
    users_created: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    users_updated: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    users_deprovisioned: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    groups_synced: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # started_at is created_at by convention (see task spec).
    completed_at: Mapped[datetime | None] = tz_col()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class DirectoryGroup(Base):
    __tablename__ = "directory_groups"
    __table_args__ = (
        UniqueConstraint("organization_id", "provider_id", "external_id", name="uq_dir_group_org_provider_ext"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    provider_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("identity_providers.id", ondelete="SET NULL"), nullable=True, index=True
    )
    external_id: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    member_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    # Group -> role mapping: members of this group hold this role.
    role_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("roles.id", ondelete="SET NULL"), nullable=True, index=True
    )
    last_synced_at: Mapped[datetime | None] = tz_col()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class DirectoryGroupMembership(Base):
    __tablename__ = "directory_group_memberships"
    __table_args__ = (UniqueConstraint("group_id", "user_id", name="uq_dir_group_membership"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    group_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("directory_groups.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    external_user_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class ServiceAccount(Base):
    __tablename__ = "service_accounts"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    # SHA-256 hex of the generated secret; the secret is shown once.
    credential_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    scopes: Mapped[list] = mapped_column(JSONB, nullable=False, server_default="[]")
    expires_at: Mapped[datetime | None] = tz_col()
    revoked_at: Mapped[datetime | None] = tz_col()
    last_used_at: Mapped[datetime | None] = tz_col()
    created_by_id: Mapped[uuid.UUID | None] = _user_fk()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class ApiCredential(Base):
    __tablename__ = "api_credentials"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    # SHA-256 hex of the generated credential; shown once at creation.
    credential_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    scopes: Mapped[list] = mapped_column(JSONB, nullable=False, server_default="[]")
    expires_at: Mapped[datetime | None] = tz_col()
    revoked_at: Mapped[datetime | None] = tz_col()
    last_used_at: Mapped[datetime | None] = tz_col()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class AccessCertification(Base):
    __tablename__ = "access_certifications"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    reviewer_id: Mapped[uuid.UUID | None] = _user_fk()
    # pending | in_progress | completed
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="pending")
    # {"departments": [...], "roles": [<role id strings>]}
    scope: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    due_at: Mapped[datetime | None] = tz_col()
    completed_at: Mapped[datetime | None] = tz_col()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class CertificationItem(Base):
    __tablename__ = "certification_items"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    certification_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("access_certifications.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("roles.id", ondelete="SET NULL"), nullable=True, index=True
    )
    # pending | approved | revoked
    decision: Mapped[str] = mapped_column(String(20), nullable=False, server_default="pending")
    decided_by_id: Mapped[uuid.UUID | None] = _user_fk()
    decided_at: Mapped[datetime | None] = tz_col()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class TemporaryAccessGrant(Base):
    __tablename__ = "temporary_access_grants"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("roles.id", ondelete="CASCADE"), nullable=False, index=True
    )
    granted_by_id: Mapped[uuid.UUID | None] = _user_fk()
    reason: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    expires_at: Mapped[datetime] = tz_col(nullable=False)
    revoked_at: Mapped[datetime | None] = tz_col()
    # active | expired | revoked
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="active")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


# --- Assets --------------------------------------------------------------


class Vendor(Base):
    __tablename__ = "vendors"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    contact_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    contact_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    website: Mapped[str | None] = mapped_column(String(500), nullable=True)
    notes: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class PurchaseOrder(Base):
    __tablename__ = "purchase_orders"
    __table_args__ = (UniqueConstraint("organization_id", "po_number", name="uq_po_org_number"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    vendor_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("vendors.id", ondelete="CASCADE"), nullable=False, index=True
    )
    po_number: Mapped[str] = mapped_column(String(100), nullable=False)
    # draft | ordered | received | cancelled
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="draft")
    total_cents: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    ordered_at: Mapped[datetime | None] = tz_col()
    received_at: Mapped[datetime | None] = tz_col()
    notes: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class Warranty(Base):
    __tablename__ = "warranties"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    vendor_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("vendors.id", ondelete="SET NULL"), nullable=True, index=True
    )
    starts_at: Mapped[datetime | None] = tz_col()
    ends_at: Mapped[datetime | None] = tz_col()
    coverage: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    # active | expired
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="active")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("organization_id", "asset_tag", name="uq_asset_org_tag"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    asset_tag: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # laptop | desktop | monitor | phone | server | other
    type: Mapped[str] = mapped_column(String(20), nullable=False, server_default="laptop")
    serial_number: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # in_stock | assigned | in_repair | lost | stolen | retired | disposed
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="in_stock")
    assigned_to_id: Mapped[uuid.UUID | None] = _user_fk()
    department: Mapped[str] = mapped_column(String(100), nullable=False, server_default="")
    location: Mapped[str] = mapped_column(String(255), nullable=False, server_default="")
    purchase_order_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("purchase_orders.id", ondelete="SET NULL"), nullable=True, index=True
    )
    purchase_date: Mapped[datetime | None] = tz_col()
    purchase_price_cents: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # straight_line | declining | none
    depreciation_method: Mapped[str] = mapped_column(String(20), nullable=False, server_default="straight_line")
    depreciation_years: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Snapshot; the live value is recomputed on read (see asset_service).
    current_value_cents: Mapped[int | None] = mapped_column(Integer, nullable=True)
    notes: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class AssetLifecycleEvent(Base):
    __tablename__ = "asset_lifecycle_events"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # procured | assigned | checked_out | checked_in | transferred | lost |
    # stolen | recovered | retired | disposed | repaired | depreciated
    event_type: Mapped[str] = mapped_column(String(20), nullable=False)
    actor_id: Mapped[uuid.UUID | None] = _user_fk()
    notes: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    meta: Mapped[dict] = mapped_column("metadata", JSONB, nullable=False, server_default="{}")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class AssetAssignment(Base):
    __tablename__ = "asset_assignments"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # assigned_at is created_at by convention (see task spec).
    returned_at: Mapped[datetime | None] = tz_col()
    # active | returned
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="active")
    assigned_by_id: Mapped[uuid.UUID | None] = _user_fk()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class License(Base):
    __tablename__ = "licenses"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    vendor: Mapped[str] = mapped_column(String(255), nullable=False, server_default="")
    # Fernet-encrypted (app.crypto, lazy import); never plaintext.
    license_key_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    total_seats: Mapped[int] = mapped_column(Integer, nullable=False, server_default="1")
    expires_at: Mapped[datetime | None] = tz_col()
    cost_cents: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    # active | expired | exceeded
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="active")
    compliance_notes: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class LicenseAssignment(Base):
    __tablename__ = "license_assignments"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    license_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("licenses.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=True, index=True
    )
    # assigned_at is created_at by convention (see task spec).
    revoked_at: Mapped[datetime | None] = tz_col()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()
