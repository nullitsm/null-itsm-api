"""Webhooks, integrations framework, and API keys (Phase 4 workstream C,
migration 0016).

- ``webhooks`` / ``webhook_deliveries``: org-scoped event subscriptions.
  The signing secret is Fernet-encrypted (``app.crypto`` via
  ``app.services.identity_service.encrypt_secret``); never plaintext, never
  returned after creation.
- ``integrations`` / ``integration_credentials``: a provider REGISTRY, not
  hardcoded vendors. An ``integrations`` row names a provider (priority:
  Entra ID, Intune, Greenbone, Defender, Slack, Teams, GitHub, Power BI,
  plus the generic ``generic_http`` provider that proves the framework)
  with a JSON config and a status that stays ``disconnected`` until a real
  test-connection call succeeds. Credentials are Fernet-encrypted rows.
- ``api_keys``: developer-portal keys. Only the SHA-256 hash is stored;
  the raw key is shown once at creation and never again.

Every table here is tenant-owned: ``organization_id`` FK to organizations
(CASCADE, NOT NULL, indexed) plus ``created_at`` / ``updated_at``.
Row-Level Security policies live in migration 0016 (standard org-scoped
ALL policy). ``webhook_deliveries`` is append-only evidence (SELECT +
INSERT only) — a delivery record is never edited after the fact; a retry
writes a NEW row.
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


class Webhook(Base):
    """One org's subscription to an event type, delivered by HTTP POST."""

    __tablename__ = "webhooks"
    __table_args__ = (UniqueConstraint("organization_id", "name", name="uq_webhooks_org_name"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    # e.g. ticket.created — validated against WEBHOOK_EVENTS in the service.
    event_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    # Fernet-encrypted HMAC signing secret (app.crypto, lazy import); never
    # plaintext, never returned by the API after creation.
    secret_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    created_by_id: Mapped[uuid.UUID | None] = _user_fk()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class WebhookDelivery(Base):
    """One delivery attempt. Append-only: a retry writes a new row.

    ``status``: pending | success | failed. ``http_status`` is the
    receiver's HTTP code (NULL when the request never completed, e.g.
    connection refused — ``error`` then carries the reason).
    ``response_snippet`` is the first 500 chars of the response body.
    """

    __tablename__ = "webhook_deliveries"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    webhook_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("webhooks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False, server_default="1")
    # pending | success | failed
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="pending")
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_snippet: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    attempted_at: Mapped[datetime] = created_at_col()
    next_retry_at: Mapped[datetime | None] = tz_col()


class Integration(Base):
    """One configured third-party integration for one org.

    ``provider`` is a registry slug (see
    ``app.services.integration_service.PROVIDER_REGISTRY``) — the framework
    never branches on a hardcoded vendor list for storage. ``config`` is
    provider-specific, non-secret settings (base URL, tenant id, channel,
    ...). Secrets live in ``integration_credentials``, never here.
    ``status``: disconnected | connected | error — ``disconnected`` until a
    real test-connection call succeeds; never claimed live otherwise.
    """

    __tablename__ = "integrations"
    __table_args__ = (
        UniqueConstraint("organization_id", "provider", "name", name="uq_integrations_org_provider_name"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    provider: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    config: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    # disconnected | connected | error
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="disconnected")
    last_tested_at: Mapped[datetime | None] = tz_col()
    # success | failed | not_tested
    last_test_result: Mapped[str] = mapped_column(String(20), nullable=False, server_default="not_tested")
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by_id: Mapped[uuid.UUID | None] = _user_fk()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class IntegrationCredential(Base):
    """One Fernet-encrypted secret for an integration (token, client
    secret, ...). ``key_name`` identifies the secret's role (e.g.
    ``api_token``); the value is never returned by the API."""

    __tablename__ = "integration_credentials"
    __table_args__ = (
        UniqueConstraint("integration_id", "key_name", name="uq_integration_credentials_integration_key"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    integration_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("integrations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    key_name: Mapped[str] = mapped_column(String(100), nullable=False)
    # Fernet-encrypted (app.crypto, lazy import); never plaintext.
    value_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class ApiKey(Base):
    """One developer-portal API key for one org.

    Only the SHA-256 hash is stored (``key_hash``, unique) plus a short
    ``key_prefix`` for display (e.g. ``null_a1b2c3d4``). The raw key is
    shown once at creation and is unrecoverable afterwards. ``scopes``
    are permission codes from the org catalog; ``expires_at`` / ``revoked_at``
    (NULL = active); ``last_used_at`` is updated on each authenticated call.
    """

    __tablename__ = "api_keys"
    __table_args__ = (UniqueConstraint("key_hash", name="uq_api_keys_key_hash"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(20), nullable=False)
    scopes: Mapped[list] = mapped_column(JSONB, nullable=False, server_default="[]")
    expires_at: Mapped[datetime | None] = tz_col()
    revoked_at: Mapped[datetime | None] = tz_col()
    last_used_at: Mapped[datetime | None] = tz_col()
    created_by_id: Mapped[uuid.UUID | None] = _user_fk()
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()
