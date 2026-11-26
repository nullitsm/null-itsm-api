"""Integrations framework: provider registry, config + encrypted
credentials, and test-connection.

The framework is provider-agnostic: an ``integrations`` row names a
provider slug from :data:`PROVIDER_REGISTRY` and carries a JSON config.
No per-vendor code path exists for storage — the only provider-specific
behaviour is the test-connection check, and that is generic too: when the
config names a ``test_url`` (or, for the ``generic_http`` provider, a
``base_url``) the check performs a real HTTP request against it and
reports the honest outcome. A provider with no reachable check and no
driver stays ``disconnected`` — an integration is never presented as live
until a successful call has been verified.

Priority providers (per docs/DATA_MODEL.md Phase 4): Entra ID, Intune,
Greenbone, Defender, Slack, Teams, GitHub, Power BI. Their registry
entries describe them; drivers for them are NOT built here — only the
generic HTTP provider proves the framework end to end.
"""

from __future__ import annotations

from datetime import datetime, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.integrations import Integration, IntegrationCredential
from app.services.identity_service import decrypt_secret, encrypt_secret

UTC = timezone.utc

# Registry: slug -> {label, description, docs_url}. The framework reads
# this; adding a provider is a registry entry, not a code branch.
PROVIDER_REGISTRY: dict[str, dict[str, str]] = {
    "entra_id": {
        "label": "Microsoft Entra ID",
        "description": "Identity provider: directory sync, SSO, SCIM provisioning.",
    },
    "intune": {
        "label": "Microsoft Intune",
        "description": "Device management: managed devices, compliance policies.",
    },
    "greenbone": {
        "label": "Greenbone / OpenVAS",
        "description": "Vulnerability scanning engine (see the vuln engine in Phase 3).",
    },
    "defender": {
        "label": "Microsoft Defender",
        "description": "Endpoint detection and response signals.",
    },
    "slack": {
        "label": "Slack",
        "description": "Notifications and chatops in Slack channels.",
    },
    "teams": {
        "label": "Microsoft Teams",
        "description": "Notifications and chatops in Teams channels.",
    },
    "github": {
        "label": "GitHub",
        "description": "Repository and workflow events.",
    },
    "power_bi": {
        "label": "Power BI",
        "description": "Embedded analytics and report datasets.",
    },
    "generic_http": {
        "label": "Generic HTTP",
        "description": "Any HTTP service: test-connection performs a real request "
        "against the configured base_url / test_url.",
    },
}

# Statuses.
STATUS_DISCONNECTED = "disconnected"
STATUS_CONNECTED = "connected"
STATUS_ERROR = "error"


def _now() -> datetime:
    return datetime.now(UTC)


def list_providers() -> list[dict]:
    """The registry, as API-safe dicts (slug + label + description)."""
    return [{"slug": slug, **info} for slug, info in PROVIDER_REGISTRY.items()]


def validate_provider(provider: str) -> None:
    if provider not in PROVIDER_REGISTRY:
        raise ValueError(f"Unknown provider: {provider}")


def set_credential(session: Session, integration: Integration, key_name: str, value: str) -> IntegrationCredential:
    """Store (or replace) one Fernet-encrypted credential for an integration.

    Fails closed (SecretStorageError) when no field-encryption key is
    configured — secrets are never stored plaintext.
    """
    encrypted = encrypt_secret(value)
    existing = session.execute(
        select(IntegrationCredential).where(
            IntegrationCredential.integration_id == integration.id,
            IntegrationCredential.key_name == key_name,
        )
    ).scalar_one_or_none()
    if existing is not None:
        existing.value_encrypted = encrypted
        session.flush()
        return existing
    row = IntegrationCredential(
        organization_id=integration.organization_id,
        integration_id=integration.id,
        key_name=key_name,
        value_encrypted=encrypted,
    )
    session.add(row)
    session.flush()
    return row


def get_credential(session: Session, integration: Integration, key_name: str) -> str | None:
    """Decrypt one stored credential, or None when it was never set."""
    row = session.execute(
        select(IntegrationCredential).where(
            IntegrationCredential.integration_id == integration.id,
            IntegrationCredential.key_name == key_name,
        )
    ).scalar_one_or_none()
    if row is None:
        return None
    return decrypt_secret(row.value_encrypted)


def list_credential_names(session: Session, integration: Integration) -> list[str]:
    """Credential key names only — values are never listed or returned."""
    rows = session.execute(
        select(IntegrationCredential.key_name).where(IntegrationCredential.integration_id == integration.id)
    ).all()
    return [r[0] for r in rows]


def _check_url(integration: Integration) -> str | None:
    """The URL a test-connection should hit, or None when the config
    names no checkable endpoint."""
    config = integration.config or {}
    if isinstance(config.get("test_url"), str) and config["test_url"]:
        return config["test_url"]
    if integration.provider == "generic_http" and isinstance(config.get("base_url"), str) and config["base_url"]:
        return config["base_url"]
    return None


def test_connection(
    session: Session,
    integration: Integration,
    *,
    transport: httpx.BaseTransport | None = None,
) -> Integration:
    """Perform a real connection check and record the honest result.

    - Config names a URL (``test_url``, or ``base_url`` for generic_http):
      a real HTTP GET is issued. 2xx → ``connected``; any other status or
      transport error → ``error`` with the reason in ``last_error``.
    - Otherwise (priority providers with no driver and no configured
      URL): no check is possible — the integration stays ``disconnected``
      with ``last_error`` saying so plainly. It is never marked live.
    ``last_tested_at`` / ``last_test_result`` are always updated.
    """
    integration.last_tested_at = _now()
    url = _check_url(integration)
    if url is None:
        integration.status = STATUS_DISCONNECTED
        integration.last_test_result = "failed"
        integration.last_error = (
            f"no connection check available for provider '{integration.provider}': "
            "configure a test_url in the integration config, or wait for a driver"
        )
        session.flush()
        return integration
    try:
        # trust_env=False: the check goes direct, never through an egress
        # proxy from the environment (this VM's NO_PROXY contains a bare
        # "::1" entry that httpx cannot even parse into a Client).
        with httpx.Client(timeout=10.0, transport=transport, trust_env=False) as client:
            response = client.get(url)
    except httpx.HTTPError as exc:
        integration.status = STATUS_ERROR
        integration.last_test_result = "failed"
        integration.last_error = f"{type(exc).__name__}: {exc}"
        session.flush()
        return integration
    if 200 <= response.status_code < 300:
        integration.status = STATUS_CONNECTED
        integration.last_test_result = "success"
        integration.last_error = None
    else:
        integration.status = STATUS_ERROR
        integration.last_test_result = "failed"
        integration.last_error = f"test endpoint returned HTTP {response.status_code}"
    session.flush()
    return integration
