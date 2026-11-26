"""Developer-portal API keys.

Keys are opaque (``null_`` + random token), stored ONLY as SHA-256 hashes
(``ApiKey.key_hash``); the raw key is shown once at creation and is
unrecoverable afterwards. Scopes are org permission codes from the
catalog — an unknown scope is rejected at creation. Optional expiry;
revocation sets ``revoked_at``. ``last_used_at`` is updated on each
authenticated call.

Lookup before any RLS context exists goes through the SECURITY DEFINER
function ``auth_get_api_key_by_hash`` (migration 0016), mirroring the
SCIM-token pattern in migration 0007: it answers the hash question only
and reveals nothing else.
"""

from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.models.integrations import ApiKey
from app.permissions import PERMISSIONS
from app.services.identity_service import hash_secret

UTC = timezone.utc

KEY_PREFIX = "null_"
VALID_SCOPES = {code for code, _, _ in PERMISSIONS}


@dataclass
class ApiKeyPrincipal:
    """The caller authenticated by an API key: their org + granted scopes."""

    organization_id: uuid.UUID
    key_id: uuid.UUID
    key_name: str
    scopes: list[str]

    def has(self, scope: str) -> bool:
        return scope in self.scopes


class ApiKeyError(ValueError):
    """Invalid API-key input (bad scope, bad name, ...)."""


class ApiKeyAuthError(Exception):
    """The presented key does not authenticate (unknown / revoked / expired)."""


def _now() -> datetime:
    return datetime.now(UTC)


def generate_raw_key() -> str:
    return KEY_PREFIX + secrets.token_urlsafe(32)


def create_api_key(
    session: Session,
    *,
    organization_id: uuid.UUID,
    name: str,
    scopes: list[str],
    expires_at: datetime | None,
    created_by_id: uuid.UUID | None,
) -> tuple[ApiKey, str]:
    """Create a key; returns (row, raw_key). The raw key is shown once."""
    unknown = sorted(set(scopes) - VALID_SCOPES)
    if unknown:
        raise ApiKeyError(f"Unknown scope(s): {', '.join(unknown)}")
    raw_key = generate_raw_key()
    row = ApiKey(
        organization_id=organization_id,
        name=name,
        key_hash=hash_secret(raw_key),
        key_prefix=raw_key[:12],
        scopes=sorted(set(scopes)),
        expires_at=expires_at,
        created_by_id=created_by_id,
    )
    session.add(row)
    session.flush()
    return row, raw_key


def _lookup_by_hash(session: Session, key_hash: str) -> dict | None:
    row = session.execute(text("SELECT * FROM auth_get_api_key_by_hash(:h)"), {"h": key_hash}).mappings().first()
    return dict(row) if row else None


def authenticate_api_key(session: Session, raw_key: str) -> ApiKeyPrincipal:
    """Resolve a raw key to its principal, or raise ApiKeyAuthError.

    Also stamps ``last_used_at`` on the key row. The caller owns the
    transaction (the RLS context is set to the key's org first, so the
    UPDATE passes the org-scoped policy). An empty / malformed key is
    rejected without a database round trip.
    """
    if not raw_key or not raw_key.startswith(KEY_PREFIX):
        raise ApiKeyAuthError("Invalid API key")
    found = _lookup_by_hash(session, hash_secret(raw_key))
    if found is None:
        raise ApiKeyAuthError("Invalid API key")
    if found.get("revoked_at") is not None:
        raise ApiKeyAuthError("API key revoked")
    expires_at = found.get("expires_at")
    if expires_at is not None and expires_at <= _now():
        raise ApiKeyAuthError("API key expired")
    org_id = uuid.UUID(str(found["organization_id"]))
    key_id = uuid.UUID(str(found["id"]))
    # Scope the session to the key's org, then stamp last use.
    from app.database import set_rls_context

    set_rls_context(session, org_id, None)
    key = session.get(ApiKey, key_id)
    if key is not None:
        key.last_used_at = _now()
        session.flush()
    return ApiKeyPrincipal(
        organization_id=org_id,
        key_id=key_id,
        key_name=found.get("name") or "",
        scopes=list(found.get("scopes") or []),
    )


def revoke_api_key(session: Session, key: ApiKey) -> ApiKey:
    """Revoke a key (idempotent: an already-revoked key stays revoked)."""
    if key.revoked_at is None:
        key.revoked_at = _now()
        session.flush()
    return key
