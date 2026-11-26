"""Webhook delivery: signing, real HTTP POST, per-attempt records, retry.

``deliver_event(session, org_id, event, payload, ...)`` is the entry point
the rest of the system calls with (org_id, event, payload) — the
coordinator wires event emission at integration. It fans out to every
ACTIVE webhook in the org subscribed to that event type.

Delivery is real HTTP (httpx) — never a stub. Every attempt writes a
``webhook_deliveries`` row (status, HTTP code, response snippet,
attempted_at); failures retry with backoff and each retry is its own row.
The payload is HMAC-SHA256 signed with the webhook's Fernet-decrypted
secret and sent as ``X-Null-Signature: sha256=<hex>``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import tenant_session
from app.models.integrations import Webhook, WebhookDelivery
from app.services.identity_service import SecretStorageError, decrypt_secret, encrypt_secret

logger = logging.getLogger("null.webhooks")

UTC = timezone.utc

# Event types a webhook may subscribe to. Keep this list in sync with the
# events the system actually emits; an unknown type is rejected at create.
WEBHOOK_EVENTS = {
    "ticket.created",
    "ticket.updated",
    "ticket.resolved",
    "change.created",
    "change.approved",
    "vulnerability.found",
    "endpoint.enrolled",
    "incident.declared",
}

# Default retry backoff (seconds) between attempts: 1s, then 5s.
DEFAULT_BACKOFF_SECONDS = (1.0, 5.0)
MAX_ATTEMPTS = 3
SIGNATURE_HEADER = "X-Null-Signature"
RESPONSE_SNIPPET_LIMIT = 500


class WebhookError(ValueError):
    """Invalid webhook input (bad event type, bad URL, ...)."""


def _now() -> datetime:
    return datetime.now(UTC)


def validate_event_type(event_type: str) -> None:
    if event_type not in WEBHOOK_EVENTS:
        raise WebhookError(f"Unknown event type: {event_type}")


def validate_target_url(target_url: str) -> None:
    parsed = urlparse(target_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise WebhookError("target_url must be an http(s) URL")


def generate_secret() -> str:
    """A fresh random signing secret (returned once at webhook creation)."""
    return secrets.token_urlsafe(32)


def sign_payload(secret: str, body: bytes) -> str:
    """HMAC-SHA256 hex signature of the raw request body."""
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def create_webhook(
    session: Session,
    *,
    organization_id: uuid.UUID,
    name: str,
    event_type: str,
    target_url: str,
    secret: str | None,
    created_by_id: uuid.UUID | None,
) -> tuple[Webhook, str]:
    """Create a webhook; returns (webhook, raw_secret).

    When no secret is supplied one is generated. The secret is stored
    Fernet-encrypted and the raw value is returned exactly once — the
    caller (router) shows it in the create response and never again.
    Fails closed (SecretStorageError) when no field-encryption key is
    configured.
    """
    validate_event_type(event_type)
    validate_target_url(target_url)
    raw_secret = secret or generate_secret()
    webhook = Webhook(
        organization_id=organization_id,
        name=name,
        event_type=event_type,
        target_url=target_url,
        secret_encrypted=encrypt_secret(raw_secret),
        is_active=True,
        created_by_id=created_by_id,
    )
    session.add(webhook)
    session.flush()
    return webhook, raw_secret


def _build_body(organization_id: uuid.UUID, event: str, payload: dict) -> bytes:
    envelope = {
        "event": event,
        "organization_id": str(organization_id),
        "delivered_at": _now().isoformat(),
        "data": payload,
    }
    return json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _record_attempt(
    session: Session,
    *,
    webhook: Webhook,
    event: str,
    payload: dict,
    attempt_number: int,
    status: str,
    http_status: int | None,
    response_snippet: str | None,
    error: str | None,
    next_retry_at: datetime | None,
) -> WebhookDelivery:
    delivery = WebhookDelivery(
        organization_id=webhook.organization_id,
        webhook_id=webhook.id,
        event_type=event,
        payload=payload,
        attempt_number=attempt_number,
        status=status,
        http_status=http_status,
        response_snippet=response_snippet,
        error=error,
        attempted_at=_now(),
        next_retry_at=next_retry_at,
    )
    session.add(delivery)
    session.flush()
    return delivery


def deliver_webhook(
    session: Session,
    webhook: Webhook,
    event: str,
    payload: dict,
    *,
    transport: httpx.BaseTransport | None = None,
    max_attempts: int = MAX_ATTEMPTS,
    backoff_seconds: tuple[float, ...] = DEFAULT_BACKOFF_SECONDS,
) -> list[WebhookDelivery]:
    """Deliver one event to one webhook, with retry on failure.

    Returns every attempt row (one per try). A 2xx response is success;
    any other status or any transport error is a failure that retries
    (up to ``max_attempts``) with ``backoff_seconds`` between tries.
    ``transport`` exists so tests can point httpx at a real local HTTP
    server through a custom transport — the delivery path is always real
    HTTP, never a mocked-out send.
    """
    if not webhook.secret_encrypted:
        return [
            _record_attempt(
                session,
                webhook=webhook,
                event=event,
                payload=payload,
                attempt_number=1,
                status="failed",
                http_status=None,
                response_snippet=None,
                error="webhook has no signing secret configured",
                next_retry_at=None,
            )
        ]
    try:
        secret = decrypt_secret(webhook.secret_encrypted)
    except SecretStorageError as exc:
        return [
            _record_attempt(
                session,
                webhook=webhook,
                event=event,
                payload=payload,
                attempt_number=1,
                status="failed",
                http_status=None,
                response_snippet=None,
                error=f"signing secret unavailable: {exc}",
                next_retry_at=None,
            )
        ]

    body = _build_body(webhook.organization_id, event, payload)
    signature = sign_payload(secret, body)
    headers = {"Content-Type": "application/json", SIGNATURE_HEADER: signature}
    attempts: list[WebhookDelivery] = []
    for attempt in range(1, max_attempts + 1):
        http_status: int | None = None
        snippet: str | None = None
        error: str | None = None
        try:
            # trust_env=False: deliveries go direct, never through an egress
            # proxy from the environment (this VM's NO_PROXY contains a bare
            # "::1" entry that httpx cannot even parse into a Client).
            with httpx.Client(timeout=10.0, transport=transport, trust_env=False) as client:
                response = client.post(webhook.target_url, content=body, headers=headers)
            http_status = response.status_code
            snippet = response.text[:RESPONSE_SNIPPET_LIMIT] if response.text else None
            if 200 <= response.status_code < 300:
                attempts.append(
                    _record_attempt(
                        session,
                        webhook=webhook,
                        event=event,
                        payload=payload,
                        attempt_number=attempt,
                        status="success",
                        http_status=http_status,
                        response_snippet=snippet,
                        error=None,
                        next_retry_at=None,
                    )
                )
                return attempts
            error = f"receiver returned HTTP {response.status_code}"
        except httpx.HTTPError as exc:
            error = f"{type(exc).__name__}: {exc}"
        is_last = attempt >= max_attempts
        next_retry = (
            None if is_last else _now() + timedelta(seconds=backoff_seconds[min(attempt - 1, len(backoff_seconds) - 1)])
        )
        attempts.append(
            _record_attempt(
                session,
                webhook=webhook,
                event=event,
                payload=payload,
                attempt_number=attempt,
                status="failed",
                http_status=http_status,
                response_snippet=snippet,
                error=error,
                next_retry_at=next_retry,
            )
        )
        if not is_last:
            time.sleep(backoff_seconds[min(attempt - 1, len(backoff_seconds) - 1)])
    return attempts


def deliver_event(
    session: Session,
    org_id: uuid.UUID,
    event: str,
    payload: dict,
    *,
    transport: httpx.BaseTransport | None = None,
    max_attempts: int = MAX_ATTEMPTS,
    backoff_seconds: tuple[float, ...] = DEFAULT_BACKOFF_SECONDS,
) -> list[WebhookDelivery]:
    """Fan one event out to every ACTIVE webhook in the org for it.

    Returns all attempt rows across all matching webhooks (empty list
    when nothing subscribes — delivery to zero subscribers is not an
    error). Raises WebhookError for an unknown event type so a caller
    emitting a typo'd event finds out immediately.
    """
    validate_event_type(event)
    webhooks = (
        session.execute(
            select(Webhook).where(
                Webhook.organization_id == org_id,
                Webhook.event_type == event,
                Webhook.is_active.is_(True),
            )
        )
        .scalars()
        .all()
    )
    deliveries: list[WebhookDelivery] = []
    for webhook in webhooks:
        deliveries.extend(
            deliver_webhook(
                session,
                webhook,
                event,
                payload,
                transport=transport,
                max_attempts=max_attempts,
                backoff_seconds=backoff_seconds,
            )
        )
    return deliveries


def emit_event(
    org_id: uuid.UUID,
    event: str,
    payload: dict,
    *,
    user_id: uuid.UUID | None = None,
    transport: httpx.BaseTransport | None = None,
) -> list[WebhookDelivery]:
    """Best-effort post-commit webhook fan-out for one event.

    Call AFTER the caller's transaction commits, with plain-data
    payloads built before the commit. Opens its own tenant session
    (the request session's RLS context is SET LOCAL and dies at
    commit, so the request session cannot deliver after commit),
    fans out through :func:`deliver_event`, and commits the delivery
    rows. Never raises: a delivery failure is already recorded as a
    failed ``webhook_deliveries`` row by :func:`deliver_webhook`, and
    any unexpected error is logged and swallowed so a webhook problem
    can never fail the write that triggered the event. Returns the
    attempt rows, or ``[]`` when nothing subscribes or emission fails.

    Known limitation: delivery is synchronous in-process, so a slow or
    failing subscriber delays the response that triggered the event
    (bounded by the 10s client timeout and the retry backoff). Async
    delivery is a future improvement, not a silent behavior change.
    """
    try:
        with tenant_session(org_id, user_id) as session:
            return deliver_event(session, org_id, event, payload, transport=transport)
    except Exception:
        logger.exception("webhook emission failed for event %s in org %s", event, org_id)
        return []

