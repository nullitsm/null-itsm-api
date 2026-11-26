"""Centralized email delivery service.

One provider abstraction for all outbound mail. Development behaviour
(``email_provider="none"``, the default): emails are logged, never
sent, and recorded in the local dev outbox (``dev_email_outbox`` table)
so invitation links can be read during local testing. Configured
behaviour (``email_provider="resend"``): the message is sent for real
through the Resend API and the attempt is recorded on an
``email_deliveries`` row (provider message id on success, error +
attempt count on failure). The API key comes from the environment
(``NULL_RESEND_API_KEY``) when set; on this VM, when no key is in the
environment, the key comes from the Muse dynamic-credential surrogate
instead (see ``app.services.resend_surrogate``): the backend never
sees the real key, it fetches a fresh ``hsurr:`` surrogate per send
and the egress proxy swaps it for the real key. API keys and
surrogates live on the backend only and are never logged or returned.

Invitation and password-reset emails contain a one-time link; the token
itself is never logged and only its SHA-256 hash is stored.
"""

from __future__ import annotations

import base64
import html as html_lib
import logging
import os
import smtplib
import ssl
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import timezone
from functools import lru_cache

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.services import resend_surrogate

logger = logging.getLogger("null.email")

UTC = timezone.utc

RESEND_API_URL = "https://api.resend.com/emails"
RESEND_TIMEOUT_SECONDS = 30.0

# NULL editorial palette (ivory / ink / purple).
IVORY = "#F2EBDD"
IVORY_LIGHT = "#FBF8F1"
INK = "#171614"
PURPLE = "#6B4FA1"
PURPLE_BUTTON = "#A17ACB"


class EmailDeliveryError(Exception):
    """The provider refused or failed the submission."""


class EmailConfigurationError(EmailDeliveryError):
    """The provider is selected but misconfigured (e.g. no API key)."""


@dataclass
class DeliveryResult:
    """The accurate outcome of one delivery attempt.

    ``delivered`` is True ONLY when the provider accepted the message.
    In dev mode ``delivered`` is False and ``dev_recorded`` is True —
    the message was recorded locally, never sent.
    """

    delivered: bool
    dev_recorded: bool
    provider: str
    provider_message_id: str | None
    error: str | None
    delivery_id: str | None = None


# --- Provider abstraction ---------------------------------------------------


class EmailProvider(ABC):
    """A transactional email provider. ``send`` returns the provider's
    message id, or raises EmailDeliveryError.

    ``attachments`` (optional) is a list of ``{"filename": str,
    "content": bytes}`` dicts; providers that cannot attach (dev
    outbox) accept and ignore it.
    """

    name: str = "unknown"

    @abstractmethod
    def send(
        self,
        *,
        to: str,
        subject: str,
        html_body: str,
        text_body: str,
        attachments: list[dict] | None = None,
    ) -> str:
        raise NotImplementedError


# Browser UA (Chrome on Linux) — required to pass Cloudflare, which
# sits in front of api.resend.com and refuses the default Python user
# agent with HTTP 403 / error code 1010. The same string the
# custom.resend connector's verified test-send helper uses.
BROWSER_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)


def _egress_proxy_url() -> str | None:
    """The VM's egress proxy URL, read explicitly from the environment.

    The URL carries egress credentials; it is used only to build the
    client and is never logged. None on a host without one (direct
    egress), which is the normal production case.
    """
    return (
        os.environ.get("HTTPS_PROXY")
        or os.environ.get("https_proxy")
        or os.environ.get("HTTP_PROXY")
        or os.environ.get("http_proxy")
    )


@lru_cache(maxsize=1)
def _system_ssl_context() -> ssl.SSLContext:
    """The system CA store (not certifi).

    The egress proxy terminates TLS with the Hatch CA, which is
    installed in the system store (``/usr/local/share/ca-certificates``).
    httpx's default (certifi) does not know it, so a default client
    fails every Resend request with CERTIFICATE_VERIFY_FAILED. The
    system context still verifies (CERT_REQUIRED + hostname check); it
    only changes WHERE the trust anchors come from.
    """
    return ssl.create_default_context()


def _resend_client(timeout: float, *, require_proxy: bool = False) -> httpx.Client:
    """httpx client for Resend: browser UA, explicit proxy, no env parsing.

    ``trust_env=False`` avoids the NO_PROXY ``::1`` parse failure (httpx
    0.28 cannot parse this VM's bare ``::1`` entry); the proxy is passed
    explicitly instead, so requests still route through the egress proxy
    that performs the surrogate swap. TLS is verified against the
    system CA store (see ``_system_ssl_context``).
    """
    proxy = _egress_proxy_url()
    if require_proxy and proxy is None:
        raise EmailConfigurationError(
            "Surrogate email delivery requires the egress proxy (HTTPS_PROXY). "
            "On a host without the Muse egress proxy, set NULL_RESEND_API_KEY instead."
        )
    return httpx.Client(
        timeout=timeout,
        headers={"User-Agent": BROWSER_USER_AGENT},
        trust_env=False,
        proxy=proxy,
        verify=_system_ssl_context(),
    )


def _post_resend(
    client: httpx.Client,
    *,
    bearer: str,
    from_address: str,
    to: str,
    subject: str,
    html_body: str,
    text_body: str,
    timeout: float,
    attachments: list[dict] | None = None,
) -> str:
    """One POST to the Resend API. Returns the provider message id.

    The bearer value (real key or surrogate) is never included in an
    error message or a log line.
    """
    payload = {
        "from": from_address,
        "to": [to],
        "subject": subject,
        "html": html_body,
        "text": text_body,
    }
    if attachments:
        # Resend takes base64 content per attachment; the filename
        # (e.g. report.csv) is what the recipient's mail client shows.
        payload["attachments"] = [
            {
                "filename": item["filename"],
                "content": base64.b64encode(item["content"]).decode("ascii"),
            }
            for item in attachments
        ]
    try:
        response = client.post(
            RESEND_API_URL,
            json=payload,
            headers={
                "Authorization": f"Bearer {bearer}",
                "Content-Type": "application/json",
                "User-Agent": BROWSER_USER_AGENT,
            },
            timeout=timeout,
        )
    except httpx.HTTPError as exc:
        raise EmailDeliveryError(f"Resend request failed: {exc}") from exc
    if response.status_code >= 400:
        snippet = response.text[:300].replace("\n", " ")
        raise EmailDeliveryError(f"Resend rejected the message (HTTP {response.status_code}): {snippet}")
    try:
        message_id = response.json().get("id")
    except ValueError as exc:
        raise EmailDeliveryError("Resend response was not valid JSON") from exc
    if not message_id:
        raise EmailDeliveryError("Resend accepted the message but returned no message id")
    return str(message_id)


class ResendProvider(EmailProvider):
    """Resend (https://resend.com) via its HTTP API, key from the
    environment (``NULL_RESEND_API_KEY``).

    No SDK dependency — a plain httpx POST. The API key is never
    included in an error message or a log line.

    Two transport facts, both verified against the live API (Nov 25,
    2026, custom.resend connector):
    - Cloudflare sits in front of api.resend.com and refuses the
      default Python user agent with HTTP 403 / error code 1010 before
      the request reaches Resend, so every request carries a browser
      User-Agent. The header is set both on the client and per
      request, so a caller-injected client cannot accidentally send
      the httpx default.
    - This VM's ``NO_PROXY`` contains a bare ``::1`` entry that httpx
      0.28 cannot parse, so a client built with the default
      ``trust_env=True`` raises ``InvalidURL`` before any request.
      The client is built with ``trust_env=False`` and the egress
      proxy (when one is configured) is passed explicitly, so
      delivery still routes through the proxy.
    - The egress proxy terminates TLS with the Hatch CA (installed in
      the system store); httpx's default certifi bundle does not know
      it, so the client verifies against the system CA store instead
      (``_system_ssl_context``). Verification stays on.
    """

    name = "resend"

    USER_AGENT = BROWSER_USER_AGENT

    def __init__(
        self,
        api_key: str,
        from_address: str,
        client: httpx.Client | None = None,
        timeout: float = RESEND_TIMEOUT_SECONDS,
    ) -> None:
        self.api_key = api_key
        self.from_address = from_address
        self._client = client
        self._owns_client = client is None
        self.timeout = timeout

    def send(
        self,
        *,
        to: str,
        subject: str,
        html_body: str,
        text_body: str,
        attachments: list[dict] | None = None,
    ) -> str:
        if not self.api_key:
            raise EmailConfigurationError(
                "Resend API key is not configured (NULL_RESEND_API_KEY). "
                "Set the key via the secure channel; delivery is not attempted without it."
            )
        client = self._client or _resend_client(self.timeout)
        try:
            return _post_resend(
                client,
                bearer=self.api_key,
                from_address=self.from_address,
                to=to,
                subject=subject,
                html_body=html_body,
                text_body=text_body,
                timeout=self.timeout,
                attachments=attachments,
            )
        finally:
            if self._owns_client:
                client.close()


class SurrogateResendProvider(EmailProvider):
    """Resend via the authd surrogate (Muse-hosted backend, this VM).

    The real key is never available to this process. Each send fetches
    a fresh ``hsurr:`` surrogate (see ``resend_surrogate``) and sends
    it as the Bearer token THROUGH the egress proxy, which swaps it for
    the real key on the approved request to api.resend.com. The
    surrogate is never logged or stored. No egress proxy configured
    means surrogate mode cannot work — that is a configuration error,
    not a delivery failure, so the caller fails loudly (the invite
    endpoints answer 503 and create nothing).
    """

    name = "resend"

    def __init__(
        self,
        from_address: str,
        client: httpx.Client | None = None,
        timeout: float = RESEND_TIMEOUT_SECONDS,
        surrogate_fetcher=None,
    ) -> None:
        self.from_address = from_address
        self._client = client
        self._owns_client = client is None
        self.timeout = timeout
        # Injectable for tests; production always fetches fresh.
        self._surrogate_fetcher = surrogate_fetcher or resend_surrogate.fetch_resend_surrogate

    def send(
        self,
        *,
        to: str,
        subject: str,
        html_body: str,
        text_body: str,
        attachments: list[dict] | None = None,
    ) -> str:
        try:
            surrogate = self._surrogate_fetcher()
        except resend_surrogate.SurrogateUnavailable as exc:
            raise EmailConfigurationError(f"Resend surrogate unavailable: {exc}") from exc
        client = self._client or _resend_client(self.timeout, require_proxy=True)
        try:
            return _post_resend(
                client,
                bearer=surrogate,
                from_address=self.from_address,
                to=to,
                subject=subject,
                html_body=html_body,
                text_body=text_body,
                timeout=self.timeout,
                attachments=attachments,
            )
        finally:
            if self._owns_client:
                client.close()


class DevOutboxProvider(EmailProvider):
    """Development mode: no network, no delivery. The caller records the
    message in the dev outbox; this provider only marks the mode."""

    name = "dev"

    def send(
        self,
        *,
        to: str,
        subject: str,
        html_body: str,
        text_body: str,
        attachments: list[dict] | None = None,
    ) -> str:
        return ""


# Test hook: tests set a fake provider here; production never touches it.
_provider_override: EmailProvider | None = None


def set_provider_override(provider: EmailProvider | None) -> None:
    """Override provider resolution (tests only)."""
    global _provider_override
    _provider_override = provider


def resolve_provider(settings=None) -> EmailProvider:
    """Resolve the configured provider. Dev ("none") is the default.

    Key precedence for "resend": an API key in the environment wins;
    without one, the Muse-hosted surrogate channel is the key source
    (``SurrogateResendProvider`` fetches a fresh surrogate per send).
    A host with neither fails loudly at send time instead of silently
    falling back to the dev outbox.
    """
    if _provider_override is not None:
        return _provider_override
    config = settings or get_settings()
    if config.email_provider == "resend":
        if config.resend_api_key:
            return ResendProvider(api_key=config.resend_api_key, from_address=config.email_from)
        return SurrogateResendProvider(from_address=config.email_from)
    return DevOutboxProvider()


def email_delivery_configured(settings=None) -> bool:
    """True only when real delivery is configured (provider + key source).

    The invitation API hides the dev accept link unless this is False.
    A selected-but-keyless provider with no surrogate channel counts as
    NOT configured here — the send itself then fails loudly with
    EmailConfigurationError instead of silently falling back to the
    outbox.
    """
    config = settings or get_settings()
    if config.email_provider != "resend":
        return False
    if config.resend_api_key:
        return True
    # Surrogate channel present (authd socket): delivery is configured;
    # the send itself is the proof (a missing credential fails loudly).
    return resend_surrogate.surrogate_channel_available()


# --- Templates (NULL editorial: ivory / black / purple) ----------------------


def _invitation_html(
    *,
    eyebrow: str,
    headline: str,
    recipient_name: str,
    lines: list[str],
    accept_url: str,
    org_name: str,
) -> str:
    esc = html_lib.escape
    body_lines = "".join(f"<p style=\"margin: 0 0 12px 0;\">{line}</p>" for line in lines)
    # Adjacent literals (one per HTML line) so no source line exceeds the
    # 120-char limit; the rendered bytes are exactly the lines below.
    return (
        "<!DOCTYPE html>\n"
        "<html>\n"
        f'<body style="margin: 0; padding: 0; background-color: {IVORY}; '
        f"font-family: Georgia, 'Times New Roman', serif; color: {INK};\">\n"
        f'  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        f'style="background-color: {IVORY};">\n'
        '    <tr><td align="center" style="padding: 32px 16px;">\n'
        f'      <table role="presentation" width="560" cellpadding="0" cellspacing="0" '
        f'style="background-color: {IVORY_LIGHT}; border: 1px solid {INK};">\n'
        '        <tr><td style="padding: 28px 32px 8px 32px;">\n'
        '          <p style="margin: 0; font-size: 26px; letter-spacing: 6px; font-weight: bold;">NULL</p>\n'
        f'          <p style="margin: 2px 0 0 0; font-size: 11px; letter-spacing: 3px; '
        f'color: {PURPLE};">UNIFIED IT OPERATIONS &amp; SECURITY</p>\n'
        "        </td></tr>\n"
        '        <tr><td style="padding: 20px 32px 8px 32px;">\n'
        f'          <p style="margin: 0; font-size: 11px; letter-spacing: 3px; color: {PURPLE};">'
        f"{esc(eyebrow)}</p>\n"
        '          <h1 style="margin: 8px 0 0 0; font-size: 24px; line-height: 1.3;">'
        f"{esc(headline)}</h1>\n"
        "        </td></tr>\n"
        '        <tr><td style="padding: 12px 32px; font-size: 15px; line-height: 1.6;">\n'
        f'          <p style="margin: 0 0 12px 0;">Hi {esc(recipient_name)},</p>\n'
        f"          {body_lines}\n"
        "        </td></tr>\n"
        '        <tr><td align="center" style="padding: 8px 32px 20px 32px;">\n'
        f'          <a href="{esc(accept_url)}" style="display: inline-block; '
        f"background-color: {PURPLE_BUTTON}; color: #ffffff; text-decoration: none; "
        "font-family: Arial, Helvetica, sans-serif; font-size: 15px; font-weight: bold; "
        'padding: 14px 32px; border-radius: 4px;">Accept Invitation</a>\n'
        "        </td></tr>\n"
        '        <tr><td style="padding: 0 32px 20px 32px; font-size: 13px; line-height: 1.6; color: #4a4741;">\n'
        "          <p style=\"margin: 0 0 8px 0;\">If the button doesn&rsquo;t work, copy and paste "
        "this link into your browser:</p>\n"
        f'          <p style="margin: 0; word-break: break-all;"><a href="{esc(accept_url)}" '
        f'style="color: {PURPLE};">{esc(accept_url)}</a></p>\n'
        "        </td></tr>\n"
        '        <tr><td style="padding: 0 32px 28px 32px; font-size: 13px; line-height: 1.6; color: #4a4741;">\n'
        "          <p style=\"margin: 0;\">This invitation expires in 48 hours and can only be used once, "
        f"for this email address. If you weren&rsquo;t expecting it, you can ignore it — or contact {esc(org_name)} "
        "to let them know.</p>\n"
        "        </td></tr>\n"
        '        <tr><td style="padding: 16px 32px; border-top: 1px solid #d8d0bd; font-size: 12px; color: #6b675f;">\n'
        "          <p style=\"margin: 0;\">NULL ITSM — Unified IT Operations &amp; Security Management. "
        "This is an automated message; please don&rsquo;t reply to it.</p>\n"
        "        </td></tr>\n"
        "      </table>\n"
        "    </td></tr>\n"
        "  </table>\n"
        "</body>\n"
        "</html>"
    )


def render_org_invitation_email(
    *,
    org_name: str,
    recipient_name: str,
    role_names: list[str],
    inviter_name: str,
    accept_url: str,
    expires_hours: int = 48,
) -> tuple[str, str, str]:
    """NULL-branded org invitation. Returns (subject, html, text)."""
    subject = "You've been invited to join NULL ITSM"
    roles = ", ".join(role_names) if role_names else "Technician"
    lines = [
        f"You have been invited to join <strong>{html_lib.escape(org_name)}</strong> on NULL ITSM.",
        f"Your assigned role: <strong>{html_lib.escape(roles)}</strong>.",
        f"Invited by: <strong>{html_lib.escape(inviter_name)}</strong>.",
        f"This invitation expires in {expires_hours} hours and can only be used once, for this email address.",
    ]
    html_body = _invitation_html(
        eyebrow="INVITATION",
        headline="You're invited to join NULL ITSM",
        recipient_name=recipient_name,
        lines=lines,
        accept_url=accept_url,
        org_name=org_name,
    )
    text_body = (
        f"Hi {recipient_name},\n\n"
        f"You have been invited to join {org_name} on NULL ITSM.\n"
        f"Your assigned role: {roles}.\n"
        f"Invited by: {inviter_name}.\n"
        f"This invitation expires in {expires_hours} hours and can only be used once, for this email address.\n\n"
        f"Accept your invitation here: {accept_url}\n\n"
        f"If you weren't expecting this, you can ignore it — or contact {org_name} to let them know.\n\n"
        "NULL ITSM — Unified IT Operations & Security Management. "
        "This is an automated message; please don't reply to it.\n"
    )
    return subject, html_body, text_body


def render_platform_invitation_email(
    *,
    recipient_name: str,
    role_name: str,
    inviter_name: str,
    accept_url: str,
    expires_hours: int = 48,
) -> tuple[str, str, str]:
    """NULL-branded platform-admin invitation. Returns (subject, html, text)."""
    subject = "You've been invited to join NULL ITSM Platform Administration"
    lines = [
        "You have been invited to join the <strong>NULL platform administration</strong> "
        "environment as a platform administrator.",
        f"Your assigned role: <strong>{html_lib.escape(role_name)}</strong>.",
        f"Invited by: <strong>{html_lib.escape(inviter_name)}</strong>.",
        f"This invitation expires in {expires_hours} hours and can only be used once, for this email address.",
    ]
    html_body = _invitation_html(
        eyebrow="PLATFORM INVITATION",
        headline="You're invited to join NULL platform administration",
        recipient_name=recipient_name,
        lines=lines,
        accept_url=accept_url,
        org_name="NULL",
    )
    text_body = (
        f"Hi {recipient_name},\n\n"
        "You have been invited to join the NULL platform administration "
        "environment as a platform administrator.\n"
        f"Your assigned role: {role_name}.\n"
        f"Invited by: {inviter_name}.\n"
        f"This invitation expires in {expires_hours} hours and can only be used once, for this email address.\n\n"
        f"Accept your invitation here: {accept_url}\n\n"
        "If you weren't expecting this, you can ignore it — or contact NULL to let them know.\n\n"
        "NULL ITSM — Unified IT Operations & Security Management. "
        "This is an automated message; please don't reply to it.\n"
    )
    return subject, html_body, text_body


# --- Dev outbox + log-only senders (unchanged interface) ----------------------


def record_outbox(
    session: Session,
    organization_id: uuid.UUID | None,
    scope: str,
    to_email: str,
    subject: str,
    body: str,
) -> None:
    """Record an email in the local dev outbox (testing only).

    The caller must have the RLS context set (org context for org mail,
    platform context for platform mail). The body may contain the
    invitation accept link — the outbox is a database record for local
    testing, not a log line. Never call this in production: with a
    provider configured the mail is sent for real and nothing is
    recorded in the outbox.
    """
    from app.models.registration import DevEmailOutbox

    session.add(
        DevEmailOutbox(
            organization_id=organization_id,
            scope=scope,
            to_email=to_email,
            subject=subject,
            body=body,
        )
    )


def send_email(to: str, subject: str, body: str, log_body: bool = True) -> None:
    """Send (dev: log) an email. The body must not contain raw tokens
    unless log_body is False — invitation bodies carry the accept link,
    so they are logged redacted."""
    if log_body:
        logger.info("EMAIL to=%s subject=%s\n%s", to, subject, body)
    else:
        logger.info("EMAIL to=%s subject=%s (body contains a one-time link; token redacted)", to, subject)


def send_reply_email(to: str, subject: str, body: str) -> bool:
    """Send a ticket reply. Returns True when it went out over SMTP.

    When no SMTP host is configured this falls back to the dev behaviour
    (logged, never sent) and returns False — the caller still records
    the outbound message row either way.
    """
    settings = get_settings()
    if not settings.smtp_host:
        send_email(to, subject, body)
        return False
    message = f"From: {settings.email_from}\r\nTo: {to}\r\nSubject: {subject}\r\n\r\n{body}"
    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=30) as smtp:
            smtp.ehlo()
            try:
                smtp.starttls()
                smtp.ehlo()
            except smtplib.SMTPException:
                pass  # server does not offer STARTTLS; continue plain
            if settings.smtp_user:
                smtp.login(settings.smtp_user, settings.smtp_password)
            smtp.sendmail(settings.email_from, [to], message)
    except (smtplib.SMTPException, OSError) as exc:
        logger.warning("SMTP reply to %s failed: %s", to, exc)
        return False
    logger.info("EMAIL (smtp) to=%s subject=%s", to, subject)
    return True


# --- Delivery recording + retries ---------------------------------------------


def _enqueue_retry(
    delivery_id: uuid.UUID,
    countdown_seconds: int,
    *,
    organization_id: uuid.UUID | None = None,
    scope: str = "org",
    created_by_id: uuid.UUID | None = None,
) -> None:
    """Enqueue a provider retry (Celery). Imported lazily: the task
    module imports this service's app, so a top-level import would be
    circular. Tests monkeypatch this helper to observe the enqueue.
    Tenant scope travels with the task args so the worker can open the
    right RLS-scoped session without a pre-read."""
    from app.tasks.email_tasks import retry_email_delivery

    retry_email_delivery.apply_async(
        args=[str(delivery_id)],
        kwargs={
            "organization_id": str(organization_id) if organization_id is not None else None,
            "scope": scope,
            "created_by_id": str(created_by_id) if created_by_id is not None else None,
        },
        countdown=countdown_seconds,
    )


def _record_delivery(
    session: Session,
    *,
    organization_id: uuid.UUID | None,
    scope: str,
    to: str,
    subject: str,
    template: str,
    provider_name: str,
    status: str,
    provider_message_id: str | None,
    attempts: int,
    last_error: str | None,
    org_invitation_id: uuid.UUID | None,
    platform_invitation_id: uuid.UUID | None,
    created_by_id: uuid.UUID | None,
    html_body: str,
    text_body: str,
):
    from app.models.email import EmailDelivery

    row = EmailDelivery(
        organization_id=organization_id,
        scope=scope,
        org_invitation_id=org_invitation_id,
        platform_invitation_id=platform_invitation_id,
        to_email=to,
        subject=subject,
        template=template,
        provider=provider_name,
        provider_message_id=provider_message_id,
        status=status,
        attempts=attempts,
        last_error=last_error,
        created_by_id=created_by_id,
        html_body=html_body,
        text_body=text_body,
    )
    session.add(row)
    session.flush()
    return row


def deliver_email(
    session: Session | None,
    *,
    organization_id: uuid.UUID | None,
    scope: str,
    to: str,
    subject: str,
    html_body: str,
    text_body: str,
    template: str,
    org_invitation_id: uuid.UUID | None = None,
    platform_invitation_id: uuid.UUID | None = None,
    created_by_id: uuid.UUID | None = None,
    provider: EmailProvider | None = None,
    attachments: list[dict] | None = None,
    retry: bool = True,
) -> DeliveryResult:
    """Deliver one email through the configured provider and record the
    attempt. Never raises for a provider failure — the failure is
    returned (and a retry is enqueued) so the caller reports it
    accurately instead of claiming success. A configuration error (a
    provider selected with no API key) DOES raise EmailConfigurationError
    so the caller fails loudly instead of recording a bogus failure.

    With ``session=None`` the message is still attempted, but no
    delivery row or outbox record is written (used by password reset,
    which runs without a tenant session).

    ``attachments`` is a list of ``{"filename", "content"}`` dicts
    (bytes); providers that cannot attach ignore them. Pass
    ``retry=False`` when the payload cannot be rebuilt from the stored
    bodies (e.g. a generated CSV attachment): a failed send is then
    recorded but not retried, and the next scheduled run re-sends it.
    """
    from app.models.email import STATUS_DEV_RECORDED, STATUS_FAILED, STATUS_SENT

    resolved = provider or resolve_provider()
    if resolved.name == "dev":
        # Development mode: nothing is sent. Log (redacted) + outbox.
        send_email(to, subject, text_body, log_body=False)
        delivery_id = None
        if session is not None:
            record_outbox(session, organization_id, scope, to, subject, text_body)
            row = _record_delivery(
                session,
                organization_id=organization_id,
                scope=scope,
                to=to,
                subject=subject,
                template=template,
                provider_name="dev",
                status=STATUS_DEV_RECORDED,
                provider_message_id=None,
                attempts=1,
                last_error=None,
                org_invitation_id=org_invitation_id,
                platform_invitation_id=platform_invitation_id,
                created_by_id=created_by_id,
                html_body=html_body,
                text_body=text_body,
            )
            delivery_id = str(row.id)
        return DeliveryResult(
            delivered=False, dev_recorded=True, provider="dev",
            provider_message_id=None, error=None, delivery_id=delivery_id,
        )

    try:
        message_id = resolved.send(
            to=to, subject=subject, html_body=html_body, text_body=text_body, attachments=attachments
        )
    except EmailConfigurationError:
        # Misconfiguration is an operator error, not a delivery failure:
        # fail loudly so the caller reports it (the invite endpoints
        # answer 503) instead of recording a failed delivery for a
        # message that was never attempted.
        raise
    except EmailDeliveryError as exc:
        logger.warning("Email delivery to %s failed (%s): %s", to, resolved.name, exc)
        delivery_id = None
        if session is not None:
            row = _record_delivery(
                session,
                organization_id=organization_id,
                scope=scope,
                to=to,
                subject=subject,
                template=template,
                provider_name=resolved.name,
                status=STATUS_FAILED,
                provider_message_id=None,
                attempts=1,
                last_error=str(exc)[:500],
                org_invitation_id=org_invitation_id,
                platform_invitation_id=platform_invitation_id,
                created_by_id=created_by_id,
                html_body=html_body,
                text_body=text_body,
            )
            delivery_id = str(row.id)
            max_attempts = get_settings().email_retry_max_attempts
            if retry and max_attempts > 1:
                _enqueue_retry(
                    row.id,
                    countdown_seconds=60,
                    organization_id=organization_id,
                    scope=scope,
                    created_by_id=created_by_id,
                )
        return DeliveryResult(
            delivered=False, dev_recorded=False, provider=resolved.name,
            provider_message_id=None, error=str(exc)[:500], delivery_id=delivery_id,
        )

    logger.info("EMAIL (%s) to=%s subject=%s id=%s", resolved.name, to, subject, message_id)
    delivery_id = None
    if session is not None:
        row = _record_delivery(
            session,
            organization_id=organization_id,
            scope=scope,
            to=to,
            subject=subject,
            template=template,
            provider_name=resolved.name,
            status=STATUS_SENT,
            provider_message_id=message_id,
            attempts=1,
            last_error=None,
            org_invitation_id=org_invitation_id,
            platform_invitation_id=platform_invitation_id,
            created_by_id=created_by_id,
            html_body=html_body,
            text_body=text_body,
        )
        delivery_id = str(row.id)
    return DeliveryResult(
        delivered=True, dev_recorded=False, provider=resolved.name,
        provider_message_id=message_id, error=None, delivery_id=delivery_id,
    )


def latest_delivery_for_invitation(
    session: Session,
    *,
    org_invitation_id: uuid.UUID | None = None,
    platform_invitation_id: uuid.UUID | None = None,
):
    """Newest delivery row for an invitation (for the API's delivery
    status), or None when nothing was ever attempted."""
    from app.models.email import EmailDelivery

    stmt = select(EmailDelivery).order_by(EmailDelivery.created_at.desc())
    if org_invitation_id is not None:
        stmt = stmt.where(EmailDelivery.org_invitation_id == org_invitation_id)
    elif platform_invitation_id is not None:
        stmt = stmt.where(EmailDelivery.platform_invitation_id == platform_invitation_id)
    else:
        return None
    return session.execute(stmt).scalars().first()


def delivery_to_dict(delivery) -> dict | None:
    """Serialize a delivery row for the API. Bodies are never exposed."""
    if delivery is None:
        return None
    return {
        "status": delivery.status,
        "provider": delivery.provider,
        "provider_message_id": delivery.provider_message_id,
        "attempts": delivery.attempts,
        "last_error": delivery.last_error,
        "delivered": delivery.status == "sent",
        "dev_recorded": delivery.status == "dev_recorded",
    }


# --- Invitation + password-reset senders --------------------------------------


def send_invitation_email(
    to: str,
    org_name: str,
    accept_url: str,
    session: Session | None = None,
    organization_id: uuid.UUID | None = None,
    *,
    recipient_name: str = "",
    role_names: list[str] | None = None,
    inviter_name: str = "",
    org_invitation_id: uuid.UUID | None = None,
    created_by_id: uuid.UUID | None = None,
    provider: EmailProvider | None = None,
) -> DeliveryResult:
    """Deliver an org invitation. Single-use link, 48 hours."""
    subject, html_body, text_body = render_org_invitation_email(
        org_name=org_name,
        recipient_name=recipient_name or to,
        role_names=role_names or [],
        inviter_name=inviter_name,
        accept_url=accept_url,
    )
    return deliver_email(
        session,
        organization_id=organization_id,
        scope="org",
        to=to,
        subject=subject,
        html_body=html_body,
        text_body=text_body,
        template="org_invitation",
        org_invitation_id=org_invitation_id,
        created_by_id=created_by_id,
        provider=provider,
    )


def send_platform_invitation_email(
    to: str,
    accept_url: str,
    session: Session | None = None,
    *,
    recipient_name: str = "",
    role_name: str = "Platform Administrator",
    inviter_name: str = "",
    platform_invitation_id: uuid.UUID | None = None,
    created_by_id: uuid.UUID | None = None,
    provider: EmailProvider | None = None,
) -> DeliveryResult:
    """Deliver a platform-admin invitation. Single-use link, 48 hours."""
    subject, html_body, text_body = render_platform_invitation_email(
        recipient_name=recipient_name or to,
        role_name=role_name,
        inviter_name=inviter_name,
        accept_url=accept_url,
    )
    return deliver_email(
        session,
        organization_id=None,
        scope="platform",
        to=to,
        subject=subject,
        html_body=html_body,
        text_body=text_body,
        template="platform_invitation",
        platform_invitation_id=platform_invitation_id,
        created_by_id=created_by_id,
        provider=provider,
    )


def send_password_reset_email(to: str, reset_url: str) -> DeliveryResult:
    """Deliver a password reset. Runs without a tenant session, so no
    delivery row is recorded — the provider attempt still happens (or
    the dev log line) and the result is returned."""
    subject = "Reset your NULL ITSM password"
    text_body = (
        "You requested a password reset.\n"
        f"Reset your password here: {reset_url}\n"
        "This link expires in 60 minutes. If you did not request this, ignore this email."
    )
    html_body = (
        "<p>You requested a password reset.</p>"
        f"<p>Reset your password here: <a href=\"{html_lib.escape(reset_url)}\">{html_lib.escape(reset_url)}</a></p>"
        "<p>This link expires in 60 minutes. If you did not request this, ignore this email.</p>"
    )
    return deliver_email(
        None,
        organization_id=None,
        scope="org",
        to=to,
        subject=subject,
        html_body=html_body,
        text_body=text_body,
        template="password_reset",
    )
