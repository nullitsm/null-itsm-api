"""Real email delivery for invitations (Nov 25, 2026 follow-up spec).

Covers the centralized email service: NULL-branded invitation templates,
the Resend provider boundary (mocked with httpx MockTransport — no real
network, no real key), dev vs configured modes and the accept_url rule,
the browser User-Agent Cloudflare requires, accurate failure reporting,
retries via the Celery task, idempotency (duplicate pending invites +
the partial unique index backstop), and delivery status in the
invitation APIs. The one acceptance item NOT covered here is a real
email reaching a real external inbox — that is blocked on the provider
key being injected into the backend process (see docs/EMAIL.md); the
key itself is verified working via the custom.resend connector.
"""

from __future__ import annotations

import ssl
import uuid

import httpx
import psycopg.errors
import pytest

from app.config import get_settings
from app.services import email as email_service
from app.services.email import (
    EmailConfigurationError,
    ResendProvider,
    SurrogateResendProvider,
    render_org_invitation_email,
    render_platform_invitation_email,
    resolve_provider,
)
from app.tasks.email_tasks import retry_email_delivery
from tests.conftest import set_rls
from tests.test_registration import _invite, _platform_role_id, _register, _uniq

TEST_KEY = "re_test_key_only"


# --- Fixtures -----------------------------------------------------------------


@pytest.fixture()
def configured_email(monkeypatch):
    """Pretend a Resend key is configured (settings only — the provider
    itself is still the mock set by the provider fixtures)."""
    settings = get_settings()
    monkeypatch.setattr(settings, "email_provider", "resend")
    monkeypatch.setattr(settings, "resend_api_key", TEST_KEY)
    monkeypatch.setattr(settings, "email_from", "no-reply@nullitsm.test")
    yield settings


@pytest.fixture()
def keyless_email(monkeypatch):
    """Provider selected but no key — the misconfiguration case.

    The surrogate channel is disabled too: on this VM authd is present
    and the credential is registered, so without this the send would
    actually go out through the surrogate instead of failing loudly.
    """

    def _no_channel(*args, **kwargs):
        raise email_service.resend_surrogate.SurrogateUnavailable("no channel")

    settings = get_settings()
    monkeypatch.setattr(settings, "email_provider", "resend")
    monkeypatch.setattr(settings, "resend_api_key", "")
    monkeypatch.setattr(email_service.resend_surrogate, "surrogate_channel_available", lambda: False)
    monkeypatch.setattr(email_service.resend_surrogate, "fetch_resend_surrogate", _no_channel)
    yield settings


@pytest.fixture()
def surrogate_email(monkeypatch):
    """Provider selected, no key, surrogate channel available.

    The fetcher returns a fake surrogate; the HTTP call is still the
    mock, so nothing reaches the network.
    """
    settings = get_settings()
    monkeypatch.setattr(settings, "email_provider", "resend")
    monkeypatch.setattr(settings, "resend_api_key", "")
    monkeypatch.setattr(email_service.resend_surrogate, "surrogate_channel_available", lambda: True)
    monkeypatch.setattr(
        email_service.resend_surrogate, "fetch_resend_surrogate", lambda *a, **kw: "hsurr:test-surrogate"
    )
    yield settings


def _mock_resend(status_code: int = 200, message_id: str = "re_mock123", calls: list | None = None):
    """A ResendProvider whose HTTP calls are captured, never sent."""

    def handler(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(request)
        if status_code >= 400:
            return httpx.Response(status_code, json={"message": "invalid api key"})
        return httpx.Response(status_code, json={"id": message_id})

    transport = httpx.MockTransport(handler)
    return ResendProvider(
        api_key=TEST_KEY,
        from_address="no-reply@nullitsm.test",
        client=httpx.Client(transport=transport),
    )


@pytest.fixture()
def resend_ok():
    provider = _mock_resend(200)
    email_service.set_provider_override(provider)
    yield provider
    email_service.set_provider_override(None)


@pytest.fixture()
def resend_failing():
    provider = _mock_resend(401)
    email_service.set_provider_override(provider)
    yield provider
    email_service.set_provider_override(None)


# --- Templates ----------------------------------------------------------------


def test_org_invitation_template_subject_content_and_branding():
    subject, html, text = render_org_invitation_email(
        recipient_name="Tech One",
        org_name="Acme Technology Group",
        role_names=["Service Desk Technician"],
        inviter_name="Alice Admin",
        accept_url="https://app.nullitsm.test/invite/accept?token=abc",
    )
    assert subject == "You've been invited to join NULL ITSM"
    assert "Acme Technology Group" in html
    assert "Tech One" in html
    assert "Service Desk Technician" in html
    assert "Alice Admin" in html
    assert "https://app.nullitsm.test/invite/accept?token=abc" in html
    assert "48 hours" in html
    assert "Accept Invitation" in html
    # NULL editorial palette: ivory, ink, purple.
    assert "#F2EBDD" in html
    assert "#171614" in html
    assert "#A17ACB" in html or "#6B4FA1" in html
    # Plain-text mirror carries the same facts.
    assert "Acme Technology Group" in text
    assert "https://app.nullitsm.test/invite/accept?token=abc" in text
    assert "48 hours" in text


def test_org_invitation_template_escapes_user_values():
    subject, html, _text = render_org_invitation_email(
        recipient_name="<script>alert(1)</script>",
        org_name="Acme & Sons <b>",
        role_names=["Technician"],
        inviter_name="Alice",
        accept_url="https://app.nullitsm.test/invite/accept?token=abc",
    )
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert "Acme &amp; Sons" in html
    assert subject == "You've been invited to join NULL ITSM"


def test_platform_invitation_template_subject():
    subject, html, text = render_platform_invitation_email(
        recipient_name="Pat Admin",
        role_name="Platform Administrator",
        inviter_name="Super Sue",
        accept_url="https://app.nullitsm.test/platform/invite/accept?token=abc",
    )
    assert subject == "You've been invited to join NULL ITSM Platform Administration"
    assert "Pat Admin" in html
    assert "Platform Administrator" in html
    assert "Super Sue" in html
    assert "48 hours" in html
    assert "https://app.nullitsm.test/platform/invite/accept?token=abc" in text


# --- Dev mode -----------------------------------------------------------------


def test_dev_invite_returns_accept_url_and_dev_delivery(client):
    reg = _register(client, "Dev Mode Org")
    invited = _invite(client, reg, _uniq("dev-tech"))
    assert invited["accept_url"], "dev mode must return the accept link"
    assert "/invite/accept?token=" in invited["accept_url"]
    delivery = invited["delivery"]
    assert delivery is not None
    assert delivery["status"] == "dev_recorded"
    assert delivery["provider"] == "dev"
    assert delivery["dev_recorded"] is True
    assert delivery["delivered"] is False
    assert delivery["provider_message_id"] is None


def test_dev_outbox_records_invitation_email(client):
    reg = _register(client, "Outbox Org")
    email = _uniq("outbox-tech")
    invited = _invite(client, reg, email)
    outbox = client.get(f"/api/v1/organizations/{reg['org_id']}/outbox", headers=reg["headers"])
    assert outbox.status_code == 200, outbox.text
    rows = outbox.json()
    assert len(rows) == 1
    assert rows[0]["to_email"] == email
    assert rows[0]["subject"] == "You've been invited to join NULL ITSM"
    assert invited["accept_url"].split("token=")[1] in rows[0]["body"]


def test_list_invitations_shows_delivery_status(client):
    reg = _register(client, "List Delivery Org")
    invited = _invite(client, reg, _uniq("list-tech"))
    rows = client.get(f"/api/v1/organizations/{reg['org_id']}/invitations", headers=reg["headers"])
    assert rows.status_code == 200, rows.text
    assert len(rows.json()) == 1
    assert rows.json()[0]["id"] == invited["id"]
    assert rows.json()[0]["delivery"]["status"] == "dev_recorded"


# --- Configured mode ----------------------------------------------------------


def test_resend_request_carries_browser_user_agent(client, configured_email):
    # Resend sits behind Cloudflare: a default Python user agent is
    # refused with HTTP 403 / error code 1010 before reaching the API.
    # The provider must send a browser UA on every request.
    calls: list = []
    provider = _mock_resend(200, calls=calls)
    email_service.set_provider_override(provider)
    try:
        reg = _register(client, "User Agent Org")
        _invite(client, reg, _uniq("ua-tech"))
    finally:
        email_service.set_provider_override(None)
    assert len(calls) == 1
    user_agent = calls[0].headers["User-Agent"]
    assert user_agent.startswith("Mozilla/5.0"), user_agent
    assert "Chrome/" in user_agent, user_agent
    assert "python-httpx" not in user_agent
    assert "python-requests" not in user_agent
    assert calls[0].headers["Authorization"] == f"Bearer {TEST_KEY}"
    assert calls[0].url == "https://api.resend.com/emails"


def test_configured_invite_sends_via_resend_and_hides_accept_url(client, configured_email, resend_ok):
    reg = _register(client, "Configured Org")
    invited = _invite(client, reg, _uniq("cfg-tech"))
    assert invited["accept_url"] is None, "configured mode must never expose the dev link"
    delivery = invited["delivery"]
    assert delivery["status"] == "sent"
    assert delivery["provider"] == "resend"
    assert delivery["provider_message_id"] == "re_mock123"
    assert delivery["delivered"] is True
    assert delivery["dev_recorded"] is False
    assert delivery["attempts"] == 1


def test_configured_invite_failure_is_reported_not_hidden(client, configured_email, resend_failing):
    reg = _register(client, "Failing Provider Org")
    email = _uniq("fail-tech")
    invited = _invite(client, reg, email)
    # The invitation is still created (pending) — the admin can resend —
    # but the response must say the email FAILED, never claim success.
    assert invited["accept_url"] is None
    delivery = invited["delivery"]
    assert delivery["status"] == "failed"
    assert delivery["delivered"] is False
    assert delivery["dev_recorded"] is False
    assert delivery["last_error"], "the provider error must be surfaced"
    assert "401" in delivery["last_error"]


def test_resend_after_failure_succeeds(client, configured_email, resend_failing):
    reg = _register(client, "Resend After Failure Org")
    invited = _invite(client, reg, _uniq("resend-tech"))
    assert invited["delivery"]["status"] == "failed"
    # Fix the provider, then resend: a fresh delivery succeeds. (That the
    # resend invalidates the old token is covered in test_registration.py,
    # where the token is visible in dev mode.)
    email_service.set_provider_override(_mock_resend(200, message_id="re_mock456"))
    try:
        resp = client.post(
            f"/api/v1/organizations/{reg['org_id']}/invitations/{invited['id']}/resend",
            headers=reg["headers"],
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["delivery"]["status"] == "sent"
        assert resp.json()["delivery"]["provider_message_id"] == "re_mock456"
    finally:
        email_service.set_provider_override(None)


def test_keyless_provider_fails_loudly_with_503_and_creates_nothing(
    client, keyless_email
):
    reg = _register(client, "Keyless Org")
    email = _uniq("keyless-tech")
    resp = client.post(
        f"/api/v1/organizations/{reg['org_id']}/invitations",
        json={"email": email, "role_ids": [], "full_name": "Tech One"},
        headers=reg["headers"],
    )
    assert resp.status_code == 503, resp.text
    detail = resp.json()["detail"]
    assert "API key" in detail or "surrogate" in detail.lower(), detail
    rows = client.get(f"/api/v1/organizations/{reg['org_id']}/invitations", headers=reg["headers"])
    assert rows.json() == [], "a misconfigured provider must not create an invitation"


def test_platform_invite_configured_sends_and_hides_link(
    client, platform_admin, configured_email, resend_ok
):
    role_id = _platform_role_id(client, platform_admin, "Platform Administrator")
    resp = client.post(
        "/api/v1/platform/admin-invitations",
        json={"email": _uniq("platform-cfg"), "full_name": "Platform Person", "role_id": role_id},
        headers=platform_admin["headers"],
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["accept_url"] is None
    delivery = resp.json()["delivery"]
    assert delivery["status"] == "sent"
    assert delivery["provider"] == "resend"
    assert delivery["provider_message_id"] == "re_mock123"


# --- Idempotency --------------------------------------------------------------


def test_duplicate_pending_invite_rejected(client):
    reg = _register(client, "Dup Org")
    email = _uniq("dup-tech")
    _invite(client, reg, email)
    resp = client.post(
        f"/api/v1/organizations/{reg['org_id']}/invitations",
        json={"email": email, "role_ids": [], "full_name": "Tech One"},
        headers=reg["headers"],
    )
    assert resp.status_code == 400, resp.text


def test_expired_pending_invite_can_be_reinvited(client, app_db):
    reg = _register(client, "Expiry Reinvite Org")
    email = _uniq("expiry-tech")
    first = _invite(client, reg, email)
    # Force the first invitation past expiry (no API moves time).
    set_rls(app_db, reg["org_id"], reg["user_id"])
    with app_db.cursor() as cur:
        cur.execute(
            "UPDATE invitations SET expires_at = now() - interval '1 hour' WHERE id = %s",
            (first["id"],),
        )
    second = _invite(client, reg, email)
    assert second["id"] != first["id"]
    assert second["status"] == "pending"
    rows = client.get(f"/api/v1/organizations/{reg['org_id']}/invitations", headers=reg["headers"])
    by_id = {r["id"]: r for r in rows.json()}
    assert by_id[first["id"]]["status"] == "expired"
    assert by_id[second["id"]]["status"] == "pending"


def test_partial_unique_index_blocks_duplicate_pending_row(client, app_db):
    reg = _register(client, "Index Org")
    email = _uniq("index-tech")
    _invite(client, reg, email)
    # A second pending row for the same (org, email) must fail at the
    # database, even if application code ever misses the check.
    set_rls(app_db, reg["org_id"], reg["user_id"])
    with pytest.raises(psycopg.errors.UniqueViolation):
        with app_db.cursor() as cur:
            cur.execute(
                "INSERT INTO invitations "
                "(id, organization_id, email, full_name, token_hash, invited_by_id, status, expires_at) "
                "VALUES (gen_random_uuid(), %s, %s, 'Tech Two', %s, %s, 'pending', now() + interval '48 hours')",
                (reg["org_id"], email, uuid.uuid4().hex, reg["user_id"]),
            )


def test_unauthorized_user_cannot_invite(client, acme_tech, org_ids):
    resp = client.post(
        f"/api/v1/organizations/{org_ids['acme']}/invitations",
        json={"email": _uniq("nope-tech"), "role_ids": [], "full_name": "Nope"},
        headers=acme_tech["headers"],
    )
    assert resp.status_code == 403, resp.text


# --- Retries ------------------------------------------------------------------


def _delivery_row(app_db, org_id: str, user_id: str, email: str) -> dict:
    set_rls(app_db, org_id, user_id)
    with app_db.cursor() as cur:
        cur.execute(
            "SELECT id, status, attempts, provider_message_id FROM email_deliveries "
            "WHERE to_email = %s ORDER BY created_at DESC LIMIT 1",
            (email,),
        )
        row = cur.fetchone()
    assert row is not None, "expected a delivery row"
    return {"id": str(row[0]), "status": row[1], "attempts": row[2], "provider_message_id": row[3]}


def test_retry_sends_failed_delivery_and_audits(client, configured_email, resend_failing, app_db, monkeypatch):
    reg = _register(client, "Retry Org")
    email = _uniq("retry-tech")
    enqueued: list = []
    monkeypatch.setattr(
        email_service,
        "_enqueue_retry",
        lambda delivery_id, countdown_seconds, **kw: enqueued.append(
            (str(delivery_id), countdown_seconds)
        ),
    )
    invited = _invite(client, reg, email)
    assert invited["delivery"]["status"] == "failed"
    assert len(enqueued) == 1, "the first failure must enqueue a retry"
    assert enqueued[0][1] == 60

    row = _delivery_row(app_db, reg["org_id"], reg["user_id"], email)
    assert row["status"] == "failed"
    assert row["attempts"] == 1

    # The provider recovers; the retry re-sends the stored bodies.
    email_service.set_provider_override(_mock_resend(200, message_id="re_retry789"))
    try:
        result = retry_email_delivery(
            row["id"],
            organization_id=reg["org_id"],
            scope="org",
            created_by_id=reg["user_id"],
        )
    finally:
        email_service.set_provider_override(None)
    assert result["delivered"] is True
    assert result["provider_message_id"] == "re_retry789"
    assert result["attempts"] == 2

    after = _delivery_row(app_db, reg["org_id"], reg["user_id"], email)
    assert after["status"] == "sent"
    assert after["attempts"] == 2
    assert after["provider_message_id"] == "re_retry789"
    # The retry is audited in the org's audit log.
    set_rls(app_db, reg["org_id"], reg["user_id"])
    with app_db.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM audit_logs WHERE action = 'email.delivery.sent' "
            "AND resource_id = %s",
            (row["id"],),
        )
        assert cur.fetchone()[0] == 1


def test_retry_skips_already_sent_delivery(client, configured_email, resend_ok, app_db):
    reg = _register(client, "Retry Skip Org")
    email = _uniq("skip-tech")
    calls: list = []
    provider = _mock_resend(200, calls=calls)
    email_service.set_provider_override(provider)
    try:
        invited = _invite(client, reg, email)
    finally:
        email_service.set_provider_override(None)
    assert invited["delivery"]["status"] == "sent"
    assert len(calls) == 1
    row = _delivery_row(app_db, reg["org_id"], reg["user_id"], email)
    result = retry_email_delivery(
        row["id"], organization_id=reg["org_id"], scope="org", created_by_id=reg["user_id"]
    )
    assert result["retried"] is False
    assert result["reason"] == "not failed"
    assert len(calls) == 1, "a sent delivery must never be sent twice"


def test_retry_stops_after_max_attempts(client, configured_email, resend_failing, app_db, monkeypatch):
    reg = _register(client, "Retry Exhausted Org")
    email = _uniq("exhausted-tech")
    monkeypatch.setattr(email_service, "_enqueue_retry", lambda *a, **kw: None)
    invited = _invite(client, reg, email)
    assert invited["delivery"]["status"] == "failed"
    row = _delivery_row(app_db, reg["org_id"], reg["user_id"], email)
    max_attempts = get_settings().email_retry_max_attempts
    set_rls(app_db, reg["org_id"], reg["user_id"])
    with app_db.cursor() as cur:
        cur.execute(
            "UPDATE email_deliveries SET attempts = %s WHERE id = %s", (max_attempts, row["id"])
        )
    calls: list = []
    email_service.set_provider_override(_mock_resend(200, calls=calls))
    try:
        result = retry_email_delivery(
            row["id"],
            organization_id=reg["org_id"],
            scope="org",
            created_by_id=reg["user_id"],
        )
    finally:
        email_service.set_provider_override(None)
    assert result["retried"] is False
    assert result["reason"] == "attempts exhausted"
    assert calls == [], "an exhausted delivery must not be sent again"


def test_retry_does_nothing_without_a_provider(client, resend_failing, app_db, monkeypatch):
    # A failed row exists, but delivery is no longer configured (dev mode):
    # the retry must not re-record a failure or loop.
    reg = _register(client, "Retry No Provider Org")
    email = _uniq("noprovider-tech")
    monkeypatch.setattr(email_service, "_enqueue_retry", lambda *a, **kw: None)
    settings = get_settings()
    monkeypatch.setattr(settings, "email_provider", "resend")
    monkeypatch.setattr(settings, "resend_api_key", TEST_KEY)
    invited = _invite(client, reg, email)
    assert invited["delivery"]["status"] == "failed"
    row = _delivery_row(app_db, reg["org_id"], reg["user_id"], email)
    # Delivery is no longer configured at all: settings back to dev mode
    # AND the test provider override cleared, so resolution yields the
    # dev provider.
    monkeypatch.setattr(settings, "email_provider", "none")
    monkeypatch.setattr(settings, "resend_api_key", "")
    email_service.set_provider_override(None)
    result = retry_email_delivery(
        row["id"], organization_id=reg["org_id"], scope="org", created_by_id=reg["user_id"]
    )
    assert result["retried"] is False
    assert result["reason"] == "no email provider configured"
    after = _delivery_row(app_db, reg["org_id"], reg["user_id"], email)
    assert after["status"] == "failed"
    assert after["attempts"] == 1


# --- Surrogate mode -----------------------------------------------------------
# Provider "resend" selected, no key in the environment: the key comes
# from the authd surrogate channel (this VM). These tests mock the
# surrogate fetch AND the HTTP transport — nothing reaches the network
# or the real Resend API. The live end-to-end send is verified
# separately, against the live boot (see docs/EMAIL.md).


def test_surrogate_invite_sends_and_hides_accept_url(client, surrogate_email):
    calls: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={"id": "re_surr123"})

    provider = SurrogateResendProvider(
        from_address="no-reply@nullitsm.test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        surrogate_fetcher=lambda: "hsurr:test-surrogate",
    )
    email_service.set_provider_override(provider)
    try:
        reg = _register(client, "Surrogate Org")
        invited = _invite(client, reg, _uniq("surr-tech"))
    finally:
        email_service.set_provider_override(None)
    assert invited["accept_url"] is None, "configured mode must never expose the dev link"
    delivery = invited["delivery"]
    assert delivery["status"] == "sent"
    assert delivery["provider"] == "resend"
    assert delivery["provider_message_id"] == "re_surr123"
    assert delivery["delivered"] is True
    assert delivery["dev_recorded"] is False
    assert len(calls) == 1
    assert calls[0].headers["Authorization"] == "Bearer hsurr:test-surrogate"
    assert calls[0].headers["User-Agent"].startswith("Mozilla/5.0")
    assert calls[0].url == "https://api.resend.com/emails"


def test_surrogate_send_routes_through_explicit_proxy(client, surrogate_email, monkeypatch):
    """Surrogate mode must route through the egress proxy (explicit
    proxy=, trust_env=False) — that proxy performs the swap. A direct
    send would reach Resend with the surrogate unswapped and fail."""
    requests: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"id": "re_surrogate123"})

    transport = httpx.MockTransport(handler)
    real_client_cls = httpx.Client
    seen_kwargs: dict = {}

    def recording_client(*args, **kwargs):
        seen_kwargs.update(kwargs)
        kwargs.pop("proxy", None)  # the mock transport needs no proxy
        return real_client_cls(transport=transport, *args, **kwargs)

    monkeypatch.setattr(email_service.httpx, "Client", recording_client)
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.test:3128")
    reg = _register(client, "Surrogate Proxy Org")
    invited = _invite(client, reg, _uniq("surr-proxy-tech"))
    assert invited["delivery"]["status"] == "sent"
    assert invited["delivery"]["provider_message_id"] == "re_surrogate123"
    assert seen_kwargs.get("proxy") == "http://proxy.test:3128"
    assert seen_kwargs.get("trust_env") is False
    # TLS is verified against the system CA store (the egress proxy's
    # Hatch CA lives there; httpx's certifi default does not know it).
    verify = seen_kwargs.get("verify")
    assert isinstance(verify, ssl.SSLContext)
    assert verify.verify_mode == ssl.CERT_REQUIRED
    assert verify.check_hostname is True
    assert len(requests) == 1
    assert requests[0].headers["Authorization"] == "Bearer hsurr:test-surrogate"


def test_resend_client_verifies_against_system_ca_store(monkeypatch):
    """The default Resend client verifies TLS (never disabled) using
    the system CA store, so the egress proxy's Hatch CA is trusted."""
    import ssl as ssl_mod

    real_client_cls = httpx.Client
    seen_kwargs: dict = {}

    def recording_client(*args, **kwargs):
        seen_kwargs.update(kwargs)
        return real_client_cls(*args, **kwargs)

    monkeypatch.setattr(email_service.httpx, "Client", recording_client)
    client = email_service._resend_client(30)
    client.close()
    verify = seen_kwargs.get("verify")
    assert isinstance(verify, ssl_mod.SSLContext)
    assert verify.verify_mode == ssl_mod.CERT_REQUIRED
    assert verify.check_hostname is True


def test_surrogate_unavailable_fails_loudly_with_503(client, monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "email_provider", "resend")
    monkeypatch.setattr(settings, "resend_api_key", "")
    monkeypatch.setattr(email_service.resend_surrogate, "surrogate_channel_available", lambda: True)

    def _boom(*args, **kwargs):
        raise email_service.resend_surrogate.SurrogateUnavailable("authd down")

    monkeypatch.setattr(email_service.resend_surrogate, "fetch_resend_surrogate", _boom)
    reg = _register(client, "Surrogate Down Org")
    resp = client.post(
        f"/api/v1/organizations/{reg['org_id']}/invitations",
        json={"email": _uniq("surr-down-tech"), "role_ids": [], "full_name": "Tech One"},
        headers=reg["headers"],
    )
    assert resp.status_code == 503, resp.text
    rows = client.get(f"/api/v1/organizations/{reg['org_id']}/invitations", headers=reg["headers"])
    assert rows.json() == [], "a failed surrogate fetch must not create an invitation"


def test_surrogate_send_without_proxy_fails_loudly(monkeypatch):
    for var in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        monkeypatch.delenv(var, raising=False)
    provider = SurrogateResendProvider(
        from_address="no-reply@nullitsm.test",
        surrogate_fetcher=lambda: "hsurr:test-surrogate",
    )
    with pytest.raises(EmailConfigurationError, match="egress proxy"):
        provider.send(to="a@test.local", subject="s", html_body="<p>x</p>", text_body="x")


def test_env_key_takes_precedence_over_surrogate(configured_email, monkeypatch):
    """Even with the surrogate channel available, a configured key is used."""
    monkeypatch.setattr(email_service.resend_surrogate, "surrogate_channel_available", lambda: True)

    def _boom(*args, **kwargs):
        raise AssertionError("surrogate must not be fetched when a key is configured")

    monkeypatch.setattr(email_service.resend_surrogate, "fetch_resend_surrogate", _boom)
    provider = resolve_provider()
    assert isinstance(provider, ResendProvider)
    assert not isinstance(provider, SurrogateResendProvider)
