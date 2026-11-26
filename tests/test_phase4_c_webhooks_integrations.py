"""Phase 4 workstream C tests: webhooks, integrations, API keys.

Run ONLY via ``bash scripts/run_tests_locked.sh
tests/test_phase4_c_webhooks_integrations.py`` (shared test DB — never
bare pytest while siblings work).

The routers are NOT registered in app/main.py yet (the coordinator wires
them at integration), so this module mounts them onto the test app
itself, guarded against double-registration. Webhook delivery is proven
against a REAL local HTTP server (threaded, scripted responses) — never
a mocked-out send.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select

from app.config import get_settings
from app.crypto import decrypt
from app.database import tenant_session
from app.main import app
from app.models.audit import AuditLog
from app.models.integrations import ApiKey, Integration, IntegrationCredential, Webhook
from app.routers import apikeys as apikeys_router
from app.routers import integrations as integrations_router
from app.routers import webhooks as webhooks_router
from app.services import webhook_service
from app.services.apikey_service import ApiKeyAuthError, authenticate_api_key

for _router in (webhooks_router.router, integrations_router.router, apikeys_router.router):
    if not any(getattr(r, "path", "").startswith(_router.prefix) for r in app.routes):
        app.include_router(_router)

ALICE = "alice@acme.example.com"
TOM = "tom@acme.example.com"
GINA = "gina@globex.example.com"


@pytest.fixture()
def enc_key():
    """Ephemeral Fernet key on the (cached) settings singleton."""
    settings = get_settings()
    old = settings.field_encryption_key
    settings.field_encryption_key = Fernet.generate_key().decode()
    yield settings.field_encryption_key
    settings.field_encryption_key = old


# --- Real local HTTP server (scripted responses, records requests) --------


class _CaptureHandler(BaseHTTPRequestHandler):
    script: list[tuple[int, str]] = []
    received: list[dict] = []
    protocol_version = "HTTP/1.1"

    def _handle(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        _CaptureHandler.received.append(
            {"method": self.command, "path": self.path, "headers": dict(self.headers), "body": body}
        )
        idx = min(len(_CaptureHandler.received) - 1, len(_CaptureHandler.script) - 1)
        status_code, text = _CaptureHandler.script[idx] if _CaptureHandler.script else (200, "ok")
        payload = text.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def log_message(self, *args):
        pass


@pytest.fixture()
def http_server():
    """A real HTTP server on an ephemeral localhost port.

    Set ``http_server.script`` to a list of (status, body) tuples — the
    Nth request gets the Nth entry (last entry repeats). ``received``
    records every request (method, path, headers, raw body).
    """
    _CaptureHandler.script = [(200, "ok")]
    _CaptureHandler.received = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _CaptureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


def _server_url(server) -> str:
    return f"http://127.0.0.1:{server.server_address[1]}"


def _closed_port_url() -> str:
    """A localhost URL nothing listens on (connection refused)."""
    import socket

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return f"http://127.0.0.1:{port}"


# --- Helpers ----------------------------------------------------------------


def _create_webhook(client, headers, url, event="ticket.created", name=None, secret="test-secret-123"):
    # Unique name by default: webhooks are unique per (org, name), and
    # tests share one org, so a fixed default would collide across tests.
    body = {"name": name or f"test-hook-{uuid.uuid4().hex[:8]}", "event_type": event, "target_url": url}
    if secret is not None:
        body["secret"] = secret
    resp = client.post("/api/v1/webhooks", json=body, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _audit_actions(org_id: str, action: str) -> int:
    with tenant_session(uuid.UUID(org_id)) as session:
        return len(session.execute(select(AuditLog).where(AuditLog.action == action)).scalars().all())


# --- Webhooks: CRUD ----------------------------------------------------------


def test_webhook_crud_and_secret_shown_once(client, acme_admin, acme_tech, globex_admin, org_ids, enc_key):
    hook = _create_webhook(client, acme_admin["headers"], "https://example.invalid/hook")
    assert hook["secret"] == "test-secret-123"
    assert hook["has_secret"] is True
    assert hook["is_active"] is True

    # The secret is encrypted at rest and is never returned again.
    with tenant_session(uuid.UUID(org_ids["acme"])) as session:
        row = session.get(Webhook, uuid.UUID(hook["id"]))
        assert row is not None and row.secret_encrypted != "test-secret-123"
        assert decrypt(row.secret_encrypted) == "test-secret-123"
    got = client.get(f"/api/v1/webhooks/{hook['id']}", headers=acme_admin["headers"])
    assert got.status_code == 200, got.text
    assert got.json()["secret"] is None
    listed = client.get("/api/v1/webhooks", headers=acme_admin["headers"])
    assert listed.status_code == 200
    assert all(item["secret"] is None for item in listed.json())

    # Bad event type / bad URL are 400.
    bad = client.post(
        "/api/v1/webhooks",
        json={"name": "bad", "event_type": "ticket.exploded", "target_url": "https://example.invalid/x"},
        headers=acme_admin["headers"],
    )
    assert bad.status_code == 400, bad.text
    bad = client.post(
        "/api/v1/webhooks",
        json={"name": "bad", "event_type": "ticket.created", "target_url": "ftp://example.invalid/x"},
        headers=acme_admin["headers"],
    )
    assert bad.status_code == 400, bad.text

    # No secret supplied -> one is generated and shown once.
    gen = _create_webhook(client, acme_admin["headers"], "https://example.invalid/gen", name="generated", secret=None)
    assert gen["secret"] and len(gen["secret"]) >= 32

    # Duplicate (org, name) is a clean 409, not a 500.
    dup = client.post(
        "/api/v1/webhooks",
        json={"name": "generated", "event_type": "ticket.created", "target_url": "https://example.invalid/x"},
        headers=acme_admin["headers"],
    )
    assert dup.status_code == 409, dup.text

    # Update + deactivate; delete.
    upd = client.patch(f"/api/v1/webhooks/{hook['id']}", json={"is_active": False}, headers=acme_admin["headers"])
    assert upd.status_code == 200 and upd.json()["is_active"] is False
    gone = client.delete(f"/api/v1/webhooks/{hook['id']}", headers=acme_admin["headers"])
    assert gone.status_code == 204
    assert client.get(f"/api/v1/webhooks/{hook['id']}", headers=acme_admin["headers"]).status_code == 404

    # Audit rows were written.
    assert _audit_actions(org_ids["acme"], "webhook.created") >= 2
    assert _audit_actions(org_ids["acme"], "webhook.updated") >= 1
    assert _audit_actions(org_ids["acme"], "webhook.deleted") >= 1


def test_webhook_permissions_and_tenant_isolation(client, acme_admin, acme_tech, globex_admin, org_ids, enc_key):
    hook = _create_webhook(client, acme_admin["headers"], "https://example.invalid/hook", name="isolation-hook")
    # Technician lacks webhooks:manage -> 403 on create.
    resp = client.post(
        "/api/v1/webhooks",
        json={"name": "nope", "event_type": "ticket.created", "target_url": "https://example.invalid/x"},
        headers=acme_tech["headers"],
    )
    assert resp.status_code == 403, resp.text
    # Cross-org ids are 404, never 403.
    assert client.get(f"/api/v1/webhooks/{hook['id']}", headers=globex_admin["headers"]).status_code == 404
    assert client.delete(f"/api/v1/webhooks/{hook['id']}", headers=globex_admin["headers"]).status_code == 404
    # The other org's list does not contain it.
    assert all(
        item["id"] != hook["id"] for item in client.get("/api/v1/webhooks", headers=globex_admin["headers"]).json()
    )


def test_webhook_create_fails_closed_without_encryption_key(client, acme_admin):
    settings = get_settings()
    old = settings.field_encryption_key
    settings.field_encryption_key = ""
    try:
        resp = client.post(
            "/api/v1/webhooks",
            json={"name": "no-key", "event_type": "ticket.created", "target_url": "https://example.invalid/x"},
            headers=acme_admin["headers"],
        )
        assert resp.status_code == 503, resp.text
    finally:
        settings.field_encryption_key = old


# --- Webhooks: real delivery -------------------------------------------------


def test_webhook_delivery_success_and_signature(client, acme_admin, org_ids, enc_key, http_server):
    hook = _create_webhook(
        client, acme_admin["headers"], _server_url(http_server) + "/hook", secret="s3cret-signing-key"
    )
    resp = client.post(
        f"/api/v1/webhooks/{hook['id']}/test",
        json={"payload": {"ticket_id": "T-1"}},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 200, resp.text
    attempts = resp.json()
    assert len(attempts) == 1
    assert attempts[0]["status"] == "success" and attempts[0]["http_status"] == 200
    assert attempts[0]["attempt_number"] == 1

    # The server really received one signed POST; verify the HMAC ourselves.
    assert len(_CaptureHandler.received) == 1
    received = _CaptureHandler.received[0]
    assert received["method"] == "POST"
    body = received["body"]
    envelope = json.loads(body)
    assert envelope["event"] == "ticket.created"
    assert envelope["data"] == {"ticket_id": "T-1"}
    expected = "sha256=" + hmac.new(b"s3cret-signing-key", body, hashlib.sha256).hexdigest()
    assert received["headers"].get("X-Null-Signature") == expected

    # The delivery row is persisted and listed.
    rows = client.get(f"/api/v1/webhooks/{hook['id']}/deliveries", headers=acme_admin["headers"]).json()
    assert len(rows) == 1 and rows[0]["status"] == "success"


def test_webhook_delivery_retries_then_succeeds(client, acme_admin, enc_key, http_server):
    _CaptureHandler.script = [(500, "boom"), (500, "boom"), (200, "ok")]
    hook = _create_webhook(client, acme_admin["headers"], _server_url(http_server) + "/hook")
    resp = client.post(f"/api/v1/webhooks/{hook['id']}/test", json={"payload": {}}, headers=acme_admin["headers"])
    assert resp.status_code == 200, resp.text
    attempts = resp.json()
    assert [a["attempt_number"] for a in attempts] == [1, 2, 3]
    assert [a["status"] for a in attempts] == ["failed", "failed", "success"]
    assert [a["http_status"] for a in attempts] == [500, 500, 200]
    assert attempts[0]["response_snippet"] == "boom"
    assert attempts[0]["next_retry_at"] is not None
    assert attempts[2]["next_retry_at"] is None
    assert len(_CaptureHandler.received) == 3


def test_webhook_delivery_failure_records_error(client, acme_admin, enc_key):
    hook = _create_webhook(client, acme_admin["headers"], _closed_port_url() + "/hook")
    resp = client.post(f"/api/v1/webhooks/{hook['id']}/test", json={"payload": {}}, headers=acme_admin["headers"])
    assert resp.status_code == 200, resp.text
    attempts = resp.json()
    assert len(attempts) == 3
    assert all(a["status"] == "failed" for a in attempts)
    assert all(a["http_status"] is None for a in attempts)
    assert attempts[0]["error"] is not None
    assert attempts[2]["next_retry_at"] is None


def test_webhook_retry_endpoint_replays_stored_payload(client, acme_admin, enc_key, http_server):
    hook = _create_webhook(client, acme_admin["headers"], _closed_port_url() + "/hook")
    first = client.post(
        f"/api/v1/webhooks/{hook['id']}/test", json={"payload": {"n": 1}}, headers=acme_admin["headers"]
    )
    assert first.status_code == 200
    failed_id = first.json()[0]["id"]
    # Point the webhook at the live server, then retry the failed delivery.
    client.patch(
        f"/api/v1/webhooks/{hook['id']}",
        json={"target_url": _server_url(http_server) + "/hook"},
        headers=acme_admin["headers"],
    )
    resp = client.post(f"/api/v1/webhooks/{hook['id']}/deliveries/{failed_id}/retry", headers=acme_admin["headers"])
    assert resp.status_code == 200, resp.text
    assert resp.json()[0]["status"] == "success"
    assert json.loads(_CaptureHandler.received[0]["body"])["data"] == {"n": 1}


def test_deliver_event_fans_out_only_to_matching_active_hooks(client, acme_admin, org_ids, enc_key, http_server):
    # incident.declared is used by no other test in this file, so leftover
    # webhooks from earlier tests cannot pollute the fan-out.
    _create_webhook(
        client, acme_admin["headers"], _server_url(http_server) + "/a", event="incident.declared", name="fan-a"
    )
    _create_webhook(
        client, acme_admin["headers"], _server_url(http_server) + "/b", event="vulnerability.found", name="fan-b"
    )
    inactive = _create_webhook(
        client, acme_admin["headers"], _server_url(http_server) + "/c", event="incident.declared", name="fan-c"
    )
    client.patch(f"/api/v1/webhooks/{inactive['id']}", json={"is_active": False}, headers=acme_admin["headers"])
    with tenant_session(uuid.UUID(org_ids["acme"])) as session:
        deliveries = webhook_service.deliver_event(
            session, uuid.UUID(org_ids["acme"]), "incident.declared", {"n": 7}, backoff_seconds=(0, 0)
        )
    assert len(deliveries) == 1 and deliveries[0].status == "success"
    assert len(_CaptureHandler.received) == 1
    assert _CaptureHandler.received[0]["path"] == "/a"
    # Unknown event types are rejected, not silently dropped.
    with tenant_session(uuid.UUID(org_ids["acme"])) as session:
        with pytest.raises(Exception):
            webhook_service.deliver_event(
                session, uuid.UUID(org_ids["acme"]), "ticket.exploded", {}, backoff_seconds=(0, 0)
            )


# --- Integrations -----------------------------------------------------------


def test_integration_providers_include_priority_list(client, acme_admin):
    resp = client.get("/api/v1/integrations/providers", headers=acme_admin["headers"])
    assert resp.status_code == 200, resp.text
    slugs = {p["slug"] for p in resp.json()}
    for expected in ("entra_id", "intune", "greenbone", "defender", "slack", "teams", "github", "power_bi"):
        assert expected in slugs
    assert "generic_http" in slugs


def test_integration_crud_rejects_unknown_provider(client, acme_admin):
    resp = client.post(
        "/api/v1/integrations",
        json={"provider": "skynet", "name": "x", "config": {}},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 400, resp.text


def test_generic_http_test_connection_success(client, acme_admin, org_ids, http_server):
    resp = client.post(
        "/api/v1/integrations",
        json={
            "provider": "generic_http",
            "name": "local",
            "config": {"base_url": _server_url(http_server) + "/health"},
        },
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 201, resp.text
    integration = resp.json()
    assert integration["status"] == "disconnected"  # never live before a check
    tested = client.post(f"/api/v1/integrations/{integration['id']}/test-connection", headers=acme_admin["headers"])
    assert tested.status_code == 200, tested.text
    assert tested.json()["status"] == "connected"
    assert tested.json()["last_test_result"] == "success"
    assert tested.json()["last_error"] is None
    assert len(_CaptureHandler.received) == 1
    assert _CaptureHandler.received[0]["method"] == "GET"


def test_generic_http_test_connection_failure_stays_honest(client, acme_admin):
    resp = client.post(
        "/api/v1/integrations",
        json={"provider": "generic_http", "name": "down", "config": {"base_url": _closed_port_url()}},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 201, resp.text
    tested = client.post(f"/api/v1/integrations/{resp.json()['id']}/test-connection", headers=acme_admin["headers"])
    assert tested.status_code == 200, tested.text
    assert tested.json()["status"] == "error"
    assert tested.json()["last_test_result"] == "failed"
    assert tested.json()["last_error"]


def test_priority_provider_without_driver_stays_disconnected(client, acme_admin):
    resp = client.post(
        "/api/v1/integrations",
        json={"provider": "slack", "name": "chat", "config": {}},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 201, resp.text
    tested = client.post(f"/api/v1/integrations/{resp.json()['id']}/test-connection", headers=acme_admin["headers"])
    assert tested.status_code == 200, tested.text
    body = tested.json()
    assert body["status"] == "disconnected"
    assert body["last_test_result"] == "failed"
    assert "no connection check available" in (body["last_error"] or "")


def test_integration_credentials_encrypted_and_never_returned(client, acme_admin, acme_tech, org_ids, enc_key):
    created = client.post(
        "/api/v1/integrations",
        json={"provider": "generic_http", "name": "creds", "config": {}},
        headers=acme_admin["headers"],
    )
    assert created.status_code == 201, created.text
    iid = created.json()["id"]
    resp = client.post(
        f"/api/v1/integrations/{iid}/credentials",
        json={"key_name": "api_token", "value": "tok-super-secret"},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 201, resp.text
    assert resp.json() == {"key_name": "api_token"}
    # Only key names are listed; the value never appears in any response.
    listed = client.get(f"/api/v1/integrations/{iid}/credentials", headers=acme_admin["headers"]).json()
    assert listed == [{"key_name": "api_token"}]
    got = client.get(f"/api/v1/integrations/{iid}", headers=acme_admin["headers"]).json()
    assert "tok-super-secret" not in json.dumps(got)
    # Encrypted at rest, decryptable by the service.
    with tenant_session(uuid.UUID(org_ids["acme"])) as session:
        rows = (
            session.execute(select(IntegrationCredential).where(IntegrationCredential.integration_id == uuid.UUID(iid)))
            .scalars()
            .all()
        )
        assert len(rows) == 1
        assert rows[0].value_encrypted != "tok-super-secret"
        from app.services.integration_service import get_credential

        integration = session.get(Integration, uuid.UUID(iid))
        assert get_credential(session, integration, "api_token") == "tok-super-secret"
        assert get_credential(session, integration, "missing") is None
    # Technician cannot manage integrations.
    assert (
        client.post(
            f"/api/v1/integrations/{iid}/credentials",
            json={"key_name": "x", "value": "y"},
            headers=acme_tech["headers"],
        ).status_code
        == 403
    )


def test_integration_credential_fails_closed_without_encryption_key(client, acme_admin):
    created = client.post(
        "/api/v1/integrations",
        json={"provider": "generic_http", "name": "nokey", "config": {}},
        headers=acme_admin["headers"],
    )
    assert created.status_code == 201, created.text
    settings = get_settings()
    old = settings.field_encryption_key
    settings.field_encryption_key = ""
    try:
        resp = client.post(
            f"/api/v1/integrations/{created.json()['id']}/credentials",
            json={"key_name": "api_token", "value": "secret"},
            headers=acme_admin["headers"],
        )
        assert resp.status_code == 503, resp.text
    finally:
        settings.field_encryption_key = old


def test_integration_tenant_isolation(client, acme_admin, globex_admin):
    created = client.post(
        "/api/v1/integrations",
        json={"provider": "github", "name": "iso", "config": {}},
        headers=acme_admin["headers"],
    )
    assert created.status_code == 201, created.text
    iid = created.json()["id"]
    assert client.get(f"/api/v1/integrations/{iid}", headers=globex_admin["headers"]).status_code == 404
    assert client.delete(f"/api/v1/integrations/{iid}", headers=globex_admin["headers"]).status_code == 404


# --- API keys ---------------------------------------------------------------


def test_api_key_create_list_revoke(client, acme_admin, acme_tech, globex_admin, org_ids):
    resp = client.post(
        "/api/v1/api-keys",
        json={"name": "ci", "scopes": ["tickets:read", "webhooks:read"]},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 201, resp.text
    created = resp.json()
    raw_key = created["key"]
    assert raw_key and raw_key.startswith("null_")
    assert created["key_prefix"] == raw_key[:12]
    assert created["revoked_at"] is None

    # Only the hash is stored; the raw key is unrecoverable afterwards.
    with tenant_session(uuid.UUID(org_ids["acme"])) as session:
        row = session.get(ApiKey, uuid.UUID(created["id"]))
        assert row is not None
        assert row.key_hash == hashlib.sha256(raw_key.encode()).hexdigest()
        assert row.key_hash != raw_key
    got = client.get(f"/api/v1/api-keys/{created['id']}", headers=acme_admin["headers"]).json()
    assert got["key"] is None
    listed = client.get("/api/v1/api-keys", headers=acme_admin["headers"]).json()
    assert all(item["key"] is None for item in listed)

    # Unknown scope is rejected.
    bad = client.post(
        "/api/v1/api-keys", json={"name": "bad", "scopes": ["tickets:fly"]}, headers=acme_admin["headers"]
    )
    assert bad.status_code == 400, bad.text
    # Technician cannot manage keys; cross-org is 404.
    assert (
        client.post("/api/v1/api-keys", json={"name": "x", "scopes": []}, headers=acme_tech["headers"]).status_code
        == 403
    )
    assert client.get(f"/api/v1/api-keys/{created['id']}", headers=globex_admin["headers"]).status_code == 404

    # Revoke, then the key no longer authenticates.
    assert client.delete(f"/api/v1/api-keys/{created['id']}", headers=acme_admin["headers"]).status_code == 204
    with tenant_session(uuid.UUID(org_ids["acme"])) as session:
        principal = None
        with pytest.raises(ApiKeyAuthError):
            principal = authenticate_api_key(session, raw_key)
        assert principal is None


def test_api_key_auth_dependency_resolves_org_and_scopes(client, acme_admin, org_ids):
    created = client.post(
        "/api/v1/api-keys",
        json={"name": "auth-test", "scopes": ["tickets:read"]},
        headers=acme_admin["headers"],
    ).json()
    raw_key = created["key"]
    from starlette.requests import Request

    with tenant_session(uuid.UUID(org_ids["acme"])) as session:
        principal = authenticate_api_key(session, raw_key)
        assert principal.organization_id == uuid.UUID(org_ids["acme"])
        assert principal.scopes == ["tickets:read"]
        assert principal.has("tickets:read") and not principal.has("tickets:create")
        # last_used_at was stamped.
        row = session.get(ApiKey, uuid.UUID(created["id"]))
        assert row.last_used_at is not None
        # The dependency itself accepts the X-Api-Key header.
        req = Request({"type": "http", "headers": [(b"x-api-key", raw_key.encode())]})
        resolved = apikeys_router.get_api_key_principal(req, session, raw_key)
        assert resolved.key_id == uuid.UUID(created["id"])
        # Missing / wrong / malformed keys are 401.
        with pytest.raises(Exception):
            apikeys_router.get_api_key_principal(Request({"type": "http", "headers": []}), session, None)
        with pytest.raises(ApiKeyAuthError):
            authenticate_api_key(session, "null_this-key-does-not-exist")
        with pytest.raises(ApiKeyAuthError):
            authenticate_api_key(session, "not-a-null-key")


def test_api_key_expired_key_is_rejected(client, acme_admin, org_ids):
    from datetime import datetime, timezone

    past = datetime(2020, 1, 1, tzinfo=timezone.utc).isoformat()
    created = client.post(
        "/api/v1/api-keys",
        json={"name": "old", "scopes": [], "expires_at": past},
        headers=acme_admin["headers"],
    )
    assert created.status_code == 201, created.text
    with tenant_session(uuid.UUID(org_ids["acme"])) as session:
        with pytest.raises(ApiKeyAuthError):
            authenticate_api_key(session, created.json()["key"])
