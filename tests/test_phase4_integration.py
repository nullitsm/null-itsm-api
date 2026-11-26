"""Phase 4 integration tests — the wiring the coordinator owns.

The four workstream modules were verified in isolation by their own
suites; these tests prove the INTEGRATION: routers registered in
app/main.py, audit literals centralized, links:manage in the catalog,
automation rules firing automatically on ticket writes + the SLA
breach sweep, webhook emission from the real write paths, API-key
auth in the main dependency chain, and scheduled-report email
delivery + the beat sweep.

Webhook tests post to a real local threaded HTTP server (the same
pattern as test_phase4_c): delivery is real HTTP, never mocked.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select

from app.config import get_settings
from app.database import tenant_session
from app.models.workflows import AutomationRun
from app.services import email as email_service
from app.services.email import EmailDeliveryError, EmailProvider
from app.services.reporting_service import cron_matches, run_scheduled_report
from app.tasks import reporting_tasks
from tests.conftest import TEST_APP_URL, set_rls

UTC = timezone.utc


def _uid() -> str:
    return uuid.uuid4().hex[:8]


# --- Real local HTTP server (records requests, scripted responses) --------


class _CaptureHandler(BaseHTTPRequestHandler):
    received: list[dict] = []
    protocol_version = "HTTP/1.1"

    def _handle(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        _CaptureHandler.received.append(
            {"method": self.command, "path": self.path, "headers": dict(self.headers), "body": body}
        )
        payload = b"ok"
        self.send_response(200)
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
def hook_server():
    _CaptureHandler.received = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _CaptureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture()
def enc_key():
    """Ephemeral Fernet key on the (cached) settings singleton."""
    settings = get_settings()
    old = settings.field_encryption_key
    settings.field_encryption_key = Fernet.generate_key().decode()
    yield settings.field_encryption_key
    settings.field_encryption_key = old


# --- Helpers ----------------------------------------------------------------


def _ticket(client, headers, priority="medium", title=None, **extra):
    body = {"title": title or f"ticket-{_uid()}", "description": "test", "priority": priority, "category": "General"}
    body.update(extra)
    resp = client.post("/api/v1/tickets", json=body, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _webhook(client, headers, url, event, secret="test-secret-123"):
    body = {"name": f"hook-{_uid()}", "event_type": event, "target_url": url, "secret": secret}
    resp = client.post("/api/v1/webhooks", json=body, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _events_for(server_url, event):
    """Decoded ``data`` payloads received for one event type.

    The wire envelope is {"event", "organization_id", "delivered_at",
    "data"} — this unwraps "data" and returns (raw_item, data) pairs.
    """
    out = []
    for item in _CaptureHandler.received:
        try:
            payload = json.loads(item["body"])
        except (ValueError, UnicodeDecodeError):
            continue
        if payload.get("event") == event:
            out.append((item, payload.get("data") or {}))
    return out


def _make_api_key(client, headers, scopes, name=None):
    resp = client.post(
        "/api/v1/api-keys", json={"name": name or f"key-{_uid()}", "scopes": scopes}, headers=headers
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _make_report(client, headers, entity="tickets", columns=None, name=None, filters=None):
    resp = client.post(
        "/api/v1/reports",
        json={
            "name": name or f"rep-{_uid()}",
            "entity": entity,
            "columns": columns or ["number", "title", "status"],
            "filters": filters or {},
        },
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _make_schedule(client, headers, report_id, cron="0 9 * * *", recipients=None, is_active=True):
    resp = client.post(
        f"/api/v1/reports/{report_id}/schedules",
        json={"cron_expression": cron, "recipients": recipients or [], "format": "csv", "is_active": is_active},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _make_rule(client, headers, trigger, conditions, actions, name=None):
    resp = client.post(
        "/api/v1/workflows/automation-rules",
        json={
            "name": name or f"rule-{_uid()}",
            "trigger": trigger,
            "entity_type": "ticket",
            "conditions": conditions,
            "actions": actions,
        },
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


class _RecordingProvider(EmailProvider):
    """Fake provider that records every send (tests only)."""

    name = "recording"

    def __init__(self, fail_with: Exception | None = None):
        self.sent: list[dict] = []
        self.fail_with = fail_with

    def send(self, *, to, subject, html_body, text_body, attachments=None):
        if self.fail_with is not None:
            raise self.fail_with
        self.sent.append(
            {"to": to, "subject": subject, "html_body": html_body, "text_body": text_body, "attachments": attachments}
        )
        return "re_recording123"


@pytest.fixture()
def recording_provider():
    provider = _RecordingProvider()
    email_service.set_provider_override(provider)
    try:
        yield provider
    finally:
        email_service.set_provider_override(None)


def _run_schedule_in_session(org_id, schedule_id):
    """Run one scheduled report the way the Celery task does."""
    with tenant_session(uuid.UUID(org_id)) as session:
        from app.models.reporting import ScheduledReport

        scheduled = session.get(ScheduledReport, uuid.UUID(schedule_id))
        assert scheduled is not None
        return run_scheduled_report(session, scheduled)


# --- Cron matcher ------------------------------------------------------------


def test_cron_matches_unit():
    monday_0900 = datetime(2026, 11, 30, 9, 0, tzinfo=UTC)  # a Monday
    sunday_0900 = datetime(2026, 11, 29, 9, 0, tzinfo=UTC)
    assert cron_matches("0 9 * * 1", monday_0900) is True
    assert cron_matches("0 9 * * 2", monday_0900) is False
    assert cron_matches("0 9 30 * *", monday_0900) is True
    assert cron_matches("0 9 15 * 1", monday_0900) is True  # dom OR dow
    assert cron_matches("0 9 15 * 2", monday_0900) is False  # neither
    assert cron_matches("*/15 * * * *", datetime(2026, 11, 30, 9, 30, tzinfo=UTC)) is True
    assert cron_matches("*/15 * * * *", datetime(2026, 11, 30, 9, 31, tzinfo=UTC)) is False
    assert cron_matches("0 9 * * 0", sunday_0900) is True
    assert cron_matches("0 9 * * 7", sunday_0900) is True  # 7 == Sunday
    assert cron_matches("0 9 1-5 * *", datetime(2026, 12, 3, 9, 0, tzinfo=UTC)) is True
    assert cron_matches("0 9 1-5 * *", datetime(2026, 12, 10, 9, 0, tzinfo=UTC)) is False
    assert cron_matches("0 9 * * *", monday_0900) is True
    assert cron_matches("0 8 * * *", monday_0900) is False


# --- API-key auth in the main dependency chain -------------------------------


def test_api_key_reads_and_writes_with_scopes(client, acme_admin, org_ids):
    key = _make_api_key(client, acme_admin["headers"], ["tickets:read", "tickets:create"])
    raw = key["key"]
    assert raw and key["id"]
    headers = {"X-Api-Key": raw}
    listed = client.get("/api/v1/tickets", headers=headers)
    assert listed.status_code == 200, listed.text
    created = client.post(
        "/api/v1/tickets",
        json={"title": "API key ticket", "description": "via key", "priority": "low", "category": "General"},
        headers=headers,
    )
    assert created.status_code == 201, created.text
    # A key has no user identity: the ticket's requester is NULL.
    assert created.json()["requester_id"] is None
    # last_used_at is stamped on the key row.
    got = client.get(f"/api/v1/api-keys/{key['id']}", headers=acme_admin["headers"]).json()
    assert got["last_used_at"] is not None


def test_api_key_scope_gate_and_revocation(client, acme_admin):
    read_only = _make_api_key(client, acme_admin["headers"], ["tickets:read"])
    headers = {"X-Api-Key": read_only["key"]}
    assert client.get("/api/v1/tickets", headers=headers).status_code == 200
    denied = client.post(
        "/api/v1/tickets",
        json={"title": "nope", "description": "x", "priority": "low", "category": "General"},
        headers=headers,
    )
    assert denied.status_code == 403, denied.text
    # Unknown key -> 401; no credentials at all -> 401.
    assert client.get("/api/v1/tickets", headers={"X-Api-Key": "null_fake"}).status_code == 401
    assert client.get("/api/v1/tickets").status_code == 401
    # Revoked key -> 401.
    assert client.delete(f"/api/v1/api-keys/{read_only['id']}", headers=acme_admin["headers"]).status_code == 204
    assert client.get("/api/v1/tickets", headers=headers).status_code == 401


def test_api_key_cannot_escape_its_org(client, acme_admin, globex_admin, org_ids):
    key = _make_api_key(client, acme_admin["headers"], ["tickets:read"])
    headers = {"X-Api-Key": key["key"], "X-Organization-Id": org_ids["globex"]}
    assert client.get("/api/v1/tickets", headers=headers).status_code == 403
    # The matching org header is fine.
    headers = {"X-Api-Key": key["key"], "X-Organization-Id": org_ids["acme"]}
    assert client.get("/api/v1/tickets", headers=headers).status_code == 200


def test_api_key_has_no_user_identity(client, acme_admin):
    key = _make_api_key(
        client,
        acme_admin["headers"],
        ["tickets:read", "tickets:create", "changes:approve", "notifications:read"],
    )
    headers = {"X-Api-Key": key["key"]}
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 403
    assert client.get("/api/v1/notifications", headers=headers).status_code == 403
    assert client.get("/api/v1/organizations/mine", headers=headers).status_code == 403
    change = client.post(
        "/api/v1/changes",
        json={"title": "key change", "risk": "low", "priority": "low", "type": "standard"},
        headers=acme_admin["headers"],
    )
    assert change.status_code == 201, change.text
    denied = client.post(f"/api/v1/changes/{change.json()['id']}/approve", json={}, headers=headers)
    assert denied.status_code == 403, denied.text


# --- Webhook emission from the real write paths ------------------------------


def test_ticket_webhooks_fire_on_create_and_resolve(client, acme_admin, hook_server, enc_key):
    base = f"http://127.0.0.1:{hook_server.server_address[1]}/hook"
    _webhook(client, acme_admin["headers"], base, "ticket.created")
    _webhook(client, acme_admin["headers"], base, "ticket.resolved")
    ticket = _ticket(client, acme_admin["headers"], priority="high", title="Webhook ticket")
    created = _events_for(base, "ticket.created")
    assert len(created) == 1, [p for _, p in _events_for(base, "ticket.created")]
    item, payload = created[0]
    assert payload["ticket_id"] == ticket["id"]
    assert payload["number"] == ticket["number"]
    assert item["headers"].get("X-Null-Signature", "").startswith("sha256=")
    # The signature verifies against the webhook secret.
    expected = "sha256=" + hmac.new(b"test-secret-123", item["body"], hashlib.sha256).hexdigest()
    assert item["headers"]["X-Null-Signature"] == expected
    # Resolve -> ticket.resolved (and ticket.updated is not subscribed here).
    resp = client.patch(f"/api/v1/tickets/{ticket['id']}", json={"status": "resolved"}, headers=acme_admin["headers"])
    assert resp.status_code == 200, resp.text
    resolved = _events_for(base, "ticket.resolved")
    assert len(resolved) == 1
    assert resolved[0][1]["ticket_id"] == ticket["id"]
    assert resolved[0][1]["status"] == "resolved"


def test_change_and_incident_webhooks_fire(client, acme_admin, hook_server, enc_key):
    base = f"http://127.0.0.1:{hook_server.server_address[1]}/hook"
    _webhook(client, acme_admin["headers"], base, "change.created")
    _webhook(client, acme_admin["headers"], base, "change.approved")
    _webhook(client, acme_admin["headers"], base, "incident.declared")
    change = client.post(
        "/api/v1/changes",
        json={"title": "Change hook", "risk": "low", "priority": "low", "type": "standard"},
        headers=acme_admin["headers"],
    )
    assert change.status_code == 201, change.text
    change_id = change.json()["id"]
    assert len(_events_for(base, "change.created")) == 1
    assert _events_for(base, "change.created")[0][1]["change_id"] == change_id
    submitted = client.post(f"/api/v1/changes/{change_id}/submit", headers=acme_admin["headers"])
    assert submitted.status_code == 200, submitted.text
    approved = client.post(
        f"/api/v1/changes/{change_id}/approve", json={"comment": "ok"}, headers=acme_admin["headers"]
    )
    assert approved.status_code == 200, approved.text
    assert len(_events_for(base, "change.approved")) == 1
    ticket = _ticket(client, acme_admin["headers"], title="Incident ticket")
    incident = client.post(
        "/api/v1/problems/incidents",
        json={"ticket_id": ticket["id"], "title": "Major outage", "severity": "critical", "summary": "down"},
        headers=acme_admin["headers"],
    )
    assert incident.status_code == 201, incident.text
    declared = _events_for(base, "incident.declared")
    assert len(declared) == 1
    assert declared[0][1]["ticket_id"] == ticket["id"]


def test_vulnerability_found_webhook_fires_on_manual_import(client, acme_admin, hook_server, enc_key, org_ids):
    base = f"http://127.0.0.1:{hook_server.server_address[1]}/hook"
    _webhook(client, acme_admin["headers"], base, "vulnerability.found")
    engine = client.post(
        "/api/v1/vulnerabilities/engines",
        json={"name": f"eng-{_uid()}", "engine_type": "manual"},
        headers=acme_admin["headers"],
    )
    assert engine.status_code == 201, engine.text
    scan = client.post(
        "/api/v1/vulnerabilities/scans",
        json={"engine_id": engine.json()["id"], "name": f"scan-{_uid()}", "target": "host-a"},
        headers=acme_admin["headers"],
    )
    assert scan.status_code == 201, scan.text
    out = client.post(
        f"/api/v1/vulnerabilities/scans/{scan.json()['id']}/import-results",
        json={"results": [{"host": "host-a", "cve_id": "CVE-2024-42424", "severity": "critical"}]},
        headers=acme_admin["headers"],
    )
    assert out.status_code == 200, out.text
    assert out.json()["findings_created"] == 1, out.json()
    found = _events_for(base, "vulnerability.found")
    assert len(found) == 1
    assert found[0][1]["cve_id"] == "CVE-2024-42424"
    assert found[0][1]["severity"] == "critical"
    # A second import of the same CVE updates the finding but does NOT
    # re-emit: vulnerability.found means first seen.
    scan2 = client.post(
        "/api/v1/vulnerabilities/scans",
        json={"engine_id": engine.json()["id"], "name": f"scan-{_uid()}", "target": "host-a"},
        headers=acme_admin["headers"],
    )
    assert scan2.status_code == 201, scan2.text
    out2 = client.post(
        f"/api/v1/vulnerabilities/scans/{scan2.json()['id']}/import-results",
        json={"results": [{"host": "host-a", "cve_id": "CVE-2024-42424", "severity": "critical"}]},
        headers=acme_admin["headers"],
    )
    assert out2.status_code == 200, out2.text
    assert len(_events_for(base, "vulnerability.found")) == 1


def test_endpoint_enrolled_webhook_fires(client, acme_admin, hook_server, enc_key):
    base = f"http://127.0.0.1:{hook_server.server_address[1]}/hook"
    _webhook(client, acme_admin["headers"], base, "endpoint.enrolled")
    token = client.post(
        "/api/v1/endpoints/enrollment-tokens", json={"label": f"tok-{_uid()}"}, headers=acme_admin["headers"]
    )
    assert token.status_code == 201, token.text
    raw = token.json()["token"]
    enrolled = client.post(
        "/api/v1/agents/enroll",
        json={
            "enrollment_token": raw,
            "device": {"hostname": "hook-laptop", "os": "macOS", "os_version": "26.6", "arch": "arm64"},
        },
    )
    assert enrolled.status_code == 201, enrolled.text
    events = _events_for(base, "endpoint.enrolled")
    assert len(events) == 1
    assert events[0][1]["hostname"] == "hook-laptop"
    assert events[0][1]["endpoint_id"] == enrolled.json()["device_id"]


# --- SLA breach automation ---------------------------------------------------


def test_patch_job_result_still_accepted(client, acme_admin, hook_server, enc_key):
    """Regression: the patch handler's "new_findings" is an INT count,
    while the vuln handler's is a LIST of payloads. Posting a patch
    result must not 500 by iterating the count (and must not emit a
    vulnerability.found event for a patch finding).
    """
    base = f"http://127.0.0.1:{hook_server.server_address[1]}/hook"
    _webhook(client, acme_admin["headers"], base, "vulnerability.found")
    token = client.post(
        "/api/v1/endpoints/enrollment-tokens", json={"label": f"tok-{_uid()}"}, headers=acme_admin["headers"]
    )
    assert token.status_code == 201, token.text
    enrolled = client.post(
        "/api/v1/agents/enroll",
        json={
            "enrollment_token": token.json()["token"],
            "device": {"hostname": "patch-laptop", "os": "macOS", "os_version": "26.6", "arch": "arm64"},
        },
    )
    assert enrolled.status_code == 201, enrolled.text
    device_id = enrolled.json()["device_id"]
    device_token = enrolled.json()["device_token"]
    job = client.post(
        f"/api/v1/endpoints/{device_id}/jobs", json={"type": "patch_scan"}, headers=acme_admin["headers"]
    )
    assert job.status_code == 201, job.text
    result = client.post(
        f"/api/v1/agents/{device_id}/jobs/{job.json()['id']}/result",
        json={
            "status": "succeeded",
            "output": {
                "missing_patches": [{"patch_id": "PATCH-REG-1", "title": "Regression patch", "severity": "high"}],
                "scanned_at": "2026-11-26T12:00:00+00:00",
            },
            "started_at": "2026-11-26T12:00:00+00:00",
            "finished_at": "2026-11-26T12:00:00+00:00",
        },
        headers={"X-Device-Id": device_id, "X-Device-Token": device_token},
    )
    assert result.status_code == 200, result.text
    findings = client.get("/api/v1/patching/findings", headers=acme_admin["headers"]).json()
    assert any(f.get("patch_title") == "Regression patch" for f in findings)
    assert _events_for(base, "vulnerability.found") == []


def test_sla_breach_rule_fires_from_the_sweep(client, acme_admin, org_ids):
    from app.tasks import sla_tasks

    # Scoped to this test's category: an unscoped sla_breach rule would
    # fire on every breached ticket in the shared org, including other
    # tests' tickets, and change their priorities mid-test.
    rule = _make_rule(
        client,
        acme_admin["headers"],
        trigger="sla_breach",
        conditions=[
            {"field": "sla_breached", "operator": "eq", "value": True},
            {"field": "category", "operator": "eq", "value": "Breach-Sweep-Cat"},
        ],
        actions=[{"type": "set_priority", "priority": "critical"}],
        name="Sweep escalator",
    )
    ticket = _ticket(
        client, acme_admin["headers"], priority="low", title="Breaching ticket", category="Breach-Sweep-Cat"
    )
    # Push the first-response due date into the past (stamp_sla_state only
    # computes due dates when they are missing, so this survives the scan).
    import psycopg

    conn = psycopg.connect(TEST_APP_URL.replace("+psycopg", ""), autocommit=True)
    try:
        set_rls(conn, org_ids["acme"])
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE tickets SET first_response_due_at = now() - interval '1 hour' WHERE id = %s",
                (ticket["id"],),
            )
    finally:
        conn.close()
    # Drive the real sweep task: detect -> escalate -> automate.
    result = sla_tasks.scan_sla_breaches()
    assert result["breaches_created"] >= 1, result
    assert result["automation_runs"] >= 1, result
    with tenant_session(uuid.UUID(org_ids["acme"])) as session:
        runs = session.execute(
            select(AutomationRun).where(AutomationRun.rule_id == uuid.UUID(rule["id"]))
        ).scalars().all()
    assert len(runs) == 1
    assert runs[0].trigger == "sla_breach"
    assert runs[0].status == "succeeded"
    got = client.get(f"/api/v1/tickets/{ticket['id']}", headers=acme_admin["headers"]).json()
    assert got["priority"] == "critical"
    assert got["sla_breached"] is True


# --- Scheduled-report email delivery + beat sweep ----------------------------


def test_scheduled_report_emails_csv_attachment(client, acme_admin, org_ids, recording_provider):
    category = f"rep-{_uid()}"
    _ticket(client, acme_admin["headers"], title="Report row one", category=category)
    _ticket(client, acme_admin["headers"], title="Report row two", category=category)
    report = _make_report(
        client, acme_admin["headers"], "tickets", ["number", "title", "status"], filters={"category": category}
    )
    schedule = _make_schedule(
        client, acme_admin["headers"], report["id"], recipients=["ops@acme.example.com", "lead@acme.example.com"]
    )
    summary = _run_schedule_in_session(org_ids["acme"], schedule["id"])
    assert summary["status"] == "success", summary
    assert summary["row_count"] == 2
    assert summary["delivered_to"] == ["ops@acme.example.com", "lead@acme.example.com"]
    assert summary["delivery_failed"] == []
    assert len(recording_provider.sent) == 2
    for sent in recording_provider.sent:
        assert sent["subject"] == f"NULL ITSM scheduled report: {report['name']}"
        assert sent["attachments"] is not None and len(sent["attachments"]) == 1
        attachment = sent["attachments"][0]
        assert attachment["filename"].endswith(".csv")
        assert attachment["filename"].startswith(report["name"].lower().replace(" ", "-")[:10])
        csv_text = attachment["content"].decode("utf-8")
        assert "Report row one" in csv_text and "Report row two" in csv_text
        assert "number,title,status" in csv_text.splitlines()[0]
    # The delivery rows are the durable record (scoped to this test's
    # recipients: the module shares one org across tests).
    with tenant_session(uuid.UUID(org_ids["acme"])) as session:
        from app.models.email import EmailDelivery

        rows = session.execute(
            select(EmailDelivery).where(
                EmailDelivery.template == "scheduled_report",
                EmailDelivery.to_email.in_(["ops@acme.example.com", "lead@acme.example.com"]),
            )
        ).scalars().all()
    assert len(rows) == 2
    assert all(r.status == "sent" for r in rows)
    assert all(r.provider_message_id == "re_recording123" for r in rows)


def test_scheduled_report_no_recipients_sends_nothing(client, acme_admin, org_ids, recording_provider):
    report = _make_report(client, acme_admin["headers"], "tickets", ["number", "title"])
    schedule = _make_schedule(client, acme_admin["headers"], report["id"], recipients=[])
    summary = _run_schedule_in_session(org_ids["acme"], schedule["id"])
    assert summary["status"] == "success", summary
    assert summary["delivered_to"] == [] and summary["delivery_failed"] == []
    assert recording_provider.sent == []


def test_scheduled_report_delivery_failure_is_recorded_not_fatal(client, acme_admin, org_ids, monkeypatch):
    failing = _RecordingProvider(fail_with=EmailDeliveryError("Resend rejected the message (HTTP 401)"))
    email_service.set_provider_override(failing)
    retries: list = []
    monkeypatch.setattr(email_service, "_enqueue_retry", lambda *a, **k: retries.append(a))
    try:
        report = _make_report(client, acme_admin["headers"], "tickets", ["number", "title"])
        schedule = _make_schedule(
            client, acme_admin["headers"], report["id"], recipients=["fail-ops@acme.example.com"]
        )
        summary = _run_schedule_in_session(org_ids["acme"], schedule["id"])
    finally:
        email_service.set_provider_override(None)
    # Generation succeeded; delivery failed and is reported, not hidden.
    assert summary["status"] == "success", summary
    assert summary["delivered_to"] == []
    assert len(summary["delivery_failed"]) == 1
    assert summary["delivery_failed"][0]["to"] == "fail-ops@acme.example.com"
    with tenant_session(uuid.UUID(org_ids["acme"])) as session:
        from app.models.email import EmailDelivery

        rows = session.execute(
            select(EmailDelivery).where(
                EmailDelivery.template == "scheduled_report",
                EmailDelivery.to_email == "fail-ops@acme.example.com",
            )
        ).scalars().all()
    assert len(rows) == 1 and rows[0].status == "failed"
    # No retry was enqueued for the report mail: the retry task re-sends
    # from stored bodies, which would drop the CSV attachment. The next
    # scheduled run re-sends it instead.
    assert retries == []
    assert failing.sent == []


def test_generate_scheduled_report_task_end_to_end(client, acme_admin, org_ids, recording_provider):
    from app.services.reporting_service import generate_scheduled_report

    _ticket(client, acme_admin["headers"], title="Task row", category=f"task-{_uid()}")
    report = _make_report(client, acme_admin["headers"], "tickets", ["number", "title"])
    schedule = _make_schedule(
        client, acme_admin["headers"], report["id"], recipients=["task@acme.example.com"]
    )
    result = generate_scheduled_report(str(schedule["id"]))
    assert result["status"] == "success", result
    assert result["delivered_to"] == ["task@acme.example.com"]
    assert len(recording_provider.sent) == 1


def test_sweep_enqueues_only_due_active_schedules(client, acme_admin, org_ids, monkeypatch):
    report = _make_report(client, acme_admin["headers"], "tickets", ["number", "title"])
    due = _make_schedule(client, acme_admin["headers"], report["id"], cron="* * * * *")
    not_due = _make_schedule(client, acme_admin["headers"], report["id"], cron="0 0 1 1 *")
    inactive = _make_schedule(client, acme_admin["headers"], report["id"], cron="* * * * *", is_active=False)
    enqueued: list[str] = []
    monkeypatch.setattr(
        reporting_tasks.generate_scheduled_report, "delay", lambda schedule_id: enqueued.append(schedule_id)
    )
    result = reporting_tasks.sweep_scheduled_reports()
    assert due["id"] in enqueued
    assert not_due["id"] not in enqueued
    assert inactive["id"] not in enqueued
    assert result["enqueued"] == len(enqueued)
    assert result["orgs"] >= 1


def test_sweep_due_window_uses_last_run():
    """A schedule that already ran for its cron minute does not re-fire.

    Tested against _due_minutes with fixed times: a live sweep would
    race the minute boundary (last_run_at 30s ago crosses it half the
    time), so the boundary logic is pinned here and the sweep test
    above covers enqueue/not-due/inactive end to end.
    """
    from app.models.reporting import ScheduledReport

    def _schedule(last_run_at, cron="* * * * *"):
        return ScheduledReport(
            organization_id=uuid.uuid4(),
            report_id=uuid.uuid4(),
            cron_expression=cron,
            recipients=[],
            last_run_at=last_run_at,
        )

    # Ran 30s ago, same minute: no new minute in (last run, now].
    assert (
        reporting_tasks._due_minutes(
            _schedule(datetime(2026, 11, 30, 9, 0, 30, tzinfo=UTC)),
            datetime(2026, 11, 30, 9, 0, 45, tzinfo=UTC),
        )
        is False
    )
    # Ran last minute, new minute in the window: due.
    assert (
        reporting_tasks._due_minutes(
            _schedule(datetime(2026, 11, 30, 8, 59, 30, tzinfo=UTC)),
            datetime(2026, 11, 30, 9, 0, 15, tzinfo=UTC),
        )
        is True
    )
    # Never ran: only the last 5 minutes count.
    assert (
        reporting_tasks._due_minutes(
            _schedule(None, cron="0 9 * * *"),
            datetime(2026, 11, 30, 9, 3, 0, tzinfo=UTC),
        )
        is True
    )
    assert (
        reporting_tasks._due_minutes(
            _schedule(None, cron="0 9 * * *"),
            datetime(2026, 11, 30, 9, 6, 0, tzinfo=UTC),
        )
        is False
    )
