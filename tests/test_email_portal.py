"""Phase 2 email / portal / import / export tests.

Run ONLY via ``bash scripts/run_tests_locked.sh tests/test_email_portal.py``
(shared test DB — never bare pytest while siblings work).
"""

from __future__ import annotations

import uuid

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import delete, select

from app.config import get_settings
from app.database import tenant_session
from app.models.audit import AuditLog
from app.models.auth import Invitation
from app.models.email_portal import EmailMailbox, EmailMessage, PortalSession
from app.models.itsm import CatalogItem, KnowledgeArticle, Notification, TicketComment
from app.models.platform import Membership
from app.models.ticket import Ticket
from app.seed import DEV_PASSWORD
from app.services.email_ingest import ingest_message, parse_message

ALICE = "alice@acme.example.com"
TOM = "tom@acme.example.com"
GINA = "gina@globex.example.com"


@pytest.fixture()
def enc_key(monkeypatch):
    """Ephemeral Fernet key on the (cached) settings singleton."""
    settings = get_settings()
    old = settings.field_encryption_key
    settings.field_encryption_key = Fernet.generate_key().decode()
    yield settings.field_encryption_key
    settings.field_encryption_key = old


def _user_id(org_id: str, email: str) -> uuid.UUID:
    """User id via the SECURITY DEFINER lookup (a raw users SELECT is
    RLS-filtered without a user context)."""
    from sqlalchemy import text

    with tenant_session(uuid.UUID(org_id)) as session:
        row = session.execute(text("SELECT * FROM auth_get_user_by_email(:email)"), {"email": email}).mappings().first()
        assert row is not None, f"no user {email}"
        return uuid.UUID(str(row["id"]))


def _portal_login(client, email: str) -> dict:
    resp = client.post("/api/v1/portal/auth/login", json={"email": email, "password": DEV_PASSWORD})
    assert resp.status_code == 200, resp.text
    data = resp.json()
    return {"headers": {"Authorization": f"Bearer {data['access_token']}"}, "tokens": data}


def _make_ticket(client, headers, title="Portal scoping ticket") -> dict:
    resp = client.post("/api/v1/tickets", json={"title": title}, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


RAW_MEMBER_MAIL = (
    b"From: Tom Technician <tom@acme.example.com>\r\n"
    b"To: support@acme.example.com\r\n"
    b"Subject: VPN is down\r\n"
    b"Message-ID: <member-1@acme.example.com>\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
    b"My VPN stopped working this morning.\r\n"
)

RAW_STRANGER_MAIL = (
    b"From: Stranger <stranger@example.com>\r\n"
    b"To: support@acme.example.com\r\n"
    b"Subject: Hello there\r\n"
    b"Message-ID: <stranger-1@example.com>\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
    b"I am not a member of this org.\r\n"
)


# --- Pure parsing / crypto -------------------------------------------------


def test_parse_message_multipart():
    raw = (
        b"From: A <a@example.com>\r\n"
        b"To: b@example.com, c@example.com\r\n"
        b"Subject: Hi\r\n"
        b"Message-ID: <m1@example.com>\r\n"
        b"In-Reply-To: <m0@example.com>\r\n"
        b"References: <m0@example.com>\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: multipart/alternative; boundary="B"\r\n\r\n'
        b"--B\r\nContent-Type: text/plain\r\n\r\nHello text\r\n"
        b"--B\r\nContent-Type: text/html\r\n\r\n<p>Hello html</p>\r\n--B--\r\n"
    )
    parsed = parse_message(raw)
    assert parsed["from"] == "a@example.com"
    assert parsed["to"] == ["b@example.com", "c@example.com"]
    assert parsed["subject"] == "Hi"
    assert parsed["message_id"] == "<m1@example.com>"
    assert parsed["in_reply_to"] == "<m0@example.com>"
    assert parsed["references"] == ["<m0@example.com>"]
    assert parsed["body_text"] == "Hello text"
    assert "<p>Hello html</p>" in (parsed["body_html"] or "")


def test_crypto_roundtrip_and_fail_closed(enc_key):
    from app.crypto import decrypt, encrypt

    token = encrypt("s3cret-password")
    assert token != "s3cret-password"
    assert decrypt(token) == "s3cret-password"
    settings = get_settings()
    settings.field_encryption_key = ""
    try:
        with pytest.raises(RuntimeError, match="not configured"):
            encrypt("x")
        with pytest.raises(RuntimeError, match="not configured"):
            decrypt(token)
    finally:
        settings.field_encryption_key = enc_key


# --- Ingest ----------------------------------------------------------------


def test_ingest_member_creates_ticket(org_ids):
    org_id = org_ids["acme"]
    with tenant_session(uuid.UUID(org_id)) as session:
        msg = ingest_message(session, uuid.UUID(org_id), None, RAW_MEMBER_MAIL)
        assert msg.ticket_id is not None
        assert msg.status == "processed"
        ticket = session.get(Ticket, msg.ticket_id)
        assert ticket is not None
        assert ticket.title == "VPN is down"
        assert ticket.requester_id == _user_id(org_id, TOM)


def test_ingest_unknown_sender_no_ticket(org_ids):
    org_id = org_ids["acme"]
    with tenant_session(uuid.UUID(org_id)) as session:
        msg = ingest_message(session, uuid.UUID(org_id), None, RAW_STRANGER_MAIL)
        assert msg.ticket_id is None
        assert msg.status == "received"


def test_ingest_duplicate_message_id_deduped(org_ids):
    org_id = org_ids["acme"]
    raw = (
        b"From: Tom Technician <tom@acme.example.com>\r\n"
        b"To: support@acme.example.com\r\n"
        b"Subject: Dup check\r\n"
        b"Message-ID: <dup-1@acme.example.com>\r\n"
        b"Content-Type: text/plain\r\n\r\nDuplicate body\r\n"
    )
    with tenant_session(uuid.UUID(org_id)) as session:
        first = ingest_message(session, uuid.UUID(org_id), None, raw)
        second = ingest_message(session, uuid.UUID(org_id), None, raw)
        assert first.id == second.id
        count = session.execute(
            select(EmailMessage).where(
                EmailMessage.organization_id == uuid.UUID(org_id),
                EmailMessage.message_id == "<dup-1@acme.example.com>",
            )
        ).scalars()
        assert len(list(count)) == 1


def test_ingest_subject_thread_attaches_and_comments(client, acme_admin, org_ids):
    ticket = _make_ticket(client, acme_admin["headers"], title="Thread target")
    org_id = org_ids["acme"]
    raw = (
        f"From: Stranger <stranger@example.com>\r\n"
        f"To: support@acme.example.com\r\n"
        f"Subject: Re: [{ticket['number']}] follow-up\r\n"
        f"Message-ID: <thread-subj-{uuid.uuid4()}@example.com>\r\n"
        f"Content-Type: text/plain\r\n\r\nAdding more detail here.\r\n"
    ).encode()
    with tenant_session(uuid.UUID(org_id)) as session:
        msg = ingest_message(session, uuid.UUID(org_id), None, raw)
        assert str(msg.ticket_id) == ticket["id"]
        assert msg.status == "processed"
        comments = list(
            session.execute(
                select(TicketComment).where(
                    TicketComment.ticket_id == uuid.UUID(ticket["id"]), TicketComment.is_internal.is_(False)
                )
            ).scalars()
        )
        assert len(comments) == 1
        assert "Adding more detail" in comments[0].body


def test_ingest_in_reply_to_thread_attaches(client, acme_admin, org_ids):
    ticket = _make_ticket(client, acme_admin["headers"], title="In-Reply-To target")
    org_id = org_ids["acme"]
    with tenant_session(uuid.UUID(org_id)) as session:
        outbound = EmailMessage(
            organization_id=uuid.UUID(org_id),
            mailbox_id=None,
            message_id="<out-1@null.local>",
            from_address="no-reply@nullitsm.local",
            to_addresses=["tom@acme.example.com"],
            subject="Re: In-Reply-To target",
            body_text="Our reply",
            direction="outbound",
            status="replied",
            ticket_id=uuid.UUID(ticket["id"]),
        )
        session.add(outbound)
        session.flush()
        raw = (
            b"From: Tom Technician <tom@acme.example.com>\r\n"
            b"To: no-reply@nullitsm.local\r\n"
            b"Subject: Re: In-Reply-To target\r\n"
            b"In-Reply-To: <out-1@null.local>\r\n"
            b"Message-ID: <in-reply-1@acme.example.com>\r\n"
            b"Content-Type: text/plain\r\n\r\nThanks, that fixed it.\r\n"
        )
        msg = ingest_message(session, uuid.UUID(org_id), None, raw)
        assert str(msg.ticket_id) == ticket["id"]


# --- Reply flow ------------------------------------------------------------


def test_reply_creates_outbound_row_and_public_comment(client, acme_admin, org_ids):
    org_id = org_ids["acme"]
    with tenant_session(uuid.UUID(org_id)) as session:
        msg = ingest_message(session, uuid.UUID(org_id), None, RAW_MEMBER_MAIL)
        message_id = str(msg.id)
        ticket_id = str(msg.ticket_id)
    resp = client.post(
        f"/api/v1/email/messages/{message_id}/reply",
        json={"body": "Please restart the VPN client."},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 201, resp.text
    outbound = resp.json()
    assert outbound["direction"] == "outbound"
    assert outbound["status"] == "replied"
    assert outbound["ticket_id"] == ticket_id
    with tenant_session(uuid.UUID(org_id)) as session:
        comments = list(
            session.execute(
                select(TicketComment).where(
                    TicketComment.ticket_id == uuid.UUID(ticket_id), TicketComment.is_internal.is_(False)
                )
            ).scalars()
        )
        assert any("restart the VPN client" in c.body for c in comments)
        audits = list(
            session.execute(
                select(AuditLog).where(AuditLog.action == "email.reply_sent", AuditLog.resource_id == message_id)
            ).scalars()
        )
        assert len(audits) == 1


def test_convert_unknown_sender_to_ticket(client, acme_admin, org_ids):
    org_id = org_ids["acme"]
    with tenant_session(uuid.UUID(org_id)) as session:
        msg = ingest_message(session, uuid.UUID(org_id), None, RAW_STRANGER_MAIL)
        message_id = str(msg.id)
    resp = client.post(f"/api/v1/email/messages/{message_id}/convert", headers=acme_admin["headers"])
    assert resp.status_code == 200, resp.text
    assert resp.json()["ticket_number"].startswith("INC-")
    with tenant_session(uuid.UUID(org_id)) as session:
        stored = session.get(EmailMessage, uuid.UUID(message_id))
        assert stored.status == "processed"
        assert stored.ticket_id is not None


# --- Mailboxes -------------------------------------------------------------


def test_mailbox_crud_encrypts_password(client, acme_admin, acme_tech, globex_admin, org_ids, enc_key):
    create = client.post(
        "/api/v1/email/mailboxes",
        json={
            "name": "Support",
            "host": "imap.example.com",
            "username": "support@acme.example.com",
            "password": "mailbox-secret",
        },
        headers=acme_admin["headers"],
    )
    assert create.status_code == 201, create.text
    mailbox = create.json()
    assert "password" not in mailbox
    assert mailbox["has_password"] is True
    mailbox_id = mailbox["id"]
    org_id = org_ids["acme"]
    with tenant_session(uuid.UUID(org_id)) as session:
        row = session.get(EmailMailbox, uuid.UUID(mailbox_id))
        assert row.password_encrypted != "mailbox-secret"
        from app.crypto import decrypt

        assert decrypt(row.password_encrypted) == "mailbox-secret"
    # Cross-org: globex admin must not see it.
    resp = client.get(f"/api/v1/email/mailboxes/{mailbox_id}", headers=globex_admin["headers"])
    assert resp.status_code == 404
    # Tech (email:read, no email:manage) cannot create.
    resp = client.post(
        "/api/v1/email/mailboxes",
        json={"name": "X", "host": "h", "username": "u", "password": "p"},
        headers=acme_tech["headers"],
    )
    assert resp.status_code == 403
    # Delete.
    resp = client.delete(f"/api/v1/email/mailboxes/{mailbox_id}", headers=acme_admin["headers"])
    assert resp.status_code == 200


def test_mailbox_create_fails_closed_without_key(client, acme_admin):
    settings = get_settings()
    old = settings.field_encryption_key
    settings.field_encryption_key = ""
    try:
        resp = client.post(
            "/api/v1/email/mailboxes",
            json={"name": "NoKey", "host": "h", "username": "u", "password": "p"},
            headers=acme_admin["headers"],
        )
        assert resp.status_code == 400
        assert "not configured" in resp.text
    finally:
        settings.field_encryption_key = old


# --- Poller (stubbed IMAP) -------------------------------------------------


class _FakeIMAP:
    def __init__(self, host, port):
        self.host = host
        self.port = port

    def login(self, user, password):
        assert password == "mailbox-secret"
        return ("OK", [])

    def select(self, folder):
        return ("OK", [b"1"])

    def search(self, charset, *criteria):
        return ("OK", [b"1"])

    def fetch(self, num, parts):
        return ("OK", [(b"1 (RFC822)", RAW_MEMBER_MAIL)])

    def store(self, num, command, flags):
        return ("OK", [])

    def logout(self):
        return ("OK", [])


def test_poll_mailbox_stubbed_imap(client, acme_admin, org_ids, enc_key, monkeypatch):
    import app.tasks.email_tasks as email_tasks

    monkeypatch.setattr(email_tasks.imaplib, "IMAP4_SSL", _FakeIMAP)
    create = client.post(
        "/api/v1/email/mailboxes",
        json={
            "name": "PollBox",
            "host": "imap.example.com",
            "username": "support@acme.example.com",
            "password": "mailbox-secret",
        },
        headers=acme_admin["headers"],
    )
    assert create.status_code == 201, create.text
    mailbox_id = create.json()["id"]
    org_id = org_ids["acme"]
    # The member mail was already ingested in an earlier test with the
    # same Message-ID, so dedupe means 0 NEW tickets — but poll still
    # counts the fetch as ingested (ingest returns the existing row).
    resp = client.post(f"/api/v1/email/mailboxes/{mailbox_id}/poll", headers=acme_admin["headers"])
    assert resp.status_code == 200, resp.text
    assert resp.json()["ingested"] == 1
    with tenant_session(uuid.UUID(org_id)) as session:
        row = session.get(EmailMailbox, uuid.UUID(mailbox_id))
        assert row.last_poll_at is not None
        assert row.last_error is None
    client.delete(f"/api/v1/email/mailboxes/{mailbox_id}", headers=acme_admin["headers"])


def test_poll_mailboxes_no_mailbox_returns_zero(org_ids):
    from app.tasks.email_tasks import poll_mailboxes

    result = poll_mailboxes(str(org_ids["globex"]))
    assert result == {"polled": 0, "ingested": 0, "errors": []}


# --- Portal ----------------------------------------------------------------


def test_portal_login_and_me(client, org_ids):
    portal = _portal_login(client, ALICE)
    me = client.get("/api/v1/portal/me", headers=portal["headers"])
    assert me.status_code == 200, me.text
    body = me.json()
    assert body["user"]["email"] == ALICE
    assert body["organization_id"] == org_ids["acme"]
    assert isinstance(body["branding"], dict)
    with tenant_session(uuid.UUID(org_ids["acme"])) as session:
        rows = list(session.execute(select(PortalSession)).scalars())
        assert any(r.user_id == uuid.UUID(portal["tokens"]["user_id"]) for r in rows)


def test_portal_token_isolation(client, acme_admin):
    portal = _portal_login(client, ALICE)
    # Org access token must NOT authenticate a portal endpoint.
    resp = client.get("/api/v1/portal/me", headers=acme_admin["headers"])
    assert resp.status_code == 401
    # Portal token must NOT authenticate an org endpoint.
    resp = client.get("/api/v1/tickets", headers=portal["headers"])
    assert resp.status_code == 401


def test_portal_own_only_scoping(client, acme_admin, acme_tech, globex_admin, org_ids):
    portal = _portal_login(client, ALICE)
    alice_id = uuid.UUID(portal["tokens"]["user_id"])
    own = client.post("/api/v1/portal/tickets", json={"title": "Alice own ticket"}, headers=portal["headers"])
    assert own.status_code == 201, own.text
    own_id = own.json()["id"]
    # Tom's ticket (same org, different requester) is invisible to Alice's portal.
    tom_ticket = _make_ticket(client, acme_tech["headers"], title="Tom ticket")
    resp = client.get(f"/api/v1/portal/tickets/{tom_ticket['id']}", headers=portal["headers"])
    assert resp.status_code == 404
    # Globex ticket is invisible too.
    globex_ticket = _make_ticket(client, globex_admin["headers"], title="Globex ticket")
    resp = client.get(f"/api/v1/portal/tickets/{globex_ticket['id']}", headers=portal["headers"])
    assert resp.status_code == 404
    # Own ticket visible; list contains only Alice's.
    resp = client.get(f"/api/v1/portal/tickets/{own_id}", headers=portal["headers"])
    assert resp.status_code == 200
    listed = client.get("/api/v1/portal/tickets", headers=portal["headers"]).json()
    assert all(t["requester_id"] == str(alice_id) for t in listed)
    assert any(t["id"] == own_id for t in listed)


def test_portal_logout_revokes(client):
    portal = _portal_login(client, ALICE)
    resp = client.post("/api/v1/portal/auth/logout", headers=portal["headers"])
    assert resp.status_code == 200
    resp = client.get("/api/v1/portal/me", headers=portal["headers"])
    assert resp.status_code == 401


def test_portal_requests_and_approve(client, org_ids):
    portal = _portal_login(client, ALICE)
    alice_id = uuid.UUID(portal["tokens"]["user_id"])
    tom_id = _user_id(org_ids["acme"], TOM)
    created = client.post("/api/v1/portal/requests", json={"title": "New laptop"}, headers=portal["headers"])
    assert created.status_code == 201, created.text
    assert created.json()["number"].startswith("REQ-")
    assert created.json()["requester_id"] == str(alice_id)
    req_id = created.json()["id"]
    assert client.get(f"/api/v1/portal/requests/{req_id}", headers=portal["headers"]).status_code == 200

    # Approve path: a request assigned to Alice (approver) in pending_approval.
    from app.models.itsm import ServiceRequest

    with tenant_session(uuid.UUID(org_ids["acme"])) as session:
        req = ServiceRequest(
            organization_id=uuid.UUID(org_ids["acme"]),
            number="REQ-999001",
            title="Approve me",
            status="pending_approval",
            requester_id=tom_id,
            assignee_id=alice_id,
        )
        session.add(req)
        session.flush()
        approvable_id = str(req.id)
        other = ServiceRequest(
            organization_id=uuid.UUID(org_ids["acme"]),
            number="REQ-999002",
            title="Not yours",
            status="pending_approval",
            requester_id=tom_id,
            assignee_id=tom_id,
        )
        session.add(other)
        session.flush()
        other_id = str(other.id)
    resp = client.post(f"/api/v1/portal/requests/{approvable_id}/approve", headers=portal["headers"])
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "approved"
    # Not the assigned approver -> 403.
    resp = client.post(f"/api/v1/portal/requests/{other_id}/approve", headers=portal["headers"])
    assert resp.status_code == 403
    # Already approved -> 400.
    resp = client.post(f"/api/v1/portal/requests/{approvable_id}/approve", headers=portal["headers"])
    assert resp.status_code == 400


def test_portal_catalog_knowledge_notifications_published_only(client, org_ids):
    portal = _portal_login(client, ALICE)
    alice_id = uuid.UUID(portal["tokens"]["user_id"])
    tom_id = _user_id(org_ids["acme"], TOM)
    org_id = uuid.UUID(org_ids["acme"])
    with tenant_session(org_id) as session:
        session.add(CatalogItem(organization_id=org_id, name="Pub item", status="published"))
        session.add(CatalogItem(organization_id=org_id, name="Draft item", status="draft"))
        session.add(
            KnowledgeArticle(organization_id=org_id, title="Pub article", slug="pub-article", status="published")
        )
        session.add(
            KnowledgeArticle(organization_id=org_id, title="Draft article", slug="draft-article", status="draft")
        )
        session.add(Notification(organization_id=org_id, user_id=alice_id, type="ticket", title="For Alice", body="hi"))
        session.add(Notification(organization_id=org_id, user_id=tom_id, type="ticket", title="For Tom", body="hi"))
    catalog = client.get("/api/v1/portal/catalog", headers=portal["headers"]).json()
    assert [c["name"] for c in catalog] == ["Pub item"]
    kb = client.get("/api/v1/portal/knowledge", headers=portal["headers"]).json()
    assert [a["title"] for a in kb] == ["Pub article"]
    notes = client.get("/api/v1/portal/notifications", headers=portal["headers"]).json()
    assert [n["title"] for n in notes] == ["For Alice"]
    # Clean up: the shared test DB is used by sibling suites, and their
    # notifications test asserts Tom has NO notifications — remove only
    # the rows this test inserted so it cannot pollute other suites.
    with tenant_session(org_id) as session:
        session.execute(
            delete(CatalogItem).where(
                CatalogItem.organization_id == org_id, CatalogItem.name.in_(["Pub item", "Draft item"])
            )
        )
        session.execute(
            delete(KnowledgeArticle).where(
                KnowledgeArticle.organization_id == org_id,
                KnowledgeArticle.slug.in_(["pub-article", "draft-article"]),
            )
        )
        session.execute(
            delete(Notification).where(
                Notification.organization_id == org_id, Notification.title.in_(["For Alice", "For Tom"])
            )
        )


# --- Imports ---------------------------------------------------------------


def test_import_servicenow_mapping_and_idempotency(client, acme_admin, org_ids):
    rows = [
        {
            "number": "INC1001",
            "short_description": "VPN down",
            "description": "VPN broken",
            "state": "1",
            "priority": "2",
            "caller_id": "tom@acme.example.com",
        },
        {"number": "INC1002", "short_description": "Bad row", "target_type": "bogus"},
    ]
    resp = client.post(
        "/api/v1/imports", json={"source_system": "servicenow", "rows": rows}, headers=acme_admin["headers"]
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["status"] == "partial"
    assert body["summary"] == {"imported": 1, "failed": 1, "skipped": 0, "total": 2}
    assert body["records"][0]["status"] == "imported"
    assert body["records"][1]["status"] == "failed"
    org_id = org_ids["acme"]
    with tenant_session(uuid.UUID(org_id)) as session:
        ticket = session.execute(
            select(Ticket).where(Ticket.organization_id == uuid.UUID(org_id), Ticket.title == "VPN down")
        ).scalar_one()
        assert ticket.status == "open"
        assert ticket.priority == "high"
        assert ticket.requester_id == _user_id(org_id, TOM)
    # Reprocess: already-imported skipped, no duplicate ticket.
    resp = client.post(f"/api/v1/imports/{body['id']}/reprocess", headers=acme_admin["headers"])
    assert resp.status_code == 200, resp.text
    assert resp.json()["summary"]["skipped"] == 1
    with tenant_session(uuid.UUID(org_id)) as session:
        count = session.execute(
            select(Ticket).where(Ticket.organization_id == uuid.UUID(org_id), Ticket.title == "VPN down")
        ).scalars()
        assert len(list(count)) == 1


def test_import_csv_and_jira(client, acme_admin, org_ids):
    csv_rows = [{"source_id": "csv-1", "title": "CSV ticket", "description": "d", "status": "open", "priority": "low"}]
    resp = client.post(
        "/api/v1/imports", json={"source_system": "csv", "rows": csv_rows}, headers=acme_admin["headers"]
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["status"] == "completed"
    jira_rows = [
        {
            "key": "PROJ-7",
            "summary": "Jira ticket",
            "description": "d",
            "status": "In Progress",
            "priority": "High",
            "reporter": {"emailAddress": "tom@acme.example.com", "displayName": "Tom"},
        }
    ]
    resp = client.post(
        "/api/v1/imports", json={"source_system": "jira", "rows": jira_rows}, headers=acme_admin["headers"]
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["status"] == "completed"
    org_id = org_ids["acme"]
    with tenant_session(uuid.UUID(org_id)) as session:
        jira_ticket = session.execute(
            select(Ticket).where(Ticket.organization_id == uuid.UUID(org_id), Ticket.title == "Jira ticket")
        ).scalar_one()
        assert jira_ticket.status == "in_progress"
        assert jira_ticket.priority == "high"


def test_import_user_invited_flow(client, acme_admin, org_ids):
    email = f"imported-{uuid.uuid4().hex[:8]}@example.com"
    rows = [{"source_id": "u-1", "target_type": "user", "requester_email": email, "full_name": "Imported Person"}]
    resp = client.post("/api/v1/imports", json={"source_system": "csv", "rows": rows}, headers=acme_admin["headers"])
    assert resp.status_code == 201, resp.text
    assert resp.json()["status"] == "completed"
    org_id = org_ids["acme"]
    with tenant_session(uuid.UUID(org_id)) as session:
        user_id = _user_id(org_id, email)
        membership = session.execute(
            select(Membership).where(Membership.organization_id == uuid.UUID(org_id), Membership.user_id == user_id)
        ).scalar_one()
        assert membership.status == "invited"
        invitation = session.execute(
            select(Invitation).where(Invitation.organization_id == uuid.UUID(org_id), Invitation.email == email)
        ).scalar_one()
        assert invitation.status == "pending"


def test_import_cross_org_404(client, acme_admin, globex_admin):
    resp = client.post(
        "/api/v1/imports",
        json={"source_system": "csv", "rows": [{"source_id": "x-1", "title": "t"}]},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 201
    import_id = resp.json()["id"]
    resp = client.get(f"/api/v1/imports/{import_id}", headers=globex_admin["headers"])
    assert resp.status_code == 404


# --- Exports ---------------------------------------------------------------


def test_export_csv_json_and_download_regeneration(client, acme_admin, org_ids):
    ticket = _make_ticket(client, acme_admin["headers"], title="Export me")
    resp = client.post(
        "/api/v1/exports", json={"export_type": "tickets", "format": "csv"}, headers=acme_admin["headers"]
    )
    assert resp.status_code == 201, resp.text
    export = resp.json()
    assert export["status"] == "completed"
    assert export["row_count"] >= 1
    assert export["storage_key"] is None  # S3 unconfigured in tests
    dl = client.get(f"/api/v1/exports/{export['id']}/download", headers=acme_admin["headers"])
    assert dl.status_code == 200
    assert ticket["number"] in dl.text
    assert "Export me" in dl.text
    # Regeneration: a ticket created AFTER the export appears in a fresh download.
    later = _make_ticket(client, acme_admin["headers"], title="Export me later")
    dl2 = client.get(f"/api/v1/exports/{export['id']}/download", headers=acme_admin["headers"])
    assert later["number"] in dl2.text
    # JSON export.
    resp = client.post(
        "/api/v1/exports", json={"export_type": "tickets", "format": "json"}, headers=acme_admin["headers"]
    )
    assert resp.status_code == 201
    dl = client.get(f"/api/v1/exports/{resp.json()['id']}/download", headers=acme_admin["headers"])
    assert '"number": "' in dl.text
    # Full export is JSON-only.
    resp = client.post("/api/v1/exports", json={"export_type": "full", "format": "json"}, headers=acme_admin["headers"])
    assert resp.status_code == 201, resp.text
    dl = client.get(f"/api/v1/exports/{resp.json()['id']}/download", headers=acme_admin["headers"])
    bundle = dl.json()
    assert set(bundle.keys()) == {"tickets", "requests", "users", "audit"}
    resp = client.post("/api/v1/exports", json={"export_type": "full", "format": "csv"}, headers=acme_admin["headers"])
    assert resp.status_code == 400


def test_export_list_and_audit(client, acme_admin, org_ids):
    resp = client.post("/api/v1/exports", json={"export_type": "audit", "format": "csv"}, headers=acme_admin["headers"])
    assert resp.status_code == 201, resp.text
    listed = client.get("/api/v1/exports", headers=acme_admin["headers"])
    assert listed.status_code == 200
    assert any(e["id"] == resp.json()["id"] for e in listed.json())
    org_id = org_ids["acme"]
    with tenant_session(uuid.UUID(org_id)) as session:
        rows = list(
            session.execute(
                select(AuditLog).where(AuditLog.action == "export.completed", AuditLog.resource_id == resp.json()["id"])
            ).scalars()
        )
        assert len(rows) == 1


# --- Tenant isolation / RLS ------------------------------------------------


def test_rls_email_messages_raw_sql(app_db, org_ids):
    from tests.conftest import set_rls

    set_rls(app_db, None)
    with app_db.cursor() as cur:
        cur.execute("SELECT count(*) FROM email_messages")
        assert cur.fetchone()[0] == 0
    set_rls(app_db, org_ids["acme"])
    with app_db.cursor() as cur:
        cur.execute("SELECT organization_id FROM email_messages")
        rows = cur.fetchall()
        assert len(rows) >= 1
        assert all(str(r[0]) == org_ids["acme"] for r in rows)
    set_rls(app_db, org_ids["globex"])
    with app_db.cursor() as cur:
        cur.execute("SELECT count(*) FROM email_messages")
        assert cur.fetchone()[0] == 0


def test_audit_rows_written_for_ingest(org_ids):
    org_id = org_ids["acme"]
    with tenant_session(uuid.UUID(org_id)) as session:
        rows = list(session.execute(select(AuditLog).where(AuditLog.action == "email.message_ingested")).scalars())
        assert len(rows) >= 1
        assert all(str(r.organization_id) == org_id for r in rows)
