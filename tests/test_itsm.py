"""Phase 2 ITSM engine tests.

Covers requests / catalog / knowledge / changes / problems /
notifications / ticket comments / attachments / links / templates /
recurring tickets / major incidents / surveys, tenant isolation on
every resource, raw-SQL RLS checks, and audit rows.
"""

from __future__ import annotations

import base64
import re
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from tests.conftest import set_rls


@pytest.fixture(scope="module", autouse=True)
def _ensure_technician_membership():
    """Reactivate tom@acme's membership before this module runs.

    test_identity_assets.py's offboarding test suspends the
    technician's membership and runs LAST in its own file — but pytest
    runs files alphabetically, so in the full suite it runs BEFORE
    this module. Without this repair every acme_tech-dependent test
    here fails with "No active membership". The owner session bypasses
    RLS (RLS is enabled, not forced), so this is a plain UPDATE.
    """
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker

    from tests.conftest import TEST_OWNER_URL

    engine = create_engine(TEST_OWNER_URL)
    session = sessionmaker(bind=engine)()
    try:
        session.execute(
            text(
                "UPDATE memberships SET status = 'active' "
                "WHERE user_id = (SELECT id FROM users WHERE email = 'tom@acme.example.com')"
            )
        )
        session.commit()
    finally:
        session.close()


def _num(n: str) -> int:
    return int(n.split("-")[1])


# --- Requests ----------------------------------------------------------------


def test_request_lifecycle(client, acme_admin):
    created = client.post(
        "/api/v1/requests",
        json={"title": "New laptop", "description": "Need a laptop", "priority": "high"},
        headers=acme_admin["headers"],
    )
    assert created.status_code == 201, created.text
    req = created.json()
    assert re.fullmatch(r"REQ-\d{6}", req["number"])
    assert req["status"] == "submitted"
    assert req["requester_id"] is not None

    # Sequential per-org numbers.
    second = client.post(
        "/api/v1/requests",
        json={"title": "Second request"},
        headers=acme_admin["headers"],
    ).json()
    assert _num(second["number"]) == _num(req["number"]) + 1

    # Fulfill from submitted is an invalid transition.
    resp = client.post(f"/api/v1/requests/{req['id']}/fulfill", headers=acme_admin["headers"])
    assert resp.status_code == 400

    # Approve then fulfill.
    approved = client.post(f"/api/v1/requests/{req['id']}/approve", headers=acme_admin["headers"])
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "approved"
    assert approved.json()["approved_by_id"] is not None
    assert approved.json()["approved_at"] is not None
    # Approving twice is invalid.
    assert client.post(f"/api/v1/requests/{req['id']}/approve", headers=acme_admin["headers"]).status_code == 400

    fulfilled = client.post(f"/api/v1/requests/{req['id']}/fulfill", headers=acme_admin["headers"])
    assert fulfilled.status_code == 200, fulfilled.text
    assert fulfilled.json()["status"] == "fulfilled"
    assert fulfilled.json()["fulfilled_at"] is not None
    # Terminal: cancel is invalid now.
    assert client.post(f"/api/v1/requests/{req['id']}/cancel", headers=acme_admin["headers"]).status_code == 400


def test_request_patch_transitions_and_cancel(client, acme_admin):
    req = client.post("/api/v1/requests", json={"title": "Move me"}, headers=acme_admin["headers"]).json()
    patched = client.patch(
        f"/api/v1/requests/{req['id']}", json={"status": "in_progress"}, headers=acme_admin["headers"]
    )
    assert patched.status_code == 200
    assert patched.json()["status"] == "in_progress"
    # in_progress -> fulfilled is allowed via PATCH; submitted -> fulfilled is not.
    req2 = client.post("/api/v1/requests", json={"title": "No skip"}, headers=acme_admin["headers"]).json()
    resp = client.patch(f"/api/v1/requests/{req2['id']}", json={"status": "fulfilled"}, headers=acme_admin["headers"])
    assert resp.status_code == 400
    cancelled = client.post(f"/api/v1/requests/{req2['id']}/cancel", headers=acme_admin["headers"])
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "cancelled"


def test_request_invalid_priority_and_bad_catalog_item(client, acme_admin):
    resp = client.post("/api/v1/requests", json={"title": "x", "priority": "urgent"}, headers=acme_admin["headers"])
    assert resp.status_code == 400
    resp = client.post(
        "/api/v1/requests",
        json={"title": "x", "catalog_item_id": str(uuid.uuid4())},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 400


# --- Catalog -----------------------------------------------------------------


def test_catalog_crud_publish_retire(client, acme_admin):
    cat = client.post("/api/v1/catalog/categories", json={"name": "Hardware"}, headers=acme_admin["headers"]).json()
    assert cat["name"] == "Hardware"
    child = client.post(
        "/api/v1/catalog/categories",
        json={"name": "Laptops", "parent_id": cat["id"]},
        headers=acme_admin["headers"],
    ).json()
    assert child["parent_id"] == cat["id"]

    item = client.post(
        "/api/v1/catalog/items",
        json={"name": "MacBook Pro", "category_id": cat["id"], "approval_required": True},
        headers=acme_admin["headers"],
    )
    assert item.status_code == 201, item.text
    item = item.json()
    assert item["status"] == "draft"
    assert item["approval_required"] is True

    published = client.get("/api/v1/catalog/items/published", headers=acme_admin["headers"]).json()
    assert all(i["id"] != item["id"] for i in published)

    pub = client.post(f"/api/v1/catalog/items/{item['id']}/publish", headers=acme_admin["headers"])
    assert pub.status_code == 200
    assert pub.json()["status"] == "published"
    published = client.get("/api/v1/catalog/items/published", headers=acme_admin["headers"]).json()
    assert any(i["id"] == item["id"] for i in published)

    retired = client.post(f"/api/v1/catalog/items/{item['id']}/retire", headers=acme_admin["headers"])
    assert retired.status_code == 200
    assert retired.json()["status"] == "retired"
    published = client.get("/api/v1/catalog/items/published", headers=acme_admin["headers"]).json()
    assert all(i["id"] != item["id"] for i in published)
    # Retiring a non-published item is invalid.
    assert client.post(f"/api/v1/catalog/items/{item['id']}/retire", headers=acme_admin["headers"]).status_code == 400


def test_catalog_manage_requires_permission(client, acme_tech):
    # Service Desk Technician has catalog:read but not catalog:manage.
    resp = client.post("/api/v1/catalog/items", json={"name": "Nope"}, headers=acme_tech["headers"])
    assert resp.status_code == 403


# --- Knowledge ---------------------------------------------------------------


def test_knowledge_publish_and_draft_visibility(client, acme_admin, acme_tech):
    created = client.post(
        "/api/v1/knowledge/articles",
        json={"title": "VPN setup", "body": "Steps...", "tags": ["vpn"]},
        headers=acme_admin["headers"],
    )
    assert created.status_code == 201, created.text
    article = created.json()
    assert article["status"] == "draft"
    assert article["slug"] == "vpn-setup"

    # Drafts are visible to holders of knowledge:create (tech) and in
    # the admin's list; publish moves it to published.
    assert client.get(f"/api/v1/knowledge/articles/{article['id']}", headers=acme_tech["headers"]).status_code == 200
    listed = client.get("/api/v1/knowledge/articles", headers=acme_admin["headers"]).json()
    assert any(a["id"] == article["id"] for a in listed)

    # Duplicate slug in the same org is rejected.
    dup = client.post("/api/v1/knowledge/articles", json={"title": "VPN setup"}, headers=acme_admin["headers"])
    assert dup.status_code == 400

    published = client.post(f"/api/v1/knowledge/articles/{article['id']}/publish", headers=acme_admin["headers"])
    assert published.status_code == 200
    assert published.json()["status"] == "published"
    assert published.json()["published_at"] is not None

    # GET on a published article increments view_count.
    first = client.get(f"/api/v1/knowledge/articles/{article['id']}", headers=acme_admin["headers"]).json()
    second = client.get(f"/api/v1/knowledge/articles/{article['id']}", headers=acme_admin["headers"]).json()
    assert second["view_count"] == first["view_count"] + 1

    # Feedback is append-only and listed back.
    fb = client.post(
        f"/api/v1/knowledge/articles/{article['id']}/feedback",
        json={"helpful": True, "comment": "Worked for me"},
        headers=acme_tech["headers"],
    )
    assert fb.status_code == 201, fb.text
    feedback = client.get(f"/api/v1/knowledge/articles/{article['id']}/feedback", headers=acme_admin["headers"]).json()
    assert len(feedback) == 1 and feedback[0]["helpful"] is True


def test_knowledge_publish_requires_permission(client, acme_tech):
    article = client.post(
        "/api/v1/knowledge/articles", json={"title": "Draft only"}, headers=acme_tech["headers"]
    ).json()
    # Tech can create but not publish.
    resp = client.post(f"/api/v1/knowledge/articles/{article['id']}/publish", headers=acme_tech["headers"])
    assert resp.status_code == 403


def test_knowledge_draft_visibility_rule():
    # Unit-level: the visibility rule is "create or manage" only.
    from app.deps import Principal
    from app.routers.knowledge import _can_see_drafts

    read_only = Principal(
        user_id=uuid.uuid4(),
        email="r@example.com",
        organization_id=uuid.uuid4(),
        organization_slug="x",
        permissions={"knowledge:read"},
    )
    assert _can_see_drafts(read_only) is False
    creator = Principal(
        user_id=uuid.uuid4(),
        email="c@example.com",
        organization_id=uuid.uuid4(),
        organization_slug="x",
        permissions={"knowledge:read", "knowledge:create"},
    )
    assert _can_see_drafts(creator) is True


# --- Changes -------------------------------------------------------------------


def test_change_approval_flow(client, acme_admin, acme_tech):
    created = client.post(
        "/api/v1/changes",
        json={"title": "Upgrade firewall", "risk": "high", "type": "normal"},
        headers=acme_admin["headers"],
    )
    assert created.status_code == 201, created.text
    change = created.json()
    assert re.fullmatch(r"CHG-\d{6}", change["number"])
    assert change["status"] == "draft"

    # Tech has no changes:create at all.
    assert client.post("/api/v1/changes", json={"title": "x"}, headers=acme_tech["headers"]).status_code == 403

    # Execute from draft is invalid; submit first.
    assert client.post(f"/api/v1/changes/{change['id']}/execute", headers=acme_admin["headers"]).status_code == 400
    submitted = client.post(f"/api/v1/changes/{change['id']}/submit", headers=acme_admin["headers"])
    assert submitted.status_code == 200
    assert submitted.json()["status"] == "pending_approval"

    # One decision per approver: approve, then a second decision 400s
    # (status is no longer pending_approval).
    approved = client.post(
        f"/api/v1/changes/{change['id']}/approve", json={"comment": "LGTM"}, headers=acme_admin["headers"]
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "approved"
    approvals = client.get(f"/api/v1/changes/{change['id']}/approvals", headers=acme_admin["headers"]).json()
    assert len(approvals) == 1 and approvals[0]["status"] == "approved"
    assert (
        client.post(f"/api/v1/changes/{change['id']}/approve", json={}, headers=acme_admin["headers"]).status_code
        == 400
    )

    executed = client.post(f"/api/v1/changes/{change['id']}/execute", headers=acme_admin["headers"])
    assert executed.status_code == 200
    assert executed.json()["status"] == "implementing"
    rolled = client.post(f"/api/v1/changes/{change['id']}/rollback", headers=acme_admin["headers"])
    assert rolled.status_code == 200
    assert rolled.json()["status"] == "rolled_back"


def test_change_reject_returns_to_draft(client, acme_admin):
    change = client.post("/api/v1/changes", json={"title": "Risky change"}, headers=acme_admin["headers"]).json()
    client.post(f"/api/v1/changes/{change['id']}/submit", headers=acme_admin["headers"])
    rejected = client.post(
        f"/api/v1/changes/{change['id']}/reject", json={"comment": "Too risky"}, headers=acme_admin["headers"]
    )
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "draft"
    approvals = client.get(f"/api/v1/changes/{change['id']}/approvals", headers=acme_admin["headers"]).json()
    assert approvals[0]["status"] == "rejected"


def test_change_tasks_crud(client, acme_admin):
    change = client.post("/api/v1/changes", json={"title": "With tasks"}, headers=acme_admin["headers"]).json()
    task = client.post(
        f"/api/v1/changes/{change['id']}/tasks",
        json={"title": "Back up config", "sort_order": 1},
        headers=acme_admin["headers"],
    )
    assert task.status_code == 201, task.text
    task = task.json()
    assert task["status"] == "pending"
    updated = client.patch(
        f"/api/v1/changes/{change['id']}/tasks/{task['id']}",
        json={"status": "done"},
        headers=acme_admin["headers"],
    )
    assert updated.status_code == 200
    assert updated.json()["status"] == "done"
    tasks = client.get(f"/api/v1/changes/{change['id']}/tasks", headers=acme_admin["headers"]).json()
    assert len(tasks) == 1
    assert (
        client.delete(f"/api/v1/changes/{change['id']}/tasks/{task['id']}", headers=acme_admin["headers"]).status_code
        == 204
    )
    assert client.get(f"/api/v1/changes/{change['id']}/tasks", headers=acme_admin["headers"]).json() == []


# --- Problems / known errors ----------------------------------------------------


def test_problem_and_known_error_link(client, acme_admin):
    problem = client.post(
        "/api/v1/problems",
        json={"title": "VPN drops hourly", "priority": "high"},
        headers=acme_admin["headers"],
    )
    assert problem.status_code == 201, problem.text
    problem = problem.json()
    assert re.fullmatch(r"PRB-\d{6}", problem["number"])

    ke = client.post(
        "/api/v1/problems/known-errors",
        json={"code": "KE-001", "title": "VPN gateway bug", "workaround": "Reconnect"},
        headers=acme_admin["headers"],
    )
    assert ke.status_code == 201, ke.text
    ke = ke.json()
    assert ke["status"] == "active"
    dup = client.post(
        "/api/v1/problems/known-errors",
        json={"code": "KE-001", "title": "Duplicate"},
        headers=acme_admin["headers"],
    )
    assert dup.status_code == 400

    linked = client.post(
        f"/api/v1/problems/{problem['id']}/link-known-error",
        json={"known_error_id": ke["id"]},
        headers=acme_admin["headers"],
    )
    assert linked.status_code == 200, linked.text
    assert linked.json()["known_error_id"] == ke["id"]
    ke_after = client.get(f"/api/v1/problems/known-errors/{ke['id']}", headers=acme_admin["headers"]).json()
    assert ke_after["problem_id"] == problem["id"]

    updated = client.patch(
        f"/api/v1/problems/{problem['id']}",
        json={"status": "investigating", "root_cause": "MTU mismatch"},
        headers=acme_admin["headers"],
    )
    assert updated.status_code == 200
    assert updated.json()["status"] == "investigating"
    # closed -> open is not a valid move.
    client.patch(f"/api/v1/problems/{problem['id']}", json={"status": "closed"}, headers=acme_admin["headers"])
    resp = client.patch(f"/api/v1/problems/{problem['id']}", json={"status": "resolved"}, headers=acme_admin["headers"])
    assert resp.status_code == 400


# --- Notifications --------------------------------------------------------------


def test_notifications_own_only_and_mark_read(client, acme_admin, acme_tech, org_ids):
    from app.database import tenant_session
    from app.services.notification_service import create_notification

    me = client.get("/api/v1/auth/me", headers=acme_admin["headers"]).json()
    with tenant_session(uuid.UUID(org_ids["acme"])) as session:
        create_notification(
            session,
            organization_id=uuid.UUID(org_ids["acme"]),
            user_id=uuid.UUID(me["user_id"]),
            type="ticket.assigned",
            title="Ticket assigned",
            body="A ticket was assigned to you.",
            resource_type="ticket",
        )
        create_notification(
            session,
            organization_id=uuid.UUID(org_ids["acme"]),
            user_id=uuid.UUID(me["user_id"]),
            type="request.approved",
            title="Request approved",
            body="Your request was approved.",
        )

    mine = client.get("/api/v1/notifications", headers=acme_admin["headers"]).json()
    assert len(mine) >= 2
    assert all(n["user_id"] == me["user_id"] for n in mine)
    assert all(n["read_at"] is None for n in mine)
    # Another user in the same org sees none of Alice's notifications.
    assert client.get("/api/v1/notifications", headers=acme_tech["headers"]).json() == []

    first = mine[0]
    read = client.post(f"/api/v1/notifications/{first['id']}/read", headers=acme_admin["headers"])
    assert read.status_code == 200
    assert read.json()["read_at"] is not None
    # Tech cannot mark Alice's notification read (404, not 403).
    assert client.post(f"/api/v1/notifications/{first['id']}/read", headers=acme_tech["headers"]).status_code == 404

    remaining = client.post("/api/v1/notifications/read-all", headers=acme_admin["headers"])
    assert remaining.status_code == 200
    mine = client.get("/api/v1/notifications", headers=acme_admin["headers"]).json()
    assert all(n["read_at"] is not None for n in mine)


# --- Ticket comments / attachments / links ---------------------------------------


def _make_ticket(client, acme_admin):
    resp = client.post(
        "/api/v1/tickets",
        json={"title": "Printer down", "description": "3rd floor", "priority": "high", "category": "Hardware"},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_ticket_comments_internal_and_public(client, acme_admin):
    ticket = _make_ticket(client, acme_admin)
    internal = client.post(
        f"/api/v1/tickets/{ticket['id']}/comments",
        json={"body": "Internal note", "is_internal": True},
        headers=acme_admin["headers"],
    )
    assert internal.status_code == 201, internal.text
    public = client.post(
        f"/api/v1/tickets/{ticket['id']}/comments",
        json={"body": "Public reply", "is_internal": False},
        headers=acme_admin["headers"],
    )
    assert public.status_code == 201
    comments = client.get(f"/api/v1/tickets/{ticket['id']}/comments", headers=acme_admin["headers"]).json()
    assert len(comments) == 2
    assert {c["is_internal"] for c in comments} == {True, False}
    assert {c["body"] for c in comments} == {"Internal note", "Public reply"}


def test_ticket_attachment_503_when_storage_unconfigured(client, acme_admin):
    ticket = _make_ticket(client, acme_admin)
    resp = client.post(
        f"/api/v1/tickets/{ticket['id']}/attachments",
        json={"filename": "log.txt", "content_type": "text/plain", "content_base64": base64.b64encode(b"log").decode()},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 503
    assert "storage not configured" in resp.json()["detail"]
    assert client.get(f"/api/v1/tickets/{ticket['id']}/attachments", headers=acme_admin["headers"]).json() == []


def test_ticket_attachment_metadata_with_stubbed_storage(client, acme_admin, monkeypatch):
    class FakeClient:
        def __init__(self):
            self.puts = []

        def put_object(self, **kwargs):
            self.puts.append(kwargs)

    class FakeStorage:
        configured = True
        bucket = "test-bucket"

        def __init__(self):
            self._client = FakeClient()

    fake = FakeStorage()
    monkeypatch.setattr("app.routers.tickets.get_storage", lambda: fake)

    ticket = _make_ticket(client, acme_admin)
    payload = b"hello attachment"
    resp = client.post(
        f"/api/v1/tickets/{ticket['id']}/attachments",
        json={
            "filename": "note.txt",
            "content_type": "text/plain",
            "content_base64": base64.b64encode(payload).decode(),
        },
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 201, resp.text
    meta = resp.json()
    assert meta["filename"] == "note.txt"
    assert meta["size_bytes"] == len(payload)
    assert meta["storage_key"].startswith(f"tickets/{ticket['id']}/")
    assert len(fake._client.puts) == 1
    assert fake._client.puts[0]["Body"] == payload
    assert fake._client.puts[0]["Bucket"] == "test-bucket"
    listed = client.get(f"/api/v1/tickets/{ticket['id']}/attachments", headers=acme_admin["headers"]).json()
    assert len(listed) == 1


def test_ticket_links_validation(client, acme_admin):
    ticket = _make_ticket(client, acme_admin)
    req = client.post("/api/v1/requests", json={"title": "Linked request"}, headers=acme_admin["headers"]).json()
    link = client.post(
        f"/api/v1/tickets/{ticket['id']}/links",
        json={"target_type": "request", "target_id": req["id"], "link_type": "related"},
        headers=acme_admin["headers"],
    )
    assert link.status_code == 201, link.text
    assert link.json()["target_type"] == "request"
    # Unknown target id is rejected.
    bad = client.post(
        f"/api/v1/tickets/{ticket['id']}/links",
        json={"target_type": "ticket", "target_id": str(uuid.uuid4()), "link_type": "related"},
        headers=acme_admin["headers"],
    )
    assert bad.status_code == 400
    # Unknown target type / link type rejected.
    assert (
        client.post(
            f"/api/v1/tickets/{ticket['id']}/links",
            json={"target_type": "asset", "target_id": str(uuid.uuid4())},
            headers=acme_admin["headers"],
        ).status_code
        == 400
    )
    links = client.get(f"/api/v1/tickets/{ticket['id']}/links", headers=acme_admin["headers"]).json()
    assert len(links) == 1
    assert (
        client.delete(
            f"/api/v1/tickets/{ticket['id']}/links/{links[0]['id']}", headers=acme_admin["headers"]
        ).status_code
        == 204
    )
    assert client.get(f"/api/v1/tickets/{ticket['id']}/links", headers=acme_admin["headers"]).json() == []


# --- Templates / recurring ---------------------------------------------------------


def test_templates_and_recurring_crud(client, acme_admin):
    template = client.post(
        "/api/v1/tickets/templates",
        json={"name": "Weekly patch check", "description": "Check patch status", "priority": "medium"},
        headers=acme_admin["headers"],
    )
    assert template.status_code == 201, template.text
    template = template.json()
    assert template["is_active"] is True

    recurring = client.post(
        "/api/v1/tickets/recurring",
        json={"template_id": template["id"], "schedule": {"frequency": "daily", "time": "09:00"}},
        headers=acme_admin["headers"],
    )
    assert recurring.status_code == 201, recurring.text
    recurring = recurring.json()
    assert recurring["next_run_at"] is not None
    assert datetime.fromisoformat(recurring["next_run_at"]) > datetime.now(timezone.utc)

    bad = client.post(
        "/api/v1/tickets/recurring",
        json={"template_id": template["id"], "schedule": {"frequency": "hourly"}},
        headers=acme_admin["headers"],
    )
    assert bad.status_code == 400

    due = client.get("/api/v1/tickets/recurring/due", headers=acme_admin["headers"]).json()
    assert all(r["id"] != recurring["id"] for r in due)

    updated = client.patch(
        f"/api/v1/tickets/templates/{template['id']}", json={"priority": "high"}, headers=acme_admin["headers"]
    )
    assert updated.status_code == 200
    assert updated.json()["priority"] == "high"


def test_recurring_sweep_creates_ticket(client, acme_admin, org_ids):
    from app.database import tenant_session
    from app.models.itsm import RecurringTicket
    from app.tasks.recurring_tasks import create_due_recurring_tickets

    template = client.post(
        "/api/v1/tickets/templates",
        json={"name": "Daily backup check", "description": "Verify backups ran"},
        headers=acme_admin["headers"],
    ).json()
    before = len(client.get("/api/v1/tickets", headers=acme_admin["headers"]).json())
    # Plant a due recurring row directly (next_run_at in the past).
    with tenant_session(uuid.UUID(org_ids["acme"])) as session:
        row = RecurringTicket(
            organization_id=uuid.UUID(org_ids["acme"]),
            template_id=uuid.UUID(template["id"]),
            schedule={"frequency": "daily", "time": "09:00"},
            next_run_at=datetime.now(timezone.utc) - timedelta(hours=1),
            is_active=True,
        )
        session.add(row)
        session.flush()
        row_id = str(row.id)
    result = create_due_recurring_tickets(org_ids["acme"])
    assert result["created"] == 1
    assert len(result["numbers"]) == 1 and result["numbers"][0].startswith("INC-")
    after = client.get("/api/v1/tickets", headers=acme_admin["headers"]).json()
    assert len(after) == before + 1
    assert any(t["number"] == result["numbers"][0] and t["title"] == "Daily backup check" for t in after)
    # The sweep advanced next_run_at into the future.
    row_after = client.get(f"/api/v1/tickets/recurring/{row_id}", headers=acme_admin["headers"]).json()
    assert datetime.fromisoformat(row_after["next_run_at"]) > datetime.now(timezone.utc)
    assert row_after["last_run_at"] is not None


def test_compute_next_run():
    from app.services.itsm_service import compute_next_run

    base = datetime(2026, 11, 25, 10, 0, tzinfo=timezone.utc)  # Wednesday
    nxt = compute_next_run({"frequency": "daily", "time": "09:00"}, base)
    assert nxt == datetime(2026, 11, 26, 9, 0, tzinfo=timezone.utc)
    nxt = compute_next_run({"frequency": "daily", "time": "11:00"}, base)
    assert nxt == datetime(2026, 11, 25, 11, 0, tzinfo=timezone.utc)
    # Weekly: Monday=0; base is Wednesday, next Monday is Nov 30.
    nxt = compute_next_run({"frequency": "weekly", "time": "09:00", "weekday": 0}, base)
    assert nxt == datetime(2026, 11, 30, 9, 0, tzinfo=timezone.utc)
    # Monthly on the 31st clamps to Feb 28.
    jan31 = datetime(2026, 1, 31, 10, 0, tzinfo=timezone.utc)
    nxt = compute_next_run({"frequency": "monthly", "time": "09:00"}, jan31)
    assert nxt == datetime(2026, 2, 28, 9, 0, tzinfo=timezone.utc)
    assert compute_next_run({"frequency": "hourly"}, base) is None


# --- Major incidents / surveys -----------------------------------------------------


def test_major_incident_flow(client, acme_admin):
    ticket = _make_ticket(client, acme_admin)
    incident = client.post(
        "/api/v1/problems/incidents",
        json={"ticket_id": ticket["id"], "title": "Outage", "severity": "critical"},
        headers=acme_admin["headers"],
    )
    assert incident.status_code == 201, incident.text
    incident = incident.json()
    assert incident["status"] == "declared"
    assert incident["started_at"] is not None
    bad = client.post(
        "/api/v1/problems/incidents",
        json={"ticket_id": str(uuid.uuid4()), "title": "Nope"},
        headers=acme_admin["headers"],
    )
    assert bad.status_code == 400
    updated = client.patch(
        f"/api/v1/problems/incidents/{incident['id']}",
        json={"status": "resolved"},
        headers=acme_admin["headers"],
    )
    assert updated.status_code == 200
    assert updated.json()["status"] == "resolved"
    assert updated.json()["resolved_at"] is not None


def test_survey_flow(client, acme_admin, acme_tech):
    ticket = _make_ticket(client, acme_admin)
    survey = client.post(
        "/api/v1/tickets/surveys",
        json={"name": "CSAT", "target_type": "ticket", "questions": [{"q": "How was it?", "type": "rating"}]},
        headers=acme_admin["headers"],
    )
    assert survey.status_code == 201, survey.text
    survey = survey.json()
    # Any org member (tech, surveys:read) may submit a response.
    resp = client.post(
        f"/api/v1/tickets/surveys/{survey['id']}/responses",
        json={"target_type": "ticket", "target_id": ticket["id"], "answers": {"q1": 5, "q2": 4}},
        headers=acme_tech["headers"],
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["score"] == 4 or body["score"] == 5  # average of 5 and 4, rounded
    assert body["submitted_at"] is not None
    responses = client.get(f"/api/v1/tickets/surveys/{survey['id']}/responses", headers=acme_admin["headers"]).json()
    assert len(responses) == 1
    # Unknown target is rejected.
    bad = client.post(
        f"/api/v1/tickets/surveys/{survey['id']}/responses",
        json={"target_type": "ticket", "target_id": str(uuid.uuid4()), "answers": {}},
        headers=acme_tech["headers"],
    )
    assert bad.status_code == 400


# --- Tenant isolation --------------------------------------------------------------


def test_cross_org_404_on_every_resource(client, acme_admin, globex_admin):
    ticket = _make_ticket(client, acme_admin)
    req = client.post("/api/v1/requests", json={"title": "iso req"}, headers=acme_admin["headers"]).json()
    cat = client.post("/api/v1/catalog/categories", json={"name": "iso cat"}, headers=acme_admin["headers"]).json()
    item = client.post("/api/v1/catalog/items", json={"name": "iso item"}, headers=acme_admin["headers"]).json()
    article = client.post("/api/v1/knowledge/articles", json={"title": "iso kb"}, headers=acme_admin["headers"]).json()
    change = client.post("/api/v1/changes", json={"title": "iso chg"}, headers=acme_admin["headers"]).json()
    problem = client.post("/api/v1/problems", json={"title": "iso prb"}, headers=acme_admin["headers"]).json()
    ke = client.post(
        "/api/v1/problems/known-errors", json={"code": "KE-ISO", "title": "iso ke"}, headers=acme_admin["headers"]
    ).json()
    template = client.post("/api/v1/tickets/templates", json={"name": "iso tpl"}, headers=acme_admin["headers"]).json()
    recurring = client.post(
        "/api/v1/tickets/recurring",
        json={"template_id": template["id"], "schedule": {"frequency": "daily", "time": "09:00"}},
        headers=acme_admin["headers"],
    ).json()
    incident = client.post(
        "/api/v1/problems/incidents",
        json={"ticket_id": ticket["id"], "title": "iso inc"},
        headers=acme_admin["headers"],
    ).json()
    survey = client.post("/api/v1/tickets/surveys", json={"name": "iso survey"}, headers=acme_admin["headers"]).json()
    client.post(
        f"/api/v1/tickets/{ticket['id']}/comments",
        json={"body": "iso comment"},
        headers=acme_admin["headers"],
    )

    paths = [
        f"/api/v1/requests/{req['id']}",
        f"/api/v1/catalog/categories/{cat['id']}",
        f"/api/v1/catalog/items/{item['id']}",
        f"/api/v1/knowledge/articles/{article['id']}",
        f"/api/v1/changes/{change['id']}",
        f"/api/v1/problems/{problem['id']}",
        f"/api/v1/problems/known-errors/{ke['id']}",
        f"/api/v1/tickets/templates/{template['id']}",
        f"/api/v1/tickets/recurring/{recurring['id']}",
        f"/api/v1/problems/incidents/{incident['id']}",
        f"/api/v1/tickets/surveys/{survey['id']}",
        f"/api/v1/tickets/{ticket['id']}/comments",
        f"/api/v1/tickets/{ticket['id']}/attachments",
        f"/api/v1/tickets/{ticket['id']}/links",
    ]
    for path in paths:
        resp = client.get(path, headers=globex_admin["headers"])
        assert resp.status_code == 404, f"{path} -> {resp.status_code}"
    # Cross-org mutation is 404 too.
    assert (
        client.patch(f"/api/v1/requests/{req['id']}", json={"title": "x"}, headers=globex_admin["headers"]).status_code
        == 404
    )
    assert client.post(f"/api/v1/requests/{req['id']}/approve", headers=globex_admin["headers"]).status_code == 404


def test_rls_blocks_cross_org_insert_on_requests(app_db, org_ids):
    """Raw SQL as null_app, scoped to Acme, cannot insert a Globex request."""
    import psycopg

    with app_db.cursor() as cur:
        set_rls(app_db, org_ids["acme"])
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            cur.execute(
                "INSERT INTO requests (id, organization_id, number, title, status, priority) "
                "VALUES (gen_random_uuid(), %s, 'REQ-999999', 'forged', 'submitted', 'low')",
                (org_ids["globex"],),
            )
        # And a Globex request is invisible from the Acme context.
        cur.execute("SELECT count(*) FROM requests WHERE organization_id = %s", (org_ids["globex"],))
        assert cur.fetchone()[0] == 0


def test_rls_scoping_on_new_tables(app_db, org_ids):
    """Acme-scoped raw session sees only Acme rows in the new tables."""
    with app_db.cursor() as cur:
        set_rls(app_db, org_ids["acme"])
        cur.execute("SELECT organization_id FROM changes")
        assert all(str(r[0]) == org_ids["acme"] for r in cur.fetchall())
        cur.execute("SELECT organization_id FROM knowledge_articles")
        assert all(str(r[0]) == org_ids["acme"] for r in cur.fetchall())
        set_rls(app_db, None)
        cur.execute("SELECT count(*) FROM requests")
        assert cur.fetchone()[0] == 0


# --- Audit ---------------------------------------------------------------------------


def test_audit_rows_written(client, acme_admin, app_db, org_ids):
    req = client.post("/api/v1/requests", json={"title": "audited req"}, headers=acme_admin["headers"]).json()
    client.post(f"/api/v1/requests/{req['id']}/approve", headers=acme_admin["headers"])
    change = client.post("/api/v1/changes", json={"title": "audited chg"}, headers=acme_admin["headers"]).json()
    with app_db.cursor() as cur:
        set_rls(app_db, org_ids["acme"])
        cur.execute(
            "SELECT action FROM audit_logs WHERE resource_id = %s ORDER BY created_at",
            (req["id"],),
        )
        actions = [r[0] for r in cur.fetchall()]
        assert "request.created" in actions
        assert "request.approved" in actions
        cur.execute("SELECT action FROM audit_logs WHERE resource_id = %s", (change["id"],))
        assert [r[0] for r in cur.fetchall()] == ["change.created"]
