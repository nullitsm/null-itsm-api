"""SLA engine tests — Phase 2 (migration 0005).

Pure business-hours math is tested without a database; API/service tests
run against the shared test DB via ``scripts/run_tests_locked.sh``.

Cross-test isolation: each test uses its own ticket ``category`` and its
own policy scoped to that category (``applies_to``), so the breach sweep
never mistakes another test's tickets for its own.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest

from app.database import tenant_session
from app.services import sla_service
from app.services.sla_service import add_business_minutes

DETROIT = ZoneInfo("America/Detroit")
WEEKDAY_9_5 = {
    "mon": [["09:00", "17:00"]],
    "tue": [["09:00", "17:00"]],
    "wed": [["09:00", "17:00"]],
    "thu": [["09:00", "17:00"]],
    "fri": [["09:00", "17:00"]],
    "sat": [],
    "sun": [],
}


def _bh(**overrides):
    base = {"timezone": "America/Detroit", "schedule": WEEKDAY_9_5, "holidays": []}
    base.update(overrides)
    return base


# --- Pure business-hours math ----------------------------------------------


def test_add_business_minutes_weekend_skip():
    start = datetime(2026, 11, 27, 16, 0, tzinfo=DETROIT)  # Friday 16:00
    due = add_business_minutes(start, 120, _bh())
    assert due == datetime(2026, 11, 30, 10, 0, tzinfo=DETROIT)  # Monday 10:00


def test_add_business_minutes_holiday_skip():
    start = datetime(2026, 11, 27, 16, 0, tzinfo=DETROIT)
    due = add_business_minutes(start, 120, _bh(holidays=["2026-11-30"]))
    assert due == datetime(2026, 12, 1, 10, 0, tzinfo=DETROIT)  # Tuesday 10:00


def test_add_business_minutes_after_hours_roll_forward():
    start = datetime(2026, 11, 25, 18, 0, tzinfo=DETROIT)  # Wednesday 18:00
    due = add_business_minutes(start, 60, _bh())
    assert due == datetime(2026, 11, 26, 10, 0, tzinfo=DETROIT)  # Thursday 10:00


def test_add_business_minutes_before_hours_roll_forward():
    start = datetime(2026, 11, 25, 7, 0, tzinfo=DETROIT)
    due = add_business_minutes(start, 30, _bh())
    assert due == datetime(2026, 11, 25, 9, 30, tzinfo=DETROIT)


def test_add_business_minutes_timezone_handling():
    # 14:00 UTC == 09:00 EST in Detroit; +60 business minutes == 15:00 UTC.
    start = datetime(2026, 11, 25, 14, 0, tzinfo=timezone.utc)
    due = add_business_minutes(start, 60, _bh())
    assert due == datetime(2026, 11, 25, 15, 0, tzinfo=timezone.utc)


def test_add_business_minutes_split_windows():
    schedule = {"wed": [["09:00", "12:00"], ["13:00", "17:00"]]}
    start = datetime(2026, 11, 25, 11, 30, tzinfo=DETROIT)
    due = add_business_minutes(start, 60, _bh(schedule=schedule))
    assert due == datetime(2026, 11, 25, 13, 30, tzinfo=DETROIT)


def test_add_business_minutes_zero_returns_start():
    start = datetime(2026, 11, 25, 10, 0, tzinfo=DETROIT)
    assert add_business_minutes(start, 0, _bh()) == start


def test_add_business_minutes_naive_start_treated_as_utc():
    start = datetime(2026, 11, 25, 14, 0)  # naive -> UTC == 09:00 EST
    due = add_business_minutes(start, 60, _bh())
    assert due == datetime(2026, 11, 25, 15, 0, tzinfo=timezone.utc)


def test_add_business_minutes_empty_schedule_raises():
    with pytest.raises(ValueError):
        add_business_minutes(datetime(2026, 11, 25, 10, 0, tzinfo=DETROIT), 60, _bh(schedule={}))


def test_add_business_minutes_unknown_timezone_raises():
    with pytest.raises(ValueError):
        add_business_minutes(datetime(2026, 11, 25, 10, 0, tzinfo=DETROIT), 60, _bh(timezone="Mars/Olympus"))


# --- API helpers ------------------------------------------------------------


def _create_ticket(client, headers, category, priority="medium"):
    resp = client.post(
        "/api/v1/tickets",
        json={"title": f"SLA test {category}", "description": "sla test", "priority": priority, "category": category},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _create_bh(client, headers, name="9-5 Detroit"):
    resp = client.post(
        "/api/v1/sla/business-hours",
        json={"name": name, "timezone": "America/Detroit", "schedule": WEEKDAY_9_5, "holidays": []},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _create_policy(client, headers, category, *, response=60, resolution=480, bh_id=None, is_default=False):
    resp = client.post(
        "/api/v1/sla/policies",
        json={
            "name": f"Policy {category}",
            "description": "",
            "applies_to": {"categories": [category], "priorities": []},
            "response_minutes": {"critical": 30, "high": 60, "medium": response, "low": 480},
            "resolution_minutes": {"critical": 240, "high": 480, "medium": resolution, "low": 960},
            "business_hours_id": bh_id,
            "is_default": is_default,
            "is_active": True,
        },
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _me(client, headers):
    resp = client.get("/api/v1/auth/me", headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()


# --- API tests --------------------------------------------------------------


def test_business_hours_crud_and_set_default(client, acme_admin, acme_tech):
    admin = acme_admin["headers"]
    bh1 = _create_bh(client, admin, "Hours A")
    bh2 = _create_bh(client, admin, "Hours B")
    # Invalid timezone -> 422.
    bad = client.post(
        "/api/v1/sla/business-hours",
        json={"name": "Bad", "timezone": "Nowhere/Special", "schedule": {}, "holidays": []},
        headers=admin,
    )
    assert bad.status_code == 422
    # Technician (sla:read only) cannot create -> 403.
    denied = client.post(
        "/api/v1/sla/business-hours",
        json={"name": "Nope", "timezone": "UTC", "schedule": {}, "holidays": []},
        headers=acme_tech["headers"],
    )
    assert denied.status_code == 403
    # Set-default flips the flag.
    resp = client.post(f"/api/v1/sla/business-hours/{bh2['id']}/set-default", headers=admin)
    assert resp.status_code == 200, resp.text
    assert resp.json()["is_default"] is True
    rows = client.get("/api/v1/sla/business-hours", headers=admin).json()
    by_id = {r["id"]: r for r in rows}
    assert by_id[bh2["id"]]["is_default"] is True
    assert by_id[bh1["id"]]["is_default"] is False
    # Cross-org read -> 404 is covered in test_tenant_isolation; delete works.
    resp = client.delete(f"/api/v1/sla/business-hours/{bh1['id']}", headers=admin)
    assert resp.status_code == 204


def test_due_dates_business_vs_calendar(client, acme_admin, globex_admin):
    admin = acme_admin["headers"]
    bh = _create_bh(client, admin, "Due-date hours")
    _create_policy(client, admin, "BH-Cat", response=60, resolution=480, bh_id=bh["id"])
    ticket = _create_ticket(client, admin, "BH-Cat")
    resp = client.post(f"/api/v1/sla/tickets/{ticket['id']}/recompute", headers=admin)
    assert resp.status_code == 200, resp.text
    state = resp.json()
    created = datetime.fromisoformat(ticket["created_at"])
    expected_first = add_business_minutes(created, 60, _bh())
    expected_res = add_business_minutes(created, 480, _bh())
    assert datetime.fromisoformat(state["first_response_due_at"]) == expected_first
    assert datetime.fromisoformat(state["resolution_due_at"]) == expected_res
    # GET returns the same state (same instant; serialization tz may differ).
    got = client.get(f"/api/v1/sla/tickets/{ticket['id']}", headers=admin)
    assert got.status_code == 200
    assert datetime.fromisoformat(got.json()["first_response_due_at"]) == datetime.fromisoformat(
        state["first_response_due_at"]
    )

    # Calendar minutes (no business hours) in the other org.
    gadmin = globex_admin["headers"]
    _create_policy(client, gadmin, "Cal-Cat", response=60, resolution=480)
    gticket = _create_ticket(client, gadmin, "Cal-Cat")
    resp = client.post(f"/api/v1/sla/tickets/{gticket['id']}/recompute", headers=gadmin)
    assert resp.status_code == 200, resp.text
    gstate = resp.json()
    gcreated = datetime.fromisoformat(gticket["created_at"])
    assert datetime.fromisoformat(gstate["first_response_due_at"]) == gcreated + timedelta(minutes=60)
    assert datetime.fromisoformat(gstate["resolution_due_at"]) == gcreated + timedelta(minutes=480)


def test_first_response_derived_from_comment(client, acme_admin, acme_tech, org_ids):
    from app.models.itsm import TicketComment

    admin = acme_admin["headers"]
    _create_policy(client, admin, "FR-Cat", response=60, resolution=480)
    ticket = _create_ticket(client, admin, "FR-Cat")
    tech_id = _me(client, acme_tech["headers"])["user_id"]
    with tenant_session(uuid.UUID(org_ids["acme"])) as session:
        session.add(
            TicketComment(
                organization_id=uuid.UUID(org_ids["acme"]),
                ticket_id=uuid.UUID(ticket["id"]),
                author_id=uuid.UUID(tech_id),
                body="Looking into this.",
                is_internal=False,
            )
        )
    resp = client.post(f"/api/v1/sla/tickets/{ticket['id']}/recompute", headers=admin)
    assert resp.status_code == 200, resp.text
    assert resp.json()["first_response_at"] is not None


def test_breach_detection_idempotent(client, acme_admin, org_ids, app_db):
    admin = acme_admin["headers"]
    _create_policy(client, admin, "Breach-Cat", response=0, resolution=0)
    ticket = _create_ticket(client, admin, "Breach-Cat")
    org_id = uuid.UUID(org_ids["acme"])
    with tenant_session(org_id) as session:
        first = sla_service.scan_breaches(session, org_id)
        second = sla_service.scan_breaches(session, org_id)
    assert first["breaches_created"] == 2  # first_response + resolution
    assert first["tickets_scanned"] >= 1
    assert second["breaches_created"] == 0
    # Exactly one breach row per type for this ticket.
    from tests.conftest import set_rls

    set_rls(app_db, org_ids["acme"])
    with app_db.cursor() as cur:
        cur.execute("SELECT breach_type FROM sla_breaches WHERE ticket_id = %s", (ticket["id"],))
        types = sorted(r[0] for r in cur.fetchall())
        cur.execute(
            "SELECT COUNT(*) FROM audit_logs WHERE action = 'sla.breach_detected' AND resource_id = %s", (ticket["id"],)
        )
        audit_count = cur.fetchone()[0]
    assert types == ["first_response", "resolution"]
    assert audit_count == 2
    # Ticket is flagged breached.
    state = client.get(f"/api/v1/sla/tickets/{ticket['id']}", headers=admin).json()
    assert state["sla_breached"] is True
    # Breach list + acknowledge.
    breaches = client.get("/api/v1/sla/breaches", params={"ticket_id": ticket["id"]}, headers=admin).json()
    assert len(breaches) == 2
    ack = client.post(f"/api/v1/sla/breaches/{breaches[0]['id']}/acknowledge", headers=admin)
    assert ack.status_code == 200, ack.text
    assert ack.json()["status"] == "acknowledged"
    assert ack.json()["acknowledged_by_id"] is not None


def test_escalation_actions(client, acme_admin, acme_tech, org_ids):
    admin = acme_admin["headers"]
    tech_id = _me(client, acme_tech["headers"])["user_id"]
    _create_policy(client, admin, "Esc-Cat", response=0, resolution=0)
    ticket = _create_ticket(client, admin, "Esc-Cat", priority="medium")
    resp = client.post(
        "/api/v1/sla/escalation-rules",
        json={
            "name": "Esc rule",
            "trigger": {"event": "sla_breach", "after_minutes": 0},
            "conditions": {"priority": ["medium", "high"]},
            "actions": [
                {"type": "priority_bump"},
                {"type": "reassign", "to_user_id": tech_id},
                {"type": "notify", "to_user_id": tech_id, "message": "Escalated to tech"},
            ],
            "is_active": True,
            "sort_order": 0,
        },
        headers=admin,
    )
    assert resp.status_code == 201, resp.text
    rule = resp.json()
    org_id = uuid.UUID(org_ids["acme"])
    with tenant_session(org_id) as session:
        sla_service.scan_breaches(session, org_id)
        result = sla_service.evaluate_escalations(session, org_id)
    assert result["events_created"] >= 1
    assert result["actions_failed"] == 0
    # Second evaluation is one-shot: no repeat event for the same rule+ticket.
    with tenant_session(org_id) as session:
        again = sla_service.evaluate_escalations(session, org_id)
    assert again["events_created"] == 0
    # Ticket was bumped medium -> high and reassigned to the tech.
    got = client.get(f"/api/v1/tickets/{ticket['id']}", headers=admin).json()
    assert got["priority"] == "high"
    assert got["assignee_id"] == tech_id
    events = client.get(f"/api/v1/sla/escalation-rules/{rule['id']}/events", headers=admin).json()
    # The rule may also have fired on other breached medium-priority
    # tickets from earlier tests; scope assertions to this ticket.
    mine = [e for e in events if e["ticket_id"] == ticket["id"]]
    assert len(mine) == 1
    assert mine[0]["status"] == "executed"
    taken = mine[0]["action_taken"]["actions"]
    assert {a["type"] for a in taken} == {"priority_bump", "reassign", "notify"}


def test_tenant_isolation(client, acme_admin, globex_admin):
    admin = acme_admin["headers"]
    policy = _create_policy(client, admin, "Iso-Cat", response=60, resolution=480)
    ticket = _create_ticket(client, admin, "Iso-Cat")
    gadmin = globex_admin["headers"]
    assert client.get(f"/api/v1/sla/policies/{policy['id']}", headers=gadmin).status_code == 404
    assert client.get(f"/api/v1/sla/tickets/{ticket['id']}", headers=gadmin).status_code == 404
    assert client.post(f"/api/v1/sla/tickets/{ticket['id']}/recompute", headers=gadmin).status_code == 404
    names = [p["name"] for p in client.get("/api/v1/sla/policies", headers=gadmin).json()]
    assert policy["name"] not in names


def test_rls_raw_sql(app_db, org_ids, client, acme_admin):
    from tests.conftest import set_rls

    _create_policy(client, acme_admin["headers"], "RLS-Cat", response=60, resolution=480)
    # Globex context cannot see Acme policies.
    set_rls(app_db, org_ids["globex"])
    with app_db.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM sla_policies")
        globex_count = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM sla_policies WHERE organization_id = %s", (org_ids["acme"],))
        assert cur.fetchone()[0] == 0
    # Acme context sees its own.
    set_rls(app_db, org_ids["acme"])
    with app_db.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM sla_policies")
        acme_count = cur.fetchone()[0]
    assert acme_count >= 1
    assert globex_count >= 0  # globex may legitimately have its own policies
    # No context sees nothing.
    set_rls(app_db, None)
    with app_db.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM sla_policies")
        assert cur.fetchone()[0] == 0


def test_audit_rows_written(client, acme_admin, org_ids, app_db):
    from tests.conftest import set_rls

    admin = acme_admin["headers"]
    policy = _create_policy(client, admin, "Audit-Cat", response=60, resolution=480)
    set_rls(app_db, org_ids["acme"])
    with app_db.cursor() as cur:
        cur.execute(
            "SELECT COUNT(*) FROM audit_logs WHERE action = 'sla.policy_created' AND resource_id = %s",
            (policy["id"],),
        )
        assert cur.fetchone()[0] == 1
        cur.execute("SELECT COUNT(*) FROM audit_logs WHERE action LIKE 'sla.%'")
        assert cur.fetchone()[0] >= 1
