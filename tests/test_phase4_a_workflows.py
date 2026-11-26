"""Phase 4 workstream A — workflow designer + automation rules (0014).

NOTE ON ROUTER REGISTRATION: the workflows router is not yet wired
into ``app/main.py`` (the coordinator registers routers at
integration). Until then this module mounts it onto the shared test
app itself, guarded so it is a no-op once ``main.py`` registers it.
Remove this block when the coordinator wires the router.
"""

from __future__ import annotations

import json
import uuid

from app.main import app
from app.routers.workflows import router as workflows_router

if not any(getattr(r, "path", "").startswith("/api/v1/workflows") for r in app.routes):
    app.include_router(workflows_router)

from tests.conftest import set_rls  # noqa: E402

BASE = "/api/v1/workflows"


def _ticket(client, headers, priority: str = "medium", title: str = "Printer jam") -> dict:
    resp = client.post(
        "/api/v1/tickets",
        json={"title": title, "description": "test ticket", "priority": priority, "category": "General"},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _user_id(client, headers) -> str:
    resp = client.get("/api/v1/auth/me", headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()["user_id"]


def _workflow(client, headers, steps: list[dict] | None = None, **overrides) -> dict:
    body = {
        "name": overrides.pop("name", "Triage workflow"),
        "description": "test workflow",
        "entity_type": "ticket",
        "trigger": "manual",
        "steps": steps if steps is not None else [{"type": "set_priority", "priority": "high"}],
    }
    body.update(overrides)
    resp = client.post(BASE, json=body, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _publish(client, headers, workflow_id: str) -> dict:
    resp = client.post(f"{BASE}/{workflow_id}/publish", headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()


def _rule(client, headers, **overrides) -> dict:
    body = {
        "name": overrides.pop("name", "Critical triage"),
        "description": "test rule",
        "trigger": "ticket.created",
        "entity_type": "ticket",
        "conditions": [{"field": "priority", "operator": "eq", "value": "critical"}],
        "actions": [{"type": "set_status", "status": "in_progress"}],
    }
    body.update(overrides)
    resp = client.post(f"{BASE}/automation-rules", json=body, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


# --- Workflow CRUD + versioning ------------------------------------------------


def test_create_workflow_is_draft_with_version_1(client, acme_admin):
    wf = _workflow(client, acme_admin["headers"])
    assert wf["status"] == "draft"
    assert wf["current_version_id"] is not None
    resp = client.get(f"{BASE}/{wf['id']}/versions", headers=acme_admin["headers"])
    assert resp.status_code == 200, resp.text
    versions = resp.json()
    assert len(versions) == 1
    assert versions[0]["version_number"] == 1
    assert versions[0]["steps"] == [{"type": "set_priority", "priority": "high", "name": "set_priority"}]


def test_create_workflow_rejects_bad_step_and_bad_trigger(client, acme_admin):
    resp = client.post(
        BASE,
        json={"name": "Bad", "entity_type": "ticket", "trigger": "manual", "steps": [{"type": "teleport"}]},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 400
    resp = client.post(
        BASE,
        json={"name": "Bad", "entity_type": "ticket", "trigger": "on_a_whim", "steps": []},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 400
    resp = client.post(
        BASE,
        json={
            "name": "Bad",
            "entity_type": "ticket",
            "trigger": "manual",
            "steps": [{"type": "add_comment", "body": "x"}],
        },
        headers=acme_admin["headers"],
    )
    # add_comment is valid for tickets, so this one must succeed.
    assert resp.status_code == 201, resp.text
    resp = client.post(
        BASE,
        json={
            "name": "Bad",
            "entity_type": "change",
            "trigger": "manual",
            "steps": [{"type": "add_comment", "body": "x"}],
        },
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 400  # add_comment is ticket-only


def test_update_steps_snapshots_new_version(client, acme_admin):
    wf = _workflow(client, acme_admin["headers"])
    resp = client.patch(
        f"{BASE}/{wf['id']}",
        json={"steps": [{"type": "set_priority", "priority": "low"}, {"type": "set_status", "status": "pending"}]},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 200, resp.text
    updated = resp.json()
    assert updated["current_version_id"] != wf["current_version_id"]
    resp = client.get(f"{BASE}/{wf['id']}/versions", headers=acme_admin["headers"])
    versions = resp.json()
    assert [v["version_number"] for v in versions] == [1, 2]
    assert len(versions[0]["steps"]) == 1  # v1 is immutable
    assert len(versions[1]["steps"]) == 2


def test_publish_empty_workflow_rejected(client, acme_admin):
    wf = _workflow(client, acme_admin["headers"], steps=[])
    resp = client.post(f"{BASE}/{wf['id']}/publish", headers=acme_admin["headers"])
    assert resp.status_code == 400


def test_workflow_delete_and_audit(client, acme_admin, app_db, org_ids):
    wf = _workflow(client, acme_admin["headers"], name="Delete me")
    resp = client.delete(f"{BASE}/{wf['id']}", headers=acme_admin["headers"])
    assert resp.status_code == 204
    resp = client.get(f"{BASE}/{wf['id']}", headers=acme_admin["headers"])
    assert resp.status_code == 404
    # The create was audited.
    set_rls(app_db, org_ids["acme"])
    with app_db.cursor() as cur:
        cur.execute(
            "SELECT COUNT(*) FROM audit_logs WHERE action = 'workflow.created' AND resource_id = %s",
            (wf["id"],),
        )
        assert cur.fetchone()[0] == 1


# --- Workflow execution ----------------------------------------------------------


def test_publish_and_run_happy_path_applies_real_effects(client, acme_admin, acme_tech):
    tech_id = _user_id(client, acme_tech["headers"])
    ticket = _ticket(client, acme_admin["headers"], priority="medium")
    wf = _workflow(
        client,
        acme_admin["headers"],
        steps=[
            {"type": "assign", "assignee_id": tech_id, "name": "assign to tech"},
            {"type": "set_priority", "priority": "high"},
            {"type": "add_comment", "body": "Auto-triaged by workflow"},
            {"type": "notify", "user_id": tech_id, "title": "Ticket assigned", "body": "See ticket"},
        ],
    )
    _publish(client, acme_admin["headers"], wf["id"])
    resp = client.post(
        f"{BASE}/{wf['id']}/run",
        json={"entity_type": "ticket", "entity_id": ticket["id"]},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 201, resp.text
    run = resp.json()
    assert run["status"] == "succeeded"
    assert run["version_number"] == 1
    assert run["finished_at"] is not None
    assert [s["status"] for s in run["steps"]] == ["succeeded"] * 4
    assert run["steps"][0]["name"] == "assign to tech"
    assert run["steps"][0]["output"]["value"] == tech_id

    # The effects are real: ticket fields changed, comment + notification exist.
    got = client.get(f"/api/v1/tickets/{ticket['id']}", headers=acme_admin["headers"]).json()
    assert got["assignee_id"] == tech_id
    assert got["priority"] == "high"
    comments = client.get(f"/api/v1/tickets/{ticket['id']}/comments", headers=acme_admin["headers"]).json()
    assert any(c["body"] == "Auto-triaged by workflow" for c in comments)
    notes = client.get("/api/v1/notifications", headers=acme_tech["headers"]).json()
    assert any(n["title"] == "Ticket assigned" for n in notes)


def test_run_draft_workflow_rejected(client, acme_admin):
    ticket = _ticket(client, acme_admin["headers"])
    wf = _workflow(client, acme_admin["headers"])
    resp = client.post(
        f"{BASE}/{wf['id']}/run",
        json={"entity_type": "ticket", "entity_id": ticket["id"]},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 400


def test_run_missing_entity_404_and_wrong_entity_type_400(client, acme_admin):
    wf = _workflow(client, acme_admin["headers"])
    _publish(client, acme_admin["headers"], wf["id"])
    resp = client.post(
        f"{BASE}/{wf['id']}/run",
        json={"entity_type": "ticket", "entity_id": str(uuid.uuid4())},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 404
    ticket = _ticket(client, acme_admin["headers"])
    resp = client.post(
        f"{BASE}/{wf['id']}/run",
        json={"entity_type": "request", "entity_id": ticket["id"]},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 400


def _failing_run(client, acme_admin, acme_tech) -> str:
    """Build a run that fails at its assign step; returns the run id.

    Shared setup for the failure/retry tests (a test function must not
    return a value, so this lives outside the tests).
    """
    ticket = _ticket(client, acme_admin["headers"], priority="low")
    stranger = str(uuid.uuid4())  # valid UUID, not a member of the org
    wf = _workflow(
        client,
        acme_admin["headers"],
        steps=[
            {"type": "set_priority", "priority": "high"},
            {"type": "assign", "assignee_id": stranger},
            {"type": "add_comment", "body": "never runs"},
        ],
    )
    _publish(client, acme_admin["headers"], wf["id"])
    resp = client.post(
        f"{BASE}/{wf['id']}/run",
        json={"entity_type": "ticket", "entity_id": ticket["id"]},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 201, resp.text
    run = resp.json()
    assert run["status"] == "failed"
    assert run["error"]
    assert [s["status"] for s in run["steps"]] == ["succeeded", "failed", "pending"]
    assert "not an active member" in run["steps"][1]["error"]

    # Step 0's real effect happened; step 2 never ran — nothing faked.
    got = client.get(f"/api/v1/tickets/{ticket['id']}", headers=acme_admin["headers"]).json()
    assert got["priority"] == "high"
    assert got["assignee_id"] is None
    comments = client.get(f"/api/v1/tickets/{ticket['id']}/comments", headers=acme_admin["headers"]).json()
    assert not any(c["body"] == "never runs" for c in comments)
    # The run is listed with its steps.
    listed = client.get(f"{BASE}/{wf['id']}/runs", headers=acme_admin["headers"]).json()
    assert len(listed) == 1 and listed[0]["id"] == run["id"]
    fetched = client.get(f"{BASE}/runs/{run['id']}", headers=acme_admin["headers"]).json()
    assert fetched["status"] == "failed" and len(fetched["steps"]) == 3
    return run["id"]


def test_failing_step_stops_run_and_records_honest_history(client, acme_admin, acme_tech):
    _failing_run(client, acme_admin, acme_tech)


def test_retry_failed_run_skips_succeeded_steps(client, acme_admin, acme_tech):
    run_id = _failing_run(client, acme_admin, acme_tech)
    resp = client.post(f"{BASE}/runs/{run_id}/retry", headers=acme_admin["headers"])
    assert resp.status_code == 200, resp.text
    run = resp.json()
    # The cause persists, so the run fails again — but step 0 was NOT
    # re-executed (still succeeded with its original output).
    assert run["status"] == "failed"
    assert [s["status"] for s in run["steps"]] == ["succeeded", "failed", "pending"]
    # Retrying a succeeded run is rejected.
    wf = _workflow(client, acme_admin["headers"])
    _publish(client, acme_admin["headers"], wf["id"])
    ticket = _ticket(client, acme_admin["headers"])
    ok = client.post(
        f"{BASE}/{wf['id']}/run",
        json={"entity_type": "ticket", "entity_id": ticket["id"]},
        headers=acme_admin["headers"],
    ).json()
    assert ok["status"] == "succeeded"
    resp = client.post(f"{BASE}/runs/{ok['id']}/retry", headers=acme_admin["headers"])
    assert resp.status_code == 400


def test_retry_succeeds_after_step_definition_fixed(client, acme_admin, acme_tech, app_db, org_ids):
    tech_id = _user_id(client, acme_tech["headers"])
    ticket = _ticket(client, acme_admin["headers"], priority="low")
    stranger = str(uuid.uuid4())
    wf = _workflow(
        client,
        acme_admin["headers"],
        steps=[{"type": "set_priority", "priority": "high"}, {"type": "assign", "assignee_id": stranger}],
    )
    _publish(client, acme_admin["headers"], wf["id"])
    run = client.post(
        f"{BASE}/{wf['id']}/run",
        json={"entity_type": "ticket", "entity_id": ticket["id"]},
        headers=acme_admin["headers"],
    ).json()
    assert run["status"] == "failed"

    # Test-only repair of the pinned version's step payload (simulates a
    # corrected step definition): point the assign at the real technician.
    set_rls(app_db, org_ids["acme"])
    fixed = json.dumps(
        [
            {"type": "set_priority", "priority": "high", "name": "set_priority"},
            {"type": "assign", "assignee_id": tech_id, "name": "assign"},
        ]
    )
    with app_db.cursor() as cur:
        cur.execute(
            "UPDATE workflow_versions SET steps = %s::jsonb WHERE id = %s",
            (fixed, run["version_id"]),
        )

    resp = client.post(f"{BASE}/runs/{run['id']}/retry", headers=acme_admin["headers"])
    assert resp.status_code == 200, resp.text
    retried = resp.json()
    assert retried["status"] == "succeeded"
    assert [s["status"] for s in retried["steps"]] == ["succeeded", "succeeded"]
    got = client.get(f"/api/v1/tickets/{ticket['id']}", headers=acme_admin["headers"]).json()
    assert got["assignee_id"] == tech_id


# --- Permissions + tenant isolation ----------------------------------------------


def test_technician_cannot_manage_or_read_workflows(client, acme_tech):
    resp = client.post(
        BASE,
        json={"name": "Nope", "entity_type": "ticket", "trigger": "manual", "steps": []},
        headers=acme_tech["headers"],
    )
    assert resp.status_code == 403
    resp = client.get(BASE, headers=acme_tech["headers"])
    assert resp.status_code == 403


def test_cross_org_workflow_is_404(client, acme_admin, globex_admin):
    wf = _workflow(client, acme_admin["headers"], name="Acme only")
    resp = client.get(f"{BASE}/{wf['id']}", headers=globex_admin["headers"])
    assert resp.status_code == 404
    resp = client.get(BASE, headers=globex_admin["headers"])
    assert resp.status_code == 200
    assert all(w["id"] != wf["id"] for w in resp.json())


def test_cross_org_run_cannot_touch_other_org_ticket(client, acme_admin, globex_admin):
    ticket = _ticket(client, acme_admin["headers"])
    wf = _workflow(client, globex_admin["headers"])
    _publish(client, globex_admin["headers"], wf["id"])
    resp = client.post(
        f"{BASE}/{wf['id']}/run",
        json={"entity_type": "ticket", "entity_id": ticket["id"]},
        headers=globex_admin["headers"],
    )
    assert resp.status_code == 404


# --- Automation rules --------------------------------------------------------------


def test_rule_fires_on_match_and_applies_real_actions(client, acme_admin, acme_tech):
    tech_id = _user_id(client, acme_tech["headers"])
    rule = _rule(
        client,
        acme_admin["headers"],
        actions=[
            {"type": "assign", "assignee_id": tech_id},
            {"type": "add_comment", "body": "Critical — auto-assigned"},
        ],
    )
    ticket = _ticket(client, acme_admin["headers"], priority="critical", title="DB down")
    resp = client.post(
        f"{BASE}/automation-rules/evaluate",
        json={"trigger": "ticket.created", "entity_type": "ticket", "entity_id": ticket["id"]},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 200, resp.text
    result = resp.json()
    # Other enabled rules from earlier tests may also evaluate; assert
    # on THIS rule's run, not on the global counts.
    assert result["evaluated_rules"] >= 1
    assert result["fired"] >= 1
    run = next(r for r in result["runs"] if r["rule_id"] == rule["id"])
    assert run["status"] == "succeeded"
    assert run["rule_id"] == rule["id"]
    assert [a["type"] for a in run["actions_applied"]] == ["assign", "add_comment"]
    assert all(a["status"] == "succeeded" for a in run["actions_applied"])

    got = client.get(f"/api/v1/tickets/{ticket['id']}", headers=acme_admin["headers"]).json()
    assert got["assignee_id"] == tech_id
    comments = client.get(f"/api/v1/tickets/{ticket['id']}/comments", headers=acme_admin["headers"]).json()
    assert any(c["body"] == "Critical — auto-assigned" for c in comments)
    # The rule fired twice: once automatically when the ticket was
    # created (Phase 4 integration) and once through the manual
    # evaluate above. Both runs are listed under the rule.
    listed = client.get(f"{BASE}/automation-rules/{rule['id']}/runs", headers=acme_admin["headers"]).json()
    assert len(listed) == 2
    assert run["id"] in {r["id"] for r in listed}


def test_rule_that_matches_nothing_runs_nothing(client, acme_admin):
    rule = _rule(client, acme_admin["headers"], name="Critical only")
    ticket = _ticket(client, acme_admin["headers"], priority="medium", title="Routine")
    resp = client.post(
        f"{BASE}/automation-rules/evaluate",
        json={"trigger": "ticket.created", "entity_type": "ticket", "entity_id": ticket["id"]},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 200, resp.text
    result = resp.json()
    assert all(r["rule_id"] != rule["id"] for r in result["runs"])
    # No run row was recorded for the non-firing evaluation.
    listed = client.get(f"{BASE}/automation-rules/{rule['id']}/runs", headers=acme_admin["headers"]).json()
    assert listed == []
    got = client.get(f"/api/v1/tickets/{ticket['id']}", headers=acme_admin["headers"]).json()
    assert got["status"] == "open"  # the rule's set_status never ran


def test_disabled_rule_does_not_fire(client, acme_admin):
    rule = _rule(client, acme_admin["headers"], name="Disabled rule", is_enabled=False)
    ticket = _ticket(client, acme_admin["headers"], priority="critical")
    resp = client.post(
        f"{BASE}/automation-rules/evaluate",
        json={"trigger": "ticket.created", "entity_type": "ticket", "entity_id": ticket["id"]},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 200, resp.text
    result = resp.json()
    # Rules from earlier tests may still fire on this critical ticket;
    # the point is THIS disabled rule never fires and records nothing.
    assert all(r["rule_id"] != rule["id"] for r in result["runs"])
    listed = client.get(f"{BASE}/automation-rules/{rule['id']}/runs", headers=acme_admin["headers"]).json()
    assert listed == []


def test_rule_validation_rejects_bad_conditions_and_actions(client, acme_admin):
    base = {"name": "Bad", "trigger": "ticket.created", "entity_type": "ticket"}
    resp = client.post(
        f"{BASE}/automation-rules",
        json={
            **base,
            "conditions": [{"field": "priority", "operator": "contains", "value": "high"}],
            "actions": [{"type": "set_status", "status": "open"}],
        },
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 400
    resp = client.post(
        f"{BASE}/automation-rules",
        json={
            **base,
            "conditions": [{"field": "nope", "operator": "eq", "value": "x"}],
            "actions": [{"type": "set_status", "status": "open"}],
        },
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 400
    resp = client.post(
        f"{BASE}/automation-rules",
        json={
            **base,
            "conditions": [{"field": "priority", "operator": "eq", "value": "ultra"}],
            "actions": [{"type": "set_status", "status": "open"}],
        },
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 400
    resp = client.post(
        f"{BASE}/automation-rules",
        json={**base, "conditions": [], "actions": []},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 400  # actions must not be empty
    resp = client.post(
        f"{BASE}/automation-rules",
        json={
            **base,
            "trigger": "ticket.deleted",
            "conditions": [],
            "actions": [{"type": "set_status", "status": "open"}],
        },
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 400


def test_rule_partial_failure_records_what_actually_ran(client, acme_admin):
    stranger = str(uuid.uuid4())
    rule = _rule(
        client,
        acme_admin["headers"],
        name="Partial rule",
        actions=[
            {"type": "set_priority", "priority": "high"},
            {"type": "assign", "assignee_id": stranger},
        ],
    )
    ticket = _ticket(client, acme_admin["headers"], priority="critical")
    # The rule fired automatically at ticket creation (Phase 4
    # integration) — no manual evaluate needed, and one would no longer
    # match: the first action already changed the priority. The run is
    # partial: set_priority succeeded, the assign to a non-member failed.
    listed = client.get(f"{BASE}/automation-rules/{rule['id']}/runs", headers=acme_admin["headers"]).json()
    assert len(listed) == 1
    run = listed[0]
    assert run["status"] == "partial"
    assert run["actions_applied"][0]["status"] == "succeeded"
    assert run["actions_applied"][1]["status"] == "failed"
    assert run["error"]
    # The first action's real effect happened; the failed assign never
    # applied (another rule from an earlier test may have assigned the
    # ticket first — what matters is it is NOT the stranger).
    got = client.get(f"/api/v1/tickets/{ticket['id']}", headers=acme_admin["headers"]).json()
    assert got["priority"] == "high"
    assert got["assignee_id"] != stranger


def test_sla_breach_rule_fires_on_breached_ticket(client, acme_admin, app_db, org_ids):
    rule = _rule(
        client,
        acme_admin["headers"],
        name="Breach escalator",
        trigger="sla_breach",
        conditions=[{"field": "sla_breached", "operator": "eq", "value": True}],
        actions=[{"type": "set_priority", "priority": "critical"}],
    )
    ticket = _ticket(client, acme_admin["headers"], priority="low")
    set_rls(app_db, org_ids["acme"])
    with app_db.cursor() as cur:
        cur.execute("UPDATE tickets SET sla_breached = true WHERE id = %s", (ticket["id"],))
    resp = client.post(
        f"{BASE}/automation-rules/evaluate",
        json={"trigger": "sla_breach", "entity_type": "ticket", "entity_id": ticket["id"]},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 200, resp.text
    result = resp.json()
    assert result["fired"] >= 1
    assert any(r["rule_id"] == rule["id"] and r["status"] == "succeeded" for r in result["runs"])
    got = client.get(f"/api/v1/tickets/{ticket['id']}", headers=acme_admin["headers"]).json()
    assert got["priority"] == "critical"


def test_rule_crud_update_disable_delete(client, acme_admin, globex_admin):
    rule = _rule(client, acme_admin["headers"], name="Editable")
    resp = client.patch(
        f"{BASE}/automation-rules/{rule['id']}",
        json={"name": "Renamed", "is_enabled": False},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["name"] == "Renamed"
    assert resp.json()["is_enabled"] is False
    # Cross-org: invisible.
    resp = client.get(f"{BASE}/automation-rules/{rule['id']}", headers=globex_admin["headers"])
    assert resp.status_code == 404
    resp = client.delete(f"{BASE}/automation-rules/{rule['id']}", headers=acme_admin["headers"])
    assert resp.status_code == 204
    resp = client.get(f"{BASE}/automation-rules/{rule['id']}", headers=acme_admin["headers"])
    assert resp.status_code == 404


def test_evaluate_unknown_entity_404(client, acme_admin):
    resp = client.post(
        f"{BASE}/automation-rules/evaluate",
        json={"trigger": "ticket.created", "entity_type": "ticket", "entity_id": str(uuid.uuid4())},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 404


def test_evaluate_bad_trigger_400(client, acme_admin):
    ticket = _ticket(client, acme_admin["headers"])
    resp = client.post(
        f"{BASE}/automation-rules/evaluate",
        json={"trigger": "ticket.deleted", "entity_type": "ticket", "entity_id": ticket["id"]},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 400


def test_condition_operators_is_null_and_in(client, acme_admin, acme_tech):
    tech_id = _user_id(client, acme_tech["headers"])
    rule = _rule(
        client,
        acme_admin["headers"],
        name="Unassigned escalator",
        conditions=[
            {"field": "assignee_id", "operator": "is_null"},
            {"field": "priority", "operator": "in", "value": ["high", "critical"]},
        ],
        actions=[{"type": "assign", "assignee_id": tech_id}],
    )
    ticket = _ticket(client, acme_admin["headers"], priority="high")
    # The rule fired automatically at creation (assignee null, priority
    # high). A manual re-evaluate would find nothing — the ticket is
    # assigned now — so assert on the automatic run.
    listed = client.get(f"{BASE}/automation-rules/{rule['id']}/runs", headers=acme_admin["headers"]).json()
    assert len(listed) == 1
    run = listed[0]
    assert run["status"] == "succeeded"
    got = client.get(f"/api/v1/tickets/{ticket['id']}", headers=acme_admin["headers"]).json()
    assert got["assignee_id"] == tech_id
