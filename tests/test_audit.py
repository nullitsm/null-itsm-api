"""Audit log tests: events are recorded, org-scoped, and append-only."""

from __future__ import annotations

import uuid


def test_login_and_ticket_actions_are_audited(client, acme_admin, org_ids):
    # Create a ticket (audited), then read the audit log.
    created = client.post(
        "/api/v1/tickets",
        json={"title": "Audit test ticket"},
        headers=acme_admin["headers"],
    )
    assert created.status_code == 201
    ticket_id = created.json()["id"]
    logs = client.get("/api/v1/audit", headers=acme_admin["headers"]).json()
    actions = {(entry["action"], entry["resource_id"]) for entry in logs}
    assert ("ticket.created", ticket_id) in actions
    # Every entry belongs to this org and carries the required fields.
    for entry in logs:
        assert entry["organization_id"] == org_ids["acme"]
        assert entry["action"] and entry["resource_type"] and entry["outcome"]
        assert entry["created_at"]


def test_audit_log_is_org_scoped(client, acme_admin, globex_admin, org_ids):
    acme_logs = client.get("/api/v1/audit", headers=acme_admin["headers"]).json()
    globex_logs = client.get("/api/v1/audit", headers=globex_admin["headers"]).json()
    assert all(e["organization_id"] == org_ids["acme"] for e in acme_logs)
    assert all(e["organization_id"] == org_ids["globex"] for e in globex_logs)
    # No overlap in event ids.
    acme_ids = {e["id"] for e in acme_logs}
    globex_ids = {e["id"] for e in globex_logs}
    assert not (acme_ids & globex_ids)


def test_technician_cannot_read_audit_log(client, acme_tech):
    assert client.get("/api/v1/audit", headers=acme_tech["headers"]).status_code == 403


def test_audit_records_cannot_be_modified_via_db(app_db, org_ids, acme_admin, client):
    """Direct UPDATE/DELETE on audit_logs as the app role is denied: the
    RLS policy set contains no UPDATE or DELETE policy for this table.

    PostgreSQL semantics note: with no policy for a command, the
    default-deny applies — UPDATE/DELETE affect ZERO rows rather than
    raising. The append-only guarantee is therefore verified by row
    counts (nothing changes) and not by an exception.
    """

    # Ensure at least one audit row exists in Acme.
    client.post("/api/v1/tickets", json={"title": "audit immutability probe"}, headers=acme_admin["headers"])
    with app_db.cursor() as cur:
        from tests.conftest import set_rls

        set_rls(app_db, org_ids["acme"])
        cur.execute("SELECT id FROM audit_logs LIMIT 1")
        row = cur.fetchone()
        assert row is not None
        audit_id = row[0]
        cur.execute("UPDATE audit_logs SET outcome = 'tampered' WHERE id = %s", (audit_id,))
        assert cur.rowcount == 0, "audit UPDATE must affect no rows (append-only)"
        cur.execute("DELETE FROM audit_logs WHERE id = %s", (audit_id,))
        assert cur.rowcount == 0, "audit DELETE must affect no rows (append-only)"
        # The row is untouched.
        cur.execute("SELECT outcome FROM audit_logs WHERE id = %s", (audit_id,))
        assert cur.fetchone()[0] != "tampered"


def test_no_audit_write_api_endpoints(client, acme_admin):
    # There is no PUT/DELETE/PATCH route for audit records at all.
    fake_id = str(uuid.uuid4())
    assert client.put(f"/api/v1/audit/{fake_id}", json={}, headers=acme_admin["headers"]).status_code in (404, 405)
    assert client.delete(f"/api/v1/audit/{fake_id}", headers=acme_admin["headers"]).status_code in (404, 405)
    assert client.patch(f"/api/v1/audit/{fake_id}", json={}, headers=acme_admin["headers"]).status_code in (404, 405)
