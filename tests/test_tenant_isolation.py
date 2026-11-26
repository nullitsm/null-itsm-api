"""Tenant isolation tests — the core multi-tenancy guarantee.

These tests prove, at BOTH the API level and the raw database level, that
Organization A can never read or modify Organization B's records.
"""

from __future__ import annotations

import uuid

import pytest

from tests.conftest import set_rls


def test_org_a_cannot_list_org_b_tickets(client, acme_admin, globex_admin, org_ids):
    # Each fixture org has at least one seeded ticket; other tests may
    # have created more, so assert scoping (not exact counts).
    acme_tickets = client.get("/api/v1/tickets", headers=acme_admin["headers"]).json()
    globex_tickets = client.get("/api/v1/tickets", headers=globex_admin["headers"]).json()
    assert len(acme_tickets) >= 1
    assert len(globex_tickets) >= 1
    assert all(t["organization_id"] == org_ids["acme"] for t in acme_tickets)
    assert all(t["organization_id"] == org_ids["globex"] for t in globex_tickets)
    assert {t["id"] for t in acme_tickets}.isdisjoint({t["id"] for t in globex_tickets})


def test_org_a_cannot_read_org_b_ticket_by_id(client, acme_admin, globex_admin):
    globex_ticket = client.get("/api/v1/tickets", headers=globex_admin["headers"]).json()[0]
    # Acme's admin asks for Globex's ticket: 404 (never reveals existence).
    resp = client.get(f"/api/v1/tickets/{globex_ticket['id']}", headers=acme_admin["headers"])
    assert resp.status_code == 404
    # And cannot update it either.
    resp = client.patch(
        f"/api/v1/tickets/{globex_ticket['id']}",
        json={"status": "resolved"},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 404


def test_org_a_cannot_list_org_b_users(client, acme_admin, globex_admin):
    acme_users = client.get("/api/v1/users", headers=acme_admin["headers"]).json()
    globex_users = client.get("/api/v1/users", headers=globex_admin["headers"]).json()
    acme_emails = {u["email"] for u in acme_users}
    globex_emails = {u["email"] for u in globex_users}
    assert "alice@acme.example.com" in acme_emails and "tom@acme.example.com" in acme_emails
    assert "gina@globex.example.com" not in acme_emails and "greg@globex.example.com" not in acme_emails
    assert "gina@globex.example.com" in globex_emails and "alice@acme.example.com" not in globex_emails


def test_cross_org_header_forged_org_id_denied(client, acme_admin, org_ids):
    # Acme's admin presents a valid token but asks for Globex's org.
    headers = dict(acme_admin["headers"])
    headers["X-Organization-Id"] = org_ids["globex"]
    resp = client.get("/api/v1/auth/me", headers=headers)
    assert resp.status_code == 403
    # A random org id is also denied.
    headers["X-Organization-Id"] = str(uuid.uuid4())
    resp = client.get("/api/v1/auth/me", headers=headers)
    assert resp.status_code == 403


def test_rls_at_database_level(app_db, org_ids):
    """Raw SQL as the app role, with different org contexts, sees only
    that org's tickets — the database enforces isolation even if the API
    layer is bypassed."""
    acme_ticket_ids = None
    with app_db.cursor() as cur:
        set_rls(app_db, org_ids["acme"])
        cur.execute("SELECT id, organization_id FROM tickets")
        acme_rows = cur.fetchall()
        assert len(acme_rows) >= 1  # other tests may have created more
        assert all(str(r[1]) == org_ids["acme"] for r in acme_rows)
        acme_ticket_ids = {str(r[0]) for r in acme_rows}

        set_rls(app_db, org_ids["globex"])
        cur.execute("SELECT id, organization_id FROM tickets")
        globex_rows = cur.fetchall()
        assert len(globex_rows) >= 1
        assert all(str(r[1]) == org_ids["globex"] for r in globex_rows)
        assert {str(r[0]) for r in globex_rows}.isdisjoint(acme_ticket_ids)

        # With NO org context, no tenant rows are visible at all.
        set_rls(app_db, None)
        cur.execute("SELECT id FROM tickets")
        assert cur.fetchall() == []


def test_rls_blocks_cross_org_insert(app_db, org_ids):
    """An INSERT carrying another org's id is rejected by the RLS policy,
    even from a raw database session scoped to the wrong org."""
    import psycopg

    with app_db.cursor() as cur:
        set_rls(app_db, org_ids["acme"])
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            cur.execute(
                "INSERT INTO tickets (id, organization_id, number, title, status, priority, category) "
                "VALUES (gen_random_uuid(), %s, 'INC-999999', 'forged', 'open', 'low', 'General')",
                (org_ids["globex"],),
            )


def test_rls_blocks_cross_org_user_read(client, app_db, org_ids, acme_admin):
    """A raw session scoped to Acme (as Alice) cannot SELECT Globex's users.

    The users SELECT policy is user-scoped by design — a caller reads
    their own row or rows of users who share an organization with them —
    so the session needs Alice's user id as well as the org id.
    """
    alice_id = client.get("/api/v1/auth/me", headers=acme_admin["headers"]).json()["user_id"]
    with app_db.cursor() as cur:
        set_rls(app_db, org_ids["acme"], alice_id)
        cur.execute("SELECT email FROM users WHERE email LIKE '%@globex.example.com'")
        assert cur.fetchall() == []
        cur.execute("SELECT email FROM users WHERE email LIKE '%@acme.example.com'")
        assert len(cur.fetchall()) == 2
