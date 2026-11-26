"""Remove a technician from an organization (Nov 25, 2026 spec).

Removal DEACTIVATES the membership (never a hard delete): the user
record and audit history are preserved, access ends immediately, and
re-adding requires a fresh invitation. Assigned assets go through the
Phase 2 offboarding flow (recovery tickets, assets to in_repair),
pending invitations for the email are cancelled, and the removal is
audited. The last Organization Administrator and the org owner cannot
be removed. The platform workflow for platform users is the existing
suspend endpoint (PATCH /api/v1/platform/admins/{id}/suspend, tested
in tests/test_platform.py) — not duplicated here.
"""

from __future__ import annotations

import uuid

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.database import set_rls_context
from app.models.rbac import Role, UserRole
from tests.conftest import TEST_OWNER_URL, TEST_PASSWORD, set_rls
from tests.test_registration import _invite, _register, _token_from_url, _uniq

PASSWORD = TEST_PASSWORD


def _accept_tech(client, reg: dict, email: str) -> dict:
    """Invite + accept + sign in. Returns user_id/email/headers/tokens."""
    invitation = _invite(client, reg, email)
    token = _token_from_url(invitation["accept_url"])
    accept = client.post(
        "/api/v1/auth/invitations/accept",
        json={"token": token, "full_name": "Tech One", "password": PASSWORD},
    )
    assert accept.status_code == 200, accept.text
    login = client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
    assert login.status_code == 200, login.text
    assert login.json()["status"] == "ok"
    me = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {login.json()['access_token']}"},
    ).json()
    return {
        "user_id": me["user_id"],
        "email": email,
        "headers": {"Authorization": f"Bearer {login.json()['access_token']}"},
        "tokens": login.json(),
    }


def _remove(client, reg: dict, user_id: str, reason: str | None = None, headers: dict | None = None):
    body = {"reason": reason} if reason is not None else {}
    return client.post(
        f"/api/v1/organizations/{reg['org_id']}/members/{user_id}/remove",
        json=body,
        headers=headers or reg["headers"],
    )


def _admin_role_id(client, reg: dict) -> str:
    roles = client.get("/api/v1/roles", headers=reg["headers"])
    assert roles.status_code == 200, roles.text
    match = [r for r in roles.json() if r["name"] == "Organization Administrator"]
    assert match, "Organization Administrator role not found"
    return match[0]["id"]


def _grant_admin_role(client, reg: dict, user_id: str) -> None:
    """Grant the Organization Administrator role, approving the
    elevated-access request the default policy creates."""
    role_id = _admin_role_id(client, reg)
    assign = client.post(
        "/api/v1/roles/assign",
        json={"role_id": role_id, "user_id": user_id},
        headers=reg["headers"],
    )
    assert assign.status_code == 200, assign.text
    if assign.json().get("status") == "pending_approval":
        decide = client.post(
            f"/api/v1/roles/approvals/{assign.json()['approval_id']}/decide",
            json={"approve": True},
            headers=reg["headers"],
        )
        assert decide.status_code == 200, decide.text


def _revoke_owner_admin_role_directly(org_id: str, owner_id: str) -> None:
    """Delete the owner's Organization Administrator role row directly.

    The API refuses this (revoke_role guards the owner's last admin
    role), so this state — a non-owner sole admin — is reachable only
    outside the API. The test constructs it to prove the last-admin
    guard holds on the invariant, not on the common path.
    """
    engine = create_engine(TEST_OWNER_URL)
    session = sessionmaker(bind=engine)()
    try:
        set_rls_context(session, uuid.UUID(org_id), uuid.UUID(owner_id))
        role = session.execute(
            select(Role).where(
                Role.organization_id == uuid.UUID(org_id),
                Role.name == "Organization Administrator",
            )
        ).scalar_one()
        row = session.execute(
            select(UserRole).where(
                UserRole.organization_id == uuid.UUID(org_id),
                UserRole.user_id == uuid.UUID(owner_id),
                UserRole.role_id == role.id,
            )
        ).scalar_one()
        session.delete(row)
        session.commit()
    finally:
        session.close()


def _make_sole_non_owner_admin(client, reg: dict) -> dict:
    """An org where the only Organization Administrator is a non-owner
    technician: grant a tech the admin role, then remove the owner's
    role row directly. Returns the tech dict."""
    tech = _accept_tech(client, reg, _uniq("sole-admin-tech"))
    _grant_admin_role(client, reg, tech["user_id"])
    _revoke_owner_admin_role_directly(reg["org_id"], reg["user_id"])
    return tech


def _members(client, reg: dict, headers: dict | None = None) -> list:
    resp = client.get(
        f"/api/v1/organizations/{reg['org_id']}/members", headers=headers or reg["headers"]
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


# --- Happy path ---------------------------------------------------------------


def test_remove_technician_deactivates_preserves_user_and_audits(client):
    reg = _register(client, "Remove Happy Path Org")
    tech = _accept_tech(client, reg, _uniq("remove-tech"))
    resp = _remove(client, reg, tech["user_id"], reason="Role ended")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["user_id"] == tech["user_id"]
    assert data["email"] == tech["email"]
    assert data["membership_status"] == "deactivated"
    assert data["reason"] == "Role ended"
    assert data["invitations_cancelled"] == []
    assert data["assets_recovered"] == []
    assert data["tickets_created"] == []
    assert data["sessions_revoked"] == 1, "the tech's login session must be revoked"
    assert data["temp_grants_revoked"] == 0

    # The member row is still there (deactivated), the user is not deleted.
    member = [m for m in _members(client, reg) if m["user_id"] == tech["user_id"]]
    assert len(member) == 1
    assert member[0]["status"] == "deactivated"
    assert member[0]["email"] == tech["email"]
    assert member[0]["full_name"] == "Tech One"

    # The removal is audited with actor, target, reason and outcome.
    logs = client.get("/api/v1/audit", headers=reg["headers"]).json()
    removed = [e for e in logs if e.get("action") == "membership.removed"]
    assert len(removed) == 1
    assert removed[0]["metadata"]["user_id"] == tech["user_id"]
    assert removed[0]["metadata"]["reason"] == "Role ended"
    assert removed[0]["metadata"]["email"] == tech["email"]


def test_removed_user_cannot_authenticate_to_org(client):
    reg = _register(client, "Remove Auth Org")
    tech = _accept_tech(client, reg, _uniq("removed-auth-tech"))
    old_headers = tech["headers"]
    old_refresh = tech["tokens"]["refresh_token"]
    assert _remove(client, reg, tech["user_id"]).status_code == 200

    # Sign-in no longer yields an org token: no active membership.
    login = client.post("/api/v1/auth/login", json={"email": tech["email"], "password": PASSWORD})
    assert login.status_code == 200, login.text
    assert login.json()["status"] == "no_org"

    # The pre-removal access token is rejected on the next request:
    # every request re-checks for an active membership.
    me = client.get("/api/v1/auth/me", headers=old_headers)
    assert me.status_code == 403, me.text

    # The revoked session cannot refresh into a new token pair.
    refresh = client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh})
    assert refresh.status_code == 401, refresh.text


def test_remove_flags_assigned_assets_for_recovery(client, app_db):
    reg = _register(client, "Remove Assets Org")
    tech = _accept_tech(client, reg, _uniq("remove-asset-tech"))
    asset = client.post(
        "/api/v1/assets",
        json={"asset_tag": "AST-RM-001", "name": "Laptop", "type": "laptop"},
        headers=reg["headers"],
    )
    assert asset.status_code == 201, asset.text
    assigned = client.post(
        f"/api/v1/assets/{asset.json()['id']}/assign",
        json={"user_id": tech["user_id"]},
        headers=reg["headers"],
    )
    assert assigned.status_code == 200, assigned.text

    resp = _remove(client, reg, tech["user_id"], reason="Left the company")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["assets_recovered"] == ["AST-RM-001"]
    assert len(data["tickets_created"]) == 1
    assert data["tickets_created"][0]["asset_tag"] == "AST-RM-001"
    assert data["tickets_created"][0]["number"].startswith("INC-")

    # The asset is flagged for recovery (in_repair, unassigned).
    set_rls(app_db, reg["org_id"], reg["user_id"])
    with app_db.cursor() as cur:
        cur.execute("SELECT status, assigned_to_id FROM assets WHERE asset_tag = 'AST-RM-001'")
        status, assigned_to = cur.fetchone()
    assert status == "in_repair"
    assert assigned_to is None


def test_remove_cancels_pending_reinvite(client):
    reg = _register(client, "Remove Reinvite Org")
    tech = _accept_tech(client, reg, _uniq("reinvite-tech"))
    # A second invite to an existing member is allowed (the first was
    # accepted, so no pending duplicate blocks it).
    second = _invite(client, reg, tech["email"])
    assert second["status"] == "pending"

    resp = _remove(client, reg, tech["user_id"])
    assert resp.status_code == 200, resp.text
    assert resp.json()["invitations_cancelled"] == [second["id"]]

    rows = client.get(f"/api/v1/organizations/{reg['org_id']}/invitations", headers=reg["headers"])
    by_id = {r["id"]: r for r in rows.json()}
    assert by_id[second["id"]]["status"] == "revoked"


# --- Safety rules -------------------------------------------------------------


def test_remove_by_non_admin_forbidden(client):
    reg = _register(client, "Remove Forbidden Org")
    tech_a = _accept_tech(client, reg, _uniq("forbid-a-tech"))
    tech_b = _accept_tech(client, reg, _uniq("forbid-b-tech"))
    # A technician cannot remove others...
    resp = _remove(client, reg, tech_b["user_id"], headers=tech_a["headers"])
    assert resp.status_code == 403, resp.text
    # ... or themselves.
    resp = _remove(client, reg, tech_a["user_id"], headers=tech_a["headers"])
    assert resp.status_code == 403, resp.text
    # Nobody was removed.
    statuses = {m["user_id"]: m["status"] for m in _members(client, reg)}
    assert statuses[tech_a["user_id"]] == "active"
    assert statuses[tech_b["user_id"]] == "active"


def test_remove_owner_refused(client):
    reg = _register(client, "Remove Owner Org")
    resp = _remove(client, reg, reg["user_id"], reason="Try to remove the owner")
    assert resp.status_code == 400, resp.text
    assert "owner" in resp.json()["detail"].lower()
    statuses = {m["user_id"]: m["status"] for m in _members(client, reg)}
    assert statuses[reg["user_id"]] == "active"


def test_remove_last_org_admin_refused(client):
    reg = _register(client, "Remove Last Admin Org")
    tech = _make_sole_non_owner_admin(client, reg)
    # The sole admin cannot remove themselves: the org would be left
    # with no Organization Administrator.
    resp = _remove(client, reg, tech["user_id"], headers=tech["headers"])
    assert resp.status_code == 400, resp.text
    assert "last organization administrator" in resp.json()["detail"].lower()
    # The owner lost users:manage when their role row was removed, so
    # the member list is read with the sole admin's headers.
    statuses = {m["user_id"]: m["status"] for m in _members(client, reg, headers=tech["headers"])}
    assert statuses[tech["user_id"]] == "active"


def test_patch_deactivate_last_admin_refused(client):
    reg = _register(client, "Patch Last Admin Org")
    tech = _make_sole_non_owner_admin(client, reg)
    # The same invariant holds on the PATCH status path.
    resp = client.patch(
        f"/api/v1/organizations/{reg['org_id']}/members/{tech['user_id']}",
        json={"status": "deactivated"},
        headers=tech["headers"],
    )
    assert resp.status_code == 400, resp.text
    assert "last organization administrator" in resp.json()["detail"].lower()


def test_admin_self_removal_allowed_when_another_admin_remains(client):
    reg = _register(client, "Self Removal Org")
    tech = _accept_tech(client, reg, _uniq("self-remove-tech"))
    _grant_admin_role(client, reg, tech["user_id"])
    # The owner remains an admin, so the second admin may remove
    # themselves.
    resp = _remove(client, reg, tech["user_id"], headers=tech["headers"], reason="Stepping down")
    assert resp.status_code == 200, resp.text
    assert resp.json()["membership_status"] == "deactivated"
    statuses = {m["user_id"]: m["status"] for m in _members(client, reg)}
    assert statuses[reg["user_id"]] == "active"
    assert statuses[tech["user_id"]] == "deactivated"


def test_suspended_member_still_listed(client):
    """Suspended members stay visible in Organization Users too — the
    same RLS fix as deactivated members (migration 0019)."""
    reg = _register(client, "Suspended Listed Org")
    tech = _accept_tech(client, reg, _uniq("suspended-listed-tech"))
    resp = client.patch(
        f"/api/v1/organizations/{reg['org_id']}/members/{tech['user_id']}",
        json={"status": "suspended"},
        headers=reg["headers"],
    )
    assert resp.status_code == 200, resp.text
    member = [m for m in _members(client, reg) if m["user_id"] == tech["user_id"]]
    assert len(member) == 1
    assert member[0]["status"] == "suspended"


def test_remove_twice_refused(client):
    reg = _register(client, "Remove Twice Org")
    tech = _accept_tech(client, reg, _uniq("twice-tech"))
    assert _remove(client, reg, tech["user_id"]).status_code == 200
    resp = _remove(client, reg, tech["user_id"])
    assert resp.status_code == 400, resp.text
    assert "already been removed" in resp.json()["detail"].lower()


def test_cross_org_removal_refused(client):
    reg_a = _register(client, "Remove Cross Org A")
    tech_a = _accept_tech(client, reg_a, _uniq("cross-tech"))
    reg_b = _register(client, "Remove Cross Org B")
    # Org B's admin cannot remove a member of org A (tenant isolation).
    resp = _remove(client, reg_a, tech_a["user_id"], headers=reg_b["headers"])
    assert resp.status_code == 403, resp.text
    statuses = {m["user_id"]: m["status"] for m in _members(client, reg_a)}
    assert statuses[tech_a["user_id"]] == "active"
    # Removing a user with no membership in the org is a 400, not a leak.
    resp = _remove(client, reg_a, str(uuid.uuid4()))
    assert resp.status_code == 400, resp.text
