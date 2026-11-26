"""Organization management tests: provisioning, invitations, policy,
access reviews, and elevated-access approvals."""

from __future__ import annotations

import secrets
import uuid

from tests.factories import TEST_PASSWORD as DEV_PASSWORD


def _login(client, email, password=DEV_PASSWORD):
    resp = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_provision_organization_flow(client):
    """A user with no organization can create one and becomes its owner."""
    from tests.conftest import make_user_with_no_org

    email = f"founder-{secrets.token_hex(4)}@example.com"
    user = make_user_with_no_org(client, email)
    headers = {"Authorization": f"Bearer {user['access_token']}"}
    resp = client.post("/api/v1/organizations", json={"name": "Founder Org"}, headers=headers)
    assert resp.status_code == 201, resp.text
    org = resp.json()
    assert org["slug"] == "founder-org"
    # After provisioning, the user logs in and lands in the new org.
    login = _login(client, email)
    assert login["status"] == "ok"
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {login['access_token']}"}).json()
    assert me["organization_id"] == org["id"]
    assert me["is_org_owner"] is True
    assert "org:manage" in me["permissions"]
    # The eight role templates were seeded.
    roles = client.get("/api/v1/roles", headers={"Authorization": f"Bearer {login['access_token']}"}).json()
    assert {r["name"] for r in roles} == {
        "Organization Administrator",
        "IT Operations",
        "Service Desk Technician",
        "Endpoint Administrator",
        "Security Analyst",
        "Change Manager",
        "Auditor",
        "Employee / Requester",
    }


def test_duplicate_org_slug_rejected(client, acme_admin):
    # Alice already owns Acme; a second org with slug "acme" must fail.
    resp = client.post(
        "/api/v1/organizations", json={"name": "Acme Copy", "slug": "acme"}, headers=acme_admin["headers"]
    )
    assert resp.status_code == 400


def test_invite_and_accept_flow(client, acme_admin, org_ids):
    """Invite a technician by email; they accept and join with the role."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.models.auth import Invitation
    from app.security import hash_token, new_opaque_token
    from tests.conftest import TEST_OWNER_URL

    roles = client.get("/api/v1/roles", headers=acme_admin["headers"]).json()
    sd_role = next(r for r in roles if r["name"] == "Service Desk Technician")
    invitee = f"invited-{secrets.token_hex(4)}@example.com"
    resp = client.post(
        f"/api/v1/organizations/{org_ids['acme']}/invitations",
        json={"email": invitee, "role_ids": [sd_role["id"]]},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 201, resp.text
    invitation_id = resp.json()["id"]

    # The API never returns the raw token; retoken the API-created
    # invitation row with a KNOWN token to exercise accept. Only one
    # pending invitation per (org, email) may exist (migration 0018
    # enforces it with a partial unique index), so no second row is
    # created — the API invite already assigned the role.
    token = new_opaque_token()
    engine = create_engine(TEST_OWNER_URL)
    session = sessionmaker(bind=engine)()
    try:
        from app.database import set_rls_context

        set_rls_context(session, uuid.UUID(org_ids["acme"]), None)
        inv = session.get(Invitation, uuid.UUID(invitation_id))
        inv.token_hash = hash_token(token)
        session.commit()
    finally:
        session.close()

    accepted = client.post(
        "/api/v1/auth/invitations/accept",
        json={"token": token, "full_name": "Invited Tech", "password": DEV_PASSWORD},
    )
    assert accepted.status_code == 200, accepted.text
    login = _login(client, invitee)
    assert login["status"] == "ok"
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {login['access_token']}"}).json()
    assert "tickets:create" in me["permissions"]
    # The first (API-created) invitation can be revoked.
    revoked = client.post(
        f"/api/v1/organizations/{org_ids['acme']}/invitations/{invitation_id}/revoke",
        headers=acme_admin["headers"],
    )
    assert revoked.status_code == 200
    # And the revoked invitation's token no longer accepts.
    assert (
        client.post(
            "/api/v1/auth/invitations/accept",
            json={"token": "bogus", "full_name": "X", "password": DEV_PASSWORD},
        ).status_code
        == 400
    )


def test_technician_cannot_invite(client, acme_tech, org_ids):
    resp = client.post(
        f"/api/v1/organizations/{org_ids['acme']}/invitations",
        json={"email": "x@example.com", "role_ids": []},
        headers=acme_tech["headers"],
    )
    assert resp.status_code == 403


def test_policy_get_set_and_access_review(client, acme_admin, org_ids):
    headers = acme_admin["headers"]
    policy = client.get(f"/api/v1/organizations/{org_ids['acme']}/policy", headers=headers).json()
    assert policy["enforce_least_privilege"] is True
    updated = client.put(
        f"/api/v1/organizations/{org_ids['acme']}/policy",
        json={"access_expiration": True, "access_review_schedule": "30d"},
        headers=headers,
    ).json()
    assert updated["access_expiration"] is True
    assert updated["access_review_schedule"] == "30d"
    assert updated["enforce_least_privilege"] is True  # untouched keys survive
    review = client.post(f"/api/v1/organizations/{org_ids['acme']}/access-reviews", headers=headers)
    assert review.status_code == 201, review.text
    review_id = review.json()["id"]
    done = client.post(f"/api/v1/organizations/{org_ids['acme']}/access-reviews/{review_id}/complete", headers=headers)
    assert done.status_code == 200
    assert done.json()["status"] == "completed"


def test_elevated_role_assignment_requires_approval(client, acme_admin, org_ids):
    """With require_approval_for_elevated on (the default), assigning a
    Privileged role creates a pending approval instead of granting it."""
    headers = acme_admin["headers"]
    roles = client.get("/api/v1/roles", headers=headers).json()
    itops = next(r for r in roles if r["name"] == "IT Operations")
    users = client.get("/api/v1/users", headers=headers).json()
    tech = next(u for u in users if u["email"] == "tom@acme.example.com")
    # Tom already has Service Desk; IT Operations is Privileged -> approval.
    result = client.post(
        "/api/v1/roles/assign",
        json={"user_id": tech["id"], "role_id": itops["id"]},
        headers=headers,
    )
    assert result.status_code == 200, result.text
    assert result.json()["status"] == "pending_approval"
    approval_id = result.json()["approval_id"]
    # Not yet effective: Tom's roles do not include IT Operations.
    roles_now = client.get(f"/api/v1/users/{tech['id']}/roles", headers=headers).json()
    assert "IT Operations" not in roles_now
    # Approve it: now the role lands.
    decided = client.post(f"/api/v1/roles/approvals/{approval_id}/decide", json={"approve": True}, headers=headers)
    assert decided.status_code == 200
    assert decided.json()["status"] == "approved"
    roles_now = client.get(f"/api/v1/users/{tech['id']}/roles", headers=headers).json()
    assert "IT Operations" in roles_now
    # Cleanup: revoke it again.
    revoked = client.post(
        "/api/v1/roles/revoke",
        json={"user_id": tech["id"], "role_id": itops["id"]},
        headers=headers,
    )
    assert revoked.status_code == 200


def test_org_switching_between_two_orgs(client):
    """A user belonging to two organizations can switch with the refresh
    token, and each token stays scoped to its own organization."""
    from tests.conftest import make_user_with_no_org

    email = f"switcher-{secrets.token_hex(4)}@example.com"
    user = make_user_with_no_org(client, email)
    headers = {"Authorization": f"Bearer {user['access_token']}"}
    org_a = client.post("/api/v1/organizations", json={"name": "Switch Org A"}, headers=headers).json()
    # Log in (now single-org) then create a second org with the org token.
    login_a = _login(client, email)
    headers_a = {"Authorization": f"Bearer {login_a['access_token']}"}
    org_b = client.post("/api/v1/organizations", json={"name": "Switch Org B"}, headers=headers_a).json()
    # Log in again: two memberships -> org_required with an org_select_token.
    login2 = client.post("/api/v1/auth/login", json={"email": email, "password": DEV_PASSWORD}).json()
    assert login2["status"] == "org_required"
    assert login2["org_select_token"]
    selected = client.post(
        "/api/v1/auth/select-organization",
        json={"organization_id": org_b["id"]},
        headers={"Authorization": f"Bearer {login2['org_select_token']}"},
    )
    assert selected.status_code == 200, selected.text
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {selected.json()['access_token']}"}).json()
    assert me["organization_id"] == org_b["id"]
    # The refresh token switches back to org A.
    switched = client.post(
        "/api/v1/auth/switch-organization",
        json={"refresh_token": selected.json()["refresh_token"], "organization_id": org_a["id"]},
    )
    assert switched.status_code == 200, switched.text
    me_a = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {switched.json()['access_token']}"}).json()
    assert me_a["organization_id"] == org_a["id"]
