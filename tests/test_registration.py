"""Registration, onboarding, invitations, switching, and platform-invitation tests.

Covers the priority insertion (Nov 25, 2026): public organization
registration, multi-tenant isolation between freshly registered orgs,
guided onboarding state, org switching for multi-org users, the
48-hour single-use email invitation lifecycle (org + platform), and
the local dev outbox. No real email is sent anywhere.
"""

from __future__ import annotations

import uuid
from urllib.parse import parse_qs, urlparse

from tests.conftest import TEST_PASSWORD, set_rls

PASSWORD = "RegPass123!@#"


def _uniq(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}@example.com"


def _register(client, org_name: str, admin_email: str | None = None, **overrides) -> dict:
    """Register a fresh organization through the public endpoint."""
    admin_email = admin_email or _uniq("admin")
    payload = {
        "org_name": org_name,
        "org_email": f"contact-{uuid.uuid4().hex[:8]}@example.com",
        "website": "https://example.com",
        "industry": "Technology",
        "org_size": "11-50",
        "admin_name": "Test Admin",
        "admin_email": admin_email,
        "password": PASSWORD,
    }
    payload.update(overrides)
    resp = client.post("/api/v1/auth/register", json=payload)
    assert resp.status_code == 201, resp.text
    data = resp.json()
    return {
        "org": data["organization"],
        "org_id": data["organization"]["id"],
        "user_id": data["user_id"],
        "admin_email": admin_email,
        "headers": {"Authorization": f"Bearer {data['access_token']}"},
        "tokens": data,
    }


def _token_from_url(url: str) -> str:
    return parse_qs(urlparse(url).query)["token"][0]


def _invite(client, reg: dict, email: str, **overrides) -> dict:
    payload = {
        "email": email,
        "role_ids": [],
        "full_name": "Tech One",
        "department": "Service Desk",
        "team": "Tier 1",
    }
    payload.update(overrides)
    resp = client.post(
        f"/api/v1/organizations/{reg['org_id']}/invitations", json=payload, headers=reg["headers"]
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


# --- Registration -----------------------------------------------------------


def test_register_happy_path_creates_org_admin_departments_onboarding(client):
    reg = _register(client, "NULL Demo Corporation")
    org = reg["org"]
    assert org["slug"] == "null-demo-corporation"
    assert org["contact_email"].endswith("@example.com")
    assert org["industry"] == "Technology"
    assert org["size"] == "11-50"
    assert reg["tokens"]["access_token"]
    assert reg["tokens"]["refresh_token"]

    # The admin is signed in and belongs to exactly this org.
    me = client.get("/api/v1/auth/me", headers=reg["headers"]).json()
    assert me["organization_id"] == reg["org_id"]

    # Default departments exist.
    depts = client.get(f"/api/v1/organizations/{reg['org_id']}/departments", headers=reg["headers"])
    assert depts.status_code == 200, depts.text
    assert {d["name"] for d in depts.json()} == {"IT Operations", "Service Desk", "Security"}

    # Onboarding starts with profile complete, current step departments.
    ob = client.get(f"/api/v1/organizations/{reg['org_id']}/onboarding", headers=reg["headers"])
    assert ob.status_code == 200, ob.text
    assert ob.json()["steps"]["profile"] == "complete"
    assert ob.json()["current_step"] == "departments"

    # The admin is the org owner with an active membership.
    members = client.get(f"/api/v1/organizations/{reg['org_id']}/members", headers=reg["headers"])
    assert members.status_code == 200, members.text
    admin_member = [m for m in members.json() if m["user_id"] == reg["user_id"]]
    assert len(admin_member) == 1
    assert admin_member[0]["is_owner"] is True
    assert admin_member[0]["status"] == "active"


def test_register_duplicate_admin_email_conflicts(client):
    email = _uniq("dup-admin")
    _register(client, "Org One", admin_email=email)
    resp = client.post(
        "/api/v1/auth/register",
        json={
            "org_name": "Org Two",
            "org_email": "two@example.com",
            "admin_name": "Second Admin",
            "admin_email": email,
            "password": PASSWORD,
        },
    )
    assert resp.status_code == 409


def test_register_same_org_name_gets_unique_slugs(client):
    first = _register(client, "Genesee Test Organization")
    second = _register(client, "Genesee Test Organization")
    assert first["org"]["slug"] == "genesee-test-organization"
    assert second["org"]["slug"] != first["org"]["slug"]
    assert second["org"]["slug"].startswith("genesee-test-organization")


def test_register_short_password_and_bad_size_rejected(client):
    resp = client.post(
        "/api/v1/auth/register",
        json={
            "org_name": "Bad Org",
            "org_email": "bad@example.com",
            "admin_name": "Bad Admin",
            "admin_email": _uniq("bad"),
            "password": "short",
        },
    )
    assert resp.status_code == 422
    resp = client.post(
        "/api/v1/auth/register",
        json={
            "org_name": "Bad Org",
            "org_email": "bad@example.com",
            "org_size": "huge",
            "admin_name": "Bad Admin",
            "admin_email": _uniq("bad"),
            "password": PASSWORD,
        },
    )
    assert resp.status_code == 422


def test_register_never_creates_platform_admin(client):
    reg = _register(client, "Platform Boundary Org")
    # Org admin credentials must not authenticate in the platform domain.
    resp = client.post(
        "/api/v1/platform/auth/login",
        json={"email": reg["admin_email"], "password": PASSWORD},
    )
    assert resp.status_code == 401


def test_registration_audit_event_written(client, app_db):
    reg = _register(client, "Audit Trail Org")
    with app_db.cursor() as cur:
        set_rls(app_db, reg["org_id"], reg["user_id"])
        cur.execute(
            "SELECT action FROM audit_logs WHERE organization_id = %s AND action = 'org.registered'",
            (reg["org_id"],),
        )
        rows = cur.fetchall()
    assert len(rows) == 1


# --- Org invitations --------------------------------------------------------


def test_invite_accept_login_end_to_end(client):
    reg = _register(client, "Invite Flow Org")
    tech_email = _uniq("tech")
    invitation = _invite(client, reg, tech_email)
    assert invitation["full_name"] == "Tech One"
    assert invitation["department"] == "Service Desk"
    assert invitation["team"] == "Tier 1"
    assert invitation["accept_url"], "accept link must be visible to the inviting admin"
    token = _token_from_url(invitation["accept_url"])

    # Public lookup: pre-filled, locked fields.
    lookup = client.get(f"/api/v1/auth/invitations/{token}")
    assert lookup.status_code == 200, lookup.text
    assert lookup.json()["email"] == tech_email
    assert lookup.json()["full_name"] == "Tech One"
    assert lookup.json()["organization_name"] == "Invite Flow Org"

    # Accept: creates the account and activates the membership.
    accept = client.post(
        "/api/v1/auth/invitations/accept",
        json={"token": token, "full_name": "Tech One", "password": PASSWORD},
    )
    assert accept.status_code == 200, accept.text
    assert accept.json()["organization_id"] == reg["org_id"]

    # The technician signs in and lands in the org.
    login = client.post("/api/v1/auth/login", json={"email": tech_email, "password": PASSWORD})
    assert login.status_code == 200, login.text
    assert login.json()["status"] == "ok"
    tech_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    me = client.get("/api/v1/auth/me", headers=tech_headers).json()
    assert me["organization_id"] == reg["org_id"]

    # MFA enrollment is available immediately after acceptance.
    enroll = client.post("/api/v1/auth/mfa/enroll", headers=tech_headers)
    assert enroll.status_code == 200, enroll.text
    assert "otpauth://" in enroll.json()["otpauth_uri"]

    # Single-use: the same token cannot be accepted again.
    again = client.post(
        "/api/v1/auth/invitations/accept",
        json={"token": token, "full_name": "Tech One", "password": PASSWORD},
    )
    assert again.status_code == 400


def test_invite_invalid_token_rejected(client):
    resp = client.post(
        "/api/v1/auth/invitations/accept",
        json={"token": "not-a-real-token", "full_name": "Nobody", "password": PASSWORD},
    )
    assert resp.status_code == 400
    lookup = client.get("/api/v1/auth/invitations/not-a-real-token")
    assert lookup.status_code == 404


def test_invite_duplicate_pending_rejected(client):
    reg = _register(client, "Duplicate Invite Org")
    email = _uniq("tech")
    _invite(client, reg, email)
    resp = client.post(
        f"/api/v1/organizations/{reg['org_id']}/invitations",
        json={"email": email, "role_ids": []},
        headers=reg["headers"],
    )
    assert resp.status_code == 400


def test_invite_expired_token_rejected(client, app_db):
    reg = _register(client, "Expired Invite Org")
    email = _uniq("tech")
    invitation = _invite(client, reg, email)
    # Move the expiry into the past directly (test-only manipulation).
    with app_db.cursor() as cur:
        set_rls(app_db, reg["org_id"], reg["user_id"])
        cur.execute(
            "UPDATE invitations SET expires_at = now() - interval '1 hour' WHERE id = %s",
            (invitation["id"],),
        )
    token = _token_from_url(invitation["accept_url"])
    resp = client.post(
        "/api/v1/auth/invitations/accept",
        json={"token": token, "full_name": "Tech One", "password": PASSWORD},
    )
    assert resp.status_code == 400


def test_invite_resend_invalidates_old_token(client):
    reg = _register(client, "Resend Invite Org")
    email = _uniq("tech")
    invitation = _invite(client, reg, email)
    old_token = _token_from_url(invitation["accept_url"])
    resp = client.post(
        f"/api/v1/organizations/{reg['org_id']}/invitations/{invitation['id']}/resend",
        headers=reg["headers"],
    )
    assert resp.status_code == 200, resp.text
    new_token = _token_from_url(resp.json()["accept_url"])
    assert new_token != old_token
    # The old link is dead.
    assert client.get(f"/api/v1/auth/invitations/{old_token}").status_code == 404
    # The new link accepts.
    accept = client.post(
        "/api/v1/auth/invitations/accept",
        json={"token": new_token, "full_name": "Tech One", "password": PASSWORD},
    )
    assert accept.status_code == 200, accept.text


def test_invite_revoke_blocks_acceptance(client):
    reg = _register(client, "Revoke Invite Org")
    email = _uniq("tech")
    invitation = _invite(client, reg, email)
    token = _token_from_url(invitation["accept_url"])
    resp = client.post(
        f"/api/v1/organizations/{reg['org_id']}/invitations/{invitation['id']}/revoke",
        headers=reg["headers"],
    )
    assert resp.status_code == 200, resp.text
    accept = client.post(
        "/api/v1/auth/invitations/accept",
        json={"token": token, "full_name": "Tech One", "password": PASSWORD},
    )
    assert accept.status_code == 400


def test_invitation_written_to_dev_outbox(client):
    reg = _register(client, "Outbox Org")
    email = _uniq("tech")
    invitation = _invite(client, reg, email)
    outbox = client.get(f"/api/v1/organizations/{reg['org_id']}/outbox", headers=reg["headers"])
    assert outbox.status_code == 200, outbox.text
    rows = outbox.json()
    assert len(rows) == 1
    assert rows[0]["to_email"] == email
    assert rows[0]["scope"] == "org"
    assert invitation["accept_url"].split("token=")[1] in rows[0]["body"]


# --- Multi-tenant isolation between freshly registered orgs -----------------


def test_two_registered_orgs_cannot_access_each_other(client):
    null_demo = _register(client, "NULL Demo Corporation")
    acme = _register(client, "Acme Technology Group")

    # Each admin creates a technician and a ticket in their own org.
    for reg, prefix in ((null_demo, "null"), (acme, "acme")):
        tech_email = _uniq(f"{prefix}-tech")
        invitation = _invite(client, reg, tech_email)
        token = _token_from_url(invitation["accept_url"])
        client.post(
            "/api/v1/auth/invitations/accept",
            json={"token": token, "full_name": "Tech One", "password": PASSWORD},
        )
        ticket = client.post(
            "/api/v1/tickets",
            json={"title": f"{prefix} ticket", "description": "isolation probe"},
            headers=reg["headers"],
        )
        assert ticket.status_code == 201, ticket.text

    # Cross-org reads: 403 on org-scoped endpoints (never reveals data).
    for reg, other in ((null_demo, acme), (acme, null_demo)):
        resp = client.get(f"/api/v1/organizations/{other['org_id']}", headers=reg["headers"])
        assert resp.status_code == 403, resp.text
        resp = client.get(f"/api/v1/organizations/{other['org_id']}/members", headers=reg["headers"])
        assert resp.status_code == 403
        resp = client.get(
            f"/api/v1/organizations/{other['org_id']}/invitations", headers=reg["headers"]
        )
        assert resp.status_code == 403

    # Cross-org writes are rejected.
    resp = client.post(
        f"/api/v1/organizations/{acme['org_id']}/invitations",
        json={"email": _uniq("forged"), "role_ids": []},
        headers=null_demo["headers"],
    )
    assert resp.status_code == 403

    # Ticket lists are disjoint: each org sees only its own ticket.
    null_tickets = client.get("/api/v1/tickets", headers=null_demo["headers"]).json()
    acme_tickets = client.get("/api/v1/tickets", headers=acme["headers"]).json()
    assert {t["organization_id"] for t in null_tickets} == {null_demo["org_id"]}
    assert {t["organization_id"] for t in acme_tickets} == {acme["org_id"]}
    assert {t["id"] for t in null_tickets}.isdisjoint({t["id"] for t in acme_tickets})

    # Settings are per-org: each org sees only its own profile.
    org = client.get(f"/api/v1/organizations/{null_demo['org_id']}", headers=null_demo["headers"]).json()
    assert org["name"] == "NULL Demo Corporation"


# --- Org switching ----------------------------------------------------------


def _org_role_id(client, reg: dict, name: str) -> str:
    roles = client.get("/api/v1/roles", headers=reg["headers"]).json()
    match = [r for r in roles if r["name"] == name]
    assert match, f"org role {name!r} not found"
    return match[0]["id"]


def test_multi_org_user_selects_and_switches(client):
    org_a = _register(client, "Switch Org A")
    org_b = _register(client, "Switch Org B")
    org_c = _register(client, "Genesee Test Organization")
    shared_email = _uniq("shared-tech")

    # The same person is invited into all three orgs as a technician.
    for reg in (org_a, org_b, org_c):
        role_id = _org_role_id(client, reg, "Service Desk Technician")
        invitation = _invite(client, reg, shared_email, role_ids=[role_id])
        token = _token_from_url(invitation["accept_url"])
        resp = client.post(
            "/api/v1/auth/invitations/accept",
            json={"token": token, "full_name": "Tech One", "password": PASSWORD},
        )
        assert resp.status_code == 200, resp.text

    # Login with three memberships returns the org selector.
    login = client.post("/api/v1/auth/login", json={"email": shared_email, "password": PASSWORD})
    assert login.status_code == 200, login.text
    assert login.json()["status"] == "org_required"
    assert len(login.json()["organizations"]) == 3
    select_token = login.json()["org_select_token"]

    # Select Org B: the org_select_token rides in the Authorization
    # header; the resulting tokens are scoped to B, and /me confirms it.
    selected = client.post(
        "/api/v1/auth/select-organization",
        json={"organization_id": org_b["org_id"]},
        headers={"Authorization": f"Bearer {select_token}"},
    )
    assert selected.status_code == 200, selected.text
    headers_b = {"Authorization": f"Bearer {selected.json()['access_token']}"}
    me = client.get("/api/v1/auth/me", headers=headers_b).json()
    assert me["organization_id"] == org_b["org_id"]

    # Switch to Org A with the refresh token: server-side, not frontend.
    refresh = client.post(
        "/api/v1/auth/switch-organization",
        json={"refresh_token": selected.json()["refresh_token"], "organization_id": org_a["org_id"]},
    )
    assert refresh.status_code == 200, refresh.text
    headers_a = {"Authorization": f"Bearer {refresh.json()['access_token']}"}
    me = client.get("/api/v1/auth/me", headers=headers_a).json()
    assert me["organization_id"] == org_a["org_id"]

    # Switching to an org the user does not belong to is forbidden.
    other = _register(client, "Switch Org D")
    forbidden = client.post(
        "/api/v1/auth/switch-organization",
        json={"refresh_token": refresh.json()["refresh_token"], "organization_id": other["org_id"]},
    )
    assert forbidden.status_code == 403

    # While scoped to Org B, the user sees only Org B's data.
    tickets_b = client.get("/api/v1/tickets", headers=headers_b).json()
    assert all(t["organization_id"] == org_b["org_id"] for t in tickets_b)


# --- Onboarding -------------------------------------------------------------


def test_onboarding_flow_with_skips_and_finish(client):
    reg = _register(client, "Onboarding Org")
    org_id = reg["org_id"]
    headers = reg["headers"]

    # Departments step with data: adds a department.
    resp = client.patch(
        f"/api/v1/organizations/{org_id}/onboarding",
        json={
            "step": "departments",
            "status": "complete",
            "data": {"departments": [{"name": "Network Ops", "description": "Networking"}]},
        },
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["steps"]["departments"] == "complete"
    assert resp.json()["current_step"] == "invite_technicians"
    depts = client.get(f"/api/v1/organizations/{org_id}/departments", headers=headers).json()
    assert "Network Ops" in {d["name"] for d in depts}

    # Service desk settings land in org settings.
    resp = client.patch(
        f"/api/v1/organizations/{org_id}/onboarding",
        json={
            "step": "service_desk",
            "status": "complete",
            "data": {"service_desk": {"default_priority": "medium", "auto_assign": True}},
        },
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    org = client.get(f"/api/v1/organizations/{org_id}", headers=headers).json()
    assert org["name"] == "Onboarding Org"

    # Business hours + SLA step creates real defaults.
    resp = client.patch(
        f"/api/v1/organizations/{org_id}/onboarding",
        json={"step": "business_hours_sla", "status": "complete", "data": {}},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    hours = client.get("/api/v1/sla/business-hours", headers=headers).json()
    assert len(hours) == 1 and hours[0]["is_default"] is True
    assert hours[0]["schedule"]["mon"] == [["09:00", "17:00"]]
    policies = client.get("/api/v1/sla/policies", headers=headers).json()
    assert len(policies) == 1 and policies[0]["is_default"] is True

    # Optional steps can be skipped.
    for step in ("invite_technicians", "assets_endpoints"):
        resp = client.patch(
            f"/api/v1/organizations/{org_id}/onboarding",
            json={"step": step, "status": "skipped", "data": {}},
            headers=headers,
        )
        assert resp.status_code == 200, resp.text

    # Finish completes onboarding.
    resp = client.patch(
        f"/api/v1/organizations/{org_id}/onboarding",
        json={"step": "finish", "status": "complete", "data": {}},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["completed_at"] is not None

    # Finished onboarding is locked.
    resp = client.patch(
        f"/api/v1/organizations/{org_id}/onboarding",
        json={"step": "departments", "status": "complete", "data": {}},
        headers=headers,
    )
    assert resp.status_code == 400


def test_onboarding_finish_blocked_while_steps_pending(client):
    reg = _register(client, "Onboarding Blocked Org")
    resp = client.patch(
        f"/api/v1/organizations/{reg['org_id']}/onboarding",
        json={"step": "finish", "status": "complete", "data": {}},
        headers=reg["headers"],
    )
    assert resp.status_code == 400


def test_onboarding_profile_step_cannot_be_skipped(client):
    reg = _register(client, "Onboarding Skip Org")
    resp = client.patch(
        f"/api/v1/organizations/{reg['org_id']}/onboarding",
        json={"step": "profile", "status": "skipped", "data": {}},
        headers=reg["headers"],
    )
    assert resp.status_code == 400


# --- Platform invitations ---------------------------------------------------


def _platform_role_id(client, platform_admin, name: str) -> str:
    roles = client.get("/api/v1/platform/roles", headers=platform_admin["headers"]).json()
    match = [r for r in roles if r["name"] == name]
    assert match, f"platform role {name!r} not found"
    return match[0]["id"]


def test_platform_invite_accept_login_end_to_end(client, platform_admin):
    role_id = _platform_role_id(client, platform_admin, "Platform Administrator")
    email = _uniq("platform-admin")
    resp = client.post(
        "/api/v1/platform/admin-invitations",
        json={"email": email, "full_name": "Platform Person", "role_id": role_id},
        headers=platform_admin["headers"],
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["accept_url"], "accept link must be visible to the inviting admin"
    token = _token_from_url(resp.json()["accept_url"])

    # Accept: creates the platform admin with the invited role.
    accept = client.post(
        "/api/v1/platform/auth/invitations/accept",
        json={"token": token, "password": TEST_PASSWORD},
    )
    assert accept.status_code == 200, accept.text

    # The new platform admin signs in to the platform domain.
    login = client.post(
        "/api/v1/platform/auth/login", json={"email": email, "password": TEST_PASSWORD}
    )
    assert login.status_code == 200, login.text
    assert login.json()["status"] == "ok"
    me = client.get(
        "/api/v1/platform/auth/me",
        headers={"Authorization": f"Bearer {login.json()['access_token']}"},
    )
    assert me.status_code == 200, me.text
    assert me.json()["email"] == email

    # Single-use.
    again = client.post(
        "/api/v1/platform/auth/invitations/accept",
        json={"token": token, "password": TEST_PASSWORD},
    )
    assert again.status_code == 400


def test_platform_invite_super_admin_boundary(client, platform_admin):
    # Invite a plain Platform Administrator, then have them try to invite
    # someone to the Platform Super Admin role: only a Super Admin may.
    admin_role_id = _platform_role_id(client, platform_admin, "Platform Administrator")
    email = _uniq("platform-admin")
    resp = client.post(
        "/api/v1/platform/admin-invitations",
        json={"email": email, "full_name": "Platform Person", "role_id": admin_role_id},
        headers=platform_admin["headers"],
    )
    token = _token_from_url(resp.json()["accept_url"])
    client.post(
        "/api/v1/platform/auth/invitations/accept",
        json={"token": token, "password": TEST_PASSWORD},
    )
    login = client.post(
        "/api/v1/platform/auth/login", json={"email": email, "password": TEST_PASSWORD}
    )
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    super_role_id = _platform_role_id(client, platform_admin, "Platform Super Admin")
    resp = client.post(
        "/api/v1/platform/admin-invitations",
        json={"email": _uniq("platform-super"), "full_name": "Super Person", "role_id": super_role_id},
        headers=headers,
    )
    assert resp.status_code == 403


def test_platform_invite_resend_and_revoke(client, platform_admin):
    role_id = _platform_role_id(client, platform_admin, "Platform Administrator")
    email = _uniq("platform-admin")
    resp = client.post(
        "/api/v1/platform/admin-invitations",
        json={"email": email, "full_name": "Platform Person", "role_id": role_id},
        headers=platform_admin["headers"],
    )
    invitation_id = resp.json()["id"]
    old_token = _token_from_url(resp.json()["accept_url"])

    # Resend invalidates the old link.
    resp = client.post(
        f"/api/v1/platform/admin-invitations/{invitation_id}/resend",
        headers=platform_admin["headers"],
    )
    assert resp.status_code == 200, resp.text
    new_token = _token_from_url(resp.json()["accept_url"])
    assert new_token != old_token
    assert (
        client.post(
            "/api/v1/platform/auth/invitations/accept",
            json={"token": old_token, "password": TEST_PASSWORD},
        ).status_code
        == 400
    )

    # Revoke blocks the new link too.
    resp = client.post(
        f"/api/v1/platform/admin-invitations/{invitation_id}/revoke",
        headers=platform_admin["headers"],
    )
    assert resp.status_code == 200, resp.text
    assert (
        client.post(
            "/api/v1/platform/auth/invitations/accept",
            json={"token": new_token, "password": TEST_PASSWORD},
        ).status_code
        == 400
    )


def test_platform_outbox_records_invitation(client, platform_admin):
    role_id = _platform_role_id(client, platform_admin, "Platform Administrator")
    email = _uniq("platform-admin")
    resp = client.post(
        "/api/v1/platform/admin-invitations",
        json={"email": email, "full_name": "Platform Person", "role_id": role_id},
        headers=platform_admin["headers"],
    )
    accept_url = resp.json()["accept_url"]
    outbox = client.get("/api/v1/platform/outbox", headers=platform_admin["headers"])
    assert outbox.status_code == 200, outbox.text
    rows = [r for r in outbox.json() if r["to_email"] == email]
    assert len(rows) == 1
    assert rows[0]["scope"] == "platform"
    assert accept_url.split("token=")[1] in rows[0]["body"]


def test_org_invitation_cannot_create_platform_admin(client):
    # An org technician created through the org invitation flow must not
    # be able to sign in to the platform domain.
    reg = _register(client, "Org Invite Boundary Org")
    email = _uniq("tech")
    invitation = _invite(client, reg, email)
    token = _token_from_url(invitation["accept_url"])
    client.post(
        "/api/v1/auth/invitations/accept",
        json={"token": token, "full_name": "Tech One", "password": PASSWORD},
    )
    resp = client.post(
        "/api/v1/platform/auth/login", json={"email": email, "password": PASSWORD}
    )
    assert resp.status_code == 401
