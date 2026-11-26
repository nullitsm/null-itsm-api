"""Phase 2 identity/directory + asset-lifecycle tests (migration 0007).

Covers: IdP CRUD + SP metadata, SAML ACS (real validator path + stub),
OIDC discovery (mocked transport + honest 502), SCIM v2 Users/Groups
CRUD + token auth (wrong/expired/revoked/cross-org), group-sync role
mapping, certification approve/revoke, temp-grant expiry sweep,
service-account / API-credential create-once-secret + verify + revoke,
asset lifecycle transitions + illegal-transition 400s, depreciation,
license seat limits, offboarding end-to-end, tenant isolation, raw-SQL
RLS checks, audit rows.

NOTE: the offboarding test provisions its own fresh user instead of
offboarding the shared fixture technician — suspending tom@acme would
break every later test file that uses the acme_tech fixture.
"""

from __future__ import annotations

import base64
import hashlib
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from tests.conftest import set_rls

UTC = timezone.utc


@pytest.fixture(scope="module")
def acme_users(client, acme_admin, acme_tech):
    alice = client.get("/api/v1/auth/me", headers=acme_admin["headers"]).json()
    tom = client.get("/api/v1/auth/me", headers=acme_tech["headers"]).json()
    return {"alice": alice, "tom": tom}


@pytest.fixture(scope="module")
def acme_roles(client, acme_admin):
    resp = client.get("/api/v1/roles", headers=acme_admin["headers"])
    assert resp.status_code == 200, resp.text
    return {r["name"]: r["id"] for r in resp.json()}


def _make_scim_token(client, acme_admin, name="test-scim", expires_at=None):
    body = {"name": name, "scopes": ["users:read", "users:write"]}
    if expires_at:
        body["expires_at"] = expires_at
    resp = client.post("/api/v1/identity/scim-tokens", json=body, headers=acme_admin["headers"])
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["token"], "raw token must be returned at creation"
    assert "token_hash" not in data
    return data


def _scim_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# --- Identity providers + SAML metadata --------------------------------------


def test_idp_crud_and_set_default(client, acme_admin, globex_admin):
    created = client.post(
        "/api/v1/identity/providers",
        json={
            "name": "Acme Okta",
            "type": "saml",
            "saml_entity_id": "https://acme.okta.com/saml",
            "saml_sso_url": "https://acme.okta.com/sso",
            "saml_certificate": "MIID_FAKE_CERT_FOR_TESTS",
        },
        headers=acme_admin["headers"],
    )
    assert created.status_code == 201, created.text
    provider = created.json()
    assert provider["has_certificate"] is True
    assert provider["has_client_secret"] is False
    assert provider["status"] == "active"

    # Cross-org: Globex cannot see Acme's provider.
    missing = client.get(f"/api/v1/identity/providers/{provider['id']}", headers=globex_admin["headers"])
    assert missing.status_code == 404

    # Second provider, then set-default flips the first one off.
    second = client.post(
        "/api/v1/identity/providers",
        json={"name": "Acme Entra", "type": "oidc", "oidc_issuer": "https://login.microsoftonline.com/tenant-x/v2.0"},
        headers=acme_admin["headers"],
    ).json()
    assert second["is_default"] is False
    defaulted = client.post(f"/api/v1/identity/providers/{second['id']}/set-default", headers=acme_admin["headers"])
    assert defaulted.status_code == 200, defaulted.text
    assert defaulted.json()["is_default"] is True
    first_again = client.get(f"/api/v1/identity/providers/{provider['id']}", headers=acme_admin["headers"]).json()
    assert first_again["is_default"] is False

    # Invalid type is a 422; invalid status is a 400.
    bad = client.post(
        "/api/v1/identity/providers",
        json={"name": "Bad", "type": "kerberos"},
        headers=acme_admin["headers"],
    )
    assert bad.status_code == 422
    bad_status = client.patch(
        f"/api/v1/identity/providers/{provider['id']}",
        json={"status": "banana"},
        headers=acme_admin["headers"],
    )
    assert bad_status.status_code == 400


def test_sp_metadata_valid_xml(client, acme_admin):
    provider = client.post(
        "/api/v1/identity/providers",
        json={
            "name": "Meta Test IdP",
            "type": "saml",
            "saml_entity_id": "https://idp.example.com/metadata",
            "saml_sso_url": "https://idp.example.com/sso",
        },
        headers=acme_admin["headers"],
    ).json()
    resp = client.get(f"/api/v1/identity/providers/{provider['id']}/metadata", headers=acme_admin["headers"])
    assert resp.status_code == 200, resp.text
    assert "application/xml" in resp.headers["content-type"]
    root = ET.fromstring(resp.text)
    assert root.tag.endswith("EntityDescriptor")
    assert root.get("entityID") == "https://idp.example.com/metadata"
    # ACS URL carries this provider's id.
    assert provider["id"] in resp.text
    assert "/acs" in resp.text
    # No certificate was configured: no KeyDescriptor element, and the
    # XML comment says so (the word appears in the comment text only).
    assert "<md:KeyDescriptor" not in resp.text
    assert "No SP signing certificate is configured" in resp.text

    # An OIDC provider has no SP metadata.
    oidc = client.post(
        "/api/v1/identity/providers",
        json={"name": "Meta OIDC", "type": "oidc", "oidc_issuer": "https://issuer.example.com"},
        headers=acme_admin["headers"],
    ).json()
    bad = client.get(f"/api/v1/identity/providers/{oidc['id']}/metadata", headers=acme_admin["headers"])
    assert bad.status_code == 400


def test_saml_acs_rejects_unvalidated(client, acme_admin):
    provider = client.post(
        "/api/v1/identity/providers",
        json={
            "name": "ACS Test IdP",
            "type": "saml",
            "saml_entity_id": "https://acs-idp.example.com",
            "saml_sso_url": "https://acs-idp.example.com/sso",
            "saml_certificate": "MIID_FAKE_CERT",
        },
        headers=acme_admin["headers"],
    ).json()
    garbage = base64.b64encode(b"<samlp:Response>not-a-real-assertion</samlp:Response>").decode()
    # No session: the ACS endpoint is unauthenticated by design.
    resp = client.post(f"/api/v1/identity/providers/{provider['id']}/acs", json={"SAMLResponse": garbage})
    assert resp.status_code == 400, resp.text
    # Missing SAMLResponse is a 400, not a login.
    resp2 = client.post(f"/api/v1/identity/providers/{provider['id']}/acs", json={})
    assert resp2.status_code == 400
    # Unknown provider is a 404.
    resp3 = client.post(f"/api/v1/identity/providers/{uuid.uuid4()}/acs", json={"SAMLResponse": garbage})
    assert resp3.status_code == 404


def test_saml_acs_stub_validator(client, acme_admin, monkeypatch):
    from app.services.saml_service import StubSamlValidator

    provider = client.post(
        "/api/v1/identity/providers",
        json={
            "name": "ACS Stub IdP",
            "type": "saml",
            "saml_entity_id": "https://stub-idp.example.com",
            "saml_sso_url": "https://stub-idp.example.com/sso",
            "saml_certificate": "MIID_FAKE_CERT",
        },
        headers=acme_admin["headers"],
    ).json()
    canned = base64.b64encode(b"<samlp:Response>canned</samlp:Response>").decode()
    validator = StubSamlValidator(
        {
            canned: {
                "name_id": "saml-user@example.com",
                "email": "saml-user@example.com",
                "attributes": {"givenName": "Sam"},
            }
        }
    )
    import app.routers.identity as identity_router

    monkeypatch.setattr(identity_router, "get_saml_validator", lambda: validator)
    resp = client.post(f"/api/v1/identity/providers/{provider['id']}/acs", json={"SAMLResponse": canned})
    assert resp.status_code == 200, resp.text
    assert resp.json()["validated"] is True
    assert resp.json()["email"] == "saml-user@example.com"
    # The stub refuses anything else.
    other = base64.b64encode(b"<samlp:Response>other</samlp:Response>").decode()
    resp2 = client.post(f"/api/v1/identity/providers/{provider['id']}/acs", json={"SAMLResponse": other})
    assert resp2.status_code == 400


def test_saml_acs_no_certificate_refuses(client, acme_admin):
    provider = client.post(
        "/api/v1/identity/providers",
        json={
            "name": "ACS NoCert IdP",
            "type": "saml",
            "saml_entity_id": "https://nocert.example.com",
            "saml_sso_url": "https://nocert.example.com/sso",
        },
        headers=acme_admin["headers"],
    ).json()
    garbage = base64.b64encode(b"<samlp:Response>x</samlp:Response>").decode()
    resp = client.post(f"/api/v1/identity/providers/{provider['id']}/acs", json={"SAMLResponse": garbage})
    assert resp.status_code == 400
    assert "certificate" in resp.json()["detail"].lower()


# --- OIDC discovery ----------------------------------------------------------


def test_oidc_discovery_mocked_transport():
    from app.services.identity_service import discover_oidc

    doc = {
        "issuer": "https://issuer.example.com",
        "authorization_endpoint": "https://issuer.example.com/auth",
        "token_endpoint": "https://issuer.example.com/token",
        "jwks_uri": "https://issuer.example.com/jwks",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/.well-known/openid-configuration"
        return httpx.Response(200, json=doc)

    result = discover_oidc("https://issuer.example.com", transport=httpx.MockTransport(handler))
    assert result["issuer"] == "https://issuer.example.com"
    # Second call is served from the 1-hour cache (transport would fail if hit).
    result2 = discover_oidc("https://issuer.example.com", transport=httpx.MockTransport(handler))
    assert result2 == result


def test_oidc_discovery_unreachable_is_502(client, acme_admin):
    provider = client.post(
        "/api/v1/identity/providers",
        json={"name": "Dead OIDC", "type": "oidc", "oidc_issuer": "https://127.0.0.1:9"},
        headers=acme_admin["headers"],
    ).json()
    resp = client.get(f"/api/v1/identity/providers/{provider['id']}/discover", headers=acme_admin["headers"])
    assert resp.status_code == 502, resp.text


# --- SCIM tokens + auth -------------------------------------------------------


def test_scim_token_auth_wrong_expired_revoked(client, acme_admin):
    token = _make_scim_token(client, acme_admin, name="auth-test")
    raw = token["token"]
    # Wrong token -> 401.
    bad = client.get("/api/v1/identity/scim/v2/Users", headers=_scim_headers("wrong-token"))
    assert bad.status_code == 401
    # No token -> 401.
    missing = client.get("/api/v1/identity/scim/v2/Users")
    assert missing.status_code == 401
    # Good token works.
    ok = client.get("/api/v1/identity/scim/v2/Users", headers=_scim_headers(raw))
    assert ok.status_code == 200, ok.text
    assert ok.json()["totalResults"] >= 2  # alice + tom

    # Expired token -> 401.
    past = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    expired = _make_scim_token(client, acme_admin, name="expired", expires_at=past)
    resp = client.get("/api/v1/identity/scim/v2/Users", headers=_scim_headers(expired["token"]))
    assert resp.status_code == 401

    # Revoked token -> 401.
    doomed = _make_scim_token(client, acme_admin, name="doomed")
    revoke = client.post(f"/api/v1/identity/scim-tokens/{doomed['id']}/revoke", headers=acme_admin["headers"])
    assert revoke.status_code == 200
    resp = client.get("/api/v1/identity/scim/v2/Users", headers=_scim_headers(doomed["token"]))
    assert resp.status_code == 401


def test_scim_users_crud(client, acme_admin, globex_admin, app_db, org_ids):
    token = _make_scim_token(client, acme_admin, name="users-crud")
    headers = _scim_headers(token["token"])
    email = "scim-new@acme.example.com"

    created = client.post(
        "/api/v1/identity/scim/v2/Users",
        json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": email,
            "name": {"formatted": "Scim Newbie", "givenName": "Scim", "familyName": "Newbie"},
            "emails": [{"value": email, "primary": True}],
            "active": True,
        },
        headers=headers,
    )
    assert created.status_code == 201, created.text
    user_id = created.json()["id"]
    assert created.json()["userName"] == email

    # Provisioning created a membership (invited) + an invitation row.
    with app_db.cursor() as cur:
        set_rls(app_db, org_ids["acme"])
        cur.execute("SELECT status FROM memberships WHERE user_id = %s", (user_id,))
        assert cur.fetchone()[0] == "invited"
        cur.execute("SELECT COUNT(*) FROM invitations WHERE email = %s AND status = 'pending'", (email,))
        assert cur.fetchone()[0] == 1

    # Duplicate in the same org is a 409.
    dup = client.post(
        "/api/v1/identity/scim/v2/Users",
        json={"userName": email, "name": {"formatted": "Scim Newbie"}},
        headers=headers,
    )
    assert dup.status_code == 409

    # Filter + pagination.
    filtered = client.get(
        "/api/v1/identity/scim/v2/Users",
        params={"filter": f'userName eq "{email}"'},
        headers=headers,
    )
    assert filtered.status_code == 200
    assert filtered.json()["totalResults"] == 1
    page = client.get("/api/v1/identity/scim/v2/Users", params={"startIndex": 1, "count": 1}, headers=headers)
    assert page.json()["itemsPerPage"] == 1

    # Replace (PUT) renames; PATCH deactivates.
    replaced = client.put(
        f"/api/v1/identity/scim/v2/Users/{user_id}",
        json={"name": {"formatted": "Scim Renamed"}, "active": True},
        headers=headers,
    )
    assert replaced.status_code == 200, replaced.text
    assert replaced.json()["name"]["formatted"] == "Scim Renamed"
    patched = client.patch(
        f"/api/v1/identity/scim/v2/Users/{user_id}",
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "active", "value": False}],
        },
        headers=headers,
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["active"] is False

    # DELETE deactivates (membership suspended), it does not erase the user.
    deleted = client.delete(f"/api/v1/identity/scim/v2/Users/{user_id}", headers=headers)
    assert deleted.status_code == 204
    with app_db.cursor() as cur:
        set_rls(app_db, org_ids["acme"])
        cur.execute("SELECT status FROM memberships WHERE user_id = %s", (user_id,))
        assert cur.fetchone()[0] == "suspended"

    # Cross-org isolation: a Globex SCIM token cannot see the Acme user.
    globex_token = client.post(
        "/api/v1/identity/scim-tokens",
        json={"name": "globex-scim"},
        headers=globex_admin["headers"],
    )
    assert globex_token.status_code == 201, globex_token.text
    gx = client.get(
        f"/api/v1/identity/scim/v2/Users/{user_id}",
        headers=_scim_headers(globex_token.json()["token"]),
    )
    assert gx.status_code == 404


def test_scim_groups_crud(client, acme_admin, acme_users):
    token = _make_scim_token(client, acme_admin, name="groups-crud")
    headers = _scim_headers(token["token"])
    tom_id = acme_users["tom"]["user_id"]

    created = client.post(
        "/api/v1/identity/scim/v2/Groups",
        json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": "SCIM Testers",
            "members": [{"value": tom_id}],
        },
        headers=headers,
    )
    assert created.status_code == 201, created.text
    group_id = created.json()["id"]
    assert len(created.json()["members"]) == 1

    fetched = client.get(f"/api/v1/identity/scim/v2/Groups/{group_id}", headers=headers)
    assert fetched.status_code == 200
    assert fetched.json()["displayName"] == "SCIM Testers"

    # PATCH: remove the member, then add them back.
    removed = client.patch(
        f"/api/v1/identity/scim/v2/Groups/{group_id}",
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "remove", "path": "members", "value": [{"value": tom_id}]}],
        },
        headers=headers,
    )
    assert removed.status_code == 200, removed.text
    assert removed.json()["members"] == []
    added = client.patch(
        f"/api/v1/identity/scim/v2/Groups/{group_id}",
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "add", "path": "members", "value": [{"value": tom_id}]}],
        },
        headers=headers,
    )
    assert len(added.json()["members"]) == 1

    # PUT replaces the member list entirely.
    replaced = client.put(
        f"/api/v1/identity/scim/v2/Groups/{group_id}",
        json={"displayName": "SCIM Testers v2", "members": []},
        headers=headers,
    )
    assert replaced.json()["members"] == []
    assert replaced.json()["displayName"] == "SCIM Testers v2"

    deleted = client.delete(f"/api/v1/identity/scim/v2/Groups/{group_id}", headers=headers)
    assert deleted.status_code == 204
    gone = client.get(f"/api/v1/identity/scim/v2/Groups/{group_id}", headers=headers)
    assert gone.status_code == 404


# --- Directory sync ----------------------------------------------------------


def test_directory_sync_scim_replay_and_honest_failures(client, acme_admin, acme_users, acme_roles, app_db, org_ids):
    tom_id = acme_users["tom"]["user_id"]
    tech_role_id = acme_roles["Service Desk Technician"]
    # A directory group mapped to the tech role, with Tom as a member.
    group = client.post(
        "/api/v1/identity/directory-groups",
        json={"external_id": "grp-sync-1", "name": "Sync Group", "role_id": tech_role_id},
        headers=acme_admin["headers"],
    )
    assert group.status_code == 201, group.text
    group_id = group.json()["id"]
    with app_db.cursor() as cur:
        set_rls(app_db, org_ids["acme"])
        cur.execute(
            "INSERT INTO directory_group_memberships (id, organization_id, group_id, user_id) "
            "VALUES (gen_random_uuid(), %s, %s, %s)",
            (org_ids["acme"], group_id, tom_id),
        )

    # Remove Tom's tech role first, so the sync visibly re-grants it.
    client.post(
        "/api/v1/roles/revoke",
        json={"user_id": tom_id, "role_id": tech_role_id},
        headers=acme_admin["headers"],
    )
    run = client.post(
        "/api/v1/identity/directory-sync",
        json={"source": "scim"},
        headers=acme_admin["headers"],
    )
    assert run.status_code == 201, run.text
    assert run.json()["status"] == "completed"
    assert run.json()["groups_synced"] >= 1
    with app_db.cursor() as cur:
        set_rls(app_db, org_ids["acme"])
        cur.execute(
            "SELECT COUNT(*) FROM user_roles WHERE user_id = %s AND role_id = %s",
            (tom_id, tech_role_id),
        )
        assert cur.fetchone()[0] == 1, "group sync must re-apply the mapped role"

    # Entra without credentials: the run is recorded as FAILED, honestly.
    provider = client.post(
        "/api/v1/identity/providers",
        json={"name": "Entra Unconfigured", "type": "oidc"},
        headers=acme_admin["headers"],
    ).json()
    failed = client.post(
        "/api/v1/identity/directory-sync",
        json={"provider_id": provider["id"], "source": "entra"},
        headers=acme_admin["headers"],
    )
    assert failed.status_code == 201, failed.text
    assert failed.json()["status"] == "failed"
    assert "not configured" in failed.json()["error"].lower()

    # LDAP without ldap3: same honest failure.
    failed_ldap = client.post(
        "/api/v1/identity/directory-sync",
        json={"provider_id": provider["id"], "source": "ldap"},
        headers=acme_admin["headers"],
    )
    assert failed_ldap.json()["status"] == "failed"
    assert "ldap3" in failed_ldap.json()["error"].lower()

    # Runs list + get.
    runs = client.get("/api/v1/identity/directory-sync/runs", headers=acme_admin["headers"])
    assert runs.status_code == 200
    assert len(runs.json()) >= 3
    one = client.get(f"/api/v1/identity/directory-sync/runs/{run.json()['id']}", headers=acme_admin["headers"])
    assert one.status_code == 200


# --- Certification -----------------------------------------------------------


def test_certification_approve_and_revoke(client, acme_admin, acme_users, acme_roles, app_db, org_ids):
    tom_id = acme_users["tom"]["user_id"]
    tech_role_id = acme_roles["Service Desk Technician"]
    # Ensure Tom holds the tech role (the sync test above may have revoked it).
    client.post(
        "/api/v1/roles/assign",
        json={"user_id": tom_id, "role_id": tech_role_id},
        headers=acme_admin["headers"],
    )
    cert = client.post(
        "/api/v1/identity/certifications",
        json={
            "name": "Q4 access review",
            "scope": {"roles": [tech_role_id]},
            "due_at": (datetime.now(UTC) + timedelta(days=7)).isoformat(),
        },
        headers=acme_admin["headers"],
    )
    assert cert.status_code == 201, cert.text
    cert_id = cert.json()["id"]
    items = client.get(f"/api/v1/identity/certifications/{cert_id}/items", headers=acme_admin["headers"]).json()
    tom_items = [i for i in items if i["user_id"] == tom_id]
    assert len(tom_items) == 1

    # Approve keeps the role.
    decided = client.post(
        f"/api/v1/identity/certifications/{cert_id}/items/{tom_items[0]['id']}/decide",
        json={"decision": "approved"},
        headers=acme_admin["headers"],
    )
    assert decided.status_code == 200, decided.text
    assert decided.json()["decision"] == "approved"

    # A second campaign: revoke removes the role row for real.
    cert2 = client.post(
        "/api/v1/identity/certifications",
        json={"name": "Q4 revoke check", "scope": {"roles": [tech_role_id]}},
        headers=acme_admin["headers"],
    ).json()
    items2 = client.get(f"/api/v1/identity/certifications/{cert2['id']}/items", headers=acme_admin["headers"]).json()
    tom_item2 = [i for i in items2 if i["user_id"] == tom_id][0]
    revoked = client.post(
        f"/api/v1/identity/certifications/{cert2['id']}/items/{tom_item2['id']}/decide",
        json={"decision": "revoked"},
        headers=acme_admin["headers"],
    )
    assert revoked.status_code == 200, revoked.text
    with app_db.cursor() as cur:
        set_rls(app_db, org_ids["acme"])
        cur.execute(
            "SELECT COUNT(*) FROM user_roles WHERE user_id = %s AND role_id = %s",
            (tom_id, tech_role_id),
        )
        assert cur.fetchone()[0] == 0, "revoke must remove the user_roles row"
    # Both campaigns complete once all their items are decided (Tom is
    # the only holder of the tech role in Acme).
    for cert_id in (cert_id, cert2["id"]):
        done = client.get(f"/api/v1/identity/certifications/{cert_id}", headers=acme_admin["headers"])
        assert done.json()["status"] == "completed", done.text
    # Re-grant the role so later tests have a working technician.
    client.post(
        "/api/v1/roles/assign",
        json={"user_id": tom_id, "role_id": tech_role_id},
        headers=acme_admin["headers"],
    )


# --- Temporary access grants + sweep ----------------------------------------


def test_temp_grant_expiry_sweep(client, acme_admin, acme_users, acme_roles, app_db, org_ids):
    from app.database import tenant_session
    from app.services import identity_service

    tom_id = acme_users["tom"]["user_id"]
    ops_role_id = acme_roles["IT Operations"]
    grant = client.post(
        "/api/v1/identity/temp-grants",
        json={
            "user_id": tom_id,
            "role_id": ops_role_id,
            "reason": "on-call cover",
            "expires_at": (datetime.now(UTC) + timedelta(hours=2)).isoformat(),
        },
        headers=acme_admin["headers"],
    )
    assert grant.status_code == 201, grant.text
    grant_id = grant.json()["id"]
    with app_db.cursor() as cur:
        set_rls(app_db, org_ids["acme"])
        cur.execute(
            "SELECT COUNT(*) FROM user_roles WHERE user_id = %s AND role_id = %s",
            (tom_id, ops_role_id),
        )
        assert cur.fetchone()[0] == 1, "creating a grant must assign the role"

    # Back-date the expiry, then run the sweep (service + celery task).
    with app_db.cursor() as cur:
        set_rls(app_db, org_ids["acme"])
        cur.execute(
            "UPDATE temporary_access_grants SET expires_at = now() - interval '1 hour' WHERE id = %s",
            (grant_id,),
        )
    with tenant_session(uuid.UUID(org_ids["acme"])) as session:
        assert identity_service.expire_temp_grants(session, uuid.UUID(org_ids["acme"])) == 1
    with app_db.cursor() as cur:
        set_rls(app_db, org_ids["acme"])
        cur.execute("SELECT status FROM temporary_access_grants WHERE id = %s", (grant_id,))
        assert cur.fetchone()[0] == "expired"
        cur.execute(
            "SELECT COUNT(*) FROM user_roles WHERE user_id = %s AND role_id = %s",
            (tom_id, ops_role_id),
        )
        assert cur.fetchone()[0] == 0, "sweep must remove the role row"

    # The Celery task entry point runs the same sweep (nothing left now).
    from app.tasks.identity_tasks import expire_temp_grants

    result = expire_temp_grants()
    assert result["expired"] == 0

    # Revoke path: a fresh grant can be revoked by hand.
    grant2 = client.post(
        "/api/v1/identity/temp-grants",
        json={
            "user_id": tom_id,
            "role_id": ops_role_id,
            "reason": "revoke check",
            "expires_at": (datetime.now(UTC) + timedelta(hours=2)).isoformat(),
        },
        headers=acme_admin["headers"],
    ).json()
    revoked = client.post(f"/api/v1/identity/temp-grants/{grant2['id']}/revoke", headers=acme_admin["headers"])
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"
    with app_db.cursor() as cur:
        set_rls(app_db, org_ids["acme"])
        cur.execute(
            "SELECT COUNT(*) FROM user_roles WHERE user_id = %s AND role_id = %s",
            (tom_id, ops_role_id),
        )
        assert cur.fetchone()[0] == 0


# --- Service accounts / API credentials --------------------------------------


def test_service_account_and_api_credential(client, acme_admin, acme_users, app_db, org_ids):
    tom_id = acme_users["tom"]["user_id"]
    # Service account: secret shown once, only the hash is stored.
    created = client.post(
        "/api/v1/identity/service-accounts",
        json={"name": "backup-bot", "description": "nightly backups", "scopes": ["assets:read"]},
        headers=acme_admin["headers"],
    )
    assert created.status_code == 201, created.text
    raw = created.json()["credential"]
    assert raw
    account_id = created.json()["id"]
    with app_db.cursor() as cur:
        set_rls(app_db, org_ids["acme"])
        cur.execute("SELECT credential_hash FROM service_accounts WHERE id = %s", (account_id,))
        stored = cur.fetchone()[0]
    assert stored == hashlib.sha256(raw.encode()).hexdigest()
    assert stored != raw
    # Listing never returns the secret.
    listed = client.get("/api/v1/identity/service-accounts", headers=acme_admin["headers"]).json()
    assert all(a["credential"] is None for a in listed)
    # Rotate invalidates the old hash and returns a new secret once.
    rotated = client.post(f"/api/v1/identity/service-accounts/{account_id}/rotate", headers=acme_admin["headers"])
    assert rotated.status_code == 200
    assert rotated.json()["credential"] != raw
    with app_db.cursor() as cur:
        set_rls(app_db, org_ids["acme"])
        cur.execute("SELECT credential_hash FROM service_accounts WHERE id = %s", (account_id,))
        assert cur.fetchone()[0] == hashlib.sha256(rotated.json()["credential"].encode()).hexdigest()
    revoked = client.post(f"/api/v1/identity/service-accounts/{account_id}/revoke", headers=acme_admin["headers"])
    assert revoked.json()["revoked_at"] is not None

    # API credential: create once, verify, revoke, verify fails.
    cred = client.post(
        "/api/v1/identity/api-credentials",
        json={"user_id": tom_id, "name": "tom-cli", "scopes": ["tickets:read"]},
        headers=acme_admin["headers"],
    )
    assert cred.status_code == 201, cred.text
    raw_cred = cred.json()["credential"]
    cred_id = cred.json()["id"]
    verified = client.post(
        "/api/v1/identity/api-credentials/verify",
        json={"credential": raw_cred},
        headers=acme_admin["headers"],
    )
    assert verified.status_code == 200, verified.text
    assert verified.json()["valid"] is True
    assert verified.json()["scopes"] == ["tickets:read"]
    bad = client.post(
        "/api/v1/identity/api-credentials/verify",
        json={"credential": "nope"},
        headers=acme_admin["headers"],
    )
    assert bad.status_code == 401
    client.post(f"/api/v1/identity/api-credentials/{cred_id}/revoke", headers=acme_admin["headers"])
    gone = client.post(
        "/api/v1/identity/api-credentials/verify",
        json={"credential": raw_cred},
        headers=acme_admin["headers"],
    )
    assert gone.status_code == 401


# --- Assets ------------------------------------------------------------------


def _make_asset(client, acme_admin, tag, **overrides):
    body = {"asset_tag": tag, "name": f"Asset {tag}", "type": "laptop"}
    body.update(overrides)
    resp = client.post("/api/v1/assets", json=body, headers=acme_admin["headers"])
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_asset_lifecycle_transitions(client, acme_admin, acme_users, globex_admin):
    tom_id = acme_users["tom"]["user_id"]
    asset = _make_asset(client, acme_admin, "AST-LIFE-001")
    assert asset["status"] == "in_stock"
    asset_id = asset["id"]

    # Illegal: check-in from in_stock.
    bad = client.post(f"/api/v1/assets/{asset_id}/check-in", headers=acme_admin["headers"])
    assert bad.status_code == 400

    # Assign -> assigned, with an assignment row + lifecycle event.
    assigned = client.post(f"/api/v1/assets/{asset_id}/assign", json={"user_id": tom_id}, headers=acme_admin["headers"])
    assert assigned.status_code == 200, assigned.text
    assert assigned.json()["status"] == "assigned"
    assert assigned.json()["assigned_to_id"] == tom_id
    # Illegal: assign again while assigned.
    again = client.post(f"/api/v1/assets/{asset_id}/assign", json={"user_id": tom_id}, headers=acme_admin["headers"])
    assert again.status_code == 400

    # Transfer keeps it assigned (new user = Alice).
    alice_id = client.get("/api/v1/auth/me", headers=acme_admin["headers"]).json()["user_id"]
    transferred = client.post(
        f"/api/v1/assets/{asset_id}/transfer", json={"user_id": alice_id}, headers=acme_admin["headers"]
    )
    assert transferred.status_code == 200, transferred.text
    assert transferred.json()["assigned_to_id"] == alice_id

    # Lost -> recovered -> in_stock.
    lost = client.post(f"/api/v1/assets/{asset_id}/mark-lost", headers=acme_admin["headers"])
    assert lost.json()["status"] == "lost"
    recovered = client.post(f"/api/v1/assets/{asset_id}/recover", headers=acme_admin["headers"])
    assert recovered.json()["status"] == "in_stock"

    # Check-out then check-in.
    out = client.post(f"/api/v1/assets/{asset_id}/check-out", json={"user_id": tom_id}, headers=acme_admin["headers"])
    assert out.json()["status"] == "assigned"
    back = client.post(f"/api/v1/assets/{asset_id}/check-in", headers=acme_admin["headers"])
    assert back.json()["status"] == "in_stock"

    # Retire then dispose; disposed is terminal.
    retired = client.post(f"/api/v1/assets/{asset_id}/retire", headers=acme_admin["headers"])
    assert retired.json()["status"] == "retired"
    disposed = client.post(f"/api/v1/assets/{asset_id}/dispose", headers=acme_admin["headers"])
    assert disposed.json()["status"] == "disposed"
    dead = client.post(f"/api/v1/assets/{asset_id}/assign", json={"user_id": tom_id}, headers=acme_admin["headers"])
    assert dead.status_code == 400

    # Lifecycle history records every transition.
    history = client.get(f"/api/v1/assets/{asset_id}/lifecycle", headers=acme_admin["headers"]).json()
    event_types = [e["event_type"] for e in history]
    for expected in (
        "procured",
        "assigned",
        "transferred",
        "lost",
        "recovered",
        "checked_out",
        "checked_in",
        "retired",
        "disposed",
    ):
        assert expected in event_types, event_types

    # Tenant isolation: Globex sees nothing.
    missing = client.get(f"/api/v1/assets/{asset_id}", headers=globex_admin["headers"])
    assert missing.status_code == 404
    listing = client.get("/api/v1/assets", headers=globex_admin["headers"]).json()
    assert all(a["asset_tag"] != "AST-LIFE-001" for a in listing)


def test_asset_depreciation(client, acme_admin):
    two_years_ago = (datetime.now(UTC) - timedelta(days=730)).isoformat()
    straight = _make_asset(
        client,
        acme_admin,
        "AST-DEPR-001",
        purchase_price_cents=120000,
        purchase_date=two_years_ago,
        depreciation_method="straight_line",
        depreciation_years=4,
    )
    # 2 of 4 years elapsed -> ~60,000 (allow a day of drift either way).
    assert 55000 <= straight["current_value_cents"] <= 65000, straight["current_value_cents"]
    one_year_ago = (datetime.now(UTC) - timedelta(days=365)).isoformat()
    declining = _make_asset(
        client,
        acme_admin,
        "AST-DEPR-002",
        purchase_price_cents=100000,
        purchase_date=one_year_ago,
        depreciation_method="declining",
        depreciation_years=5,
    )
    # Double-declining 2/5 per year for 1 year -> 100,000 * 0.6 = 60,000.
    assert 55000 <= declining["current_value_cents"] <= 65000, declining["current_value_cents"]
    none = _make_asset(
        client,
        acme_admin,
        "AST-DEPR-003",
        purchase_price_cents=42000,
        purchase_date=two_years_ago,
        depreciation_method="none",
    )
    assert none["current_value_cents"] == 42000


def test_vendors_pos_warranties(client, acme_admin):
    vendor = client.post(
        "/api/v1/assets/vendors",
        json={"name": "Lenovo Direct", "contact_email": "sales@lenovo.example"},
        headers=acme_admin["headers"],
    )
    assert vendor.status_code == 201, vendor.text
    vendor_id = vendor.json()["id"]
    po = client.post(
        "/api/v1/assets/purchase-orders",
        json={"vendor_id": vendor_id, "po_number": "PO-TEST-001", "total_cents": 150000},
        headers=acme_admin["headers"],
    )
    assert po.status_code == 201, po.text
    po_id = po.json()["id"]
    dup = client.post(
        "/api/v1/assets/purchase-orders",
        json={"vendor_id": vendor_id, "po_number": "PO-TEST-001"},
        headers=acme_admin["headers"],
    )
    assert dup.status_code == 400
    ordered = client.patch(
        f"/api/v1/assets/purchase-orders/{po_id}",
        json={"status": "ordered"},
        headers=acme_admin["headers"],
    )
    assert ordered.json()["status"] == "ordered"
    assert ordered.json()["ordered_at"] is not None
    asset = _make_asset(client, acme_admin, "AST-WARR-001", purchase_order_id=po_id)
    warranty = client.post(
        "/api/v1/assets/warranties",
        json={
            "asset_id": asset["id"],
            "vendor_id": vendor_id,
            "starts_at": datetime.now(UTC).isoformat(),
            "ends_at": (datetime.now(UTC) + timedelta(days=365)).isoformat(),
            "coverage": "3-year onsite",
        },
        headers=acme_admin["headers"],
    )
    assert warranty.status_code == 201, warranty.text
    assert warranty.json()["coverage"] == "3-year onsite"


def test_license_seat_limit_and_compliance(client, acme_admin, acme_users):
    tom_id = acme_users["tom"]["user_id"]
    alice_id = client.get("/api/v1/auth/me", headers=acme_admin["headers"]).json()["user_id"]
    lic = client.post(
        "/api/v1/assets/licenses",
        json={
            "name": "Office Suite",
            "vendor": "Contoso",
            "total_seats": 1,
            "expires_at": (datetime.now(UTC) + timedelta(days=10)).isoformat(),
        },
        headers=acme_admin["headers"],
    )
    assert lic.status_code == 201, lic.text
    lic_id = lic.json()["id"]
    assert lic.json()["seats_available"] == 1
    first = client.post(
        f"/api/v1/assets/licenses/{lic_id}/assign", json={"user_id": tom_id}, headers=acme_admin["headers"]
    )
    assert first.status_code == 201, first.text
    # Second seat is blocked...
    blocked = client.post(
        f"/api/v1/assets/licenses/{lic_id}/assign", json={"user_id": alice_id}, headers=acme_admin["headers"]
    )
    assert blocked.status_code == 400
    # ...unless an admin explicitly overrides, flipping status to exceeded.
    forced = client.post(
        f"/api/v1/assets/licenses/{lic_id}/assign",
        json={"user_id": alice_id, "override": True},
        headers=acme_admin["headers"],
    )
    assert forced.status_code == 201, forced.text
    after = client.get(f"/api/v1/assets/licenses/{lic_id}", headers=acme_admin["headers"]).json()
    assert after["status"] == "exceeded"
    assert after["seats_used"] == 2
    compliance = client.get("/api/v1/assets/licenses/compliance", headers=acme_admin["headers"]).json()
    assert any(e["license_id"] == lic_id for e in compliance["over_allocated"])
    assert any(e["license_id"] == lic_id for e in compliance["expiring_within_30_days"])
    # Revoking a seat brings it back under the limit and to active.
    assignments = client.get(f"/api/v1/assets/licenses/{lic_id}/assignments", headers=acme_admin["headers"]).json()
    client.post(f"/api/v1/assets/licenses/assignments/{assignments[0]['id']}/revoke", headers=acme_admin["headers"])
    back = client.get(f"/api/v1/assets/licenses/{lic_id}", headers=acme_admin["headers"]).json()
    assert back["status"] == "active"
    assert back["seats_used"] == 1


def test_raw_sql_rls_on_assets(client, acme_admin, app_db, org_ids):
    asset = _make_asset(client, acme_admin, "AST-RLS-001")
    with app_db.cursor() as cur:
        # Globex context cannot see the Acme asset.
        set_rls(app_db, org_ids["globex"])
        cur.execute("SELECT COUNT(*) FROM assets WHERE id = %s", (asset["id"],))
        assert cur.fetchone()[0] == 0
        # Cross-org insert is rejected by RLS (0 rows / error).
        try:
            cur.execute(
                "INSERT INTO assets (id, organization_id, asset_tag, name) "
                "VALUES (gen_random_uuid(), %s, 'AST-RLS-X', 'x')",
                (org_ids["acme"],),
            )
            inserted = cur.rowcount
        except Exception:
            app_db.rollback()
            inserted = 0
        assert inserted == 0
        # Acme context sees it.
        set_rls(app_db, org_ids["acme"])
        cur.execute("SELECT COUNT(*) FROM assets WHERE id = %s", (asset["id"],))
        assert cur.fetchone()[0] == 1
        # No context sees nothing.
        set_rls(app_db, None)
        cur.execute("SELECT COUNT(*) FROM assets")
        assert cur.fetchone()[0] == 0


def test_audit_rows_written(client, acme_admin, app_db, org_ids):
    asset = _make_asset(client, acme_admin, "AST-AUDIT-001")
    with app_db.cursor() as cur:
        set_rls(app_db, org_ids["acme"])
        cur.execute(
            "SELECT COUNT(*) FROM audit_logs WHERE organization_id = %s "
            "AND action = 'asset.created' AND resource_id = %s",
            (org_ids["acme"], asset["id"]),
        )
        assert cur.fetchone()[0] == 1
        # Lifecycle events are append-only: no UPDATE/DELETE policy means
        # an update affects zero rows.
        cur.execute("SELECT id FROM asset_lifecycle_events WHERE asset_id = %s LIMIT 1", (asset["id"],))
        event_id = cur.fetchone()[0]
        cur.execute("UPDATE asset_lifecycle_events SET notes = 'tampered' WHERE id = %s", (event_id,))
        assert cur.rowcount == 0


# --- Offboarding (uses a FRESH user, never the shared fixture technician) ---
# Offboarding suspends the target's membership: doing that to tom@acme
# (the session-scoped acme_tech fixture) would break every later test
# file that logs in as the technician. So this test provisions its own
# user in Acme, logs them in once (to create a session), and offboards
# them instead.


def _make_active_acme_user(org_id: str, email: str, full_name: str) -> str:
    """Create a fresh active Acme member directly in the DB (owner session).

    Same pattern as conftest.make_user_with_no_org, plus an active
    membership in the Acme fixture org.
    """
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker

    from app.models.platform import Membership, User
    from app.security import hash_password
    from tests.conftest import DEV_PASSWORD, TEST_OWNER_URL

    engine = create_engine(TEST_OWNER_URL)
    session = sessionmaker(bind=engine)()
    try:
        user_id = uuid.uuid4()
        session.execute(text("SELECT set_config('app.current_org_id', :v, false)"), {"v": str(org_id)})
        session.execute(text("SELECT set_config('app.current_user_id', :v, false)"), {"v": str(user_id)})
        user = User(
            id=user_id,
            email=email,
            full_name=full_name,
            password_hash=hash_password(DEV_PASSWORD),
            email_verified=True,
        )
        session.add(user)
        session.flush()
        session.add(Membership(organization_id=uuid.UUID(org_id), user_id=user_id, status="active"))
        session.commit()
        return str(user_id)
    finally:
        session.close()


def test_offboarding_end_to_end(client, acme_admin, acme_roles, app_db, org_ids):
    from tests.conftest import DEV_PASSWORD

    user_id = _make_active_acme_user(org_ids["acme"], "offboard-me@acme.example.com", "Offboard Test")
    ops_role_id = acme_roles["IT Operations"]
    # Log the user in once so a live session exists to be revoked.
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "offboard-me@acme.example.com", "password": DEV_PASSWORD},
    )
    assert login.status_code == 200, login.text
    asset = _make_asset(client, acme_admin, "AST-OFF-001")
    assigned = client.post(
        f"/api/v1/assets/{asset['id']}/assign", json={"user_id": user_id}, headers=acme_admin["headers"]
    )
    assert assigned.status_code == 200, assigned.text
    grant = client.post(
        "/api/v1/identity/temp-grants",
        json={
            "user_id": user_id,
            "role_id": ops_role_id,
            "reason": "offboard check",
            "expires_at": (datetime.now(UTC) + timedelta(hours=2)).isoformat(),
        },
        headers=acme_admin["headers"],
    )
    assert grant.status_code == 201, grant.text

    report = client.post("/api/v1/assets/offboard", json={"user_id": user_id}, headers=acme_admin["headers"])
    assert report.status_code == 200, report.text
    data = report.json()
    assert data["assets_recovered"] == ["AST-OFF-001"]
    assert len(data["tickets_created"]) == 1
    assert data["tickets_created"][0]["asset_tag"] == "AST-OFF-001"
    assert data["temp_grants_revoked"] == 1
    assert data["membership_status"] == "suspended"
    assert data["sessions_revoked"] >= 1, "the user's login session must be revoked"

    with app_db.cursor() as cur:
        set_rls(app_db, org_ids["acme"])
        cur.execute("SELECT status FROM memberships WHERE user_id = %s", (user_id,))
        assert cur.fetchone()[0] == "suspended"
        cur.execute("SELECT status FROM assets WHERE id = %s", (asset["id"],))
        assert cur.fetchone()[0] == "in_repair"
        cur.execute("SELECT COUNT(*) FROM asset_assignments WHERE asset_id = %s AND status = 'active'", (asset["id"],))
        assert cur.fetchone()[0] == 0
        cur.execute("SELECT COUNT(*) FROM temporary_access_grants WHERE user_id = %s AND status = 'active'", (user_id,))
        assert cur.fetchone()[0] == 0
        cur.execute("SELECT COUNT(*) FROM sessions WHERE user_id = %s AND revoked_at IS NULL", (user_id,))
        assert cur.fetchone()[0] == 0
        cur.execute(
            "SELECT COUNT(*) FROM audit_logs WHERE organization_id = %s "
            "AND action = 'asset.offboarding_completed' AND resource_id = %s",
            (org_ids["acme"], user_id),
        )
        assert cur.fetchone()[0] == 1

    # The recovery ticket exists and is assigned to the caller.
    tickets = client.get("/api/v1/tickets", headers=acme_admin["headers"]).json()
    recovery = [t for t in tickets if t["number"] == data["tickets_created"][0]["number"]]
    assert len(recovery) == 1
    assert recovery[0]["title"] == "Recover AST-OFF-001 from Offboard Test"
    assert recovery[0]["assignee_id"] is not None
