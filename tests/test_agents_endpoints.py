"""Phase 3 workstream A: agent API + user-facing endpoint management.

Uses the shared fixtures (client, acme_admin, acme_tech, globex_admin,
org_ids, app_db). Hostnames / release os+arch are unique per test:
the suite shares one test DB, so nothing here asserts exact counts
on shared tables.
"""

from __future__ import annotations

import uuid

from app.services import agent_service
from tests.conftest import set_rls

UTC_ISO = "2026-11-25T12:00:00+00:00"


def _uniq(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _make_enrollment_token(client, headers, expires_in_hours: int = 24) -> dict:
    resp = client.post(
        "/api/v1/endpoints/enrollment-tokens",
        json={"expires_in_hours": expires_in_hours},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _enroll(client, raw_token: str, hostname: str) -> dict:
    resp = client.post(
        "/api/v1/agents/enroll",
        json={
            "enrollment_token": raw_token,
            "device": {"hostname": hostname, "os": "macOS", "os_version": "26.6.2", "arch": "arm64"},
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _device_headers(device: dict) -> dict:
    return {"X-Device-Id": device["device_id"], "X-Device-Token": device["device_token"]}


def _enrolled_device(client, admin_headers: dict, hostname: str | None = None) -> dict:
    hostname = hostname or _uniq("host")
    token = _make_enrollment_token(client, admin_headers)
    return _enroll(client, token["token"], hostname)


def _inventory_payload() -> dict:
    return {
        "collected_at": UTC_ISO,
        "os": {"name": "macOS", "version": "26.6.2"},
        "hardware": {"cpu": "Apple M4", "memory_mb": 16384, "disks": []},
        "network": {"interfaces": ["en0"], "mac_addresses": ["aa:bb:cc:dd:ee:ff"]},
        "software": [{"name": "NULL Agent", "version": "1.0.0"}],
        "services": [{"name": "null-agent", "status": "running"}],
    }


# --- Enrollment --------------------------------------------------------------


def test_enrollment_happy_path(client, acme_admin, org_ids):
    token = _make_enrollment_token(client, acme_admin["headers"])
    assert token["token"]
    assert "token_hash" not in token
    device = _enroll(client, token["token"], _uniq("host"))
    assert device["device_id"]
    assert device["device_token"]
    assert device["enrolled_organization_id"] == org_ids["acme"]
    # The endpoint is visible to its org admin.
    got = client.get(f"/api/v1/endpoints/{device['device_id']}", headers=acme_admin["headers"])
    assert got.status_code == 200, got.text
    assert got.json()["status"] == "enrolled"


def test_enrollment_token_reuse_rejected(client, acme_admin):
    token = _make_enrollment_token(client, acme_admin["headers"])
    _enroll(client, token["token"], _uniq("host"))
    resp = client.post(
        "/api/v1/agents/enroll",
        json={
            "enrollment_token": token["token"],
            "device": {"hostname": _uniq("host"), "os": "macOS", "os_version": "26.6.2", "arch": "arm64"},
        },
    )
    assert resp.status_code == 401


def test_enrollment_expired_token_rejected(client, acme_admin, app_db, org_ids):
    token = _make_enrollment_token(client, acme_admin["headers"])
    with app_db.cursor() as cur:
        set_rls(app_db, org_ids["acme"])
        cur.execute(
            "UPDATE enrollment_tokens SET expires_at = now() - interval '1 hour' WHERE id = %s",
            (token["id"],),
        )
    resp = client.post(
        "/api/v1/agents/enroll",
        json={
            "enrollment_token": token["token"],
            "device": {"hostname": _uniq("host"), "os": "macOS", "os_version": "26.6.2", "arch": "arm64"},
        },
    )
    assert resp.status_code == 401


def test_enrollment_revoked_token_rejected(client, acme_admin):
    token = _make_enrollment_token(client, acme_admin["headers"])
    revoked = client.post(f"/api/v1/endpoints/enrollment-tokens/{token['id']}/revoke", headers=acme_admin["headers"])
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["revoked_at"] is not None
    resp = client.post(
        "/api/v1/agents/enroll",
        json={
            "enrollment_token": token["token"],
            "device": {"hostname": _uniq("host"), "os": "macOS", "os_version": "26.6.2", "arch": "arm64"},
        },
    )
    assert resp.status_code == 401


def test_enrollment_unknown_token_rejected(client):
    resp = client.post(
        "/api/v1/agents/enroll",
        json={
            "enrollment_token": "no-such-token",
            "device": {"hostname": _uniq("host"), "os": "macOS", "os_version": "26.6.2", "arch": "arm64"},
        },
    )
    assert resp.status_code == 401


def test_enrollment_token_list_never_returns_secrets(client, acme_admin):
    token = _make_enrollment_token(client, acme_admin["headers"])
    rows = client.get("/api/v1/endpoints/enrollment-tokens", headers=acme_admin["headers"])
    assert rows.status_code == 200, rows.text
    mine = [r for r in rows.json() if r["id"] == token["id"]]
    assert len(mine) == 1
    assert "token" not in mine[0] and "token_hash" not in mine[0]


# --- Device auth -------------------------------------------------------------


def test_device_auth_wrong_token_401(client, acme_admin):
    device = _enrolled_device(client, acme_admin["headers"])
    headers = {"X-Device-Id": device["device_id"], "X-Device-Token": "wrong-token"}
    resp = client.post(f"/api/v1/agents/{device['device_id']}/heartbeat", json={"status": "online"}, headers=headers)
    assert resp.status_code == 401


def test_device_auth_cross_device_token_401(client, acme_admin):
    device_a = _enrolled_device(client, acme_admin["headers"])
    device_b = _enrolled_device(client, acme_admin["headers"])
    # A's token presented with B's id in the header.
    headers = {"X-Device-Id": device_b["device_id"], "X-Device-Token": device_a["device_token"]}
    resp = client.post(f"/api/v1/agents/{device_b['device_id']}/heartbeat", json={"status": "online"}, headers=headers)
    assert resp.status_code == 401
    # A's token + A's headers, but B's id in the path.
    resp = client.post(
        f"/api/v1/agents/{device_b['device_id']}/heartbeat",
        json={"status": "online"},
        headers=_device_headers(device_a),
    )
    assert resp.status_code == 401


def test_device_auth_revoked_device_401(client, acme_admin):
    device = _enrolled_device(client, acme_admin["headers"])
    revoked = client.post(f"/api/v1/endpoints/{device['device_id']}/revoke", headers=acme_admin["headers"])
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["status"] == "unenrolled"
    resp = client.post(
        f"/api/v1/agents/{device['device_id']}/heartbeat",
        json={"status": "online"},
        headers=_device_headers(device),
    )
    assert resp.status_code == 401
    # Revoking twice is a 400.
    again = client.post(f"/api/v1/endpoints/{device['device_id']}/revoke", headers=acme_admin["headers"])
    assert again.status_code == 400


def test_user_bearer_token_on_agent_endpoint_401(client, acme_admin):
    device = _enrolled_device(client, acme_admin["headers"])
    resp = client.post(
        f"/api/v1/agents/{device['device_id']}/heartbeat",
        json={"status": "online"},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 401


def test_device_token_on_user_endpoint_401(client, acme_admin):
    device = _enrolled_device(client, acme_admin["headers"])
    resp = client.get("/api/v1/endpoints", headers=_device_headers(device))
    assert resp.status_code == 401


# --- Heartbeat + inventory ---------------------------------------------------


def test_heartbeat_updates_last_seen_and_returns_pending_jobs(client, acme_admin):
    device = _enrolled_device(client, acme_admin["headers"])
    job = client.post(
        f"/api/v1/endpoints/{device['device_id']}/jobs",
        json={"type": "inventory_refresh"},
        headers=acme_admin["headers"],
    )
    assert job.status_code == 201, job.text
    resp = client.post(
        f"/api/v1/agents/{device['device_id']}/heartbeat",
        json={"status": "online", "agent_version": "1.2.0", "ip_address": "10.0.0.5"},
        headers=_device_headers(device),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "ok"
    assert resp.json()["pending_jobs"] == 1
    assert resp.json()["server_time"]
    got = client.get(f"/api/v1/endpoints/{device['device_id']}", headers=acme_admin["headers"])
    assert got.status_code == 200, got.text
    body = got.json()
    assert body["last_seen_at"] is not None
    assert body["agent_version"] == "1.2.0"
    assert body["status"] == "online"


def test_inventory_happy_path_and_latest_on_detail(client, acme_admin):
    device = _enrolled_device(client, acme_admin["headers"])
    resp = client.post(
        f"/api/v1/agents/{device['device_id']}/inventory",
        json=_inventory_payload(),
        headers=_device_headers(device),
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["status"] == "ok"
    assert resp.json()["inventory_id"]
    got = client.get(f"/api/v1/endpoints/{device['device_id']}", headers=acme_admin["headers"])
    latest = got.json()["latest_inventory"]
    assert latest is not None
    assert latest["software"] == [{"name": "NULL Agent", "version": "1.0.0"}]


def test_inventory_unknown_section_422(client, acme_admin):
    device = _enrolled_device(client, acme_admin["headers"])
    payload = _inventory_payload()
    payload["bogus_section"] = {"surprise": True}
    resp = client.post(
        f"/api/v1/agents/{device['device_id']}/inventory",
        json=payload,
        headers=_device_headers(device),
    )
    assert resp.status_code == 422


def test_inventory_second_submission_appends(client, acme_admin):
    device = _enrolled_device(client, acme_admin["headers"])
    for _ in range(2):
        resp = client.post(
            f"/api/v1/agents/{device['device_id']}/inventory",
            json=_inventory_payload(),
            headers=_device_headers(device),
        )
        assert resp.status_code == 201, resp.text
    history = client.get(f"/api/v1/endpoints/{device['device_id']}/inventory", headers=acme_admin["headers"])
    assert history.status_code == 200, history.text
    rows = [r for r in history.json() if r["endpoint_id"] == device["device_id"]]
    assert len(rows) == 2


# --- Jobs: polling, at-most-once, results, expiry ---------------------------


def _issue_job(client, admin_headers, device_id, job_type="patch_scan", **kwargs):
    body = {"type": job_type}
    body.update(kwargs)
    resp = client.post(f"/api/v1/endpoints/{device_id}/jobs", json=body, headers=admin_headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_jobs_next_at_most_once_and_result_closes(client, acme_admin):
    device = _enrolled_device(client, acme_admin["headers"])
    job = _issue_job(client, acme_admin["headers"], device["device_id"], "patch_scan")
    first = client.get(f"/api/v1/agents/{device['device_id']}/jobs/next", headers=_device_headers(device))
    assert first.status_code == 200, first.text
    delivered = first.json()["job"]
    assert delivered is not None
    assert delivered["job_id"] == job["id"]
    assert delivered["type"] == "patch_scan"
    assert delivered["payload"] == {}
    second = client.get(f"/api/v1/agents/{device['device_id']}/jobs/next", headers=_device_headers(device))
    assert second.status_code == 200, second.text
    assert second.json()["job"] is None
    result = client.post(
        f"/api/v1/agents/{device['device_id']}/jobs/{job['id']}/result",
        json={
            "status": "succeeded",
            "output": {"missing_patches": [], "scanned_at": UTC_ISO},
            "started_at": UTC_ISO,
            "finished_at": UTC_ISO,
        },
        headers=_device_headers(device),
    )
    assert result.status_code == 200, result.text
    assert result.json()["status"] == "ok"
    jobs = client.get(f"/api/v1/endpoints/{device['device_id']}/jobs", headers=acme_admin["headers"])
    mine = [j for j in jobs.json() if j["id"] == job["id"]]
    assert len(mine) == 1 and mine[0]["status"] == "succeeded"
    # Reporting a result on a closed job is a 400.
    again = client.post(
        f"/api/v1/agents/{device['device_id']}/jobs/{job['id']}/result",
        json={"status": "succeeded", "started_at": UTC_ISO, "finished_at": UTC_ISO},
        headers=_device_headers(device),
    )
    assert again.status_code == 400


def test_expired_job_never_delivered(client, acme_admin, app_db, org_ids):
    device = _enrolled_device(client, acme_admin["headers"])
    job = _issue_job(client, acme_admin["headers"], device["device_id"], "inventory_refresh")
    with app_db.cursor() as cur:
        set_rls(app_db, org_ids["acme"])
        cur.execute(
            "UPDATE agent_jobs SET expires_at = now() - interval '1 minute' WHERE id = %s",
            (job["id"],),
        )
    polled = client.get(f"/api/v1/agents/{device['device_id']}/jobs/next", headers=_device_headers(device))
    assert polled.status_code == 200, polled.text
    assert polled.json()["job"] is None
    jobs = client.get(f"/api/v1/endpoints/{device['device_id']}/jobs", headers=acme_admin["headers"])
    mine = [j for j in jobs.json() if j["id"] == job["id"]]
    assert len(mine) == 1 and mine[0]["status"] == "expired"


def test_job_result_from_different_device_404(client, acme_admin):
    device_a = _enrolled_device(client, acme_admin["headers"])
    device_b = _enrolled_device(client, acme_admin["headers"])
    job = _issue_job(client, acme_admin["headers"], device_a["device_id"], "vuln_scan")
    first = client.get(f"/api/v1/agents/{device_a['device_id']}/jobs/next", headers=_device_headers(device_a))
    assert first.json()["job"] is not None
    # Device B reports on A's job, using B's own id in the path.
    resp = client.post(
        f"/api/v1/agents/{device_b['device_id']}/jobs/{job['id']}/result",
        json={"status": "succeeded", "started_at": UTC_ISO, "finished_at": UTC_ISO},
        headers=_device_headers(device_b),
    )
    assert resp.status_code == 404


# --- Job issuance: permissions + allowlist -----------------------------------


def test_job_issue_permission_checks(client, acme_admin, acme_tech):
    device = _enrolled_device(client, acme_admin["headers"])
    # The Service Desk Technician holds no endpoints:deploy.
    denied = client.post(
        f"/api/v1/endpoints/{device['device_id']}/jobs",
        json={"type": "patch_deploy", "payload": {"patch_id": "KB123"}},
        headers=acme_tech["headers"],
    )
    assert denied.status_code == 403
    # Unknown type is a 400 (as an admin who could otherwise issue).
    unknown = client.post(
        f"/api/v1/endpoints/{device['device_id']}/jobs",
        json={"type": "rm -rf /"},
        headers=acme_admin["headers"],
    )
    assert unknown.status_code == 400
    # A deploy type as admin works.
    ok = client.post(
        f"/api/v1/endpoints/{device['device_id']}/jobs",
        json={"type": "restart"},
        headers=acme_admin["headers"],
    )
    assert ok.status_code == 201, ok.text


def test_endpoint_rename(client, acme_admin):
    device = _enrolled_device(client, acme_admin["headers"])
    patched = client.patch(
        f"/api/v1/endpoints/{device['device_id']}",
        json={"display_name": "Miah's Mac"},
        headers=acme_admin["headers"],
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["display_name"] == "Miah's Mac"


def test_endpoint_list_filters(client, acme_admin):
    hostname = _uniq("filterhost")
    device = _enrolled_device(client, acme_admin["headers"], hostname=hostname)
    listed = client.get("/api/v1/endpoints?search=" + hostname, headers=acme_admin["headers"])
    assert listed.status_code == 200, listed.text
    assert any(e["id"] == device["device_id"] for e in listed.json())
    by_status = client.get("/api/v1/endpoints?status=enrolled", headers=acme_admin["headers"])
    assert by_status.status_code == 200, by_status.text
    assert all(e["status"] == "enrolled" for e in by_status.json())
    bad = client.get("/api/v1/endpoints?status=nope", headers=acme_admin["headers"])
    assert bad.status_code == 400


# --- Tenant isolation ----------------------------------------------------------


def test_tenant_isolation_endpoints(client, acme_admin, globex_admin):
    globex_device = _enrolled_device(client, globex_admin["headers"])
    acme_list = client.get("/api/v1/endpoints", headers=acme_admin["headers"])
    assert acme_list.status_code == 200, acme_list.text
    assert all(e["id"] != globex_device["device_id"] for e in acme_list.json())
    acme_get = client.get(f"/api/v1/endpoints/{globex_device['device_id']}", headers=acme_admin["headers"])
    assert acme_get.status_code == 404
    globex_get = client.get(f"/api/v1/endpoints/{globex_device['device_id']}", headers=globex_admin["headers"])
    assert globex_get.status_code == 200, globex_get.text


# --- Agent releases + update check --------------------------------------------


def test_releases_crud_and_update_check(client, acme_admin):
    os_name = _uniq("testos")
    arch = _uniq("testarch")
    created = client.post(
        "/api/v1/endpoints/releases",
        json={
            "version": "1.0.0",
            "os": os_name,
            "arch": arch,
            "sha256": "a" * 64,
            "signature": "sig-1",
            "release_notes": "First test release",
        },
        headers=acme_admin["headers"],
    )
    assert created.status_code == 201, created.text
    release = created.json()
    duplicate = client.post(
        "/api/v1/endpoints/releases",
        json={"version": "1.0.0", "os": os_name, "arch": arch, "sha256": "b" * 64},
        headers=acme_admin["headers"],
    )
    assert duplicate.status_code == 409
    device = _enrolled_device(client, acme_admin["headers"])
    check = client.get(
        f"/api/v1/agents/updates/check?current_version=0.9.0&os={os_name}&arch={arch}",
        headers=_device_headers(device),
    )
    assert check.status_code == 200, check.text
    body = check.json()
    assert body["update_available"] is True
    assert body["version"] == "1.0.0"
    assert body["download_url"] is None  # no artifact storage configured
    assert body["sha256"] == "a" * 64
    assert body["signature"] == "sig-1"
    current = client.get(
        f"/api/v1/agents/updates/check?current_version=1.0.0&os={os_name}&arch={arch}",
        headers=_device_headers(device),
    )
    assert current.json()["update_available"] is False
    # Deactivating the release hides the update; deleting removes it.
    patched = client.patch(
        f"/api/v1/endpoints/releases/{release['id']}",
        json={"is_active": False},
        headers=acme_admin["headers"],
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["is_active"] is False
    hidden = client.get(
        f"/api/v1/agents/updates/check?current_version=0.9.0&os={os_name}&arch={arch}",
        headers=_device_headers(device),
    )
    assert hidden.json()["update_available"] is False
    deleted = client.delete(f"/api/v1/endpoints/releases/{release['id']}", headers=acme_admin["headers"])
    assert deleted.status_code == 204


def test_update_check_requires_device_auth(client, acme_admin):
    resp = client.get("/api/v1/agents/updates/check?current_version=0.1.0&os=macOS&arch=arm64")
    assert resp.status_code == 401


# --- Job-result handler registry (stub) ---------------------------------------


def _stub_patch_scan_handler(session, org_id, job):
    """Test stub: records the dispatch by marking the job output.

    The marker is read back through the API, so the assertion does not
    depend on which module identity pytest imported this file under.
    """
    job.output = f"stub-handled:{job.id}"
    session.flush()


def test_job_result_handler_registry_dispatches_stub(client, acme_admin, monkeypatch):
    monkeypatch.setitem(
        agent_service.JOB_RESULT_HANDLERS,
        "patch_scan",
        "tests.test_agents_endpoints:_stub_patch_scan_handler",
    )
    device = _enrolled_device(client, acme_admin["headers"])
    job = _issue_job(client, acme_admin["headers"], device["device_id"], "patch_scan")
    first = client.get(f"/api/v1/agents/{device['device_id']}/jobs/next", headers=_device_headers(device))
    assert first.json()["job"] is not None
    result = client.post(
        f"/api/v1/agents/{device['device_id']}/jobs/{job['id']}/result",
        json={
            "status": "succeeded",
            "output": {"missing_patches": [], "scanned_at": UTC_ISO},
            "started_at": UTC_ISO,
            "finished_at": UTC_ISO,
        },
        headers=_device_headers(device),
    )
    assert result.status_code == 200, result.text
    jobs = client.get(f"/api/v1/endpoints/{device['device_id']}/jobs", headers=acme_admin["headers"])
    mine = [j for j in jobs.json() if j["id"] == job["id"]]
    assert len(mine) == 1
    assert mine[0]["output"] == f"stub-handled:{job['id']}"


def test_job_result_without_handler_still_records(client, acme_admin):
    """inventory_refresh has no registered handler: the result is still
    recorded (200) and the job closes — the missing handler never fails
    the call."""
    device = _enrolled_device(client, acme_admin["headers"])
    job = _issue_job(client, acme_admin["headers"], device["device_id"], "inventory_refresh")
    first = client.get(f"/api/v1/agents/{device['device_id']}/jobs/next", headers=_device_headers(device))
    assert first.json()["job"] is not None
    result = client.post(
        f"/api/v1/agents/{device['device_id']}/jobs/{job['id']}/result",
        json={"status": "succeeded", "started_at": UTC_ISO, "finished_at": UTC_ISO},
        headers=_device_headers(device),
    )
    assert result.status_code == 200, result.text
    jobs = client.get(f"/api/v1/endpoints/{device['device_id']}/jobs", headers=acme_admin["headers"])
    mine = [j for j in jobs.json() if j["id"] == job["id"]]
    assert len(mine) == 1 and mine[0]["status"] == "succeeded"
