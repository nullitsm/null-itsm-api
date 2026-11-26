"""Patching tests — Phase 3 (migration 0010).

Covers: scan trigger (job + pending scan), apply_patch_scan_result
(patches + findings, idempotent re-apply, dedupe across scans), the
install/failed deploy-result flows and deployment roll-up, deployment
lifecycle guards, the verify flow, tenant isolation, and malformed job
output tolerance.

Endpoints do not exist yet as an API (workstream A), so test endpoints
are inserted directly into the database via the ``app_db`` fixture.
Service functions are called directly through ``tenant_session``.
"""

from __future__ import annotations

import json
import uuid

from sqlalchemy import select

from app.database import tenant_session
from app.main import app
from app.models.endpoints import AgentJob
from app.models.patching import Patch, PatchFinding, PatchScan
from app.routers.patching import router as patching_router
from app.services.patching_service import (
    apply_patch_deploy_result,
    apply_patch_scan_result,
)
from tests.conftest import set_rls

# The coordinator registers this router in app/main.py; until then, mount
# it here so this file runs standalone. Guarded so a coordinator
# registration never double-mounts it.
if not any(getattr(r, "path", "").startswith("/api/v1/patching") for r in app.routes):
    app.include_router(patching_router)

SCAN_OUTPUT = {
    "missing_patches": [
        {
            "title": "Security Update for Windows (KB5034123)",
            "vendor": "Microsoft",
            "kb_id": "KB5034123",
            "severity": "critical",
            "category": "Security",
            "cve_ids": ["CVE-2024-1234"],
            "os_family": "Windows",
        },
        {
            "title": "Cumulative Update for .NET (KB5034080)",
            "vendor": "Microsoft",
            "kb_id": "KB5034080",
            "severity": "high",
            "category": "Security",
            "cve_ids": [],
            "os_family": "Windows",
        },
    ],
    "scanned_at": "2026-11-25T20:00:00Z",
}


def _make_endpoint(app_db, org_id: str, hostname: str = "patch-host-1") -> str:
    endpoint_id = str(uuid.uuid4())
    set_rls(app_db, org_id)
    with app_db.cursor() as cur:
        cur.execute(
            "INSERT INTO endpoints (id, organization_id, hostname, status) VALUES (%s, %s, %s, 'enrolled')",
            (endpoint_id, org_id, hostname),
        )
    return endpoint_id


def _make_job(
    session,
    org_id: str,
    endpoint_id: str,
    job_type: str,
    output: str | None = None,
) -> AgentJob:
    job = AgentJob(
        id=uuid.uuid4(),
        organization_id=uuid.UUID(org_id),
        endpoint_id=uuid.UUID(endpoint_id),
        type=job_type,
        payload={},
        status="pending",
        output=output,
    )
    session.add(job)
    session.flush()
    return job


def _apply_scan(org_id: str, endpoint_id: str, output: dict) -> dict:
    with tenant_session(uuid.UUID(org_id)) as session:
        job = _make_job(session, org_id, endpoint_id, "patch_scan", json.dumps(output))
        result = apply_patch_scan_result(session, uuid.UUID(org_id), job)
        session.commit()
        return result


def _open_findings(org_id: str) -> list[PatchFinding]:
    with tenant_session(uuid.UUID(org_id)) as session:
        rows = (
            session.execute(
                select(PatchFinding).where(
                    PatchFinding.organization_id == uuid.UUID(org_id),
                    PatchFinding.status == "missing",
                )
            )
            .scalars()
            .all()
        )
        session.expunge_all()
        return rows


def _deployment_via_api(client, headers, endpoint_id: str, patch_id: str, name: str = "Patch Tuesday"):
    resp = client.post(
        "/api/v1/patching/deployments",
        json={"name": name, "items": [{"endpoint_id": endpoint_id, "patch_id": patch_id}]},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


# --- Scan trigger -----------------------------------------------------------


def test_scan_trigger_creates_job_and_pending_scan(client, acme_admin, acme_tech, org_ids, app_db):
    endpoint_id = _make_endpoint(app_db, org_ids["acme"], "scan-trigger-host")
    resp = client.post("/api/v1/patching/scans", json={"endpoint_id": endpoint_id}, headers=acme_admin["headers"])
    assert resp.status_code == 201, resp.text
    scan = resp.json()
    assert scan["status"] == "pending"
    assert scan["endpoint_id"] == endpoint_id
    assert scan["job_id"]
    with tenant_session(uuid.UUID(org_ids["acme"])) as session:
        job = session.get(AgentJob, uuid.UUID(scan["job_id"]))
        assert job is not None
        assert job.type == "patch_scan"
        assert job.endpoint_id == uuid.UUID(endpoint_id)


def test_scan_trigger_unknown_endpoint_404(client, acme_admin):
    resp = client.post(
        "/api/v1/patching/scans",
        json={"endpoint_id": str(uuid.uuid4())},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 404


def test_scan_trigger_without_permission_403(client, acme_tech, org_ids, app_db):
    endpoint_id = _make_endpoint(app_db, org_ids["acme"], "scan-403-host")
    resp = client.post("/api/v1/patching/scans", json={"endpoint_id": endpoint_id}, headers=acme_tech["headers"])
    assert resp.status_code == 403


# --- Apply scan: patches + findings, idempotency, dedupe --------------------


def test_apply_scan_creates_patches_and_findings(client, acme_admin, org_ids, app_db):
    endpoint_id = _make_endpoint(app_db, org_ids["acme"], "apply-scan-host")
    result = _apply_scan(org_ids["acme"], endpoint_id, SCAN_OUTPUT)
    assert result["status"] == "applied"
    assert result["missing_count"] == 2
    assert result["new_findings"] == 2
    assert result["updated_findings"] == 0

    patches = client.get("/api/v1/patching/patches", headers=acme_admin["headers"]).json()
    kb_ids = {p["kb_id"] for p in patches}
    assert "KB5034123" in kb_ids and "KB5034080" in kb_ids
    critical = client.get(
        "/api/v1/patching/patches", params={"severity": "critical"}, headers=acme_admin["headers"]
    ).json()
    assert all(p["severity"] == "critical" for p in critical)
    assert any(p["kb_id"] == "KB5034123" for p in critical)
    searched = client.get(
        "/api/v1/patching/patches", params={"search": "KB5034080"}, headers=acme_admin["headers"]
    ).json()
    assert len(searched) == 1 and searched[0]["kb_id"] == "KB5034080"

    findings = client.get(
        "/api/v1/patching/findings",
        params={"endpoint_id": endpoint_id},
        headers=acme_admin["headers"],
    ).json()
    assert len(findings) == 2
    assert all(f["status"] == "missing" for f in findings)
    severe = client.get(
        "/api/v1/patching/findings",
        params={"endpoint_id": endpoint_id, "severity": "critical"},
        headers=acme_admin["headers"],
    ).json()
    assert len(severe) == 1


def test_apply_scan_idempotent_same_job_and_dedupe_across_scans(org_ids, app_db):
    endpoint_id = _make_endpoint(app_db, org_ids["acme"], "dedupe-host")
    with tenant_session(uuid.UUID(org_ids["acme"])) as session:
        job = _make_job(session, org_ids["acme"], endpoint_id, "patch_scan", json.dumps(SCAN_OUTPUT))
        first = apply_patch_scan_result(session, uuid.UUID(org_ids["acme"]), job)
        assert first["status"] == "applied"
        assert first["new_findings"] == 2
        # Re-applying the SAME job must not duplicate anything.
        second = apply_patch_scan_result(session, uuid.UUID(org_ids["acme"]), job)
        assert second["status"] == "already_applied"
        session.commit()

    assert len(_open_findings(org_ids["acme"])) >= 2

    # A second scan (new job) reporting the same missing patch must still
    # leave exactly one open finding per (endpoint, patch) for this host.
    with tenant_session(uuid.UUID(org_ids["acme"])) as session:
        job2 = _make_job(session, org_ids["acme"], endpoint_id, "patch_scan", json.dumps(SCAN_OUTPUT))
        result = apply_patch_scan_result(session, uuid.UUID(org_ids["acme"]), job2)
        assert result["status"] == "applied"
        assert result["new_findings"] == 0
        assert result["updated_findings"] == 2
        session.commit()

    with tenant_session(uuid.UUID(org_ids["acme"])) as session:
        rows = (
            session.execute(
                select(PatchFinding).where(
                    PatchFinding.organization_id == uuid.UUID(org_ids["acme"]),
                    PatchFinding.endpoint_id == uuid.UUID(endpoint_id),
                    PatchFinding.status == "missing",
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 2


def test_scan_detail_includes_findings(client, acme_admin, org_ids, app_db):
    endpoint_id = _make_endpoint(app_db, org_ids["acme"], "scan-detail-host")
    result = _apply_scan(org_ids["acme"], endpoint_id, SCAN_OUTPUT)
    resp = client.get(f"/api/v1/patching/scans/{result['scan_id']}", headers=acme_admin["headers"])
    assert resp.status_code == 200, resp.text
    detail = resp.json()
    assert detail["status"] == "completed"
    assert detail["missing_count"] == 2
    assert len(detail["findings"]) == 2


# --- Deploy result: install flow --------------------------------------------


def _setup_missing_patch(client, acme_admin, org_ids, app_db, hostname: str):
    endpoint_id = _make_endpoint(app_db, org_ids["acme"], hostname)
    _apply_scan(org_ids["acme"], endpoint_id, SCAN_OUTPUT)
    patches = client.get("/api/v1/patching/patches", headers=acme_admin["headers"]).json()
    patch = next(p for p in patches if p["kb_id"] == "KB5034123")
    return endpoint_id, patch["id"]


def _apply_deploy_result(org_id: str, job_id: str, output: dict) -> dict:
    with tenant_session(uuid.UUID(org_id)) as session:
        job = session.get(AgentJob, uuid.UUID(job_id))
        assert job is not None
        job.output = json.dumps(output)
        result = apply_patch_deploy_result(session, uuid.UUID(org_id), job)
        session.commit()
        return result


def test_install_flow_completes_deployment(client, acme_admin, org_ids, app_db):
    endpoint_id, patch_id = _setup_missing_patch(client, acme_admin, org_ids, app_db, "install-host")
    dep = _deployment_via_api(client, acme_admin["headers"], endpoint_id, patch_id)
    dep_id = dep["id"]
    assert (
        client.post(f"/api/v1/patching/deployments/{dep_id}/approve", headers=acme_admin["headers"]).status_code == 200
    )
    executed = client.post(f"/api/v1/patching/deployments/{dep_id}/execute", headers=acme_admin["headers"]).json()
    assert executed["status"] == "deploying"
    assert executed["items"][0]["status"] == "queued"
    job_id = executed["items"][0]["job_id"]
    assert job_id

    result = _apply_deploy_result(
        org_ids["acme"], job_id, {"patch_id": patch_id, "status": "installed", "detail": "ok"}
    )
    assert result["status"] == "applied"
    assert result["item_status"] == "succeeded"
    assert result["deployment_status"] == "completed"

    findings = client.get(
        "/api/v1/patching/findings",
        params={"endpoint_id": endpoint_id, "status": "installed"},
        headers=acme_admin["headers"],
    ).json()
    assert any(f["patch_id"] == patch_id for f in findings)
    detail = client.get(f"/api/v1/patching/deployments/{dep_id}", headers=acme_admin["headers"]).json()
    assert detail["status"] == "completed"
    assert detail["items"][0]["status"] == "succeeded"

    # Re-applying the same deploy job is a no-op.
    again = _apply_deploy_result(org_ids["acme"], job_id, {"patch_id": patch_id, "status": "installed"})
    assert again["status"] == "already_applied"


def test_failed_item_fails_deployment(client, acme_admin, org_ids, app_db):
    ep1 = _make_endpoint(app_db, org_ids["acme"], "fail-host-1")
    ep2 = _make_endpoint(app_db, org_ids["acme"], "fail-host-2")
    _apply_scan(org_ids["acme"], ep1, SCAN_OUTPUT)
    _apply_scan(org_ids["acme"], ep2, SCAN_OUTPUT)
    patches = client.get("/api/v1/patching/patches", headers=acme_admin["headers"]).json()
    patch_id = next(p for p in patches if p["kb_id"] == "KB5034123")["id"]
    resp = client.post(
        "/api/v1/patching/deployments",
        json={
            "name": "Fail case",
            "items": [
                {"endpoint_id": ep1, "patch_id": patch_id},
                {"endpoint_id": ep2, "patch_id": patch_id},
            ],
        },
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 201, resp.text
    dep_id = resp.json()["id"]
    client.post(f"/api/v1/patching/deployments/{dep_id}/approve", headers=acme_admin["headers"])
    executed = client.post(f"/api/v1/patching/deployments/{dep_id}/execute", headers=acme_admin["headers"]).json()
    jobs = {item["endpoint_id"]: item["job_id"] for item in executed["items"]}
    _apply_deploy_result(org_ids["acme"], jobs[ep1], {"patch_id": patch_id, "status": "installed"})
    result = _apply_deploy_result(
        org_ids["acme"], jobs[ep2], {"patch_id": patch_id, "status": "failed", "detail": "exit 1"}
    )
    assert result["deployment_status"] == "failed"
    detail = client.get(f"/api/v1/patching/deployments/{dep_id}", headers=acme_admin["headers"]).json()
    assert detail["status"] == "failed"
    assert {i["status"] for i in detail["items"]} == {"succeeded", "failed"}


# --- Deployment lifecycle guards --------------------------------------------


def test_deployment_lifecycle_guards(client, acme_admin, acme_tech, org_ids, app_db):
    endpoint_id, patch_id = _setup_missing_patch(client, acme_admin, org_ids, app_db, "guard-host")
    dep = _deployment_via_api(client, acme_admin["headers"], endpoint_id, patch_id)
    dep_id = dep["id"]

    # Execute without approve -> 400.
    resp = client.post(f"/api/v1/patching/deployments/{dep_id}/execute", headers=acme_admin["headers"])
    assert resp.status_code == 400

    # Approve without patching:approve (Service Desk Technician) -> 403.
    resp = client.post(f"/api/v1/patching/deployments/{dep_id}/approve", headers=acme_tech["headers"])
    assert resp.status_code == 403

    # Approve, execute, then cancel from deploying -> 400.
    assert (
        client.post(f"/api/v1/patching/deployments/{dep_id}/approve", headers=acme_admin["headers"]).status_code == 200
    )
    assert (
        client.post(f"/api/v1/patching/deployments/{dep_id}/execute", headers=acme_admin["headers"]).status_code == 200
    )
    resp = client.post(f"/api/v1/patching/deployments/{dep_id}/cancel", headers=acme_admin["headers"])
    assert resp.status_code == 400

    # Cancel from draft works.
    dep2 = _deployment_via_api(client, acme_admin["headers"], endpoint_id, patch_id, name="Cancel me")
    resp = client.post(f"/api/v1/patching/deployments/{dep2['id']}/cancel", headers=acme_admin["headers"])
    assert resp.status_code == 200
    assert resp.json()["status"] == "cancelled"

    # Deployment create validates in-org references -> 404.
    globex_endpoint = _make_endpoint(app_db, org_ids["globex"], "guard-globex-host")
    resp = client.post(
        "/api/v1/patching/deployments",
        json={
            "name": "Cross org",
            "items": [{"endpoint_id": globex_endpoint, "patch_id": patch_id}],
        },
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 404


# --- Verify flow ------------------------------------------------------------


def _verify_and_apply_scan(client, acme_admin, org_ids, dep_id: str, missing: list) -> dict:
    resp = client.post(f"/api/v1/patching/deployments/{dep_id}/verify", headers=acme_admin["headers"])
    assert resp.status_code == 200, resp.text
    dep = resp.json()
    assert dep["verification_status"] == "pending"
    scan_id = dep["verification_scan_id"]
    assert scan_id
    scan = client.get(f"/api/v1/patching/scans/{scan_id}", headers=acme_admin["headers"]).json()
    job_id = scan["job_id"]
    with tenant_session(uuid.UUID(org_ids["acme"])) as session:
        job = session.get(AgentJob, uuid.UUID(job_id))
        job.output = json.dumps({"missing_patches": missing})
        apply_patch_scan_result(session, uuid.UUID(org_ids["acme"]), job)
        session.commit()
    return client.get(f"/api/v1/patching/deployments/{dep_id}", headers=acme_admin["headers"]).json()


def test_verify_flow_failed_then_passed(client, acme_admin, org_ids, app_db):
    endpoint_id, patch_id = _setup_missing_patch(client, acme_admin, org_ids, app_db, "verify-host")
    dep = _deployment_via_api(client, acme_admin["headers"], endpoint_id, patch_id)
    dep_id = dep["id"]
    client.post(f"/api/v1/patching/deployments/{dep_id}/approve", headers=acme_admin["headers"])
    executed = client.post(f"/api/v1/patching/deployments/{dep_id}/execute", headers=acme_admin["headers"]).json()
    _apply_deploy_result(
        org_ids["acme"],
        executed["items"][0]["job_id"],
        {"patch_id": patch_id, "status": "installed"},
    )
    detail = client.get(f"/api/v1/patching/deployments/{dep_id}", headers=acme_admin["headers"]).json()
    assert detail["status"] == "completed"

    # Verify while the patch is still reported missing -> failed.
    missing_entry = [p for p in SCAN_OUTPUT["missing_patches"] if p["kb_id"] == "KB5034123"][0]
    after_fail = _verify_and_apply_scan(client, acme_admin, org_ids, dep_id, [missing_entry])
    assert after_fail["verification_status"] == "failed"
    assert after_fail["status"] == "completed"  # deployment status itself unchanged

    # A later verification scan reporting nothing missing -> passed.
    after_pass = _verify_and_apply_scan(client, acme_admin, org_ids, dep_id, [])
    assert after_pass["verification_status"] == "passed"


def test_verify_from_draft_400(client, acme_admin, org_ids, app_db):
    endpoint_id, patch_id = _setup_missing_patch(client, acme_admin, org_ids, app_db, "verify-400-host")
    dep = _deployment_via_api(client, acme_admin["headers"], endpoint_id, patch_id)
    resp = client.post(f"/api/v1/patching/deployments/{dep['id']}/verify", headers=acme_admin["headers"])
    assert resp.status_code == 400


# --- Tenant isolation -------------------------------------------------------


def test_tenant_isolation(client, acme_admin, globex_admin, org_ids, app_db):
    endpoint_id, patch_id = _setup_missing_patch(client, acme_admin, org_ids, app_db, "iso-host")
    dep = _deployment_via_api(client, acme_admin["headers"], endpoint_id, patch_id)
    scan = client.post(
        "/api/v1/patching/scans", json={"endpoint_id": endpoint_id}, headers=acme_admin["headers"]
    ).json()

    globex_patches = client.get("/api/v1/patching/patches", headers=globex_admin["headers"]).json()
    assert all(p["id"] != patch_id for p in globex_patches)
    assert client.get(f"/api/v1/patching/patches/{patch_id}", headers=globex_admin["headers"]).status_code == 404

    globex_findings = client.get("/api/v1/patching/findings", headers=globex_admin["headers"]).json()
    assert all(f["endpoint_id"] != endpoint_id for f in globex_findings)
    globex_scans = client.get("/api/v1/patching/scans", headers=globex_admin["headers"]).json()
    assert all(s["id"] != scan["id"] for s in globex_scans)
    assert client.get(f"/api/v1/patching/scans/{scan['id']}", headers=globex_admin["headers"]).status_code == 404

    globex_deps = client.get("/api/v1/patching/deployments", headers=globex_admin["headers"]).json()
    assert all(d["id"] != dep["id"] for d in globex_deps)
    assert client.get(f"/api/v1/patching/deployments/{dep['id']}", headers=globex_admin["headers"]).status_code == 404


# --- Malformed job output ---------------------------------------------------


def test_malformed_job_output_tolerated(org_ids, app_db):
    endpoint_id = _make_endpoint(app_db, org_ids["acme"], "malformed-host")
    with tenant_session(uuid.UUID(org_ids["acme"])) as session:
        job = _make_job(session, org_ids["acme"], endpoint_id, "patch_scan", "not json {{{")
        result = apply_patch_scan_result(session, uuid.UUID(org_ids["acme"]), job)
        assert result["status"] == "malformed_output"
        assert "error" in result
        assert session.execute(select(PatchScan).where(PatchScan.job_id == job.id)).scalar_one_or_none() is None

        job2 = _make_job(session, org_ids["acme"], endpoint_id, "patch_scan", None)
        result2 = apply_patch_scan_result(session, uuid.UUID(org_ids["acme"]), job2)
        assert result2["status"] == "malformed_output"

        job3 = _make_job(session, org_ids["acme"], endpoint_id, "patch_deploy", json.dumps({"status": "installed"}))
        result3 = apply_patch_deploy_result(session, uuid.UUID(org_ids["acme"]), job3)
        assert result3["status"] == "malformed_output"

        job4 = _make_job(
            session,
            org_ids["acme"],
            endpoint_id,
            "patch_deploy",
            json.dumps({"patch_id": str(uuid.uuid4()), "status": "installed"}),
        )
        result4 = apply_patch_deploy_result(session, uuid.UUID(org_ids["acme"]), job4)
        assert result4["status"] == "no_item"
        session.commit()


def test_scan_without_kb_id_matches_on_title_and_vendor(org_ids, app_db):
    endpoint_id = _make_endpoint(app_db, org_ids["acme"], "no-kb-host")
    output = {
        "missing_patches": [
            {"title": "Vendor Tool Update 2.1", "vendor": "AcmeSoft", "severity": "low"},
            {"title": "Vendor Tool Update 2.1", "vendor": "AcmeSoft", "severity": "low"},
        ]
    }
    result = _apply_scan(org_ids["acme"], endpoint_id, output)
    assert result["status"] == "applied"
    assert result["new_findings"] == 1
    with tenant_session(uuid.UUID(org_ids["acme"])) as session:
        rows = (
            session.execute(
                select(Patch).where(
                    Patch.organization_id == uuid.UUID(org_ids["acme"]),
                    Patch.title == "Vendor Tool Update 2.1",
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 1
