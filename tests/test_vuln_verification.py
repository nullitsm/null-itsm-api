"""Integration tests for the finding verification endpoint (coordinator-added).

Covers the remediate -> verify -> rescan-verification flow that no single
workstream owned: POST /vulnerabilities/findings/{id}/verify flips the
finding to ``remediated`` and triggers verification — via an agent
``vuln_scan`` job when the endpoint is enrolled, or a queued verification
scan otherwise. The finding becomes ``verified`` only when the verification
scan's results contain no row for its (endpoint, CVE).

Uses the shared conftest fixtures. CVEs here are labelled test values
(CVE-2024-9991x), never real findings.
"""

from __future__ import annotations

import uuid

BASE = "/api/v1/vulnerabilities"
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


def _make_manual_engine(client, headers, name="Manual engine") -> dict:
    resp = client.post(f"{BASE}/engines", json={"name": name, "engine_type": "manual"}, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _make_manual_scan(client, headers, engine_id, name="Manual scan") -> dict:
    resp = client.post(
        f"{BASE}/scans",
        json={"engine_id": engine_id, "name": name, "target": "host-a"},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _import(client, headers, scan_id, results) -> dict:
    resp = client.post(f"{BASE}/scans/{scan_id}/import-results", json={"results": results}, headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()


def _finding_for_host_cve(client, headers, cve_id: str) -> dict:
    resp = client.get(f"{BASE}/findings", headers=headers)
    assert resp.status_code == 200, resp.text
    matches = [f for f in resp.json() if f["cve_id"] == cve_id]
    assert len(matches) == 1, f"expected one finding for {cve_id}, got {len(matches)}"
    return matches[0]


def _detect_finding(client, headers, hostname: str, cve_id: str) -> dict:
    engine = _make_manual_engine(client, headers, name=f"Detect {cve_id}")
    scan = _make_manual_scan(client, headers, engine["id"], name=f"Detect scan {cve_id}")
    _import(client, headers, scan["id"], [{"host": hostname, "cve_id": cve_id, "severity": "high"}])
    return _finding_for_host_cve(client, headers, cve_id)


def _remediate(client, headers, finding_id: str) -> dict:
    resp = client.post(f"{BASE}/findings/{finding_id}/remediate", json={}, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_verify_open_finding_rejected(client, acme_admin):
    hostname = _uniq("verify-guard")
    finding = _detect_finding(client, acme_admin["headers"], hostname, "CVE-2024-99911")
    assert finding["status"] == "open"
    resp = client.post(f"{BASE}/findings/{finding['id']}/verify", headers=acme_admin["headers"])
    assert resp.status_code == 400, resp.text


def test_verify_requires_manage_permission(client, acme_admin, acme_tech):
    hostname = _uniq("verify-perm")
    finding = _detect_finding(client, acme_admin["headers"], hostname, "CVE-2024-99912")
    _remediate(client, acme_admin["headers"], finding["id"])
    resp = client.post(f"{BASE}/findings/{finding['id']}/verify", headers=acme_tech["headers"])
    assert resp.status_code == 403, resp.text


def test_verify_agent_flow_absent_cve_verifies(client, acme_admin):
    hostname = _uniq("verify-agent")
    device = _enrolled_device(client, acme_admin["headers"], hostname)
    finding = _detect_finding(client, acme_admin["headers"], hostname, "CVE-2024-99913")
    assert finding["endpoint_id"] == device["device_id"]
    _remediate(client, acme_admin["headers"], finding["id"])
    resp = client.post(f"{BASE}/findings/{finding['id']}/verify", headers=acme_admin["headers"])
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["finding"]["status"] == "remediated"
    assert body["job_id"] is not None
    assert body["scan_id"] is None  # linked only when the job result arrives
    # The agent polls and receives the verification job.
    polled = client.get(f"/api/v1/agents/{device['device_id']}/jobs/next", headers=_device_headers(device))
    assert polled.status_code == 200, polled.text
    job = polled.json()["job"]
    assert job is not None and job["type"] == "vuln_scan"
    assert job["payload"]["verify_finding_id"] == finding["id"]
    # Agent reports a clean rescan: the CVE is gone.
    result = client.post(
        f"/api/v1/agents/{device['device_id']}/jobs/{job['job_id']}/result",
        json={"status": "succeeded", "output": {"results": []}, "started_at": UTC_ISO, "finished_at": UTC_ISO},
        headers=_device_headers(device),
    )
    assert result.status_code == 200, result.text
    got = client.get(f"{BASE}/findings/{finding['id']}", headers=acme_admin["headers"]).json()
    assert got["status"] == "verified"
    assert got["verified_at"] is not None
    assert got["verification_scan_id"] is not None
    # Verify again is rejected: a verified finding cannot re-enter the flow.
    resp = client.post(f"{BASE}/findings/{finding['id']}/verify", headers=acme_admin["headers"])
    assert resp.status_code == 400, resp.text


def test_verify_agent_flow_present_cve_stays_open(client, acme_admin):
    hostname = _uniq("verify-agent2")
    device = _enrolled_device(client, acme_admin["headers"], hostname)
    finding = _detect_finding(client, acme_admin["headers"], hostname, "CVE-2024-99914")
    _remediate(client, acme_admin["headers"], finding["id"])
    resp = client.post(f"{BASE}/findings/{finding['id']}/verify", headers=acme_admin["headers"])
    assert resp.status_code == 200, resp.text
    polled = client.get(f"/api/v1/agents/{device['device_id']}/jobs/next", headers=_device_headers(device))
    job = polled.json()["job"]
    assert job is not None and job["type"] == "vuln_scan"
    result = client.post(
        f"/api/v1/agents/{device['device_id']}/jobs/{job['job_id']}/result",
        json={
            "status": "succeeded",
            "output": {"results": [{"host": hostname, "cve_id": "CVE-2024-99914", "severity": "high"}]},
            "started_at": UTC_ISO,
            "finished_at": UTC_ISO,
        },
        headers=_device_headers(device),
    )
    assert result.status_code == 200, result.text
    got = client.get(f"{BASE}/findings/{finding['id']}", headers=acme_admin["headers"]).json()
    assert got["status"] == "open"  # re-detected: reopened, not verified
    assert got["verification_scan_id"] is None


def test_verify_queued_scan_path_for_unenrolled_host(client, acme_admin):
    hostname = _uniq("verify-queued")
    finding = _detect_finding(client, acme_admin["headers"], hostname, "CVE-2024-99915")
    assert finding["endpoint_id"] is None
    _remediate(client, acme_admin["headers"], finding["id"])
    resp = client.post(f"{BASE}/findings/{finding['id']}/verify", headers=acme_admin["headers"])
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["finding"]["status"] == "remediated"
    assert body["job_id"] is None
    assert body["scan_id"] is not None
    assert body["finding"]["verification_scan_id"] == body["scan_id"]
    # Import a clean rescan into the queued verification scan.
    out = _import(client, acme_admin["headers"], body["scan_id"], [{"host": hostname, "cve_id": "CVE-2024-99916"}])
    assert out["verified"] == 1, out
    got = client.get(f"{BASE}/findings/{finding['id']}", headers=acme_admin["headers"]).json()
    assert got["status"] == "verified"


def test_correlate_duplicate_hostname_does_not_500(client, acme_admin, org_ids):
    """Regression: two endpoints sharing a hostname must not 500 the import.

    Found by the live boot: re-enrolling the same hostname created duplicate
    endpoint rows, and resolve_endpoint's scalar_one_or_none() raised
    MultipleResultsFound. Correlation now attributes to the most recently
    seen endpoint (deterministic) instead of raising.
    """
    from sqlalchemy import select

    from app.database import tenant_session
    from app.models.endpoints import Endpoint

    hostname = _uniq("dup-host")
    with tenant_session(uuid.UUID(org_ids["acme"])) as session:
        for _ in range(2):
            session.add(
                Endpoint(
                    organization_id=uuid.UUID(org_ids["acme"]),
                    hostname=hostname,
                    display_name=hostname,
                    os_name="FixtureOS",
                    status="enrolled",
                )
            )
        session.flush()
        ids = (
            session.execute(
                select(Endpoint.id).where(
                    Endpoint.organization_id == uuid.UUID(org_ids["acme"]), Endpoint.hostname == hostname
                )
            )
            .scalars()
            .all()
        )
    assert len(ids) == 2
    finding = _detect_finding(client, acme_admin["headers"], hostname, "CVE-2024-99917")
    assert finding["endpoint_id"] in [str(i) for i in ids]
