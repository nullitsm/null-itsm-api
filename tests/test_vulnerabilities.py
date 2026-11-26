"""Workstream C — vulnerability engine tests.

Uses the shared conftest fixtures (client, acme_admin, acme_tech,
globex_admin, org_ids). The coordinator owns ``app/main.py`` and
registers the router there; until then this module mounts the router
itself (idempotently — the mount is a no-op once main.py includes it),
so the suite can run before integration.
"""

from __future__ import annotations

import json
import uuid

import httpx
import pytest
from sqlalchemy import select

from app.database import system_session, tenant_session
from app.main import app
from app.models.endpoints import AgentJob, Endpoint
from app.models.vulnerabilities import CveCatalog, VulnerabilityFinding, VulnScan
from app.routers import vulnerabilities as vuln_router
from app.services import vuln_service

if not any(getattr(r, "path", "").startswith("/api/v1/vulnerabilities") for r in app.routes):
    app.include_router(vuln_router.router)

BASE = "/api/v1/vulnerabilities"

# --- Labelled fixture payloads (never the real feeds) -----------------------


KEV_FIXTURE = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2024-99901",
            "vendorProject": "Fixture Vendor",
            "product": "Fixture Product",
            "vulnerabilityName": "Fixture KEV vulnerability",
            "dateAdded": "2024-01-15",
            "dueDate": "2024-02-05",
            "knownRansomwareCampaignUse": "Known",
            "shortDescription": "A labelled test KEV entry.",
        },
        {
            "cveID": "CVE-2024-99902",
            "vendorProject": "Fixture Vendor",
            "product": "Other Product",
            "vulnerabilityName": "Second fixture KEV",
            "dateAdded": "2024-03-01",
            "dueDate": "2024-03-22",
            "knownRansomwareCampaignUse": "Unknown",
            "shortDescription": "Second labelled test KEV entry.",
        },
    ]
}

NVD_FIXTURE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2024-99901",
                "descriptions": [{"lang": "en", "value": "NVD description for the fixture CVE."}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 9.8,
                                "vectorString": "CVSS:3.1/AV:N/AC:L",
                                "baseSeverity": "CRITICAL",
                            }
                        }
                    ]
                },
                "published": "2024-01-10T00:00:00.000Z",
                "lastModified": "2024-01-20T00:00:00.000Z",
                "references": [{"url": "https://example.invalid/fixture"}],
            }
        },
        {
            "cve": {
                "id": "CVE-2024-99903",
                "descriptions": [{"lang": "en", "value": "NVD-only fixture CVE."}],
                "metrics": {
                    "cvssMetricV30": [
                        {"cvssData": {"baseScore": 5.3, "vectorString": "CVSS:3.0/AV:N/AC:L", "baseSeverity": "MEDIUM"}}
                    ]
                },
                "published": "2024-02-01T00:00:00.000Z",
                "lastModified": "2024-02-02T00:00:00.000Z",
                "references": [],
            }
        },
    ]
}


def _kev_nvd_transport() -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if "cisa.gov" in request.url.host:
            return httpx.Response(200, json=KEV_FIXTURE)
        if "nvd.nist.gov" in request.url.host:
            return httpx.Response(200, json=NVD_FIXTURE)
        return httpx.Response(404, json={})

    return httpx.MockTransport(handler)


# --- Helpers ----------------------------------------------------------------


def _make_endpoint(org_id: str, hostname: str, ip: str | None = None) -> str:
    with tenant_session(uuid.UUID(org_id)) as session:
        endpoint = Endpoint(
            organization_id=uuid.UUID(org_id),
            hostname=hostname,
            display_name=hostname,
            os_name="FixtureOS",
            ip_address=ip,
            status="enrolled",
        )
        session.add(endpoint)
        session.flush()
        return str(endpoint.id)


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


# --- CVE / KEV sync ----------------------------------------------------------


def test_kev_nvd_sync_upserts_and_is_idempotent():
    transport = _kev_nvd_transport()
    with system_session() as session:
        first = vuln_service.sync_cve_kev(session, transport=transport)
        session.flush()
    assert first["kev_created"] == 2, first
    assert first["nvd_created"] == 1, first  # CVE-2024-99901 already exists from KEV
    assert first["nvd_updated"] == 1, first
    with system_session() as session:
        row = session.execute(select(CveCatalog).where(CveCatalog.cve_id == "CVE-2024-99901")).scalar_one()
        assert row.kev is True
        assert row.severity == "critical"
        assert row.cvss_score is not None and float(row.cvss_score) == 9.8
        assert row.kev_vendor == "Fixture Vendor"
        assert row.kev_ransomware_use is True
        count_before = len(session.execute(select(CveCatalog)).scalars().all())
        second = vuln_service.sync_cve_kev(session, transport=transport)
        session.flush()
        count_after = len(session.execute(select(CveCatalog)).scalars().all())
    assert second["kev_created"] == 0 and second["nvd_created"] == 0, second
    assert count_after == count_before


def test_kev_nvd_sync_failure_leaves_catalog_unchanged():
    def failing(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("labelled test transport failure", request=request)

    with system_session() as session:
        before = len(session.execute(select(CveCatalog)).scalars().all())
        with pytest.raises(httpx.HTTPError):
            vuln_service.sync_cve_kev(session, transport=httpx.MockTransport(failing))
        after = len(session.execute(select(CveCatalog)).scalars().all())
    assert after == before


def test_cve_endpoints_and_filters(client, acme_admin):
    resp = client.get(f"{BASE}/cves/CVE-2024-99901", headers=acme_admin["headers"])
    assert resp.status_code == 200, resp.text
    assert resp.json()["kev"] is True
    assert resp.json()["severity"] == "critical"
    resp = client.get(f"{BASE}/cves/CVE-2024-99903", headers=acme_admin["headers"])
    assert resp.status_code == 200
    assert resp.json()["kev"] is False
    resp = client.get(f"{BASE}/cves?kev=true", headers=acme_admin["headers"])
    assert resp.status_code == 200
    assert all(row["kev"] for row in resp.json())
    assert any(row["cve_id"] == "CVE-2024-99901" for row in resp.json())
    resp = client.get(f"{BASE}/cves?severity=critical", headers=acme_admin["headers"])
    assert resp.status_code == 200
    assert all(row["severity"] == "critical" for row in resp.json())
    resp = client.get(f"{BASE}/cves/CVE-1999-00000", headers=acme_admin["headers"])
    assert resp.status_code == 404


# --- Engines -----------------------------------------------------------------


def test_engine_crud_and_password_never_returned(client, acme_admin):
    engine = _make_manual_engine(client, acme_admin["headers"], name="Manual A")
    assert engine["has_password"] is False
    assert "password" not in engine and "password_encrypted" not in engine
    resp = client.get(f"{BASE}/engines/{engine['id']}", headers=acme_admin["headers"])
    assert resp.status_code == 200
    assert "password_encrypted" not in resp.text
    assert resp.json()["has_password"] is False
    resp = client.patch(
        f"{BASE}/engines/{engine['id']}", json={"name": "Manual A renamed"}, headers=acme_admin["headers"]
    )
    assert resp.status_code == 200
    assert resp.json()["name"] == "Manual A renamed"
    resp = client.post(f"{BASE}/engines/{engine['id']}/set-default", headers=acme_admin["headers"])
    assert resp.status_code == 200
    assert resp.json()["is_default"] is True
    resp = client.get(f"{BASE}/engines", headers=acme_admin["headers"])
    assert resp.status_code == 200
    assert any(e["id"] == engine["id"] for e in resp.json())
    resp = client.delete(f"{BASE}/engines/{engine['id']}", headers=acme_admin["headers"])
    assert resp.status_code == 204
    resp = client.get(f"{BASE}/engines/{engine['id']}", headers=acme_admin["headers"])
    assert resp.status_code == 404


def test_engine_password_without_field_key_is_503(client, acme_admin):
    # The test env configures no NULL_FIELD_ENCRYPTION_KEY: storing a
    # reversible engine password must fail closed, never plaintext.
    resp = client.post(
        f"{BASE}/engines",
        json={"name": "GB no key", "engine_type": "greenbone", "host": "127.0.0.1", "password": "secret"},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 503, resp.text


def test_engine_password_encrypts_when_key_configured(client, acme_admin, monkeypatch):
    from cryptography.fernet import Fernet

    from app import crypto as crypto_mod

    key = Fernet.generate_key().decode()

    class _Settings:
        field_encryption_key = key

    monkeypatch.setattr(crypto_mod, "get_settings", lambda: _Settings())
    resp = client.post(
        f"{BASE}/engines",
        json={
            "name": "GB with key",
            "engine_type": "greenbone",
            "host": "127.0.0.1",
            "username": "admin",
            "password": "s3cret-value",
        },
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["has_password"] is True
    assert "s3cret-value" not in resp.text
    assert "password_encrypted" not in body
    with tenant_session(uuid.UUID(body["organization_id"])) as session:
        from app.models.vulnerabilities import VulnEngine

        row = session.get(VulnEngine, uuid.UUID(body["id"]))
        assert row.password_encrypted and row.password_encrypted != "s3cret-value"
        assert crypto_mod.decrypt(row.password_encrypted) == "s3cret-value"
    client.delete(f"{BASE}/engines/{body['id']}", headers=acme_admin["headers"])


def test_engine_invalid_type_400(client, acme_admin):
    resp = client.post(f"{BASE}/engines", json={"name": "Bad", "engine_type": "nessus"}, headers=acme_admin["headers"])
    assert resp.status_code == 400


# --- Scans -------------------------------------------------------------------


def test_scan_create_without_engine_is_400(client, globex_admin):
    # Globex has no engines in this module: honest failure, no fake scan.
    resp = client.post(
        f"{BASE}/scans", json={"name": "No engine scan", "target": "10.0.0.1"}, headers=globex_admin["headers"]
    )
    assert resp.status_code == 400, resp.text
    assert "no engine configured" in resp.text


def test_manual_import_correlates_and_dedupes(client, acme_admin, org_ids):
    endpoint_id = _make_endpoint(org_ids["acme"], "host-a", "10.0.0.11")
    engine = _make_manual_engine(client, acme_admin["headers"], name="Manual dedupe")
    scan1 = _make_manual_scan(client, acme_admin["headers"], engine["id"], name="Scan 1")
    assert scan1["status"] == "queued"
    out = _import(
        client,
        acme_admin["headers"],
        scan1["id"],
        [
            {"host": "host-a", "cve_id": "CVE-2024-99901", "plugin_name": "Fixture check", "severity": "critical"},
            {"host": "10.0.0.99", "cve_id": "CVE-2024-99903", "plugin_name": "Fixture check 2"},
        ],
    )
    assert out["results_applied"] == 2 and out["findings_created"] == 2, out
    assert out["status"] == "completed"
    resp = client.get(f"{BASE}/scans/{scan1['id']}", headers=acme_admin["headers"])
    assert resp.status_code == 200
    assert len(resp.json()["results"]) == 2
    findings = client.get(f"{BASE}/findings", headers=acme_admin["headers"]).json()
    mine = [f for f in findings if f["cve_id"] == "CVE-2024-99901" and f["endpoint_id"] == endpoint_id]
    assert len(mine) == 1
    assert mine[0]["severity"] == "critical"
    assert mine[0]["status"] == "open"
    assert mine[0]["catalog"]["kev"] is True
    first_seen = mine[0]["last_seen_at"]
    # Second import of the same CVE (different scan) must not duplicate.
    scan2 = _make_manual_scan(client, acme_admin["headers"], engine["id"], name="Scan 2")
    out2 = _import(
        client,
        acme_admin["headers"],
        scan2["id"],
        [{"host": "host-a", "cve_id": "CVE-2024-99901", "severity": "critical"}],
    )
    assert out2["findings_created"] == 0 and out2["findings_updated"] == 1, out2
    findings = client.get(f"{BASE}/findings", headers=acme_admin["headers"]).json()
    mine = [f for f in findings if f["cve_id"] == "CVE-2024-99901" and f["endpoint_id"] == endpoint_id]
    assert len(mine) == 1
    assert mine[0]["last_seen_at"] >= first_seen
    # Unenrolled host still gets a finding with endpoint_id NULL.
    unenrolled = [f for f in findings if f["cve_id"] == "CVE-2024-99903"]
    assert len(unenrolled) == 1 and unenrolled[0]["endpoint_id"] is None
    # Import into a completed scan is rejected; non-manual import is rejected.
    resp = client.post(
        f"{BASE}/scans/{scan1['id']}/import-results",
        json={"results": []},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 400
    client.delete(f"{BASE}/engines/{engine['id']}", headers=acme_admin["headers"])


def test_scan_cancel(client, acme_admin):
    engine = _make_manual_engine(client, acme_admin["headers"], name="Manual cancel")
    scan = _make_manual_scan(client, acme_admin["headers"], engine["id"], name="Cancellable")
    resp = client.post(f"{BASE}/scans/{scan['id']}/cancel", headers=acme_admin["headers"])
    assert resp.status_code == 200
    assert resp.json()["status"] == "cancelled"
    resp = client.post(f"{BASE}/scans/{scan['id']}/cancel", headers=acme_admin["headers"])
    assert resp.status_code == 400
    client.delete(f"{BASE}/engines/{engine['id']}", headers=acme_admin["headers"])


# --- Findings / remediation / verification -----------------------------------


def test_finding_status_guard(client, acme_admin, org_ids):
    endpoint_id = _make_endpoint(org_ids["acme"], "host-guard", "10.0.0.21")
    engine = _make_manual_engine(client, acme_admin["headers"], name="Manual guard")
    scan = _make_manual_scan(client, acme_admin["headers"], engine["id"], name="Guard scan")
    _import(client, acme_admin["headers"], scan["id"], [{"host": "host-guard", "cve_id": "CVE-2024-99902"}])
    findings = client.get(f"{BASE}/findings", headers=acme_admin["headers"]).json()
    finding = [f for f in findings if f["cve_id"] == "CVE-2024-99902" and f["endpoint_id"] == endpoint_id][0]
    for forbidden in ("verified", "remediated"):
        resp = client.patch(
            f"{BASE}/findings/{finding['id']}", json={"status": forbidden}, headers=acme_admin["headers"]
        )
        assert resp.status_code == 400, resp.text
    resp = client.patch(
        f"{BASE}/findings/{finding['id']}", json={"status": "false_positive"}, headers=acme_admin["headers"]
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "false_positive"
    client.delete(f"{BASE}/engines/{engine['id']}", headers=acme_admin["headers"])


def test_remediate_creates_real_ticket_and_link(client, acme_admin, org_ids):
    endpoint_id = _make_endpoint(org_ids["acme"], "host-rem", "10.0.0.31")
    engine = _make_manual_engine(client, acme_admin["headers"], name="Manual remediate")
    scan = _make_manual_scan(client, acme_admin["headers"], engine["id"], name="Remediate scan")
    _import(client, acme_admin["headers"], scan["id"], [{"host": "host-rem", "cve_id": "CVE-2024-99903"}])
    findings = client.get(f"{BASE}/findings", headers=acme_admin["headers"]).json()
    finding = [
        f
        for f in findings
        if f["cve_id"] == "CVE-2024-99903" and f["endpoint_id"] == endpoint_id and f["status"] == "open"
    ][0]
    resp = client.post(f"{BASE}/findings/{finding['id']}/remediate", json={}, headers=acme_admin["headers"])
    assert resp.status_code == 201, resp.text
    link = resp.json()
    assert link["finding_id"] == finding["id"]
    assert link["ticket_number"].startswith("INC-")
    # The ticket is a real ticket in the ITSM ticket list.
    tickets = client.get("/api/v1/tickets", headers=acme_admin["headers"]).json()
    assert any(t["number"] == link["ticket_number"] for t in tickets)
    assert "Remediate CVE-2024-99903 on host-rem" in [t["title"] for t in tickets]
    updated = client.get(f"{BASE}/findings/{finding['id']}", headers=acme_admin["headers"]).json()
    assert updated["status"] == "in_progress"
    assert updated["remediation_ticket_id"] == link["ticket_id"]
    assert len(updated["remediation"]) == 1
    # A second open remediation is refused.
    resp = client.post(f"{BASE}/findings/{finding['id']}/remediate", json={}, headers=acme_admin["headers"])
    assert resp.status_code == 400
    client.delete(f"{BASE}/engines/{engine['id']}", headers=acme_admin["headers"])


def _set_finding_remediated_with_verification_scan(org_id, cve_id, endpoint_id, verification_scan_id):
    """Test setup: a finding in `remediated` awaiting a verification scan.

    No API path sets `remediated` yet (see workstream report) — the
    state is staged directly so the verification flow itself is tested.
    """
    with tenant_session(uuid.UUID(org_id)) as session:
        finding = session.execute(
            select(VulnerabilityFinding).where(
                VulnerabilityFinding.organization_id == uuid.UUID(org_id),
                VulnerabilityFinding.cve_id == cve_id,
                VulnerabilityFinding.endpoint_id == uuid.UUID(endpoint_id),
                VulnerabilityFinding.status == "open",
            )
        ).scalar_one()
        finding.status = "remediated"
        finding.verification_scan_id = uuid.UUID(verification_scan_id)
        session.flush()
        return str(finding.id)


def test_verification_flow_absent_cve_verifies(client, acme_admin, org_ids):
    endpoint_id = _make_endpoint(org_ids["acme"], "host-ver", "10.0.0.41")
    engine = _make_manual_engine(client, acme_admin["headers"], name="Manual verify")
    scan = _make_manual_scan(client, acme_admin["headers"], engine["id"], name="Detect scan")
    _import(client, acme_admin["headers"], scan["id"], [{"host": "host-ver", "cve_id": "CVE-2024-99902"}])
    verify_scan = _make_manual_scan(client, acme_admin["headers"], engine["id"], name="Verify scan")
    finding_id = _set_finding_remediated_with_verification_scan(
        org_ids["acme"], "CVE-2024-99902", endpoint_id, verify_scan["id"]
    )
    out = _import(client, acme_admin["headers"], verify_scan["id"], [{"host": "host-ver", "cve_id": "CVE-2024-99903"}])
    assert out["verified"] == 1, out
    finding = client.get(f"{BASE}/findings/{finding_id}", headers=acme_admin["headers"]).json()
    assert finding["status"] == "verified"
    assert finding["verified_at"] is not None
    client.delete(f"{BASE}/engines/{engine['id']}", headers=acme_admin["headers"])


def test_verification_flow_present_cve_stays_open(client, acme_admin, org_ids):
    endpoint_id = _make_endpoint(org_ids["acme"], "host-ver2", "10.0.0.42")
    engine = _make_manual_engine(client, acme_admin["headers"], name="Manual verify 2")
    scan = _make_manual_scan(client, acme_admin["headers"], engine["id"], name="Detect scan 2")
    _import(client, acme_admin["headers"], scan["id"], [{"host": "host-ver2", "cve_id": "CVE-2024-99901"}])
    verify_scan = _make_manual_scan(client, acme_admin["headers"], engine["id"], name="Verify scan 2")
    finding_id = _set_finding_remediated_with_verification_scan(
        org_ids["acme"], "CVE-2024-99901", endpoint_id, verify_scan["id"]
    )
    out = _import(client, acme_admin["headers"], verify_scan["id"], [{"host": "host-ver2", "cve_id": "CVE-2024-99901"}])
    assert out["verified"] == 0, out
    finding = client.get(f"{BASE}/findings/{finding_id}", headers=acme_admin["headers"]).json()
    assert finding["status"] == "open"  # re-detected: reopened, not verified
    client.delete(f"{BASE}/engines/{engine['id']}", headers=acme_admin["headers"])


def test_summary_is_derived(client, acme_admin):
    resp = client.get(f"{BASE}/summary", headers=acme_admin["headers"])
    assert resp.status_code == 200
    body = resp.json()
    assert set(body.keys()) == {"by_severity", "by_status", "open_kev", "total_open"}
    assert body["total_open"] == sum(v for k, v in body["by_status"].items() if k in ("open", "in_progress"))
    assert body["open_kev"] >= 0


# --- Agent job-result contract ----------------------------------------------


def test_apply_vuln_scan_result_idempotent_and_malformed(org_ids):
    acme = uuid.UUID(org_ids["acme"])
    _make_endpoint(org_ids["acme"], "agent-host", "10.0.0.51")
    job_id = uuid.uuid4()
    with tenant_session(acme) as session:
        endpoint = session.execute(
            select(Endpoint).where(Endpoint.organization_id == acme, Endpoint.hostname == "agent-host")
        ).scalar_one()
        job = AgentJob(
            id=job_id,
            organization_id=acme,
            endpoint_id=endpoint.id,
            type="vuln_scan",
            payload={},
            status="succeeded",
            output=json.dumps(
                {
                    "results": [
                        {
                            "host": "agent-host",
                            "cve_id": "CVE-2024-99901",
                            "plugin_name": "agent check",
                            "severity": "critical",
                        },
                        {"host": "agent-host", "cve_id": "CVE-2024-99903", "severity": "medium"},
                    ]
                }
            ),
        )
        session.add(job)
        session.flush()
        first = vuln_service.apply_vuln_scan_result(session, acme, job)
        assert first["status"] == "ok", first
        assert first["results_applied"] == 2
        assert first["findings_created"] == 2
        session.flush()
        # Re-applying the same job is a no-op (idempotent).
        second = vuln_service.apply_vuln_scan_result(session, acme, job)
        assert second["status"] == "already_applied", second
        assert second["results_applied"] == 0
    with tenant_session(acme) as session:
        scans = (
            session.execute(select(VulnScan).where(VulnScan.engine_scan_id == f"agent-job:{job_id}")).scalars().all()
        )
        assert len(scans) == 1
        findings = (
            session.execute(
                select(VulnerabilityFinding).where(
                    VulnerabilityFinding.organization_id == acme, VulnerabilityFinding.cve_id == "CVE-2024-99901"
                )
            )
            .scalars()
            .all()
        )
        assert len([f for f in findings if f.status in ("open", "in_progress")]) >= 1
    # Malformed output: error dict, no state change, no raise.
    bad_job_id = uuid.uuid4()
    with tenant_session(acme) as session:
        endpoint = session.execute(
            select(Endpoint).where(Endpoint.organization_id == acme, Endpoint.hostname == "agent-host")
        ).scalar_one()
        bad_job = AgentJob(
            id=bad_job_id,
            organization_id=acme,
            endpoint_id=endpoint.id,
            type="vuln_scan",
            payload={},
            status="succeeded",
            output="{not json",
        )
        session.add(bad_job)
        session.flush()
        result = vuln_service.apply_vuln_scan_result(session, acme, bad_job)
        assert result["status"] == "error", result
        scans = (
            session.execute(select(VulnScan).where(VulnScan.engine_scan_id == f"agent-job:{bad_job_id}"))
            .scalars()
            .all()
        )
        assert scans == []


# --- Greenbone client (stubbed transport) ------------------------------------


class _FakeSocket:
    """Clearly-labelled test double: replays scripted response chunks."""

    def __init__(self, chunks: list[bytes]):
        self._chunks = list(chunks)
        self.sent: list[bytes] = []
        self.closed = False

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def recv(self, n: int) -> bytes:
        if not self._chunks:
            return b""
        return self._chunks.pop(0)

    def close(self) -> None:
        self.closed = True


def _gmp_response(body: str) -> bytes:
    return body.encode("utf-8")


def test_greenbone_client_stubbed_transport():
    from app.services.greenbone import GreenboneClient

    responses = [
        _gmp_response('<authenticate_response status="200" status_text="OK"/>'),
        _gmp_response(
            '<create_target_response status="201" status_text="OK"><id>target-1</id></create_target_response>'
        ),
        _gmp_response('<create_task_response status="201" status_text="OK"><id>task-1</id></create_task_response>'),
        _gmp_response(
            '<start_task_response status="202" status_text="OK"><report_id>report-1</report_id></start_task_response>'
        ),
        _gmp_response(
            '<get_tasks_response status="200" status_text="OK"><task id="task-1">'
            "<status>Done</status><progress>100</progress>"
            '<last_report><report id="report-1"/></last_report></task></get_tasks_response>'
        ),
        # Split the report across two chunks to exercise the read-until-parse loop.
        _gmp_response('<get_reports_response status="200" status_text="OK"><report id="report-1"><results>'),
        _gmp_response(
            '<result><host>host-a</host><nvt oid="1.3.6.1.4.1.25623.1.0.1">'
            "<name>Fixture VT</name><cve>CVE-2024-99901</cve></nvt>"
            "<severity>9.8</severity><description>Fixture output</description></result>"
            '<result><host>host-b</host><nvt oid="1.3.6.1.4.1.25623.1.0.2">'
            "<name>Other VT</name><cve>NOCVE</cve></nvt>"
            "<severity>2.5</severity><description>Other output</description></result>"
            "</results></report></get_reports_response>"
        ),
    ]
    sock = _FakeSocket(responses)
    client = GreenboneClient("127.0.0.1", 9390, "admin", "pw", socket_factory=lambda h, p, t: sock)
    assert client.authenticate() is True
    assert client.create_target("t", "10.0.0.1") == "target-1"
    assert client.create_task("t", "target-1") == "task-1"
    assert client.start_task("task-1") == "report-1"
    task_status = client.get_task_status("task-1")
    assert task_status["status"] == "Done"
    assert task_status["report_id"] == "report-1"
    results = client.get_report("report-1")
    assert len(results) == 2, results
    assert results[0] == {
        "host": "host-a",
        "cve_id": "CVE-2024-99901",
        "plugin_name": "Fixture VT",
        "plugin_output": "Fixture output",
        "severity": "critical",
    }
    assert results[1]["cve_id"] is None
    assert results[1]["severity"] == "low"
    assert b"<authenticate>" in sock.sent[0]
    client.close()
    assert sock.closed


def test_greenbone_client_unreachable_raises():
    from app.services.greenbone import GreenboneClient, GreenboneError

    def _refused(host, port, timeout):
        raise OSError("connection refused (labelled test double)")

    client = GreenboneClient("127.0.0.1", 9390, "admin", "pw", socket_factory=_refused)
    with pytest.raises(GreenboneError, match="engine unreachable"):
        client.authenticate()


def test_greenbone_scan_create_and_poll_with_stub(client, acme_admin, org_ids, monkeypatch):
    _make_endpoint(org_ids["acme"], "host-gb", "10.0.0.61")
    engine = client.post(
        f"{BASE}/engines",
        json={"name": "GB stub", "engine_type": "greenbone", "host": "127.0.0.1"},
        headers=acme_admin["headers"],
    ).json()

    class _StubClient:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return None

        def create_target(self, name, hosts):
            return "target-9"

        def create_task(self, name, target_id):
            return "task-9"

        def start_task(self, task_id):
            return "report-9"

        def get_task_status(self, task_id):
            return {"status": "Done", "progress": "100", "report_id": "report-9"}

        def get_report(self, report_id):
            return [{"host": "host-gb", "cve_id": "CVE-2024-99902", "plugin_name": "Stub VT", "severity": "high"}]

    monkeypatch.setattr(vuln_service, "get_engine_client", lambda engine: _StubClient())
    resp = client.post(
        f"{BASE}/scans",
        json={"engine_id": engine["id"], "name": "GB scan", "target": "10.0.0.61"},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 201, resp.text
    scan = resp.json()
    assert scan["status"] == "running"
    assert scan["engine_scan_id"] == "task-9"
    resp = client.post(f"{BASE}/scans/{scan['id']}/poll", headers=acme_admin["headers"])
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "completed"
    assert resp.json()["results_applied"] == 1
    findings = client.get(f"{BASE}/findings", headers=acme_admin["headers"]).json()
    assert any(f["cve_id"] == "CVE-2024-99902" and f["endpoint_id"] is not None for f in findings)
    client.delete(f"{BASE}/engines/{engine['id']}", headers=acme_admin["headers"])


def test_greenbone_scan_create_unreachable_is_502(client, acme_admin, monkeypatch):
    from app.services.greenbone import GreenboneError

    engine = client.post(
        f"{BASE}/engines",
        json={"name": "GB down", "engine_type": "greenbone", "host": "10.255.255.1"},
        headers=acme_admin["headers"],
    ).json()

    def _down(engine):
        raise GreenboneError("engine unreachable: 10.255.255.1:9390")

    monkeypatch.setattr(vuln_service, "get_engine_client", _down)
    resp = client.post(
        f"{BASE}/scans",
        json={"engine_id": engine["id"], "name": "GB down scan", "target": "10.0.0.1"},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 502, resp.text
    assert "engine unreachable" in resp.text
    scans = client.get(f"{BASE}/scans", headers=acme_admin["headers"]).json()
    assert not any(s["name"] == "GB down scan" for s in scans)
    client.delete(f"{BASE}/engines/{engine['id']}", headers=acme_admin["headers"])


# --- Tenant isolation / permissions ------------------------------------------


def test_tenant_isolation(client, acme_admin, globex_admin, org_ids):
    engine = _make_manual_engine(client, acme_admin["headers"], name="Acme only engine")
    scan = _make_manual_scan(client, acme_admin["headers"], engine["id"], name="Acme only scan")
    _import(client, acme_admin["headers"], scan["id"], [{"host": "host-a", "cve_id": "CVE-2024-99903"}])
    findings = client.get(f"{BASE}/findings", headers=acme_admin["headers"]).json()
    finding_id = findings[0]["id"]
    # Globex sees none of Acme's rows, and direct ids are 404, not 403.
    assert client.get(f"{BASE}/engines", headers=globex_admin["headers"]).json() == []
    assert client.get(f"{BASE}/scans", headers=globex_admin["headers"]).json() == []
    assert client.get(f"{BASE}/findings", headers=globex_admin["headers"]).json() == []
    assert client.get(f"{BASE}/engines/{engine['id']}", headers=globex_admin["headers"]).status_code == 404
    assert client.get(f"{BASE}/scans/{scan['id']}", headers=globex_admin["headers"]).status_code == 404
    assert client.get(f"{BASE}/findings/{finding_id}", headers=globex_admin["headers"]).status_code == 404
    client.delete(f"{BASE}/engines/{engine['id']}", headers=acme_admin["headers"])


def test_vuln_endpoints_require_permission(client, acme_tech):
    # Service Desk Technician holds no vulnerabilities:* permission.
    assert client.get(f"{BASE}/engines", headers=acme_tech["headers"]).status_code == 403
    assert client.get(f"{BASE}/findings", headers=acme_tech["headers"]).status_code == 403
