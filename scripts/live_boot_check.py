"""Live-boot end-to-end check (coordinator scratch, not shipped).

Boots uvicorn against the `null_itsm_live` database (see
scripts/live_boot_setup.py), provisions a real organization through the
public API (no fixtures exist anywhere in this repo — the boot starts
from an empty database), then drives the real HTTP agent flow:
login -> enrollment token -> enroll -> heartbeat -> inventory -> issue
patch_scan job -> poll -> result -> patch findings; manual-engine vuln
import -> remediate -> verify -> agent rescan -> verified; CMDB + network
smoke. Dev-only credentials are read from tests/conftest.py at runtime,
never typed here.
"""

import os
import re
import secrets
import subprocess
import sys
import time
import uuid

import httpx
from cryptography.fernet import Fernet

CONF = open("tests/conftest.py").read()


def conf_url(name: str) -> str:
    m = re.search(rf'^{name} = "([^"]+)"', CONF, re.M)
    assert m, name
    return m.group(1)


APP_URL = conf_url("TEST_APP_URL").replace("null_itsm_test", "null_itsm_live")
# Port from the environment so a stale server on the default port can
# never silently answer for us (a bind failure must fail loudly, not
# let the checks run against someone else's backend).
PORT = int(os.environ.get("NULL_LIVE_BOOT_PORT", "8001"))
# Random per-run password for the live-boot user (created below); no
# credential is stored in this repo.
LIVE_PASSWORD = secrets.token_urlsafe(16)
LIVE_EMAIL = f"liveboot-{uuid.uuid4().hex[:8]}@example.com"
BASE = f"http://127.0.0.1:{PORT}"

env = dict(os.environ)
env["NULL_ENV"] = "development"
env["NULL_JWT_SECRET"] = "live-boot-dev-only-secret"
env["NULL_DATABASE_URL"] = APP_URL
env["NULL_DATABASE_OWNER_URL"] = conf_url("TEST_OWNER_URL").replace("null_itsm_test", "null_itsm_live")
env["NULL_REDIS_URL"] = "redis://localhost:6379/0"
env["NULL_CELERY_BROKER_URL"] = "redis://localhost:6379/1"
env["NULL_CELERY_RESULT_BACKEND"] = "redis://localhost:6379/2"
# Webhook secrets + integration credentials are Fernet-encrypted at
# rest and fail closed without a key (app/crypto.py) — generate a fresh
# dev-only key per boot so webhook creation works in the live check.
env["NULL_FIELD_ENCRYPTION_KEY"] = Fernet.generate_key().decode()

proc = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(PORT)],
    env=env,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
)
results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(("PASS " if ok else "FAIL ") + name + (f" — {detail}" if detail else ""))
    if not ok:
        raise SystemExit(f"live-boot check failed at: {name} {detail}")


try:
    with httpx.Client(timeout=15, trust_env=False) as c:
        for _ in range(30):
            if proc.poll() is not None:
                raise SystemExit(f"uvicorn exited early (port {PORT} likely in use); refusing to test another server")
            try:
                r = c.get(f"{BASE}/health")
                if r.status_code == 200:
                    break
            except httpx.ConnectError:
                time.sleep(0.5)
        else:
            raise SystemExit("uvicorn did not come up")
        check("health", r.json().get("status") == "ok", str(r.json()))
        r = c.get(f"{BASE}/health/ready")
        check("health/ready", r.status_code == 200, r.text[:200])

        # --- Provision a real org through the public registration API ---
        r = c.post(
            f"{BASE}/api/v1/auth/register",
            json={
                "org_name": "Live Boot Org",
                "org_email": "admin@liveboot.example",
                "industry": "Technology",
                "org_size": "1-10",
                "admin_name": "Live Boot",
                "admin_email": LIVE_EMAIL,
                "password": LIVE_PASSWORD,
            },
        )
        check("register org via API", r.status_code == 201, r.text[:200])
        token = r.json().get("access_token")
        H = {"Authorization": f"Bearer {token}"}
        me = c.get(f"{BASE}/api/v1/auth/me", headers=H).json()
        org_id = me["organization_id"]
        check("auth/me org", bool(org_id), org_id[:8])
        check("register returned tokens", bool(token), "access_token present")
        r = c.get(f"{BASE}/api/v1/organizations/{org_id}/onboarding", headers=H)
        check(
            "onboarding profile complete",
            r.status_code == 200 and r.json().get("steps", {}).get("profile") == "complete",
            r.text[:200],
        )

        # --- Agent flow ---
        r = c.post(f"{BASE}/api/v1/endpoints/enrollment-tokens", json={"expires_in_hours": 1}, headers=H)
        check("enrollment token", r.status_code == 201, r.text[:200])
        raw_token = r.json()["token"]
        hostname = "liveboot-mac-" + uuid.uuid4().hex[:6]
        r = c.post(
            f"{BASE}/api/v1/agents/enroll",
            json={
                "enrollment_token": raw_token,
                "device": {"hostname": hostname, "os": "macOS", "os_version": "26.6.2", "arch": "arm64"},
            },
        )
        check("enroll", r.status_code == 201, r.text[:200])
        device = r.json()
        DH = {"X-Device-Id": device["device_id"], "X-Device-Token": device["device_token"]}
        r = c.post(f"{BASE}/api/v1/agents/{device['device_id']}/heartbeat", json={}, headers=DH)
        check("heartbeat", r.status_code == 200, r.text[:200])
        r = c.post(
            f"{BASE}/api/v1/agents/{device['device_id']}/inventory",
            json={
                "collected_at": "2026-11-26T12:00:00+00:00",
                "os": {"name": "macOS", "version": "26.6.2"},
                "hardware": {"cpu": "Apple M4", "memory_mb": 16384, "disks": []},
                "network": {"interfaces": ["en0"], "mac_addresses": ["aa:bb:cc:dd:ee:ff"]},
                "software": [{"name": "NULL Agent", "version": "1.0.0"}],
                "services": [{"name": "null-agent", "status": "running"}],
            },
            headers=DH,
        )
        check("inventory", r.status_code == 201, r.text[:200])
        r = c.get(f"{BASE}/api/v1/endpoints/{device['device_id']}", headers=H)
        check("endpoint visible", r.status_code == 200 and r.json()["status"] in ("enrolled", "online"), r.text[:200])

        # --- Patch flow ---
        r = c.post(f"{BASE}/api/v1/endpoints/{device['device_id']}/jobs", json={"type": "patch_scan"}, headers=H)
        check("issue patch_scan job", r.status_code == 201, r.text[:200])
        job_id = r.json()["id"]
        r = c.get(f"{BASE}/api/v1/agents/{device['device_id']}/jobs/next", headers=DH)
        check("job delivered", r.status_code == 200 and r.json()["job"] is not None, r.text[:200])
        check("job id matches", r.json()["job"]["job_id"] == job_id)
        r = c.post(
            f"{BASE}/api/v1/agents/{device['device_id']}/jobs/{job_id}/result",
            json={
                "status": "succeeded",
                "output": {
                    "missing_patches": [{"patch_id": "LIVE-PATCH-1", "title": "Live boot patch", "severity": "high"}],
                    "scanned_at": "2026-11-26T12:00:00+00:00",
                },
                "started_at": "2026-11-26T12:00:00+00:00",
                "finished_at": "2026-11-26T12:00:00+00:00",
            },
            headers=DH,
        )
        check("patch result accepted", r.status_code == 200, r.text[:200])
        r = c.get(f"{BASE}/api/v1/patching/findings", headers=H)
        check(
            "patch finding applied",
            r.status_code == 200 and any(f.get("patch_title") == "Live boot patch" for f in r.json()),
            r.text[:300],
        )

        # --- Vuln verify flow ---
        r = c.post(
            f"{BASE}/api/v1/vulnerabilities/engines", json={"name": "Live manual", "engine_type": "manual"}, headers=H
        )
        check("manual engine", r.status_code == 201, r.text[:200])
        engine_id = r.json()["id"]
        r = c.post(
            f"{BASE}/api/v1/vulnerabilities/scans",
            json={"engine_id": engine_id, "name": "Live detect", "target": hostname},
            headers=H,
        )
        check("manual scan", r.status_code == 201, r.text[:200])
        scan_id = r.json()["id"]
        r = c.post(
            f"{BASE}/api/v1/vulnerabilities/scans/{scan_id}/import-results",
            json={"results": [{"host": hostname, "cve_id": "CVE-2024-99999", "severity": "high"}]},
            headers=H,
        )
        check("import results", r.status_code == 200, r.text[:200])
        r = c.get(f"{BASE}/api/v1/vulnerabilities/findings", headers=H)
        finding = next(f for f in r.json() if f["cve_id"] == "CVE-2024-99999")
        check("finding created", finding["status"] == "open", finding["id"][:8])
        r = c.post(f"{BASE}/api/v1/vulnerabilities/findings/{finding['id']}/remediate", json={}, headers=H)
        check("remediate", r.status_code == 201, r.text[:200])
        r = c.post(f"{BASE}/api/v1/vulnerabilities/findings/{finding['id']}/verify", headers=H)
        check("verify issues agent job", r.status_code == 200 and r.json()["job_id"] is not None, r.text[:200])
        r = c.get(f"{BASE}/api/v1/agents/{device['device_id']}/jobs/next", headers=DH)
        vjob = r.json()["job"]
        check("verify job delivered", vjob is not None and vjob["type"] == "vuln_scan", r.text[:200])
        r = c.post(
            f"{BASE}/api/v1/agents/{device['device_id']}/jobs/{vjob['job_id']}/result",
            json={
                "status": "succeeded",
                "output": {"results": []},
                "started_at": "2026-11-26T12:00:00+00:00",
                "finished_at": "2026-11-26T12:00:00+00:00",
            },
            headers=DH,
        )
        check("verify rescan result", r.status_code == 200, r.text[:200])
        r = c.get(f"{BASE}/api/v1/vulnerabilities/findings/{finding['id']}", headers=H)
        check("finding verified", r.json()["status"] == "verified", r.text[:200])

        # --- CMDB + network smoke ---
        r = c.post(
            f"{BASE}/api/v1/cmdb/items",
            json={"name": "live-web-01", "ci_type": "server", "status": "active"},
            headers=H,
        )
        check("cmdb item", r.status_code == 201, r.text[:200])
        r = c.post(
            f"{BASE}/api/v1/network/devices",
            json={"hostname": "live-sw-01", "ip_address": "127.0.0.1", "device_type": "switch"},
            headers=H,
        )
        check("network device", r.status_code == 201, r.text[:200])
        r = c.post(f"{BASE}/api/v1/network/discover", json={"cidr": "127.0.0.1/32"}, headers=H)
        check("network discover /32", r.status_code == 200, r.text[:300])
        r = c.get(f"{BASE}/api/v1/network/certificates/expiring?days=90", headers=H)
        check("certificates expiring", r.status_code == 200, r.text[:200])

        # --- Beat entries resolve ---
        from app.tasks.celery_app import celery_app

        sched = celery_app.conf.beat_schedule
        check(
            "beat sync_cve_kev",
            "sync-cve-kev-daily" in sched and sched["sync-cve-kev-daily"]["task"] == "null.tasks.sync_cve_kev",
        )
        check(
            "beat check_network_health",
            "check-network-health-hourly" in sched
            and sched["check-network-health-hourly"]["task"] == "null.tasks.check_network_health",
        )
        check("task sync_cve_kev registered", "null.tasks.sync_cve_kev" in celery_app.tasks)
        check("task check_network_health registered", "null.tasks.check_network_health" in celery_app.tasks)
finally:
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()

print(f"\nLIVE BOOT: {sum(1 for _, ok, _ in results if ok)}/{len(results)} checks passed")
