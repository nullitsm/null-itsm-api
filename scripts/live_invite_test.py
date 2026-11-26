"""Live invitation send (coordinator scratch, not shipped).

Boots uvicorn against the `null_itsm_live` database (already created by
scripts/live_boot_setup.py), registers a fresh organization through the
public API, and invites a real external recipient through the
configured email provider. Prints the delivery result (status,
provider, provider message id, whether the dev accept link was
exposed). The server is stopped afterwards; the DATABASE IS KEPT so
the invitation can be accepted later once the token is relayed from
the recipient's inbox. Drop it with psql when the acceptance test is
done.
"""

import os
import re
import secrets
import subprocess
import sys
import time
import uuid

import httpx

CONF = open("tests/conftest.py").read()


def conf_url(name: str) -> str:
    m = re.search(rf'^{name} = "([^"]+)"', CONF, re.M)
    assert m, name
    return m.group(1)


APP_URL = conf_url("TEST_APP_URL").replace("null_itsm_test", "null_itsm_live")
# Distinct port: 8001 is held by another agent's dev-mode server (see
# DEVELOPMENT_REGISTER.md) — never test against it.
PORT = int(os.environ.get("NULL_LIVE_BOOT_PORT", "8002"))
BASE = f"http://127.0.0.1:{PORT}"
RECIPIENT = sys.argv[1] if len(sys.argv) > 1 else "jamiah_mcq@yahoo.com"

env = dict(os.environ)
env["NULL_ENV"] = "development"
env["NULL_JWT_SECRET"] = "live-boot-dev-only-secret"
env["NULL_DATABASE_URL"] = APP_URL
env["NULL_DATABASE_OWNER_URL"] = conf_url("TEST_OWNER_URL").replace("null_itsm_test", "null_itsm_live")
env["NULL_REDIS_URL"] = "redis://localhost:6379/0"
env["NULL_CELERY_BROKER_URL"] = "redis://localhost:6379/1"
env["NULL_CELERY_RESULT_BACKEND"] = "redis://localhost:6379/2"
# Surrogate mode: provider resend, NO key in the environment — the key
# comes from the authd surrogate channel. Sender must be the Resend
# onboarding address (the account has no verified domain yet).
env["NULL_EMAIL_PROVIDER"] = "resend"
env["NULL_EMAIL_FROM"] = "onboarding@resend.dev"
env.pop("NULL_RESEND_API_KEY", None)

proc = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(PORT)],
    env=env,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
)
try:
    with httpx.Client(timeout=30, trust_env=False) as c:
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
            raise SystemExit("backend did not come up")

        admin_email = f"live-invite-{uuid.uuid4().hex[:8]}@example.com"
        r = c.post(
            f"{BASE}/api/v1/auth/register",
            json={
                "org_name": "NULL Live Invite Test",
                "org_email": "contact@example.com",
                "industry": "Technology",
                "org_size": "1-10",
                "admin_name": "Live Test Admin",
                "admin_email": admin_email,
                "password": secrets.token_urlsafe(16),
            },
        )
        assert r.status_code == 201, r.text
        data = r.json()
        org_id = data["organization"]["id"]
        headers = {"Authorization": f"Bearer {data['access_token']}"}
        print(f"org registered: {org_id}")

        r = c.post(
            f"{BASE}/api/v1/organizations/{org_id}/invitations",
            json={"email": RECIPIENT, "role_ids": [], "full_name": "Jamiah McQuiller"},
            headers=headers,
        )
        print(f"invite status: {r.status_code}")
        print(f"invite body: {r.text}")
        assert r.status_code == 201, r.text
        body = r.json()
        print(f"invitation id: {body['id']}")
        print(f"accept_url exposed: {body.get('accept_url') is not None}")
        print(f"delivery: {body.get('delivery')}")
finally:
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
print("server stopped; live DB KEPT for the acceptance step")
