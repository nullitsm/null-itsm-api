"""Live-boot setup (coordinator scratch, not shipped).

Reads the dev-only database credentials from tests/conftest.py (never types
them), creates a fresh `null_itsm_live` database, and runs alembic to head.
The database is intentionally EMPTY — there are no fixtures or sample
records anywhere in this repo; the boot check creates its own org through
the public API. The live DB is dropped after the boot check.
"""

import os
import re
import subprocess
import sys

import psycopg

CONF = open("tests/conftest.py").read()


def url(name: str) -> str:
    m = re.search(rf'^{name} = "([^"]+)"', CONF, re.M)
    assert m, name
    return m.group(1)


SUPER = url("SUPERUSER_URL").replace("+psycopg", "")
# NB: keep the +psycopg driver on APP/OWNER — stripping it makes SQLAlchemy
# fall back to the psycopg2 driver, which is not installed.
APP = url("TEST_APP_URL").replace("null_itsm_test", "null_itsm_live")
OWNER = url("TEST_OWNER_URL").replace("null_itsm_test", "null_itsm_live")

conn = psycopg.connect(SUPER, autocommit=True)
with conn.cursor() as cur:
    cur.execute("SELECT 1 FROM pg_database WHERE datname = 'null_itsm_live'")
    if cur.fetchone():
        cur.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'null_itsm_live'")
        cur.execute("DROP DATABASE null_itsm_live")
    cur.execute("CREATE DATABASE null_itsm_live OWNER null_owner")
conn.close()
print("created null_itsm_live")

env = dict(os.environ)
env["NULL_DATABASE_OWNER_URL"] = OWNER.replace("null_itsm_live", "null_itsm_live")  # owner URL, live DB
env["NULL_DATABASE_URL"] = APP
subprocess.run(
    [sys.executable, "-m", "alembic", "upgrade", "head"],
    check=True,
    env=env,
)
print("alembic at head")
print("APP_URL_DB=null_itsm_live")
