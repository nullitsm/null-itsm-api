"""Vulnerability Celery tasks — CVE / CISA KEV catalog sync.

Task name: ``null.tasks.sync_cve_kev`` (no args). The catalog is
GLOBAL (no tenant data), so the task needs no org loop: it fetches
the real CISA KEV feed and one bounded NVD page and upserts into
``cve_catalog``. A fetch failure raises and leaves the catalog
unchanged (the service fetches both feeds before writing anything).

The coordinator wires the beat entry (suggested: daily); this module
only defines the task.
"""

from __future__ import annotations

import logging

from app.database import system_session
from app.services import vuln_service
from app.tasks.celery_app import celery_app

logger = logging.getLogger("null.tasks.vuln")


@celery_app.task(name="null.tasks.sync_cve_kev")
def sync_cve_kev() -> dict:
    """Sync CISA KEV (full) + NVD (one bounded page) into cve_catalog."""
    with system_session() as session:
        result = vuln_service.sync_cve_kev(session)
        session.flush()
    logger.info("CVE/KEV sync complete: %s", result)
    return result
