"""GRC, releases, feature flags, status page, cross-module links tests
(Phase 4 workstream D, migration 0017).

Covers: GRC control CRUD + framework mappings + evidence (incl. linked
entity validation) + assessments driving derived control status +
time-boxed exceptions + revoke; releases CRUD + release transition;
feature flags CRUD + deterministic per-org evaluation; status page
incidents + updates timeline + PUBLIC read (no auth, incident data
only); entity links create validation (unknown type 400, missing /
cross-org end 404, duplicate 409) + linked graph both directions +
delete; tenant isolation + permission gates throughout.

The coordinator registers the grc/linking routers in app/main.py;
until then this module mounts them itself (guarded, so a later
main.py registration does not double-mount) — the same pattern as
tests/test_cmdb_network.py.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from app.main import app
from app.routers import grc as grc_router
from app.routers import linking as linking_router
from tests.conftest import set_rls

if not any(getattr(r, "path", "").startswith("/api/v1/grc") for r in app.routes):
    app.include_router(grc_router.router)
for _router, _prefix in (
    (linking_router.links_router, "/api/v1/links"),
    (linking_router.releases_router, "/api/v1/releases"),
    (linking_router.flags_router, "/api/v1/feature-flags"),
    (linking_router.status_router, "/api/v1/status"),
):
    if not any(getattr(r, "path", "").startswith(_prefix) for r in app.routes):
        app.include_router(_router)

UTC = timezone.utc


def _uid() -> str:
    return uuid.uuid4().hex[:8]


# --- Helpers ----------------------------------------------------------------


def _make_control(client, headers, code=None, **extra):
    body = {"code": code or f"CTRL-{_uid()}", "title": f"control {_uid()}", "description": "test control"}
    body.update(extra)
    resp = client.post("/api/v1/grc/controls", json=body, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _make_ticket(client, headers, title=None):
    resp = client.post("/api/v1/tickets", json={"title": title or f"ticket {_uid()}"}, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _make_asset(client, headers):
    resp = client.post(
        "/api/v1/assets",
        json={"asset_tag": f"AST-{_uid()}", "name": f"asset-{_uid()}", "type": "laptop"},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _make_change(client, headers):
    resp = client.post("/api/v1/changes", json={"title": f"change {_uid()}"}, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _insert_row(app_db, org_id, table, columns):
    """Insert one row as null_app under the org's RLS context; returns id."""
    set_rls(app_db, org_id)
    row_id = str(uuid.uuid4())
    cols = ["id", "organization_id", *columns.keys()]
    vals = [row_id, org_id, *columns.values()]
    placeholders = ", ".join(["%s"] * len(vals))
    with app_db.cursor() as cur:
        cur.execute(
            f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({placeholders})",
            vals,
        )
    return row_id


# --- GRC: controls + mappings -----------------------------------------------


def test_grc_control_crud_and_duplicate_code(client, acme_admin):
    h = acme_admin["headers"]
    control = _make_control(client, h, code="AC-1")
    assert control["status"] == "not_assessed"

    dup = client.post(
        "/api/v1/grc/controls",
        json={"code": "AC-1", "title": "dup", "description": ""},
        headers=h,
    )
    assert dup.status_code == 409, dup.text

    got = client.get(f"/api/v1/grc/controls/{control['id']}", headers=h)
    assert got.status_code == 200, got.text
    assert got.json()["code"] == "AC-1"
    assert got.json()["mappings"] == []
    assert got.json()["latest_assessment"] is None

    patched = client.patch(
        f"/api/v1/grc/controls/{control['id']}", json={"title": "renamed"}, headers=h
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["title"] == "renamed"

    # Status is derived: a client-supplied status is ignored (not a field).
    patched2 = client.patch(
        f"/api/v1/grc/controls/{control['id']}", json={"status": "satisfied"}, headers=h
    )
    assert patched2.status_code == 200, patched2.text
    assert patched2.json()["status"] == "not_assessed"

    deleted = client.delete(f"/api/v1/grc/controls/{control['id']}", headers=h)
    assert deleted.status_code == 204, deleted.text
    assert client.get(f"/api/v1/grc/controls/{control['id']}", headers=h).status_code == 404


def test_grc_control_permissions_and_isolation(client, acme_admin, acme_tech, globex_admin):
    h = acme_admin["headers"]
    control = _make_control(client, h)
    # Technician (no compliance:read) cannot read or manage GRC.
    assert client.get("/api/v1/grc/controls", headers=acme_tech["headers"]).status_code == 403
    resp = client.post(
        "/api/v1/grc/controls", json={"code": "X-1", "title": "x"}, headers=acme_tech["headers"]
    )
    assert resp.status_code == 403
    # Cross-org ids are 404, never 403.
    assert client.get(f"/api/v1/grc/controls/{control['id']}", headers=globex_admin["headers"]).status_code == 404
    assert client.get("/api/v1/grc/controls", headers=globex_admin["headers"]).status_code == 200
    globex_controls = client.get("/api/v1/grc/controls", headers=globex_admin["headers"]).json()
    assert all(c["id"] != control["id"] for c in globex_controls)


def test_grc_mappings_framework_validation(client, acme_admin):
    h = acme_admin["headers"]
    control = _make_control(client, h)
    bad = client.post(
        f"/api/v1/grc/controls/{control['id']}/mappings",
        json={"framework": "pci_dss", "clause": "1.1"},
        headers=h,
    )
    assert bad.status_code == 400, bad.text
    ok = client.post(
        f"/api/v1/grc/controls/{control['id']}/mappings",
        json={"framework": "soc2", "clause": "CC6.1", "notes": "logical access"},
        headers=h,
    )
    assert ok.status_code == 201, ok.text
    assert ok.json()["framework"] == "soc2"
    dup = client.post(
        f"/api/v1/grc/controls/{control['id']}/mappings",
        json={"framework": "soc2", "clause": "CC6.1"},
        headers=h,
    )
    assert dup.status_code == 409, dup.text
    iso = client.post(
        f"/api/v1/grc/controls/{control['id']}/mappings",
        json={"framework": "iso27001", "clause": "A.5.1"},
        headers=h,
    )
    assert iso.status_code == 201, iso.text
    # Framework filter on the list.
    listed = client.get("/api/v1/grc/controls?framework=iso27001", headers=h).json()
    assert any(c["id"] == control["id"] for c in listed)
    listed2 = client.get("/api/v1/grc/controls?framework=cis", headers=h).json()
    assert all(c["id"] != control["id"] for c in listed2)
    # Delete the mapping.
    deleted = client.delete(
        f"/api/v1/grc/controls/{control['id']}/mappings/{ok.json()['id']}", headers=h
    )
    assert deleted.status_code == 204, deleted.text
    detail = client.get(f"/api/v1/grc/controls/{control['id']}", headers=h).json()
    assert len(detail["mappings"]) == 1


# --- GRC: evidence ------------------------------------------------------------


def test_grc_evidence_reference_and_linked_entity(client, acme_admin):
    h = acme_admin["headers"]
    control = _make_control(client, h)
    ticket = _make_ticket(client, h)
    ref = client.post(
        f"/api/v1/grc/controls/{control['id']}/evidence",
        json={"title": "policy doc", "evidence_type": "reference", "reference": "https://example.invalid/policy.pdf"},
        headers=h,
    )
    assert ref.status_code == 201, ref.text
    assert ref.json()["reference"] == "https://example.invalid/policy.pdf"
    linked = client.post(
        f"/api/v1/grc/controls/{control['id']}/evidence",
        json={
            "title": "remediation ticket",
            "evidence_type": "link",
            "linked_entity_type": "ticket",
            "linked_entity_id": ticket["id"],
        },
        headers=h,
    )
    assert linked.status_code == 201, linked.text
    assert linked.json()["linked_entity_id"] == ticket["id"]
    # Unknown entity type -> 400; nonexistent entity -> 404.
    bad_type = client.post(
        f"/api/v1/grc/controls/{control['id']}/evidence",
        json={
            "title": "bad",
            "evidence_type": "link",
            "linked_entity_type": "server",
            "linked_entity_id": ticket["id"],
        },
        headers=h,
    )
    assert bad_type.status_code == 400, bad_type.text
    missing = client.post(
        f"/api/v1/grc/controls/{control['id']}/evidence",
        json={
            "title": "ghost",
            "evidence_type": "link",
            "linked_entity_type": "ticket",
            "linked_entity_id": str(uuid.uuid4()),
        },
        headers=h,
    )
    assert missing.status_code == 404, missing.text
    # Delete evidence.
    assert client.delete(f"/api/v1/grc/evidence/{ref.json()['id']}", headers=h).status_code == 204


def test_grc_evidence_cross_org_end_is_404(client, acme_admin, globex_admin):
    h = acme_admin["headers"]
    control = _make_control(client, h)
    globex_ticket = _make_ticket(client, globex_admin["headers"])
    resp = client.post(
        f"/api/v1/grc/controls/{control['id']}/evidence",
        json={
            "title": "other org ticket",
            "evidence_type": "link",
            "linked_entity_type": "ticket",
            "linked_entity_id": globex_ticket["id"],
        },
        headers=h,
    )
    assert resp.status_code == 404, resp.text


# --- GRC: assessments drive derived status -----------------------------------


def test_grc_assessment_derives_control_status(client, acme_admin):
    h = acme_admin["headers"]
    c1 = _make_control(client, h)
    c2 = _make_control(client, h)
    # In-progress assessment -> in_progress.
    a = client.post(
        "/api/v1/grc/assessments",
        json={
            "name": "Q4 review",
            "control_ids": [c1["id"], c2["id"]],
            "status": "in_progress",
            "findings": [{"title": "MFA not enforced on one admin", "severity": "medium"}],
        },
        headers=h,
    )
    assert a.status_code == 201, a.text
    assert a.json()["control_ids"] == [c1["id"], c2["id"]]
    assert client.get(f"/api/v1/grc/controls/{c1['id']}", headers=h).json()["status"] == "in_progress"
    # Passing it -> satisfied (a recorded outcome, not certification).
    patched = client.patch(f"/api/v1/grc/assessments/{a.json()['id']}", json={"status": "passed"}, headers=h)
    assert patched.status_code == 200, patched.text
    assert client.get(f"/api/v1/grc/controls/{c1['id']}", headers=h).json()["status"] == "satisfied"
    assert client.get(f"/api/v1/grc/controls/{c2['id']}", headers=h).json()["status"] == "satisfied"
    # A later failing assessment overrides to failed.
    a2 = client.post(
        "/api/v1/grc/assessments",
        json={"name": "follow-up", "control_ids": [c1["id"]], "status": "failed"},
        headers=h,
    )
    assert a2.status_code == 201, a2.text
    assert client.get(f"/api/v1/grc/controls/{c1['id']}", headers=h).json()["status"] == "failed"
    assert client.get(f"/api/v1/grc/controls/{c2['id']}", headers=h).json()["status"] == "satisfied"
    # Summary reflects derived statuses.
    summary = client.get("/api/v1/grc/summary", headers=h).json()
    assert summary["by_status"].get("failed", 0) >= 1
    assert summary["by_status"].get("satisfied", 0) >= 1
    # Assessment for an unknown / other-org control -> 404.
    bad = client.post(
        "/api/v1/grc/assessments",
        json={"name": "ghost", "control_ids": [str(uuid.uuid4())], "status": "passed"},
        headers=h,
    )
    assert bad.status_code == 404, bad.text
    bad_status = client.post(
        "/api/v1/grc/assessments",
        json={"name": "bad", "control_ids": [c1["id"]], "status": "compliant"},
        headers=h,
    )
    assert bad_status.status_code == 400, bad_status.text


# --- GRC: exceptions ----------------------------------------------------------


def test_grc_exception_timeboxed_and_revoked(client, acme_admin):
    h = acme_admin["headers"]
    control = _make_control(client, h)
    # Passing assessment first so the exception visibly overrides it.
    client.post(
        "/api/v1/grc/assessments",
        json={"name": "pass", "control_ids": [control["id"]], "status": "passed"},
        headers=h,
    )
    assert client.get(f"/api/v1/grc/controls/{control['id']}", headers=h).json()["status"] == "satisfied"
    future = (datetime.now(UTC) + timedelta(days=30)).isoformat()
    exc = client.post(
        f"/api/v1/grc/controls/{control['id']}/exceptions",
        json={"reason": "legacy system, compensating control in place", "expires_at": future},
        headers=h,
    )
    assert exc.status_code == 201, exc.text
    assert exc.json()["status"] == "active"
    assert client.get(f"/api/v1/grc/controls/{control['id']}", headers=h).json()["status"] == "exception"
    # Past expiry is rejected: exceptions are always time-boxed forward.
    past = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    bad = client.post(
        f"/api/v1/grc/controls/{control['id']}/exceptions",
        json={"reason": "too late", "expires_at": past},
        headers=h,
    )
    assert bad.status_code == 400, bad.text
    # Revoke -> control falls back to the assessment-derived status.
    revoked = client.post(f"/api/v1/grc/exceptions/{exc.json()['id']}/revoke", headers=h)
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["status"] == "revoked"
    assert client.get(f"/api/v1/grc/controls/{control['id']}", headers=h).json()["status"] == "satisfied"
    assert client.post(f"/api/v1/grc/exceptions/{exc.json()['id']}/revoke", headers=h).status_code == 400


# --- Releases -----------------------------------------------------------------


def test_releases_crud_and_release_transition(client, acme_admin, acme_tech):
    h = acme_admin["headers"]
    rel = client.post(
        "/api/v1/releases",
        json={"version": "1.4.0", "title": "November release", "notes": "GRC + links", "status": "draft"},
        headers=h,
    )
    assert rel.status_code == 201, rel.text
    assert rel.json()["released_at"] is None
    dup = client.post(
        "/api/v1/releases",
        json={"version": "1.4.0", "title": "dup"},
        headers=h,
    )
    assert dup.status_code == 409, dup.text
    bad = client.post("/api/v1/releases", json={"version": "9.9.9", "title": "bad", "status": "shipped"}, headers=h)
    assert bad.status_code == 400, bad.text
    patched = client.patch(f"/api/v1/releases/{rel.json()['id']}", json={"status": "released"}, headers=h)
    assert patched.status_code == 200, patched.text
    assert patched.json()["status"] == "released"
    assert patched.json()["released_at"] is not None
    assert client.get("/api/v1/releases?status_filter=released", headers=h).status_code == 200
    resp = client.post(
        "/api/v1/releases", json={"version": "2.0.0", "title": "x"}, headers=acme_tech["headers"]
    )
    assert resp.status_code == 403
    assert client.delete(f"/api/v1/releases/{rel.json()['id']}", headers=h).status_code == 204
    assert client.get(f"/api/v1/releases/{rel.json()['id']}", headers=h).status_code == 404


# --- Feature flags -------------------------------------------------------------


def test_feature_flags_crud_validation_and_evaluation(client, acme_admin, globex_admin):
    h = acme_admin["headers"]
    flag = client.post(
        "/api/v1/feature-flags",
        json={"key": "new_dashboard", "description": "New dashboard UI", "enabled": True, "rollout_percentage": 100},
        headers=h,
    )
    assert flag.status_code == 201, flag.text
    assert client.post(
        "/api/v1/feature-flags",
        json={"key": "new_dashboard", "description": "dup"},
        headers=h,
    ).status_code == 409
    assert client.post(
        "/api/v1/feature-flags",
        json={"key": "Bad Key!", "description": "bad key"},
        headers=h,
    ).status_code == 400
    assert client.post(
        "/api/v1/feature-flags",
        json={"key": "too_much", "rollout_percentage": 101},
        headers=h,
    ).status_code == 400
    # 100% rollout + enabled -> enabled for this org, deterministically.
    ev = client.get("/api/v1/feature-flags/new_dashboard/evaluate", headers=h).json()
    assert ev["enabled"] is True
    assert ev["rollout_percentage"] == 100
    assert 0 <= ev["bucket"] < 100
    ev2 = client.get("/api/v1/feature-flags/new_dashboard/evaluate", headers=h).json()
    assert ev2 == ev  # deterministic: same org, same answer
    # 0% rollout -> disabled even though the flag is enabled.
    client.patch("/api/v1/feature-flags/new_dashboard", json={"rollout_percentage": 0}, headers=h)
    assert client.get("/api/v1/feature-flags/new_dashboard/evaluate", headers=h).json()["enabled"] is False
    # Disabled flag -> disabled regardless of rollout.
    client.patch(
        "/api/v1/feature-flags/new_dashboard", json={"rollout_percentage": 100, "enabled": False}, headers=h
    )
    assert client.get("/api/v1/feature-flags/new_dashboard/evaluate", headers=h).json()["enabled"] is False
    # Evaluation is per-org: the flag does not exist in Globex at all.
    ev_g = client.get("/api/v1/feature-flags/new_dashboard/evaluate", headers=globex_admin["headers"])
    assert ev_g.status_code == 404
    assert client.get("/api/v1/feature-flags/new_dashboard", headers=globex_admin["headers"]).status_code == 404
    assert client.get("/api/v1/feature-flags", headers=globex_admin["headers"]).json() == []
    assert client.delete("/api/v1/feature-flags/new_dashboard", headers=h).status_code == 204


# --- Status page ----------------------------------------------------------------


def test_status_page_incidents_updates_and_public_read(client, acme_admin, globex_admin):
    h = acme_admin["headers"]
    inc = client.post(
        "/api/v1/status/incidents",
        json={"title": "API latency", "description": "Elevated latency on the API", "status": "investigating"},
        headers=h,
    )
    assert inc.status_code == 201, inc.text
    inc_id = inc.json()["id"]
    assert inc.json()["resolved_at"] is None
    upd = client.post(
        f"/api/v1/status/incidents/{inc_id}/updates",
        json={"status": "identified", "message": "Root cause found in the queue worker."},
        headers=h,
    )
    assert upd.status_code == 201, upd.text
    # The update moves the incident's status.
    got = client.get(f"/api/v1/status/incidents/{inc_id}", headers=h).json()
    assert got["status"] == "identified"
    assert len(got["updates"]) == 1
    assert got["updates"][0]["message"] == "Root cause found in the queue worker."
    resolved = client.post(
        f"/api/v1/status/incidents/{inc_id}/updates",
        json={"status": "resolved", "message": "Latency back to normal."},
        headers=h,
    )
    assert resolved.status_code == 201, resolved.text
    got2 = client.get(f"/api/v1/status/incidents/{inc_id}", headers=h).json()
    assert got2["status"] == "resolved"
    assert got2["resolved_at"] is not None
    assert len(got2["updates"]) == 2
    # Public read: no auth, incident data only.
    pub = client.get("/api/v1/status/public/acme")
    assert pub.status_code == 200, pub.text
    body = pub.json()
    assert body["organization_slug"] == "acme"
    mine = [i for i in body["incidents"] if i["id"] == inc_id]
    assert len(mine) == 1
    assert set(mine[0].keys()) == {
        "id",
        "title",
        "description",
        "status",
        "started_at",
        "resolved_at",
        "created_at",
        "updated_at",
        "updates",
    }
    assert len(mine[0]["updates"]) == 2
    # Another org's public page does not show Acme's incidents.
    pub_g = client.get("/api/v1/status/public/globex").json()
    assert all(i["id"] != inc_id for i in pub_g["incidents"])
    # Unknown slug -> 404; no auth header needed either way.
    assert client.get("/api/v1/status/public/no-such-org").status_code == 404
    # Authenticated list is tenant-scoped.
    globex_incidents = client.get("/api/v1/status/incidents", headers=globex_admin["headers"]).json()
    assert all(i["id"] != inc_id for i in globex_incidents)
    assert client.delete(f"/api/v1/status/incidents/{inc_id}", headers=h).status_code == 204
    pub_after = client.get("/api/v1/status/public/acme").json()
    assert all(i["id"] != inc_id for i in pub_after["incidents"])


# --- Entity links ----------------------------------------------------------------


def test_links_create_validate_graph_and_delete(client, acme_admin, app_db, org_ids):
    h = acme_admin["headers"]
    ticket = _make_ticket(client, h)
    asset = _make_asset(client, h)
    change = _make_change(client, h)
    endpoint_id = _insert_row(
        app_db, org_ids["acme"], "endpoints", {"hostname": f"host-{_uid()}", "status": "enrolled"}
    )
    finding_id = _insert_row(
        app_db, org_ids["acme"], "vulnerability_findings", {"cve_id": "CVE-2026-0001", "severity": "high"}
    )
    deployment_id = _insert_row(app_db, org_ids["acme"], "patch_deployments", {"name": f"deploy-{_uid()}"})
    # Unknown types -> 400.
    bad_type = client.post(
        "/api/v1/links",
        json={
            "source_type": "server",
            "source_id": ticket["id"],
            "target_type": "ticket",
            "target_id": ticket["id"],
            "link_type": "relates_to",
        },
        headers=h,
    )
    assert bad_type.status_code == 400, bad_type.text
    bad_link_type = client.post(
        "/api/v1/links",
        json={
            "source_type": "ticket",
            "source_id": ticket["id"],
            "target_type": "asset",
            "target_id": asset["id"],
            "link_type": "owns",
        },
        headers=h,
    )
    assert bad_link_type.status_code == 400, bad_link_type.text
    # Nonexistent end -> 404.
    ghost = client.post(
        "/api/v1/links",
        json={
            "source_type": "ticket",
            "source_id": ticket["id"],
            "target_type": "asset",
            "target_id": str(uuid.uuid4()),
            "link_type": "affects",
        },
        headers=h,
    )
    assert ghost.status_code == 404, ghost.text
    # The remediation chain: finding -> endpoint -> ticket -> deployment.
    l1 = client.post(
        "/api/v1/links",
        json={
            "source_type": "vulnerability_finding",
            "source_id": finding_id,
            "target_type": "endpoint",
            "target_id": endpoint_id,
            "link_type": "affects",
        },
        headers=h,
    )
    assert l1.status_code == 201, l1.text
    l2 = client.post(
        "/api/v1/links",
        json={
            "source_type": "vulnerability_finding",
            "source_id": finding_id,
            "target_type": "ticket",
            "target_id": ticket["id"],
            "link_type": "remediates",
        },
        headers=h,
    )
    assert l2.status_code == 201, l2.text
    l3 = client.post(
        "/api/v1/links",
        json={
            "source_type": "ticket",
            "source_id": ticket["id"],
            "target_type": "patch_deployment",
            "target_id": deployment_id,
            "link_type": "verifies",
        },
        headers=h,
    )
    assert l3.status_code == 201, l3.text
    # Exact duplicate -> 409.
    assert client.post(
        "/api/v1/links",
        json={
            "source_type": "vulnerability_finding",
            "source_id": finding_id,
            "target_type": "ticket",
            "target_id": ticket["id"],
            "link_type": "remediates",
        },
        headers=h,
    ).status_code == 409
    # Graph from the finding: both outgoing links, with identities.
    graph = client.get(
        f"/api/v1/links/graph?entity_type=vulnerability_finding&entity_id={finding_id}", headers=h
    )
    assert graph.status_code == 200, graph.text
    g = graph.json()
    assert g["entity"]["label"] == "CVE-2026-0001"
    assert g["entity"]["status"] == "open"
    assert len(g["links"]) == 2
    assert {x["direction"] for x in g["links"]} == {"outgoing"}
    labels = {x["entity"]["label"] for x in g["links"]}
    assert any("host-" in label for label in labels)
    assert any(label.startswith("INC-") for label in labels)
    # Graph from the ticket: one incoming (finding remediates), one outgoing.
    graph_t = client.get(f"/api/v1/links/graph?entity_type=ticket&entity_id={ticket['id']}", headers=h).json()
    assert len(graph_t["links"]) == 2
    assert {x["direction"] for x in graph_t["links"]} == {"incoming", "outgoing"}
    incoming = [x for x in graph_t["links"] if x["direction"] == "incoming"][0]
    assert incoming["entity"]["entity_type"] == "vulnerability_finding"
    assert incoming["link_type"] == "remediates"
    # Change <-> asset link round-trips through the list filter.
    l4 = client.post(
        "/api/v1/links",
        json={
            "source_type": "change",
            "source_id": change["id"],
            "target_type": "asset",
            "target_id": asset["id"],
            "link_type": "affects",
        },
        headers=h,
    )
    assert l4.status_code == 201, l4.text
    listed = client.get(f"/api/v1/links?source_type=change&source_id={change['id']}", headers=h).json()
    assert len(listed) == 1
    assert listed[0]["target_id"] == asset["id"]
    # Delete removes it from the graph.
    assert client.delete(f"/api/v1/links/{l4.json()['id']}", headers=h).status_code == 204
    assert client.get(f"/api/v1/links?source_type=change&source_id={change['id']}", headers=h).json() == []


def test_links_cross_org_end_is_404(client, acme_admin, globex_admin):
    h = acme_admin["headers"]
    ticket = _make_ticket(client, h)
    globex_asset = _make_asset(client, globex_admin["headers"])
    resp = client.post(
        "/api/v1/links",
        json={
            "source_type": "ticket",
            "source_id": ticket["id"],
            "target_type": "asset",
            "target_id": globex_asset["id"],
            "link_type": "affects",
        },
        headers=h,
    )
    assert resp.status_code == 404, resp.text
    # And the reverse direction too.
    resp2 = client.post(
        "/api/v1/links",
        json={
            "source_type": "asset",
            "source_id": globex_asset["id"],
            "target_type": "ticket",
            "target_id": ticket["id"],
            "link_type": "affects",
        },
        headers=h,
    )
    assert resp2.status_code == 404, resp2.text


def test_links_permissions(client, acme_admin, acme_tech):
    h = acme_admin["headers"]
    ticket = _make_ticket(client, h)
    asset = _make_asset(client, h)
    # Technician has neither links:read nor links:manage.
    assert client.get("/api/v1/links", headers=acme_tech["headers"]).status_code == 403
    assert (
        client.post(
            "/api/v1/links",
            json={
                "source_type": "ticket",
                "source_id": ticket["id"],
                "target_type": "asset",
                "target_id": asset["id"],
                "link_type": "affects",
            },
            headers=acme_tech["headers"],
        ).status_code
        == 403
    )
    # Admin can read (links:read is in the catalog).
    assert client.get("/api/v1/links", headers=h).status_code == 200
    # Graph for an unknown type -> 400; for a missing entity -> 404.
    assert client.get("/api/v1/links/graph?entity_type=server&entity_id=" + ticket["id"], headers=h).status_code == 400
    assert (
        client.get(f"/api/v1/links/graph?entity_type=ticket&entity_id={uuid.uuid4()}", headers=h).status_code == 404
    )
