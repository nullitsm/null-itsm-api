"""Custom forms / dashboards / reports tests (Phase 4, workstream B).

Covers: form + field CRUD and validation, ticket field-value
submission (required / type / select-options / user-membership
checks), dashboard + widget CRUD and query validation, widget data
computed from real rows (tickets by status/priority, vulnerabilities
by severity, endpoints by OS), report definitions + on-demand CSV
generation (real rows, real columns), scheduled reports (cron
validation, run-now, and the Celery task invoked directly), tenant
isolation, and permissions.

The coordinator registers the forms/reporting routers in app/main.py;
until then this module mounts them itself (guarded, so a later
main.py registration does not double-mount).
"""

from __future__ import annotations

import csv
import io
import uuid

from app.main import app
from app.routers import forms as forms_router
from app.routers import reporting as reporting_router
from tests.conftest import set_rls

if not any(getattr(r, "path", "").startswith("/api/v1/forms") for r in app.routes):
    app.include_router(forms_router.router)
if not any(getattr(r, "path", "").startswith("/api/v1/dashboards") for r in app.routes):
    app.include_router(reporting_router.dashboards_router)
if not any(getattr(r, "path", "").startswith("/api/v1/reports") for r in app.routes):
    app.include_router(reporting_router.reports_router)


def _uid() -> str:
    return uuid.uuid4().hex[:8]


# --- Helpers ----------------------------------------------------------------


def _make_form(client, headers, name=None, fields=None, **extra):
    body = {"name": name or f"form-{_uid()}", "target_type": "ticket"}
    body["fields"] = fields if fields is not None else []
    body.update(extra)
    resp = client.post("/api/v1/forms", json=body, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _make_ticket(client, headers, title=None, **extra):
    body = {"title": title or f"ticket-{_uid()}", "priority": "medium", "category": "General"}
    body.update(extra)
    resp = client.post("/api/v1/tickets", json=body, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _set_ticket_status(client, headers, ticket_id, status):
    resp = client.patch(f"/api/v1/tickets/{ticket_id}", json={"status": status}, headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()


def _make_dashboard(client, headers, name=None):
    resp = client.post(
        "/api/v1/dashboards", json={"name": name or f"dash-{_uid()}"}, headers=headers
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _make_widget(client, headers, dashboard_id, query, title=None, widget_type="count"):
    resp = client.post(
        f"/api/v1/dashboards/{dashboard_id}/widgets",
        json={"title": title or f"w-{_uid()}", "widget_type": widget_type, "query": query},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _make_report(client, headers, entity, columns, name=None, filters=None):
    resp = client.post(
        "/api/v1/reports",
        json={
            "name": name or f"rep-{_uid()}",
            "entity": entity,
            "columns": columns,
            "filters": filters or {},
        },
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _insert_vuln(app_db, org_id, cve_id, severity="critical"):
    set_rls(app_db, org_id)
    with app_db.cursor() as cur:
        cur.execute(
            "INSERT INTO vulnerability_findings (id, organization_id, cve_id, severity, status)"
            " VALUES (gen_random_uuid(), %s, %s, %s, 'open') RETURNING id",
            (org_id, cve_id, severity),
        )
        return str(cur.fetchone()[0])


def _insert_endpoint(app_db, org_id, os_name):
    set_rls(app_db, org_id)
    with app_db.cursor() as cur:
        cur.execute(
            "INSERT INTO endpoints (id, organization_id, hostname, os_name, status)"
            " VALUES (gen_random_uuid(), %s, %s, %s, 'online') RETURNING id",
            (org_id, f"host-{_uid()}", os_name),
        )
        return str(cur.fetchone()[0])


# --- Forms: CRUD + field validation -------------------------------------------


def test_form_crud(client, acme_admin):
    form = _make_form(
        client,
        acme_admin["headers"],
        fields=[
            {"key": "business_unit", "label": "Business unit", "field_type": "select",
             "required": True, "options": ["Sales", "Ops"]},
            {"key": "impact_score", "label": "Impact", "field_type": "number",
             "validation": {"min": 0, "max": 10}},
        ],
    )
    assert form["target_type"] == "ticket"
    assert len(form["fields"]) == 2
    assert form["fields"][0]["key"] == "business_unit"

    got = client.get(f"/api/v1/forms/{form['id']}", headers=acme_admin["headers"])
    assert got.status_code == 200, got.text
    assert got.json()["name"] == form["name"]

    patched = client.patch(
        f"/api/v1/forms/{form['id']}", json={"description": "intake"}, headers=acme_admin["headers"]
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["description"] == "intake"

    listed = client.get("/api/v1/forms", headers=acme_admin["headers"])
    assert listed.status_code == 200
    assert any(f["id"] == form["id"] for f in listed.json())

    deleted = client.delete(f"/api/v1/forms/{form['id']}", headers=acme_admin["headers"])
    assert deleted.status_code == 204, deleted.text
    gone = client.get(f"/api/v1/forms/{form['id']}", headers=acme_admin["headers"])
    assert gone.status_code == 404


def test_form_validation_errors(client, acme_admin):
    # Bad target type.
    resp = client.post(
        "/api/v1/forms", json={"name": f"f-{_uid()}", "target_type": "change"},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 400, resp.text
    # Bad field type.
    resp = client.post(
        "/api/v1/forms",
        json={"name": f"f-{_uid()}", "fields": [{"key": "x", "label": "X", "field_type": "nope"}]},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 400, resp.text
    # Select without options.
    resp = client.post(
        "/api/v1/forms",
        json={"name": f"f-{_uid()}", "fields": [{"key": "x", "label": "X", "field_type": "select"}]},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 400, resp.text
    # Duplicate field key.
    resp = client.post(
        "/api/v1/forms",
        json={
            "name": f"f-{_uid()}",
            "fields": [
                {"key": "dup", "label": "A", "field_type": "text"},
                {"key": "dup", "label": "B", "field_type": "text"},
            ],
        },
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 400, resp.text
    # Bad key shape.
    resp = client.post(
        "/api/v1/forms",
        json={"name": f"f-{_uid()}", "fields": [{"key": "Bad Key", "label": "X", "field_type": "text"}]},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 400, resp.text
    # Duplicate form name in the same org.
    name = f"dup-form-{_uid()}"
    _make_form(client, acme_admin["headers"], name=name)
    resp = client.post("/api/v1/forms", json={"name": name}, headers=acme_admin["headers"])
    assert resp.status_code == 409, resp.text


def test_field_crud(client, acme_admin):
    form = _make_form(client, acme_admin["headers"])
    added = client.post(
        f"/api/v1/forms/{form['id']}/fields",
        json={"key": "region", "label": "Region", "field_type": "select", "options": ["NA", "EU"]},
        headers=acme_admin["headers"],
    )
    assert added.status_code == 201, added.text
    field_id = added.json()["id"]

    dup = client.post(
        f"/api/v1/forms/{form['id']}/fields",
        json={"key": "region", "label": "Region 2", "field_type": "text"},
        headers=acme_admin["headers"],
    )
    assert dup.status_code == 409, dup.text

    patched = client.patch(
        f"/api/v1/forms/{form['id']}/fields/{field_id}",
        json={"label": "Sales region", "required": True},
        headers=acme_admin["headers"],
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["label"] == "Sales region"
    assert patched.json()["required"] is True

    # Clearing the options of a select field is rejected.
    bad = client.patch(
        f"/api/v1/forms/{form['id']}/fields/{field_id}",
        json={"options": []},
        headers=acme_admin["headers"],
    )
    assert bad.status_code == 400, bad.text

    deleted = client.delete(
        f"/api/v1/forms/{form['id']}/fields/{field_id}", headers=acme_admin["headers"]
    )
    assert deleted.status_code == 204, deleted.text
    gone = client.patch(
        f"/api/v1/forms/{form['id']}/fields/{field_id}",
        json={"label": "x"},
        headers=acme_admin["headers"],
    )
    assert gone.status_code == 404


def test_forms_permissions_and_isolation(client, acme_admin, acme_tech, globex_admin):
    form = _make_form(client, acme_admin["headers"])
    # The technician role has neither forms:read nor forms:manage.
    assert client.get("/api/v1/forms", headers=acme_tech["headers"]).status_code == 403
    assert client.post(
        "/api/v1/forms", json={"name": f"f-{_uid()}"}, headers=acme_tech["headers"]
    ).status_code == 403
    # Another org sees nothing (404, never a leak).
    assert client.get(f"/api/v1/forms/{form['id']}", headers=globex_admin["headers"]).status_code == 404
    assert client.delete(f"/api/v1/forms/{form['id']}", headers=globex_admin["headers"]).status_code == 404


def test_form_created_audit_event(client, acme_admin, org_ids, app_db):
    form = _make_form(client, acme_admin["headers"])
    set_rls(app_db, org_ids["acme"])
    with app_db.cursor() as cur:
        cur.execute(
            "SELECT action, resource_type FROM audit_logs WHERE resource_id = %s AND action = 'form.created'",
            (form["id"],),
        )
        row = cur.fetchone()
    assert row is not None, "expected a form.created audit event"
    assert row[1] == "custom_form"


# --- Field values ---------------------------------------------------------------


def _intake_form(client, headers):
    me = client.get("/api/v1/auth/me", headers=headers).json()
    return _make_form(
        client,
        headers,
        fields=[
            {"key": "business_unit", "label": "Business unit", "field_type": "select",
             "required": True, "options": ["Sales", "Ops"]},
            {"key": "impact_score", "label": "Impact", "field_type": "number",
             "validation": {"min": 0, "max": 10}},
            {"key": "due_date", "label": "Due date", "field_type": "date"},
            {"key": "tags", "label": "Tags", "field_type": "multi_select",
             "options": ["urgent", "vip"]},
            {"key": "owner", "label": "Owner", "field_type": "user"},
        ],
    ), me["user_id"]


def test_submit_values_happy_path_and_readback(client, acme_admin):
    form, admin_user_id = _intake_form(client, acme_admin["headers"])
    ticket = _make_ticket(client, acme_admin["headers"])
    resp = client.post(
        f"/api/v1/forms/{form['id']}/tickets/{ticket['id']}/values",
        json={"values": [
            {"field_key": "business_unit", "value": "Sales"},
            {"field_key": "impact_score", "value": 7},
            {"field_key": "due_date", "value": "2026-12-01"},
            {"field_key": "tags", "value": ["urgent"]},
            {"field_key": "owner", "value": admin_user_id},
        ]},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 200, resp.text
    assert len(resp.json()) == 5

    listed = client.get(
        f"/api/v1/forms/{form['id']}/tickets/{ticket['id']}/values", headers=acme_admin["headers"]
    )
    assert listed.status_code == 200, listed.text
    by_key = {v["field_key"]: v["value"] for v in listed.json()}
    assert by_key["business_unit"] == "Sales"
    assert by_key["impact_score"] == 7
    assert by_key["due_date"] == "2026-12-01"
    assert by_key["tags"] == ["urgent"]
    assert by_key["owner"] == admin_user_id

    # Resubmission replaces the value (one value per field per ticket).
    resp = client.post(
        f"/api/v1/forms/{form['id']}/tickets/{ticket['id']}/values",
        json={"values": [{"field_key": "impact_score", "value": 3}]},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 200, resp.text
    listed = client.get(
        f"/api/v1/forms/{form['id']}/tickets/{ticket['id']}/values", headers=acme_admin["headers"]
    )
    by_key = {v["field_key"]: v["value"] for v in listed.json()}
    assert by_key["impact_score"] == 3
    assert by_key["business_unit"] == "Sales"


def test_submit_values_validation(client, acme_admin):
    form, _ = _intake_form(client, acme_admin["headers"])
    ticket = _make_ticket(client, acme_admin["headers"])
    url = f"/api/v1/forms/{form['id']}/tickets/{ticket['id']}/values"

    def _post(values):
        return client.post(url, json={"values": values}, headers=acme_admin["headers"])

    # Missing required field.
    assert _post([{"field_key": "impact_score", "value": 1}]).status_code == 400
    # Select value not in options.
    assert _post([
        {"field_key": "business_unit", "value": "Mars"},
        {"field_key": "impact_score", "value": 1},
    ]).status_code == 400
    # Number out of range.
    assert _post([
        {"field_key": "business_unit", "value": "Ops"},
        {"field_key": "impact_score", "value": 99},
    ]).status_code == 400
    # Number given as a string.
    assert _post([
        {"field_key": "business_unit", "value": "Ops"},
        {"field_key": "impact_score", "value": "high"},
    ]).status_code == 400
    # Bad date.
    assert _post([
        {"field_key": "business_unit", "value": "Ops"},
        {"field_key": "due_date", "value": "Dec 1"},
    ]).status_code == 400
    # Multi-select with an invalid option.
    assert _post([
        {"field_key": "business_unit", "value": "Ops"},
        {"field_key": "tags", "value": ["urgent", "nope"]},
    ]).status_code == 400
    # User field referencing a non-member (random UUID).
    assert _post([
        {"field_key": "business_unit", "value": "Ops"},
        {"field_key": "owner", "value": str(uuid.uuid4())},
    ]).status_code == 400
    # Unknown field key.
    assert _post([{"field_key": "nope", "value": 1}]).status_code == 400
    # Duplicate field in one submission.
    assert _post([
        {"field_key": "business_unit", "value": "Ops"},
        {"field_key": "business_unit", "value": "Sales"},
    ]).status_code == 400
    # Cross-org ticket is 404.
    other_ticket = _make_ticket(client, acme_admin["headers"])
    resp = client.post(
        f"/api/v1/forms/{form['id']}/tickets/{other_ticket['id']}/values",
        json={"values": [{"field_key": "business_unit", "value": "Ops"}]},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 200, resp.text  # same-org ticket works; isolation is below
    # Globex cannot submit values against acme's form/ticket.
    resp = client.post(
        url, json={"values": [{"field_key": "business_unit", "value": "Ops"}]},
        headers={"Authorization": "Bearer invalid"},
    )
    assert resp.status_code == 401


def test_submit_values_cross_org_ticket(client, acme_admin, globex_admin):
    form, _ = _intake_form(client, acme_admin["headers"])
    globex_ticket = _make_ticket(client, globex_admin["headers"])
    resp = client.post(
        f"/api/v1/forms/{form['id']}/tickets/{globex_ticket['id']}/values",
        json={"values": [{"field_key": "business_unit", "value": "Ops"}]},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 404, resp.text


# --- Dashboards + widgets -------------------------------------------------------


def test_dashboard_and_widget_crud(client, acme_admin):
    dashboard = _make_dashboard(client, acme_admin["headers"])
    widget = _make_widget(
        client, acme_admin["headers"], dashboard["id"],
        {"entity": "tickets", "group_by": "status"}, widget_type="group_by",
    )
    assert widget["query"]["entity"] == "tickets"
    assert widget["query"]["group_by"] == "status"

    got = client.get(f"/api/v1/dashboards/{dashboard['id']}", headers=acme_admin["headers"])
    assert got.status_code == 200, got.text
    assert len(got.json()["widgets"]) == 1

    patched = client.patch(
        f"/api/v1/dashboards/{dashboard['id']}/widgets/{widget['id']}",
        json={"title": "Tickets by status"},
        headers=acme_admin["headers"],
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["title"] == "Tickets by status"

    deleted = client.delete(
        f"/api/v1/dashboards/{dashboard['id']}/widgets/{widget['id']}",
        headers=acme_admin["headers"],
    )
    assert deleted.status_code == 204, deleted.text
    assert client.delete(
        f"/api/v1/dashboards/{dashboard['id']}", headers=acme_admin["headers"]
    ).status_code == 204


def test_widget_query_validation(client, acme_admin):
    dashboard = _make_dashboard(client, acme_admin["headers"])
    url = f"/api/v1/dashboards/{dashboard['id']}/widgets"

    def _post(query, widget_type="count"):
        return client.post(
            url, json={"title": "w", "widget_type": widget_type, "query": query},
            headers=acme_admin["headers"],
        )

    assert _post({"entity": "nope"}).status_code == 400
    assert _post({}).status_code == 400  # no entity
    assert _post({"entity": "tickets", "group_by": "status"}).status_code == 400  # count + group_by
    assert _post(
        {"entity": "tickets", "group_by": "number"}, widget_type="group_by"
    ).status_code == 400  # not groupable
    assert _post(
        {"entity": "tickets", "group_by": "status", "filters": {"nope": "x"}},
        widget_type="group_by",
    ).status_code == 400
    assert _post(
        {"entity": "tickets", "group_by": "status", "filters": {"status": []}},
        widget_type="group_by",
    ).status_code == 400
    assert _post({"entity": "tickets", "widget_type": "bogus"}).status_code == 400


def test_widget_data_from_real_tickets(client, acme_admin):
    category = f"wcat-{_uid()}"
    _make_ticket(client, acme_admin["headers"], priority="high", category=category)
    _make_ticket(client, acme_admin["headers"], priority="high", category=category)
    t3 = _make_ticket(client, acme_admin["headers"], priority="low", category=category)
    _set_ticket_status(client, acme_admin["headers"], t3["id"], "resolved")

    dashboard = _make_dashboard(client, acme_admin["headers"])
    by_status = _make_widget(
        client, acme_admin["headers"], dashboard["id"],
        {"entity": "tickets", "group_by": "status", "filters": {"category": category}},
        widget_type="group_by",
    )
    by_priority = _make_widget(
        client, acme_admin["headers"], dashboard["id"],
        {"entity": "tickets", "group_by": "priority", "filters": {"category": category}},
        widget_type="group_by",
    )
    total = _make_widget(
        client, acme_admin["headers"], dashboard["id"],
        {"entity": "tickets", "filters": {"category": category, "priority": ["high", "low"]}},
        widget_type="count",
    )

    data = client.get(
        f"/api/v1/dashboards/{dashboard['id']}/widgets/{by_status['id']}/data",
        headers=acme_admin["headers"],
    )
    assert data.status_code == 200, data.text
    body = data.json()
    assert body["total"] == 3
    assert {g["group"]: g["count"] for g in body["groups"]} == {"open": 2, "resolved": 1}

    data = client.get(
        f"/api/v1/dashboards/{dashboard['id']}/widgets/{by_priority['id']}/data",
        headers=acme_admin["headers"],
    )
    assert {g["group"]: g["count"] for g in data.json()["groups"]} == {"high": 2, "low": 1}

    data = client.get(
        f"/api/v1/dashboards/{dashboard['id']}/widgets/{total['id']}/data",
        headers=acme_admin["headers"],
    )
    assert data.json()["total"] == 3
    assert data.json()["groups"] == []

    # Whole-dashboard data aggregates every widget.
    all_data = client.get(
        f"/api/v1/dashboards/{dashboard['id']}/data", headers=acme_admin["headers"]
    )
    assert all_data.status_code == 200, all_data.text
    assert len(all_data.json()["widgets"]) == 3
    assert sum(w["total"] for w in all_data.json()["widgets"]) == 9


def test_widget_data_empty_entity_and_other_entities(client, acme_admin, org_ids, app_db):
    # No vulnerability findings with this CVE exist yet: honest zeros.
    dashboard = _make_dashboard(client, acme_admin["headers"])
    empty = _make_widget(
        client, acme_admin["headers"], dashboard["id"],
        {"entity": "vulnerabilities", "group_by": "severity",
         "filters": {"cve_id": f"CVE-2099-{_uid()}"}},
        widget_type="group_by",
    )
    data = client.get(
        f"/api/v1/dashboards/{dashboard['id']}/widgets/{empty['id']}/data",
        headers=acme_admin["headers"],
    )
    assert data.status_code == 200, data.text
    assert data.json()["total"] == 0
    assert data.json()["groups"] == []

    # One real finding + one real endpoint, isolated by unique filters.
    cve = f"CVE-2026-{_uid()}"
    _insert_vuln(app_db, org_ids["acme"], cve, severity="critical")
    os_name = f"TestOS-{_uid()}"
    _insert_endpoint(app_db, org_ids["acme"], os_name)

    vuln_widget = _make_widget(
        client, acme_admin["headers"], dashboard["id"],
        {"entity": "vulnerabilities", "group_by": "severity", "filters": {"cve_id": cve}},
        widget_type="group_by",
    )
    data = client.get(
        f"/api/v1/dashboards/{dashboard['id']}/widgets/{vuln_widget['id']}/data",
        headers=acme_admin["headers"],
    )
    assert data.json()["groups"] == [{"group": "critical", "count": 1}]

    ep_widget = _make_widget(
        client, acme_admin["headers"], dashboard["id"],
        {"entity": "endpoints", "group_by": "os_name", "filters": {"os_name": os_name}},
        widget_type="group_by",
    )
    data = client.get(
        f"/api/v1/dashboards/{dashboard['id']}/widgets/{ep_widget['id']}/data",
        headers=acme_admin["headers"],
    )
    assert data.json()["groups"] == [{"group": os_name, "count": 1}]


def test_dashboards_permissions_and_isolation(client, acme_admin, acme_tech, globex_admin):
    dashboard = _make_dashboard(client, acme_admin["headers"])
    # Technician has neither dashboards:read nor dashboards:manage.
    assert client.get("/api/v1/dashboards", headers=acme_tech["headers"]).status_code == 403
    assert client.post(
        "/api/v1/dashboards", json={"name": f"d-{_uid()}"}, headers=acme_tech["headers"]
    ).status_code == 403
    assert client.get(
        f"/api/v1/dashboards/{dashboard['id']}", headers=globex_admin["headers"]
    ).status_code == 404
    assert client.get(
        f"/api/v1/dashboards/{dashboard['id']}/data", headers=globex_admin["headers"]
    ).status_code == 404


# --- Reports --------------------------------------------------------------------


def test_report_crud_and_validation(client, acme_admin):
    report = _make_report(
        client, acme_admin["headers"], "tickets",
        ["number", "title", "status", "priority"],
    )
    assert report["entity"] == "tickets"

    bad = client.post(
        "/api/v1/reports",
        json={"name": f"r-{_uid()}", "entity": "tickets", "columns": ["bogus"]},
        headers=acme_admin["headers"],
    )
    assert bad.status_code == 400, bad.text
    bad = client.post(
        "/api/v1/reports",
        json={"name": f"r-{_uid()}", "entity": "nope", "columns": ["number"]},
        headers=acme_admin["headers"],
    )
    assert bad.status_code == 400, bad.text
    bad = client.post(
        "/api/v1/reports",
        json={"name": f"r-{_uid()}", "entity": "tickets", "columns": []},
        headers=acme_admin["headers"],
    )
    assert bad.status_code == 400, bad.text
    bad = client.post(
        "/api/v1/reports",
        json={"name": f"r-{_uid()}", "entity": "tickets", "columns": ["number"],
             "filters": {"nope": "x"}},
        headers=acme_admin["headers"],
    )
    assert bad.status_code == 400, bad.text

    patched = client.patch(
        f"/api/v1/reports/{report['id']}",
        json={"columns": ["number", "title"]},
        headers=acme_admin["headers"],
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["columns"] == ["number", "title"]

    assert client.delete(
        f"/api/v1/reports/{report['id']}", headers=acme_admin["headers"]
    ).status_code == 204


def test_report_generate_csv(client, acme_admin):
    category = f"rcat-{_uid()}"
    t1 = _make_ticket(client, acme_admin["headers"], title="Alpha ticket", category=category)
    t2 = _make_ticket(client, acme_admin["headers"], title="Beta ticket", category=category)
    _set_ticket_status(client, acme_admin["headers"], t2["id"], "resolved")

    report = _make_report(
        client, acme_admin["headers"], "tickets",
        ["number", "title", "status", "priority"],
        filters={"category": category},
    )
    resp = client.post(
        f"/api/v1/reports/{report['id']}/generate", headers=acme_admin["headers"]
    )
    assert resp.status_code == 200, resp.text
    assert "text/csv" in resp.headers["content-type"]
    assert "attachment" in resp.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(resp.text)))
    assert len(rows) == 2
    assert {r["title"] for r in rows} == {"Alpha ticket", "Beta ticket"}
    assert {r["number"] for r in rows} == {t1["number"], t2["number"]}
    assert {r["status"] for r in rows} == {"open", "resolved"}
    assert list(rows[0].keys()) == ["number", "title", "status", "priority"]

    # Filtered report only returns matching rows.
    filtered = _make_report(
        client, acme_admin["headers"], "tickets", ["number", "title"],
        filters={"category": category, "status": "resolved"},
    )
    resp = client.post(
        f"/api/v1/reports/{filtered['id']}/generate", headers=acme_admin["headers"]
    )
    rows = list(csv.DictReader(io.StringIO(resp.text)))
    assert len(rows) == 1
    assert rows[0]["number"] == t2["number"]

    # Excel is answered honestly: openpyxl is not installed.
    resp = client.post(
        f"/api/v1/reports/{report['id']}/generate?format=xlsx", headers=acme_admin["headers"]
    )
    assert resp.status_code == 501, resp.text
    resp = client.post(
        f"/api/v1/reports/{report['id']}/generate?format=pdf", headers=acme_admin["headers"]
    )
    assert resp.status_code == 400, resp.text


def test_report_permissions_and_isolation(client, acme_admin, acme_tech, globex_admin):
    report = _make_report(client, acme_admin["headers"], "tickets", ["number", "title"])
    # Technician has reports:read but NOT reports:export or reports:manage.
    assert client.get("/api/v1/reports", headers=acme_tech["headers"]).status_code == 200
    assert client.post(
        f"/api/v1/reports/{report['id']}/generate", headers=acme_tech["headers"]
    ).status_code == 403
    assert client.post(
        "/api/v1/reports",
        json={"name": f"r-{_uid()}", "entity": "tickets", "columns": ["number"]},
        headers=acme_tech["headers"],
    ).status_code == 403
    assert client.get(
        f"/api/v1/reports/{report['id']}", headers=globex_admin["headers"]
    ).status_code == 404
    assert client.post(
        f"/api/v1/reports/{report['id']}/generate", headers=globex_admin["headers"]
    ).status_code == 404


# --- Scheduled reports ------------------------------------------------------------


def _make_schedule(client, headers, report_id, cron="0 9 * * 1", **extra):
    body = {
        "cron_expression": cron,
        "recipients": ["ops@example.com"],
        "format": "csv",
        "is_active": True,
    }
    body.update(extra)
    resp = client.post(f"/api/v1/reports/{report_id}/schedules", json=body, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_scheduled_report_crud_and_cron_validation(client, acme_admin):
    report = _make_report(client, acme_admin["headers"], "tickets", ["number", "title"])
    schedule = _make_schedule(client, acme_admin["headers"], report["id"])
    assert schedule["last_status"] == "never_run"
    assert schedule["recipients"] == ["ops@example.com"]

    bad_crons = ["", "0 9 * *", "0 9 * * 1 2", "61 9 * * *", "0 25 * * *",
                 "0 9 32 * *", "0 9 * 13 *", "0 9 * * 8", "abc", "0 9 * * MON"]
    for bad in bad_crons:
        resp = client.post(
            f"/api/v1/reports/{report['id']}/schedules",
            json={"cron_expression": bad, "recipients": []},
            headers=acme_admin["headers"],
        )
        assert resp.status_code == 400, f"cron {bad!r} should be rejected: {resp.text}"
    bad = client.post(
        f"/api/v1/reports/{report['id']}/schedules",
        json={"cron_expression": "0 9 * * 1", "recipients": ["not-an-email"]},
        headers=acme_admin["headers"],
    )
    assert bad.status_code == 400, bad.text

    patched = client.patch(
        f"/api/v1/reports/{report['id']}/schedules/{schedule['id']}",
        json={"cron_expression": "30 8 * * 1-5", "is_active": False},
        headers=acme_admin["headers"],
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["cron_expression"] == "30 8 * * 1-5"
    assert patched.json()["is_active"] is False

    listed = client.get(
        f"/api/v1/reports/{report['id']}/schedules", headers=acme_admin["headers"]
    )
    assert listed.status_code == 200
    assert any(s["id"] == schedule["id"] for s in listed.json())

    assert client.delete(
        f"/api/v1/reports/{report['id']}/schedules/{schedule['id']}",
        headers=acme_admin["headers"],
    ).status_code == 204


def test_scheduled_report_run_now(client, acme_admin):
    category = f"scat-{_uid()}"
    _make_ticket(client, acme_admin["headers"], category=category)
    _make_ticket(client, acme_admin["headers"], category=category)
    report = _make_report(
        client, acme_admin["headers"], "tickets", ["number", "title"],
        filters={"category": category},
    )
    schedule = _make_schedule(client, acme_admin["headers"], report["id"])
    resp = client.post(
        f"/api/v1/reports/{report['id']}/schedules/{schedule['id']}/run",
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "success"
    assert body["row_count"] == 2
    assert body["csv_bytes"] > 0

    listed = client.get(
        f"/api/v1/reports/{report['id']}/schedules", headers=acme_admin["headers"]
    )
    updated = next(s for s in listed.json() if s["id"] == schedule["id"])
    assert updated["last_status"] == "success"
    assert updated["last_row_count"] == 2
    assert updated["last_run_at"] is not None

    # Inactive schedules refuse a manual run.
    client.patch(
        f"/api/v1/reports/{report['id']}/schedules/{schedule['id']}",
        json={"is_active": False},
        headers=acme_admin["headers"],
    )
    resp = client.post(
        f"/api/v1/reports/{report['id']}/schedules/{schedule['id']}/run",
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 400, resp.text


def test_scheduled_report_celery_task(client, acme_admin):
    """The Celery task invoked directly (no worker): same code path as
    the beat schedule will use."""
    from app.services.reporting_service import generate_scheduled_report

    category = f"tcat-{_uid()}"
    _make_ticket(client, acme_admin["headers"], category=category)
    report = _make_report(
        client, acme_admin["headers"], "tickets", ["number", "title"],
        filters={"category": category},
    )
    schedule = _make_schedule(client, acme_admin["headers"], report["id"])

    result = generate_scheduled_report.run(schedule["id"])
    assert result["status"] == "success", result
    assert result["row_count"] == 1

    listed = client.get(
        f"/api/v1/reports/{report['id']}/schedules", headers=acme_admin["headers"]
    )
    updated = next(s for s in listed.json() if s["id"] == schedule["id"])
    assert updated["last_status"] == "success"
    assert updated["last_row_count"] == 1

    # Unknown id fails honestly; inactive schedules are skipped.
    missing = generate_scheduled_report.run(str(uuid.uuid4()))
    assert missing["status"] == "failed"
    client.patch(
        f"/api/v1/reports/{report['id']}/schedules/{schedule['id']}",
        json={"is_active": False},
        headers=acme_admin["headers"],
    )
    skipped = generate_scheduled_report.run(schedule["id"])
    assert skipped["status"] == "skipped"
