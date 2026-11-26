"""CMDB + network operations tests (Phase 3, workstream D).

Covers: CI CRUD + relationship validation + graph depth-2, device /
interface / topology CRUD + SNMP community handling, metrics append-only
+ derived health, events + acknowledge, certificate expiry derivation,
real discovery against 127.0.0.1/32, tenant isolation, permissions, and
the ``null.tasks.check_network_health`` Celery task (invoked directly,
synchronously — no worker needed).

The coordinator registers the cmdb/network routers in app/main.py; until
then this module mounts them itself (guarded, so a later main.py
registration does not double-mount).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from app.main import app
from app.routers import cmdb as cmdb_router
from app.routers import network as network_router
from tests.conftest import set_rls

if not any(getattr(r, "path", "").startswith("/api/v1/cmdb") for r in app.routes):
    app.include_router(cmdb_router.router)
if not any(getattr(r, "path", "").startswith("/api/v1/network") for r in app.routes):
    app.include_router(network_router.router)

UTC = timezone.utc


def _uid() -> str:
    return uuid.uuid4().hex[:8]


# --- Helpers ----------------------------------------------------------------


def _make_ci(client, headers, name=None, ci_type="server", **extra):
    body = {"name": name or f"ci-{_uid()}", "ci_type": ci_type}
    body.update(extra)
    resp = client.post("/api/v1/cmdb/items", json=body, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _make_device(client, headers, hostname=None, ip=None, **extra):
    body = {"hostname": hostname or f"dev-{_uid()}", "device_type": "switch"}
    if ip is not None:
        body["ip_address"] = ip
    body.update(extra)
    resp = client.post("/api/v1/network/devices", json=body, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _make_asset(client, headers):
    resp = client.post(
        "/api/v1/assets",
        json={"asset_tag": f"AST-{_uid()}", "name": f"asset-{_uid()}", "type": "server"},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


# --- CMDB: CRUD -------------------------------------------------------------


def test_ci_crud_and_filters(client, acme_admin):
    h = acme_admin["headers"]
    ci = _make_ci(client, h, ci_type="server", attributes={"rack": "A1"})
    assert ci["status"] == "active"
    assert ci["attributes"] == {"rack": "A1"}

    got = client.get(f"/api/v1/cmdb/items/{ci['id']}", headers=h)
    assert got.status_code == 200, got.text
    detail = got.json()
    assert detail["name"] == ci["name"]
    assert detail["asset"] is None and detail["endpoint"] is None
    assert detail["relationships"] == []

    patched = client.patch(
        f"/api/v1/cmdb/items/{ci['id']}",
        json={"name": ci["name"] + "-renamed", "status": "inactive"},
        headers=h,
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["name"].endswith("-renamed")
    assert patched.json()["status"] == "inactive"

    listed = client.get("/api/v1/cmdb/items?ci_type=server", headers=h)
    assert listed.status_code == 200
    assert all(row["ci_type"] == "server" for row in listed.json())
    assert any(row["id"] == ci["id"] for row in listed.json())

    searched = client.get(f"/api/v1/cmdb/items?search={ci['name'][:12]}", headers=h)
    assert any(row["id"] == ci["id"] for row in searched.json())

    deleted = client.delete(f"/api/v1/cmdb/items/{ci['id']}", headers=h)
    assert deleted.status_code == 204, deleted.text
    assert client.get(f"/api/v1/cmdb/items/{ci['id']}", headers=h).status_code == 404


def test_ci_create_validates_links_and_enums(client, acme_admin):
    h = acme_admin["headers"]
    asset = _make_asset(client, h)

    linked = _make_ci(client, h, asset_id=asset["id"])
    assert linked["asset_id"] == asset["id"]
    detail = client.get(f"/api/v1/cmdb/items/{linked['id']}", headers=h).json()
    assert detail["asset"]["asset_tag"] == asset["asset_tag"]

    bad_asset = client.post(
        "/api/v1/cmdb/items",
        json={"name": f"ci-{_uid()}", "asset_id": str(uuid.uuid4())},
        headers=h,
    )
    assert bad_asset.status_code == 404, bad_asset.text

    bad_endpoint = client.post(
        "/api/v1/cmdb/items",
        json={"name": f"ci-{_uid()}", "endpoint_id": str(uuid.uuid4())},
        headers=h,
    )
    assert bad_endpoint.status_code == 404, bad_endpoint.text

    bad_type = client.post("/api/v1/cmdb/items", json={"name": f"ci-{_uid()}", "ci_type": "nope"}, headers=h)
    assert bad_type.status_code == 400, bad_type.text

    bad_status = client.post("/api/v1/cmdb/items", json={"name": f"ci-{_uid()}", "status": "nope"}, headers=h)
    assert bad_status.status_code == 400, bad_status.text


def test_ci_permissions(client, acme_admin, acme_tech):
    assert client.get("/api/v1/cmdb/items", headers=acme_tech["headers"]).status_code == 403
    assert (
        client.post("/api/v1/cmdb/items", json={"name": f"ci-{_uid()}"}, headers=acme_tech["headers"]).status_code
        == 403
    )
    # Admin (and globex IT Ops tech) can read; acme tech cannot.
    assert client.get("/api/v1/cmdb/items", headers=acme_admin["headers"]).status_code == 200


# --- CMDB: relationships + graph --------------------------------------------


def test_relationship_validation(client, acme_admin, globex_admin):
    h = acme_admin["headers"]
    a = _make_ci(client, h, ci_type="application")
    b = _make_ci(client, h, ci_type="server")
    foreign = _make_ci(client, globex_admin["headers"], ci_type="database")

    self_link = client.post(
        f"/api/v1/cmdb/items/{a['id']}/relationships",
        json={"target_ci_id": a["id"], "relationship_type": "depends_on"},
        headers=h,
    )
    assert self_link.status_code == 400, self_link.text

    cross_org = client.post(
        f"/api/v1/cmdb/items/{a['id']}/relationships",
        json={"target_ci_id": foreign["id"], "relationship_type": "depends_on"},
        headers=h,
    )
    assert cross_org.status_code == 404, cross_org.text

    bad_type = client.post(
        f"/api/v1/cmdb/items/{a['id']}/relationships",
        json={"target_ci_id": b["id"], "relationship_type": "teleports_to"},
        headers=h,
    )
    assert bad_type.status_code == 400, bad_type.text

    created = client.post(
        f"/api/v1/cmdb/items/{a['id']}/relationships",
        json={"target_ci_id": b["id"], "relationship_type": "depends_on"},
        headers=h,
    )
    assert created.status_code == 201, created.text
    rel = created.json()
    assert rel["source_ci_id"] == a["id"] and rel["target_ci_id"] == b["id"]

    duplicate = client.post(
        f"/api/v1/cmdb/items/{a['id']}/relationships",
        json={"target_ci_id": b["id"], "relationship_type": "depends_on"},
        headers=h,
    )
    assert duplicate.status_code == 400, duplicate.text

    listed = client.get(f"/api/v1/cmdb/items/{a['id']}/relationships", headers=h)
    assert listed.status_code == 200
    assert len(listed.json()) == 1
    assert listed.json()[0]["direction"] == "outgoing"
    listed_b = client.get(f"/api/v1/cmdb/items/{b['id']}/relationships", headers=h)
    assert listed_b.json()[0]["direction"] == "incoming"

    deleted = client.delete(f"/api/v1/cmdb/relationships/{rel['id']}", headers=h)
    assert deleted.status_code == 204, deleted.text
    assert client.delete(f"/api/v1/cmdb/relationships/{rel['id']}", headers=h).status_code == 404
    assert client.get(f"/api/v1/cmdb/items/{a['id']}/relationships", headers=h).json() == []


def test_ci_graph_depth2(client, acme_admin):
    h = acme_admin["headers"]
    a = _make_ci(client, h)
    b = _make_ci(client, h)
    c = _make_ci(client, h)
    d = _make_ci(client, h)
    for src, dst in ((a, b), (b, c), (c, d)):
        resp = client.post(
            f"/api/v1/cmdb/items/{src['id']}/relationships",
            json={"target_ci_id": dst["id"], "relationship_type": "depends_on"},
            headers=h,
        )
        assert resp.status_code == 201, resp.text

    graph = client.get(f"/api/v1/cmdb/items/{a['id']}/graph", headers=h)
    assert graph.status_code == 200, graph.text
    body = graph.json()
    node_ids = {n["id"] for n in body["nodes"]}
    assert node_ids == {a["id"], b["id"], c["id"]}, body  # depth 2: d excluded
    assert len(body["edges"]) == 2
    assert {e["source_ci_id"] for e in body["edges"]} == {a["id"], b["id"]}

    assert client.get(f"/api/v1/cmdb/items/{uuid.uuid4()}/graph", headers=h).status_code == 404


def test_ci_delete_cascades_relationships(client, acme_admin):
    h = acme_admin["headers"]
    a = _make_ci(client, h)
    b = _make_ci(client, h)
    rel = client.post(
        f"/api/v1/cmdb/items/{a['id']}/relationships",
        json={"target_ci_id": b["id"], "relationship_type": "hosts"},
        headers=h,
    )
    assert rel.status_code == 201, rel.text
    assert client.delete(f"/api/v1/cmdb/items/{a['id']}", headers=h).status_code == 204
    # The relationship is gone with its source CI; b survives with no edges.
    assert client.get(f"/api/v1/cmdb/items/{b['id']}/relationships", headers=h).json() == []
    assert client.get(f"/api/v1/cmdb/items/{b['id']}", headers=h).status_code == 200


def test_ci_tenant_isolation(client, acme_admin, globex_admin):
    foreign = _make_ci(client, globex_admin["headers"])
    assert client.get(f"/api/v1/cmdb/items/{foreign['id']}", headers=acme_admin["headers"]).status_code == 404
    listed = client.get("/api/v1/cmdb/items", headers=acme_admin["headers"]).json()
    assert all(row["id"] != foreign["id"] for row in listed)
    assert client.delete(f"/api/v1/cmdb/items/{foreign['id']}", headers=acme_admin["headers"]).status_code == 404


# --- Network: devices -------------------------------------------------------


def test_device_crud_and_community_never_returned(client, acme_admin):
    h = acme_admin["headers"]
    device = _make_device(client, h, ip="10.20.30.40", vendor="Cisco", model="Catalyst 9300")
    assert "snmp_community" not in device
    assert "snmp_community_encrypted" not in device
    assert device["has_snmp_community"] is False
    assert device["status"] == "unknown"

    got = client.get(f"/api/v1/network/devices/{device['id']}", headers=h).json()
    assert "snmp_community" not in got and "snmp_community_encrypted" not in got

    patched = client.patch(
        f"/api/v1/network/devices/{device['id']}",
        json={"status": "up", "os_version": "17.9.1"},
        headers=h,
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["status"] == "up"
    assert patched.json()["os_version"] == "17.9.1"

    listed = client.get("/api/v1/network/devices?device_type=switch", headers=h)
    assert all(row["device_type"] == "switch" for row in listed.json())
    assert any(row["id"] == device["id"] for row in listed.json())
    searched = client.get(f"/api/v1/network/devices?search={device['hostname'][:10]}", headers=h)
    assert any(row["id"] == device["id"] for row in searched.json())

    assert client.delete(f"/api/v1/network/devices/{device['id']}", headers=h).status_code == 204
    assert client.get(f"/api/v1/network/devices/{device['id']}", headers=h).status_code == 404


def test_device_community_requires_encryption_key(client, acme_admin):
    # No NULL_FIELD_ENCRYPTION_KEY is configured in the test env, so
    # storing a reversible community must fail closed with 503 — never
    # plaintext.
    resp = client.post(
        "/api/v1/network/devices",
        json={"hostname": f"dev-{_uid()}", "device_type": "router", "snmp_community": "public"},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 503, resp.text
    assert client.get("/api/v1/network/devices", headers=acme_admin["headers"]).status_code == 200


def test_device_validation(client, acme_admin):
    h = acme_admin["headers"]
    assert (
        client.post("/api/v1/network/devices", json={"hostname": "x", "device_type": "toaster"}, headers=h).status_code
        == 400
    )
    assert (
        client.post(
            "/api/v1/network/devices",
            json={"hostname": "x", "device_type": "router", "ip_address": "999.1.1.1"},
            headers=h,
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/api/v1/network/devices", json={"hostname": "x", "device_type": "router", "snmp_version": "v9"}, headers=h
        ).status_code
        == 400
    )


def test_network_permissions(client, acme_admin, acme_tech, globex_tech):
    assert client.get("/api/v1/network/devices", headers=acme_tech["headers"]).status_code == 403
    assert client.get("/api/v1/network/devices", headers=globex_tech["headers"]).status_code == 403
    assert (
        client.post("/api/v1/network/discover", json={"cidr": "127.0.0.1/32"}, headers=acme_tech["headers"]).status_code
        == 403
    )
    assert client.get("/api/v1/network/devices", headers=acme_admin["headers"]).status_code == 200


# --- Network: interfaces + topology -----------------------------------------


def test_interface_crud(client, acme_admin):
    h = acme_admin["headers"]
    device = _make_device(client, h)
    other = _make_device(client, h)

    iface = client.post(
        f"/api/v1/network/devices/{device['id']}/interfaces",
        json={"name": "GigabitEthernet1/0/1", "if_index": 1, "speed_mbps": 1000, "status": "up"},
        headers=h,
    )
    assert iface.status_code == 201, iface.text
    iface = iface.json()
    assert iface["device_id"] == device["id"]

    listed = client.get(f"/api/v1/network/devices/{device['id']}/interfaces", headers=h)
    assert [row["id"] for row in listed.json()] == [iface["id"]]

    patched = client.patch(
        f"/api/v1/network/interfaces/{iface['id']}", json={"status": "down", "speed_mbps": 100}, headers=h
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["status"] == "down"

    # Interface on a foreign device: 404.
    assert (
        client.post(
            f"/api/v1/network/devices/{other['id']}/interfaces",
            json={"name": "x"},
            headers=h,
        ).status_code
        == 201
    )
    assert client.get(f"/api/v1/network/devices/{uuid.uuid4()}/interfaces", headers=h).status_code == 404

    assert client.delete(f"/api/v1/network/interfaces/{iface['id']}", headers=h).status_code == 204
    assert client.delete(f"/api/v1/network/interfaces/{iface['id']}", headers=h).status_code == 404


def test_topology_links(client, acme_admin, globex_admin):
    h = acme_admin["headers"]
    a = _make_device(client, h)
    b = _make_device(client, h)
    foreign = _make_device(client, globex_admin["headers"])
    iface_a = client.post(f"/api/v1/network/devices/{a['id']}/interfaces", json={"name": "eth0"}, headers=h).json()
    iface_b = client.post(f"/api/v1/network/devices/{b['id']}/interfaces", json={"name": "eth0"}, headers=h).json()

    link = client.post(
        "/api/v1/network/topology/links",
        json={
            "source_device_id": a["id"],
            "source_interface_id": iface_a["id"],
            "target_device_id": b["id"],
            "target_interface_id": iface_b["id"],
            "link_type": "ethernet",
        },
        headers=h,
    )
    assert link.status_code == 201, link.text
    link = link.json()

    duplicate = client.post(
        "/api/v1/network/topology/links",
        json={
            "source_device_id": a["id"],
            "source_interface_id": iface_a["id"],
            "target_device_id": b["id"],
            "target_interface_id": iface_b["id"],
        },
        headers=h,
    )
    assert duplicate.status_code == 400, duplicate.text

    reverse = client.post(
        "/api/v1/network/topology/links",
        json={
            "source_device_id": b["id"],
            "source_interface_id": iface_b["id"],
            "target_device_id": a["id"],
            "target_interface_id": iface_a["id"],
        },
        headers=h,
    )
    assert reverse.status_code == 400, reverse.text

    cross_org = client.post(
        "/api/v1/network/topology/links",
        json={"source_device_id": a["id"], "target_device_id": foreign["id"]},
        headers=h,
    )
    assert cross_org.status_code == 404, cross_org.text

    wrong_iface = client.post(
        "/api/v1/network/topology/links",
        json={
            "source_device_id": a["id"],
            "source_interface_id": iface_b["id"],  # belongs to b, not a
            "target_device_id": b["id"],
        },
        headers=h,
    )
    assert wrong_iface.status_code == 400, wrong_iface.text

    self_link = client.post(
        "/api/v1/network/topology/links",
        json={"source_device_id": a["id"], "target_device_id": a["id"]},
        headers=h,
    )
    assert self_link.status_code == 400, self_link.text

    topo = client.get("/api/v1/network/topology", headers=h)
    assert topo.status_code == 200, topo.text
    assert any(li["id"] == link["id"] for li in topo.json()["links"])
    assert any(d["id"] == a["id"] for d in topo.json()["devices"])

    assert client.delete(f"/api/v1/network/topology/links/{link['id']}", headers=h).status_code == 204
    assert client.delete(f"/api/v1/network/topology/links/{link['id']}", headers=h).status_code == 404


# --- Network: service dependencies ------------------------------------------


def test_service_dependencies(client, acme_admin):
    h = acme_admin["headers"]
    ci = _make_ci(client, h, ci_type="service")
    dep = client.post(
        "/api/v1/network/service-dependencies",
        json={"service_name": f"vpn-{_uid()}", "ci_id": ci["id"], "criticality": "high"},
        headers=h,
    )
    assert dep.status_code == 201, dep.text
    dep = dep.json()
    assert dep["dependency_type"] == "depends_on"

    filtered = client.get(f"/api/v1/network/service-dependencies?service_name={dep['service_name'][:6]}", headers=h)
    assert any(row["id"] == dep["id"] for row in filtered.json())

    patched = client.patch(
        f"/api/v1/network/service-dependencies/{dep['id']}", json={"criticality": "critical"}, headers=h
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["criticality"] == "critical"

    bad_ci = client.post(
        "/api/v1/network/service-dependencies",
        json={"service_name": f"svc-{_uid()}", "ci_id": str(uuid.uuid4())},
        headers=h,
    )
    assert bad_ci.status_code == 404, bad_ci.text

    assert client.delete(f"/api/v1/network/service-dependencies/{dep['id']}", headers=h).status_code == 204
    assert client.delete(f"/api/v1/network/service-dependencies/{dep['id']}", headers=h).status_code == 404


# --- Network: metrics + health ----------------------------------------------


def test_metrics_append_only_and_health(client, acme_admin):
    h = acme_admin["headers"]
    device = _make_device(client, h)
    now = datetime.now(UTC)

    batch = client.post(
        "/api/v1/network/metrics",
        json={
            "samples": [
                {
                    "device_id": device["id"],
                    "metric_type": "cpu",
                    "value": 42.5,
                    "recorded_at": (now - timedelta(hours=1)).isoformat(),
                },
                {"device_id": device["id"], "metric_type": "cpu", "value": 55.0, "recorded_at": now.isoformat()},
                {"device_id": device["id"], "metric_type": "memory", "value": 71.25},
            ]
        },
        headers=h,
    )
    assert batch.status_code == 201, batch.text
    assert len(batch.json()) == 3

    metrics = client.get(f"/api/v1/network/devices/{device['id']}/metrics", headers=h)
    assert metrics.status_code == 200, metrics.text
    rows = metrics.json()
    assert len(rows) == 3
    # Newest first.
    assert rows[0]["recorded_at"] >= rows[-1]["recorded_at"]
    # Append-only: the first cpu sample is unchanged by the second.
    cpu_rows = [r for r in rows if r["metric_type"] == "cpu"]
    assert sorted(r["value"] for r in cpu_rows) == [42.5, 55.0]

    cpu_only = client.get(f"/api/v1/network/devices/{device['id']}/metrics?metric_type=cpu", headers=h)
    assert len(cpu_only.json()) == 2
    windowed = client.get(
        f"/api/v1/network/devices/{device['id']}/metrics?since={(now - timedelta(minutes=30)).isoformat()}",
        headers=h,
    )
    assert len(windowed.json()) == 2  # the hour-old cpu sample is outside the window

    # Ingest refreshes last_seen_at.
    assert client.get(f"/api/v1/network/devices/{device['id']}", headers=h).json()["last_seen_at"] is not None

    health = client.get(f"/api/v1/network/devices/{device['id']}/health", headers=h)
    assert health.status_code == 200, health.text
    body = health.json()
    assert body["latest_metrics"]["cpu"]["value"] == 55.0
    assert body["latest_metrics"]["memory"]["value"] == 71.25
    assert body["unacknowledged_critical_events"] == 0

    # One unacknowledged + one acknowledged critical event -> count is 1.
    client.post(
        "/api/v1/network/events",
        json={"device_id": device["id"], "event_type": "outage", "severity": "critical", "message": "link down"},
        headers=h,
    ).json()
    acked = client.post(
        "/api/v1/network/events",
        json={"device_id": device["id"], "event_type": "syslog", "severity": "critical", "message": "old"},
        headers=h,
    ).json()
    assert client.post(f"/api/v1/network/events/{acked['id']}/acknowledge", headers=h).status_code == 200
    health = client.get(f"/api/v1/network/devices/{device['id']}/health", headers=h).json()
    assert health["unacknowledged_critical_events"] == 1


def test_metrics_reject_foreign_device(client, acme_admin, globex_admin):
    foreign = _make_device(client, globex_admin["headers"])
    resp = client.post(
        "/api/v1/network/metrics",
        json={"samples": [{"device_id": foreign["id"], "metric_type": "cpu", "value": 1.0}]},
        headers=acme_admin["headers"],
    )
    assert resp.status_code == 404, resp.text
    assert (
        client.post(
            "/api/v1/network/metrics",
            json={"samples": [{"device_id": str(uuid.uuid4()), "metric_type": "nope", "value": 1.0}]},
            headers=acme_admin["headers"],
        ).status_code
        == 404
    )


# --- Network: events ----------------------------------------------------------


def test_events_acknowledge(client, acme_admin, globex_admin):
    h = acme_admin["headers"]
    device = _make_device(client, h)
    event = client.post(
        "/api/v1/network/events",
        json={
            "device_id": device["id"],
            "event_type": "syslog",
            "severity": "warning",
            "message": "interface flapping",
            "source_ip": "10.0.0.1",
        },
        headers=h,
    )
    assert event.status_code == 201, event.text
    event = event.json()
    assert event["acknowledged_at"] is None

    listed = client.get("/api/v1/network/events?severity=warning&acknowledged=false", headers=h)
    assert any(row["id"] == event["id"] for row in listed.json())

    acked = client.post(f"/api/v1/network/events/{event['id']}/acknowledge", headers=h)
    assert acked.status_code == 200, acked.text
    assert acked.json()["acknowledged_at"] is not None
    assert acked.json()["acknowledged_by_id"] is not None

    again = client.post(f"/api/v1/network/events/{event['id']}/acknowledge", headers=h)
    assert again.status_code == 400, again.text

    foreign_event = client.post(
        "/api/v1/network/events",
        json={"event_type": "other", "severity": "info", "message": "globex event"},
        headers=globex_admin["headers"],
    ).json()
    assert client.get(f"/api/v1/network/events?device_id={device['id']}", headers=h).status_code == 200
    assert client.post(f"/api/v1/network/events/{foreign_event['id']}/acknowledge", headers=h).status_code == 404

    bad_type = client.post(
        "/api/v1/network/events",
        json={"event_type": "teleport", "severity": "info", "message": "x"},
        headers=h,
    )
    assert bad_type.status_code == 400, bad_type.text


# --- Network: certificates ----------------------------------------------------


def test_certificates_expiring_derived(client, acme_admin):
    h = acme_admin["headers"]
    now = datetime.now(UTC)
    soon = client.post(
        "/api/v1/network/certificates",
        json={"hostname": f"soon-{_uid()}.example.com", "expires_at": (now + timedelta(days=10)).isoformat()},
        headers=h,
    )
    assert soon.status_code == 201, soon.text
    soon = soon.json()
    later = client.post(
        "/api/v1/network/certificates",
        json={"hostname": f"later-{_uid()}.example.com", "expires_at": (now + timedelta(days=90)).isoformat()},
        headers=h,
    ).json()
    already_expired = client.post(
        "/api/v1/network/certificates",
        json={
            "hostname": f"dead-{_uid()}.example.com",
            "expires_at": (now + timedelta(days=5)).isoformat(),
            "status": "expired",
        },
        headers=h,
    ).json()

    expiring = client.get("/api/v1/network/certificates/expiring", headers=h)
    assert expiring.status_code == 200, expiring.text
    ids = {row["id"] for row in expiring.json()}
    assert soon["id"] in ids
    assert later["id"] not in ids
    assert already_expired["id"] not in ids  # status == expired is excluded

    patched = client.patch(f"/api/v1/network/certificates/{later['id']}", json={"status": "expiring"}, headers=h)
    assert patched.status_code == 200 and patched.json()["status"] == "expiring"
    assert client.delete(f"/api/v1/network/certificates/{later['id']}", headers=h).status_code == 204
    assert client.delete(f"/api/v1/network/certificates/{later['id']}", headers=h).status_code == 404


# --- Network: discovery -------------------------------------------------------


def test_discovery_localhost(client, acme_admin):
    h = acme_admin["headers"]
    resp = client.post("/api/v1/network/discover", json={"cidr": "127.0.0.1/32"}, headers=h)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["discovered"] + body["updated"] >= 1, body
    assert body["unreachable"] == 0, body
    assert body["snmp_available"] is False  # pysnmp is not installed
    assert body["snmp_note"] == "snmp_unavailable"

    devices = client.get("/api/v1/network/devices?search=127.0.0.1", headers=h).json()
    assert len(devices) >= 1
    assert any(d["ip_address"] == "127.0.0.1" and d["status"] == "up" for d in devices)

    # Second run refreshes the same device instead of duplicating it.
    again = client.post("/api/v1/network/discover", json={"cidr": "127.0.0.1/32"}, headers=h)
    assert again.status_code == 200, again.text
    assert again.json()["discovered"] == 0, again.json()
    assert again.json()["updated"] >= 1, again.json()


def test_discovery_rejects_bad_cidrs(client, acme_admin):
    h = acme_admin["headers"]
    for cidr, why in (
        ("10.0.0.0/16", "larger than /24"),
        ("10.0.0.0/23", "larger than /24"),
        ("not-a-cidr", "invalid"),
        ("10.0.0.0/33", "invalid"),
    ):
        resp = client.post("/api/v1/network/discover", json={"cidr": cidr}, headers=h)
        assert resp.status_code == 400, (why, resp.text)
    resp = client.post("/api/v1/network/discover", json={"cidr": "127.0.0.1/32", "timeout_seconds": 99}, headers=h)
    assert resp.status_code == 422, resp.text  # pydantic le=10


# --- Network: tenant isolation -------------------------------------------------


def test_network_tenant_isolation(client, acme_admin, globex_admin):
    foreign_device = _make_device(client, globex_admin["headers"], ip="10.99.99.99")
    foreign_cert = client.post(
        "/api/v1/network/certificates",
        json={"hostname": f"gx-{_uid()}.example.com"},
        headers=globex_admin["headers"],
    ).json()
    foreign_event = client.post(
        "/api/v1/network/events",
        json={"device_id": foreign_device["id"], "event_type": "other", "severity": "info", "message": "gx"},
        headers=globex_admin["headers"],
    ).json()

    h = acme_admin["headers"]
    assert client.get(f"/api/v1/network/devices/{foreign_device['id']}", headers=h).status_code == 404
    assert client.get(f"/api/v1/network/devices/{foreign_device['id']}/health", headers=h).status_code == 404
    assert client.get(f"/api/v1/network/devices/{foreign_device['id']}/metrics", headers=h).status_code == 404
    resp = client.patch(f"/api/v1/network/certificates/{foreign_cert['id']}", json={"status": "expired"}, headers=h)
    assert resp.status_code == 404
    assert client.get(f"/api/v1/network/events?device_id={foreign_device['id']}", headers=h).json() == []
    assert client.post(f"/api/v1/network/events/{foreign_event['id']}/acknowledge", headers=h).status_code == 404
    listed = client.get("/api/v1/network/devices", headers=h).json()
    assert all(row["id"] != foreign_device["id"] for row in listed)


# --- Celery task: network health sweep -----------------------------------------


def _set_last_seen(app_db, org_id: str, device_id: str, when: datetime) -> None:
    set_rls(app_db, org_id)
    with app_db.cursor() as cur:
        cur.execute(
            "UPDATE network_devices SET last_seen_at = %s WHERE id = %s",
            (when, device_id),
        )


def test_check_network_health_task(client, acme_admin, org_ids, app_db):
    from app.tasks.network_tasks import check_network_health

    h = acme_admin["headers"]
    acme_org = org_ids["acme"]
    stale = _make_device(client, h, ip="10.44.44.44")
    assert client.patch(f"/api/v1/network/devices/{stale['id']}", json={"status": "up"}, headers=h).status_code == 200
    _set_last_seen(app_db, acme_org, stale["id"], datetime.now(UTC) - timedelta(hours=2))

    fresh = _make_device(client, h, ip="10.44.44.45")
    assert client.patch(f"/api/v1/network/devices/{fresh['id']}", json={"status": "up"}, headers=h).status_code == 200
    client.post(
        "/api/v1/network/metrics",
        json={"samples": [{"device_id": fresh["id"], "metric_type": "cpu", "value": 10.0}]},
        headers=h,
    )  # metric ingest refreshes last_seen_at to now

    result = check_network_health()
    assert result["orgs"] >= 2, result
    assert result["devices_marked_down"] >= 1, result
    assert result["events_created"] >= 1, result

    assert client.get(f"/api/v1/network/devices/{stale['id']}", headers=h).json()["status"] == "down"
    assert client.get(f"/api/v1/network/devices/{fresh['id']}", headers=h).json()["status"] == "up"

    events = client.get(f"/api/v1/network/events?device_id={stale['id']}&event_type=outage", headers=h).json()
    assert len(events) == 1, events
    assert events[0]["severity"] == "critical"

    # Second run: idempotent — no second outage event for the same episode.
    check_network_health()
    events = client.get(f"/api/v1/network/events?device_id={stale['id']}&event_type=outage", headers=h).json()
    assert len(events) == 1, events
