"""Coletor SNMP contra um snmpd (net-snmp) real e o TimescaleDB de teste.

Precisa de ``OPENMON_TEST_PG`` e ``OPENMON_TEST_SNMP=host:porta`` de um snmpd com
comunidade ``public-om`` e o usuário v3 ``omuser`` (SHA/AES, senhas abaixo).
"""
import asyncio
import os

import pytest

from openmon import vault
from openmon.collector import engine
from openmon.db import pool

from pgsupport import requires_pg, sql
from test_admin_tenants import client, database, h, login, new_tenant, new_user, TEMP_PW  # noqa: F401

SNMP = os.environ.get("OPENMON_TEST_SNMP", "")
pytestmark = [requires_pg, pytest.mark.skipif(not SNMP, reason="OPENMON_TEST_SNMP não definido")]
HOST, PORT = (SNMP.rsplit(":", 1) + ["161"])[:2] if SNMP else ("", "161")


@pytest.fixture(autouse=True)
def master_key(tmp_path, monkeypatch):
    path = tmp_path / "master.key"
    path.write_bytes(os.urandom(32))
    monkeypatch.setenv("OPENMON_MASTER_KEY_FILE", str(path))
    vault.reset()
    sql("DELETE FROM integrations")
    yield
    vault.reset()


def snmp_body(tenant_id, version="2c", **over):
    body = {"kind": "snmp", "name": f"switch-{version}", "tenant_id": tenant_id, "endpoint": HOST, "port": int(PORT),
            "options": {"version": version, "asset_type": "network_switch", "timeout_ms": 1000, "retries": 1}}
    if version == "2c":
        body["secret"] = "public-om"
    else:
        body.update(username="omuser", auth_protocol="sha", auth_password="AuthPass-12345", priv_protocol="aes",
                    priv_password="PrivPass-12345")
    body.update(over)
    return body


def test_snmp_v2c_and_v3_test_poll_and_tenant_isolation(client):
    csrf, _ = login(client)
    acme = new_tenant(client, csrf)
    for version in ("2c", "3"):
        r = client.post("/api/admin/integrations/test", json=snmp_body(acme["id"], version), headers=h(csrf))
        assert r.status_code == 200 and r.json()["ok"], r.text
        assert "interface" in r.json()["summary"]
    bad = client.post("/api/admin/integrations/test", json=snmp_body(acme["id"], "3", auth_password="Errada-123456"),
                      headers=h(csrf)).json()
    assert not bad["ok"] and "wrongDigests" in bad["error"]

    r = client.post("/api/admin/integrations", json=snmp_body(acme["id"], "3"), headers=h(csrf))
    assert r.status_code == 201, r.text
    integ = r.json()["integration"]
    assert integ["has_secret"] and "auth_password" not in integ and integ["auth_protocol"] == "sha"
    assert b"AuthPass" not in bytes(sql("SELECT ciphertext FROM credentials")[0][0])

    # Duas coletas: a segunda já calcula tráfego pelos deltas dos contadores
    for _ in range(2):
        out = client.post(f"/api/admin/integrations/{integ['id']}/poll", headers=h(csrf)).json()
        assert out["status"] == "ok", out
        asyncio.run(asyncio.sleep(1.1))
    assert sql("SELECT count(*) FROM interface_samples")[0][0] >= 1
    assert sql("SELECT count(*) FROM metric_samples WHERE metric_id = 40 AND value = 1")[0][0] == 2
    listed = client.get("/api/admin/integrations").json()["integrations"][0]
    assert listed["last_status"] == "ok" and listed["assets"] == 1

    assets = client.get("/api/assets").json()["assets"]
    assert len(assets) == 1 and assets[0]["tenant_name"] == "ACME S.A." and assets[0]["status"] == "up"
    detail = client.get(f"/api/assets/{assets[0]['id']}").json()
    assert detail["interfaces"] and any(i["is_monitored"] for i in detail["interfaces"])

    # Editar sem reenviar as senhas mantém as do cofre
    body = snmp_body(acme["id"], "3", auth_password=None, priv_password=None, poll_interval_seconds=120)
    assert client.put(f"/api/admin/integrations/{integ['id']}", json=body, headers=h(csrf)).status_code == 200
    assert client.post(f"/api/admin/integrations/{integ['id']}/poll", headers=h(csrf)).json()["status"] == "ok"

    # Cliente de outro tenant não vê o switch; o da ACME vê
    beta = new_tenant(client, csrf, "beta", "Beta")
    new_user(client, csrf, "cli-beta", tenant_ids=[beta["id"]], must_change_password=False)
    new_user(client, csrf, "cli-acme", tenant_ids=[acme["id"]], must_change_password=False)
    login(client, "cli-beta", TEMP_PW)
    assert client.get("/api/assets").json()["assets"] == []
    assert client.get(f"/api/assets/{assets[0]['id']}").status_code == 404
    assert client.get("/api/admin/integrations").status_code == 403
    login(client, "cli-acme", TEMP_PW)
    assert len(client.get("/api/assets").json()["assets"]) == 1


def test_unreachable_device_is_marked_down(client):
    csrf, _ = login(client)
    t = new_tenant(client, csrf)
    r = client.post("/api/admin/integrations", json=snmp_body(t["id"]), headers=h(csrf))
    iid = r.json()["integration"]["id"]
    assert client.post(f"/api/admin/integrations/{iid}/poll", headers=h(csrf)).json()["status"] == "ok"
    sql("UPDATE integrations SET port = 9 WHERE id = %s", iid)
    out = client.post(f"/api/admin/integrations/{iid}/poll", headers=h(csrf)).json()
    assert out["status"] == "error" and ("timeout" in out["message"] or "recusou" in out["message"])
    assert sql("SELECT status FROM assets")[0][0] == "down"
    assert sql("SELECT last_status FROM integrations")[0][0] == "error"


def test_engine_claims_due_integrations_once(client):
    csrf, _ = login(client)
    t = new_tenant(client, csrf)
    iid = client.post("/api/admin/integrations", json=snmp_body(t["id"]), headers=h(csrf)).json()["integration"]["id"]

    async def go():
        due = await engine.due("snmp", set())
        results = await asyncio.gather(engine.poll_once(iid), engine.poll_once(iid))
        return due, sorted(r[0] for r in results), await engine.due("snmp", set())
    due, statuses, after = client.portal.call(go)
    assert due == [iid] and statuses == ["ok", "skipped"] and after == []
    assert pool  # pool real do teste


def test_customer_link_visible_to_client_without_the_switch(client):
    csrf, _ = login(client)
    acme = new_tenant(client, csrf)
    provider = sql("SELECT id FROM tenants WHERE is_provider")[0][0]
    iid = client.post("/api/admin/integrations", json=snmp_body(provider), headers=h(csrf)).json()["integration"]["id"]
    assert client.post(f"/api/admin/integrations/{iid}/poll", headers=h(csrf)).json()["status"] == "ok"
    asset = client.get(f"/api/assets?integration_id={iid}").json()["assets"][0]
    f = client.get(f"/api/assets/{asset['id']}").json()["interfaces"][-1]
    body = {"is_monitored": True, "is_customer_link": True, "tenant_id": acme["id"], "contracted_bps": 500_000_000}
    assert client.put(f"/api/admin/interfaces/{f['id']}", json=body, headers=h(csrf)).status_code == 200
    links = client.get("/api/assets").json()["links"]
    assert [(x["id"], x["asset_name"], x["tenant_id"]) for x in links] == [(f["id"], asset["name"], acme["id"])]
    assert client.get("/api/assets?integration_id=999999").json()["assets"] == []

    # Trocar o tenant do switch não leva junto o link do cliente
    beta = new_tenant(client, csrf, "beta", "Beta")
    r = client.put(f"/api/admin/assets/{asset['id']}", json={"tenant_id": beta["id"]}, headers=h(csrf))
    assert r.status_code == 200
    assert sql("SELECT tenant_id FROM interfaces WHERE id = %s", f["id"])[0][0] == acme["id"]
    client.put(f"/api/admin/assets/{asset['id']}", json={"tenant_id": provider}, headers=h(csrf))

    new_user(client, csrf, "cli-acme", tenant_ids=[acme["id"]], must_change_password=False)
    ccsrf, _ = login(client, "cli-acme", TEMP_PW)
    out = client.get("/api/assets").json()
    assert out["assets"] == []
    assert [(x["id"], x["asset_name"], x["contracted_bps"]) for x in out["links"]] == [(f["id"], None, 500_000_000)]
    assert client.put(f"/api/admin/interfaces/{f['id']}", json=body, headers=h(ccsrf)).status_code == 403
