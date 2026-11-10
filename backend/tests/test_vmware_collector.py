"""Coletor vCenter contra o simulador oficial (vcsim) e o TimescaleDB de teste.

Precisa de ``OPENMON_TEST_PG`` e ``OPENMON_TEST_VCSIM=host:porta`` de um vcsim, por exemplo
``docker run -p 127.0.0.1:58989:8989 vmware/vcsim -l 0.0.0.0:8989 -dc 1 -cluster 2 -host 3 -vm 4``.
"""
import os

import pytest

from openmon import vault
from openmon.collector import vmware

from pgsupport import requires_pg, sql
from test_admin_tenants import client, database, h, login, new_tenant, new_user, TEMP_PW  # noqa: F401

VCSIM = os.environ.get("OPENMON_TEST_VCSIM", "")
pytestmark = [requires_pg, pytest.mark.skipif(not VCSIM, reason="OPENMON_TEST_VCSIM não definido")]
HOST, PORT = (VCSIM.rsplit(":", 1) + ["443"])[:2] if VCSIM else ("", "443")


@pytest.fixture(autouse=True)
def master_key(tmp_path, monkeypatch):
    path = tmp_path / "master.key"
    path.write_bytes(os.urandom(32))
    monkeypatch.setenv("OPENMON_MASTER_KEY_FILE", str(path))
    vault.reset()
    vmware._sessions.clear()
    sql("DELETE FROM integrations")
    yield
    vault.reset()


def vc_body(tenant_id, **over):
    body = {"kind": "vmware_vcenter", "name": "vcenter-lab", "tenant_id": tenant_id, "endpoint": HOST,
            "port": int(PORT), "verify_tls": False, "username": "openmon@vsphere.local", "secret": "Senha-vc-1"}
    body.update(over)
    return body


def test_vcenter_inventory_metrics_and_tenant_rules(client):
    csrf, _ = login(client)
    provider = sql("SELECT id FROM tenants WHERE is_provider")[0][0]
    acme = new_tenant(client, csrf)
    beta = new_tenant(client, csrf, "beta", "Beta")

    r = client.post("/api/admin/integrations/test", json=vc_body(provider), headers=h(csrf)).json()
    assert r["ok"] and "VM(s)" in r["summary"], r
    strict = client.post("/api/admin/integrations/test", json=vc_body(provider, verify_tls=True),
                         headers=h(csrf)).json()
    assert not strict["ok"] and "certificado" in strict["error"]

    integ = client.post("/api/admin/integrations", json=vc_body(provider), headers=h(csrf)).json()["integration"]
    # Regras: VMs do cluster C1 são da Beta; as que têm "_C0_" no nome, da ACME; o resto fica no datacenter
    sql("INSERT INTO tenant_assignment_rules (tenant_id, integration_id, match_field, pattern, priority) "
        "VALUES (%s, %s, 'cluster', 'dc0_c1', 10), (%s, NULL, 'name_regex', '_C0_', 20)",
        beta["id"], integ["id"], acme["id"])
    out = client.post(f"/api/admin/integrations/{integ['id']}/poll", headers=h(csrf)).json()
    assert out["status"] == "ok", out
    assert "VM(s)" in out["message"]

    by_type = dict(sql("SELECT asset_type, count(*) FROM assets WHERE deleted_at IS NULL GROUP BY 1"))
    assert by_type["vcenter"] == 1 and by_type["datacenter"] == 1 and by_type["cluster"] == 2
    assert by_type["hypervisor_host"] >= 3 and by_type["vm"] >= 4 and by_type["datastore"] >= 1
    tenants = dict(sql("SELECT a.name, t.slug FROM assets a JOIN tenants t ON t.id = a.tenant_id "
                       "WHERE a.asset_type = 'vm'"))
    assert all(slug == "beta" for name, slug in tenants.items() if name.startswith("DC0_C1"))
    assert all(slug == "acme" for name, slug in tenants.items() if name.startswith("DC0_C0"))
    assert all(slug not in ("acme", "beta") for name, slug in tenants.items() if name.startswith("DC0_H0"))
    # VM pendurada no host, host no cluster
    parent = sql("SELECT p.asset_type FROM assets a JOIN assets p ON p.id = a.parent_id "
                 "WHERE a.name LIKE 'DC0_C0_RP0_VM%%' LIMIT 1")[0][0]
    assert parent == "hypervisor_host"
    metrics = {r[0] for r in sql("SELECT DISTINCT metric_id FROM metric_samples")}
    assert {1, 4, 10, 12, 40, 50, 51}.issubset(metrics), metrics
    assert 30 in metrics  # tráfego de rede pelo PerfManager

    # Tenant fixado à mão não é mudado pelas regras na próxima coleta
    vm = sql("SELECT id FROM assets WHERE name LIKE 'DC0_C1%%' AND asset_type = 'vm' LIMIT 1")[0][0]
    assert client.put(f"/api/admin/assets/{vm}", json={"tenant_id": acme["id"]}, headers=h(csrf)).status_code == 200
    assert client.post(f"/api/admin/integrations/{integ['id']}/poll", headers=h(csrf)).json()["status"] == "ok"
    assert sql("SELECT tenant_id FROM assets WHERE id = %s", vm)[0][0] == acme["id"]

    # Cliente da Beta vê só as VMs dela (nem hosts, nem datastores)
    new_user(client, csrf, "cli-beta", tenant_ids=[beta["id"]], must_change_password=False)
    login(client, "cli-beta", TEMP_PW)
    seen = client.get("/api/assets").json()["assets"]
    assert seen and {a["asset_type"] for a in seen} == {"vm"}
    assert all(a["tenant_id"] == beta["id"] for a in seen)
    assert any("cpu_pct" in a["latest"] or "mem_pct" in a["latest"] for a in seen)
