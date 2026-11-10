"""Coletor Hyper-V: script PowerShell simulado por host (sem Windows) e o TimescaleDB de teste."""
import json
import os

import pytest

from openmon import vault
from openmon.collector import hyperv
from openmon.collector.common import CollectorError

from pgsupport import requires_pg, sql
from test_admin_tenants import client, database, h, login, new_tenant, new_user, TEMP_PW  # noqa: F401


def host_json(name, vms, cluster="HVCLU01"):
    net = {}
    for v in vms:
        inst = f"{v['name'].lower()}_network adapter_{{a1b2}}--0"
        net[f"\\\\{name.lower()}\\hyper-v virtual network adapter({inst})\\bytes received/sec"] = 1_000_000
        net[f"\\\\{name.lower()}\\hyper-v virtual network adapter({inst})\\bytes sent/sec"] = 250_000
    return {"host": name, "domain": "empresa.local", "vendor": "Dell Inc.", "model": "PowerEdge R750", "cores": 64,
            "mem": 512 * 1024 ** 3, "free": 128 * 1024 ** 3, "os": "Microsoft Windows Server 2022 Datacenter",
            "boot": "2026-10-01T03:00:00.0000000Z", "cpu": 37, "cluster": cluster, "net": net,
            "vms": [{"id": v["id"], "name": v["name"], "state": v.get("state", "Running"), "cpu": 12, "vcpu": 4,
                     "mem": 8 * 1024 ** 3, "mem_startup": 8 * 1024 ** 3, "mem_demand": 6 * 1024 ** 3, "dyn": False,
                     "up": 86400, "status": "Operating normally", "hb": "OkApplicationsHealthy", "gen": 2,
                     "ver": "10.0", "clustered": True, "repl": "Disabled", "ips": ["10.1.0.%d" % (i + 10)]}
                    for i, v in enumerate(vms)]}


def test_parse_and_net_mapping():
    out = json.dumps(host_json("HV01", [{"id": "A", "name": "acme_web01"}, {"id": "B", "name": "acme"}]))
    data = hyperv._parse(0, out.encode(), b"", "hv01")
    assert len(data["vms"]) == 2
    net = hyperv._net_by_vm(data["net"], ["acme_web01", "acme"])
    assert net["acme_web01"] == (1_000_000, 250_000) and net["acme"] == (1_000_000, 250_000)
    one = hyperv._parse(0, json.dumps({"host": "x", "vms": {"id": "C", "name": "so-uma"}}).encode(), b"", "x")
    assert one["vms"] == [{"id": "C", "name": "so-uma"}]
    clixml = (b'#< CLIXML\r\n<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">'
              b'<S S="Error">Get-VM : The term \'Get-VM\' is not recognized as the name of a cmdlet_x000D__x000A_'
              b'</S></Objs>')
    with pytest.raises(CollectorError, match="módulo Hyper-V"):
        hyperv._parse(1, b"", clixml, "hv01")
    assert "recusados" in hyperv._describe(type("InvalidCredentialsError", (Exception,), {})("x"), "hv01")


@pytest.fixture
def hosts(tmp_path, monkeypatch):
    path = tmp_path / "master.key"
    path.write_bytes(os.urandom(32))
    monkeypatch.setenv("OPENMON_MASTER_KEY_FILE", str(path))
    vault.reset()
    sql("DELETE FROM integrations")
    state = {
        "hv01.empresa.local": host_json("HV01", [{"id": "11111111-AAAA", "name": "ACME-APP01"},
                                                 {"id": "22222222-BBBB", "name": "ACME-DB01"}]),
        "hv02.empresa.local": host_json("HV02", [{"id": "33333333-CCCC", "name": "BETA-ERP"},
                                                 {"id": "44444444-DDDD", "name": "infra-dc01", "state": "Off"}]),
    }
    calls = []

    def fake_run(integ, host):
        calls.append((host, integ.username, integ.secret, integ.options.get("transport")))
        if isinstance(state.get(host), Exception):
            raise state[host]
        return json.loads(json.dumps(state[host]))
    monkeypatch.setattr(hyperv, "_run", fake_run)
    yield state, calls
    vault.reset()


@pytest.mark.skipif(not os.environ.get("OPENMON_TEST_PG"), reason="OPENMON_TEST_PG não definido")
def test_hyperv_hosts_vms_rules_migration_and_down_host(client, hosts):
    state, calls = hosts
    csrf, _ = login(client)
    provider = sql("SELECT id FROM tenants WHERE is_provider")[0][0]
    acme = new_tenant(client, csrf)
    beta = new_tenant(client, csrf, "beta", "Beta")
    body = {"kind": "hyperv", "name": "cluster-hv", "tenant_id": provider, "endpoint": "hvclu01.empresa.local",
            "username": "EMPRESA\\svc-openmon", "secret": "Senha-hv-123",
            "options": {"transport": "ntlm", "hosts": ["hv01.empresa.local", "hv02.empresa.local"]}}
    r = client.post("/api/admin/integrations/test", json=body, headers=h(csrf)).json()
    assert r["ok"] and r["summary"] == "2 host(s) · 4 VM(s)", r
    assert calls[0][1:] == ("EMPRESA\\svc-openmon", "Senha-hv-123", "ntlm")
    integ = client.post("/api/admin/integrations", json=body, headers=h(csrf)).json()["integration"]
    assert integ["port"] == 5986
    sql("INSERT INTO tenant_assignment_rules (tenant_id, match_field, pattern, priority) "
        "VALUES (%s, 'name_regex', '^acme-', 10), (%s, 'name_regex', '^beta-', 10)", acme["id"], beta["id"])
    out = client.post(f"/api/admin/integrations/{integ['id']}/poll", headers=h(csrf)).json()
    assert out == {"status": "ok", "message": "2 host(s), 4 VM(s) (3 ligada(s))"}, out

    vms = {r[0]: r[1:] for r in sql(
        "SELECT a.name, t.slug, a.status, p.name, host(a.ip_address) FROM assets a JOIN tenants t ON t.id = a.tenant_id "
        "JOIN assets p ON p.id = a.parent_id WHERE a.asset_type = 'vm'")}
    assert vms["ACME-APP01"] == ("acme", "up", "HV01.empresa.local", "10.1.0.10")
    assert vms["BETA-ERP"][0] == "beta" and vms["infra-dc01"][:2] == ("datacenter", "powered_off")
    assert sql("SELECT count(*) FROM assets WHERE asset_type = 'cluster' AND name = 'HVCLU01'")[0][0] == 1
    rx = sql("SELECT value FROM metric_samples m JOIN assets a ON a.id = m.asset_id "
             "WHERE a.name = 'ACME-APP01' AND m.metric_id = 30")
    assert rx and rx[0][0] == 8_000_000

    # Live migration: ACME-DB01 vai para o HV02, mesmo ativo (VMId), outro host
    db01 = state["hv01.empresa.local"]["vms"].pop(1)
    state["hv02.empresa.local"]["vms"].append(db01)
    assert client.post(f"/api/admin/integrations/{integ['id']}/poll", headers=h(csrf)).json()["status"] == "ok"
    assert sql("SELECT count(*) FROM assets WHERE name = 'ACME-DB01'")[0][0] == 1
    assert sql("SELECT p.name FROM assets a JOIN assets p ON p.id = a.parent_id WHERE a.name = 'ACME-DB01'")[0][0] \
        == "HV02.empresa.local"

    # HV02 cai: aviso, host fora, e as VMs dele NÃO são removidas do inventário
    state["hv02.empresa.local"] = CollectorError("hv02.empresa.local: sem resposta (timeout)")
    out = client.post(f"/api/admin/integrations/{integ['id']}/poll", headers=h(csrf)).json()
    assert out["status"] == "warning" and "timeout" in out["message"]
    assert sql("SELECT status FROM assets WHERE hostname = 'hv02.empresa.local' OR name = 'HV02.empresa.local'")[0][0] \
        == "down"
    assert sql("SELECT count(*) FROM assets WHERE asset_type = 'vm' AND deleted_at IS NULL")[0][0] == 4
    assert sql("SELECT count(*) FROM assets WHERE asset_type = 'hypervisor_host'")[0][0] == 2

    new_user(client, csrf, "cli-beta", tenant_ids=[beta["id"]], must_change_password=False)
    login(client, "cli-beta", TEMP_PW)
    assert [a["name"] for a in client.get("/api/assets").json()["assets"]] == ["BETA-ERP"]
