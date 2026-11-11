"""Coletor VMware Cloud Director (vCloud) contra um vCD simulado (httpx.MockTransport) e o TimescaleDB de teste."""
import base64
import os

import httpx
import pytest

from openmon import vault
from openmon.collector import vcd

from pgsupport import requires_pg, sql
from test_admin_tenants import client, database, h, login, new_tenant, new_user, TEMP_PW  # noqa: F401

pytestmark = requires_pg
B = "https://vcloud.empresa.com.br"


def vdc(uid, org, name, **kw):
    return {"href": f"{B}/api/vdc/{uid}", "name": name, "orgName": org, "isEnabled": True,
            "allocationModel": "AllocationPool", "cpuAllocationMhz": 20000, "cpuUsedMhz": 5000,
            "memoryAllocationMB": 65536, "memoryUsedMB": 49152, "storageLimitMB": 0, "numberOfVMs": 2, **kw}


DISKS_XML = """<?xml version="1.0" encoding="UTF-8"?>
<RasdItemsList xmlns="http://www.vmware.com/vcloud/v1.5" xmlns:vcloud="http://www.vmware.com/vcloud/v1.5"
    xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData">
  <Item><rasd:ElementName>SCSI Controller 0</rasd:ElementName><rasd:ResourceType>6</rasd:ResourceType></Item>
  <Item><rasd:ElementName>Hard disk 1</rasd:ElementName>
    <rasd:HostResource vcloud:capacity="20480" vcloud:storageProfileHref="x"></rasd:HostResource>
    <rasd:ResourceType>17</rasd:ResourceType></Item>
  <Item><rasd:ElementName>Hard disk 2</rasd:ElementName><rasd:HostResource></rasd:HostResource>
    <rasd:ResourceType>17</rasd:ResourceType><rasd:VirtualQuantity>10737418240</rasd:VirtualQuantity></Item>
</RasdItemsList>"""


class FakeVcd:
    """O suficiente da API do Cloud Director 10.5 (versão 38.0) para a coleta."""

    def __init__(self):
        self.calls = []
        self.vdcs = [vdc("v1", "POLLUX", "VDC-POLLUX"), vdc("v2", "ACME", "VDC-ACME"),
                     vdc("v3", "OUTRO", "VDC-OUTRO")]
        self.sps = [{"href": f"{B}/api/admin/vdcStorageProfile/s1", "name": "Gold", "vdc": f"{B}/api/vdc/v1",
                     "vdcName": "VDC-POLLUX", "storageLimitMB": 1048576, "storageUsedMB": 996147, "isEnabled": True},
                    {"href": f"{B}/api/admin/vdcStorageProfile/s2", "name": "Silver", "vdc": f"{B}/api/vdc/v2",
                     "vdcName": "VDC-ACME", "storageLimitMB": 0, "storageUsedMB": 2048, "isEnabled": True}]
        self.vms = [self.vm(i, "v1" if i < 200 else "v2") for i in range(260)]
        self.vms[0]["status"] = "POWERED_OFF"
        self.metrics_status = 200
        self.disk_reads = 0
        for i in range(10, 20):
            self.vms[i].pop("totalStorageAllocatedMb")
        for m in self.vms[:10]:  # o vCD 10.5 manda a data na VM; sem ela vale a da vApp
            m["dateCreated"] = "2022-12-15T10:00:00.000-03:00"
        self.vapps = [{"href": f"{B}/api/vApp/vapp-{n}", "name": f"vapp-{n}", "creationDate": d}
                      for n, d in enumerate(("2023-01-10T09:00:00.000Z", "2024-06-01T09:00:00.000Z",
                                             "2025-03-05T09:00:00.000Z", "2026-02-20T09:00:00.000Z"))]

    @staticmethod
    def vm(i, v):
        return {"href": f"{B}/api/vApp/vm-{i:04d}", "name": f"vm-{v}-{i}", "vdc": f"{B}/api/vdc/{v}",
                "status": "POWERED_ON", "numberOfCpus": 2, "memoryMB": 4096, "guestOs": "Ubuntu Linux (64-bit)",
                "ipAddress": f"10.0.{i // 250}.{i % 250 + 1}", "containerName": f"vapp-{i % 4}", "container": f"{B}/api/vApp/vapp-{i % 4}", "isVAppTemplate": False,
                "totalStorageAllocatedMb": 40960, "moref": f"vm-{1000 + i}"}

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.calls.append((request.method, path))
        if path == "/cloudapi/1.0.0/sessions/provider":
            assert request.headers["accept"] == "application/json;version=38.0"
            user, pw = base64.b64decode(request.headers["authorization"].split()[1]).decode().split(":", 1)
            if (user, pw) != ("openmon@System", "Senha-vcd-1"):
                return httpx.Response(401, json={"message": "Unauthorized"})
            return httpx.Response(200, json={"id": "s"}, headers={"X-VMware-VCLOUD-ACCESS-TOKEN": "tok-1"})
        if path == "/oauth/provider/token":
            if b"refresh_token=tok-api" not in request.content:
                return httpx.Response(400, json={"error": "invalid_grant"})
            return httpx.Response(200, json={"access_token": "tok-1", "token_type": "Bearer"})
        if request.headers.get("authorization") != "Bearer tok-1":
            return httpx.Response(401, json={"message": "no token"})
        if path == "/cloudapi/1.0.0/sessions/current":
            return httpx.Response(204)
        if path == "/api/query":
            assert request.headers["accept"] == "application/*+json;version=38.0"
            q = request.url.params
            data = {"adminOrgVdc": self.vdcs, "adminOrgVdcStorageProfile": self.sps, "adminVM": self.vms,
                    "adminVApp": self.vapps}[q["type"]]
            if q.get("filter"):
                assert q["filter"] in ("isVAppTemplate==false", "isVAppTemplate==false;status==POWERED_ON")
                if "POWERED_ON" in q["filter"]:
                    data = [r for r in data if r["status"] == "POWERED_ON"]
            page, size = int(q["page"]), int(q["pageSize"])
            assert size <= 128
            return httpx.Response(200, json={"total": len(data), "page": page, "pageSize": size,
                                             "record": data[(page - 1) * size:page * size]})
        if path.startswith("/api/vApp/vm-") and path.endswith("/metrics/current"):
            assert request.headers["accept"] == "application/*+json;version=38.0"
            if self.metrics_status != 200:
                return httpx.Response(self.metrics_status, json={"message": "Forbidden"})
            i = int(path.split("/")[3][3:])
            if i == 7:  # VM sem VMware Tools: o vCD responde sem métricas
                return httpx.Response(200, json={"metric": []})
            if 10 <= i < 20:  # vCD que não manda espaço em disco nas métricas (visto em produção)
                return httpx.Response(200, json={"metric": [
                    {"name": "cpu.usage.average", "unit": "PERCENT", "value": 12.5},
                    {"name": "disk.provisioned.latest", "unit": "KILOBYTE", "value": -1},
                    {"name": "disk.read.average", "unit": "KILOBYTES_PER_SECOND", "value": 10}]})
            if i == 3:  # um registro por disco
                return httpx.Response(200, json={"metric": [
                    {"name": "disk.used.latest", "unit": "KILOBYTE", "value": 1048576},
                    {"name": "disk.used.latest", "unit": "KILOBYTE", "value": 2097152}]})
            return httpx.Response(200, json={"metric": [
                {"name": "cpu.usage.average", "unit": "PERCENT", "value": 12.5},
                {"name": "cpu.usagemhz.average", "unit": "MEGAHERTZ", "value": 600.0},
                {"name": "mem.usage.average", "unit": "PERCENT", "value": 50.0},
                {"name": "disk.provisioned.latest", "unit": "KILOBYTE", "value": 41943040},
                {"name": "disk.used.latest", "unit": "KILOBYTE", "value": 10485760},
                {"name": "disk.read.average", "unit": "KILOBYTES_PER_SECOND", "value": 100},
                {"name": "disk.write.average", "unit": "KILOBYTES_PER_SECOND", "value": "x"}]})
        if path.startswith("/api/vApp/vm-") and path.endswith("/virtualHardwareSection/disks"):
            assert request.headers["accept"] == "application/*+xml;version=38.0"
            self.disk_reads += 1
            return httpx.Response(200, text=DISKS_XML)
        return httpx.Response(404, json={"message": "not found"})


@pytest.fixture(autouse=True)
def fake(tmp_path, monkeypatch):
    path = tmp_path / "master.key"
    path.write_bytes(os.urandom(32))
    monkeypatch.setenv("OPENMON_MASTER_KEY_FILE", str(path))
    vault.reset()
    sql("DELETE FROM integrations")
    f = FakeVcd()
    monkeypatch.setattr(vcd, "_transport", httpx.MockTransport(f.handler))
    vcd._disk_cache.clear()
    yield f
    vault.reset()


def body(tenant_id, **over):
    b = {"kind": "vmware_vcd", "name": "vcloud", "tenant_id": tenant_id, "endpoint": "https://vcloud.empresa.com.br/",
         "username": "openmon@System", "secret": "Senha-vcd-1", "options": {"api_version": "38.0"}}
    b.update(over)
    return b


def test_vcd_orgs_vdcs_vms_and_tenant_rules(client, fake):
    csrf, _ = login(client)
    provider = sql("SELECT id FROM tenants WHERE is_provider")[0][0]
    pollux = new_tenant(client, csrf, "pollux", "Cliente Pollux")

    bad = client.post("/api/admin/integrations/test", json=body(provider, secret="errada-123"), headers=h(csrf)).json()
    assert not bad["ok"] and "recusados" in bad["error"]
    ok = client.post("/api/admin/integrations/test", json=body(provider), headers=h(csrf)).json()
    assert ok["ok"] and "3 organização(ões) · 3 VDC(s) · 260 VM(s)" in ok["summary"], ok
    d = ok["details"]
    assert d["vm_exemplo"] == "vm-v1-1" and d["campos_disco"] == {"totalStorageAllocatedMb": 40960}
    assert "disk.used.latest" in d["metricas"] and d["disco_pelo_hardware"] == 30 * 1024 ** 3

    # Só POLLUX e ACME (filtro de organizações); a regra manda POLLUX para o tenant do cliente
    integ = client.post("/api/admin/integrations", json=body(provider, options={"orgs": ["pollux", "AC*"]}),
                        headers=h(csrf)).json()["integration"]
    assert integ["kind"] == "vmware_vcd" and integ["endpoint"] == "vcloud.empresa.com.br" and integ["port"] == 443
    assert integ["options"] == {"api": "vcd", "api_version": "38.0", "auth": "password", "orgs": ["pollux", "AC*"]}
    assert sql("SELECT kind FROM integrations")[0][0] == "vmware_vcenter"
    client.post("/api/admin/tenant-rules", json={"tenant_id": pollux["id"], "match_field": "folder",
                                                 "pattern": "POLLUX", "priority": 10}, headers=h(csrf))
    out = client.post(f"/api/admin/integrations/{integ['id']}/poll", headers=h(csrf)).json()
    assert out["status"] == "ok" and "2 organização(ões), 2 VDC(s), 260 VM(s) (259 ligada(s), 258 com métricas, 248 com disco usado)" in out["message"], out
    assert ("DELETE", "/cloudapi/1.0.0/sessions/current") in fake.calls

    by_tenant = dict(sql("SELECT t.slug, count(*) FROM assets a JOIN tenants t ON t.id = a.tenant_id "
                         "WHERE a.asset_type = 'vm' AND a.deleted_at IS NULL GROUP BY t.slug"))
    assert by_tenant == {"pollux": 200, "datacenter": 60}
    sp = sql("SELECT t.slug, a.name FROM assets a JOIN tenants t ON t.id = a.tenant_id "
             "WHERE a.asset_type = 'datastore'")
    assert ("pollux", "POLLUX / VDC-POLLUX / Gold") in sp
    # Perfil Gold a 95%: capacidade e uso para o alerta de armazenamento
    vals = dict(sql("SELECT m.metric_id, m.value FROM metric_samples m JOIN assets a ON a.id = m.asset_id "
                    "WHERE a.name = 'POLLUX / VDC-POLLUX / Gold'"))
    assert vals[50] == 1048576 * 1024 * 1024 and round(vals[52] / vals[50] * 100) == 95
    vdc_mem = dict(sql("SELECT m.metric_id, m.value FROM metric_samples m JOIN assets a ON a.id = m.asset_id "
                       "WHERE a.name = 'POLLUX / VDC-POLLUX'"))
    assert vdc_mem[10] == 75.0 and vdc_mem[1] == 25.0
    # Uso real por VM ligada (metrics/current); desligada e sem Tools ficam só com a alocação
    vm1 = dict(sql("SELECT m.metric_id, m.value FROM metric_samples m JOIN assets a ON a.id = m.asset_id "
                   "WHERE a.name = 'vm-v1-1'"))
    assert vm1[1] == 12.5 and vm1[2] == 600 and vm1[10] == 50 and vm1[11] == 2048 * 1024 * 1024
    assert vm1[20] == 40 * 1024 ** 3 and vm1[21] == 10 * 1024 ** 3 and vm1[26] == 100 * 1024 and 27 not in vm1
    for name in ("vm-v1-0", "vm-v1-7"):
        ids = {r[0] for r in sql("SELECT m.metric_id FROM metric_samples m JOIN assets a ON a.id = m.asset_id "
                                 "WHERE a.name = %s", name)}
        assert 1 not in ids and 20 in ids and 4 in ids, (name, ids)
    # Sem espaço nas métricas nem no Query Service: provisionado pelo hardware virtual (20 GB + 10 GB)
    vm12 = dict(sql("SELECT m.metric_id, m.value FROM metric_samples m JOIN assets a ON a.id = m.asset_id "
                    "WHERE a.name = 'vm-v1-12'"))
    assert vm12[20] == 30 * 1024 ** 3 and 21 not in vm12 and vm12[1] == 12.5, vm12
    assert fake.disk_reads == 11  # 10 na coleta + 1 do diagnóstico em Testar conexão
    # Um registro por disco: soma
    vm3 = dict(sql("SELECT m.metric_id, m.value FROM metric_samples m JOIN assets a ON a.id = m.asset_id "
                   "WHERE a.name = 'vm-v1-3'"))
    assert vm3[21] == 3 * 1024 ** 3 and vm3[20] == 40 * 1024 ** 3
    # Só VMs das organizações escolhidas (OUTRO fica de fora) e ligadas
    asked = {p for _, p in fake.calls if p.endswith("/metrics/current")}
    assert len(asked) == 259 and "/api/vApp/vm-0000/metrics/current" not in asked

    # Cliente Pollux só vê as próprias VMs
    new_user(client, csrf, "cli-pollux", tenant_ids=[pollux["id"]], must_change_password=False)
    login(client, "cli-pollux", TEMP_PW)
    seen = client.get("/api/assets?asset_type=vm&limit=1000").json()
    assert len(seen["assets"]) == 200
    assert all(a["name"].startswith("vm-v1-") for a in seen["assets"])

    # VM apagada no vCloud sai do inventário
    csrf, _ = login(client)
    fake.vms.pop()
    out = client.post(f"/api/admin/integrations/{integ['id']}/poll", headers=h(csrf)).json()
    assert "1 removido(s)" in out["message"], out
    assert fake.disk_reads == 11  # hardware em cache (6 h)

    # Conta sem o direito de ver métricas: a coleta segue com o inventário e avisa
    fake.metrics_status = 403
    out = client.post(f"/api/admin/integrations/{integ['id']}/poll", headers=h(csrf)).json()
    assert out["status"] == "warning" and "View VM metrics" in out["message"], out


def test_vcd_api_token_and_edit_keeps_mode(client, fake):
    csrf, _ = login(client)
    provider = sql("SELECT id FROM tenants WHERE is_provider")[0][0]
    b = body(provider, username="", secret="tok-api", options={"auth": "token"})
    ok = client.post("/api/admin/integrations/test", json=b, headers=h(csrf)).json()
    assert ok["ok"], ok
    integ = client.post("/api/admin/integrations", json=b, headers=h(csrf)).json()["integration"]
    assert integ["username"] == "System"
    assert ("DELETE", "/cloudapi/1.0.0/sessions/current") not in fake.calls
    # Editar sem mandar o token mantém o do cofre; não dá para virar vCenter
    b2 = dict(b, secret=None, name="vcloud-sp")
    r = client.put(f"/api/admin/integrations/{integ['id']}", json=b2, headers=h(csrf))
    assert r.status_code == 200 and r.json()["integration"]["kind"] == "vmware_vcd"
    r = client.put(f"/api/admin/integrations/{integ['id']}", json=dict(b2, kind="vmware_vcenter"), headers=h(csrf))
    assert r.status_code == 422
    assert client.post(f"/api/admin/integrations/{integ['id']}/poll", headers=h(csrf)).json()["status"] == "ok"
    bad = client.post("/api/admin/integrations/test", json=dict(b, secret="outro"), headers=h(csrf)).json()
    assert not bad["ok"] and "token" in bad["error"]
