"""Volumes do sistema convidado pelo vCenter, VMs do vCloud completadas pelo vCenter e o que o cliente não vê."""
import json
from types import SimpleNamespace

import pytest

from openmon.collector import vmware

from pgsupport import requires_pg, sql
from test_admin_tenants import client, database, h, login, new_tenant, new_user, TEMP_PW  # noqa: F401

pytestmark = requires_pg
GB = 1024 ** 3


def disk(path, cap_gb, free_gb):
    return SimpleNamespace(diskPath=path, capacity=cap_gb * GB, freeSpace=free_gb * GB, filesystemType="NTFS")


def vm(name, host="host-1", disks=(), on=True):
    return {"name": name, "config.instanceUuid": name, "runtime.powerState": "poweredOn" if on else "poweredOff",
            "runtime.connectionState": "connected", "summary.overallStatus": "green", "runtime.host": host,
            "parent": "group-v1", "resourcePool": None, "folder": ["Clientes"], "summary.config.numCpu": 4,
            "summary.config.memorySizeMB": 8192, "summary.quickStats.overallCpuUsage": 1000,
            "summary.runtime.maxCpuUsage": 8000, "summary.quickStats.guestMemoryUsage": 2048,
            "summary.quickStats.uptimeSeconds": 86400, "summary.storage.committed": 60 * GB,
            "summary.storage.uncommitted": 40 * GB, "guest.guestFullName": "Microsoft Windows Server 2022",
            "guest.hostName": name.lower(), "guest.ipAddress": "10.0.0.5",
            "perf": {"net.received.average": 100.0, "disk.read.average": 50.0, "cpu.ready.summation": 400.0},
            "guest.disk": vmware._volumes(list(disks))}


def fake_data():
    return {"about": {"name": "VMware vCenter Server 8", "version": "8.0", "build": "1", "uuid": "u", "api": "8.0"},
            "datacenters": {"dc-1": {"name": "DC"}}, "clusters": {"c-1": {"name": "CL01", "is_cluster": True,
                                                                          "dc": "dc-1"}},
            "pools": {}, "datastores": {},
            "hosts": {"host-1": {"name": "esx07.provedor.local", "parent": "c-1", "runtime.connectionState": "connected",
                                 "runtime.powerState": "poweredOn", "summary.overallStatus": "green",
                                 "summary.hardware.cpuMhz": 2000, "summary.hardware.numCpuCores": 32,
                                 "summary.hardware.memorySize": 512 * GB, "perf": {}}},
            "vms": {"vm-1001": vm("PLX-SAPIENS", disks=[disk("C:\\", 100, 30), disk("F:\\", 500, 25)]),
                    "vm-2000": vm("INFRA-DC01", disks=[disk("/", 50, 40)])}}


def test_volumes_and_vcd_twin(client, monkeypatch):
    csrf, _ = login(client)
    provider = sql("SELECT id FROM tenants WHERE is_provider")[0][0]
    pollux = new_tenant(client, csrf, "pollux", "CLIENTE_POLLUX")
    vcd_integ = sql("INSERT INTO integrations (tenant_id, kind, name, endpoint, options) VALUES "
                    "(%s, 'vmware_vcenter', 'vcloud', 'vcloud.local', '{\"api\": \"vcd\"}') RETURNING id", provider)[0][0]
    twin = sql("INSERT INTO assets (tenant_id, integration_id, asset_type, name, external_id, hostname, status, "
               "attributes) VALUES (%s, %s, 'vm', 'PLX-SAPIENS', 'vm:abc', NULL, 'up', %s::jsonb) RETURNING id",
               pollux["id"], vcd_integ, json.dumps({"hypervisor": "vcloud", "moref": "vm-1001",
                                                    "esx_host": "esx07.provedor.local", "vcpu": 4}))[0][0]
    vc = sql("INSERT INTO integrations (tenant_id, kind, name, endpoint) VALUES "
             "(%s, 'vmware_vcenter', 'vcenter01', 'vcenter01.local') RETURNING id", provider)[0][0]
    monkeypatch.setattr(vmware, "collect", lambda integ: fake_data())

    out = client.post(f"/api/admin/integrations/{vc}/poll", headers=h(csrf)).json()
    assert out["status"] == "ok" and "2 VM(s) (2 ligada(s), 1 completando o vCloud)" in out["message"], out
    # A VM do vCloud não ganhou uma gêmea do vCenter; a outra virou ativo normal
    assert sql("SELECT count(*) FROM assets WHERE name = 'PLX-SAPIENS' AND deleted_at IS NULL")[0][0] == 1
    vals = dict(sql("SELECT metric_id, value FROM metric_samples WHERE asset_id = %s", twin))
    assert vals[60] == 600 * GB and vals[61] == 545 * GB and vals[62] == 95.0 and vals[21] == 60 * GB
    assert vals[30] == 100 * 8192 and vals[41] == 86400 and vals[3] == 0.5
    assert 26 not in vals and 1 not in vals  # leitura de disco e CPU continuam vindo do vCloud
    attrs = sql("SELECT attributes FROM assets WHERE id = %s", twin)[0][0]
    assert [v["path"] for v in attrs["volumes"]] == ["C:\\", "F:\\"] and attrs["moref"] == "vm-1001"
    dc01 = sql("SELECT a.id, a.attributes FROM assets a WHERE a.name = 'INFRA-DC01'")[0]
    assert dc01[1]["volumes"] == [{"path": "/", "cap": 50 * GB, "free": 40 * GB, "fs": "NTFS"}]

    # Admin vê o host do virtualizador; o cliente não
    adm = {a["name"]: a for a in client.get("/api/assets?asset_type=vm").json()["assets"]}
    assert adm["INFRA-DC01"]["parent_name"] == "esx07.provedor.local"
    assert client.get(f"/api/assets/{twin}").json()["asset"]["attributes"]["esx_host"] == "esx07.provedor.local"
    new_user(client, csrf, "cli-pollux", tenant_ids=[pollux["id"]], must_change_password=False)
    login(client, "cli-pollux", TEMP_PW)
    lst = client.get("/api/assets?asset_type=vm").json()["assets"]
    assert [a["name"] for a in lst] == ["PLX-SAPIENS"]
    a = lst[0]
    assert "esx_host" not in a["attributes"] and "integration_name" not in a and a["hostname"] is None
    assert a["latest"]["fs_max_pct"] == 95.0 and len(a["attributes"]["volumes"]) == 2
    d = client.get(f"/api/assets/{twin}").json()["asset"]
    assert "esx_host" not in d["attributes"] and "moref" not in d["attributes"] and "external_id" not in d
    assert "esx07" not in json.dumps(d)


@pytest.mark.parametrize("disks,expected", [([], []), ([SimpleNamespace(diskPath="/x", capacity=0, freeSpace=0)], [])])
def test_volumes_skip_empty(disks, expected):
    assert vmware._volumes(disks) == expected
