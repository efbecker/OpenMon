"""Coletor Veeam (API REST) contra um Veeam simulado (httpx.MockTransport) e o TimescaleDB de teste."""
import json
import os
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from openmon import vault
from openmon.collector import veeam

from pgsupport import requires_pg, sql
from test_admin_tenants import client, database, h, login, new_tenant, new_user, TEMP_PW  # noqa: F401

pytestmark = requires_pg
NOW = datetime.now(timezone.utc).replace(microsecond=0)


def iso(d):
    return d.isoformat().replace("+00:00", "Z")


class FakeVeeam:
    """O suficiente da API REST v1.1 do Veeam B&R 12 para a coleta."""

    def __init__(self):
        self.calls = []
        self.jobs = [
            {"id": "j-acme", "name": "ACME - Diário", "type": "Backup", "status": "inactive", "lastResult": "Success",
             "lastRun": iso(NOW - timedelta(hours=3)), "repositoryId": "r1", "description": "todo dia 22h"},
            {"id": "j-beta", "name": "BETA - SQL", "type": "Backup", "status": "inactive", "lastResult": "Failed",
             "lastRun": iso(NOW - timedelta(hours=2)), "repositoryId": "r1"},
            {"id": "j-dc", "name": "Infra - vCenter", "type": "Backup", "status": "running", "lastResult": "Success",
             "lastRun": iso(NOW - timedelta(minutes=10)), "repositoryId": "r2"},
        ]
        self.sessions = [
            {"id": "s1", "jobId": "j-acme", "creationTime": iso(NOW - timedelta(hours=27)),
             "endTime": iso(NOW - timedelta(hours=26)), "state": "Stopped", "result": {"result": "Success"}},
            {"id": "s2", "jobId": "j-acme", "creationTime": iso(NOW - timedelta(hours=3)),
             "endTime": iso(NOW - timedelta(hours=2, minutes=30)), "state": "Stopped",
             "result": {"result": "Warning", "message": "1 VM com snapshot antigo"}},
            {"id": "s3", "jobId": "j-beta", "creationTime": iso(NOW - timedelta(hours=2)),
             "endTime": iso(NOW - timedelta(hours=1)), "state": "Stopped",
             "result": {"result": "Failed", "message": "Erro ao acessar o repositório"}},
            {"id": "s4", "jobId": "j-dc", "creationTime": iso(NOW - timedelta(minutes=10)), "endTime": None,
             "state": "Working", "result": {"result": "None"}},
        ]

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append((request.method, request.url.path))
        assert request.headers["x-api-version"] == "1.1-rev1"
        if request.url.path == "/api/oauth2/token":
            form = dict(x.split("=", 1) for x in request.content.decode().split("&"))
            if form.get("password") != "Senha-veeam-1":
                return httpx.Response(401, json={"errorCode": "Unauthorized", "message": "Invalid credentials"})
            return httpx.Response(200, json={"access_token": "tok-1", "token_type": "bearer", "expires_in": 900})
        if request.url.path == "/api/oauth2/logout":
            return httpx.Response(200, json={})
        if request.headers.get("authorization") != "Bearer tok-1":
            return httpx.Response(401, json={"message": "no token"})
        page = {"/api/v1/jobs/states": self.jobs, "/api/v1/sessions": self.sessions,
                "/api/v1/backupInfrastructure/repositories/states": [
                    {"id": "r1", "name": "Repo Clientes", "type": "WinLocal", "hostName": "vbr01", "path": "E:\\Backups",
                     "capacityGB": 10240.0, "freeGB": 2048.0, "usedSpaceGB": 8192.0},
                    {"id": "r2", "name": "Repo Infra", "type": "LinuxHardened", "hostName": "repo02",
                     "path": "/backups", "capacityGB": 4096.0, "freeGB": 3000.0}]}
        if request.url.path == "/api/v1/serverInfo":
            return httpx.Response(200, json={"vbrId": "vbr-1", "name": "vbr01.empresa.local",
                                             "buildVersion": "12.1.2.172"})
        if request.url.path in page:
            data = page[request.url.path]
            skip = int(request.url.params.get("skip", 0))
            limit = int(request.url.params.get("limit", 500))
            return httpx.Response(200, json={"data": data[skip:skip + limit],
                                             "pagination": {"total": len(data), "count": len(data[skip:skip + limit]),
                                                            "skip": skip, "limit": limit}})
        return httpx.Response(404, json={"message": "not found"})


@pytest.fixture(autouse=True)
def fake(tmp_path, monkeypatch):
    path = tmp_path / "master.key"
    path.write_bytes(os.urandom(32))
    monkeypatch.setenv("OPENMON_MASTER_KEY_FILE", str(path))
    vault.reset()
    sql("DELETE FROM integrations")
    f = FakeVeeam()
    monkeypatch.setattr(veeam, "_transport", httpx.MockTransport(f.handler))
    yield f
    vault.reset()


def body(tenant_id, **over):
    b = {"kind": "veeam", "name": "vbr01", "tenant_id": tenant_id, "endpoint": "vbr01.empresa.local",
         "username": "EMPRESA\\svc-openmon", "secret": "Senha-veeam-1"}
    b.update(over)
    return b


def test_veeam_jobs_sessions_repositories_and_sla(client, fake):
    csrf, _ = login(client)
    provider = sql("SELECT id FROM tenants WHERE is_provider")[0][0]
    acme = new_tenant(client, csrf, backup_sla_hours=24)
    beta = new_tenant(client, csrf, "beta", "Beta", backup_sla_hours=24)

    bad = client.post("/api/admin/integrations/test", json=body(provider, secret="errada-123"), headers=h(csrf)).json()
    assert not bad["ok"] and "recusados" in bad["error"]
    ok = client.post("/api/admin/integrations/test", json=body(provider), headers=h(csrf)).json()
    assert ok["ok"] and "3 job(s)" in ok["summary"], ok

    integ = client.post("/api/admin/integrations", json=body(provider), headers=h(csrf)).json()["integration"]
    assert integ["port"] == 9419
    sql("INSERT INTO tenant_assignment_rules (tenant_id, match_field, pattern, priority) "
        "VALUES (%s, 'veeam_job', 'acme*', 10), (%s, 'veeam_job', 'beta*', 10)", acme["id"], beta["id"])
    out = client.post(f"/api/admin/integrations/{integ['id']}/poll", headers=h(csrf)).json()
    assert out["status"] == "ok" and "3 job(s), 4 sessão(ões), 2 repositório(s)" in out["message"], out

    jobs = {r[0]: r[1:] for r in sql(
        "SELECT j.name, t.slug, j.last_result, j.last_success_at IS NOT NULL FROM backup_jobs j "
        "JOIN tenants t ON t.id = j.tenant_id")}
    assert jobs["ACME - Diário"] == ("acme", "success", True)
    assert jobs["BETA - SQL"] == ("beta", "failed", False)
    assert jobs["Infra - vCenter"][1] == "running"
    runs = dict(sql("SELECT session_external_id, result FROM backup_job_runs"))
    assert runs == {"s1": "success", "s2": "warning", "s3": "failed", "s4": "running"}
    assert sql("SELECT count(*) FROM assets WHERE asset_type = 'backup_repository'")[0][0] == 2
    assert {r[0] for r in sql("SELECT DISTINCT metric_id FROM metric_samples")} >= {40, 50, 51, 52}

    # Sessão em andamento termina: a próxima coleta atualiza (sem duplicar)
    fake.sessions[3].update(endTime=iso(NOW), state="Stopped", result={"result": "Success"})
    assert client.post(f"/api/admin/integrations/{integ['id']}/poll", headers=h(csrf)).json()["status"] == "ok"
    assert sql("SELECT result FROM backup_job_runs WHERE session_external_id = 's4'")[0][0] == "success"
    assert sql("SELECT count(*) FROM backup_job_runs")[0][0] == 4
    assert ("POST", "/api/oauth2/logout") in fake.calls

    # Job some do Veeam: fica no histórico, marcado como removido
    fake.jobs.pop(1)
    client.post(f"/api/admin/integrations/{integ['id']}/poll", headers=h(csrf))
    assert sql("SELECT deleted_at IS NOT NULL FROM backup_jobs WHERE name = 'BETA - SQL'")[0][0]

    # SLA por tenant na API de backups
    sla = {t["tenant_name"]: t for t in client.get("/api/backups").json()["tenants"]}
    assert sla["ACME S.A."]["in_sla"] == 1 and sla["ACME S.A."]["out_of_sla"] == 0

    new_user(client, csrf, "cli-acme", tenant_ids=[acme["id"]], must_change_password=False)
    login(client, "cli-acme", TEMP_PW)
    seen = client.get("/api/backups").json()
    assert [j["name"] for j in seen["jobs"]] == ["ACME - Diário"]
    assert [r["result"] for r in client.get(f"/api/backups/{seen['jobs'][0]['id']}/runs").json()["runs"]] == \
        ["warning", "success"]
    assert json.dumps(seen).count("Infra") == 0


def test_tenant_rules_api(client):
    csrf, _ = login(client)
    acme = new_tenant(client, csrf)
    r = client.post("/api/admin/tenant-rules", json={"tenant_id": acme["id"], "match_field": "name_regex",
                                                     "pattern": "(", "priority": 5}, headers=h(csrf))
    assert r.status_code == 422 and "regular" in r.json()["detail"]
    r = client.post("/api/admin/tenant-rules", json={"tenant_id": acme["id"], "match_field": "folder",
                                                     "pattern": " Clientes/ACME* ", "priority": 5}, headers=h(csrf))
    assert r.status_code == 201
    rid = r.json()["id"]
    rules = client.get("/api/admin/tenant-rules").json()["rules"]
    assert [(x["pattern"], x["tenant_name"]) for x in rules] == [("Clientes/ACME*", "ACME S.A.")]
    body = {"tenant_id": acme["id"], "match_field": "veeam_job", "pattern": "ACME*", "priority": 1, "is_enabled": False}
    assert client.put(f"/api/admin/tenant-rules/{rid}", json=body, headers=h(csrf)).status_code == 200
    assert client.get("/api/admin/tenant-rules").json()["rules"][0]["is_enabled"] is False
    new_user(client, csrf, "noc", role="operator", must_change_password=False)
    ncsrf, _ = login(client, "noc", TEMP_PW)
    assert client.get("/api/admin/tenant-rules").status_code == 403
    assert client.delete(f"/api/admin/tenant-rules/{rid}", headers=h(ncsrf)).status_code == 403
    csrf, _ = login(client)
    assert client.delete(f"/api/admin/tenant-rules/{rid}", headers=h(csrf)).status_code == 200
    assert sql("SELECT count(*) FROM audit_log WHERE action LIKE 'tenant_rule.%%'")[0][0] == 3
