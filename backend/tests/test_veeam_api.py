"""APIs do Veeam sem banco: login no VBR (9419) e no Enterprise Manager (9398), detecção e mensagens."""
import asyncio
import base64
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from openmon.collector import veeam
from openmon.collector.common import CollectorError, Integration

NOW = datetime.now(timezone.utc).replace(microsecond=0)


def utc(d):  # o Enterprise Manager manda *UTC sem fuso
    return d.replace(tzinfo=None).isoformat()


def integ(port=9398, **opts):
    return Integration(id=1, tenant_id=1, kind="veeam", name="veeam", endpoint="em.empresa.local", port=port,
                       verify_tls=True, ca_cert_pem=None, options=opts, poll_interval_seconds=300,
                       username="EMPRESA\\svc", secret="Senha-1")


def job(uid, name, **kw):
    return {"UID": f"urn:veeam:Job:{uid}", "Name": name, "JobType": "Backup", "ScheduleConfigured": True,
            "ScheduleEnabled": True, **kw}


def sess(uid, job_uid, created, ended, state, result):
    return {"UID": f"urn:veeam:BackupJobSession:{uid}", "JobUid": f"urn:veeam:Job:{job_uid}",
            "CreationTimeUTC": utc(created), "EndTimeUTC": utc(ended) if ended else "0001-01-01T00:00:00",
            "State": state, "Result": result}


class FakeEm:
    """O suficiente da API REST do Enterprise Manager: sessionMngr + serviço de consulta."""

    def __init__(self, style="pascal", query=True):
        self.style, self.query = style, query  # formatos que o EM devolve conforme a versão
        self.orgs = [{"OrganizationName": "ACME", "RepositoryFriendlyName": "Repo Cloud", "QuotaGb": 1000,
                      "UsedQuotaMb": 512000, "IsEnabled": True, "UID": "urn:veeam:VCloudOrganizationConfig:o1"},
                     {"OrganizationName": "Beta", "QuotaMb": 1024, "UsedSpaceMb": 0, "IsEnabled": False,
                      "UID": "urn:veeam:VCloudOrganizationConfig:o2"}]
        self.calls = []
        self.jobs = [job("j1", "ACME - Diário"), job("j2", "BETA - SQL"), job("j3", "Infra"),
                     job("j4", "Antigo", ScheduleEnabled=False)]
        self.sessions = [
            sess("s0", "j1", NOW - timedelta(days=20), NOW - timedelta(days=20), "Stopped", "Failed"),
            sess("s1", "j1", NOW - timedelta(hours=27), NOW - timedelta(hours=26), "Stopped", "Failed"),
            sess("s2", "j1", NOW - timedelta(hours=3), NOW - timedelta(hours=2), "Stopped", "Success"),
            sess("s3", "j2", NOW - timedelta(hours=2), NOW - timedelta(hours=1), "Stopped", "Failed"),
            sess("s4", "j3", NOW - timedelta(minutes=10), None, "Working", "None"),
        ]

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.calls.append((request.method, path))
        if path == "/api/oauth2/token":
            return httpx.Response(404, json={"Message": "Resource does not exist"})
        if path == "/api/sessionMngr/":
            auth = base64.b64decode(request.headers["authorization"].split()[1]).decode()
            if auth != "EMPRESA\\svc:Senha-1":
                return httpx.Response(401, json={"Message": "Unauthorized"})
            return httpx.Response(201, headers={"X-RestSvcSessionId": "c2Vzcw=="},
                                  json={"SessionId": "urn:veeam:LogonSession:abc", "UserName": "EMPRESA\\svc"})
        if request.headers.get("x-restsvcsessionid") != "c2Vzcw==":
            return httpx.Response(401, json={"Message": "no session"})
        if path == "/api/logonSessions/abc" and request.method == "DELETE":
            return httpx.Response(204)
        if path == "/api/vCloud/orgConfigs":
            return self.out({"VCloudOrganizationConfigs": {"VCloudOrganizationConfig": self.orgs}})
        direct = {"/api/jobs": ("Jobs", "Job", self.jobs), "/api/repositories": ("Repositories", "Repository", [
            {"UID": "urn:veeam:Repository:r1", "Name": "Repo 1", "Kind": "WinLocal", "Capacity": 10 * 1024 ** 4,
             "FreeSpace": 2 * 1024 ** 4}]), "/api/backupServers": ("BackupServers", "BackupServer", [
                 {"Name": "vbr01", "Version": "12.1.2.172", "UID": "urn:veeam:BackupServer:b1"},
                 {"Name": "vbr02", "Version": "12.1.2.172", "UID": "urn:veeam:BackupServer:b2"}]),
            "/api/backupSessions": (
            "BackupJobSessions", "BackupJobSession", self.sessions)}
        if path in direct:
            outer, inner, data = direct[path]
            return self.out({outer: {inner: data}})
        if path == "/api/query" and not self.query:
            return self.out({"Entities": {}, "PagingInfo": {"PagesCount": 0}})
        if path == "/api/query":
            t = request.url.params["type"]
            if t == "BackupServer":
                data, key = [{"Name": "vbr01", "Version": "12.1.2.172", "UID": "urn:veeam:BackupServer:b1"},
                             {"Name": "vbr02", "Version": "12.1.2.172", "UID": "urn:veeam:BackupServer:b2"}], \
                    "BackupServers"
            elif t == "Job":
                data, key = self.jobs, "Jobs"
            elif t == "Repository":
                data, key = [{"UID": "urn:veeam:Repository:r1", "Name": "Repo 1", "Kind": "WinLocal",
                              "Capacity": 10 * 1024 ** 4, "FreeSpace": 2 * 1024 ** 4}], "Repositories"
            elif t == "BackupJobSession":
                assert request.url.params["sortDesc"] == "CreationTime"
                data = sorted(self.sessions, key=lambda s: s["CreationTimeUTC"], reverse=True)
                key = "BackupJobSessions"
            else:
                return httpx.Response(400, json={"Message": "bad type"})
            return self.out({"Refs": [{"UID": d["UID"], "Type": "JobReference"} for d in data[:1]],
                             "Entities": {key: {key: data}},
                             "PagingInfo": {"PageNum": 1, "PageSize": 500, "PagesCount": 1}})
        return httpx.Response(404, json={"Message": "Resource does not exist"})

    def out(self, body):
        if self.style == "camel":
            def camel(o):
                if isinstance(o, dict):
                    return {k[:1].lower() + k[1:]: camel(v) for k, v in o.items()}
                return [camel(x) for x in o] if isinstance(o, list) else o
            return httpx.Response(200, json=camel(body))
        if self.style == "xml":
            def xml(tag, v):
                if isinstance(v, dict):
                    return f"<{tag}>" + "".join(
                        "".join(xml(k, x) for x in i) if isinstance(i, list) else xml(k, i)
                        for k, i in v.items()) + f"</{tag}>"
                return f"<{tag}>{'' if v is None else str(v).lower() if isinstance(v, bool) else v}</{tag}>"
            (root, inner), = (body if len(body) == 1 else {"QueryResult": body}).items()
            return httpx.Response(200, text='<?xml version="1.0"?>' + xml(root, inner),
                                  headers={"content-type": "application/xml"})
        return httpx.Response(200, json=body)


@pytest.fixture(params=[("pascal", True), ("camel", True), ("xml", False)], ids=["pascal", "camel", "xml-sem-query"])
def em(request, monkeypatch):
    f = FakeEm(*request.param)
    monkeypatch.setattr(veeam, "_transport", httpx.MockTransport(f.handler))
    return f


def test_enterprise_manager_by_port(em):
    out = asyncio.run(veeam.test(integ()))
    assert out["ok"] and out["details"]["api"] == "em", out
    assert "2 servidor(es)" in out["summary"] and "4 job(s)" in out["summary"]
    assert ("POST", "/api/oauth2/token") not in em.calls  # 9398 vai direto ao Enterprise Manager
    assert ("DELETE", "/api/logonSessions/abc") in em.calls


def test_auto_falls_back_to_enterprise_manager_on_404(em):
    out = asyncio.run(veeam.test(integ(port=443)))
    assert out["details"]["api"] == "em"
    assert em.calls[0] == ("POST", "/api/oauth2/token")


def test_forced_vbr_on_enterprise_manager_explains(em):
    with pytest.raises(CollectorError, match="não respondeu como API REST do VBR.*Enterprise Manager"):
        asyncio.run(veeam.test(integ(api="vbr")))


def test_nothing_found_explains_ports(monkeypatch):
    monkeypatch.setattr(veeam, "_transport", httpx.MockTransport(lambda r: httpx.Response(404)))
    with pytest.raises(CollectorError, match="9419.*9398"):
        asyncio.run(veeam.test(integ()))


def test_enterprise_manager_bad_password(em):
    i = integ()
    i.secret = "errada"
    with pytest.raises(CollectorError, match="recusados pelo Enterprise Manager"):
        asyncio.run(veeam.test(i))


def test_enterprise_manager_data_in_vbr_shape(em):
    async def run():
        api = await veeam.connect(integ())
        async with api:
            repos = await api.repositories()
            sessions = await api.sessions(NOW - timedelta(days=7), ["s0", "s4"])
            jobs = await api.jobs(sessions)
            orgs = await api.org_quotas()
        return repos, sessions, jobs, orgs
    repos, sessions, jobs, orgs = asyncio.run(run())
    assert repos == [{"id": "r1", "name": "Repo 1", "type": "WinLocal", "capacityGB": 10240.0, "freeGB": 2048.0}]
    assert orgs == [{"id": "o1", "org": "ACME", "repo": "Repo Cloud", "quota": 1000 * 1024 ** 3,
                     "used": 500 * 1024 ** 3, "enabled": True},
                    {"id": "o2", "org": "Beta", "repo": "Beta", "quota": 1024 ** 3, "used": 0, "enabled": False}]
    assert [s["id"] for s in sessions] == ["s1", "s2", "s3", "s4"]  # s0 fora da janela; s4 sem duplicar
    assert [veeam._session_result(s) for s in sessions] == ["failed", "success", "failed", "running"]
    assert sessions[3]["endTime"] is None and veeam._ts(sessions[0]["creationTime"]).tzinfo is not None
    byname = {j["name"]: j for j in jobs}
    assert byname["ACME - Diário"]["lastResult"] == "Success" and byname["ACME - Diário"]["id"] == "j1"
    assert byname["BETA - SQL"]["lastResult"] == "Failed"
    assert byname["Infra"]["status"] == "running"
    assert byname["Antigo"]["status"] == "disabled" and byname["Antigo"]["lastResult"] is None


def test_vbr_rest_api_still_default_on_9419(monkeypatch):
    seen = []

    def handler(request):
        seen.append(request.url.path)
        assert request.headers["x-api-version"] == "1.1-rev1"
        if request.url.path == "/api/oauth2/token":
            return httpx.Response(200, json={"access_token": "t"})
        if request.url.path == "/api/v1/serverInfo":
            return httpx.Response(200, json={"name": "vbr01", "buildVersion": "12.1.2.172"})
        if request.url.path.startswith("/api/v1/"):
            return httpx.Response(200, json={"data": [{}], "pagination": {"total": 7}})
        return httpx.Response(200, json={})
    monkeypatch.setattr(veeam, "_transport", httpx.MockTransport(handler))
    out = asyncio.run(veeam.test(integ(port=9419)))
    assert out["details"]["api"] == "vbr" and "7 job(s)" in out["summary"]
    assert "/api/sessionMngr/" not in seen


def test_enterprise_manager_summary_counts_vcloud_orgs(em):
    out = asyncio.run(veeam.test(integ()))
    assert "2 quota(s) de organização do vCloud" in out["summary"] and out["details"]["organizations"] == 2


def test_enterprise_manager_empty_shows_diagnostic(monkeypatch):
    f = FakeEm()
    f.jobs, f.sessions, f.orgs = [], [], []
    monkeypatch.setattr(veeam, "_transport", httpx.MockTransport(f.handler))
    out = asyncio.run(veeam.test(integ()))
    assert "0 job(s)" in out["summary"] and "query Job" in out["details"]["diagnostic"], out
