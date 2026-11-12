"""Coletor Veeam Backup & Replication.

Fala com duas APIs do Veeam, escolhidas em Avançado ("API do Veeam") ou automaticamente pela porta:

- **API REST do VBR** (porta 9419, v12+): OAuth2 em ``/api/oauth2/token`` com ``x-api-version``. Estado dos
  jobs (``/jobs/states``), sessões (``/sessions``) e repositórios (``/backupInfrastructure/repositories/states``).
- **API REST do Enterprise Manager** (porta 9398): sessão em ``/api/sessionMngr/?v=latest`` com Basic auth e o
  cabeçalho ``X-RestSvcSessionId``. Jobs, sessões e repositórios saem do serviço de consulta (``/api/query``) e
  cobrem todos os servidores de backup ligados ao Enterprise Manager.

No modo automático a porta 9398 vai direto ao Enterprise Manager e as outras ao VBR; se a API escolhida
responder 404 no login, a outra é tentada na mesma porta. Os dois lados devolvem os dados no formato do VBR, e a
coleta grava jobs em ``backup_jobs`` com o tenant das regras (campo ``veeam_job``), as sessões em
``backup_job_runs`` e os repositórios como ativos com métricas de capacidade. O SLA por tenant (horas desde o
último backup bom) sai dessas tabelas.
"""
from __future__ import annotations

import ssl
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from openmon.collector.common import CollectorError, Integration, Writer, now

PAGE = 500
API_VERSION = "1.1-rev1"
VBR_PORT, EM_PORT = 9419, 9398
RESULT = {"success": "success", "warning": "warning", "failed": "failed", "none": "none"}
GB = 1024 ** 3
WRONG_API = ("{host}:{port} não tem a API REST do Veeam B&R nem a do Enterprise Manager (HTTP 404). Use a porta "
             "9419 para o servidor do Backup & Replication (v12+) ou 9398 para o Enterprise Manager")

# Testes trocam por um httpx.MockTransport
_transport: httpx.AsyncBaseTransport | None = None


class NotThisApi(CollectorError):
    """O login respondeu 404: a porta não é desta API (o modo automático tenta a outra)."""


def _verify(integ: Integration) -> ssl.SSLContext | bool:
    if not integ.verify_tls:
        return False
    ctx = ssl.create_default_context()
    if integ.ca_cert_pem:
        ctx.load_verify_locations(cadata=integ.ca_cert_pem)
    return ctx


def _ts(v: Any) -> datetime | None:
    if not v:
        return None
    try:
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return None
    if d.tzinfo is None:  # o Enterprise Manager manda os campos *UTC sem fuso
        d = d.replace(tzinfo=timezone.utc)
    return None if d.year < 1971 else d


def _mode(integ: Integration) -> str:
    m = str(integ.options.get("api") or "auto").lower()
    if m in ("vbr", "em"):
        return m
    return "em" if (integ.port or VBR_PORT) in (EM_PORT, 9399) else "vbr"


class _Base:
    product = "Veeam Backup & Replication"

    def __init__(self, integ: Integration, headers: dict[str, str]) -> None:
        self.integ = integ
        self.base = f"https://{integ.endpoint}:{integ.port or self.default_port}"
        self.client = httpx.AsyncClient(base_url=self.base, verify=_verify(integ), timeout=30.0,
                                        transport=_transport, headers={"Accept": "application/json", **headers})

    default_port = VBR_PORT

    def _msg(self, r: httpx.Response) -> str:
        try:
            body = r.json()
        except ValueError:
            return r.text[:200]
        if isinstance(body, dict):
            return str(body.get("message") or body.get("Message") or body.get("errorCode") or "")
        return ""

    async def _check(self, r: httpx.Response) -> None:
        if r.status_code < 400:
            return
        msg = self._msg(r)
        if r.status_code == 403:
            raise CollectorError("a conta não tem permissão para ler este dado no Veeam")
        raise CollectorError(f"Veeam respondeu HTTP {r.status_code} em {r.request.url.path}: {msg}"[:400])

    async def get(self, path: str, **params: Any) -> Any:
        r = await self.client.get(path, params=params)
        await self._check(r)
        return r.json()


class Api(_Base):
    """API REST do servidor do Backup & Replication (porta 9419)."""

    api = "vbr"

    def __init__(self, integ: Integration) -> None:
        self.version = str(integ.options.get("api_version") or API_VERSION)
        super().__init__(integ, {"x-api-version": self.version})
        self.token: str | None = None

    async def __aenter__(self) -> "Api":
        try:
            r = await self.client.post("/api/oauth2/token", data={
                "grant_type": "password", "username": self.integ.username or "", "password": self.integ.secret or ""})
            if r.status_code in (400, 401) and "version" not in self._msg(r).lower():
                raise CollectorError("usuário ou senha recusados pelo Veeam (use DOMINIO\\usuario com papel "
                                     "Backup Viewer ou superior)")
            if r.status_code in (404, 405):
                raise NotThisApi(f"HTTP {r.status_code} em /api/oauth2/token")
            await self._check(r)
            self.token = r.json().get("access_token")
        except BaseException:
            await self.client.aclose()
            raise
        self.client.headers["Authorization"] = f"Bearer {self.token}"
        return self

    async def __aexit__(self, *exc: Any) -> None:
        try:
            if self.token:
                await self.client.post("/api/oauth2/logout")
        except httpx.HTTPError:
            pass
        await self.client.aclose()

    async def _check(self, r: httpx.Response) -> None:
        if r.status_code == 400 and "version" in self._msg(r).lower():
            raise CollectorError(f"versão da API {self.version} não aceita por este Veeam: {self._msg(r)}. Ajuste "
                                 "em Avançado (12.0 = 1.1-rev0, 12.1+ = 1.1-rev1, 13 = 1.2-rev0)")
        await super()._check(r)

    async def all(self, path: str, **params: Any) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        skip = 0
        while True:
            page = await self.get(path, skip=skip, limit=PAGE, **params)
            data = page.get("data") or []
            out.extend(data)
            total = (page.get("pagination") or {}).get("total")
            skip += len(data)
            if not data or len(data) < PAGE or (total is not None and skip >= total) or skip > 200_000:
                return out

    # Interface comum (formato da API do VBR)
    async def server_info(self) -> dict[str, Any]:
        return await self.get("/api/v1/serverInfo")

    async def count(self, what: str) -> int:
        path = {"jobs": "/api/v1/jobs/states", "repositories": "/api/v1/backupInfrastructure/repositories/states"}
        page = await self.get(path[what], limit=1)
        return (page.get("pagination") or {}).get("total", len(page.get("data") or []))

    async def repositories(self) -> list[dict[str, Any]]:
        return await self.all("/api/v1/backupInfrastructure/repositories/states")

    async def sessions(self, since: datetime, extra_ids: list[str]) -> list[dict[str, Any]]:
        out = await self.all("/api/v1/sessions", createdAfterFilter=since.isoformat(),
                             orderColumn="CreationTime", orderAsc="true")
        for sid in extra_ids[:200]:  # sessões em andamento há mais de 1 dia
            try:
                out.append(await self.get(f"/api/v1/sessions/{sid}"))
            except CollectorError:
                pass
        return out

    async def jobs(self, sessions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return await self.all("/api/v1/jobs/states")


def _uid(v: Any) -> str:
    """``urn:veeam:Job:6d1f...`` -> ``6d1f...`` (o mesmo id que aparece nos hrefs)."""
    return str(v or "").rsplit(":", 1)[-1]


def _find_list(obj: Any, key: str) -> list[dict[str, Any]]:
    """Lista ``key`` em qualquer nível do JSON do Enterprise Manager (``{"Entities": {"Jobs": {"Jobs": [...]}}}``)."""
    if isinstance(obj, dict):
        v = obj.get(key)
        if isinstance(v, list):
            return [x for x in v if isinstance(x, dict)]
        for k in (key, *[k for k in obj if k != key]):
            if isinstance(obj.get(k), dict):
                found = _find_list(obj[k], key)
                if found:
                    return found
    return []


class EmApi(_Base):
    """API REST do Veeam Backup Enterprise Manager (porta 9398)."""

    api = "em"
    product = "Veeam Backup Enterprise Manager"
    default_port = EM_PORT

    def __init__(self, integ: Integration) -> None:
        super().__init__(integ, {})
        self.session_id: str | None = None

    async def __aenter__(self) -> "EmApi":
        try:
            r = await self.client.post("/api/sessionMngr/?v=latest",
                                       auth=(self.integ.username or "", self.integ.secret or ""))
            if r.status_code == 401:
                raise CollectorError("usuário ou senha recusados pelo Enterprise Manager (use DOMINIO\\usuario com "
                                     "papel Portal Administrator no Enterprise Manager)")
            if r.status_code in (404, 405):
                raise NotThisApi(f"HTTP {r.status_code} em /api/sessionMngr/")
            await self._check(r)
            self.session_id = r.headers.get("X-RestSvcSessionId")
            if not self.session_id:
                raise CollectorError("o Enterprise Manager não devolveu o X-RestSvcSessionId no login")
        except BaseException:
            await self.client.aclose()
            raise
        self.client.headers["X-RestSvcSessionId"] = self.session_id
        try:
            self.logon_id = _uid((r.json() or {}).get("SessionId") or (r.json() or {}).get("UID"))
        except ValueError:
            self.logon_id = ""
        return self

    async def __aexit__(self, *exc: Any) -> None:
        try:
            if self.session_id and self.logon_id:
                await self.client.delete(f"/api/logonSessions/{self.logon_id}")
        except httpx.HTTPError:
            pass
        await self.client.aclose()

    async def query(self, type_: str, key: str, stop: Any = None, **params: Any) -> list[dict[str, Any]]:
        """Serviço de consulta paginado; ``stop(lista_da_página)`` encerra antes (sessões em ordem decrescente)."""
        out: list[dict[str, Any]] = []
        page = 1
        while True:
            body = await self.get("/api/query", type=type_, format="Entities", pageSize=PAGE, page=page, **params)
            data = _find_list(body, key)
            out.extend(data)
            paging = body.get("PagingInfo") if isinstance(body, dict) else None
            pages = paging.get("PagesCount") if isinstance(paging, dict) else None
            if not data or len(data) < PAGE or (pages is not None and page >= int(pages)) or page >= 400:
                return out
            if stop and stop(data):
                return out
            page += 1

    async def server_info(self) -> dict[str, Any]:
        servers = await self.query("BackupServer", "BackupServers")
        names = [s.get("Name") for s in servers if s.get("Name")]
        versions = sorted({str(s.get("Version")) for s in servers if s.get("Version")})
        return {"name": names[0] if len(names) == 1 else f"Enterprise Manager {self.integ.endpoint}",
                "buildVersion": ", ".join(versions), "vbrId": None, "servers": names,
                "patches": None}

    async def count(self, what: str) -> int:
        key = {"jobs": ("Job", "Jobs"), "repositories": ("Repository", "Repositories")}[what]
        return len(await self.query(*key))

    async def repositories(self) -> list[dict[str, Any]]:
        out = []
        for r in await self.query("Repository", "Repositories"):
            cap, free = r.get("Capacity"), r.get("FreeSpace")
            out.append({"id": _uid(r.get("UID")), "name": r.get("Name"), "type": r.get("Kind"),
                        "capacityGB": cap / GB if isinstance(cap, (int, float)) and cap >= 0 else None,
                        "freeGB": free / GB if isinstance(free, (int, float)) and free >= 0 else None})
        return [r for r in out if r["id"]]

    @staticmethod
    def _session(s: dict[str, Any]) -> dict[str, Any]:
        end = s.get("EndTimeUTC") or s.get("EndTime")
        return {"id": _uid(s.get("UID")), "jobId": _uid(s.get("JobUid")), "jobName": s.get("JobName"),
                "creationTime": s.get("CreationTimeUTC") or s.get("CreationTime"),
                "endTime": end if _ts(end) else None, "state": s.get("State"),
                "result": {"result": s.get("Result"), "message": s.get("Description") or None}}

    async def sessions(self, since: datetime, extra_ids: list[str]) -> list[dict[str, Any]]:
        def older(page: list[dict[str, Any]]) -> bool:
            last = _ts(page[-1].get("CreationTimeUTC") or page[-1].get("CreationTime"))
            return last is not None and last < since
        raw = await self.query("BackupJobSession", "BackupJobSessions", stop=older, sortDesc="CreationTime")
        out = [self._session(s) for s in raw]
        out = [s for s in out if (_ts(s["creationTime"]) or since) >= since]
        have = {s["id"] for s in out}
        for sid in extra_ids[:200]:
            if sid in have:
                continue
            try:
                one = await self.get(f"/api/backupSessions/{sid}", format="Entity")
            except CollectorError:
                continue
            if isinstance(one, dict):
                out.append(self._session(one))
        out.sort(key=lambda s: str(s["creationTime"] or ""))
        return out

    async def jobs(self, sessions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """O Enterprise Manager não tem o estado do job: sai da sessão mais recente dele."""
        latest: dict[str, dict[str, Any]] = {}
        for s in sessions:  # em ordem crescente de criação
            latest[s["jobId"]] = s
        out = []
        for j in await self.query("Job", "Jobs"):
            jid = _uid(j.get("UID"))
            if not jid:
                continue
            s = latest.get(jid)
            running = bool(s) and _session_result(s) == "running"
            status = "running" if running else ("disabled" if j.get("ScheduleEnabled") is False
                                                and j.get("ScheduleConfigured") else "inactive")
            out.append({"id": jid, "name": j.get("Name"), "type": j.get("JobType"), "status": status,
                        "description": j.get("Description"),
                        "lastResult": (s["result"]["result"] if s and not running else None),
                        "lastRun": s["creationTime"] if s else None})
        return out


async def connect(integ: Integration) -> _Base:
    """Abre a sessão na API escolhida; no modo automático, 404 no login faz tentar a outra."""
    mode = _mode(integ)
    first, second = (EmApi, Api) if mode == "em" else (Api, EmApi)
    try:
        return await first(integ).__aenter__()
    except NotThisApi:
        if str(integ.options.get("api") or "auto").lower() in ("vbr", "em"):
            other = "Enterprise Manager (9398)" if mode == "vbr" else "API REST do VBR (9419)"
            raise CollectorError(f"{integ.endpoint}:{integ.port} não respondeu como "
                                 f"{'API REST do VBR' if mode == 'vbr' else 'Enterprise Manager'} (HTTP 404). "
                                 f"Confira a porta ou troque a API para {other} em Avançado") from None
    try:
        return await second(integ).__aenter__()
    except NotThisApi:
        raise CollectorError(WRONG_API.format(host=integ.endpoint, port=integ.port)) from None


def _describe(exc: BaseException, integ: Integration) -> str:
    if isinstance(exc, httpx.ConnectError):
        text = str(exc)
        if "CERTIFICATE_VERIFY_FAILED" in text:
            return ("certificado do Veeam não confiável. Cole a CA em Avançado ou, só em laboratório, desmarque a "
                    "validação")
        if "refused" in text.lower():
            return (f"{integ.endpoint}:{integ.port} recusou a conexão (a API REST do VBR escuta na 9419 e a do "
                    "Enterprise Manager na 9398)")
        return f"não foi possível conectar em {integ.endpoint}:{integ.port}: {text[:200]}"
    if isinstance(exc, httpx.TimeoutException):
        return f"sem resposta de {integ.endpoint}:{integ.port} (timeout)"
    return f"{type(exc).__name__}: {str(exc)[:200]}"


async def test(integ: Integration) -> dict[str, Any]:
    try:
        api = await connect(integ)
        async with api:
            info = await api.server_info()
            njobs = await api.count("jobs")
            nrepos = await api.count("repositories")
    except CollectorError:
        raise
    except httpx.HTTPError as exc:
        raise CollectorError(_describe(exc, integ)) from exc
    if api.api == "em":
        servers = info.get("servers") or []
        summary = (f"Enterprise Manager {integ.endpoint} · {len(servers)} servidor(es) de backup"
                   f"{' (' + info['buildVersion'] + ')' if info.get('buildVersion') else ''} · {njobs} job(s)")
    else:
        summary = f"{info.get('name') or integ.endpoint} · Veeam {info.get('buildVersion', '')} · {njobs} job(s)"
    return {"ok": True, "summary": summary,
            "details": {"product": api.product, "api": api.api, "version": info.get("buildVersion"),
                        "jobs": njobs, "repositories": nrepos}}


def _session_result(s: dict[str, Any]) -> str:
    state = str(s.get("state") or "").lower()
    res = s.get("result") or {}
    if state not in ("stopped", "") and not s.get("endTime"):
        return "running"
    if res.get("isCanceled"):
        return "canceled"
    r = str(res.get("result") or "").lower()
    return {"success": "success", "warning": "warning", "failed": "failed"}.get(r, "running" if r == "none" and
                                                                                not s.get("endTime") else "failed")


async def poll(integ: Integration, w: Writer) -> str:
    conn = w.conn
    try:
        api = await connect(integ)
        async with api:
            info = await api.server_info()
            repos = await api.repositories()
            last = await conn.fetchval(
                "SELECT max(r.started_at) FROM backup_job_runs r JOIN backup_jobs j ON j.id = r.job_id "
                "WHERE j.integration_id = $1", integ.id)
            # Volta 1 dia para pegar sessões longas que terminaram depois da última coleta
            since = (last - timedelta(days=1)) if last else now() - timedelta(days=7)
            running_ids = [r["session_external_id"] for r in await conn.fetch(
                "SELECT r.session_external_id FROM backup_job_runs r JOIN backup_jobs j ON j.id = r.job_id "
                "WHERE j.integration_id = $1 AND r.result = 'running' AND r.started_at < $2", integ.id, since)]
            sessions = await api.sessions(since, running_ids)
            jobs = await api.jobs(sessions)
    except CollectorError:
        raise
    except httpx.HTTPError as exc:
        raise CollectorError(_describe(exc, integ)) from exc

    server = await w.assets_bulk([{"external_id": "veeam-server", "asset_type": "backup_server",
                                   "name": info.get("name") or integ.name, "hostname": integ.endpoint,
                                   "vendor": "Veeam",
                                   "model": "Backup Enterprise Manager" if api.api == "em" else "Backup & Replication",
                                   "os_name": f"Veeam B&R {info.get('buildVersion', '')}".strip(),
                                   "attributes": {"api": api.api, "servers": info.get("servers"), "vbr_id": info.get("vbrId"),
                                                  "version": info.get("buildVersion"), "patches": info.get("patches")}}])
    sid, stid = server["veeam-server"]
    w.metric(sid, stid, "availability.up", 1)

    repo_ids = await w.assets_bulk([
        {"external_id": f"repo:{r['id']}", "asset_type": "backup_repository", "name": r.get("name") or r["id"],
         "parent_id": sid, "status": "down" if r.get("isOnline") is False else "up",
         "hostname": r.get("hostName"), "model": r.get("type"),
         "attributes": {"path": r.get("path"), "type": r.get("type"),
                        "capacity_bytes": int((r.get("capacityGB") or 0) * GB),
                        "free_bytes": int((r.get("freeGB") or 0) * GB)}}
        for r in repos if r.get("id")])
    for r in repos:
        if f"repo:{r.get('id')}" not in repo_ids:
            continue
        aid, tid = repo_ids[f"repo:{r['id']}"]
        cap, free = r.get("capacityGB"), r.get("freeGB")
        w.metric(aid, tid, "availability.up", 0 if r.get("isOnline") is False else 1)
        if cap is not None:
            w.metric(aid, tid, "storage.capacity.bytes", cap * GB)
        if free is not None:
            w.metric(aid, tid, "storage.free.bytes", free * GB)
        used = r.get("usedSpaceGB")
        if used is None and cap is not None and free is not None:
            used = cap - free
        w.metric(aid, tid, "storage.used.bytes", used * GB if used is not None else None)

    job_ids: dict[str, tuple[int, int]] = {}
    for j in jobs:
        if not j.get("id"):
            continue
        status = str(j.get("status") or "").lower()
        result = "running" if status == "running" else RESULT.get(str(j.get("lastResult") or "none").lower(), "none")
        tenant = await w.tenant_for({"veeam_job": j.get("name"), "name": j.get("name") or ""})
        repo = repo_ids.get(f"repo:{j.get('repositoryId')}")
        row = await conn.fetchrow(
            """INSERT INTO backup_jobs (tenant_id, integration_id, external_id, name, job_type, is_enabled,
                                        schedule_desc, repository_id, last_result, last_run_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
               ON CONFLICT (integration_id, external_id) DO UPDATE SET
                   tenant_id = CASE WHEN backup_jobs.tenant_locked THEN backup_jobs.tenant_id
                                    ELSE EXCLUDED.tenant_id END,
                   name = EXCLUDED.name, job_type = EXCLUDED.job_type, is_enabled = EXCLUDED.is_enabled,
                   schedule_desc = EXCLUDED.schedule_desc, repository_id = EXCLUDED.repository_id,
                   -- sem execução na janela (Enterprise Manager): mantém o último resultado conhecido
                   last_result = CASE WHEN EXCLUDED.last_result = 'none' AND backup_jobs.last_result IS NOT NULL
                                      THEN backup_jobs.last_result ELSE EXCLUDED.last_result END,
                   last_run_at = coalesce(EXCLUDED.last_run_at, backup_jobs.last_run_at),
                   deleted_at = NULL, updated_at = now()
               RETURNING id, tenant_id""",
            tenant, integ.id, j["id"], (j.get("name") or j["id"])[:250], j.get("type"), status != "disabled",
            (j.get("description") or "")[:500] or None, repo[0] if repo else None, result, _ts(j.get("lastRun")))
        job_ids[j["id"]] = (row["id"], row["tenant_id"])
    # Cada job também vira um ativo "other" (escondido do Inventário) para os alertas terem um problema por job
    jrows = await conn.fetch("SELECT id, external_id, name, tenant_id, last_result, repository_id FROM backup_jobs "
                             "WHERE integration_id = $1 AND id = ANY($2::bigint[])", integ.id,
                             [v[0] for v in job_ids.values()])
    await w.assets_bulk([{"external_id": f"job:{r['external_id']}", "asset_type": "other", "name": r["name"],
                          "tenant_id": r["tenant_id"], "parent_id": r["repository_id"] or sid,
                          "status": "warning" if r["last_result"] == "failed" else "up", "vendor": "Veeam",
                          "attributes": {"backup_job_id": r["id"]}} for r in jrows])
    if job_ids:
        await conn.execute("UPDATE backup_jobs SET deleted_at = now(), updated_at = now() WHERE integration_id = $1 "
                           "AND deleted_at IS NULL AND NOT (id = ANY($2::bigint[]))",
                           integ.id, [v[0] for v in job_ids.values()])

    await w.retire_missing(("backup_repository", "other"))

    runs = []
    for s in sessions:
        job = job_ids.get(str(s.get("jobId") or ""))
        started = _ts(s.get("creationTime"))
        if not job or not started or not s.get("id"):
            continue
        ended = _ts(s.get("endTime"))
        result = _session_result(s)
        runs.append((job[1], job[0], str(s["id"]), started, ended, result,
                     int((ended - started).total_seconds()) if ended else None,
                     ((s.get("result") or {}).get("message") or "")[:2000] or None))
    if runs:
        await conn.executemany(
            """INSERT INTO backup_job_runs (tenant_id, job_id, session_external_id, started_at, ended_at, result,
                                            duration_s, message)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
               ON CONFLICT (job_id, session_external_id) DO UPDATE SET
                   tenant_id = EXCLUDED.tenant_id, ended_at = EXCLUDED.ended_at, result = EXCLUDED.result,
                   duration_s = EXCLUDED.duration_s, message = EXCLUDED.message""", runs)
        # Sessões herdam o tenant do job (se o job mudou de cliente, o histórico acompanha)
        await conn.execute(
            """UPDATE backup_job_runs r SET tenant_id = j.tenant_id FROM backup_jobs j
                WHERE r.job_id = j.id AND j.integration_id = $1 AND r.tenant_id <> j.tenant_id""", integ.id)
    await conn.execute(
        """UPDATE backup_jobs j SET last_success_at = s.at
             FROM (SELECT job_id, max(coalesce(ended_at, started_at)) AS at FROM backup_job_runs
                    WHERE result IN ('success', 'warning') GROUP BY job_id) s
            WHERE s.job_id = j.id AND j.integration_id = $1
              AND (j.last_success_at IS NULL OR j.last_success_at < s.at)""", integ.id)
    failed = sum(1 for j in jobs if str(j.get("lastResult") or "").lower() == "failed")
    msg = f"{len(job_ids)} job(s), {len(runs)} sessão(ões), {len(repo_ids)} repositório(s)"
    # Job falhando é assunto dos alertas e do SLA, não da saúde da integração
    return msg + (f"; {failed} job(s) com a última execução falhando" if failed else "")
