"""Coletor Veeam Backup & Replication pela API REST (porta 9419, v12+).

A cada coleta: estado dos jobs (``/jobs/states``), sessões novas ou em andamento
(``/sessions``), repositórios com capacidade e espaço livre
(``/backupInfrastructure/repositories/states``). Jobs vão para ``backup_jobs`` com
o tenant das regras (campo ``veeam_job``), as sessões para ``backup_job_runs``
e os repositórios viram ativos com métricas de capacidade. O SLA por tenant
(horas desde o último backup bom) sai dessas tabelas.
"""
from __future__ import annotations

import ssl
from datetime import datetime, timedelta
from typing import Any

import httpx

from openmon.collector.common import CollectorError, Integration, Writer, now

PAGE = 500
API_VERSION = "1.1-rev1"
RESULT = {"success": "success", "warning": "warning", "failed": "failed", "none": "none"}
GB = 1024 ** 3

# Testes trocam por um httpx.MockTransport
_transport: httpx.AsyncBaseTransport | None = None


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
    return None if d.year < 1971 else d


class Api:
    def __init__(self, integ: Integration) -> None:
        self.integ = integ
        self.base = f"https://{integ.endpoint}:{integ.port or 9419}"
        self.version = str(integ.options.get("api_version") or API_VERSION)
        self.client = httpx.AsyncClient(base_url=self.base, verify=_verify(integ), timeout=30.0,
                                        transport=_transport, headers={"x-api-version": self.version,
                                                                       "Accept": "application/json"})
        self.token: str | None = None

    async def __aenter__(self) -> "Api":
        try:
            r = await self.client.post("/api/oauth2/token", data={
                "grant_type": "password", "username": self.integ.username or "", "password": self.integ.secret or ""})
        except BaseException:
            await self.client.aclose()
            raise
        if r.status_code in (400, 401):
            await self.client.aclose()
            raise CollectorError("usuário ou senha recusados pelo Veeam (use DOMINIO\\usuario com papel "
                                 "Backup Viewer ou superior)")
        await self._check(r)
        self.token = r.json().get("access_token")
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
        if r.status_code < 400:
            return
        try:
            body = r.json()
            msg = body.get("message") or body.get("errorCode") or ""
        except ValueError:
            msg = r.text[:200]
        if r.status_code == 400 and "version" in str(msg).lower():
            raise CollectorError(f"versão da API {self.version} não aceita por este Veeam: {msg}. Ajuste em "
                                 "Avançado (12.0 = 1.1-rev0, 12.1+ = 1.1-rev1, 13 = 1.2-rev0)")
        if r.status_code == 403:
            raise CollectorError("a conta não tem permissão para ler este dado no Veeam")
        raise CollectorError(f"Veeam respondeu HTTP {r.status_code} em {r.request.url.path}: {msg}"[:400])

    async def get(self, path: str, **params: Any) -> Any:
        r = await self.client.get(path, params=params)
        await self._check(r)
        return r.json()

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


def _describe(exc: BaseException, integ: Integration) -> str:
    if isinstance(exc, httpx.ConnectError):
        text = str(exc)
        if "CERTIFICATE_VERIFY_FAILED" in text:
            return ("certificado do Veeam não confiável. Cole a CA em Avançado ou, só em laboratório, desmarque a "
                    "validação")
        if "refused" in text.lower():
            return f"{integ.endpoint}:{integ.port} recusou a conexão (a API REST do Veeam escuta na 9419)"
        return f"não foi possível conectar em {integ.endpoint}:{integ.port}: {text[:200]}"
    if isinstance(exc, httpx.TimeoutException):
        return f"sem resposta de {integ.endpoint}:{integ.port} (timeout)"
    return f"{type(exc).__name__}: {str(exc)[:200]}"


async def test(integ: Integration) -> dict[str, Any]:
    try:
        async with Api(integ) as api:
            info = await api.get("/api/v1/serverInfo")
            jobs = await api.get("/api/v1/jobs/states", limit=1)
            repos = await api.get("/api/v1/backupInfrastructure/repositories/states", limit=1)
    except CollectorError:
        raise
    except httpx.HTTPError as exc:
        raise CollectorError(_describe(exc, integ)) from exc
    njobs = (jobs.get("pagination") or {}).get("total", len(jobs.get("data") or []))
    nrepos = (repos.get("pagination") or {}).get("total", len(repos.get("data") or []))
    return {"ok": True, "summary": f"{info.get('name') or integ.endpoint} · Veeam {info.get('buildVersion', '')} · "
                                   f"{njobs} job(s)",
            "details": {"product": "Veeam Backup & Replication", "version": info.get("buildVersion"),
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
        async with Api(integ) as api:
            info = await api.get("/api/v1/serverInfo")
            repos = await api.all("/api/v1/backupInfrastructure/repositories/states")
            jobs = await api.all("/api/v1/jobs/states")
            last = await conn.fetchval(
                "SELECT max(r.started_at) FROM backup_job_runs r JOIN backup_jobs j ON j.id = r.job_id "
                "WHERE j.integration_id = $1", integ.id)
            # Volta 1 dia para pegar sessões longas que terminaram depois da última coleta
            since = (last - timedelta(days=1)) if last else now() - timedelta(days=7)
            running_ids = [r["session_external_id"] for r in await conn.fetch(
                "SELECT r.session_external_id FROM backup_job_runs r JOIN backup_jobs j ON j.id = r.job_id "
                "WHERE j.integration_id = $1 AND r.result = 'running' AND r.started_at < $2", integ.id, since)]
            sessions = await api.all("/api/v1/sessions", createdAfterFilter=since.isoformat(),
                                     orderColumn="CreationTime", orderAsc="true")
            for sid in running_ids[:200]:  # sessões em andamento há mais de 1 dia
                try:
                    sessions.append(await api.get(f"/api/v1/sessions/{sid}"))
                except CollectorError:
                    pass
    except CollectorError:
        raise
    except httpx.HTTPError as exc:
        raise CollectorError(_describe(exc, integ)) from exc

    server = await w.assets_bulk([{"external_id": "veeam-server", "asset_type": "backup_server",
                                   "name": info.get("name") or integ.name, "hostname": integ.endpoint,
                                   "vendor": "Veeam", "model": "Backup & Replication",
                                   "os_name": f"Veeam B&R {info.get('buildVersion', '')}".strip(),
                                   "attributes": {"vbr_id": info.get("vbrId"), "version": info.get("buildVersion"),
                                                  "patches": info.get("patches")}}])
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
                   last_result = EXCLUDED.last_result,
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
