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

    async def org_quotas(self) -> list[dict[str, Any]]:
        return []  # quotas do vCloud só vêm pelo Enterprise Manager

    diag: list[str] = []


def _uid(v: Any) -> str:
    """``urn:veeam:Job:6d1f...`` -> ``6d1f...`` (o mesmo id que aparece nos hrefs)."""
    return str(v or "").rsplit(":", 1)[-1]


def _xml(text: str) -> Any:
    """XML do Enterprise Manager -> dict (atributos e filhos viram chaves; filhos repetidos, listas)."""
    import xml.etree.ElementTree as ET

    def conv(e: Any) -> Any:
        kids = list(e)
        if not kids and not e.attrib:
            return (e.text or "").strip()
        d: dict[str, Any] = dict(e.attrib)
        for k in kids:
            tag = k.tag.rsplit("}", 1)[-1]
            v = conv(k)
            if tag in d:
                d[tag] = d[tag] if isinstance(d[tag], list) else [d[tag]]
                d[tag].append(v)
            else:
                d[tag] = v
        return d
    root = ET.fromstring(text)
    return {root.tag.rsplit("}", 1)[-1]: conv(root)}


def _lower(o: Any) -> Any:
    """O EM devolve PascalCase ou camelCase conforme a versão: chaves em minúsculas, uma vez só."""
    if isinstance(o, dict):
        return {str(k).lower(): _lower(v) for k, v in o.items()}
    if isinstance(o, list):
        return [_lower(x) for x in o]
    return o


def _entities(obj: Any, kind: str) -> list[dict[str, Any]]:
    """Entidades ``urn:veeam:<kind>:...`` em qualquer nível da resposta (sem as referências/links)."""
    prefix = f"urn:veeam:{kind.lower()}:"
    out: dict[str, dict[str, Any]] = {}

    def walk(n: Any, depth: int) -> None:
        if depth > 10:
            return
        if isinstance(n, list):
            for x in n:
                walk(x, depth + 1)
            return
        if not isinstance(n, dict):
            return
        uid = str(n.get("uid") or "")
        if uid.lower().startswith(prefix) and not str(n.get("type") or "").lower().endswith("reference"):
            out.setdefault(uid, n)
            return
        for k, v in n.items():
            if k != "links":
                walk(v, depth + 1)
    walk(obj, 0)
    return list(out.values())


def _with_fields(obj: Any, fields: tuple[str, ...]) -> list[dict[str, Any]]:
    """Objetos que têm algum dos campos, como o template do Zabbix faz com as orgConfigs."""
    out: list[dict[str, Any]] = []

    def walk(n: Any, depth: int) -> None:
        if depth > 10:
            return
        if isinstance(n, list):
            for x in n:
                walk(x, depth + 1)
        elif isinstance(n, dict):
            if any(n.get(f) not in (None, "") for f in fields):
                out.append(n)
                return
            for v in n.values():
                walk(v, depth + 1)
    walk(obj, 0)
    return out


def _shape(node: Any, depth: int = 0) -> str:
    """Só os nomes dos campos e tamanhos das listas, para diagnóstico quando nada é encontrado."""
    if not isinstance(node, (dict, list)):
        return type(node).__name__
    if depth > 3:
        return "..."
    if isinstance(node, list):
        return f"[{len(node)}{' x ' + _shape(node[0], depth + 1) if node else ''}]"
    return "{" + ",".join(f"{k}:{_shape(v, depth + 1)}" for k, v in node.items()) + "}"


def _num(v: Any) -> float | None:
    if v in (None, ""):
        return None
    try:
        return float(str(v).replace(",", "."))
    except ValueError:
        return None


def _bool(v: Any) -> bool | None:
    if v in (None, ""):
        return None
    if isinstance(v, bool):
        return v
    return str(v).lower() in ("1", "true", "yes", "sim", "on")


ORG_QUOTA_FIELDS = ("quotagb", "quotamb", "usedquotamb", "usedquotagb", "usedspacemb")


class EmApi(_Base):
    """API REST do Veeam Backup Enterprise Manager (porta 9398).

    As respostas variam entre versões (JSON PascalCase, camelCase ou XML, listas embrulhadas de jeitos
    diferentes): tudo vira dict com chaves minúsculas e as entidades são achadas pelo UID
    (``urn:veeam:Job:...``), em qualquer nível. O serviço de consulta (``/api/query``) vem primeiro; se ele não
    trouxer nada, as coleções diretas (``/api/jobs``, ``/api/repositories``...) são lidas.
    """

    api = "em"
    product = "Veeam Backup Enterprise Manager"
    default_port = EM_PORT

    def __init__(self, integ: Integration) -> None:
        super().__init__(integ, {})
        self.session_id: str | None = None
        self.logon_id = ""
        self.diag: list[str] = []

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
            body = self._parse(r)
            self.logon_id = _uid(_with_fields(body, ("sessionid",))[0]["sessionid"]) if body else ""
        except (ValueError, IndexError, KeyError):
            self.logon_id = ""
        return self

    async def __aexit__(self, *exc: Any) -> None:
        try:
            if self.session_id and self.logon_id:
                await self.client.delete(f"/api/logonSessions/{self.logon_id}")
        except httpx.HTTPError:
            pass
        await self.client.aclose()

    @staticmethod
    def _parse(r: httpx.Response) -> Any:
        text = r.text.lstrip("﻿").strip()
        if not text:
            return {}
        if text.startswith("<"):
            try:
                return _lower(_xml(text))
            except Exception as exc:  # noqa: BLE001 - XML inesperado vira erro de coleta legível
                raise CollectorError(f"resposta XML inválida do Enterprise Manager em {r.request.url.path}") from exc
        return _lower(r.json())

    async def get(self, path: str, **params: Any) -> Any:
        r = await self.client.get(path, params=params)
        await self._check(r)
        return self._parse(r)

    async def _query(self, type_: str, stop: Any = None, **params: Any) -> list[dict[str, Any]]:
        """Serviço de consulta paginado; ``stop(lista_da_página)`` encerra antes (sessões em ordem decrescente)."""
        out: dict[str, dict[str, Any]] = {}
        page = 1
        while True:
            body = await self.get("/api/query", type=type_, format="Entities", pageSize=PAGE, page=page, **params)
            data = _entities(body, type_)
            if not data and page == 1:
                self.diag.append(f"query {type_}: {_shape(body)[:300]}")
            new = [d for d in data if d["uid"] not in out]
            out.update((d["uid"], d) for d in new)
            paging = _with_fields(body, ("pagescount",))
            pages = _num(paging[0].get("pagescount")) if paging else None
            if not new or len(data) < PAGE or (pages is not None and page >= pages) or page >= 400:
                return list(out.values())
            if stop and stop(data):
                return list(out.values())
            page += 1

    async def _list(self, type_: str, path: str, stop: Any = None, **params: Any) -> list[dict[str, Any]]:
        try:
            got = await self._query(type_, stop=stop, **params)
        except CollectorError as exc:
            self.diag.append(f"query {type_}: {str(exc)[:150]}")
            got = []
        if got:
            return got
        body = await self.get(path, format="Entity")
        got = _entities(body, type_)
        if not got:
            self.diag.append(f"{path}: {_shape(body)[:300]}")
        return got

    async def server_info(self) -> dict[str, Any]:
        servers = await self._list("BackupServer", "/api/backupServers")
        names = [str(s.get("name")) for s in servers if s.get("name")]
        versions = sorted({str(s.get("version")) for s in servers if s.get("version")})
        return {"name": names[0] if len(names) == 1 else f"Enterprise Manager {self.integ.endpoint}",
                "buildVersion": ", ".join(versions), "vbrId": None, "servers": names, "patches": None}

    async def count(self, what: str) -> int:
        if what == "jobs":
            return len(await self._list("Job", "/api/jobs"))
        if what == "repositories":
            return len(await self._list("Repository", "/api/repositories"))
        return len(await self.org_quotas())

    async def repositories(self) -> list[dict[str, Any]]:
        out = []
        for r in await self._list("Repository", "/api/repositories"):
            cap, free = _num(r.get("capacity")), _num(r.get("freespace"))
            out.append({"id": _uid(r.get("uid")), "name": r.get("name"), "type": r.get("kind"),
                        "capacityGB": cap / GB if cap is not None and cap >= 0 else None,
                        "freeGB": free / GB if free is not None and free >= 0 else None})
        return [r for r in out if r["id"]]

    @staticmethod
    def _session(s: dict[str, Any]) -> dict[str, Any]:
        end = s.get("endtimeutc") or s.get("endtime")
        return {"id": _uid(s.get("uid")), "jobId": _uid(s.get("jobuid")), "jobName": s.get("jobname"),
                "creationTime": s.get("creationtimeutc") or s.get("creationtime"),
                "endTime": end if _ts(end) else None, "state": s.get("state"),
                "result": {"result": s.get("result"), "message": s.get("description") or None}}

    async def sessions(self, since: datetime, extra_ids: list[str]) -> list[dict[str, Any]]:
        def older(page: list[dict[str, Any]]) -> bool:
            times = [t for t in (_ts(s.get("creationtimeutc") or s.get("creationtime")) for s in page) if t]
            return bool(times) and min(times) < since
        raw = await self._list("BackupJobSession", "/api/backupSessions", stop=older, sortDesc="CreationTime")
        out = [self._session(s) for s in raw]
        out = [s for s in out if s["id"] and (_ts(s["creationTime"]) or since) >= since]
        have = {s["id"] for s in out}
        for sid in extra_ids[:200]:
            if sid in have:
                continue
            try:
                one = _entities(await self.get(f"/api/backupSessions/{sid}", format="Entity"), "BackupJobSession")
            except CollectorError:
                continue
            out.extend(self._session(s) for s in one)
        out.sort(key=lambda s: _ts(s["creationTime"]) or since)
        return out

    async def jobs(self, sessions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """O Enterprise Manager não tem o estado do job: sai da sessão mais recente dele."""
        latest: dict[str, dict[str, Any]] = {}
        for s in sessions:  # em ordem crescente de criação
            latest[s["jobId"]] = s
        out = []
        for j in await self._list("Job", "/api/jobs"):
            jid = _uid(j.get("uid"))
            if not jid:
                continue
            s = latest.get(jid)
            running = bool(s) and _session_result(s) == "running"
            disabled = _bool(j.get("scheduleenabled")) is False and _bool(j.get("scheduleconfigured")) is True
            out.append({"id": jid, "name": j.get("name"), "type": j.get("jobtype"),
                        "status": "running" if running else ("disabled" if disabled else "inactive"),
                        "description": j.get("description") or None,
                        "lastResult": (s["result"]["result"] if s and not running else None),
                        "lastRun": s["creationTime"] if s else None})
        return out

    async def org_quotas(self) -> list[dict[str, Any]]:
        """Quotas de backup das organizações do vCloud Director (Veeam Cloud Director / orgConfigs)."""
        if hasattr(self, "_orgs"):
            return self._orgs
        items: list[dict[str, Any]] = []
        try:
            items = _with_fields(await self.get("/api/vCloud/orgConfigs", format="Entity"), ORG_QUOTA_FIELDS)
        except CollectorError as exc:
            self.diag.append(f"orgConfigs: {str(exc)[:150]}")
        if not items:
            try:
                q = await self.get("/api/query", type="VCloudOrganizationConfig", format="Entities", pageSize=1000)
                items = _with_fields(q, ORG_QUOTA_FIELDS)
            except CollectorError:
                pass
        rows = []
        for it in items:
            org = it.get("organizationname") or it.get("orgname") or it.get("name")
            if not org:
                continue
            quota = (_num(it.get("quotagb")) or 0) * GB if it.get("quotagb") not in (None, "") \
                else (_num(it.get("quotamb")) or 0) * 1024 ** 2
            used_mb = it.get("usedquotamb") if it.get("usedquotamb") not in (None, "") else it.get("usedspacemb")
            used = (_num(used_mb) or 0) * 1024 ** 2 if used_mb not in (None, "") \
                else (_num(it.get("usedquotagb")) or 0) * GB
            enabled = _bool(it.get("enabled") if it.get("enabled") not in (None, "") else it.get("isenabled"))
            if enabled is None:
                dis = _bool(it.get("disabled") if it.get("disabled") not in (None, "") else it.get("isdisabled"))
                enabled = not dis if dis is not None else True
            repo = it.get("repositoryfriendlyname") or it.get("repositoryname") or it.get("name") or org
            rows.append({"id": _uid(it.get("uid")) or f"{org}/{repo}", "org": str(org), "repo": str(repo),
                         "quota": quota, "used": used, "enabled": enabled})
        self._orgs = rows
        return rows


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
            norgs = len(await api.org_quotas())
    except CollectorError:
        raise
    except httpx.HTTPError as exc:
        raise CollectorError(_describe(exc, integ)) from exc
    if api.api == "em":
        servers = info.get("servers") or []
        summary = (f"Enterprise Manager {integ.endpoint} · {len(servers)} servidor(es) de backup"
                   f"{' (' + info['buildVersion'] + ')' if info.get('buildVersion') else ''} · {njobs} job(s)"
                   f"{f' · {norgs} quota(s) de organização do vCloud' if norgs else ''}")
    else:
        summary = f"{info.get('name') or integ.endpoint} · Veeam {info.get('buildVersion', '')} · {njobs} job(s)"
    return {"ok": True, "summary": summary,
            "details": {"product": api.product, "api": api.api, "version": info.get("buildVersion"),
                        "jobs": njobs, "repositories": nrepos,
                        **({"organizations": norgs} if api.api == "em" else {}),
                        # Nada encontrado: o formato que o Veeam devolveu, para ajustar o coletor
                        **({"diagnostic": " | ".join(api.diag)[:1500]} if api.diag and not njobs else {})}}


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
            orgs = await api.org_quotas()
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

    # Quotas de backup das organizações do vCloud (Enterprise Manager): um repositório por org/repositório,
    # no tenant da regra de "pasta / organização"
    org_items = []
    for o in orgs:
        tid = await w.tenant_for({"folder": [o["org"]], "name": o["org"]})
        org_items.append({"external_id": f"vcdorg:{o['id']}", "asset_type": "backup_repository",
                          "name": f"{o['org']} / {o['repo']}", "tenant_id": tid, "parent_id": sid,
                          "status": "up" if o["enabled"] else "maintenance", "vendor": "Veeam",
                          "model": "Quota vCloud Director",
                          "attributes": {"org": o["org"], "repository": o["repo"], "folder": o["org"],
                                         "capacity_bytes": int(o["quota"]), "free_bytes":
                                         int(max(o["quota"] - o["used"], 0)), "used_bytes": int(o["used"])}})
    org_ids = await w.assets_bulk(org_items) if org_items else {}
    for o in orgs:
        if f"vcdorg:{o['id']}" not in org_ids:
            continue
        aid, tid = org_ids[f"vcdorg:{o['id']}"]
        w.metric(aid, tid, "availability.up", 1 if o["enabled"] else 0)
        if o["quota"] > 0:
            w.metric(aid, tid, "storage.capacity.bytes", o["quota"])
            w.metric(aid, tid, "storage.free.bytes", max(o["quota"] - o["used"], 0))
        w.metric(aid, tid, "storage.used.bytes", o["used"])

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
    if org_ids:
        msg += f", {len(org_ids)} quota(s) de organização do vCloud"
    if not job_ids and not repo_ids and not org_ids and api.diag:
        msg += f"; nada encontrado. Resposta do Veeam: {' | '.join(api.diag)}"[:1500]
    # Job falhando é assunto dos alertas e do SLA, não da saúde da integração
    return msg + (f"; {failed} job(s) com a última execução falhando" if failed else "")
