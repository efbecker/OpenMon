"""Coletor VMware Cloud Director (vCloud Director) pela API REST, só leitura.

Cadastrado como uma integração "VMware" com ``options.api = "vcd"`` (o banco não
muda: o vCD é a camada de nuvem sobre o vCenter). A cada coleta:

* login: conta do provedor (``usuario@System``) em ``/cloudapi/1.0.0/sessions/provider``,
  conta de uma organização (``usuario@Org``) em ``/cloudapi/1.0.0/sessions``, ou API token
  (refresh token) em ``/oauth/provider/token`` / ``/oauth/tenant/<org>/token``;
* Query Service em lote (128 registros por página): VDCs, perfis de armazenamento e VMs;
* cada VDC vira um ativo "datacenter" com CPU e memória usadas x alocadas, cada perfil de
  armazenamento um "datastore" com limite e uso, cada VM um "vm" com vCPU, RAM e disco;
* o tenant do VDC sai das regras (o campo "Pasta / organização" casa com ``Org`` e ``Org/VDC``) ou de
  o administrador fixá-lo num cliente; perfis de armazenamento e VMs seguem o tenant do VDC.

* uso real por VM ligada (CPU, memória, disco, throughput de disco e, quando o vCD expõe,
  rede) vem de ``/api/vApp/vm-<id>/metrics/current``, várias VMs em paralelo. Desligue com
  ``options.vm_metrics = false``; a concorrência é ``options.metrics_concurrency`` (padrão 16).
  A conta precisa do direito "View VM metrics"; sem ele a coleta segue só com o inventário.
"""
from __future__ import annotations

import asyncio
import fnmatch
import ssl
from typing import Any

import httpx

from openmon.collector.common import CollectorError, Integration, Writer

API_VERSION = "38.0"
PAGE = 128
MB = 1024 * 1024
# /metrics/current do vCD -> (métrica OpenMon, fator). KILOBYTE e KILOBYTES_PER_SECOND são KiB.
VM_METRICS = {"cpu.usage.average": ("cpu.usage.pct", 1), "cpu.usagemhz.average": ("cpu.usage.mhz", 1),
              "mem.usage.average": ("mem.usage.pct", 1), "disk.provisioned.latest": ("disk.capacity.bytes", 1024),
              "disk.used.latest": ("disk.used.bytes", 1024), "disk.read.average": ("disk.read.bps", 1024),
              "disk.write.average": ("disk.write.bps", 1024), "net.received.average": ("net.rx.bps", 8192),
              "net.transmitted.average": ("net.tx.bps", 8192)}
METRICS_CONCURRENCY = 16
STATUS_VM = {"POWERED_ON": "up", "POWERED_OFF": "powered_off", "SUSPENDED": "suspended",
             "PARTIALLY_POWERED_OFF": "warning", "MIXED": "warning"}

# Testes trocam por um httpx.MockTransport
_transport: httpx.AsyncBaseTransport | None = None


def is_vcd(integ: Integration) -> bool:
    return (integ.options or {}).get("api") == "vcd"


def _verify(integ: Integration) -> ssl.SSLContext | bool:
    if not integ.verify_tls:
        return False
    ctx = ssl.create_default_context()
    if integ.ca_cert_pem:
        ctx.load_verify_locations(cadata=integ.ca_cert_pem)
    return ctx


def _uuid(href: str | None) -> str:
    """``https://.../api/vdc/9a1b...`` ou ``urn:vcloud:vdc:9a1b...`` -> ``9a1b...``."""
    s = str(href or "").rstrip("/")
    return s.rsplit("/", 1)[-1].rsplit(":", 1)[-1]


def _org_of(username: str) -> str:
    return username.rsplit("@", 1)[1] if "@" in username else "System"


class Api:
    def __init__(self, integ: Integration) -> None:
        self.integ = integ
        port = integ.port or 443
        self.base = f"https://{integ.endpoint}" + ("" if port == 443 else f":{port}")
        self.version = str(integ.options.get("api_version") or API_VERSION)
        self.client = httpx.AsyncClient(base_url=self.base, verify=_verify(integ), timeout=60.0,
                                        transport=_transport)
        self.token: str | None = None
        self.provider = True
        self.org = "System"

    @property
    def accept(self) -> str:
        return f"application/*+json;version={self.version}"

    async def __aenter__(self) -> "Api":
        try:
            await self._login()
        except BaseException:
            await self.client.aclose()
            raise
        self.client.headers["Authorization"] = f"Bearer {self.token}"
        return self

    async def _login(self) -> None:
        user = (self.integ.username or "").strip()
        if (self.integ.options or {}).get("auth") == "token":
            self.org = user.lstrip("@") or "System"
            self.provider = self.org.lower() == "system"
            path = "/oauth/provider/token" if self.provider else f"/oauth/tenant/{self.org}/token"
            r = await self.client.post(path, data={"grant_type": "refresh_token",
                                                   "refresh_token": self.integ.secret or ""},
                                       headers={"Accept": "application/json"})
            if r.status_code in (400, 401, 403):
                raise CollectorError("API token recusado pelo vCloud Director (gere outro em Preferências do "
                                     "usuário > Tokens de acesso à API e confira a organização)")
            await self._check(r)
            self.token = (r.json() or {}).get("access_token")
        else:
            if "@" not in user:
                user += "@System"
            self.org = _org_of(user)
            self.provider = self.org.lower() == "system"
            path = "/cloudapi/1.0.0/sessions/provider" if self.provider else "/cloudapi/1.0.0/sessions"
            r = await self.client.post(path, auth=(user, self.integ.secret or ""),
                                       headers={"Accept": f"application/json;version={self.version}"})
            if r.status_code == 401:
                raise CollectorError(f"usuário ou senha recusados pelo vCloud Director ({user}). Use "
                                     "usuario@System para a conta do provedor ou usuario@Org para uma organização")
            await self._check(r)
            self.token = r.headers.get("x-vmware-vcloud-access-token")
        if not self.token:
            raise CollectorError("o vCloud Director não devolveu o token de acesso (versão da API muito antiga?)")

    async def __aexit__(self, *exc: Any) -> None:
        try:
            if self.token and (self.integ.options or {}).get("auth") != "token":
                await self.client.delete("/cloudapi/1.0.0/sessions/current",
                                         headers={"Accept": f"application/json;version={self.version}"})
        except httpx.HTTPError:
            pass
        await self.client.aclose()

    async def _check(self, r: httpx.Response) -> None:
        if r.status_code < 400:
            return
        try:
            body = r.json()
            msg = body.get("message") or body.get("minorErrorCode") or ""
        except ValueError:
            msg = r.text[:200]
        if r.status_code == 406 or "version" in str(msg).lower() and r.status_code == 400:
            raise CollectorError(f"versão da API {self.version} não aceita por este vCloud Director: {msg}. "
                                 "Ajuste em Avançado (10.4 = 37.x, 10.5 = 38.x, 10.6 = 39.x)")
        if r.status_code == 403:
            raise CollectorError("a conta não tem permissão para ler este dado no vCloud Director")
        raise CollectorError(f"vCloud Director respondeu HTTP {r.status_code} em {r.request.url.path}: {msg}"[:400])

    async def query(self, qtype: str, filter_: str | None = None, limit: int | None = None) -> list[dict[str, Any]]:
        """Query Service em formato records, todas as páginas."""
        out: list[dict[str, Any]] = []
        page = 1
        while True:
            params: dict[str, Any] = {"type": qtype, "format": "records", "page": page,
                                      "pageSize": min(PAGE, limit or PAGE)}
            if filter_:
                params["filter"] = filter_
            r = await self.client.get("/api/query", params=params, headers={"Accept": self.accept})
            if r.status_code == 400 and page > 1 and "page" in r.text.lower():
                return out  # passou da última página
            await self._check(r)
            body = r.json() or {}
            recs = body.get("record") or []
            out.extend(recs)
            total = body.get("total")
            if limit is not None and len(out) >= limit:
                return out[:limit]
            if not recs or len(recs) < params["pageSize"] or (total is not None and len(out) >= int(total)) \
                    or page >= 2000:
                return out
            page += 1

    async def vm_metrics(self, vm_id: str) -> dict[str, float]:
        """Leitura atual de uma VM (``vm-<uuid>``). {} quando não há dado (recém-ligada, sem VMware Tools...)."""
        vm_id = vm_id if vm_id.startswith("vm-") else f"vm-{vm_id}"
        r = await self.client.get(f"/api/vApp/{vm_id}/metrics/current", headers={"Accept": self.accept})
        if r.status_code in (400, 404, 500, 503):
            return {}
        await self._check(r)
        out: dict[str, float] = {}
        for m in (r.json() or {}).get("metric") or []:
            try:
                name, value = str(m.get("name")), float(m.get("value"))
            except (TypeError, ValueError):
                continue
            if value < 0:  # -1 = sem dado neste contador
                continue
            # Um registro por disco em algumas versões: soma espaço e throughput, o resto fica com o último
            out[name] = out.get(name, 0.0) + value if name.startswith("disk.") else value
        return out

    async def vm_disks_bytes(self, vm_id: str) -> int | None:
        """Tamanho provisionado dos discos da VM (soma), pelo hardware virtual. None se não der para ler."""
        vm_id = vm_id if vm_id.startswith("vm-") else f"vm-{vm_id}"
        r = await self.client.get(f"/api/vApp/{vm_id}/virtualHardwareSection/disks",
                                  headers={"Accept": f"application/*+xml;version={self.version}"})
        if r.status_code >= 400:
            return None
        return disks_bytes_from_xml(r.text)

    async def total(self, qtype: str, filter_: str | None = None) -> int:
        params: dict[str, Any] = {"type": qtype, "format": "records", "page": 1, "pageSize": 1}
        if filter_:
            params["filter"] = filter_
        r = await self.client.get("/api/query", params=params, headers={"Accept": self.accept})
        await self._check(r)
        return int((r.json() or {}).get("total") or 0)


def _describe(exc: BaseException, integ: Integration) -> str:
    if isinstance(exc, httpx.ConnectError):
        text = str(exc)
        if "CERTIFICATE_VERIFY_FAILED" in text:
            return ("certificado do vCloud Director não confiável. Cole a CA em Avançado ou desmarque a validação "
                    "do certificado")
        if "refused" in text.lower():
            return f"{integ.endpoint}:{integ.port} recusou a conexão"
        return f"não foi possível conectar em {integ.endpoint}:{integ.port}: {text[:200]}"
    if isinstance(exc, httpx.TimeoutException):
        return f"sem resposta de {integ.endpoint}:{integ.port} (timeout)"
    return f"{type(exc).__name__}: {str(exc)[:200]}"


async def _all_vm_metrics(api: Api, integ: Integration, uuids: list[str]) -> tuple[dict[str, dict[str, float]], str]:
    """Métricas atuais de muitas VMs em paralelo. Devolve ({uuid: {contador: valor}}, aviso)."""
    if not uuids or (integ.options or {}).get("vm_metrics") is False:
        return {}, ""
    sem = asyncio.Semaphore(max(1, min(64, int((integ.options or {}).get("metrics_concurrency")
                                                or METRICS_CONCURRENCY))))
    out: dict[str, dict[str, float]] = {}
    denied: list[str] = []
    failed = 0

    async def one(uid: str) -> None:
        nonlocal failed
        if denied:
            return
        async with sem:
            if denied:
                return
            try:
                vals = await api.vm_metrics(uid)
            except CollectorError as exc:
                if "permissão" in str(exc):
                    denied.append(str(exc))
                failed += 1
                return
            except httpx.HTTPError:
                failed += 1
                return
            if vals:
                out[uid] = vals

    await asyncio.gather(*(one(u) for u in uuids))
    if denied:
        return out, "sem permissão para ler as métricas das VMs (direito \"View VM metrics\"); só o inventário"
    if failed and not out:
        return out, f"não foi possível ler as métricas das VMs ({failed} falha(s))"
    return out, ""


def disks_bytes_from_xml(text: str) -> int | None:
    """RasdItemsList: soma dos itens ResourceType 17 (disco). Capacidade em MB no atributo ``capacity`` do
    HostResource ou, na falta dele, VirtualQuantity em bytes."""
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    total, found = 0, False
    for item in root.iter():
        if not item.tag.endswith("}Item") and item.tag != "Item":
            continue
        kids = {c.tag.rsplit("}", 1)[-1]: c for c in item}
        if (kids.get("ResourceType") is None or (kids["ResourceType"].text or "").strip() != "17"):
            continue
        size = None
        host = kids.get("HostResource")
        if host is not None:
            for k, v in host.attrib.items():
                if k.rsplit("}", 1)[-1] == "capacity":
                    try:
                        size = int(float(v)) * MB
                    except ValueError:
                        pass
        if size is None and kids.get("VirtualQuantity") is not None:
            try:
                size = int(float(kids["VirtualQuantity"].text or ""))
            except ValueError:
                pass
        if size:
            total += size
            found = True
    return total if found else None


# (integração, vm) -> (monotonic, bytes): o hardware muda pouco; relê a cada 6 h
_disk_cache: dict[tuple[int, str], tuple[float, int]] = {}
DISK_CACHE_SECONDS = 6 * 3600


async def _all_vm_disks(api: Api, integ: Integration, uuids: list[str]) -> dict[str, int]:
    """Disco provisionado das VMs sem esse dado no Query Service nem nas métricas (cache de 6 h)."""
    import time
    now = time.monotonic()
    out: dict[str, int] = {}
    todo = []
    for u in uuids:
        hit = _disk_cache.get((integ.id, u))
        if hit and now - hit[0] < DISK_CACHE_SECONDS:
            out[u] = hit[1]
        else:
            todo.append(u)
    sem = asyncio.Semaphore(max(1, min(64, int((integ.options or {}).get("metrics_concurrency")
                                                or METRICS_CONCURRENCY))))

    async def one(uid: str) -> None:
        async with sem:
            try:
                size = await api.vm_disks_bytes(uid)
            except httpx.HTTPError:
                return
        if size:
            _disk_cache[(integ.id, uid)] = (now, size)
            out[uid] = size

    await asyncio.gather(*(one(u) for u in todo))
    return out


def _write_vm_metrics(w: Writer, aid: int, tid: int, vals: dict[str, float], memory_mb: Any) -> None:
    for counter, (key, factor) in VM_METRICS.items():
        v = vals.get(counter)
        if v is None or v < 0:
            continue
        w.metric(aid, tid, key, round(v * factor, 2) if factor == 1 else v * factor)
    pct = vals.get("mem.usage.average")
    if pct is not None and memory_mb:
        w.metric(aid, tid, "mem.used.bytes", pct / 100 * float(memory_mb) * MB)


def _types(api: Api) -> tuple[str, str, str]:
    """Tipos do Query Service: os "admin" só existem para a conta do provedor."""
    if api.provider:
        return "adminOrgVdc", "adminOrgVdcStorageProfile", "adminVM"
    return "orgVdc", "orgVdcStorageProfile", "vm"


async def _vapp_dates(api: Api, vms: list[dict[str, Any]]) -> dict[str, str]:
    """Data de criação das vApps (o registro da VM nem sempre traz a sua): base do relatório de crescimento.

    Só quando alguma VM vem sem ``dateCreated``; falha de permissão aqui não derruba a coleta.
    """
    if all(m.get("dateCreated") or m.get("creationDate") for m in vms):
        return {}
    try:
        vapps = await api.query("adminVApp" if api.provider else "vApp")
    except CollectorError:
        return {}
    return {_uuid(v.get("href")): v["creationDate"] for v in vapps if v.get("creationDate")}


def _org_filter(integ: Integration) -> list[str]:
    return [str(p).strip().lower() for p in (integ.options.get("orgs") or []) if str(p).strip()]


def _wanted(org: str, patterns: list[str]) -> bool:
    return not patterns or any(fnmatch.fnmatchcase(org.lower(), p) for p in patterns)


async def test(integ: Integration) -> dict[str, Any]:
    try:
        async with Api(integ) as api:
            t_vdc, _, t_vm = _types(api)
            vdcs = await api.query(t_vdc)
            nvm = await api.total(t_vm, "isVAppTemplate==false")
            # Diagnóstico: o que este vCD devolve de uma VM ligada (campos de disco e nomes das métricas)
            sample = await api.query(t_vm, "isVAppTemplate==false;status==POWERED_ON", limit=1)
            probe: dict[str, Any] = {}
            if sample:
                vid = _uuid(sample[0].get("href"))
                probe["vm_exemplo"] = sample[0].get("name")
                probe["campos_disco"] = {k: v for k, v in sample[0].items()
                                         if "storage" in k.lower() or "disk" in k.lower()} or "nenhum"
                try:
                    probe["metricas"] = sorted(await api.vm_metrics(vid)) or "nenhuma"
                except CollectorError as exc:
                    probe["metricas"] = str(exc)
                probe["disco_pelo_hardware"] = await api.vm_disks_bytes(vid)
    except CollectorError:
        raise
    except httpx.HTTPError as exc:
        raise CollectorError(_describe(exc, integ)) from exc
    orgs = sorted({v.get("orgName") or api.org for v in vdcs})
    patterns = _org_filter(integ)
    chosen = [o for o in orgs if _wanted(o, patterns)]
    who = "provedor" if api.provider else f"organização {api.org}"
    summary = f"vCloud Director (API {api.version}, {who}) · {len(orgs)} organização(ões) · {len(vdcs)} VDC(s) · " \
              f"{nvm} VM(s)"
    if patterns:
        summary += f" · filtro casa {len(chosen)} organização(ões)"
    return {"ok": True, "summary": summary,
            "details": {"api_version": api.version, "provider": "sim" if api.provider else "não", "orgs": len(orgs),
                        "vdcs": len(vdcs), "vms": nvm, "orgs_matched": chosen[:50] if patterns else None,
                        **probe}}


async def poll(integ: Integration, w: Writer) -> str:
    try:
        async with Api(integ) as api:
            t_vdc, t_sp, t_vm = _types(api)
            vdcs = await api.query(t_vdc)
            sps = await api.query(t_sp)
            vms = await api.query(t_vm, "isVAppTemplate==false")
            patterns = _org_filter(integ)
            wanted_vdcs = {_uuid(v.get("href")) for v in vdcs if _wanted(v.get("orgName") or api.org, patterns)}
            perf, perf_warning = await _all_vm_metrics(api, integ, [
                _uuid(m.get("href")) for m in vms if str(m.get("status") or "").upper() == "POWERED_ON"
                and _uuid(m.get("vdc")) in wanted_vdcs and not m.get("isVAppTemplate")])
            vapp_created = await _vapp_dates(api, vms)
            # Plano B do disco provisionado: VMs sem totalStorageAllocatedMb e sem disk.provisioned nas métricas
            disks = await _all_vm_disks(api, integ, [
                _uuid(m.get("href")) for m in vms if _uuid(m.get("vdc")) in wanted_vdcs
                and not m.get("isVAppTemplate") and not m.get("totalStorageAllocatedMb")
                and "disk.provisioned.latest" not in perf.get(_uuid(m.get("href")), {})])
    except CollectorError:
        raise
    except httpx.HTTPError as exc:
        raise CollectorError(_describe(exc, integ)) from exc

    root = (await w.assets_bulk([{"external_id": "vcd", "asset_type": "vcenter", "name": integ.name,
                                  "vendor": "VMware", "model": "Cloud Director", "hostname": integ.endpoint,
                                  "attributes": {"api_version": api.version, "product": "vCloud Director"}}]))["vcd"]
    w.metric(root[0], root[1], "availability.up", 1)

    # VDCs: tenant pelas regras (Org e Org/VDC no campo "pasta")
    vdc_info: dict[str, dict[str, Any]] = {}
    items = []
    for v in vdcs:
        org = v.get("orgName") or api.org
        if not _wanted(org, patterns):
            continue
        vid = _uuid(v.get("href"))
        name = v.get("name") or vid
        facts = {"name": name, "folder": [org, f"{org}/{name}"], "resource_pool": [name]}
        tid = await w.tenant_for(facts)
        vdc_info[vid] = {"org": org, "name": name, "tenant_id": tid}
        enabled = v.get("isEnabled", True) is not False
        items.append({"external_id": f"vdc:{vid}", "asset_type": "datacenter", "name": f"{org} / {name}",
                      "tenant_id": tid, "parent_id": root[0], "status": "up" if enabled else "maintenance",
                      "vendor": "VMware", "model": "Org VDC",
                      "attributes": {"org": org, "vdc": name, "folder": f"{org}/{name}",
                                     "allocation_model": v.get("allocationModel"),
                                     "provider_vdc": v.get("providerVdcName"),
                                     "cpu_allocation_mhz": v.get("cpuAllocationMhz"),
                                     "memory_allocation_mb": v.get("memoryAllocationMB"),
                                     "storage_limit_mb": v.get("storageLimitMB"),
                                     "vms": v.get("numberOfVMs"), "running_vms": v.get("numberOfRunningVMs"),
                                     "hypervisor": "vcloud"}})
    vdc_ids = await w.assets_bulk(items)
    for v in vdcs:
        vid = _uuid(v.get("href"))
        if f"vdc:{vid}" not in vdc_ids:
            continue
        aid, tid = vdc_ids[f"vdc:{vid}"]
        w.metric(aid, tid, "availability.up", 1)
        cpu_used, cpu_alloc = v.get("cpuUsedMhz"), v.get("cpuAllocationMhz") or v.get("cpuLimitMhz")
        mem_used, mem_alloc = v.get("memoryUsedMB"), v.get("memoryAllocationMB") or v.get("memoryLimitMB")
        w.metric(aid, tid, "cpu.usage.mhz", cpu_used)
        if cpu_used is not None and cpu_alloc and cpu_alloc > 0:
            w.metric(aid, tid, "cpu.usage.pct", round(cpu_used / cpu_alloc * 100, 2))
        if mem_used is not None:
            w.metric(aid, tid, "mem.used.bytes", mem_used * MB)
        if mem_alloc and mem_alloc > 0:
            w.metric(aid, tid, "mem.allocated.bytes", mem_alloc * MB)
            if mem_used is not None:
                w.metric(aid, tid, "mem.usage.pct", round(mem_used / mem_alloc * 100, 2))

    # Perfis de armazenamento e VMs ficam com o tenant EFETIVO do VDC: quando o administrador fixa o VDC
    # num cliente, tudo o que está dentro dele vai junto (cada item ainda pode ser fixado à parte).
    for vid, info in vdc_info.items():
        if f"vdc:{vid}" in vdc_ids:
            info["tenant_id"] = vdc_ids[f"vdc:{vid}"][1]

    # Perfis de armazenamento por VDC (limite 0 = ilimitado: só o uso)
    items = []
    for s in sps:
        vid = _uuid(s.get("vdc"))
        info = vdc_info.get(vid)
        if info is None:
            continue
        sid = _uuid(s.get("href"))
        items.append({"external_id": f"sp:{sid}", "asset_type": "datastore",
                      "name": f"{info['org']} / {info['name']} / {s.get('name') or sid}",
                      "tenant_id": info["tenant_id"], "parent_id": vdc_ids[f"vdc:{vid}"][0],
                      "status": "up" if s.get("isEnabled", True) is not False else "maintenance",
                      "model": "Storage policy",
                      "attributes": {"org": info["org"], "vdc": info["name"], "storage_profile": s.get("name"),
                                     "limit_mb": s.get("storageLimitMB"), "used_mb": s.get("storageUsedMB"),
                                     "default": s.get("isDefaultStorageProfile")}})
    sp_ids = await w.assets_bulk(items)
    for s in sps:
        key = f"sp:{_uuid(s.get('href'))}"
        if key not in sp_ids:
            continue
        aid, tid = sp_ids[key]
        limit, used = s.get("storageLimitMB") or 0, s.get("storageUsedMB")
        w.metric(aid, tid, "availability.up", 1)
        if used is not None:
            w.metric(aid, tid, "storage.used.bytes", used * MB)
        if limit > 0:
            w.metric(aid, tid, "storage.capacity.bytes", limit * MB)
            if used is not None:
                w.metric(aid, tid, "storage.free.bytes", max(0, limit - used) * MB)

    # VMs
    items = []
    for m in vms:
        info = vdc_info.get(_uuid(m.get("vdc")))
        if info is None or m.get("isVAppTemplate") or m.get("isDeleted"):
            continue
        mid = _uuid(m.get("href"))
        name = m.get("name") or mid
        created = m.get("dateCreated") or m.get("creationDate") or vapp_created.get(_uuid(m.get("container")))
        items.append({"external_id": f"vm:{mid}", "asset_type": "vm", "name": name, "tenant_id": info["tenant_id"],
                      "parent_id": vdc_ids[f"vdc:{_uuid(m.get('vdc'))}"][0],
                      "status": STATUS_VM.get(str(m.get("status") or "").upper(), "unknown"),
                      "ip": m.get("ipAddress"), "vendor": "VMware",
                      "os_name": m.get("guestOs"),
                      "attributes": {"vcpu": m.get("numberOfCpus"), "memory_bytes": (m.get("memoryMB") or 0) * MB,
                                     "guest_os": m.get("guestOs"), "power_state": m.get("status"),
                                     "org": info["org"], "vdc": info["name"], "vapp": m.get("containerName"),
                                     "folder": f"{info['org']}/{info['name']}", "moref": m.get("moref"),
                                     "storage_profile": m.get("storageProfileName"), "hypervisor": "vcloud",
                                     # hostName do Query Service é o host ESXi, não o nome da VM (só o admin vê)
                                     "esx_host": m.get("hostName") or None, "vc_name": m.get("vcName"),
                                     "disk_bytes": (float(m["totalStorageAllocatedMb"]) * MB if m.get("totalStorageAllocatedMb")
                                                    else disks.get(mid)),
                                     **({"created_at": str(created)} if created else {})}})
    vm_ids = await w.assets_bulk(items)
    # Versões antigas gravavam o host ESXi como hostname da VM
    await w.conn.execute("UPDATE assets SET hostname = NULL WHERE integration_id = $1 AND asset_type = 'vm' "
                         "AND hostname IS NOT NULL", integ.id)
    on = with_disk = 0
    for m in vms:
        key = f"vm:{_uuid(m.get('href'))}"
        if key not in vm_ids:
            continue
        aid, tid = vm_ids[key]
        powered = str(m.get("status") or "").upper() == "POWERED_ON"
        on += powered
        w.metric(aid, tid, "availability.up", 1 if powered else 0)
        w.metric(aid, tid, "cpu.allocated.vcpu", m.get("numberOfCpus"))
        if m.get("memoryMB"):
            w.metric(aid, tid, "mem.allocated.bytes", m["memoryMB"] * MB)
        vals = perf.get(_uuid(m.get("href"))) if powered else None
        if not (vals and "disk.provisioned.latest" in vals):
            if m.get("totalStorageAllocatedMb"):
                w.metric(aid, tid, "disk.capacity.bytes", float(m["totalStorageAllocatedMb"]) * MB)
            elif disks.get(_uuid(m.get("href"))):
                w.metric(aid, tid, "disk.capacity.bytes", disks[_uuid(m.get("href"))])
        if vals and "disk.used.latest" in vals:
            with_disk += 1
        if vals:
            _write_vm_metrics(w, aid, tid, vals, m.get("memoryMB"))

    removed = await w.retire_missing(("vcenter", "datacenter", "datastore", "vm"))
    orgs = {i["org"] for i in vdc_info.values()}
    msg = (f"{len(orgs)} organização(ões), {len(vdc_ids)} VDC(s), {len(vm_ids)} VM(s) ({on} ligada(s), "
           f"{len(perf)} com métricas, {with_disk} com disco usado), {len(sp_ids)} perfil(is) de armazenamento"
           + (f", {removed} removido(s) do inventário" if removed else ""))
    return f"warning: {msg}; {perf_warning}" if perf_warning else msg
