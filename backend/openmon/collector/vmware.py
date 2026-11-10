"""Coletor VMware vCenter (pyvmomi), em lote para 5.000+ VMs.

Inventário e estatísticas rápidas saem de um único PropertyCollector
(``RetrievePropertiesEx`` sobre um ContainerView, paginado de 1.000 em 1.000):
nada de navegar objeto por objeto. Tráfego de rede, CPU ready e IOPS vêm do
PerfManager em tempo real (amostras de 20 s), com várias VMs por chamada.

O pyvmomi é síncrono: a coleta roda numa thread (``asyncio.to_thread``) e a
gravação no banco volta para o loop. A sessão do vCenter é reaproveitada entre
coletas (login a cada minuto enche o vCenter de sessões) e refeita se cair.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import ssl
import threading
from typing import Any

from openmon.collector import vcd
from openmon.collector.common import CollectorError, Integration, Writer

log = logging.getLogger("openmon.collector.vmware")

PAGE = 1000
PERF_BATCH = 250
VM_PROPS = ["name", "config.instanceUuid", "config.template", "config.guestFullName", "guest.guestFullName",
            "guest.ipAddress", "guest.hostName", "runtime.powerState", "runtime.host", "runtime.connectionState",
            "summary.config.numCpu", "summary.config.memorySizeMB", "summary.quickStats.overallCpuUsage",
            "summary.quickStats.guestMemoryUsage", "summary.quickStats.uptimeSeconds",
            "summary.quickStats.swappedMemory", "summary.quickStats.balloonedMemory", "summary.runtime.maxCpuUsage",
            "summary.storage.committed", "summary.storage.uncommitted", "parent", "resourcePool",
            "summary.overallStatus"]
HOST_PROPS = ["name", "parent", "runtime.connectionState", "runtime.powerState", "runtime.inMaintenanceMode",
              "summary.hardware.vendor", "summary.hardware.model", "summary.hardware.cpuMhz",
              "summary.hardware.numCpuCores", "summary.hardware.memorySize", "summary.quickStats.overallCpuUsage",
              "summary.quickStats.overallMemoryUsage", "summary.quickStats.uptime", "config.product.fullName",
              "summary.overallStatus"]
CLUSTER_PROPS = ["name", "parent"]
DS_PROPS = ["name", "parent", "summary.capacity", "summary.freeSpace", "summary.accessible", "summary.type"]
FOLDER_PROPS = ["name", "parent"]
POOL_PROPS = ["name", "parent"]
DC_PROPS = ["name", "parent"]
# contador do PerfManager -> (métrica OpenMon, fator)
PERF = {"net.received.average": ("net.rx.bps", 8000), "net.transmitted.average": ("net.tx.bps", 8000),
        "cpu.ready.summation": ("cpu.ready.pct", None),
        "disk.numberReadAveraged.average": ("disk.read.iops", 1),
        "disk.numberWriteAveraged.average": ("disk.write.iops", 1),
        "disk.read.average": ("disk.read.bps", 8000), "disk.write.average": ("disk.write.bps", 8000)}
STATUS_VM = {"poweredOn": "up", "poweredOff": "powered_off", "suspended": "suspended"}

_sessions: dict[int, tuple[str, Any]] = {}
_lock = threading.Lock()


def _ssl_context(integ: Integration) -> ssl.SSLContext:
    if not integ.verify_tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    ctx = ssl.create_default_context()
    if integ.ca_cert_pem:
        ctx.load_verify_locations(cadata=integ.ca_cert_pem)
    return ctx


def _describe(exc: BaseException, integ: Integration) -> str:
    from pyVmomi import vim
    name = type(exc).__name__
    if isinstance(exc, vim.fault.InvalidLogin):
        return "usuário ou senha do vCenter recusados"
    if isinstance(exc, vim.fault.NoPermission):
        return "a conta não tem permissão de leitura no vCenter (dê o papel Read-only na raiz, propagando)"
    if isinstance(exc, ssl.SSLCertVerificationError):
        return (f"certificado do vCenter não confiável ({exc.verify_message}). Cole a CA em Avançado ou, só em "
                "laboratório, desmarque a validação")
    if isinstance(exc, (ConnectionRefusedError,)):
        return f"{integ.endpoint}:{integ.port} recusou a conexão"
    if isinstance(exc, (TimeoutError, OSError)) and "timed out" in str(exc):
        return f"sem resposta de {integ.endpoint}:{integ.port} (timeout)"
    if isinstance(exc, OSError):
        return f"não foi possível conectar em {integ.endpoint}:{integ.port}: {exc.strerror or exc}"
    msg = getattr(exc, "msg", "") or str(exc)
    return f"{name}: {msg[:200]}"


def _fingerprint(integ: Integration) -> str:
    raw = "|".join(str(x) for x in (integ.endpoint, integ.port, integ.username, integ.secret, integ.verify_tls,
                                    integ.ca_cert_pem))
    return hashlib.sha256(raw.encode()).hexdigest()


def _connect(integ: Integration) -> Any:
    from pyVim.connect import SmartConnect
    try:
        return SmartConnect(host=integ.endpoint, port=integ.port or 443, user=integ.username or "",
                            pwd=integ.secret or "", sslContext=_ssl_context(integ), httpConnectionTimeout=30,
                            connectionPoolTimeout=-1)
    except Exception as exc:  # noqa: BLE001 - vira mensagem para a tela
        raise CollectorError(_describe(exc, integ)) from exc


def _session(integ: Integration) -> Any:
    """Sessão reaproveitada; testa com currentSession e refaz se expirou."""
    fp = _fingerprint(integ)
    with _lock:
        cached = _sessions.get(integ.id)
    if cached and cached[0] == fp:
        try:
            if cached[1].content.sessionManager.currentSession is not None:
                return cached[1]
        except Exception:  # noqa: BLE001 - sessão caiu: faz login de novo
            pass
    si = _connect(integ)
    with _lock:
        old = _sessions.pop(integ.id, None)
        _sessions[integ.id] = (fp, si)
    if old:
        _logout(old[1])
    return si


def _logout(si: Any) -> None:
    from pyVim.connect import Disconnect
    try:
        Disconnect(si)
    except Exception:  # noqa: BLE001
        pass


def _moid(obj: Any) -> str | None:
    return obj._moId if obj is not None and hasattr(obj, "_moId") else None


def _retrieve(content: Any, vimtype: Any, props: list[str]) -> dict[str, dict[str, Any]]:
    """{moid: {prop: valor}} de todos os objetos do tipo, via ContainerView + RetrievePropertiesEx paginado."""
    from pyVmomi import vmodl
    view = content.viewManager.CreateContainerView(content.rootFolder, [vimtype], True)
    try:
        pc = content.propertyCollector
        spec = vmodl.query.PropertyCollector.FilterSpec(
            objectSet=[vmodl.query.PropertyCollector.ObjectSpec(
                obj=view, skip=True, selectSet=[vmodl.query.PropertyCollector.TraversalSpec(
                    name="traverseView", path="view", skip=False, type=type(view))])],
            propSet=[vmodl.query.PropertyCollector.PropertySpec(type=vimtype, pathSet=props, all=False)])
        out: dict[str, dict[str, Any]] = {}
        res = pc.RetrievePropertiesEx([spec], vmodl.query.PropertyCollector.RetrieveOptions(maxObjects=PAGE))
        while res:
            for oc in res.objects:
                d = {p.name: p.val for p in (oc.propSet or [])}
                d["_obj"] = oc.obj
                out[oc.obj._moId] = d
            if not res.token:
                break
            res = pc.ContinueRetrievePropertiesEx(res.token)
        return out
    finally:
        try:
            view.Destroy()
        except Exception:  # noqa: BLE001
            pass


def _perf(content: Any, entities: list[Any]) -> dict[str, dict[str, float]]:
    """Última amostra de tempo real (20 s) dos contadores de PERF, várias entidades por chamada."""
    from pyVmomi import vim
    if not entities:
        return {}
    pm = content.perfManager
    by_name = {f"{c.groupInfo.key}.{c.nameInfo.key}.{c.rollupType}": c.key for c in pm.perfCounter}
    ids = {by_name[n]: n for n in PERF if n in by_name}
    if not ids:
        return {}
    metric_ids = [vim.PerformanceManager.MetricId(counterId=cid, instance="") for cid in ids]
    out: dict[str, dict[str, float]] = {}
    for i in range(0, len(entities), PERF_BATCH):
        specs = [vim.PerformanceManager.QuerySpec(entity=e, metricId=metric_ids, intervalId=20, maxSample=1)
                 for e in entities[i:i + PERF_BATCH]]
        try:
            result = pm.QueryPerf(specs) or []
        except Exception as exc:  # noqa: BLE001 - sem perf, segue com as quickStats
            log.warning("QueryPerf falhou: %s", exc)
            continue
        for em in result:
            vals = out.setdefault(em.entity._moId, {})
            for series in em.value or []:
                if series.value:
                    vals[ids[series.id.counterId]] = float(series.value[-1])
    return out


def _path(moid: str | None, folders: dict[str, dict[str, Any]], stop: set[str]) -> list[str]:
    """Nomes das pastas do objeto até o datacenter (de cima para baixo)."""
    names: list[str] = []
    seen = 0
    while moid and moid in folders and moid not in stop and seen < 64:
        f = folders[moid]
        names.append(f.get("name") or "")
        moid = _moid(f.get("parent"))
        seen += 1
    names = [n for n in reversed(names) if n not in ("vm", "host", "datastore", "network")]
    return names


def collect(integ: Integration) -> dict[str, Any]:
    """Roda na thread: lê tudo do vCenter e devolve dados simples (sem objetos pyvmomi)."""
    from pyVmomi import vim
    si = _session(integ)
    try:
        content = si.RetrieveContent()
        about = content.about
        dcs = _retrieve(content, vim.Datacenter, DC_PROPS)
        folders = _retrieve(content, vim.Folder, FOLDER_PROPS)
        clusters = _retrieve(content, vim.ComputeResource, CLUSTER_PROPS)
        hosts = _retrieve(content, vim.HostSystem, HOST_PROPS)
        dss = _retrieve(content, vim.Datastore, DS_PROPS)
        pools = _retrieve(content, vim.ResourcePool, POOL_PROPS)
        vms = _retrieve(content, vim.VirtualMachine, VM_PROPS)
        live = [v["_obj"] for v in vms.values()
                if str(v.get("runtime.powerState")) == "poweredOn" and not v.get("config.template")]
        live += [h["_obj"] for h in hosts.values() if str(h.get("runtime.connectionState")) == "connected"]
        perf = _perf(content, live)
    except CollectorError:
        raise
    except Exception as exc:  # noqa: BLE001
        with _lock:
            _sessions.pop(integ.id, None)
        raise CollectorError(_describe(exc, integ)) from exc

    def dc_of(moid: str | None, table: dict[str, dict[str, Any]]) -> str | None:
        seen = 0
        while moid and seen < 64:
            if moid in dcs:
                return moid
            obj = table.get(moid) or folders.get(moid) or clusters.get(moid) or {}
            moid = _moid(obj.get("parent"))
            seen += 1
        return None

    def clean(d: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in d.items() if k != "_obj"}

    out_clusters = {}
    for m, c in clusters.items():
        is_cluster = isinstance(c["_obj"], vim.ClusterComputeResource)
        out_clusters[m] = {"name": c.get("name"), "is_cluster": is_cluster, "dc": dc_of(_moid(c.get("parent")), {})}
    out_pools = {m: {"name": p.get("name"), "parent": _moid(p.get("parent"))} for m, p in pools.items()}
    out_hosts = {}
    for m, h in hosts.items():
        d = clean(h)
        d["parent"] = _moid(h.get("parent"))
        d["runtime.connectionState"] = str(h.get("runtime.connectionState") or "")
        d["runtime.powerState"] = str(h.get("runtime.powerState") or "")
        d["summary.overallStatus"] = str(h.get("summary.overallStatus") or "")
        d["perf"] = perf.get(m, {})
        out_hosts[m] = d
    out_vms = {}
    for m, v in vms.items():
        if v.get("config.template"):
            continue
        d = clean(v)
        d["parent"] = _moid(v.get("parent"))
        d["runtime.host"] = _moid(v.get("runtime.host"))
        d["resourcePool"] = _moid(v.get("resourcePool"))
        d["runtime.powerState"] = str(v.get("runtime.powerState") or "")
        d["runtime.connectionState"] = str(v.get("runtime.connectionState") or "")
        d["summary.overallStatus"] = str(v.get("summary.overallStatus") or "")
        d["folder"] = _path(d["parent"], folders, set(dcs))
        d["perf"] = perf.get(m, {})
        out_vms[m] = d
    out_ds = {}
    for m, ds in dss.items():
        d = clean(ds)
        d["dc"] = dc_of(_moid(ds.get("parent")), {})
        out_ds[m] = d
    return {"about": {"name": about.fullName, "version": about.version, "build": about.build,
                      "uuid": about.instanceUuid, "api": about.apiVersion},
            "datacenters": {m: {"name": d.get("name")} for m, d in dcs.items()},
            "clusters": out_clusters, "pools": out_pools, "hosts": out_hosts, "vms": out_vms, "datastores": out_ds}


def _pool_chain(moid: str | None, pools: dict[str, dict[str, Any]]) -> list[str]:
    names: list[str] = []
    seen = 0
    while moid and moid in pools and seen < 32:
        names.append(pools[moid]["name"])
        moid = pools[moid]["parent"]
        seen += 1
    # o pool raiz de todo cluster se chama "Resources" e não diz nada
    return [n for n in reversed(names) if n != "Resources"]


def _pct(part: Any, total: Any) -> float | None:
    try:
        p, t = float(part), float(total)
    except (TypeError, ValueError):
        return None
    return round(100.0 * p / t, 2) if t > 0 else None


async def test(integ: Integration) -> dict[str, Any]:
    """"Testar conexão": login, versão e contagem de objetos (sem gravar nada)."""
    if vcd.is_vcd(integ):
        return await vcd.test(integ)
    def run() -> dict[str, Any]:
        from pyVmomi import vim
        si = _connect(integ)
        try:
            content = si.RetrieveContent()
            about = content.about
            counts = {}
            for key, t in (("hosts", vim.HostSystem), ("vms", vim.VirtualMachine), ("datastores", vim.Datastore)):
                view = content.viewManager.CreateContainerView(content.rootFolder, [t], True)
                counts[key] = len(view.view)
                view.Destroy()
            return {"ok": True, "summary": f"{about.fullName} · {counts['hosts']} host(s) · {counts['vms']} VM(s)",
                    "details": {"product": about.fullName, "version": about.version, "build": about.build,
                                **counts}}
        except CollectorError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise CollectorError(_describe(exc, integ)) from exc
        finally:
            _logout(si)
    return await asyncio.to_thread(run)


async def poll(integ: Integration, w: Writer) -> str:
    if vcd.is_vcd(integ):
        return await vcd.poll(integ, w)
    data = await asyncio.to_thread(collect, integ)
    about = data["about"]
    root = (await w.assets_bulk([{"external_id": "vcenter", "asset_type": "vcenter", "name": integ.name,
                                  "hostname": integ.endpoint, "vendor": "VMware", "model": about["name"],
                                  "attributes": {"version": about["version"], "build": about["build"],
                                                 "instance_uuid": about["uuid"]}}]))["vcenter"]
    w.metric(root[0], root[1], "availability.up", 1)

    dc_ids = await w.assets_bulk([{"external_id": m, "asset_type": "datacenter", "name": d["name"],
                                   "parent_id": root[0]} for m, d in data["datacenters"].items()])
    cl_ids = await w.assets_bulk([
        {"external_id": m, "asset_type": "cluster", "name": c["name"],
         "parent_id": dc_ids.get(c["dc"], (None,))[0]}
        for m, c in data["clusters"].items() if c["is_cluster"]])

    host_items = []
    for m, h in data["hosts"].items():
        conn_state = h["runtime.connectionState"]
        status = ("maintenance" if h.get("runtime.inMaintenanceMode") else
                  "up" if conn_state == "connected" and h["runtime.powerState"] == "poweredOn" else "down")
        if status == "up" and h["summary.overallStatus"] == "red":
            status = "warning"
        parent = cl_ids.get(h["parent"], (None,))[0]
        if parent is None:  # host avulso: o "ComputeResource" dele não vira ativo; pendura no datacenter
            dc = data["clusters"].get(h["parent"], {}).get("dc")
            parent = dc_ids.get(dc, (None,))[0]
        host_items.append({"external_id": m, "asset_type": "hypervisor_host", "name": h.get("name") or m,
                           "parent_id": parent, "status": status, "hostname": h.get("name"),
                           "vendor": h.get("summary.hardware.vendor"), "model": h.get("summary.hardware.model"),
                           "os_name": h.get("config.product.fullName"),
                           "attributes": {"cpu_cores": h.get("summary.hardware.numCpuCores"),
                                          "cpu_mhz": h.get("summary.hardware.cpuMhz"),
                                          "memory_bytes": h.get("summary.hardware.memorySize"),
                                          "connection_state": conn_state, "hypervisor": "vmware"}})
    host_ids = await w.assets_bulk(host_items)
    for m, h in data["hosts"].items():
        aid, tid = host_ids[m]
        up = h["runtime.connectionState"] == "connected" and h["runtime.powerState"] == "poweredOn"
        w.metric(aid, tid, "availability.up", 1 if up else 0)
        if not up:
            continue
        total_mhz = (h.get("summary.hardware.cpuMhz") or 0) * (h.get("summary.hardware.numCpuCores") or 0)
        w.metric(aid, tid, "cpu.usage.mhz", h.get("summary.quickStats.overallCpuUsage"))
        w.metric(aid, tid, "cpu.usage.pct", _pct(h.get("summary.quickStats.overallCpuUsage"), total_mhz))
        mem_used = (h.get("summary.quickStats.overallMemoryUsage") or 0) * 1024 * 1024
        w.metric(aid, tid, "mem.used.bytes", mem_used)
        w.metric(aid, tid, "mem.usage.pct", _pct(mem_used, h.get("summary.hardware.memorySize")))
        w.metric(aid, tid, "host.uptime.seconds", h.get("summary.quickStats.uptime"))
        _perf_metrics(w, aid, tid, h["perf"], h.get("summary.hardware.numCpuCores") or 1)

    ds_ids = await w.assets_bulk([
        {"external_id": m, "asset_type": "datastore", "name": d.get("name") or m,
         "parent_id": dc_ids.get(d["dc"], (None,))[0], "status": "up" if d.get("summary.accessible") else "down",
         "model": d.get("summary.type"),
         "attributes": {"capacity_bytes": d.get("summary.capacity"), "free_bytes": d.get("summary.freeSpace"),
                        "fs_type": d.get("summary.type")}}
        for m, d in data["datastores"].items()])
    for m, d in data["datastores"].items():
        aid, tid = ds_ids[m]
        cap, free = d.get("summary.capacity"), d.get("summary.freeSpace")
        w.metric(aid, tid, "availability.up", 1 if d.get("summary.accessible") else 0)
        w.metric(aid, tid, "storage.capacity.bytes", cap)
        w.metric(aid, tid, "storage.free.bytes", free)
        if cap is not None and free is not None:
            w.metric(aid, tid, "storage.used.bytes", cap - free)

    host_cluster = {m: data["clusters"].get(h["parent"], {}).get("name") for m, h in data["hosts"].items()}
    vm_items = []
    for m, v in data["vms"].items():
        cluster = host_cluster.get(v["runtime.host"] or "")
        facts = {"name": v.get("name") or "", "folder": ["/".join(v["folder"])] + v["folder"],
                 "resource_pool": _pool_chain(v["resourcePool"], data["pools"]), "cluster": cluster}
        status = STATUS_VM.get(v["runtime.powerState"], "unknown")
        if v["runtime.connectionState"] not in ("connected", ""):
            status = "unknown"
        elif status == "up" and v["summary.overallStatus"] == "red":
            status = "warning"
        vm_items.append({"external_id": m, "asset_type": "vm", "name": v.get("name") or m,
                         "tenant_id": await w.tenant_for(facts),
                         "parent_id": host_ids.get(v["runtime.host"] or "", (None,))[0], "status": status,
                         "hostname": v.get("guest.hostName"), "ip": v.get("guest.ipAddress"), "vendor": "VMware",
                         "os_name": v.get("guest.guestFullName") or v.get("config.guestFullName"),
                         "attributes": {"vcpu": v.get("summary.config.numCpu"),
                                        "memory_bytes": (v.get("summary.config.memorySizeMB") or 0) * 1024 * 1024,
                                        "guest_os": v.get("guest.guestFullName") or v.get("config.guestFullName"),
                                        "power_state": v["runtime.powerState"],
                                        "instance_uuid": v.get("config.instanceUuid"),
                                        "folder": "/".join(v["folder"]), "cluster": cluster,
                                        "resource_pool": "/".join(facts["resource_pool"]), "hypervisor": "vmware"}})
    vm_ids = await w.assets_bulk(vm_items)
    on = 0
    for m, v in data["vms"].items():
        aid, tid = vm_ids[m]
        vcpu = v.get("summary.config.numCpu") or 0
        mem = (v.get("summary.config.memorySizeMB") or 0) * 1024 * 1024
        w.metric(aid, tid, "cpu.allocated.vcpu", vcpu)
        w.metric(aid, tid, "mem.allocated.bytes", mem)
        committed = v.get("summary.storage.committed")
        w.metric(aid, tid, "disk.used.bytes", committed)
        if committed is not None:
            w.metric(aid, tid, "disk.capacity.bytes", committed + (v.get("summary.storage.uncommitted") or 0))
        powered = v["runtime.powerState"] == "poweredOn"
        w.metric(aid, tid, "availability.up", 1 if powered else 0)
        if not powered:
            continue
        on += 1
        w.metric(aid, tid, "cpu.usage.mhz", v.get("summary.quickStats.overallCpuUsage"))
        # maxCpuUsage = vCPUs x MHz do host; quando o vCenter não preenche, calcula pelo host
        max_mhz = v.get("summary.runtime.maxCpuUsage") or vcpu * (
            data["hosts"].get(v["runtime.host"] or "", {}).get("summary.hardware.cpuMhz") or 0)
        w.metric(aid, tid, "cpu.usage.pct", _pct(v.get("summary.quickStats.overallCpuUsage"), max_mhz))
        guest_mem = (v.get("summary.quickStats.guestMemoryUsage") or 0) * 1024 * 1024
        w.metric(aid, tid, "mem.used.bytes", guest_mem)
        w.metric(aid, tid, "mem.usage.pct", _pct(guest_mem, mem))
        w.metric(aid, tid, "mem.swapped.bytes", (v.get("summary.quickStats.swappedMemory") or 0) * 1024 * 1024)
        w.metric(aid, tid, "mem.ballooned.bytes", (v.get("summary.quickStats.balloonedMemory") or 0) * 1024 * 1024)
        w.metric(aid, tid, "host.uptime.seconds", v.get("summary.quickStats.uptimeSeconds"))
        _perf_metrics(w, aid, tid, v["perf"], vcpu)

    removed = await w.retire_missing(("datacenter", "cluster", "hypervisor_host", "vm", "datastore"))
    msg = (f"{len(data['hosts'])} host(s), {len(vm_ids)} VM(s) ({on} ligada(s)), {len(ds_ids)} datastore(s)"
           + (f", {removed} removido(s) do inventário" if removed else ""))
    return msg


def _perf_metrics(w: Writer, aid: int, tid: int, perf: dict[str, float], vcpu: int) -> None:
    for counter, value in perf.items():
        key, factor = PERF[counter]
        if value < 0:
            continue
        if counter == "cpu.ready.summation":
            # ms de espera em 20 s, somados de todas as vCPUs -> % por vCPU
            w.metric(aid, tid, key, round(value / (20_000 * max(vcpu, 1)) * 100, 2))
        else:
            w.metric(aid, tid, key, value * factor)
