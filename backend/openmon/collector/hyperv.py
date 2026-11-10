"""Coletor Hyper-V por WinRM: uma sessão por host, um script PowerShell que devolve JSON de tudo.

Para cada host da integração (lista em Avançado, ou só o endereço principal) o
coletor abre uma sessão WinRM (HTTPS 5986 por padrão, NTLM) e roda um único
script que traz o host (CPU, memória, uptime, cluster) e todas as VMs dele
(estado, vCPU, memória atribuída/demanda, uptime, IPs, heartbeat) com o tráfego
de rede de cada VM (contadores "Hyper-V Virtual Network Adapter"). Nada de uma
chamada por VM. Os hosts rodam em paralelo (até 8 por integração).

A conta precisa estar no grupo "Hyper-V Administrators" (ou Administrators) do
host e no "Remote Management Users". Num cluster, cada nó devolve as VMs que
estão nele; a VM que migra muda de host no inventário sem perder o histórico.
"""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
from typing import Any

from openmon.collector.common import CollectorError, Integration, Writer

PARALLEL_HOSTS = 8

# Compacto de propósito: o pywinrm manda o script em -EncodedCommand (limite de linha de comando do Windows)
SCRIPT = r"""
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$o=Get-CimInstance Win32_OperatingSystem;$c=Get-CimInstance Win32_ComputerSystem
$cpu=(Get-CimInstance Win32_Processor|Measure-Object LoadPercentage -Average).Average
$cl=$null;try{$cl=(Get-Cluster -ErrorAction Stop).Name}catch{}
$net=@{};try{(Get-Counter '\Hyper-V Virtual Network Adapter(*)\Bytes Received/sec','\Hyper-V Virtual Network Adapter(*)\Bytes Sent/sec' -ErrorAction SilentlyContinue).CounterSamples|%{$net[$_.Path]=$_.CookedValue}}catch{}
$vms=@(Get-VM|%{$v=$_;[pscustomobject]@{id=$v.VMId.Guid;name=$v.Name;state=[string]$v.State;cpu=$v.CPUUsage;vcpu=$v.ProcessorCount;mem=$v.MemoryAssigned;mem_startup=$v.MemoryStartup;mem_demand=$v.MemoryDemand;dyn=$v.DynamicMemoryEnabled;up=[int64]$v.Uptime.TotalSeconds;status=[string]$v.Status;hb=[string]$v.Heartbeat;gen=$v.Generation;ver=[string]$v.Version;clustered=$v.IsClustered;repl=[string]$v.ReplicationState;ips=@($v.NetworkAdapters|%{$_.IPAddresses}|?{$_ -and $_ -notmatch ':'})}})
[pscustomobject]@{host=$c.DNSHostName;domain=$c.Domain;vendor=$c.Manufacturer;model=$c.Model;cores=$c.NumberOfLogicalProcessors;mem=$c.TotalPhysicalMemory;free=[int64]$o.FreePhysicalMemory*1024;os=$o.Caption;boot=$o.LastBootUpTime.ToUniversalTime().ToString('o');cpu=$cpu;cluster=$cl;vms=$vms;net=$net}|ConvertTo-Json -Depth 4 -Compress
"""

STATE = {"Running": "up", "Off": "powered_off", "Saved": "suspended", "Paused": "suspended",
         "Starting": "up", "Stopping": "up", "Saving": "up", "Pausing": "up", "Resuming": "up"}


def hosts_of(integ: Integration) -> list[str]:
    hosts = [h for h in (integ.options.get("hosts") or []) if h]
    return hosts or [integ.endpoint]


def _session(integ: Integration, host: str) -> Any:
    try:
        import winrm
    except ImportError as exc:
        raise CollectorError("biblioteca pywinrm ausente (python3-winrm); rode o instalador de novo") from exc
    https = integ.options.get("https", True) is not False
    port = integ.port or (5986 if https else 5985)
    transport = integ.options.get("transport") or "ntlm"
    kwargs: dict[str, Any] = {"transport": transport, "read_timeout_sec": 70, "operation_timeout_sec": 60}
    if https:
        if not integ.verify_tls:
            kwargs["server_cert_validation"] = "ignore"
        elif integ.ca_cert_pem:
            kwargs["ca_trust_path"] = _ca_file(integ.ca_cert_pem)
    elif transport == "ntlm":
        kwargs["message_encryption"] = "always"  # HTTP 5985 só com o corpo cifrado pelo NTLM
    url = f"{'https' if https else 'http'}://{host}:{port}/wsman"
    return winrm.Session(url, auth=(integ.username or "", integ.secret or ""), **kwargs)


_ca_files: dict[str, str] = {}


def _ca_file(pem: str) -> str:
    """O pywinrm/requests quer a CA num arquivo: grava uma vez por conteúdo (PrivateTmp do serviço)."""
    path = _ca_files.get(pem)
    if path and os.path.exists(path):
        return path
    fd, path = tempfile.mkstemp(prefix="openmon-ca-", suffix=".pem")
    with os.fdopen(fd, "w") as f:
        f.write(pem)
    _ca_files[pem] = path
    return path


def _describe(exc: BaseException, host: str) -> str:
    name = type(exc).__name__
    text = str(exc)
    if name == "InvalidCredentialsError" or "401" in text and "Unauthorized" in text:
        return f"{host}: usuário ou senha recusados pelo WinRM (NTLM)"
    if "CERTIFICATE_VERIFY_FAILED" in text:
        return (f"{host}: certificado WinRM não confiável. Cole a CA em Avançado ou, só em laboratório, desmarque "
                "a validação")
    if "refused" in text.lower() or "Errno 111" in text:
        return f"{host}: recusou a conexão (WinRM HTTPS escuta na 5986; rode 'winrm quickconfig -transport:https')"
    if "timed out" in text.lower() or "Timeout" in name:
        return f"{host}: sem resposta (timeout)"
    if "Name or service not known" in text or "getaddrinfo" in text or "nodename nor servname" in text:
        return f"{host}: nome não resolve no DNS"
    if "is not installed" in text or "requests_kerberos" in text or "requests_credssp" in text:
        return f"{host}: o transporte escolhido precisa de biblioteca que não vem no Debian por padrão; use NTLM"
    return f"{host}: {name}: {text[:200]}"


def _run(integ: Integration, host: str) -> dict[str, Any]:
    """Roda o script num host (na thread) e devolve o JSON."""
    try:
        r = _session(integ, host).run_ps(SCRIPT)
    except CollectorError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise CollectorError(_describe(exc, host)) from exc
    return _parse(r.status_code, r.std_out, r.std_err, host)


def _parse(code: int, out: bytes, err: bytes, host: str) -> dict[str, Any]:
    text = (out or b"").decode("utf-8", "replace").strip()
    if code != 0 or not text:
        msg = _clean_err((err or b"").decode("utf-8", "replace"))
        if "Get-VM" in msg and ("not recognized" in msg or "não é reconhecido" in msg):
            msg = "o módulo Hyper-V do PowerShell não está instalado neste host"
        elif "permission" in msg.lower() or "permiss" in msg.lower() or "authoriz" in msg.lower():
            msg = "a conta não tem permissão no Hyper-V (grupo Hyper-V Administrators)"
        raise CollectorError(f"{host}: {msg or f'PowerShell terminou com código {code}'}")
    try:
        data = json.loads(text.splitlines()[-1])
    except ValueError as exc:
        raise CollectorError(f"{host}: resposta inesperada do PowerShell: {text[:200]}") from exc
    vms = data.get("vms")
    data["vms"] = [] if vms is None else vms if isinstance(vms, list) else [vms]
    return data


def _clean_err(err: str) -> str:
    """O stderr do PowerShell remoto vem em CLIXML; fica só com o texto da mensagem."""
    if "<Objs" in err:
        import re
        parts = re.findall(r'<S S="Error">(.*?)</S>', err, re.S)
        err = "".join(parts).replace("_x000D__x000A_", " ")
    return " ".join(err.split())[:300]


async def test(integ: Integration) -> dict[str, Any]:
    results = await _all_hosts(integ)
    errors = [r for r in results if isinstance(r, CollectorError)]
    if errors and len(errors) == len(results):
        raise errors[0]
    ok = [r for r in results if isinstance(r, dict)]
    vms = sum(len(r["vms"]) for r in ok)
    details: dict[str, Any] = {"hosts": ", ".join(str(r.get("host")) for r in ok), "vms": vms,
                               "product": ok[0].get("os") if ok else None}
    if ok and ok[0].get("cluster"):
        details["cluster"] = ok[0]["cluster"]
    if errors:
        details["falhas"] = "; ".join(str(e) for e in errors)
    return {"ok": True, "summary": f"{len(ok)} host(s) · {vms} VM(s)" + (f" · {len(errors)} host(s) com erro"
                                                                       if errors else ""), "details": details}


async def _all_hosts(integ: Integration) -> list[dict[str, Any] | CollectorError]:
    sem = asyncio.Semaphore(PARALLEL_HOSTS)

    async def one(host: str) -> dict[str, Any] | CollectorError:
        async with sem:
            try:
                return await asyncio.to_thread(_run, integ, host)
            except CollectorError as exc:
                return exc
    return list(await asyncio.gather(*(one(h) for h in hosts_of(integ))))


def _net_by_vm(net: dict[str, float], names: list[str]) -> dict[str, tuple[float, float]]:
    """Soma bytes/s por VM a partir dos caminhos dos contadores ("...adapter(<vm>_network adapter_...)\\bytes ...")."""
    lower = sorted(((n.lower(), n) for n in names), key=lambda x: -len(x[0]))
    out: dict[str, list[float]] = {}
    for path, value in (net or {}).items():
        p = path.lower()
        start, end = p.find("adapter("), p.rfind(")\\")
        if start < 0 or end < 0:
            continue
        inst = p[start + 8:end]
        vm = next((orig for low, orig in lower if inst.startswith(low + "_")), None)
        if vm is None:
            continue
        acc = out.setdefault(vm, [0.0, 0.0])
        if p.endswith("bytes received/sec"):
            acc[0] += float(value or 0)
        elif p.endswith("bytes sent/sec"):
            acc[1] += float(value or 0)
    return {k: (v[0], v[1]) for k, v in out.items()}


async def poll(integ: Integration, w: Writer) -> str:
    results = await _all_hosts(integ)
    errors = [r for r in results if isinstance(r, CollectorError)]
    ok = [r for r in results if isinstance(r, dict)]
    if not ok:
        raise errors[0] if errors else CollectorError("nenhum host configurado")
    clusters = sorted({r["cluster"] for r in ok if r.get("cluster")})
    cl_ids = await w.assets_bulk([{"external_id": f"cluster:{c.lower()}", "asset_type": "cluster", "name": c,
                                   "attributes": {"hypervisor": "hyperv"}} for c in clusters])
    host_items = []
    for r, h in zip(results, hosts_of(integ)):
        if not isinstance(r, dict):
            continue
        r["_key"] = f"host:{h.lower()}"
        fqdn = ".".join(x for x in (r.get("host"), r.get("domain")) if x and x != "WORKGROUP") or "?"
        r["_fqdn"] = fqdn
        host_items.append({"external_id": r["_key"], "asset_type": "hypervisor_host", "name": fqdn,
                           "parent_id": cl_ids.get(f"cluster:{str(r.get('cluster') or '').lower()}", (None,))[0],
                           "hostname": fqdn, "vendor": r.get("vendor"), "model": r.get("model"),
                           "os_name": r.get("os"),
                           "attributes": {"cpu_cores": r.get("cores"), "memory_bytes": r.get("mem"),
                                          "cluster": r.get("cluster"), "hypervisor": "hyperv"}})
    # Host que falhou nesta coleta: fica "fora" (sem mexer nas VMs dele, que podem ter migrado)
    for e, h in zip(results, hosts_of(integ)):
        if isinstance(e, CollectorError):
            host_items.append({"external_id": f"host:{h.lower()}", "asset_type": "hypervisor_host", "name": h,
                               "hostname": h, "status": "down", "attributes": {"last_error": str(e)[:300],
                                                                               "hypervisor": "hyperv"}})
    host_ids = await w.assets_bulk(host_items)
    for r in ok:
        aid, tid = host_ids[r["_key"]]
        w.metric(aid, tid, "availability.up", 1)
        w.metric(aid, tid, "cpu.usage.pct", r.get("cpu"))
        mem, free = r.get("mem"), r.get("free")
        if mem and free is not None:
            w.metric(aid, tid, "mem.used.bytes", mem - free)
            w.metric(aid, tid, "mem.usage.pct", round(100.0 * (mem - free) / mem, 2))
        boot = r.get("boot")
        if boot:
            from datetime import datetime
            from openmon.collector.common import now
            try:
                w.metric(aid, tid, "host.uptime.seconds",
                         (now() - datetime.fromisoformat(str(boot).replace("Z", "+00:00"))).total_seconds())
            except ValueError:
                pass
    for e, h in zip(results, hosts_of(integ)):
        if isinstance(e, CollectorError):
            aid, tid = host_ids[f"host:{h.lower()}"]
            w.metric(aid, tid, "availability.up", 0)

    vm_items, vm_rows = [], []
    for r in ok:
        host_aid = host_ids[r["_key"]][0]
        net = _net_by_vm(r.get("net") or {}, [v.get("name") or "" for v in r["vms"]])
        for v in r["vms"]:
            if not v.get("id"):
                continue
            facts = {"name": v.get("name") or "", "hyperv_host": [r["_fqdn"], r.get("host")],
                     "cluster": r.get("cluster")}
            state = str(v.get("state") or "")
            status = STATE.get(state, "unknown")
            if status == "up" and str(v.get("status") or "") not in ("Operating normally", ""):
                status = "warning"
            ips = [i for i in (v.get("ips") or []) if i]
            vm_items.append({"external_id": v["id"].lower(), "asset_type": "vm", "name": v.get("name") or v["id"],
                             "tenant_id": await w.tenant_for(facts), "parent_id": host_aid, "status": status,
                             "ip": ips[0] if ips else None, "vendor": "Microsoft",
                             "attributes": {"vcpu": v.get("vcpu"), "memory_bytes": v.get("mem_startup"),
                                            "memory_assigned_bytes": v.get("mem"), "dynamic_memory": v.get("dyn"),
                                            "power_state": state, "heartbeat": v.get("hb"),
                                            "generation": v.get("gen"), "config_version": v.get("ver"),
                                            "clustered": v.get("clustered"), "replication": v.get("repl"),
                                            "ips": ips, "host": r["_fqdn"], "cluster": r.get("cluster"),
                                            "hypervisor": "hyperv"}})
            vm_rows.append((v, net.get(v.get("name") or "")))
    vm_ids = await w.assets_bulk(vm_items)
    running = 0
    for v, net in vm_rows:
        aid, tid = vm_ids[v["id"].lower()]
        on = str(v.get("state")) == "Running"
        w.metric(aid, tid, "availability.up", 1 if on else 0)
        w.metric(aid, tid, "cpu.allocated.vcpu", v.get("vcpu"))
        alloc = v.get("mem") if v.get("dyn") else v.get("mem_startup")
        w.metric(aid, tid, "mem.allocated.bytes", alloc)
        if not on:
            continue
        running += 1
        w.metric(aid, tid, "cpu.usage.pct", v.get("cpu"))
        demand = v.get("mem_demand")
        w.metric(aid, tid, "mem.used.bytes", demand)
        if demand is not None and v.get("mem"):
            w.metric(aid, tid, "mem.usage.pct", round(100.0 * demand / v["mem"], 2))
        w.metric(aid, tid, "host.uptime.seconds", v.get("up"))
        if net:
            w.metric(aid, tid, "net.rx.bps", net[0] * 8)
            w.metric(aid, tid, "net.tx.bps", net[1] * 8)
    # VMs que sumiram só são aposentadas quando todos os hosts responderam (senão parecem ter sumido)
    removed = 0
    if not errors:
        removed = await w.retire_missing(("vm", "hypervisor_host", "cluster"))
    msg = f"{len(ok)} host(s), {len(vm_ids)} VM(s) ({running} ligada(s))"
    if removed:
        msg += f", {removed} removido(s) do inventário"
    if errors:
        return "warning: " + msg + "; " + "; ".join(str(e) for e in errors)[:600]
    return msg
