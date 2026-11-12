"""Painel do cliente e relatórios: ambiente atual, consumo x contratado por período e crescimento.

Tudo passa pela sessão do usuário (RLS + views ``v_*``): o Cliente só enxerga os próprios tenants.

* ``/api/reports/scope``: tenants que o usuário pode consultar (seletor das telas);
* ``/api/reports/overview``: VDCs (contratado x em uso hoje), perfis de armazenamento e VMs;
* ``/api/reports/consumption``: séries de CPU, memória e armazenamento do(s) VDC(s) no período, com média,
  pico e percentil 95, e as VMs mais exigidas (quando há métricas de uso por VM);
* ``/api/reports/growth``: VMs, vCPU, memória e disco no fim de cada mês do período, resumo por ano e
  a lista de VMs (criadas e removidas no período), no modelo do relatório de crescimento.

Camada das séries (mesma regra das telas de VMs): até 2 dias, amostras brutas; até 90 dias, agregação
horária; acima disso, diária.

O crescimento é reconstruído pelo inventário: data de criação de cada VM (vCloud: ``dateCreated`` da VM ou
``creationDate`` da vApp; sem ela, a data em que o OpenMon viu a VM pela primeira vez) e data de remoção.
Os tamanhos são os atuais de cada VM.
"""
from __future__ import annotations

import json
import math
from datetime import date, datetime, time, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from openmon.api.admin_tenants import _db_error, _iso
from openmon.api.auth import SessionInfo, require_permission
from openmon.db import pool

router = APIRouter(prefix="/api/reports", tags=["reports"])

UTC = timezone.utc
GB = 1024 ** 3
MB = 1024 ** 2
# ids de metric_definitions (ver collector/common.METRIC)
CPU_PCT, CPU_MHZ, MEM_PCT, MEM_USED, MEM_ALLOC = 1, 2, 10, 11, 12
DISK_CAP, STO_CAP, STO_USED = 20, 50, 52
MAX_SPAN = timedelta(days=366 * 6)


def _json(v: Any) -> dict[str, Any]:
    return json.loads(v) if isinstance(v, str) else dict(v or {})


def _num(v: Any) -> float | None:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if math.isfinite(f) else None


def _parse_dt(v: Any) -> datetime | None:
    if not v:
        return None
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=UTC)
    try:
        d = datetime.fromisoformat(str(v).strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=UTC)


def _period(start: str | None, end: str | None, default_days: int) -> tuple[datetime, datetime]:
    """Período [início, fim) em UTC. Datas puras (AAAA-MM-DD) valem o dia inteiro; o fim nunca passa de agora."""
    now = datetime.now(UTC)

    def parse(v: str, is_end: bool) -> datetime:
        v = v.strip()
        if len(v) == 10:
            try:
                d = date.fromisoformat(v)
            except ValueError as exc:
                raise HTTPException(422, f"Data inválida: {v}") from exc
            return datetime.combine(d + timedelta(days=1) if is_end else d, time(), UTC)
        dt = _parse_dt(v)
        if dt is None:
            raise HTTPException(422, f"Data inválida: {v}")
        return dt

    e = parse(end, True) if end else now
    e = min(e, now)
    s = parse(start, False) if start else e - timedelta(days=default_days)
    if s >= e:
        raise HTTPException(422, "O início do período precisa ser anterior ao fim.")
    if e - s > MAX_SPAN:
        raise HTTPException(422, "Período longo demais (máximo de 6 anos).")
    return s, e


def _tier(s: datetime, e: datetime) -> tuple[str, str, timedelta]:
    """(view, coluna de tempo, largura do ponto no gráfico)."""
    span = e - s
    if span <= timedelta(days=2):
        return "v_metric_samples", "time", timedelta(minutes=10 if span > timedelta(hours=12) else 5)
    if span <= timedelta(days=90):
        return "v_metric_hourly", "bucket", timedelta(hours=1 if span <= timedelta(days=15) else 3)
    return "v_metric_daily", "bucket", timedelta(days=1 if span <= timedelta(days=800) else 7)


async def _tenant(conn: Any, session: SessionInfo, tenant_id: int | None) -> dict[str, Any]:
    """Tenant consultado: o informado (se visível) ou, sem ele, o único do usuário."""
    if tenant_id is None:
        if session.is_global or len(session.tenant_ids) != 1:
            raise HTTPException(422, "Escolha o tenant (cliente).")
        tenant_id = session.tenant_ids[0]
    elif not session.is_global and tenant_id not in session.tenant_ids:
        raise HTTPException(404, "Tenant não encontrado.")
    row = await conn.fetchrow("SELECT id, name, slug, is_provider FROM tenants WHERE id = $1", tenant_id)
    if row is None:
        raise HTTPException(404, "Tenant não encontrado.")
    return dict(row)


async def _latest(conn: Any, ids: list[int], metrics: list[int], hours: int = 6) -> dict[int, dict[int, float]]:
    if not ids:
        return {}
    rows = await conn.fetch(
        """SELECT DISTINCT ON (asset_id, metric_id) asset_id, metric_id, value
             FROM v_metric_samples
            WHERE asset_id = ANY($1::bigint[]) AND metric_id = ANY($2::smallint[])
              AND time > now() - make_interval(hours => $3)
            ORDER BY asset_id, metric_id, time DESC""", ids, metrics, hours)
    out: dict[int, dict[int, float]] = {}
    for r in rows:
        out.setdefault(r["asset_id"], {})[r["metric_id"]] = r["value"]
    return out


async def _vdcs(conn: Any, tenant_id: int) -> tuple[list[Any], list[Any]]:
    """VDCs do vCloud do tenant e os perfis de armazenamento de cada um."""
    vdcs = await conn.fetch(
        """SELECT id, name, status, attributes FROM assets
            WHERE tenant_id = $1 AND asset_type = 'datacenter' AND deleted_at IS NULL
              AND attributes ->> 'hypervisor' = 'vcloud'
            ORDER BY lower(name)""", tenant_id)
    sps = await conn.fetch(
        """SELECT id, parent_id, name, status, attributes FROM assets
            WHERE asset_type = 'datastore' AND deleted_at IS NULL AND parent_id = ANY($1::bigint[])
            ORDER BY lower(name)""", [v["id"] for v in vdcs])
    return list(vdcs), list(sps)


def _pct(used: float | None, cap: float | None) -> float | None:
    if used is None or not cap:
        return None
    return round(used / cap * 100, 1)


# -----------------------------------------------------------------------------
# Escopo
# -----------------------------------------------------------------------------
@router.get("/scope")
async def scope(session: SessionInfo = Depends(require_permission("reports.view"))) -> dict[str, Any]:
    try:
        async with session.db() as conn:
            rows = await conn.fetch(
                """SELECT t.id, t.name, t.is_provider,
                          EXISTS (SELECT 1 FROM assets a WHERE a.tenant_id = t.id AND a.asset_type = 'datacenter'
                                    AND a.deleted_at IS NULL AND a.attributes ->> 'hypervisor' = 'vcloud') AS has_vdc,
                          (SELECT count(*) FROM assets a WHERE a.tenant_id = t.id AND a.asset_type = 'vm'
                                    AND a.deleted_at IS NULL) AS vms
                     FROM tenants t WHERE t.is_active ORDER BY t.is_provider, lower(t.name)""")
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    tenants = [dict(r) for r in rows]
    if not session.is_global:
        tenants = [t for t in tenants if t["id"] in session.tenant_ids]
    # Padrão: o primeiro cliente com VDC, depois o primeiro com VMs, depois o primeiro da lista
    default = next((t["id"] for t in tenants if t["has_vdc"] and not t["is_provider"]), None) \
        or next((t["id"] for t in tenants if t["vms"] and not t["is_provider"]), None) \
        or (tenants[0]["id"] if tenants else None)
    return {"tenants": tenants, "default_tenant_id": default, "is_global": session.is_global}


# -----------------------------------------------------------------------------
# Ambiente atual
# -----------------------------------------------------------------------------
@router.get("/overview")
async def overview(tenant_id: int | None = None,
                   session: SessionInfo = Depends(require_permission("reports.view"))) -> dict[str, Any]:
    try:
        async with session.db() as conn:
            tenant = await _tenant(conn, session, tenant_id)
            vdcs, sps = await _vdcs(conn, tenant["id"])
            vms = await conn.fetch(
                """SELECT id, name, parent_id, status, os_name, first_seen_at, attributes FROM assets
                    WHERE tenant_id = $1 AND asset_type = 'vm' AND deleted_at IS NULL
                    ORDER BY lower(name) LIMIT 10000""", tenant["id"])
            vm_ids = [v["id"] for v in vms]
            latest = await _latest(conn, [v["id"] for v in vdcs] + [s["id"] for s in sps],
                                   [CPU_PCT, CPU_MHZ, MEM_PCT, MEM_USED, MEM_ALLOC, STO_CAP, STO_USED])
            vm_latest = await _latest(conn, vm_ids, [CPU_PCT, MEM_PCT, DISK_CAP], hours=72)
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc

    sp_by_vdc: dict[int, list[dict[str, Any]]] = {}
    for s in sps:
        a, m = _json(s["attributes"]), latest.get(s["id"], {})
        used = m.get(STO_USED, (_num(a.get("used_mb")) or 0) * MB if a.get("used_mb") is not None else None)
        cap = m.get(STO_CAP) or ((_num(a.get("limit_mb")) or 0) * MB or None)
        sp_by_vdc.setdefault(s["parent_id"], []).append(
            {"id": s["id"], "name": a.get("storage_profile") or s["name"], "used_bytes": used, "limit_bytes": cap,
             "pct": _pct(used, cap), "default": bool(a.get("default"))})

    vm_count: dict[int, list[int]] = {}
    for v in vms:
        on = str(_json(v["attributes"]).get("power_state") or "").upper() in ("POWERED_ON", "POWEREDON") \
            or v["status"] == "up"
        vm_count.setdefault(v["parent_id"], [0, 0])
        vm_count[v["parent_id"]][0] += 1
        vm_count[v["parent_id"]][1] += on

    out_vdcs = []
    for v in vdcs:
        a, m = _json(v["attributes"]), latest.get(v["id"], {})
        cpu_used = m.get(CPU_MHZ)
        cpu_cap = _num(a.get("cpu_allocation_mhz"))
        if not cpu_cap and cpu_used and m.get(CPU_PCT):
            cpu_cap = cpu_used / m[CPU_PCT] * 100
        mem_used = m.get(MEM_USED)
        mem_cap = m.get(MEM_ALLOC) or ((_num(a.get("memory_allocation_mb")) or 0) * MB or None)
        profiles = sp_by_vdc.get(v["id"], [])
        sto_used = sum(p["used_bytes"] or 0 for p in profiles) if profiles else None
        caps = [p["limit_bytes"] for p in profiles if p["limit_bytes"]]
        sto_cap = sum(caps) if caps and len(caps) == len(profiles) else (
            (_num(a.get("storage_limit_mb")) or 0) * MB or None)
        total, on = vm_count.get(v["id"], [a.get("vms") or 0, a.get("running_vms") or 0])
        out_vdcs.append({
            "id": v["id"], "name": v["name"], "vdc": a.get("vdc") or v["name"], "org": a.get("org"),
            "status": v["status"], "allocation_model": a.get("allocation_model"),
            "cpu": {"used_mhz": cpu_used, "allocated_mhz": cpu_cap,
                    "pct": m.get(CPU_PCT) if m.get(CPU_PCT) is not None else _pct(cpu_used, cpu_cap)},
            "memory": {"used_bytes": mem_used, "allocated_bytes": mem_cap,
                       "pct": m.get(MEM_PCT) if m.get(MEM_PCT) is not None else _pct(mem_used, mem_cap)},
            "storage": {"used_bytes": sto_used, "limit_bytes": sto_cap, "pct": _pct(sto_used, sto_cap)},
            "storage_profiles": profiles, "vms": total, "vms_on": on})

    out_vms = []
    for v in vms:
        a, m = _json(v["attributes"]), vm_latest.get(v["id"], {})
        created = _parse_dt(a.get("created_at"))
        out_vms.append({
            "id": v["id"], "name": v["name"], "os": a.get("guest_os") or v["os_name"], "status": v["status"],
            "power_state": a.get("power_state"), "vcpu": _num(a.get("vcpu")),
            "memory_bytes": _num(a.get("memory_bytes")),
            "disk_bytes": _num(a.get("disk_bytes")) or m.get(DISK_CAP),
            "created_at": _iso(created or v["first_seen_at"]), "created_estimated": created is None,
            "cpu_pct": m.get(CPU_PCT), "mem_pct": m.get(MEM_PCT), "vdc_id": v["parent_id"]})

    totals = {"vms": len(out_vms), "vms_on": sum(1 for v in out_vms if v["status"] == "up"),
              "vcpu": sum(v["vcpu"] or 0 for v in out_vms),
              "memory_bytes": sum(v["memory_bytes"] or 0 for v in out_vms),
              "disk_bytes": sum(v["disk_bytes"] or 0 for v in out_vms)}
    contract = None
    if out_vdcs:
        def total(key: str, field: str) -> float | None:
            vals = [d[key][field] for d in out_vdcs]
            return None if any(x is None for x in vals) else sum(vals)
        contract = {
            "cpu": {"used_mhz": total("cpu", "used_mhz"), "allocated_mhz": total("cpu", "allocated_mhz")},
            "memory": {"used_bytes": total("memory", "used_bytes"), "allocated_bytes": total("memory", "allocated_bytes")},
            "storage": {"used_bytes": total("storage", "used_bytes"), "limit_bytes": total("storage", "limit_bytes")}}
        contract["cpu"]["pct"] = _pct(contract["cpu"]["used_mhz"], contract["cpu"]["allocated_mhz"])
        contract["memory"]["pct"] = _pct(contract["memory"]["used_bytes"], contract["memory"]["allocated_bytes"])
        contract["storage"]["pct"] = _pct(contract["storage"]["used_bytes"], contract["storage"]["limit_bytes"])
    return {"tenant": tenant, "generated_at": _iso(datetime.now(UTC)), "vdcs": out_vdcs, "contract": contract,
            "totals": totals, "vms": out_vms}


# -----------------------------------------------------------------------------
# Consumo x contratado no período
# -----------------------------------------------------------------------------
async def _series(conn: Any, ids: list[int], metrics: list[int], s: datetime, e: datetime
                  ) -> tuple[list[datetime], dict[tuple[int, int], dict[datetime, tuple[float, float]]], str]:
    """Média e máximo por (ativo, métrica, ponto). Devolve os pontos do eixo, os valores e a camada usada."""
    view, col, width = _tier(s, e)
    if view == "v_metric_samples":
        avg, mx = "avg(value)", "max(value)"
    else:
        avg, mx = "sum(avg_value * samples) / nullif(sum(samples), 0)", "max(max_value)"
    rows = await conn.fetch(
        f"""SELECT public.time_bucket($1::interval, {col}, origin => $4::timestamptz) AS b, asset_id, metric_id,
                   {avg} AS v, {mx} AS mx
              FROM {view}
             WHERE asset_id = ANY($2::bigint[]) AND metric_id = ANY($3::smallint[])
               AND {col} >= $4 AND {col} < $5
             GROUP BY 1, 2, 3 ORDER BY 1""", width, ids, metrics, s, e) if ids else []
    vals: dict[tuple[int, int], dict[datetime, tuple[float, float]]] = {}
    for r in rows:
        if r["v"] is not None:
            vals.setdefault((r["asset_id"], r["metric_id"]), {})[r["b"]] = (r["v"], r["mx"])
    axis: list[datetime] = []
    t = s
    while t < e and len(axis) < 5000:
        axis.append(t)
        t += width
    return axis, vals, view.removeprefix("v_metric_")


def _carry(axis: list[datetime], points: dict[datetime, tuple[float, float]] | None,
           idx: int = 0) -> list[float | None]:
    """Série no eixo, repetindo o último valor por até 3 pontos (coleta atrasada não vira um vale)."""
    out: list[float | None] = []
    last, gap = None, 0
    for t in axis:
        p = (points or {}).get(t)
        if p is not None:
            last, gap = p[idx], 0
        else:
            gap += 1
            if gap > 3:
                last = None
        out.append(last)
    return out


def _sum(series: list[list[float | None]]) -> list[float | None]:
    if not series:
        return []
    out: list[float | None] = []
    for vals in zip(*series):
        out.append(None if any(v is None for v in vals) else sum(vals))  # type: ignore[arg-type]
    return out


def _stats(values: list[float | None], peaks: list[float | None] | None = None) -> dict[str, float | None]:
    v = sorted(x for x in values if x is not None)
    if not v:
        return {"avg": None, "min": None, "max": None, "p95": None, "last": None}
    pk = [x for x in (peaks or []) if x is not None]
    last = next((x for x in reversed(values) if x is not None), None)
    p95 = v[min(len(v) - 1, max(0, math.ceil(len(v) * 0.95) - 1))]
    return {"avg": round(sum(v) / len(v), 2), "min": round(v[0], 2), "max": round(max(pk or v), 2),
            "p95": round(p95, 2), "last": round(last, 2) if last is not None else None}


@router.get("/consumption")
async def consumption(tenant_id: int | None = None, start: str | None = Query(default=None, max_length=40),
                      end: str | None = Query(default=None, max_length=40),
                      session: SessionInfo = Depends(require_permission("reports.view"))) -> dict[str, Any]:
    s, e = _period(start, end, 30)
    try:
        async with session.db() as conn:
            tenant = await _tenant(conn, session, tenant_id)
            vdcs, sps = await _vdcs(conn, tenant["id"])
            vdc_ids, sp_ids = [v["id"] for v in vdcs], [x["id"] for x in sps]
            axis, vals, tier = await _series(conn, vdc_ids + sp_ids,
                                             [CPU_PCT, CPU_MHZ, MEM_USED, MEM_ALLOC, STO_CAP, STO_USED], s, e)
            vm_ids = [r["id"] for r in await conn.fetch(
                "SELECT id FROM assets WHERE tenant_id = $1 AND asset_type = 'vm' LIMIT 10000", tenant["id"])]
            top = await _top_vms(conn, vm_ids, s, e)
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc

    # CPU: MHz em uso; contratado = MHz / % (o vCloud manda os dois) ou a alocação atual do VDC
    cpu_used, cpu_cap, mem_used, mem_cap, sto_used, sto_cap = [], [], [], [], [], []
    for v in vdcs:
        a = _json(v["attributes"])
        used = _carry(axis, vals.get((v["id"], CPU_MHZ)))
        pct = _carry(axis, vals.get((v["id"], CPU_PCT)))
        alloc = _num(a.get("cpu_allocation_mhz"))
        cap = [(u * 100 / p) if (u is not None and p) else (alloc if u is not None else None)
               for u, p in zip(used, pct)]
        cpu_used.append(used)
        cpu_cap.append(cap)
        mem_used.append(_carry(axis, vals.get((v["id"], MEM_USED))))
        mem_cap.append(_carry(axis, vals.get((v["id"], MEM_ALLOC))))
    limited = all((x["id"], STO_CAP) in vals for x in sps) and bool(sps)
    for x in sps:
        sto_used.append(_carry(axis, vals.get((x["id"], STO_USED))))
        if limited:
            sto_cap.append(_carry(axis, vals.get((x["id"], STO_CAP))))

    def block(used: list[list[float | None]], cap: list[list[float | None]], unit: str) -> dict[str, Any] | None:
        u, c = _sum(used), _sum(cap) if cap else []
        if not any(x is not None for x in u):
            return None
        pct = [(round(a / b * 100, 2) if (a is not None and b) else None) for a, b in zip(u, c)] if c else []
        return {"unit": unit, "used": [round(x, 2) if x is not None else None for x in u],
                "allocated": [round(x, 2) if x is not None else None for x in c] if c else None,
                "pct": pct or None, "stats": _stats(u), "pct_stats": _stats(pct) if pct else None,
                "allocated_last": next((round(x, 2) for x in reversed(c) if x is not None), None) if c else None,
                "hours_above_90": (round(sum(1 for p in pct if p is not None and p >= 90)
                                         * (axis[1] - axis[0]).total_seconds() / 3600, 1)
                                   if pct and len(axis) > 1 else None)}

    return {"tenant": tenant, "start": _iso(s), "end": _iso(e), "tier": tier,
            "step_seconds": int((axis[1] - axis[0]).total_seconds()) if len(axis) > 1 else None,
            "labels": [_iso(t) for t in axis],
            "cpu": block(cpu_used, cpu_cap, "MHz"), "memory": block(mem_used, mem_cap, "B"),
            "storage": block(sto_used, sto_cap, "B"), "vdcs": [v["name"] for v in vdcs], "top_vms": top}


async def _top_vms(conn: Any, vm_ids: list[int], s: datetime, e: datetime) -> dict[str, list[dict[str, Any]]]:
    """VMs com maior uso médio de CPU e de memória no período (precisa das métricas de uso por VM)."""
    if not vm_ids:
        return {"cpu": [], "memory": []}
    view, col, _ = _tier(s, e)
    if view == "v_metric_samples":
        avg, mx = "avg(m.value)", "max(m.value)"
    else:
        avg, mx = "sum(m.avg_value * m.samples) / nullif(sum(m.samples), 0)", "max(m.max_value)"
    rows = await conn.fetch(
        f"""SELECT m.asset_id, m.metric_id, a.name, {avg} AS avg, {mx} AS peak
              FROM {view} m JOIN assets a ON a.id = m.asset_id
             WHERE m.asset_id = ANY($1::bigint[]) AND m.metric_id = ANY($2::smallint[])
               AND m.{col} >= $3 AND m.{col} < $4
             GROUP BY 1, 2, 3""", vm_ids, [CPU_PCT, MEM_PCT], s, e)
    out: dict[str, list[dict[str, Any]]] = {"cpu": [], "memory": []}
    for r in rows:
        if r["avg"] is None:
            continue
        out["cpu" if r["metric_id"] == CPU_PCT else "memory"].append(
            {"id": r["asset_id"], "name": r["name"], "avg": round(r["avg"], 1), "peak": round(r["peak"], 1)})
    for k in out:
        out[k] = sorted(out[k], key=lambda x: -x["avg"])[:10]
    return out


# -----------------------------------------------------------------------------
# Crescimento
# -----------------------------------------------------------------------------
def _month_ends(s: datetime, e: datetime) -> list[tuple[str, datetime]]:
    """(rótulo MM/AAAA, instante de corte) para cada mês do período; o último corta no fim do período."""
    out = []
    y, m = s.year, s.month
    while True:
        ny, nm = (y + 1, 1) if m == 12 else (y, m + 1)
        cut = datetime(ny, nm, 1, tzinfo=UTC)
        out.append((f"{m:02d}/{y}", min(cut, e)))
        if cut >= e or len(out) > 120:
            return out
        y, m = ny, nm


@router.get("/growth")
async def growth(tenant_id: int | None = None, start: str | None = Query(default=None, max_length=40),
                 end: str | None = Query(default=None, max_length=40),
                 session: SessionInfo = Depends(require_permission("reports.view"))) -> dict[str, Any]:
    try:
        async with session.db() as conn:
            tenant = await _tenant(conn, session, tenant_id)
            rows = await conn.fetch(
                """SELECT id, name, status, os_name, first_seen_at, deleted_at, attributes FROM assets
                    WHERE tenant_id = $1 AND asset_type = 'vm' ORDER BY lower(name) LIMIT 20000""", tenant["id"])
            no_disk = [r["id"] for r in rows if not _num(_json(r["attributes"]).get("disk_bytes"))]
            disks = await _latest(conn, no_disk, [DISK_CAP], hours=24 * 3) if no_disk else {}
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc

    vms = []
    for r in rows:
        a = _json(r["attributes"])
        created = _parse_dt(a.get("created_at"))
        vms.append({"id": r["id"], "name": r["name"], "os": a.get("guest_os") or r["os_name"],
                    "status": r["status"], "power_state": a.get("power_state"),
                    "vcpu": _num(a.get("vcpu")) or 0, "memory_bytes": _num(a.get("memory_bytes")) or 0,
                    "disk_bytes": _num(a.get("disk_bytes")) or disks.get(r["id"], {}).get(DISK_CAP) or 0,
                    "created": created or r["first_seen_at"], "created_estimated": created is None,
                    "deleted": r["deleted_at"]})

    # Período padrão: de janeiro do ano da VM mais antiga até hoje
    if start is None:
        first = min((v["created"] for v in vms), default=datetime.now(UTC))
        start = f"{first.year}-01-01"
    s, e = _period(start, end, 365)
    months = _month_ends(s, e)

    def totals(at: datetime) -> dict[str, float]:
        alive = [v for v in vms if v["created"] < at and (v["deleted"] is None or v["deleted"] >= at)]
        return {"vms": len(alive), "vcpu": sum(v["vcpu"] for v in alive),
                "memory_bytes": sum(v["memory_bytes"] for v in alive),
                "disk_bytes": sum(v["disk_bytes"] for v in alive)}

    points = [totals(cut) for _, cut in months]
    begin, final = totals(s), points[-1] if points else totals(e)
    since = f"{s.month:02d}/{s.year}"
    if not begin["vms"]:
        # Cliente que começou dentro do período: compara com o fim do primeiro mês com VMs (como "desde 12/2022")
        first = next((i for i, p in enumerate(points) if p["vms"]), None)
        if first is not None and first < len(points) - 1:
            begin, since = points[first], months[first][0]

    def change(key: str) -> dict[str, float | None]:
        a, b = begin[key], final[key]
        return {"start": a, "end": b, "delta": b - a, "pct": round((b - a) / a * 100, 1) if a else None}

    years: list[dict[str, Any]] = []
    prev = totals(s)
    for i, (label, cut) in enumerate(months):
        if label.startswith("12/") or i == len(months) - 1:
            cur = points[i]
            years.append({"year": int(label[3:]), "partial_until": None if label.startswith("12/") else label,
                          **cur, "added": {k: cur[k] - prev[k] for k in cur}})
            prev = cur

    def vm_out(v: dict[str, Any]) -> dict[str, Any]:
        return {"id": v["id"], "name": v["name"], "os": v["os"], "status": v["status"],
                "power_state": v["power_state"], "vcpu": v["vcpu"], "memory_bytes": v["memory_bytes"],
                "disk_bytes": v["disk_bytes"], "created_at": _iso(v["created"]),
                "created_estimated": v["created_estimated"], "deleted_at": _iso(v["deleted"]),
                "new_in_period": s <= v["created"] < e}

    alive_end = sorted((v for v in vms if v["created"] < e and (v["deleted"] is None or v["deleted"] >= e)),
                       key=lambda v: v["created"], reverse=True)
    removed = sorted((v for v in vms if v["deleted"] is not None and s <= v["deleted"] < e),
                     key=lambda v: v["deleted"], reverse=True)
    return {"tenant": tenant, "start": _iso(s), "end": _iso(e), "labels": [m[0] for m in months],
            "series": {k: [p[k] for p in points] for k in ("vms", "vcpu", "memory_bytes", "disk_bytes")},
            "kpis": {k: change(k) for k in ("vms", "vcpu", "memory_bytes", "disk_bytes")}, "kpis_since": since,
            "years": years, "vms": [vm_out(v) for v in alive_end], "removed": [vm_out(v) for v in removed],
            "estimated_dates": sum(1 for v in alive_end if v["created_estimated"])}


# -----------------------------------------------------------------------------
# FinOps: VMs mal dimensionadas e economia possível
# -----------------------------------------------------------------------------
NET_RX, NET_TX, FS_MAX, UPTIME, DISK_USED, AVAIL = 30, 31, 62, 41, 21, 40
# Limiares (uso medido pelo percentil 95 das médias de cada ponto do período)
CPU_LOW, CPU_HIGH, MEM_LOW, MEM_HIGH = 40.0, 85.0, 40.0, 90.0
TARGET = 70.0  # uso alvo depois do ajuste
FS_FULL, DISK_SPARE = 90.0, 30.0
IDLE_CPU = 2.0


def _round_gb(gb: float, windows: bool) -> int:
    """Memória recomendada em GB "redondos" (1, 2, 4, 6, 8, 12, 16, 24, 32...)."""
    steps = [1, 2, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024]
    floor = 4 if windows else 1
    return next((x for x in steps if x >= max(gb, floor)), int(math.ceil(gb)))


def _pstats(points: dict[datetime, tuple[float, float]] | None) -> dict[str, float | None]:
    """Média, P95 (das médias dos pontos) e pico (máximo bruto) de uma série."""
    if not points:
        return {"avg": None, "p95": None, "peak": None, "last": None}
    vals = [v for v, _ in points.values() if v is not None]
    if not vals:
        return {"avg": None, "p95": None, "peak": None, "last": None}
    s = sorted(vals)
    last = points[max(points)][0]
    return {"avg": sum(vals) / len(vals), "p95": s[min(len(s) - 1, max(0, math.ceil(len(s) * 0.95) - 1))],
            "peak": max(mx for _, mx in points.values() if mx is not None), "last": last}


def _analyse(vm: dict[str, Any], st: dict[int, dict[str, float | None]], days: float) -> dict[str, Any]:
    """Recomendações de right-sizing de uma VM a partir das estatísticas do período."""
    recs: list[dict[str, Any]] = []
    saving = {"vcpu": 0.0, "memory_gb": 0.0, "disk_gb": 0.0}
    extra = {"vcpu": 0.0, "memory_gb": 0.0, "disk_gb": 0.0}
    vcpu = int(vm["vcpu"] or 0)
    mem_gb = (vm["memory_bytes"] or 0) / GB
    windows = "windows" in (vm["os"] or "").lower()
    cpu, mem = st.get(CPU_PCT, {}), st.get(MEM_PCT, {})
    up = st.get(AVAIL, {})
    on_ratio = up.get("avg")
    disk_cap = st.get(DISK_CAP, {}).get("last") or vm["disk_bytes"]
    disk_used = st.get(DISK_USED, {}).get("last")
    fs_max = st.get(FS_MAX, {}).get("last")

    if cpu.get("avg") is None and mem.get("avg") is None:
        if on_ratio is not None and on_ratio < 0.01 or (on_ratio is None and vm["status"] != "up"):
            gb = (disk_cap or 0) / GB
            recs.append({"kind": "off", "level": "warn", "title": "VM desligada no período",
                         "text": f"Ficou desligada o período todo e mantém {gb:,.0f} GB de disco e {vcpu} vCPU / "
                                 f"{mem_gb:,.0f} GB reservados. Avalie arquivar ou remover."
                         .replace(",", ".")})
            saving["disk_gb"] += gb
            return {"status": "warn", "recs": recs, "saving": saving, "extra": extra}
        recs.append({"kind": "nodata", "level": "info", "title": "Sem métricas no período",
                     "text": "Sem leituras de uso de CPU e memória neste período (VMware Tools ou permissão de "
                             "métricas). Não há como avaliar o dimensionamento."})
        return {"status": "nodata", "recs": recs, "saving": saving, "extra": extra}

    # CPU
    p95, peak, avg = cpu.get("p95"), cpu.get("peak"), cpu.get("avg")
    if p95 is not None and vcpu:
        if p95 >= CPU_HIGH or (peak is not None and peak >= 98 and p95 >= 70):
            new = max(vcpu + 1, math.ceil(vcpu * p95 / TARGET))
            recs.append({"kind": "cpu_up", "level": "crit", "title": "CPU sob pressão",
                         "text": f"Uso médio de {avg:.0f}%, P95 de {p95:.0f}% e pico de {peak:.0f}% da capacidade. "
                                 f"Recomenda-se aumentar de {vcpu} para {new} vCPU.", "from": vcpu, "to": new})
            extra["vcpu"] += new - vcpu
        elif p95 < CPU_LOW and vcpu > 1:
            new = max(1, math.ceil(vcpu * max(p95, 1) / TARGET))
            if peak is not None and peak >= 90:
                new = max(new, vcpu - max(1, vcpu // 4))  # picos altos: reduz com cautela
            if new < vcpu:
                recs.append({"kind": "cpu_down", "level": "warn", "title": "CPU ociosa (right-sizing)",
                             "text": f"Uso médio de {avg:.0f}% e P95 de {p95:.0f}% (pico {peak:.0f}%). "
                                     f"Recomenda-se reduzir de {vcpu} para {new} vCPU.", "from": vcpu, "to": new})
                saving["vcpu"] += vcpu - new
    # Memória
    p95, peak, avg = mem.get("p95"), mem.get("peak"), mem.get("avg")
    if p95 is not None and mem_gb:
        if p95 >= MEM_HIGH:
            new = _round_gb(mem_gb * p95 / TARGET, windows)
            new = max(new, _round_gb(mem_gb + 1, windows))
            recs.append({"kind": "mem_up", "level": "crit", "title": "Memória sob pressão",
                         "text": f"Uso médio de {avg:.0f}%, P95 de {p95:.0f}% de {mem_gb:.0f} GB. "
                                 f"Recomenda-se aumentar para {new} GB.", "from": mem_gb, "to": new})
            extra["memory_gb"] += new - mem_gb
        elif p95 < MEM_LOW:
            new = _round_gb(mem_gb * max(p95, 1) / TARGET, windows)
            if new < mem_gb:
                recs.append({"kind": "mem_down", "level": "warn", "title": "Memória ociosa (right-sizing)",
                             "text": f"Uso médio de {avg * mem_gb / 100:.1f} de {mem_gb:.0f} GB ({avg:.0f}%), "
                                     f"P95 de {p95:.0f}% e pico de {peak:.0f}%. Recomenda-se reduzir para {new} GB.",
                             "from": mem_gb, "to": new})
                saving["memory_gb"] += mem_gb - new
    # Disco
    if fs_max is not None and fs_max >= FS_FULL:
        recs.append({"kind": "disk_full", "level": "crit", "title": "Volume quase cheio",
                     "text": f"O volume mais cheio do sistema está com {fs_max:.0f}% ocupados. Amplie o disco ou "
                             "libere espaço."})
    elif disk_cap and disk_used is not None and disk_cap > 50 * GB and disk_used / disk_cap * 100 < DISK_SPARE:
        free = (disk_cap - disk_used) / GB
        target = math.ceil(disk_used / GB / (TARGET / 100))
        recs.append({"kind": "disk_down", "level": "warn", "title": "Disco superprovisionado",
                     "text": f"Usa {disk_used / GB:,.0f} de {disk_cap / GB:,.0f} GB ({disk_used / disk_cap * 100:.0f}%). "
                             f"Cerca de {free:,.0f} GB provisionados sem uso; um disco de ~{target:,} GB atenderia "
                             "(reduzir disco exige migrar os dados para um disco menor).".replace(",", "."),
                     "from": disk_cap / GB, "to": target})
        saving["disk_gb"] += disk_cap / GB - target
    # Ociosa
    cavg = cpu.get("avg")
    net = (st.get(NET_RX, {}).get("avg") or 0) + (st.get(NET_TX, {}).get("avg") or 0)
    if cavg is not None and cavg < IDLE_CPU and (cpu.get("peak") or 0) < 10 and net < 20_000 and days >= 7:
        recs.insert(0, {"kind": "idle", "level": "warn", "title": "VM possivelmente ociosa",
                        "text": f"CPU média de {cavg:.1f}% (pico {cpu.get('peak') or 0:.0f}%) e rede quase parada no "
                                "período. Confirme com o responsável se ainda é usada; desligar ou remover libera "
                                "todos os recursos."})
    if not recs:
        recs.append({"kind": "ok", "level": "ok", "title": "Dimensionamento adequado",
                     "text": "O uso de CPU e memória ficou dentro da faixa esperada no período."})
    levels = {r["level"] for r in recs}
    status = "crit" if "crit" in levels else "warn" if "warn" in levels else "ok"
    return {"status": status, "recs": recs, "saving": saving, "extra": extra}


@router.get("/finops")
async def finops(tenant_id: int | None = None, start: str | None = Query(default=None, max_length=40),
                 end: str | None = Query(default=None, max_length=40),
                 session: SessionInfo = Depends(require_permission("reports.view"))) -> dict[str, Any]:
    s, e = _period(start, end, 30)
    metrics = [CPU_PCT, CPU_MHZ, MEM_PCT, MEM_USED, DISK_CAP, DISK_USED, NET_RX, NET_TX, FS_MAX, UPTIME, AVAIL]
    try:
        async with session.db() as conn:
            tenant = await _tenant(conn, session, tenant_id)
            rows = await conn.fetch(
                """SELECT id, name, status, os_name, attributes FROM assets
                    WHERE tenant_id = $1 AND asset_type = 'vm' AND deleted_at IS NULL
                    ORDER BY lower(name) LIMIT 5000""", tenant["id"])
            ids = [r["id"] for r in rows]
            axis, vals, tier = await _series(conn, ids, metrics, s, e)
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc

    days = (e - s).total_seconds() / 86400
    out, chart_budget = [], 100
    totals = {"saving": {"vcpu": 0.0, "memory_gb": 0.0, "disk_gb": 0.0},
              "extra": {"vcpu": 0.0, "memory_gb": 0.0, "disk_gb": 0.0},
              "status": {"ok": 0, "warn": 0, "crit": 0, "nodata": 0},
              "allocated": {"vcpu": 0.0, "memory_gb": 0.0, "disk_gb": 0.0}}
    for r in rows:
        a = _json(r["attributes"])
        vm = {"id": r["id"], "name": r["name"], "os": a.get("guest_os") or r["os_name"], "status": r["status"],
              "vcpu": _num(a.get("vcpu")), "memory_bytes": _num(a.get("memory_bytes")),
              "disk_bytes": _num(a.get("disk_bytes"))}
        st = {m: _pstats(vals.get((r["id"], m))) for m in metrics}
        res = _analyse(vm, st, days)
        cpu_mhz = st[CPU_MHZ]["avg"]
        cap_mhz = (cpu_mhz * 100 / st[CPU_PCT]["avg"]) if cpu_mhz and st[CPU_PCT]["avg"] else None
        volumes = [{"path": v.get("path"), "pct": round((1 - (v.get("free") or 0) / v["cap"]) * 100, 1)}
                   for v in (a.get("volumes") or []) if isinstance(v, dict) and v.get("cap")]
        item = {**vm, **res, "avg": {
                    "cpu_pct": st[CPU_PCT]["avg"], "cpu_p95": st[CPU_PCT]["p95"], "cpu_peak": st[CPU_PCT]["peak"],
                    "cpu_mhz": cpu_mhz, "cpu_capacity_mhz": cap_mhz,
                    "mem_pct": st[MEM_PCT]["avg"], "mem_p95": st[MEM_PCT]["p95"], "mem_peak": st[MEM_PCT]["peak"],
                    "mem_used_bytes": st[MEM_USED]["avg"], "disk_capacity_bytes": st[DISK_CAP]["last"] or vm["disk_bytes"],
                    "disk_used_bytes": st[DISK_USED]["last"], "fs_max_pct": st[FS_MAX]["last"],
                    "net_rx_bps": st[NET_RX]["avg"], "net_tx_bps": st[NET_TX]["avg"],
                    "uptime_s": st[UPTIME]["last"]},
                "volumes": volumes[:12]}
        out.append(item)
        totals["status"][res["status"]] += 1
        for k in totals["saving"]:
            totals["saving"][k] += res["saving"][k]
            totals["extra"][k] += res["extra"][k]
        totals["allocated"]["vcpu"] += vm["vcpu"] or 0
        totals["allocated"]["memory_gb"] += (vm["memory_bytes"] or 0) / GB
        totals["allocated"]["disk_gb"] += (item["avg"]["disk_capacity_bytes"] or 0) / GB
    order = {"crit": 0, "warn": 1, "ok": 2, "nodata": 3}
    out.sort(key=lambda v: (order[v["status"]], -(v["saving"]["vcpu"] * 4 + v["saving"]["memory_gb"]), v["name"].lower()))
    # Gráfico por VM: as que pedem ação primeiro, até 100 (o relatório não fica pesado demais)
    for item in out:
        if item["status"] == "nodata" or chart_budget <= 0:
            continue
        chart_budget -= 1
        item["series"] = {k: [round(x, 1) if x is not None else None for x in _carry(axis, vals.get((item["id"], m)))]
                          for k, m in (("cpu", CPU_PCT), ("mem", MEM_PCT))}
    for k in ("saving", "extra", "allocated"):
        totals[k] = {x: round(y, 1) for x, y in totals[k].items()}
    return {"tenant": tenant, "start": _iso(s), "end": _iso(e), "tier": tier,
            "step_seconds": int((axis[1] - axis[0]).total_seconds()) if len(axis) > 1 else None,
            "labels": [_iso(t) for t in axis], "vms": out, "totals": totals,
            "thresholds": {"cpu_low": CPU_LOW, "cpu_high": CPU_HIGH, "mem_low": MEM_LOW, "mem_high": MEM_HIGH,
                           "target": TARGET}}
