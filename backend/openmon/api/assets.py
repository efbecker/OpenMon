"""Inventário: ativos e interfaces, sempre filtrados pelo tenant da sessão (RLS + views ``v_*``).

Leitura: ``assets.view`` (todos os perfis; Cliente só vê os próprios tenants).
Mudar tenant de ativo/interface, monitorar interface e marcar link de cliente:
``integrations.manage`` (Administrador global).

Séries de um ativo por período (gráficos de VM, host, datastore, VDC): ``GET /api/assets/{id}/metrics``,
que escolhe a camada (bruto, horária, diária) pelo tamanho e pela idade do período. Ver docs/10-metricas-vms.md.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from openmon.api.admin_tenants import _audit, _db_error, _iso
from openmon.api.auth import SessionInfo, require_permission
from openmon.db import pool

router = APIRouter(prefix="/api", tags=["assets"])

LATEST = {1: "cpu_pct", 10: "mem_pct", 11: "mem_used", 20: "disk_capacity", 21: "disk_used", 26: "disk_read_bps",
          27: "disk_write_bps", 30: "net_rx_bps", 31: "net_tx_bps", 40: "up", 41: "uptime_s",
          50: "storage_capacity", 51: "storage_free", 60: "fs_capacity", 61: "fs_used", 62: "fs_max_pct"}
# Detalhes da infraestrutura do provedor que o cliente não vê: host ESXi/Hyper-V, cluster, MoRef, pastas...
INFRA_ATTRS = frozenset({"host", "cluster", "esx_host", "moref", "resource_pool", "folder", "provider_vdc",
                         "instance_uuid", "vc_name", "connection_state"})


def _hide_infra(item: dict[str, Any], session: SessionInfo) -> dict[str, Any]:
    """Visão do cliente: tira host do virtualizador, cluster e identificadores internos do provedor."""
    if session.is_global:
        return item
    attrs = item.get("attributes") or {}
    for k in INFRA_ATTRS:
        attrs.pop(k, None)
    if item.get("asset_type") == "vm":
        # vCloud: o "hostName" da VM é o host ESXi; vCenter/Hyper-V: o pai é o host
        if attrs.get("hypervisor") == "vcloud":
            item["hostname"] = None
        item.pop("external_id", None)
    for k in ("integration_name", "integration_id"):
        item.pop(k, None)
    return item


def _json(v: Any) -> dict[str, Any]:
    return json.loads(v) if isinstance(v, str) else dict(v or {})


@router.get("/assets")
async def list_assets(tenant_id: int | None = None, integration_id: int | None = None, asset_type: str | None = Query(default=None, max_length=40),
                      q: str | None = Query(default=None, max_length=100), include_deleted: bool = False,
                      limit: int = Query(default=500, ge=1, le=5000),
                      session: SessionInfo = Depends(require_permission("assets.view"))) -> dict[str, Any]:
    try:
        async with session.db() as conn:
            rows = await conn.fetch(
                """SELECT a.id, a.tenant_id, t.name AS tenant_name, a.integration_id, i.name AS integration_name,
                          i.kind AS integration_kind, a.parent_id, p.name AS parent_name, a.asset_type, a.name,
                          a.hostname, host(a.ip_address) AS ip, a.vendor, a.model, a.os_name, a.status, a.tenant_locked,
                          a.last_seen_at, a.last_status_change_at, a.deleted_at, a.attributes,
                          (SELECT count(*) FROM interfaces f WHERE f.asset_id = a.id AND f.is_monitored) AS interfaces
                     FROM assets a JOIN tenants t ON t.id = a.tenant_id
                     LEFT JOIN integrations i ON i.id = a.integration_id
                     LEFT JOIN assets p ON p.id = a.parent_id
                    WHERE ($1::bigint IS NULL OR a.tenant_id = $1)
                      AND ($2::text IS NULL OR a.asset_type = $2)
                      AND ($3::text IS NULL OR a.name ILIKE '%' || $3 || '%' OR a.hostname ILIKE '%' || $3 || '%'
                           OR host(a.ip_address) LIKE $3 || '%')
                      AND ($4 OR a.deleted_at IS NULL)
                      AND ($6::bigint IS NULL OR a.integration_id = $6)
                      AND NOT (a.attributes ? 'backup_job_id')
                    ORDER BY a.asset_type, lower(a.name) LIMIT $5""",
                tenant_id, asset_type, (q or "").strip() or None, include_deleted, limit, integration_id)
            counts = await conn.fetch(
                "SELECT asset_type, status, count(*) AS n FROM assets WHERE deleted_at IS NULL "
                "AND NOT (attributes ? 'backup_job_id') "
                "AND ($1::bigint IS NULL OR tenant_id = $1) GROUP BY 1, 2", tenant_id)
            latest = await _latest(conn, [r["id"] for r in rows])
            tenants = await conn.fetch("SELECT id, name, is_provider FROM tenants WHERE is_active "
                                       "ORDER BY is_provider DESC, lower(name)")
            # Links de cliente: a interface é do cliente mesmo quando o equipamento é do datacenter (o cliente vê a
            # porta dele, não o switch; o nome do equipamento só aparece para quem pode ver o ativo)
            links = await conn.fetch(
                """SELECT f.id, f.asset_id, a.name AS asset_name, f.if_name, f.if_alias, f.speed_bps, f.oper_status,
                          f.contracted_bps, f.tenant_id, t.name AS tenant_name, s.in_bps, s.out_bps, s.time AS sample_at
                     FROM interfaces f JOIN tenants t ON t.id = f.tenant_id
                     LEFT JOIN assets a ON a.id = f.asset_id
                     LEFT JOIN LATERAL (SELECT in_bps, out_bps, time FROM v_interface_samples x
                                         WHERE x.interface_id = f.id AND x.time > now() - interval '30 min'
                                         ORDER BY x.time DESC LIMIT 1) s ON true
                    WHERE f.is_customer_link AND ($1::bigint IS NULL OR f.tenant_id = $1)
                      AND ($2::bigint IS NULL OR a.integration_id = $2)
                    ORDER BY lower(t.name), f.if_name LIMIT 2000""", tenant_id, integration_id)
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    out = []
    for r in rows:
        attrs = _json(r["attributes"])
        out.append({"id": r["id"], "tenant_id": r["tenant_id"], "tenant_name": r["tenant_name"],
                    "integration_id": r["integration_id"], "integration_name": r["integration_name"],
                    "integration_kind": r["integration_kind"], "parent_id": r["parent_id"],
                    "parent_name": r["parent_name"], "asset_type": r["asset_type"], "name": r["name"],
                    "hostname": r["hostname"], "ip": r["ip"], "vendor": r["vendor"], "model": r["model"],
                    "os_name": r["os_name"], "status": r["status"], "tenant_locked": r["tenant_locked"],
                    "last_seen_at": _iso(r["last_seen_at"]), "deleted_at": _iso(r["deleted_at"]),
                    "interfaces": r["interfaces"], "latest": latest.get(r["id"], {}),
                    "attributes": {k: attrs[k] for k in ("vcpu", "memory_bytes", "guest_os", "power_state",
                                                         "sys_descr", "location", "capacity_bytes", "free_bytes",
                                                         "hypervisor", "org", "vdc", "vapp", "cluster", "host",
                                                         "folder", "volumes", "created_at")
                                   if k in attrs}})
        _hide_infra(out[-1], session)
    summary: dict[str, dict[str, int]] = {}
    for c in counts:
        summary.setdefault(c["asset_type"], {})[c["status"]] = c["n"]
    return {"assets": out, "summary": summary, "tenants": [dict(t) for t in tenants],
            "links": [{k: _iso(r[k]) for k in r.keys()} for r in links],
            "can_manage": session.can("integrations.manage")}


async def _latest(conn: Any, ids: list[int]) -> dict[int, dict[str, float]]:
    if not ids:
        return {}
    rows = await conn.fetch(
        """SELECT DISTINCT ON (asset_id, metric_id) asset_id, metric_id, value
             FROM v_metric_samples
            WHERE asset_id = ANY($1::bigint[]) AND metric_id = ANY($2::smallint[]) AND time > now() - interval '30 min'
            ORDER BY asset_id, metric_id, time DESC""", ids, list(LATEST))
    out: dict[int, dict[str, float]] = {}
    for r in rows:
        out.setdefault(r["asset_id"], {})[LATEST[r["metric_id"]]] = r["value"]
    return out


@router.get("/assets/{asset_id}")
async def get_asset(asset_id: int, session: SessionInfo = Depends(require_permission("assets.view"))) -> dict[str, Any]:
    try:
        async with session.db() as conn:
            a = await conn.fetchrow(
                """SELECT a.*, host(a.ip_address) AS ip, t.name AS tenant_name, i.name AS integration_name
                     FROM assets a JOIN tenants t ON t.id = a.tenant_id
                     LEFT JOIN integrations i ON i.id = a.integration_id WHERE a.id = $1""", asset_id)
            ifs = await conn.fetch(
                """SELECT f.id, f.if_index, f.if_name, f.if_alias, f.if_descr, f.if_type, f.speed_bps, f.admin_status,
                          f.oper_status, f.is_monitored, f.is_customer_link, f.contracted_bps, f.tenant_id,
                          t.name AS tenant_name, s.in_bps, s.out_bps, s.time AS sample_at
                     FROM interfaces f JOIN tenants t ON t.id = f.tenant_id
                     LEFT JOIN LATERAL (SELECT in_bps, out_bps, time FROM v_interface_samples x
                                         WHERE x.interface_id = f.id AND x.time > now() - interval '30 min'
                                         ORDER BY x.time DESC LIMIT 1) s ON true
                    WHERE f.asset_id = $1 ORDER BY f.if_index""", asset_id)
            children = await conn.fetchval("SELECT count(*) FROM assets WHERE parent_id = $1 AND deleted_at IS NULL",
                                           asset_id)
            latest = await _latest(conn, [asset_id])
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    if a is None:
        raise HTTPException(404, "Ativo não encontrado.")
    asset = {k: _iso(a[k]) for k in ("id", "tenant_id", "tenant_name", "integration_id", "integration_name",
                                      "parent_id", "asset_type", "name", "external_id", "hostname", "ip", "vendor",
                                      "model", "serial_number", "os_name", "status", "tenant_locked", "is_monitored",
                                      "first_seen_at", "last_seen_at", "last_status_change_at", "deleted_at")}
    asset["attributes"] = _json(a["attributes"])
    asset["children"] = children
    asset["latest"] = latest.get(asset_id, {})
    _hide_infra(asset, session)
    return {"asset": asset, "interfaces": [{k: _iso(r[k]) for k in r.keys()} for r in ifs],
            "can_manage": session.can("integrations.manage")}


class AssetUpdate(BaseModel):
    tenant_id: int
    tenant_locked: bool = True
    is_monitored: bool = True


@router.put("/admin/assets/{asset_id}")
async def update_asset(asset_id: int, form: AssetUpdate, request: Request,
                       session: SessionInfo = Depends(require_permission("integrations.manage", write=True))
                       ) -> dict[str, Any]:
    try:
        async with session.db() as conn:
            old = await conn.fetchrow("SELECT tenant_id, name FROM assets WHERE id = $1 FOR UPDATE", asset_id)
            if old is None:
                raise HTTPException(404, "Ativo não encontrado.")
            if not await conn.fetchval("SELECT 1 FROM tenants WHERE id = $1", form.tenant_id):
                raise HTTPException(422, "Tenant inexistente.")
            await conn.execute("UPDATE assets SET tenant_id = $2, tenant_locked = $3, is_monitored = $4, "
                               "updated_at = now() WHERE id = $1", asset_id, form.tenant_id, form.tenant_locked,
                               form.is_monitored)
            # Interfaces que seguiam o tenant do equipamento acompanham (links de cliente mantêm o seu)
            await conn.execute("UPDATE interfaces SET tenant_id = $2, updated_at = now() WHERE asset_id = $1 "
                               "AND tenant_id = $3 AND NOT is_customer_link", asset_id, form.tenant_id, old["tenant_id"])
            await _audit(conn, session, request, "asset.update", "asset", asset_id, form.tenant_id,
                         {"name": old["name"], "from_tenant": old["tenant_id"], **form.model_dump()})
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    return {"ok": True}


class InterfaceUpdate(BaseModel):
    is_monitored: bool
    is_customer_link: bool = False
    tenant_id: int
    contracted_bps: int | None = Field(default=None, gt=0, le=10**13)


@router.put("/admin/interfaces/{interface_id}")
async def update_interface(interface_id: int, form: InterfaceUpdate, request: Request,
                           session: SessionInfo = Depends(require_permission("integrations.manage", write=True))
                           ) -> dict[str, Any]:
    try:
        async with session.db() as conn:
            old = await conn.fetchrow("SELECT asset_id, if_name, tenant_id FROM interfaces WHERE id = $1 FOR UPDATE",
                                      interface_id)
            if old is None:
                raise HTTPException(404, "Interface não encontrada.")
            if not await conn.fetchval("SELECT 1 FROM tenants WHERE id = $1", form.tenant_id):
                raise HTTPException(422, "Tenant inexistente.")
            await conn.execute(
                """UPDATE interfaces SET is_monitored = $2, is_customer_link = $3, tenant_id = $4, contracted_bps = $5,
                          updated_at = now() WHERE id = $1""",
                interface_id, form.is_monitored, form.is_customer_link, form.tenant_id, form.contracted_bps)
            if not form.is_monitored:
                await conn.execute("DELETE FROM interface_counter_state WHERE interface_id = $1", interface_id)
            await _audit(conn, session, request, "interface.update", "interface", interface_id, form.tenant_id,
                         {"asset_id": old["asset_id"], "if_name": old["if_name"], **form.model_dump()})
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    return {"ok": True}


# ----------------------------------------------------------------------------------------------- séries por período
PERIODS = {"1h": timedelta(hours=1), "6h": timedelta(hours=6), "24h": timedelta(days=1), "7d": timedelta(days=7),
           "30d": timedelta(days=30), "90d": timedelta(days=90), "180d": timedelta(days=180),
           "365d": timedelta(days=365), "730d": timedelta(days=730), "1825d": timedelta(days=1825)}
MAX_POINTS = 480
# Idade máxima de cada camada (um pouco abaixo da retenção padrão de 35 dias / 25 meses)
RAW_MAX_SPAN, RAW_MAX_AGE = timedelta(days=2), timedelta(days=34)
HOURLY_MAX_SPAN, HOURLY_MAX_AGE = timedelta(days=90), timedelta(days=750)
RAW_BUCKETS = (60, 300, 900, 1800, 3600)
HOURLY_BUCKETS = (3600, 3 * 3600, 6 * 3600, 12 * 3600, 86400)
DAILY_BUCKETS = (86400, 7 * 86400, 30 * 86400)


def choose_tier(start: datetime, end: datetime, now: datetime | None = None) -> tuple[str, int]:
    """Camada e tamanho do balde (s) para o período: ~MAX_POINTS pontos no máximo por série.

    Até 2 dias (e começo nos últimos 34 dias): bruto; até 90 dias (e nos últimos ~25 meses): horária; acima: diária.
    """
    now = now or datetime.now(timezone.utc)
    span = end - start
    age = now - start
    if span <= RAW_MAX_SPAN and age <= RAW_MAX_AGE:
        tier, options = "raw", RAW_BUCKETS
    elif span <= HOURLY_MAX_SPAN and age <= HOURLY_MAX_AGE:
        tier, options = "hourly", HOURLY_BUCKETS
    else:
        tier, options = "daily", DAILY_BUCKETS
    want = span.total_seconds() / MAX_POINTS
    bucket = next((b for b in options if b >= want), options[-1])
    return tier, bucket


SERIES_SQL = {
    "raw": """SELECT public.time_bucket(make_interval(secs => $5), time) AS t, metric_id,
                     avg(value) AS avg, min(value) AS min, max(value) AS max
                FROM v_metric_samples
               WHERE asset_id = $1 AND time >= $2 AND time < $3 AND ($4::smallint[] IS NULL OR metric_id = ANY($4))
               GROUP BY 1, 2 ORDER BY 2, 1""",
    "hourly": """SELECT public.time_bucket(make_interval(secs => $5), bucket) AS t, metric_id,
                        sum(avg_value * samples) / nullif(sum(samples), 0) AS avg,
                        min(min_value) AS min, max(max_value) AS max
                   FROM v_metric_hourly
                  WHERE asset_id = $1 AND bucket >= $2 AND bucket < $3
                    AND ($4::smallint[] IS NULL OR metric_id = ANY($4))
                  GROUP BY 1, 2 ORDER BY 2, 1""",
    "daily": """SELECT public.time_bucket(make_interval(secs => $5), bucket) AS t, metric_id,
                       sum(avg_value * samples) / nullif(sum(samples), 0) AS avg,
                       min(min_value) AS min, max(max_value) AS max
                  FROM v_metric_daily
                 WHERE asset_id = $1 AND bucket >= $2 AND bucket < $3
                   AND ($4::smallint[] IS NULL OR metric_id = ANY($4))
                 GROUP BY 1, 2 ORDER BY 2, 1""",
}


def _parse_time(v: str | None, name: str) -> datetime | None:
    if not v:
        return None
    try:
        d = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(422, f"Data inválida em {name}: use ISO 8601 (ex.: 2026-11-01T00:00:00Z).") from exc
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


@router.get("/assets/{asset_id}/metrics")
async def asset_metrics(asset_id: int, period: str | None = Query(default=None, max_length=8),
                        start: str | None = Query(default=None, alias="from", max_length=40),
                        end: str | None = Query(default=None, alias="to", max_length=40),
                        keys: str | None = Query(default=None, max_length=1000),
                        session: SessionInfo = Depends(require_permission("assets.view"))) -> dict[str, Any]:
    """Séries do ativo no período: por métrica, pontos [epoch_ms, média, mínimo, máximo] e o resumo do período.

    ``period`` (1h, 6h, 24h, 7d, 30d, 90d, 180d, 365d, 730d, 1825d) ou ``from``/``to`` em ISO 8601;
    ``keys`` filtra métricas (``cpu.usage.pct,mem.usage.pct``). O tenant vem da sessão: ativo de outro cliente
    dá 404, e as views ``v_metric_*`` só devolvem amostras gravadas com um tenant visível.
    """
    now = datetime.now(timezone.utc)
    t_end = _parse_time(end, "to") or now
    t_start = _parse_time(start, "from")
    if t_start is None:
        if period and period not in PERIODS:
            raise HTTPException(422, f"Período inválido. Use um destes: {', '.join(PERIODS)}.")
        t_start = t_end - PERIODS[period or "24h"]
    if t_start >= t_end:
        raise HTTPException(422, "O início do período precisa ser antes do fim.")
    if t_end - t_start > timedelta(days=1830):
        raise HTTPException(422, "Período máximo: 5 anos.")
    tier, bucket = choose_tier(t_start, t_end, now)
    try:
        async with session.db() as conn:
            a = await conn.fetchrow(
                """SELECT a.id, a.name, a.asset_type, a.status, a.tenant_id, t.name AS tenant_name, a.attributes
                     FROM assets a JOIN tenants t ON t.id = a.tenant_id WHERE a.id = $1""", asset_id)
            if a is None:
                raise HTTPException(404, "Ativo não encontrado.")
            defs = {r["id"]: r for r in await conn.fetch(
                "SELECT id, key, name, unit, category, value_kind FROM metric_definitions")}
            ids = None
            if keys:
                by_key = {d["key"]: i for i, d in defs.items()}
                wanted = [k.strip() for k in keys.split(",") if k.strip()]
                unknown = [k for k in wanted if k not in by_key]
                if unknown:
                    raise HTTPException(422, f"Métrica desconhecida: {', '.join(unknown[:5])}.")
                ids = [by_key[k] for k in wanted]
            rows = await conn.fetch(SERIES_SQL[tier], asset_id, t_start, t_end, ids, float(bucket))
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    series: dict[int, dict[str, Any]] = {}
    for r in rows:
        mid = r["metric_id"]
        d = defs.get(mid)
        if d is None or r["avg"] is None:
            continue
        s = series.setdefault(mid, {"key": d["key"], "name": d["name"], "unit": d["unit"], "category": d["category"],
                                    "kind": d["value_kind"], "points": []})
        s["points"].append([int(r["t"].timestamp() * 1000), r["avg"], r["min"], r["max"]])
    out = []
    for mid in sorted(series):
        s = series[mid]
        pts = s["points"]
        s["stats"] = {"avg": sum(p[1] for p in pts) / len(pts), "min": min(p[2] for p in pts),
                      "max": max(p[3] for p in pts), "last": pts[-1][1], "first": pts[0][1]}
        out.append(s)
    attrs = _json(a["attributes"])
    return {"asset": {"id": a["id"], "name": a["name"], "asset_type": a["asset_type"], "status": a["status"],
                      "tenant_id": a["tenant_id"], "tenant_name": a["tenant_name"],
                      "vcpu": attrs.get("vcpu"), "memory_bytes": attrs.get("memory_bytes")},
            "from": t_start.isoformat(), "to": t_end.isoformat(), "tier": tier, "bucket_seconds": bucket,
            "series": out}
