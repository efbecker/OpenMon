"""Inventário: ativos e interfaces, sempre filtrados pelo tenant da sessão (RLS + views ``v_*``).

Leitura: ``assets.view`` (todos os perfis; Cliente só vê os próprios tenants).
Mudar tenant de ativo/interface, monitorar interface e marcar link de cliente:
``integrations.manage`` (Administrador global).
"""
from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from openmon.api.admin_tenants import _audit, _db_error, _iso
from openmon.api.auth import SessionInfo, require_permission
from openmon.db import pool

router = APIRouter(prefix="/api", tags=["assets"])

LATEST = {1: "cpu_pct", 10: "mem_pct", 30: "net_rx_bps", 31: "net_tx_bps", 40: "up", 41: "uptime_s",
          50: "storage_capacity", 51: "storage_free"}


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
                    ORDER BY a.asset_type, lower(a.name) LIMIT $5""",
                tenant_id, asset_type, (q or "").strip() or None, include_deleted, limit, integration_id)
            counts = await conn.fetch(
                "SELECT asset_type, status, count(*) AS n FROM assets WHERE deleted_at IS NULL "
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
                                                         "sys_descr", "location", "capacity_bytes", "free_bytes")
                                   if k in attrs}})
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
