"""Backups (Veeam): jobs, última execução, SLA por tenant e repositórios. Filtrado pelo tenant da sessão (RLS).

SLA de um job = horas contratadas do job (``sla_rpo_hours``) ou, sem isso, do tenant
(``tenants.backup_sla_hours``). Dentro do SLA se o último backup bom (sucesso ou aviso)
terminou há menos que isso. Sem SLA definido, o job aparece mas não conta.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from openmon.api.admin_tenants import _db_error, _iso
from openmon.api.auth import SessionInfo, require_permission
from openmon.db import pool

router = APIRouter(prefix="/api/backups", tags=["backups"])


@router.get("")
async def list_backups(tenant_id: int | None = None, include_deleted: bool = False,
                       session: SessionInfo = Depends(require_permission("backups.view"))) -> dict[str, Any]:
    try:
        async with session.db() as conn:
            jobs = await conn.fetch(
                """SELECT j.id, j.name, j.job_type, j.is_enabled, j.schedule_desc, j.last_result, j.last_run_at,
                          j.last_success_at, j.tenant_id, t.name AS tenant_name, j.tenant_locked, j.deleted_at,
                          i.name AS integration_name, r.name AS repository_name,
                          coalesce(j.sla_rpo_hours, t.backup_sla_hours) AS sla_hours,
                          CASE WHEN coalesce(j.sla_rpo_hours, t.backup_sla_hours) IS NULL OR NOT j.is_enabled THEN NULL
                               ELSE coalesce(j.last_success_at > now() - make_interval(
                                        hours => coalesce(j.sla_rpo_hours, t.backup_sla_hours)), false) END AS in_sla
                     FROM backup_jobs j JOIN tenants t ON t.id = j.tenant_id
                     LEFT JOIN integrations i ON i.id = j.integration_id
                     LEFT JOIN assets r ON r.id = j.repository_id
                    WHERE ($1::bigint IS NULL OR j.tenant_id = $1) AND ($2 OR j.deleted_at IS NULL)
                    ORDER BY lower(t.name), lower(j.name)""", tenant_id, include_deleted)
            repos = await conn.fetch(
                """SELECT a.id, a.name, a.status, a.hostname, a.model, a.attributes->>'path' AS path,
                          (a.attributes->>'capacity_bytes')::bigint AS capacity_bytes,
                          (a.attributes->>'free_bytes')::bigint AS free_bytes, i.name AS integration_name
                     FROM assets a LEFT JOIN integrations i ON i.id = a.integration_id
                    WHERE a.asset_type = 'backup_repository' AND a.deleted_at IS NULL
                      AND ($1::bigint IS NULL OR a.tenant_id = $1)
                    ORDER BY lower(a.name)""", tenant_id)
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    out = [{k: _iso(r[k]) for k in r.keys()} for r in jobs]
    tenants: dict[int, dict[str, Any]] = {}
    for j in out:
        if j["deleted_at"]:
            continue
        t = tenants.setdefault(j["tenant_id"], {"tenant_id": j["tenant_id"], "tenant_name": j["tenant_name"],
                                                "sla_hours": None, "jobs": 0, "in_sla": 0, "out_of_sla": 0,
                                                "failed": 0, "running": 0})
        t["jobs"] += 1
        t["in_sla"] += j["in_sla"] is True
        t["out_of_sla"] += j["in_sla"] is False
        t["failed"] += j["last_result"] == "failed"
        t["running"] += j["last_result"] == "running"
        if j["sla_hours"] and (t["sla_hours"] is None or j["sla_hours"] < t["sla_hours"]):
            t["sla_hours"] = j["sla_hours"]
    return {"jobs": out, "tenants": sorted(tenants.values(), key=lambda t: t["tenant_name"].lower()),
            "repositories": [dict(r) for r in repos], "can_manage": session.can("integrations.manage")}


@router.get("/{job_id}/runs")
async def job_runs(job_id: int, limit: int = Query(default=50, ge=1, le=500),
                   session: SessionInfo = Depends(require_permission("backups.view"))) -> dict[str, Any]:
    try:
        async with session.db() as conn:
            if not await conn.fetchval("SELECT 1 FROM backup_jobs WHERE id = $1", job_id):
                raise HTTPException(404, "Job não encontrado.")
            rows = await conn.fetch(
                """SELECT session_external_id, started_at, ended_at, result, duration_s, message
                     FROM backup_job_runs WHERE job_id = $1 ORDER BY started_at DESC LIMIT $2""", job_id, limit)
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    return {"runs": [{k: _iso(r[k]) for k in r.keys()} for r in rows]}
