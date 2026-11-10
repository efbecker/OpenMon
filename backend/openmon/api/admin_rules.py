"""Regras automáticas de tenant: qual cliente é dono de cada VM/job descoberto.

Avaliadas na coleta, em ordem de prioridade (menor primeiro); a primeira que casa
decide. Ativo com o tenant fixado à mão (``tenant_locked``) não é mexido. Campos:
pasta, resource pool e cluster do vCenter, host Hyper-V, nome do job Veeam (curingas
``*`` e ``?``, sem diferenciar maiúsculas) e nome do ativo por expressão regular.
"""
from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from openmon.api.admin_tenants import _audit, _db_error, _iso
from openmon.api.auth import SessionInfo, require_permission
from openmon.db import pool

router = APIRouter(prefix="/api/admin/tenant-rules", tags=["admin"])
FIELDS = ("folder", "resource_pool", "cluster", "vsphere_tag", "name_regex", "hyperv_host", "veeam_job")


class RuleForm(BaseModel):
    tenant_id: int
    integration_id: int | None = None
    match_field: str = Field(pattern="^(" + "|".join(FIELDS) + ")$")
    pattern: str = Field(min_length=1, max_length=300)
    priority: int = Field(default=100, ge=0, le=100000)
    is_enabled: bool = True


async def _validate(conn: Any, form: RuleForm) -> str:
    pattern = form.pattern.strip()
    if form.match_field == "name_regex":
        try:
            re.compile(pattern)
        except re.error as exc:
            raise HTTPException(422, f"Expressão regular inválida: {exc}") from exc
    if not await conn.fetchval("SELECT 1 FROM tenants WHERE id = $1 AND is_active", form.tenant_id):
        raise HTTPException(422, "Tenant inexistente ou desativado.")
    if form.integration_id is not None and not await conn.fetchval(
            "SELECT 1 FROM integrations WHERE id = $1", form.integration_id):
        raise HTTPException(422, "Integração inexistente.")
    return pattern


@router.get("")
async def list_rules(session: SessionInfo = Depends(require_permission("integrations.manage"))) -> dict[str, Any]:
    try:
        async with session.db() as conn:
            rows = await conn.fetch(
                """SELECT r.id, r.tenant_id, t.name AS tenant_name, r.integration_id, i.name AS integration_name,
                          r.match_field, r.pattern, r.priority, r.is_enabled, r.created_at
                     FROM tenant_assignment_rules r JOIN tenants t ON t.id = r.tenant_id
                     LEFT JOIN integrations i ON i.id = r.integration_id
                    ORDER BY r.priority, r.id""")
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    return {"rules": [{k: _iso(r[k]) for k in r.keys()} for r in rows]}


@router.post("", status_code=201)
async def create_rule(form: RuleForm, request: Request,
                      session: SessionInfo = Depends(require_permission("integrations.manage", write=True))
                      ) -> dict[str, Any]:
    try:
        async with session.db() as conn:
            pattern = await _validate(conn, form)
            rid = await conn.fetchval(
                """INSERT INTO tenant_assignment_rules (tenant_id, integration_id, match_field, pattern, priority,
                                                        is_enabled)
                   VALUES ($1, $2, $3, $4, $5, $6) RETURNING id""",
                form.tenant_id, form.integration_id, form.match_field, pattern, form.priority, form.is_enabled)
            await _audit(conn, session, request, "tenant_rule.create", "tenant_rule", rid, form.tenant_id,
                         form.model_dump() | {"pattern": pattern})
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    return {"id": rid}


@router.put("/{rule_id}")
async def update_rule(rule_id: int, form: RuleForm, request: Request,
                      session: SessionInfo = Depends(require_permission("integrations.manage", write=True))
                      ) -> dict[str, Any]:
    try:
        async with session.db() as conn:
            pattern = await _validate(conn, form)
            res = await conn.execute(
                """UPDATE tenant_assignment_rules SET tenant_id = $2, integration_id = $3, match_field = $4,
                          pattern = $5, priority = $6, is_enabled = $7 WHERE id = $1""",
                rule_id, form.tenant_id, form.integration_id, form.match_field, pattern, form.priority,
                form.is_enabled)
            if res.endswith(" 0"):
                raise HTTPException(404, "Regra não encontrada.")
            await _audit(conn, session, request, "tenant_rule.update", "tenant_rule", rule_id, form.tenant_id,
                         form.model_dump() | {"pattern": pattern})
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    return {"ok": True}


@router.delete("/{rule_id}")
async def delete_rule(rule_id: int, request: Request,
                      session: SessionInfo = Depends(require_permission("integrations.manage", write=True))
                      ) -> dict[str, Any]:
    try:
        async with session.db() as conn:
            old = await conn.fetchrow("DELETE FROM tenant_assignment_rules WHERE id = $1 "
                                      "RETURNING tenant_id, match_field, pattern", rule_id)
            if old is None:
                raise HTTPException(404, "Regra não encontrada.")
            await _audit(conn, session, request, "tenant_rule.delete", "tenant_rule", rule_id, old["tenant_id"],
                         dict(old))
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    return {"ok": True}
