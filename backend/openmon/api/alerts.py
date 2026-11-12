"""Alertas: problemas (ver e reconhecer), triggers e canais de notificação.

- Problemas: ``alerts.view`` (Cliente vê só os dos seus tenants, pelo RLS); reconhecer: ``alerts.ack``.
- Triggers, canais, fila de envio: ``alerts.manage`` (Administrador global e Operador).

Segredos dos canais (senha SMTP, token do bot do Telegram, segredo HMAC do webhook) ficam no
cofre e nunca voltam para o navegador; ao editar, campo em branco mantém o atual.
"""
from __future__ import annotations

import json
import re
import secrets
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from openmon import vault
from openmon.api.admin_tenants import _audit, _db_error, _iso
from openmon.api.auth import SessionInfo, require_permission
from openmon.db import pool
from openmon.scheduler import evaluator, notify

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

SOURCES = ("metric", "interface", "availability", "backup", "integration")
ASSET_TYPES = ("vcenter", "datacenter", "cluster", "hypervisor_host", "vm", "datastore", "network_switch", "router",
               "firewall", "storage", "physical_server", "backup_server", "backup_repository", "other")
SEVERITIES = ("info", "warning", "average", "high", "disaster")
EMAIL_RE = re.compile(r"^[^@\s<>\"',;]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,}$")
HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
HEADER_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
TOKEN_RE = re.compile(r"^\d{5,15}:[A-Za-z0-9_-]{30,64}$")
CHAT_RE = re.compile(r"^(-?\d{1,20}|@[A-Za-z0-9_]{5,64})$")
CRED_KIND = {"email": "smtp", "telegram": "telegram_bot", "webhook": "webhook"}


def _json(v: Any) -> Any:
    return json.loads(v) if isinstance(v, str) else v


# ------------------------------------------------------------------ problemas
@router.get("/problems")
async def list_problems(status: str = Query(default="open", pattern="^(open|resolved|all)$"),
                        tenant_id: int | None = None, severity: str | None = Query(default=None, max_length=20),
                        limit: int = Query(default=300, ge=1, le=2000),
                        session: SessionInfo = Depends(require_permission("alerts.view"))) -> dict[str, Any]:
    try:
        async with session.db() as conn:
            rows = await conn.fetch(
                """SELECT p.id, p.tenant_id, t.name AS tenant_name, p.trigger_id, tr.name AS trigger_name,
                          p.asset_id, a.name AS asset_name, a.asset_type, p.interface_id, f.if_name, p.severity,
                          p.status, p.opened_at, p.resolved_at, p.acknowledged_at,
                          coalesce(u.display_name, u.username) AS acknowledged_by, p.ack_comment, p.value, p.message
                     FROM alert_problems p JOIN tenants t ON t.id = p.tenant_id
                     LEFT JOIN alert_triggers tr ON tr.id = p.trigger_id
                     LEFT JOIN assets a ON a.id = p.asset_id
                     LEFT JOIN interfaces f ON f.id = p.interface_id
                     LEFT JOIN users u ON u.id = p.acknowledged_by
                    WHERE ($1 = 'all' OR ($1 = 'open') = (p.status = 'problem'))
                      AND ($2::bigint IS NULL OR p.tenant_id = $2) AND ($3::text IS NULL OR p.severity = $3)
                    ORDER BY p.status = 'problem' DESC,
                             array_position(ARRAY['disaster','high','average','warning','info'], p.severity),
                             coalesce(p.resolved_at, p.opened_at) DESC
                    LIMIT $4""", status, tenant_id, severity, limit)
            counts = await conn.fetch("SELECT severity, count(*) AS n, count(*) FILTER (WHERE acknowledged_at IS NULL) "
                                      "AS unack FROM alert_problems WHERE status = 'problem' "
                                      "AND ($1::bigint IS NULL OR tenant_id = $1) GROUP BY 1", tenant_id)
            tenants = await conn.fetch("SELECT id, name FROM tenants WHERE is_active ORDER BY is_provider DESC, "
                                       "lower(name)")
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    return {"problems": [{k: _iso(r[k]) for k in r.keys()} for r in rows],
            "counts": {r["severity"]: {"open": r["n"], "unack": r["unack"]} for r in counts},
            "tenants": [dict(t) for t in tenants], "can_ack": session.can("alerts.ack"),
            "can_manage": session.can("alerts.manage")}


class AckForm(BaseModel):
    comment: str | None = Field(default=None, max_length=500)


@router.post("/problems/{problem_id}/ack")
async def ack_problem(problem_id: int, form: AckForm, request: Request,
                      session: SessionInfo = Depends(require_permission("alerts.ack", write=True))) -> dict[str, Any]:
    try:
        async with session.db() as conn:
            row = await conn.fetchrow(
                """UPDATE alert_problems SET acknowledged_at = now(), acknowledged_by = $2, ack_comment = $3
                    WHERE id = $1 AND acknowledged_at IS NULL RETURNING tenant_id, message""",
                problem_id, session.user["id"], (form.comment or "").strip() or None)
            if row is None:
                if not await conn.fetchval("SELECT 1 FROM alert_problems WHERE id = $1", problem_id):
                    raise HTTPException(404, "Problema não encontrado.")
                raise HTTPException(409, "Este problema já foi reconhecido.")
            await _audit(conn, session, request, "alert.ack", "alert_problem", problem_id, row["tenant_id"],
                         {"message": row["message"], "comment": form.comment})
        # A fila de envio é global (o canal pode ser do NOC): enfileira fora do contexto do cliente
        async with pool.system_transaction() as conn:
            await evaluator.enqueue(conn, problem_id, "ack")
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    return {"ok": True}


# ------------------------------------------------------------------- triggers
class TriggerForm(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    tenant_id: int | None = None
    source: str = Field(pattern="^(" + "|".join(SOURCES) + ")$")
    metric_id: int | None = None
    asset_id: int | None = None
    interface_id: int | None = None
    asset_type: str | None = None
    expression: str = Field(default="avg", pattern="^(last|avg|min|max)$")
    operator: str = Field(default=">", pattern="^(>|>=|<|<=|=|<>)$")
    threshold: float = 0
    recovery_threshold: float | None = None
    window_seconds: int = Field(default=300, ge=60, le=86400)
    severity: str = Field(pattern="^(" + "|".join(SEVERITIES) + ")$")
    is_enabled: bool = True
    channel_ids: list[int] = Field(default_factory=list, max_length=50)


async def _validate_trigger(conn: Any, f: TriggerForm) -> None:
    if sum(x is not None for x in (f.asset_id, f.interface_id, f.asset_type)) > 1:
        raise HTTPException(422, "Escolha só um alvo: um ativo, uma interface ou um tipo de ativo.")
    if f.asset_type and f.asset_type not in ASSET_TYPES:
        raise HTTPException(422, "Tipo de ativo inválido.")
    if f.source == "metric":
        if f.metric_id is None or not await conn.fetchval("SELECT 1 FROM metric_definitions WHERE id = $1",
                                                          f.metric_id):
            raise HTTPException(422, "Escolha a métrica.")
    elif f.metric_id is not None:
        raise HTTPException(422, "Métrica só vale para alertas de métrica.")
    if f.interface_id is not None and f.source != "interface":
        raise HTTPException(422, "Interface só vale para alertas de uso de interface.")
    if f.source in ("backup", "integration") and (f.asset_type or f.interface_id):
        raise HTTPException(422, "Este tipo de alerta não usa tipo de ativo nem interface.")
    if f.tenant_id is not None and not await conn.fetchval("SELECT 1 FROM tenants WHERE id = $1", f.tenant_id):
        raise HTTPException(422, "Tenant inexistente.")
    if f.asset_id is not None and not await conn.fetchval("SELECT 1 FROM assets WHERE id = $1", f.asset_id):
        raise HTTPException(422, "Ativo inexistente.")
    if f.interface_id is not None and not await conn.fetchval("SELECT 1 FROM interfaces WHERE id = $1",
                                                              f.interface_id):
        raise HTTPException(422, "Interface inexistente.")
    if f.channel_ids:
        found = await conn.fetch("SELECT id, tenant_id FROM notification_channels WHERE id = ANY($1::bigint[])",
                                 f.channel_ids)
        if len(found) != len(set(f.channel_ids)):
            raise HTTPException(422, "Canal de notificação inexistente.")
        if f.tenant_id is not None and any(c["tenant_id"] not in (None, f.tenant_id) for c in found):
            raise HTTPException(422, "Um canal de outro cliente não pode receber os alertas deste tenant.")


_TRIGGER_SELECT = """
SELECT tr.*, t.name AS tenant_name, a.name AS asset_name, f.if_name AS interface_name, m.name AS metric_name,
       m.unit AS metric_unit,
       coalesce((SELECT array_agg(channel_id ORDER BY channel_id) FROM alert_trigger_channels
                  WHERE trigger_id = tr.id), '{}') AS channel_ids,
       (SELECT count(*) FROM alert_problems p WHERE p.trigger_id = tr.id AND p.status = 'problem') AS open_problems
  FROM alert_triggers tr LEFT JOIN tenants t ON t.id = tr.tenant_id
  LEFT JOIN assets a ON a.id = tr.asset_id LEFT JOIN interfaces f ON f.id = tr.interface_id
  LEFT JOIN metric_definitions m ON m.id = tr.metric_id
"""


@router.get("/triggers")
async def list_triggers(session: SessionInfo = Depends(require_permission("alerts.manage"))) -> dict[str, Any]:
    try:
        async with session.db() as conn:
            rows = await conn.fetch(_TRIGGER_SELECT + " ORDER BY tr.is_enabled DESC, lower(tr.name)")
            metrics = await conn.fetch("SELECT id, key, name, unit, category FROM metric_definitions ORDER BY id")
            tenants = await conn.fetch("SELECT id, name, is_provider FROM tenants WHERE is_active "
                                       "ORDER BY is_provider DESC, lower(name)")
            channels = await conn.fetch("SELECT c.id, c.name, c.kind, c.tenant_id, t.name AS tenant_name "
                                        "FROM notification_channels c LEFT JOIN tenants t ON t.id = c.tenant_id "
                                        "ORDER BY lower(c.name)")
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    return {"triggers": [{k: _iso(r[k]) for k in r.keys()} for r in rows], "metrics": [dict(m) for m in metrics],
            "tenants": [dict(t) for t in tenants], "channels": [dict(c) for c in channels],
            "asset_types": list(ASSET_TYPES)}


async def _set_channels(conn: Any, trigger_id: int, ids: list[int]) -> None:
    await conn.execute("DELETE FROM alert_trigger_channels WHERE trigger_id = $1", trigger_id)
    if ids:
        await conn.execute("INSERT INTO alert_trigger_channels (trigger_id, channel_id) "
                           "SELECT $1, unnest($2::bigint[])", trigger_id, sorted(set(ids)))


_TRIGGER_COLS = ("tenant_id", "name", "asset_id", "interface_id", "asset_type", "source", "metric_id", "expression",
                 "operator", "threshold", "recovery_threshold", "window_seconds", "severity", "is_enabled")


@router.post("/triggers", status_code=201)
async def create_trigger(form: TriggerForm, request: Request,
                         session: SessionInfo = Depends(require_permission("alerts.manage", write=True))
                         ) -> dict[str, Any]:
    try:
        async with session.db() as conn:
            await _validate_trigger(conn, form)
            vals = [getattr(form, c) for c in _TRIGGER_COLS]
            tid = await conn.fetchval(
                f"INSERT INTO alert_triggers ({', '.join(_TRIGGER_COLS)}, created_by) "
                f"VALUES ({', '.join(f'${i}' for i in range(1, len(vals) + 2))}) RETURNING id",
                *vals, session.user["id"])
            await _set_channels(conn, tid, form.channel_ids)
            await _audit(conn, session, request, "trigger.create", "alert_trigger", tid, form.tenant_id,
                         form.model_dump())
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    return {"id": tid}


@router.put("/triggers/{trigger_id}")
async def update_trigger(trigger_id: int, form: TriggerForm, request: Request,
                         session: SessionInfo = Depends(require_permission("alerts.manage", write=True))
                         ) -> dict[str, Any]:
    try:
        async with session.db() as conn:
            if not await conn.fetchval("SELECT 1 FROM alert_triggers WHERE id = $1", trigger_id):
                raise HTTPException(404, "Alerta não encontrado.")
            await _validate_trigger(conn, form)
            sets = ", ".join(f"{c} = ${i + 2}" for i, c in enumerate(_TRIGGER_COLS))
            await conn.execute(f"UPDATE alert_triggers SET {sets}, updated_at = now() WHERE id = $1", trigger_id,
                               *[getattr(form, c) for c in _TRIGGER_COLS])
            await _set_channels(conn, trigger_id, form.channel_ids)
            if not form.is_enabled:
                await _close_problems(conn, trigger_id)
            await _audit(conn, session, request, "trigger.update", "alert_trigger", trigger_id, form.tenant_id,
                         form.model_dump())
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    return {"ok": True}


async def _close_problems(conn: Any, trigger_id: int) -> None:
    """Alerta desligado/excluído: os problemas abertos dele fecham (sem notificar)."""
    await conn.execute("UPDATE alert_problems SET status = 'resolved', resolved_at = now() "
                       "WHERE trigger_id = $1 AND status = 'problem'", trigger_id)


@router.delete("/triggers/{trigger_id}")
async def delete_trigger(trigger_id: int, request: Request,
                         session: SessionInfo = Depends(require_permission("alerts.manage", write=True))
                         ) -> dict[str, Any]:
    try:
        async with session.db() as conn:
            old = await conn.fetchrow("SELECT name, tenant_id FROM alert_triggers WHERE id = $1", trigger_id)
            if old is None:
                raise HTTPException(404, "Alerta não encontrado.")
            await _close_problems(conn, trigger_id)
            await conn.execute("DELETE FROM alert_triggers WHERE id = $1", trigger_id)
            await _audit(conn, session, request, "trigger.delete", "alert_trigger", trigger_id, old["tenant_id"],
                         {"name": old["name"]})
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    return {"ok": True}


RECOMMENDED = [
    {"name": "Equipamento, host ou VM fora do ar", "source": "availability", "operator": "<", "threshold": 1,
     "window_seconds": 120, "severity": "high"},
    {"name": "CPU acima de 90%", "source": "metric", "metric_id": 1, "expression": "avg", "operator": ">",
     "threshold": 90, "recovery_threshold": 80, "window_seconds": 900, "severity": "warning"},
    {"name": "Memória acima de 95%", "source": "metric", "metric_id": 10, "expression": "avg", "operator": ">",
     "threshold": 95, "recovery_threshold": 90, "window_seconds": 900, "severity": "warning"},
    {"name": "Datastore ou repositório acima de 90%", "source": "metric", "metric_id": 52, "expression": "last",
     "operator": ">", "threshold": 90, "recovery_threshold": 85, "window_seconds": 900, "severity": "average"},
    # Ligados de fábrica pela migration 0007 (mesmos limites da tela VMs); ficam aqui para recriar se apagados
    {"name": "Volume de disco da VM acima de 90%", "source": "metric", "metric_id": 62, "asset_type": "vm",
     "expression": "last", "operator": ">=", "threshold": 90, "recovery_threshold": 85, "window_seconds": 300,
     "severity": "average"},
    {"name": "Volume de disco da VM acima de 97%", "source": "metric", "metric_id": 62, "asset_type": "vm",
     "expression": "last", "operator": ">=", "threshold": 97, "recovery_threshold": 95, "window_seconds": 300,
     "severity": "high"},
    {"name": "Link acima de 90% da banda", "source": "interface", "expression": "avg", "operator": ">",
     "threshold": 90, "recovery_threshold": 80, "window_seconds": 300, "severity": "average"},
    {"name": "Backup com falha ou fora do SLA", "source": "backup", "operator": ">", "threshold": 0,
     "window_seconds": 300, "severity": "high"},
    {"name": "Integração com erro de coleta", "source": "integration", "operator": ">", "threshold": 0,
     "window_seconds": 300, "severity": "average"},
]


@router.post("/triggers/recommended")
async def create_recommended(request: Request,
                             session: SessionInfo = Depends(require_permission("alerts.manage", write=True))
                             ) -> dict[str, Any]:
    """Cria os alertas recomendados que ainda não existem (pelo nome), para todos os tenants."""
    created = []
    try:
        async with session.db() as conn:
            for r in RECOMMENDED:
                if await conn.fetchval("SELECT 1 FROM alert_triggers WHERE tenant_id IS NULL AND name = $1",
                                       r["name"]):
                    continue
                f = TriggerForm(**r)
                vals = [getattr(f, c) for c in _TRIGGER_COLS]
                tid = await conn.fetchval(
                    f"INSERT INTO alert_triggers ({', '.join(_TRIGGER_COLS)}, created_by) "
                    f"VALUES ({', '.join(f'${i}' for i in range(1, len(vals) + 2))}) RETURNING id",
                    *vals, session.user["id"])
                created.append(r["name"])
            if created:
                await _audit(conn, session, request, "trigger.recommended", "alert_trigger", "-", None,
                             {"created": created})
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    return {"created": created}


# -------------------------------------------------------------------- canais
class ChannelForm(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    kind: str = Field(pattern="^(email|telegram|webhook)$")
    tenant_id: int | None = None
    is_enabled: bool = True
    config: dict[str, Any] = Field(default_factory=dict)
    username: str | None = Field(default=None, max_length=256)   # usuário SMTP
    secret: str | None = Field(default=None, max_length=4096)     # senha SMTP, token do bot, segredo HMAC


class ChannelTestForm(ChannelForm):
    channel_id: int | None = None


def _clean_config(f: ChannelForm) -> dict[str, Any]:
    c = f.config or {}
    if f.kind == "email":
        host = str(c.get("host") or "").strip()
        if not HOST_RE.match(host):
            raise HTTPException(422, "Servidor SMTP inválido.")
        security = c.get("security") or "starttls"
        if security not in ("starttls", "tls"):
            raise HTTPException(422, "Segurança SMTP deve ser STARTTLS ou TLS (sem texto aberto).")
        try:
            port = int(c.get("port") or (465 if security == "tls" else 587))
        except (TypeError, ValueError) as exc:
            raise HTTPException(422, "Porta SMTP inválida.") from exc
        sender = str(c.get("from") or "").strip()
        to = [str(x).strip() for x in (c.get("to") or []) if str(x).strip()]
        if not EMAIL_RE.match(sender):
            raise HTTPException(422, "Remetente inválido.")
        if not to or len(to) > 20 or not all(EMAIL_RE.match(x) for x in to):
            raise HTTPException(422, "Informe de 1 a 20 destinatários válidos.")
        if not 1 <= port <= 65535:
            raise HTTPException(422, "Porta SMTP inválida.")
        return {"host": host, "port": port, "security": security, "from": sender, "to": to}
    if f.kind == "telegram":
        chat = str(c.get("chat_id") or "").strip()
        if not CHAT_RE.match(chat):
            raise HTTPException(422, "Chat ID inválido (número, -100… para grupos, ou @canal).")
        return {"chat_id": chat}
    url = str(c.get("url") or "").strip()
    if not re.match(r"^https://[^\s/$.?#][^\s]{1,2000}$", url):
        raise HTTPException(422, "A URL do webhook precisa começar com https://.")
    method = (c.get("method") or "POST").upper()
    if method not in ("POST", "PUT"):
        raise HTTPException(422, "Método do webhook: POST ou PUT.")
    headers = {}
    for k, v in (c.get("headers") or {}).items():
        if not HEADER_RE.match(str(k)) or any(ch in str(v) for ch in "\r\n") or len(str(v)) > 1000:
            raise HTTPException(422, f"Cabeçalho inválido: {k}")
        if str(k).lower() in ("content-type", "content-length", "host", "x-openmon-signature", "x-openmon-timestamp"):
            raise HTTPException(422, f"O cabeçalho {k} é definido pelo OpenMon.")
        headers[str(k)] = str(v)
    if len(headers) > 10:
        raise HTTPException(422, "No máximo 10 cabeçalhos.")
    return {"url": url, "method": method, "headers": headers}


def _check_secret(f: ChannelForm, has_old: bool) -> None:
    if f.kind == "telegram" and not f.secret and not has_old:
        raise HTTPException(422, "Informe o token do bot.")
    if f.kind == "telegram" and f.secret and not TOKEN_RE.match(f.secret.strip()):
        raise HTTPException(422, "Token do bot inválido (formato 123456:ABC…, do @BotFather).")
    if f.kind == "email" and f.username and not f.secret and not has_old:
        raise HTTPException(422, "Informe a senha do usuário SMTP.")


_CHANNEL_SELECT = """
SELECT c.id, c.name, c.kind, c.tenant_id, t.name AS tenant_name, c.config, c.is_enabled, c.last_test_at,
       c.last_test_ok, c.credential_id::text AS cred_id, cr.username,
       (SELECT count(*) FROM alert_trigger_channels x WHERE x.channel_id = c.id) AS triggers,
       (SELECT count(*) FROM notification_deliveries d WHERE d.channel_id = c.id AND d.status = 'failed'
           AND d.created_at > now() - interval '7 days') AS failed_7d
  FROM notification_channels c LEFT JOIN tenants t ON t.id = c.tenant_id
  LEFT JOIN credentials cr ON cr.id = c.credential_id
"""


def _channel_out(r: Any) -> dict[str, Any]:
    return {"id": r["id"], "name": r["name"], "kind": r["kind"], "tenant_id": r["tenant_id"],
            "tenant_name": r["tenant_name"], "config": _json(r["config"]), "is_enabled": r["is_enabled"],
            "last_test_at": _iso(r["last_test_at"]), "last_test_ok": r["last_test_ok"],
            "has_secret": bool(r["cred_id"]), "username": r["username"] or "", "triggers": r["triggers"],
            "failed_7d": r["failed_7d"]}


@router.get("/channels")
async def list_channels(session: SessionInfo = Depends(require_permission("alerts.manage"))) -> dict[str, Any]:
    try:
        async with session.db() as conn:
            rows = await conn.fetch(_CHANNEL_SELECT + " ORDER BY lower(c.name)")
            tenants = await conn.fetch("SELECT id, name, is_provider FROM tenants WHERE is_active "
                                       "ORDER BY is_provider DESC, lower(name)")
            deliveries = await conn.fetch(
                """SELECT d.id, d.event, d.status, d.attempts, d.last_error, d.created_at, d.sent_at,
                          c.name AS channel_name, p.message
                     FROM notification_deliveries d LEFT JOIN notification_channels c ON c.id = d.channel_id
                     LEFT JOIN alert_problems p ON p.id = d.problem_id
                    ORDER BY d.created_at DESC LIMIT 50""")
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    return {"channels": [_channel_out(r) for r in rows], "tenants": [dict(t) for t in tenants],
            "deliveries": [{k: _iso(r[k]) for k in r.keys()} for r in deliveries]}


async def _save_secret(conn: Any, session: SessionInfo, f: ChannelForm, cred_id: str | None) -> str | None:
    username = (f.username or "").strip() or None if f.kind == "email" else None
    if f.secret:
        return await vault.save(conn, kind=CRED_KIND[f.kind], name=f"channel:{secrets.token_hex(8)}" if not cred_id
                                else await conn.fetchval("SELECT name FROM credentials WHERE id = $1::uuid", cred_id),
                                secret=f.secret.strip() if f.kind == "telegram" else f.secret, username=username,
                                created_by=session.user["id"], cred_id=cred_id)
    if cred_id:
        if f.kind == "email" and not username:  # tirou o usuário: SMTP sem autenticação
            await conn.execute("DELETE FROM credentials WHERE id = $1::uuid", cred_id)
            return None
        await vault.set_username(conn, cred_id, username)
    return cred_id


@router.post("/channels", status_code=201)
async def create_channel(form: ChannelForm, request: Request,
                         session: SessionInfo = Depends(require_permission("alerts.manage", write=True))
                         ) -> dict[str, Any]:
    cfg = _clean_config(form)
    _check_secret(form, False)
    try:
        async with session.db() as conn:
            if form.tenant_id is not None and not await conn.fetchval("SELECT 1 FROM tenants WHERE id = $1",
                                                                      form.tenant_id):
                raise HTTPException(422, "Tenant inexistente.")
            if await conn.fetchval("SELECT 1 FROM notification_channels WHERE tenant_id IS NOT DISTINCT FROM $1 "
                                   "AND lower(name) = lower($2)", form.tenant_id, form.name.strip()):
                raise HTTPException(409, "Já existe um canal com esse nome.")
            cid = await _save_secret(conn, session, form, None)
            ch = await conn.fetchval(
                """INSERT INTO notification_channels (tenant_id, kind, name, config, credential_id, is_enabled)
                   VALUES ($1, $2, $3, $4::jsonb, $5::uuid, $6) RETURNING id""",
                form.tenant_id, form.kind, form.name.strip(), json.dumps(cfg), cid, form.is_enabled)
            await _audit(conn, session, request, "channel.create", "notification_channel", ch, form.tenant_id,
                         {"name": form.name, "kind": form.kind, "config": cfg})
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    except vault.VaultError as exc:
        raise HTTPException(500, f"Cofre de credenciais: {exc}") from exc
    return {"id": ch}


@router.put("/channels/{channel_id}")
async def update_channel(channel_id: int, form: ChannelForm, request: Request,
                         session: SessionInfo = Depends(require_permission("alerts.manage", write=True))
                         ) -> dict[str, Any]:
    cfg = _clean_config(form)
    try:
        async with session.db() as conn:
            old = await conn.fetchrow("SELECT kind, credential_id::text AS cred_id FROM notification_channels "
                                      "WHERE id = $1", channel_id)
            if old is None:
                raise HTTPException(404, "Canal não encontrado.")
            if old["kind"] != form.kind:
                raise HTTPException(422, "O tipo do canal não pode mudar; crie outro.")
            _check_secret(form, bool(old["cred_id"]))
            if form.tenant_id is not None and not await conn.fetchval("SELECT 1 FROM tenants WHERE id = $1",
                                                                      form.tenant_id):
                raise HTTPException(422, "Tenant inexistente.")
            if form.tenant_id is not None and await conn.fetchval(
                    """SELECT 1 FROM alert_trigger_channels x JOIN alert_triggers t ON t.id = x.trigger_id
                        WHERE x.channel_id = $1 AND t.tenant_id IS NOT NULL AND t.tenant_id <> $2""",
                    channel_id, form.tenant_id):
                raise HTTPException(422, "Este canal recebe alertas de outro cliente; tire-o desses alertas antes.")
            cid = await _save_secret(conn, session, form, old["cred_id"])
            await conn.execute(
                """UPDATE notification_channels SET tenant_id = $2, name = $3, config = $4::jsonb,
                          credential_id = $5::uuid, is_enabled = $6, updated_at = now() WHERE id = $1""",
                channel_id, form.tenant_id, form.name.strip(), json.dumps(cfg), cid, form.is_enabled)
            await _audit(conn, session, request, "channel.update", "notification_channel", channel_id, form.tenant_id,
                         {"name": form.name, "config": cfg, "secret_changed": bool(form.secret)})
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    except vault.VaultError as exc:
        raise HTTPException(500, f"Cofre de credenciais: {exc}") from exc
    return {"ok": True}


@router.delete("/channels/{channel_id}")
async def delete_channel(channel_id: int, request: Request,
                         session: SessionInfo = Depends(require_permission("alerts.manage", write=True))
                         ) -> dict[str, Any]:
    try:
        async with session.db() as conn:
            old = await conn.fetchrow("DELETE FROM notification_channels WHERE id = $1 "
                                      "RETURNING name, tenant_id, credential_id::text AS cred_id", channel_id)
            if old is None:
                raise HTTPException(404, "Canal não encontrado.")
            if old["cred_id"]:
                await conn.execute("DELETE FROM credentials WHERE id = $1::uuid", old["cred_id"])
            await _audit(conn, session, request, "channel.delete", "notification_channel", channel_id,
                         old["tenant_id"], {"name": old["name"]})
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    return {"ok": True}


@router.post("/channels/test")
async def test_channel(form: ChannelTestForm, request: Request,
                       session: SessionInfo = Depends(require_permission("alerts.manage", write=True))
                       ) -> dict[str, Any]:
    """Manda uma mensagem de teste agora (com o que está no formulário; segredo em branco = o salvo)."""
    cfg = _clean_config(form)
    username = (form.username or "").strip() or None
    secret = form.secret.strip() if form.secret and form.kind == "telegram" else form.secret
    try:
        async with session.db() as conn:
            if form.channel_id and not form.secret:
                cid = await conn.fetchval("SELECT credential_id::text FROM notification_channels WHERE id = $1",
                                          form.channel_id)
                if cid:
                    _, secret = await vault.load(conn, cid)
            _check_secret(form.model_copy(update={"secret": secret}), False)
            await _audit(conn, session, request, "channel.test", "notification_channel", form.channel_id or "-",
                         form.tenant_id, {"kind": form.kind, "name": form.name})
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    except vault.VaultError as exc:
        raise HTTPException(500, f"Cofre de credenciais: {exc}") from exc
    sample = {"id": 0, "severity": "info", "message": f"Teste do canal \"{form.name}\" pelo OpenMon",
              "trigger_name": "Teste", "tenant_name": "—", "opened_at": datetime.now(timezone.utc),
              "asset_name": None}
    ok, error = True, None
    try:
        await notify.send({"kind": form.kind, "config": cfg}, username if form.kind == "email" else None, secret,
                          "test", sample)
    except notify.SendError as exc:
        ok, error = False, str(exc)
    except Exception as exc:  # noqa: BLE001
        ok, error = False, f"{type(exc).__name__}: {str(exc)[:200]}"
    if form.channel_id:
        try:
            async with session.db() as conn:
                await conn.execute("UPDATE notification_channels SET last_test_at = now(), last_test_ok = $2 "
                                   "WHERE id = $1", form.channel_id, ok)
        except pool.DatabaseUnavailable:
            pass
    return {"ok": ok, "error": error}
