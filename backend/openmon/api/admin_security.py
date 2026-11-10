"""Tela Segurança: quem acessa o OpenMon, quem está bloqueado, bloquear/desbloquear IP.

Só para o Administrador Global. A API não fala com o Fail2ban (ela roda sem
privilégios): lê o estado publicado em ``/var/lib/openmon/fail2ban/status.json``
e grava pedidos em ``/var/lib/openmon/fail2ban-requests/``, que o
``openmon-fail2ban`` (root, disparado por uma unit .path) valida e aplica.
"""
from __future__ import annotations

import ipaddress
import json
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from openmon import config
from openmon.api import authlog, security
from openmon.api.auth import SessionInfo, current_session, require_csrf
from openmon.db import pool

router = APIRouter(prefix="/api/admin/security", tags=["admin"])

STALE_AFTER_S = 180
MAX_PENDING = 100
LOGIN_WINDOW_H = 24


def _admin(session: SessionInfo) -> SessionInfo:
    if session.user.get("role") != "global_admin":
        raise HTTPException(403, "Somente o Administrador Global acessa esta tela.")
    return session


def require_admin(session: SessionInfo = Depends(current_session)) -> SessionInfo:
    return _admin(session)


def require_admin_write(session: SessionInfo = Depends(require_csrf)) -> SessionInfo:
    return _admin(session)


def _read_status() -> dict[str, Any] | None:
    try:
        with (config.fail2ban_state_dir() / "status.json").open(encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _age_seconds(iso: str | None) -> float | None:
    if not iso:
        return None
    try:
        ts = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return (datetime.now(timezone.utc) - ts).total_seconds()


def _pending() -> list[dict[str, Any]]:
    out = []
    try:
        entries = sorted(config.fail2ban_requests_dir().iterdir())
    except OSError:
        return out
    for path in entries:
        if path.suffix != ".json" or path.name.startswith("."):
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            out.append({"action": data.get("action"), "ip": data.get("ip")})
        except (OSError, ValueError):
            continue
    return out


async def login_summary(hours: int = LOGIN_WINDOW_H) -> list[dict[str, Any]]:
    async with pool.system_transaction() as conn:
        rows = await conn.fetch(
            """SELECT host(client_ip) AS ip, count(*) AS attempts,
                      count(*) FILTER (WHERE success) AS successes,
                      count(*) FILTER (WHERE NOT success) AS failures,
                      max(time) AS last_attempt,
                      (array_agg(DISTINCT username))[1:5] AS usernames
                 FROM login_attempts
                WHERE time > now() - make_interval(hours => $1)
                GROUP BY client_ip
                ORDER BY max(time) DESC
                LIMIT 500""", hours)
    return [{"ip": r["ip"], "attempts": r["attempts"], "successes": r["successes"],
             "failures": r["failures"], "last_attempt": r["last_attempt"].isoformat(),
             "usernames": list(r["usernames"] or [])} for r in rows]


def merge_ips(access: list[dict[str, Any]], logins: list[dict[str, Any]],
              bans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    banned: dict[str, list[str]] = {}
    for b in bans:
        banned.setdefault(b.get("ip", ""), []).append(b.get("jail", ""))
    rows: dict[str, dict[str, Any]] = {}
    for a in access:
        rows[a["ip"]] = {**a, "attempts": 0, "successes": 0, "failures": 0, "usernames": []}
    for lg in logins:
        row = rows.setdefault(lg["ip"], {"ip": lg["ip"], "requests": 0, "errors_4xx": 0, "errors_5xx": 0,
                                         "first_seen": None, "last_seen": lg["last_attempt"],
                                         "last_request": "", "user_agent": ""})
        row.update(attempts=lg["attempts"], successes=lg["successes"], failures=lg["failures"],
                   usernames=lg["usernames"])
    for ip, row in rows.items():
        row["banned_in"] = banned.get(ip, [])
    return sorted(rows.values(), key=lambda r: (r["failures"], r["requests"]), reverse=True)


@router.get("/overview")
async def overview(request: Request, session: SessionInfo = Depends(require_admin)) -> dict[str, Any]:
    status = _read_status()
    age = _age_seconds(status.get("updated_at")) if status else None
    try:
        logins = await login_summary()
        db_error = None
    except pool.DatabaseUnavailable as exc:
        logins, db_error = [], str(exc)
    bans = (status or {}).get("bans", [])
    return {
        "bridge_ok": status is not None and age is not None and age < STALE_AFTER_S,
        "updated_at": (status or {}).get("updated_at"),
        "fail2ban_running": bool((status or {}).get("fail2ban_running")),
        "jails": (status or {}).get("jails", {}),
        "bans": bans,
        "history": (status or {}).get("history", [])[:20],
        "pending": _pending(),
        "ips": merge_ips((status or {}).get("access", []), logins, bans),
        "window_hours": LOGIN_WINDOW_H,
        "your_ip": security.client_ip(request),
        "db_error": db_error,
    }


class IpForm(BaseModel):
    ip: str = Field(min_length=2, max_length=64)
    reason: str | None = Field(default=None, max_length=200)


def _validate_ip(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise HTTPException(422, "Endereço IP inválido.") from exc
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
        raise HTTPException(422, "Esse endereço não pode ser bloqueado.")
    return str(ip)


def _enqueue(action: str, ip: str, by: str, reason: str | None) -> None:
    qdir = config.fail2ban_requests_dir()
    if not qdir.is_dir():
        raise HTTPException(503, "Fila do Fail2ban indisponível (rode o instalador de novo).")
    if len(_pending()) >= MAX_PENDING:
        raise HTTPException(429, "Muitos pedidos pendentes; aguarde o Fail2ban processar.")
    name = f"{time.time_ns()}-{secrets.token_hex(4)}.json"
    tmp = qdir / f".{name}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump({"action": action, "ip": ip, "by": by, "reason": (reason or "").strip()[:200]}, fh)
    os.replace(tmp, qdir / name)  # só aparece pronto para o .path


async def _audit(session: SessionInfo, request: Request, action: str, ip: str, reason: str | None) -> None:
    try:
        async with pool.transaction(session.user["id"], True, ()) as conn:
            await conn.execute(
                """INSERT INTO audit_log (user_id, username, client_ip, user_agent, action, object_type,
                                          object_id, details)
                   VALUES ($1, $2, $3::inet, $4, $5, 'ip', $6, jsonb_build_object('reason', $7::text))""",
                session.user["id"], session.user["username"],
                security.inet_or_none(security.client_ip(request)), security.user_agent(request),
                action, ip, reason or "")
    except pool.DatabaseUnavailable:
        pass  # o auth.log abaixo continua registrando


@router.post("/ban", status_code=202)
async def ban(form: IpForm, request: Request, session: SessionInfo = Depends(require_admin_write)) -> dict[str, Any]:
    ip = _validate_ip(form.ip)
    mine = security.inet_or_none(security.client_ip(request))
    if mine and ipaddress.ip_address(mine) == ipaddress.ip_address(ip):
        raise HTTPException(422, "Esse é o seu próprio IP: bloqueá-lo tiraria você da aplicação.")
    _enqueue("ban", ip, session.user["username"], form.reason)
    await _audit(session, request, "security.ip_ban", ip, form.reason)
    authlog.event("security.ip_ban", security.client_ip(request), username=session.user["username"], target=ip)
    return {"queued": True, "ip": ip}


@router.post("/unban", status_code=202)
async def unban(form: IpForm, request: Request,
                session: SessionInfo = Depends(require_admin_write)) -> dict[str, Any]:
    ip = _validate_ip(form.ip)
    _enqueue("unban", ip, session.user["username"], form.reason)
    await _audit(session, request, "security.ip_unban", ip, form.reason)
    authlog.event("security.ip_unban", security.client_ip(request), username=session.user["username"], target=ip)
    return {"queued": True, "ip": ip}
