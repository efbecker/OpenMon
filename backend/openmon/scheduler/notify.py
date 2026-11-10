"""Envio das notificações: e-mail (SMTP com TLS ou STARTTLS), Telegram e webhook (JSON assinado com HMAC).

A fila é ``notification_deliveries``: cada entrega tenta até 5 vezes, com espera crescente
(1, 4, 9, 16 min). Segredos (senha SMTP, token do bot, segredo do webhook) vêm do cofre.
O texto nunca é interpretado como HTML/Markdown no destino (sem ``parse_mode`` no Telegram,
e-mail só texto), então o nome de um ativo não injeta nada na mensagem.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import smtplib
import ssl
import time
from datetime import datetime
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Any

import httpx

from openmon import vault

MAX_ATTEMPTS = 5
SEVERITY = {"info": "Informação", "warning": "Atenção", "average": "Média", "high": "Alta", "disaster": "Desastre"}
EVENT = {"problem": "PROBLEMA", "recovery": "RESOLVIDO", "ack": "RECONHECIDO", "test": "TESTE"}
TELEGRAM_API = "https://api.telegram.org"

# Testes trocam por um httpx.MockTransport / um SMTP falso
_transport: httpx.AsyncBaseTransport | None = None
_smtp_factory: Any = None


class SendError(RuntimeError):
    pass


def _local(v: Any) -> str | None:
    """Data no fuso do Servidor 1 (o do Debian), no formato brasileiro."""
    if not isinstance(v, datetime):
        return v
    return v.astimezone().strftime("%d/%m/%Y %H:%M")


def render(event: str, p: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
    """(assunto, texto, payload JSON) de um evento."""
    iso = {k: p[k].isoformat() if isinstance(p.get(k), datetime) else p.get(k) for k in ("opened_at", "resolved_at")}
    p = {**p, "opened_at": _local(p.get("opened_at")), "resolved_at": _local(p.get("resolved_at"))}
    sev = SEVERITY.get(p.get("severity") or "", p.get("severity") or "")
    subject = f"[OpenMon] {EVENT[event]} [{sev}] {p.get('message', '')}"[:200]
    lines = [f"{EVENT[event]}: {p.get('message', '')}", "",
             f"Severidade: {sev}", f"Alerta: {p.get('trigger_name') or '—'}",
             f"Cliente: {p.get('tenant_name') or '—'}"]
    if p.get("asset_name"):
        lines.append(f"Ativo: {p['asset_name']}")
    lines.append(f"Início: {p.get('opened_at') or '—'}")
    if event == "recovery" and p.get("resolved_at"):
        lines.append(f"Resolvido: {p['resolved_at']}")
    if event == "ack":
        lines.append(f"Reconhecido por: {p.get('ack_by') or '—'}" + (f" ({p['ack_comment']})" if p.get("ack_comment")
                                                                     else ""))
    payload = {"event": event, "problem_id": p.get("id"), "severity": p.get("severity"), "message": p.get("message"),
               "trigger": p.get("trigger_name"), "tenant": p.get("tenant_name"), "tenant_id": p.get("tenant_id"),
               "asset": p.get("asset_name"), "asset_id": p.get("asset_id"), "value": p.get("value"),
               "opened_at": iso["opened_at"], "resolved_at": iso["resolved_at"],
               "acknowledged_by": p.get("ack_by"), "comment": p.get("ack_comment")}
    return subject, "\n".join(lines), payload


async def send(channel: dict[str, Any], username: str | None, secret: str | None, event: str,
               p: dict[str, Any]) -> None:
    subject, text, payload = render(event, p)
    kind = channel["kind"]
    cfg = channel["config"]
    if kind == "email":
        await asyncio.to_thread(_send_email, cfg, username, secret, subject, text)
    elif kind == "telegram":
        await _send_telegram(cfg, secret, text)
    elif kind == "webhook":
        await _send_webhook(cfg, secret, payload)
    else:
        raise SendError(f"tipo de canal desconhecido: {kind}")


def _send_email(cfg: dict[str, Any], username: str | None, password: str | None, subject: str, text: str) -> None:
    msg = EmailMessage()
    msg["From"] = cfg["from"]
    msg["To"] = ", ".join(cfg["to"])
    msg["Subject"] = subject.replace("\n", " ").replace("\r", " ")
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=cfg["from"].split("@")[-1].strip("> ") or "openmon")
    msg.set_content(text)
    ctx = ssl.create_default_context()
    host, port, security = cfg["host"], int(cfg.get("port") or 587), cfg.get("security") or "starttls"
    factory = _smtp_factory
    try:
        if security == "tls":
            smtp = (factory or smtplib.SMTP_SSL)(host, port, timeout=20, context=ctx)
        else:
            smtp = (factory or smtplib.SMTP)(host, port, timeout=20)
        with smtp:
            if security != "tls":
                smtp.ehlo()
                smtp.starttls(context=ctx)  # obrigatório: sem STARTTLS não manda nada
                smtp.ehlo()
            if username:
                smtp.login(username, password or "")
            smtp.send_message(msg)
    except smtplib.SMTPAuthenticationError as exc:
        raise SendError("SMTP recusou o usuário/senha") from exc
    except smtplib.SMTPNotSupportedError as exc:
        raise SendError("o servidor SMTP não oferece STARTTLS; use TLS direto (porta 465)") from exc
    except ssl.SSLCertVerificationError as exc:
        raise SendError(f"certificado do servidor SMTP não confiável ({exc.verify_message})") from exc
    except smtplib.SMTPRecipientsRefused as exc:
        raise SendError("o servidor SMTP recusou os destinatários") from exc
    except (smtplib.SMTPException, OSError) as exc:
        raise SendError(f"SMTP {host}:{port}: {type(exc).__name__}: {str(exc)[:200]}") from exc


async def _send_telegram(cfg: dict[str, Any], token: str | None, text: str) -> None:
    if not token:
        raise SendError("token do bot ausente")
    async with httpx.AsyncClient(timeout=20.0, transport=_transport) as client:
        try:
            r = await client.post(f"{TELEGRAM_API}/bot{token}/sendMessage",
                                  json={"chat_id": cfg["chat_id"], "text": text[:4000],
                                        "disable_web_page_preview": True})
        except httpx.HTTPError as exc:
            raise SendError(f"Telegram: {type(exc).__name__}") from exc  # sem a URL: ela contém o token
    if r.status_code != 200:
        try:
            desc = r.json().get("description", "")
        except ValueError:
            desc = ""
        raise SendError(f"Telegram HTTP {r.status_code}: {desc[:200]}")


async def _send_webhook(cfg: dict[str, Any], secret: str | None, payload: dict[str, Any]) -> None:
    body = json.dumps(payload, ensure_ascii=False, default=str).encode()
    ts = str(int(time.time()))
    headers = {"Content-Type": "application/json", "User-Agent": "OpenMon-Webhook/1"}
    headers.update({k: str(v) for k, v in (cfg.get("headers") or {}).items()})
    if secret:
        sig = hmac.new(secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
        headers["X-OpenMon-Timestamp"] = ts
        headers["X-OpenMon-Signature"] = f"sha256={sig}"
    async with httpx.AsyncClient(timeout=20.0, transport=_transport, follow_redirects=False) as client:
        try:
            r = await client.request(cfg.get("method") or "POST", cfg["url"], content=body, headers=headers)
        except httpx.HTTPError as exc:
            raise SendError(f"webhook: {type(exc).__name__}: {str(exc)[:200]}") from exc
    if r.status_code >= 300:
        raise SendError(f"webhook HTTP {r.status_code}: {r.text[:200]}")


PROBLEM_SQL = """
SELECT p.id, p.tenant_id, t.name AS tenant_name, p.severity, p.message, p.value, p.asset_id, a.name AS asset_name,
       p.opened_at, p.resolved_at,
       tr.name AS trigger_name, coalesce(u.display_name, u.username) AS ack_by, p.ack_comment
  FROM alert_problems p JOIN tenants t ON t.id = p.tenant_id
  LEFT JOIN assets a ON a.id = p.asset_id LEFT JOIN alert_triggers tr ON tr.id = p.trigger_id
  LEFT JOIN users u ON u.id = p.acknowledged_by
 WHERE p.id = $1
"""


async def channel_secret(conn: Any, channel: Any) -> tuple[str | None, str | None]:
    if not channel["credential_id"]:
        return None, None
    return await vault.load(conn, str(channel["credential_id"]))


def _cfg(v: Any) -> dict[str, Any]:
    return json.loads(v) if isinstance(v, str) else dict(v or {})


async def deliver_pending(conn_factory: Any, limit: int = 50) -> dict[str, int]:
    """Envia o que está na fila. ``conn_factory`` abre uma transação global (pool.system_transaction)."""
    stats = {"sent": 0, "failed": 0, "retry": 0}
    async with conn_factory() as conn:
        rows = await conn.fetch(
            """SELECT d.id, d.problem_id, d.event, d.attempts, c.id AS channel_id, c.kind, c.name, c.config,
                      c.credential_id, c.is_enabled
                 FROM notification_deliveries d JOIN notification_channels c ON c.id = d.channel_id
                WHERE d.status = 'queued'
                  AND d.created_at + make_interval(mins => d.attempts * d.attempts) <= now()
                ORDER BY d.created_at LIMIT $1 FOR UPDATE OF d SKIP LOCKED""", limit)
        jobs = []
        for d in rows:
            if not d["is_enabled"]:
                await conn.execute("UPDATE notification_deliveries SET status = 'failed', last_error = $2 "
                                   "WHERE id = $1", d["id"], "canal desabilitado")
                continue
            p = await conn.fetchrow(PROBLEM_SQL, d["problem_id"])
            try:
                user, secret = await channel_secret(conn, d)
            except vault.VaultError as exc:
                user, secret = None, None
                await _mark(conn, d, f"cofre: {exc}")
                stats["failed"] += 1
                continue
            jobs.append((d, dict(p) if p else {}, user, secret))
        # Envia em paralelo, ainda com as linhas travadas (outro agendador não manda em dobro)
        results = await asyncio.gather(*(send({"kind": d["kind"], "config": _cfg(d["config"])}, u, s, d["event"], p)
                                         for d, p, u, s in jobs), return_exceptions=True)
        for (d, _p, _u, _s), res in zip(jobs, results):
            if isinstance(res, BaseException):
                err = str(res) if isinstance(res, SendError) else f"{type(res).__name__}: {str(res)[:200]}"
                final = await _mark(conn, d, err)
                stats["failed" if final else "retry"] += 1
            else:
                await conn.execute("UPDATE notification_deliveries SET status = 'sent', sent_at = now(), "
                                   "attempts = attempts + 1, last_error = NULL WHERE id = $1", d["id"])
                stats["sent"] += 1
    return stats


async def _mark(conn: Any, d: Any, err: str) -> bool:
    final = d["attempts"] + 1 >= MAX_ATTEMPTS
    await conn.execute("UPDATE notification_deliveries SET attempts = attempts + 1, last_error = $2, "
                       "status = CASE WHEN $3 THEN 'failed' ELSE 'queued' END WHERE id = $1", d["id"], err[:1000],
                       final)
    return final
