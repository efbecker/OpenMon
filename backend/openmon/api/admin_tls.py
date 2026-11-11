"""Tela "Domínio & HTTPS": certificado digital do domínio no Apache da VM 1.

Só quem tem ``system.settings`` (Administrador Global). A API valida os arquivos
(``openmon.tlscert``), guarda no banco (certificado nos parâmetros, chave privada
cifrada no cofre AES-256-GCM, credencial ``tls:https``) e grava um pedido em
``/var/lib/openmon/tls-requests/``; quem mexe no Apache é o ``openmon-tls``
(root). Como fica no banco, o certificado volta sozinho numa reinstalação da
VM 1 que use o mesmo banco: ver ``reapply_if_missing``.
"""
from __future__ import annotations

import json
import logging
import os
import secrets
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from openmon import config, tlscert, vault
from openmon.api.admin_tenants import _audit, _db_error
from openmon.api.auth import SessionInfo, require_permission
from openmon.db import pool

router = APIRouter(prefix="/api/admin/tls", tags=["admin"])
log = logging.getLogger("openmon.api")
CRED_NAME = "tls:https"


class CertForm(BaseModel):
    domain: str = Field(min_length=3, max_length=253)
    certificate: str = Field(min_length=1, max_length=tlscert.MAX_PEM)
    private_key: str | None = Field(default=None, max_length=tlscert.MAX_PEM)
    chain: str | None = Field(default=None, max_length=tlscert.MAX_PEM)


def _status() -> dict[str, Any] | None:
    try:
        with (config.tls_state_dir() / "status.json").open(encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _pending() -> bool:
    return (config.tls_requests_dir() / "request.json").exists()


def _enqueue(req: dict[str, Any]) -> str:
    """Grava o pedido (0600, só o usuário openmon lê) para o openmon-tls (root)."""
    qdir = config.tls_requests_dir()
    qdir.mkdir(parents=True, exist_ok=True)
    rid = secrets.token_hex(8)
    tmp = qdir / f".request.{rid}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump({**req, "id": rid}, fh)
    os.replace(tmp, qdir / "request.json")
    return rid


async def _stored(conn: Any) -> Any:
    return await conn.fetchrow(
        "SELECT id::text AS id, username AS domain, params, updated_at FROM credentials WHERE name = $1 "
        "AND tenant_id IS NULL", CRED_NAME)


def _params(row: Any) -> dict[str, Any]:
    p = row["params"]
    return json.loads(p) if isinstance(p, str) else dict(p or {})


@router.get("")
async def get_tls(session: SessionInfo = Depends(require_permission("system.settings"))) -> dict[str, Any]:
    try:
        async with session.db() as conn:
            row = await _stored(conn)
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    stored = None
    if row:
        p = _params(row)
        stored = {"domain": row["domain"], "info": tlscert.info_from_pem(p.get("fullchain") or ""),
                  "uploaded_by": p.get("uploaded_by"), "uploaded_at": p.get("uploaded_at")}
    return {"status": _status(), "stored": stored, "pending": _pending()}


@router.post("")
async def upload(form: CertForm, request: Request,
                 session: SessionInfo = Depends(require_permission("system.settings", write=True))
                 ) -> dict[str, Any]:
    key = form.private_key or ""
    try:
        async with session.db() as conn:
            row = await _stored(conn)
            if not key.strip() and row:
                # Trocar só o certificado (renovação com a mesma chave): usa a chave guardada no cofre
                _, key = await vault.load(conn, row["id"])
            try:
                v = tlscert.validate(form.domain, form.certificate, key, form.chain or "")
            except tlscert.CertError as exc:
                raise HTTPException(422, str(exc)) from exc
            params = {"purpose": "https", "fullchain": v["fullchain"], "uploaded_by": session.user["username"],
                      "uploaded_at": datetime.now(timezone.utc).isoformat()}
            cid = await vault.save(conn, kind="generic", name=CRED_NAME, secret=v["key"], username=v["domain"],
                                   created_by=session.user["id"], cred_id=row["id"] if row else None)
            await conn.execute("UPDATE credentials SET params = $2::jsonb WHERE id = $1::uuid", cid,
                               json.dumps(params))
            rid = _enqueue({"action": "apply", "domain": v["domain"], "fullchain": v["fullchain"], "key": v["key"]})
            await _audit(conn, session, request, "tls.upload", "tls", v["domain"], None,
                         {"domain": v["domain"], "issuer": v["info"]["issuer"], "names": v["info"]["names"],
                          "not_after": v["info"]["not_after"], "sha256": v["info"]["sha256"]})
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    except vault.VaultError as exc:
        raise HTTPException(500, f"Cofre de credenciais: {exc}") from exc
    except OSError as exc:
        raise HTTPException(500, f"Não foi possível gravar o pedido para o Apache: {exc}") from exc
    return {"ok": True, "request_id": rid, "info": v["info"], "chain_count": v["chain_count"],
            "warning": v["warning"]}


@router.post("/reapply")
async def reapply(request: Request,
                  session: SessionInfo = Depends(require_permission("system.settings", write=True))
                  ) -> dict[str, Any]:
    try:
        async with session.db() as conn:
            row = await _stored(conn)
            if row is None:
                raise HTTPException(404, "Nenhum certificado guardado.")
            _, key = await vault.load(conn, row["id"])
            rid = _enqueue({"action": "apply", "domain": row["domain"], "fullchain": _params(row)["fullchain"],
                            "key": key})
            await _audit(conn, session, request, "tls.reapply", "tls", row["domain"], None, {"domain": row["domain"]})
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    except vault.VaultError as exc:
        raise HTTPException(500, f"Cofre de credenciais: {exc}") from exc
    return {"ok": True, "request_id": rid}


@router.delete("")
async def remove(request: Request,
                 session: SessionInfo = Depends(require_permission("system.settings", write=True))
                 ) -> dict[str, Any]:
    try:
        async with session.db() as conn:
            row = await _stored(conn)
            if row is not None:
                await conn.execute("DELETE FROM credentials WHERE id = $1::uuid", row["id"])
            rid = _enqueue({"action": "remove"})
            await _audit(conn, session, request, "tls.remove", "tls", row["domain"] if row else "-", None, {})
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    return {"ok": True, "request_id": rid}


async def reapply_if_missing() -> str | None:
    """Na subida da API: certificado no banco mas não no Apache (VM 1 reinstalada) -> pede para aplicar."""
    status = _status()
    if status is None or _pending():
        return None  # openmon-tls ainda não publicou o estado (ou já tem pedido na fila)
    try:
        async with pool.system_transaction() as conn:
            row = await _stored(conn)
            if row is None:
                return None
            fullchain = _params(row).get("fullchain") or ""
            info = tlscert.info_from_pem(fullchain) or {}
            active = status.get("info") or {}
            if status.get("mode") == "custom" and active.get("sha256") == info.get("sha256") \
                    and status.get("domain") == row["domain"]:
                return None
            if (status.get("last") or {}).get("ok") is False and (status.get("last") or {}).get("action") == "apply":
                return None  # a última tentativa falhou: não fica tentando sozinho
            _, key = await vault.load(conn, row["id"])
    except (pool.DatabaseUnavailable, vault.VaultError, tlscert.CertError) as exc:
        log.warning("certificado HTTPS não reaplicado: %s", exc)
        return None
    log.info("certificado HTTPS de %s guardado no banco e ausente no Apache: reaplicando", row["domain"])
    return _enqueue({"action": "apply", "domain": row["domain"], "fullchain": fullchain, "key": key})
