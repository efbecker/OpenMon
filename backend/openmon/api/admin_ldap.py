"""Configuração do Active Directory / LDAP (opcional). Só o Administrador Global (``users.manage``).

A senha da conta de serviço vai para o cofre (AES-256-GCM, ``credentials``
tipo ``ldap_bind``) e nunca volta para o navegador: a API só informa se existe.
Ao editar, senha em branco mantém a atual.

Mapeamentos grupo do AD → perfil (+ tenant para o perfil Cliente) decidem quem
entra e o que vê; ver ``ldapauth.resolve_access``.
"""
from __future__ import annotations

import asyncio
import json
import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from openmon import ldapauth, vault
from openmon.api.admin_tenants import _audit, _db_error, _iso
from openmon.api.auth import SessionInfo, require_permission
from openmon.db import pool

router = APIRouter(prefix="/api/admin/ldap", tags=["admin"])

URL_RE = re.compile(r"^ldaps?://[A-Za-z0-9.-]+(:\d{1,5})?/?$", re.I)
AD_FILTER = "(&(objectClass=user)(sAMAccountName={username}))"


class MappingForm(BaseModel):
    group_dn: str = Field(min_length=3, max_length=1000)
    role: str = Field(min_length=2, max_length=41)
    tenant_id: int | None = None
    priority: int = Field(default=100, ge=0, le=10000)


class DirectoryForm(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    is_enabled: bool = True
    urls: list[str] = Field(min_length=1, max_length=10)
    security: str = Field(default="ldaps", pattern="^(ldaps|starttls)$")
    base_dn: str = Field(min_length=3, max_length=1000)
    bind_dn: str = Field(min_length=3, max_length=1000)
    bind_password: str | None = Field(default=None, max_length=1024)
    user_filter: str = Field(default=AD_FILTER, min_length=3, max_length=1000)
    group_attribute: str = Field(default="memberOf", max_length=100)
    ca_cert_pem: str | None = Field(default=None, max_length=50000)
    timeout_seconds: int = Field(default=5, ge=1, le=60)
    mappings: list[MappingForm] = Field(default_factory=list, max_length=500)


class TestForm(DirectoryForm):
    directory_id: int | None = None
    test_username: str | None = Field(default=None, max_length=256)
    test_password: str | None = Field(default=None, max_length=1024)


def _validate(form: DirectoryForm) -> dict[str, Any]:
    urls = [u.strip() for u in form.urls if u.strip()]
    if not urls:
        raise HTTPException(422, "Informe pelo menos um servidor (ex.: ldaps://dc1.empresa.local).")
    prefix = "ldaps://" if form.security == "ldaps" else "ldap://"
    for u in urls:
        if not URL_RE.match(u) or not u.lower().startswith(prefix):
            raise HTTPException(422, f"Servidor inválido: {u}. Com {'LDAPS' if form.security == 'ldaps' else 'StartTLS'} "
                                     f"use {prefix}nome-do-dc[:porta]. LDAP sem TLS não é aceito.")
    if "{username}" not in form.user_filter or not form.user_filter.strip().startswith("("):
        raise HTTPException(422, "O filtro de usuário precisa estar entre parênteses e conter {username}.")
    pem = (form.ca_cert_pem or "").strip() or None
    if pem and "-----BEGIN CERTIFICATE-----" not in pem:
        raise HTTPException(422, "Certificado da CA deve estar em formato PEM (-----BEGIN CERTIFICATE-----).")
    attr = form.group_attribute.strip()
    if attr and not re.match(r"^[A-Za-z][A-Za-z0-9-]{0,99}$", attr):
        raise HTTPException(422, "Atributo de grupos inválido.")
    return {"name": form.name.strip(), "is_enabled": form.is_enabled, "urls": urls, "security": form.security,
            "base_dn": form.base_dn.strip(), "bind_dn": form.bind_dn.strip(), "user_filter": form.user_filter.strip(),
            "group_attribute": attr, "ca_cert_pem": pem, "timeout_seconds": form.timeout_seconds}


async def _mappings(conn: Any, maps: list[MappingForm]) -> list[tuple[str, int, int | None, int]]:
    roles = {r["code"]: (r["id"], r["scope"]) for r in await conn.fetch("SELECT id, code, scope FROM roles")}
    tenants = {r["id"] for r in await conn.fetch("SELECT id FROM tenants")}
    out, seen = [], set()
    for m in maps:
        if m.role not in roles:
            raise HTTPException(422, f"Perfil inválido no mapeamento: {m.role}.")
        role_id, scope = roles[m.role]
        tenant = m.tenant_id if scope == "tenant" else None
        if scope == "tenant" and tenant not in tenants:
            raise HTTPException(422, f"Escolha o tenant do grupo {m.group_dn} (perfil Cliente).")
        key = (ldapauth.norm_dn(m.group_dn), tenant)
        if key in seen:
            raise HTTPException(422, f"Grupo repetido: {m.group_dn}.")
        seen.add(key)
        out.append((m.group_dn.strip(), role_id, tenant, m.priority))
    return out


async def _save_mappings(conn: Any, directory_id: int, rows: list[tuple[str, int, int | None, int]]) -> None:
    await conn.execute("DELETE FROM ldap_group_mappings WHERE directory_id = $1", directory_id)
    for group_dn, role_id, tenant_id, priority in rows:
        await conn.execute(
            "INSERT INTO ldap_group_mappings (directory_id, group_dn, role_id, tenant_id, priority) "
            "VALUES ($1, $2, $3, $4, $5)", directory_id, group_dn, role_id, tenant_id, priority)


_SELECT = """
SELECT d.id, d.name, d.is_enabled, d.urls, d.security, d.base_dn, d.user_filter, d.group_attribute, d.ca_cert_pem,
       d.timeout_seconds, d.created_at, d.updated_at, d.bind_credential_id::text AS cred_id, c.username AS bind_dn,
       (SELECT count(*) FROM users u WHERE u.ldap_directory_id = d.id) AS users,
       coalesce((SELECT json_agg(json_build_object('group_dn', m.group_dn, 'role', r.code, 'tenant_id', m.tenant_id,
                                                   'priority', m.priority) ORDER BY m.priority, m.id)
                   FROM ldap_group_mappings m JOIN roles r ON r.id = m.role_id
                  WHERE m.directory_id = d.id), '[]') AS mappings
  FROM ldap_directories d LEFT JOIN credentials c ON c.id = d.bind_credential_id
"""


def _out(r: Any) -> dict[str, Any]:
    maps = r["mappings"]
    return {"id": r["id"], "name": r["name"], "is_enabled": r["is_enabled"], "urls": list(r["urls"]),
            "security": r["security"], "base_dn": r["base_dn"], "bind_dn": r["bind_dn"] or "",
            "has_password": bool(r["cred_id"]), "user_filter": r["user_filter"],
            "group_attribute": r["group_attribute"], "ca_cert_pem": r["ca_cert_pem"] or "",
            "timeout_seconds": r["timeout_seconds"], "users": r["users"], "created_at": _iso(r["created_at"]),
            "updated_at": _iso(r["updated_at"]),
            "mappings": json.loads(maps) if isinstance(maps, str) else list(maps or [])}


@router.get("")
async def list_directories(session: SessionInfo = Depends(require_permission("users.manage"))) -> dict[str, Any]:
    try:
        async with session.db() as conn:
            rows = await conn.fetch(_SELECT + " ORDER BY d.id")
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    return {"directories": [_out(r) for r in rows], "default_filter": AD_FILTER}


def _vault_error(exc: vault.VaultError) -> HTTPException:
    return HTTPException(500, f"Cofre de credenciais: {exc}")


@router.post("", status_code=201)
async def create_directory(form: DirectoryForm, request: Request,
                           session: SessionInfo = Depends(require_permission("users.manage", write=True))
                           ) -> dict[str, Any]:
    v = _validate(form)
    if not form.bind_password:
        raise HTTPException(422, "Informe a senha da conta de serviço.")
    try:
        async with session.db() as conn:
            maps = await _mappings(conn, form.mappings)
            if await conn.fetchval("SELECT 1 FROM ldap_directories WHERE lower(name) = lower($1)", v["name"]):
                raise HTTPException(409, f"Já existe um diretório chamado \"{v['name']}\".")
            cred = await vault.save(conn, kind="ldap_bind", name=f"ldap-bind:{v['name']}", secret=form.bind_password,
                                    username=v["bind_dn"], created_by=session.user["id"])
            did = await conn.fetchval(
                """INSERT INTO ldap_directories (name, is_enabled, urls, security, base_dn, bind_credential_id,
                                                 user_filter, group_attribute, ca_cert_pem, timeout_seconds)
                   VALUES ($1, $2, $3, $4, $5, $6::uuid, $7, $8, $9, $10) RETURNING id""",
                v["name"], v["is_enabled"], v["urls"], v["security"], v["base_dn"], cred, v["user_filter"],
                v["group_attribute"], v["ca_cert_pem"], v["timeout_seconds"])
            await _save_mappings(conn, did, maps)
            await _audit(conn, session, request, "ldap.create", "ldap_directory", did, None,
                         {k: v[k] for k in ("name", "urls", "security", "base_dn", "bind_dn", "is_enabled")}
                         | {"mappings": len(maps)})
            row = await conn.fetchrow(_SELECT + " WHERE d.id = $1", did)
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    except vault.VaultError as exc:
        raise _vault_error(exc) from exc
    return {"directory": _out(row)}


@router.put("/{directory_id}")
async def update_directory(directory_id: int, form: DirectoryForm, request: Request,
                           session: SessionInfo = Depends(require_permission("users.manage", write=True))
                           ) -> dict[str, Any]:
    v = _validate(form)
    try:
        async with session.db() as conn:
            old = await conn.fetchrow(_SELECT + " WHERE d.id = $1", directory_id)
            if old is None:
                raise HTTPException(404, "Diretório não encontrado.")
            maps = await _mappings(conn, form.mappings)
            if await conn.fetchval("SELECT 1 FROM ldap_directories WHERE lower(name) = lower($1) AND id <> $2",
                                   v["name"], directory_id):
                raise HTTPException(409, f"Já existe um diretório chamado \"{v['name']}\".")
            cred = old["cred_id"]
            if form.bind_password:
                cred = await vault.save(conn, kind="ldap_bind", name=f"ldap-bind:{v['name']}",
                                        secret=form.bind_password, username=v["bind_dn"],
                                        created_by=session.user["id"], cred_id=cred)
            elif cred:
                await vault.set_username(conn, cred, v["bind_dn"])
                await conn.execute("UPDATE credentials SET name = $2 WHERE id = $1::uuid", cred,
                                   f"ldap-bind:{v['name']}")
            else:
                raise HTTPException(422, "Informe a senha da conta de serviço.")
            await conn.execute(
                """UPDATE ldap_directories SET name = $2, is_enabled = $3, urls = $4, security = $5, base_dn = $6,
                          bind_credential_id = $7::uuid, user_filter = $8, group_attribute = $9, ca_cert_pem = $10,
                          timeout_seconds = $11, updated_at = now()
                    WHERE id = $1""",
                directory_id, v["name"], v["is_enabled"], v["urls"], v["security"], v["base_dn"], cred,
                v["user_filter"], v["group_attribute"], v["ca_cert_pem"], v["timeout_seconds"])
            await _save_mappings(conn, directory_id, maps)
            await _audit(conn, session, request, "ldap.update", "ldap_directory", directory_id, None,
                         {k: v[k] for k in ("name", "urls", "security", "base_dn", "bind_dn", "is_enabled")}
                         | {"mappings": len(maps), "password_changed": bool(form.bind_password)})
            row = await conn.fetchrow(_SELECT + " WHERE d.id = $1", directory_id)
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    except vault.VaultError as exc:
        raise _vault_error(exc) from exc
    return {"directory": _out(row)}


@router.delete("/{directory_id}")
async def delete_directory(directory_id: int, request: Request,
                           session: SessionInfo = Depends(require_permission("users.manage", write=True))
                           ) -> dict[str, Any]:
    try:
        async with session.db() as conn:
            old = await conn.fetchrow(_SELECT + " WHERE d.id = $1", directory_id)
            if old is None:
                raise HTTPException(404, "Diretório não encontrado.")
            # Usuários do AD perdem o vínculo e deixam de entrar (não há senha local); a conta fica para a auditoria
            await conn.execute("UPDATE users SET is_active = false, updated_at = now() WHERE ldap_directory_id = $1",
                               directory_id)
            await conn.execute("UPDATE user_sessions SET revoked_at = now() WHERE revoked_at IS NULL AND user_id IN "
                               "(SELECT id FROM users WHERE ldap_directory_id = $1)", directory_id)
            await conn.execute("DELETE FROM ldap_directories WHERE id = $1", directory_id)
            if old["cred_id"]:
                await conn.execute("DELETE FROM credentials WHERE id = $1::uuid", old["cred_id"])
            await _audit(conn, session, request, "ldap.delete", "ldap_directory", directory_id, None,
                         {"name": old["name"], "users_disabled": old["users"]})
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    return {"ok": True}


@router.post("/test")
async def test_directory(form: TestForm, request: Request,
                         session: SessionInfo = Depends(require_permission("users.manage", write=True))
                         ) -> dict[str, Any]:
    """Testa a configuração do formulário (salva ou não). Senha em branco usa a já guardada no cofre."""
    v = _validate(form)
    password = form.bind_password or ""
    tenant_names: dict[int, str] = {}
    try:
        async with session.db() as conn:
            if not password and form.directory_id:
                cred = await conn.fetchval("SELECT bind_credential_id::text FROM ldap_directories WHERE id = $1",
                                           form.directory_id)
                if cred:
                    _, password = await vault.load(conn, cred)
            maps = await _mappings(conn, form.mappings)
            roles = {r["id"]: (r["code"], r["scope"]) for r in await conn.fetch("SELECT id, code, scope FROM roles")}
            tenant_names = {r["id"]: r["name"] for r in await conn.fetch("SELECT id, name FROM tenants")}
            await _audit(conn, session, request, "ldap.test", "ldap_directory", form.directory_id or "-", None,
                         {"urls": v["urls"], "test_username": form.test_username or None})
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    except vault.VaultError as exc:
        raise _vault_error(exc) from exc
    if not password:
        raise HTTPException(422, "Informe a senha da conta de serviço.")
    cfg = ldapauth.Directory(urls=v["urls"], security=v["security"], base_dn=v["base_dn"], bind_dn=v["bind_dn"],
                             bind_password=password, user_filter=v["user_filter"],
                             group_attribute=v["group_attribute"], ca_cert_pem=v["ca_cert_pem"],
                             timeout=v["timeout_seconds"])
    username = (form.test_username or "").strip() or None
    result = await asyncio.to_thread(ldapauth.test, cfg, username, form.test_password or None)
    if username and "groups" in result:
        mapping_dicts = [{"group_dn": g, "role": roles[r][0], "scope": roles[r][1], "tenant_id": t, "priority": p}
                         for g, r, t, p in maps]
        access = ldapauth.resolve_access(mapping_dicts, result["groups"])
        result["access"] = None if access is None else {
            "role": access[0], "tenants": [tenant_names.get(t, str(t)) for t in access[1]]}
    return result
