"""Cadastro de tenants (clientes) e de usuários.

* Tenants: ``tenants.manage`` (Administrador Global). Operadores, que já têm
  visão global, só listam.
* Usuários: ``users.manage`` (Administrador Global).

As consultas rodam com o contexto de RLS do próprio usuário (``session.db()``),
então o banco aplica as mesmas políticas da migration 0005 que valem para o
resto da aplicação. Toda alteração vai para ``audit_log`` (sem senhas).

Regras que o banco sozinho não garante:
* o tenant provedor (datacenter) não pode ser desativado nem excluído;
* um tenant com ativos, integrações ou usuários vinculados não é excluído
  (desativar mantém o histórico de 5 anos);
* perfil de escopo ``tenant`` (Cliente) precisa de pelo menos um tenant; perfis
  globais não têm vínculos;
* sempre sobra pelo menos um Administrador Global ativo, e ninguém exclui ou
  desativa a própria conta;
* senha definida pelo administrador é provisória por padrão (o usuário troca
  no primeiro acesso) e derruba as sessões abertas da conta.
"""
from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from openmon.api import authlog, security
from openmon.api.auth import SessionInfo, require_permission
from openmon.db import pool

router = APIRouter(prefix="/api/admin", tags=["admin"])

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{1,63}$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$")


def _db_error(exc: pool.DatabaseUnavailable) -> HTTPException:
    return HTTPException(503, f"Banco de dados indisponível: {exc}")


def _iso(v: Any) -> Any:
    return v.isoformat() if isinstance(v, datetime) else v


def _clean(v: str | None) -> str | None:
    v = (v or "").strip()
    return v or None


def _email(v: str | None) -> str | None:
    v = _clean(v)
    if v and (len(v) > 254 or not EMAIL_RE.match(v)):
        raise HTTPException(422, "E-mail inválido.")
    return v


def _pg_code(exc: BaseException) -> str:
    return getattr(exc, "sqlstate", "") or ""


async def _audit(conn: Any, session: SessionInfo, request: Request, action: str, object_type: str,
                 object_id: Any, tenant_id: int | None = None, details: dict[str, Any] | None = None) -> None:
    await conn.execute(
        """INSERT INTO audit_log (tenant_id, user_id, username, client_ip, user_agent, action, object_type,
                                  object_id, details)
           VALUES ($1, $2, $3, $4::inet, $5, $6, $7, $8, $9::jsonb)""",
        tenant_id, session.user["id"], session.user["username"],
        security.inet_or_none(security.client_ip(request)), security.user_agent(request),
        action, object_type, str(object_id), json.dumps(details or {}, default=str))


# =============================================================================
# Tenants
# =============================================================================
class TenantForm(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    slug: str = Field(min_length=2, max_length=63)
    contact_email: str | None = Field(default=None, max_length=254)
    backup_sla_hours: int | None = Field(default=None, ge=1, le=8760)
    notes: str | None = Field(default=None, max_length=2000)
    is_active: bool = True


def _tenant_values(form: TenantForm) -> dict[str, Any]:
    slug = form.slug.strip().lower()
    if not SLUG_RE.match(slug):
        raise HTTPException(422, "Identificador inválido: use letras minúsculas, números e hífen (2 a 63).")
    name = form.name.strip()
    if len(name) < 2:
        raise HTTPException(422, "Informe o nome do tenant.")
    return {"name": name, "slug": slug, "contact_email": _email(form.contact_email),
            "backup_sla_hours": form.backup_sla_hours, "notes": _clean(form.notes), "is_active": form.is_active}


_TENANT_SELECT = """
SELECT t.id, t.slug, t.name, t.is_provider, t.is_active, t.contact_email, t.backup_sla_hours, t.notes,
       t.created_at, t.updated_at,
       (SELECT count(*) FROM user_tenants ut WHERE ut.tenant_id = t.id) AS users,
       (SELECT count(*) FROM assets a WHERE a.tenant_id = t.id AND a.deleted_at IS NULL) AS assets,
       (SELECT count(*) FROM integrations i WHERE i.tenant_id = t.id) AS integrations
  FROM tenants t
"""


def _tenant_out(r: Any) -> dict[str, Any]:
    return {k: _iso(r[k]) for k in ("id", "slug", "name", "is_provider", "is_active", "contact_email",
                                     "backup_sla_hours", "notes", "created_at", "updated_at", "users",
                                     "assets", "integrations")}


@router.get("/tenants")
async def list_tenants(session: SessionInfo = Depends(require_permission("dashboard.view"))) -> dict[str, Any]:
    if not session.is_global:
        raise HTTPException(403, "Somente perfis do datacenter listam todos os tenants.")
    try:
        async with session.db() as conn:
            rows = await conn.fetch(_TENANT_SELECT + " ORDER BY t.is_provider DESC, lower(t.name)")
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    return {"tenants": [_tenant_out(r) for r in rows], "can_manage": session.can("tenants.manage")}


@router.post("/tenants", status_code=201)
async def create_tenant(form: TenantForm, request: Request,
                        session: SessionInfo = Depends(require_permission("tenants.manage", write=True))
                        ) -> dict[str, Any]:
    v = _tenant_values(form)
    try:
        async with session.db() as conn:
            try:
                async with conn.transaction():
                    tid = await conn.fetchval(
                        """INSERT INTO tenants (slug, name, contact_email, backup_sla_hours, notes, is_active)
                           VALUES ($1, $2, $3, $4, $5, $6) RETURNING id""",
                        v["slug"], v["name"], v["contact_email"], v["backup_sla_hours"], v["notes"], v["is_active"])
            except Exception as exc:
                if _pg_code(exc) == "23505":
                    raise HTTPException(409, f"Já existe um tenant com o identificador \"{v['slug']}\".") from exc
                raise
            await _audit(conn, session, request, "tenant.create", "tenant", tid, tid, v)
            row = await conn.fetchrow(_TENANT_SELECT + " WHERE t.id = $1", tid)
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    return {"tenant": _tenant_out(row)}


@router.put("/tenants/{tenant_id}")
async def update_tenant(tenant_id: int, form: TenantForm, request: Request,
                        session: SessionInfo = Depends(require_permission("tenants.manage", write=True))
                        ) -> dict[str, Any]:
    v = _tenant_values(form)
    try:
        async with session.db() as conn:
            old = await conn.fetchrow("SELECT * FROM tenants WHERE id = $1 FOR UPDATE", tenant_id)
            if old is None:
                raise HTTPException(404, "Tenant não encontrado.")
            if old["is_provider"] and not v["is_active"]:
                raise HTTPException(422, "O tenant do datacenter (provedor) não pode ser desativado.")
            try:
                async with conn.transaction():
                    await conn.execute(
                        """UPDATE tenants SET slug = $2, name = $3, contact_email = $4, backup_sla_hours = $5,
                                  notes = $6, is_active = $7, updated_at = now()
                            WHERE id = $1""",
                        tenant_id, v["slug"], v["name"], v["contact_email"], v["backup_sla_hours"], v["notes"],
                        v["is_active"])
            except Exception as exc:
                if _pg_code(exc) == "23505":
                    raise HTTPException(409, f"Já existe um tenant com o identificador \"{v['slug']}\".") from exc
                raise
            changed = {k: val for k, val in v.items() if old[k] != val}
            if changed:
                action = ("tenant.deactivate" if changed.get("is_active") is False else
                          "tenant.activate" if changed.get("is_active") is True else "tenant.update")
                await _audit(conn, session, request, action, "tenant", tenant_id, tenant_id, changed)
            row = await conn.fetchrow(_TENANT_SELECT + " WHERE t.id = $1", tenant_id)
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    return {"tenant": _tenant_out(row)}


@router.delete("/tenants/{tenant_id}")
async def delete_tenant(tenant_id: int, request: Request,
                        session: SessionInfo = Depends(require_permission("tenants.manage", write=True))
                        ) -> dict[str, Any]:
    try:
        async with session.db() as conn:
            row = await conn.fetchrow(_TENANT_SELECT + " WHERE t.id = $1 FOR UPDATE OF t", tenant_id)
            if row is None:
                raise HTTPException(404, "Tenant não encontrado.")
            if row["is_provider"]:
                raise HTTPException(422, "O tenant do datacenter (provedor) não pode ser excluído.")
            if row["users"] or row["assets"] or row["integrations"]:
                raise HTTPException(409, "Este tenant tem usuários, ativos ou integrações. Desative-o em vez de "
                                         "excluir: o histórico fica preservado e os clientes perdem o acesso.")
            try:
                async with conn.transaction():
                    await conn.execute("DELETE FROM tenants WHERE id = $1", tenant_id)
            except Exception as exc:
                if _pg_code(exc) == "23503":
                    raise HTTPException(409, "Este tenant ainda tem dados vinculados (backups, alertas...). "
                                             "Desative-o em vez de excluir.") from exc
                raise
            await _audit(conn, session, request, "tenant.delete", "tenant", tenant_id, tenant_id,
                         {"slug": row["slug"], "name": row["name"]})
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    return {"ok": True}


# =============================================================================
# Usuários
# =============================================================================
class UserForm(BaseModel):
    username: str = Field(min_length=2, max_length=64)
    display_name: str | None = Field(default=None, max_length=120)
    email: str | None = Field(default=None, max_length=254)
    role: str = Field(min_length=2, max_length=41)
    tenant_ids: list[int] = Field(default_factory=list, max_length=500)
    is_active: bool = True
    password: str | None = Field(default=None, max_length=security.PASSWORD_MAX)
    must_change_password: bool = True
    # 'ldap': entra com a senha do domínio, com o perfil e os tenants definidos aqui (fixos)
    auth_source: str = Field(default="local", pattern="^(local|ldap)$")
    ldap_directory_id: int | None = None


class UserUpdateForm(BaseModel):
    display_name: str | None = Field(default=None, max_length=120)
    email: str | None = Field(default=None, max_length=254)
    role: str = Field(min_length=2, max_length=41)
    tenant_ids: list[int] = Field(default_factory=list, max_length=500)
    is_active: bool = True
    # Só usuários do AD: True = perfil e tenants seguem os grupos a cada login; False = fixos (definidos aqui)
    profile_from_groups: bool | None = None


class PasswordResetForm(BaseModel):
    password: str = Field(min_length=1, max_length=security.PASSWORD_MAX)
    must_change_password: bool = True


_USER_SELECT = """
SELECT u.id, u.username, u.display_name, u.email, u.auth_source, u.is_active, u.must_change_password,
       u.locked_until, u.locked_until IS NOT NULL AND u.locked_until > now() AS locked,
       u.last_login_at, host(u.last_login_ip) AS last_login_ip, u.password_changed_at, u.created_at,
       r.code AS role, r.name AS role_name, r.scope,
       u.auth_source = 'ldap' AND u.external_dn IS NOT NULL AS profile_from_groups,
       (SELECT name FROM ldap_directories d WHERE d.id = u.ldap_directory_id) AS ldap_directory,
       coalesce((SELECT json_agg(json_build_object('id', t.id, 'name', t.name, 'slug', t.slug,
                                                   'is_active', t.is_active) ORDER BY lower(t.name))
                   FROM user_tenants ut JOIN tenants t ON t.id = ut.tenant_id
                  WHERE ut.user_id = u.id), '[]') AS tenants
  FROM users u JOIN roles r ON r.id = u.role_id
"""


def _user_out(r: Any) -> dict[str, Any]:
    out = {k: _iso(r[k]) for k in ("id", "username", "display_name", "email", "auth_source", "is_active",
                                    "must_change_password", "locked", "locked_until", "last_login_at",
                                    "last_login_ip", "password_changed_at", "created_at", "role", "role_name",
                                    "scope", "profile_from_groups", "ldap_directory")}
    tenants = r["tenants"]
    out["tenants"] = json.loads(tenants) if isinstance(tenants, str) else list(tenants or [])
    return out


async def _role(conn: Any, code: str) -> Any:
    role = await conn.fetchrow("SELECT id, code, name, scope FROM roles WHERE code = $1", code)
    if role is None:
        raise HTTPException(422, "Perfil inválido.")
    return role


async def _tenant_ids(conn: Any, role: Any, tenant_ids: list[int]) -> list[int]:
    if role["scope"] == "global":
        return []  # perfis do datacenter enxergam tudo; vínculo não se aplica
    ids = sorted(set(tenant_ids))
    if not ids:
        raise HTTPException(422, "Selecione pelo menos um tenant para o perfil Cliente.")
    found = await conn.fetch("SELECT id FROM tenants WHERE id = ANY($1::bigint[])", ids)
    if len(found) != len(ids):
        raise HTTPException(422, "Tenant inexistente na lista de vínculos.")
    return ids


async def _set_tenants(conn: Any, user_id: int, ids: list[int]) -> None:
    await conn.execute("DELETE FROM user_tenants WHERE user_id = $1 AND NOT (tenant_id = ANY($2::bigint[]))",
                       user_id, ids)
    if ids:
        await conn.execute(
            "INSERT INTO user_tenants (user_id, tenant_id) SELECT $1, unnest($2::bigint[]) ON CONFLICT DO NOTHING",
            user_id, ids)


async def _other_active_admins(conn: Any, user_id: int) -> int:
    # Trava as linhas dos administradores: duas remoções simultâneas não deixam o sistema sem nenhum
    await conn.execute(
        "SELECT u.id FROM users u JOIN roles r ON r.id = u.role_id WHERE r.code = 'global_admin' FOR UPDATE OF u")
    return await conn.fetchval(
        """SELECT count(*) FROM users u JOIN roles r ON r.id = u.role_id
            WHERE r.code = 'global_admin' AND u.is_active AND u.id <> $1""", user_id)


async def _revoke_sessions(conn: Any, user_id: int) -> None:
    await conn.execute("UPDATE user_sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL",
                       user_id)


def _password(password: str | None, username: str) -> str:
    if not password:
        raise HTTPException(422, "Informe a senha inicial.")
    problem = security.password_problem(password, username)
    if problem:
        raise HTTPException(422, problem)
    return password


@router.get("/roles")
async def list_roles(session: SessionInfo = Depends(require_permission("users.manage"))) -> dict[str, Any]:
    try:
        async with session.db() as conn:
            rows = await conn.fetch(
                """SELECT r.code, r.name, r.scope, r.description,
                          ARRAY(SELECT permission_code FROM role_permissions rp WHERE rp.role_id = r.id
                                 ORDER BY permission_code) AS permissions
                     FROM roles r ORDER BY r.scope, r.id""")
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    return {"roles": [dict(r) | {"permissions": list(r["permissions"])} for r in rows]}


@router.get("/users")
async def list_users(tenant_id: int | None = None,
                     session: SessionInfo = Depends(require_permission("users.manage"))) -> dict[str, Any]:
    try:
        async with session.db() as conn:
            if tenant_id is None:
                rows = await conn.fetch(_USER_SELECT + " ORDER BY lower(u.username)")
            else:
                rows = await conn.fetch(
                    _USER_SELECT + " WHERE EXISTS (SELECT 1 FROM user_tenants x WHERE x.user_id = u.id "
                                   "AND x.tenant_id = $1) ORDER BY lower(u.username)", tenant_id)
            dirs = await conn.fetch("SELECT id, name FROM ldap_directories WHERE is_enabled ORDER BY id")
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    return {"users": [_user_out(r) for r in rows], "you": session.user["id"],
            "ldap_directories": [dict(d) for d in dirs]}


@router.post("/users", status_code=201)
async def create_user(form: UserForm, request: Request,
                      session: SessionInfo = Depends(require_permission("users.manage", write=True))
                      ) -> dict[str, Any]:
    username = form.username.strip()
    if not USERNAME_RE.match(username):
        raise HTTPException(422, "Usuário inválido: 2 a 64 caracteres (letras, números, ponto, hífen, _ e @).")
    ldap = form.auth_source == "ldap"
    email = _email(form.email)
    pw_hash = None
    if not ldap:
        password = _password(form.password, username)
        pw_hash = await asyncio.to_thread(security.hash_password, password)
    try:
        async with session.db() as conn:
            role = await _role(conn, form.role)
            ids = await _tenant_ids(conn, role, form.tenant_ids)
            directory_id = None
            if ldap:
                dirs = [r["id"] for r in await conn.fetch(
                    "SELECT id FROM ldap_directories WHERE is_enabled ORDER BY id")]
                if not dirs:
                    raise HTTPException(422, "Nenhum Active Directory habilitado: configure em AD/LDAP primeiro.")
                directory_id = form.ldap_directory_id or dirs[0]
                if directory_id not in dirs:
                    raise HTTPException(422, "Diretório do AD inválido.")
            try:
                async with conn.transaction():
                    # Usuário do AD cadastrado aqui: external_dn fica NULL = perfil fixo (os grupos não mudam)
                    uid = await conn.fetchval(
                        """INSERT INTO users (username, display_name, email, auth_source, password_hash, role_id,
                                              is_active, must_change_password, password_changed_at, ldap_directory_id)
                           VALUES ($1, $2, $3, $8, $4, $5, $6, $7, CASE WHEN $8 = 'local' THEN now() END, $9)
                           RETURNING id""",
                        username, _clean(form.display_name), email, pw_hash, role["id"], form.is_active,
                        form.must_change_password and not ldap, form.auth_source, directory_id)
            except Exception as exc:
                if _pg_code(exc) == "23505":
                    raise HTTPException(409, f"Já existe um usuário \"{username}\".") from exc
                raise
            await _set_tenants(conn, uid, ids)
            await _audit(conn, session, request, "user.create", "user", uid, ids[0] if len(ids) == 1 else None,
                         {"username": username, "role": role["code"], "tenant_ids": ids, "auth_source": form.auth_source,
                          "is_active": form.is_active, "must_change_password": form.must_change_password and not ldap})
            row = await conn.fetchrow(_USER_SELECT + " WHERE u.id = $1", uid)
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    authlog.event("admin.user_create", security.client_ip(request), username=session.user["username"],
                  target=username)
    return {"user": _user_out(row)}


async def _load_user(conn: Any, user_id: int) -> Any:
    row = await conn.fetchrow(_USER_SELECT + " WHERE u.id = $1", user_id)
    if row is None:
        raise HTTPException(404, "Usuário não encontrado.")
    await conn.execute("SELECT 1 FROM users WHERE id = $1 FOR UPDATE", user_id)
    return row


@router.put("/users/{user_id}")
async def update_user(user_id: int, form: UserUpdateForm, request: Request,
                      session: SessionInfo = Depends(require_permission("users.manage", write=True))
                      ) -> dict[str, Any]:
    email = _email(form.email)
    try:
        async with session.db() as conn:
            old = await _load_user(conn, user_id)
            role = await _role(conn, form.role)
            ids = await _tenant_ids(conn, role, form.tenant_ids)
            losing_admin = old["role"] == "global_admin" and old["is_active"] and (
                role["code"] != "global_admin" or not form.is_active)
            if user_id == session.user["id"] and losing_admin:
                raise HTTPException(422, "Você não pode remover o seu próprio perfil de administrador nem "
                                         "desativar a sua conta.")
            if losing_admin and await _other_active_admins(conn, user_id) == 0:
                raise HTTPException(422, "Este é o último Administrador Global ativo.")
            await conn.execute(
                """UPDATE users SET display_name = $2, email = $3, role_id = $4, is_active = $5, updated_at = now()
                    WHERE id = $1""",
                user_id, _clean(form.display_name), email, role["id"], form.is_active)
            await _set_tenants(conn, user_id, ids)
            if old["auth_source"] == "ldap" and form.profile_from_groups is not None \
                    and form.profile_from_groups != old["profile_from_groups"]:
                # '' = volta a seguir os grupos (o DN real é gravado no próximo login); NULL = fixo
                await conn.execute("UPDATE users SET external_dn = $2 WHERE id = $1", user_id,
                                   "" if form.profile_from_groups else None)
            if not form.is_active and old["is_active"]:
                await _revoke_sessions(conn, user_id)
            old_ids = sorted(t["id"] for t in _user_out(old)["tenants"])
            changed: dict[str, Any] = {}
            if old["display_name"] != _clean(form.display_name):
                changed["display_name"] = _clean(form.display_name)
            if old["email"] != email:
                changed["email"] = email
            if old["role"] != role["code"]:
                changed["role"] = role["code"]
            if old["is_active"] != form.is_active:
                changed["is_active"] = form.is_active
            if old_ids != ids:
                changed["tenant_ids"] = ids
            if old["auth_source"] == "ldap" and form.profile_from_groups is not None \
                    and form.profile_from_groups != old["profile_from_groups"]:
                changed["profile_from_groups"] = form.profile_from_groups
            if changed:
                action = ("user.deactivate" if changed.get("is_active") is False else
                          "user.activate" if changed.get("is_active") is True else "user.update")
                await _audit(conn, session, request, action, "user", user_id, None,
                             {"username": old["username"], **changed})
            row = await conn.fetchrow(_USER_SELECT + " WHERE u.id = $1", user_id)
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    return {"user": _user_out(row)}


@router.post("/users/{user_id}/password")
async def reset_password(user_id: int, form: PasswordResetForm, request: Request,
                         session: SessionInfo = Depends(require_permission("users.manage", write=True))
                         ) -> dict[str, Any]:
    if user_id == session.user["id"]:
        raise HTTPException(422, "Para trocar a sua própria senha use \"Minha senha\".")
    try:
        async with session.db() as conn:
            old = await _load_user(conn, user_id)
            if old["auth_source"] != "local":
                raise HTTPException(409, "A senha desta conta é gerenciada pelo Active Directory/LDAP.")
            password = _password(form.password, old["username"])
            pw_hash = await asyncio.to_thread(security.hash_password, password)
            await conn.execute(
                """UPDATE users SET password_hash = $2, must_change_password = $3, password_changed_at = now(),
                          failed_login_count = 0, locked_until = NULL, updated_at = now()
                    WHERE id = $1""", user_id, pw_hash, form.must_change_password)
            await _revoke_sessions(conn, user_id)
            await _audit(conn, session, request, "user.password_reset", "user", user_id, None,
                         {"username": old["username"], "must_change_password": form.must_change_password})
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    authlog.event("admin.password_reset", security.client_ip(request), username=session.user["username"],
                  target=old["username"])
    return {"ok": True}


@router.post("/users/{user_id}/unlock")
async def unlock_user(user_id: int, request: Request,
                      session: SessionInfo = Depends(require_permission("users.manage", write=True))
                      ) -> dict[str, Any]:
    try:
        async with session.db() as conn:
            old = await _load_user(conn, user_id)
            await conn.execute("UPDATE users SET failed_login_count = 0, locked_until = NULL, updated_at = now() "
                               "WHERE id = $1", user_id)
            # As falhas recentes em login_attempts também contam para o bloqueio: um login
            # "desbloqueado" registrado zera a janela do usuário (ver PgAuthStore.recent_failures).
            await conn.execute(
                "INSERT INTO login_attempts (username, client_ip, success, reason, auth_source) "
                "VALUES ($1, '0.0.0.0', true, 'admin_unlock', 'local')", old["username"])
            await _audit(conn, session, request, "user.unlock", "user", user_id, None, {"username": old["username"]})
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    return {"ok": True}


@router.delete("/users/{user_id}")
async def delete_user(user_id: int, request: Request,
                      session: SessionInfo = Depends(require_permission("users.manage", write=True))
                      ) -> dict[str, Any]:
    if user_id == session.user["id"]:
        raise HTTPException(422, "Você não pode excluir a sua própria conta.")
    try:
        async with session.db() as conn:
            old = await _load_user(conn, user_id)
            if old["role"] == "global_admin" and old["is_active"] and await _other_active_admins(conn, user_id) == 0:
                raise HTTPException(422, "Este é o último Administrador Global ativo.")
            try:
                async with conn.transaction():
                    await conn.execute("DELETE FROM users WHERE id = $1", user_id)
            except Exception as exc:
                if _pg_code(exc) == "23503":
                    raise HTTPException(409, "Este usuário tem registros vinculados. Desative-o em vez de "
                                             "excluir.") from exc
                raise
            await _audit(conn, session, request, "user.delete", "user", user_id, None,
                         {"username": old["username"], "role": old["role"]})
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    authlog.event("admin.user_delete", security.client_ip(request), username=session.user["username"],
                  target=old["username"])
    return {"ok": True}
