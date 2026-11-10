"""Login local, sessões e CSRF.

* Senha conferida com Argon2id; usuário inexistente gasta o mesmo tempo (hash fictício).
* Bloqueio: ``auth.lockout`` em ``system_settings`` (padrão 5 erros em 15 min
  bloqueiam a conta por 15 min). Vale também para nomes que não existem, para a
  resposta não revelar quais usuários existem. Limite adicional por IP.
* Toda tentativa vai para ``login_attempts`` e para ``auth.log`` (Fail2ban).
* Sessão no servidor (``user_sessions`` guarda só o SHA-256 do token). Cookie
  ``__Host-openmon_session``: HttpOnly, Secure, SameSite=Strict, Path=/.
* CSRF: o token é um HMAC do token de sessão, entregue no corpo de ``/login`` e
  ``/me`` e exigido no cabeçalho ``X-CSRF-Token`` em todo método que altera estado.
* Expiração por inatividade e absoluta (``auth.session``: 30 min / 12 h).
"""
from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from pydantic import BaseModel, Field

from openmon.api import authlog, security
from openmon.db import pool

router = APIRouter(prefix="/api/auth", tags=["auth"])

COOKIE = "__Host-openmon_session"
IP_MAX_FAILURES = 30          # por IP, na mesma janela do bloqueio de conta
GENERIC_FAIL = "Usuário ou senha inválidos."
LOCKED_FAIL = "Muitas tentativas para este usuário. Aguarde alguns minutos e tente de novo."

DEFAULT_LOCKOUT = {"max_failures": 5, "window_minutes": 15, "lock_minutes": 15}
DEFAULT_SESSION = {"idle_minutes": 30, "absolute_hours": 12}


@dataclass
class SessionInfo:
    token: str
    token_hash: bytes
    csrf_hash: bytes
    user: dict[str, Any]
    expires_at: datetime
    tenant_ids: list[int] = field(default_factory=list)
    permissions: frozenset[str] = frozenset()

    @property
    def is_global(self) -> bool:
        return self.user.get("scope") == "global"

    def can(self, permission: str) -> bool:
        return permission in self.permissions

    def db(self) -> Any:
        """Transação com o contexto de RLS deste usuário (escopo global ou só os tenants dele)."""
        return pool.transaction(self.user["id"], self.is_global, () if self.is_global else self.tenant_ids)


# Permissões dos perfis embutidos (migration 0001). O banco é a fonte; isto é o
# reserva para sessões carregadas sem a lista (testes e bancos antigos).
BUILTIN_PERMISSIONS: dict[str, frozenset[str]] = {
    "global_admin": frozenset({
        "dashboard.view", "assets.view", "assets.manage", "integrations.manage", "credentials.manage",
        "alerts.view", "alerts.ack", "alerts.manage", "backups.view", "reports.view", "tenants.manage",
        "users.manage", "audit.view", "system.backup", "system.settings"}),
    "operator": frozenset({"dashboard.view", "assets.view", "assets.manage", "alerts.view", "alerts.ack",
                           "alerts.manage", "backups.view", "reports.view", "audit.view"}),
    "client": frozenset({"dashboard.view", "assets.view", "alerts.view", "backups.view", "reports.view"}),
}


# -----------------------------------------------------------------------------
# Persistência (PostgreSQL). Os testes trocam ``store`` por uma versão em memória.
# -----------------------------------------------------------------------------
class PgAuthStore:
    _settings_cache: tuple[float, dict[str, dict[str, int]]] | None = None

    async def settings(self) -> dict[str, dict[str, int]]:
        now = time.monotonic()
        if self._settings_cache and now - self._settings_cache[0] < 60:
            return self._settings_cache[1]
        out = {"auth.lockout": dict(DEFAULT_LOCKOUT), "auth.session": dict(DEFAULT_SESSION)}
        async with pool.system_transaction() as conn:
            rows = await conn.fetch("SELECT key, value FROM system_settings WHERE key = ANY($1::text[])",
                                    list(out))
        for r in rows:
            value = json.loads(r["value"]) if isinstance(r["value"], str) else r["value"]
            for k, v in (value or {}).items():
                if k in out[r["key"]] and isinstance(v, int) and v > 0:
                    out[r["key"]][k] = v
        self._settings_cache = (now, out)
        return out

    async def recent_failures(self, username: str, ip: str | None, minutes: int) -> tuple[int, int]:
        async with pool.system_transaction() as conn:
            # Falhas do usuário contam só depois do último login bem-sucedido
            row = await conn.fetchrow(
                """WITH w AS (
                       SELECT time, username, client_ip, success FROM login_attempts
                        WHERE time > now() - make_interval(mins => $3)
                          AND (lower(username) = lower($1) OR client_ip = $2::inet))
                   SELECT count(*) FILTER (WHERE NOT success AND lower(username) = lower($1)
                                             AND time > coalesce((SELECT max(time) FROM w
                                                                   WHERE success AND lower(username) = lower($1)),
                                                                 '-infinity')) AS by_user,
                          count(*) FILTER (WHERE NOT success AND client_ip = $2::inet) AS by_ip
                     FROM w""",
                username, ip, minutes)
        return int(row["by_user"]), int(row["by_ip"])

    async def find_user(self, username: str) -> dict[str, Any] | None:
        async with pool.system_transaction() as conn:
            row = await conn.fetchrow(
                """SELECT u.id, u.username, u.display_name, u.email, u.auth_source, u.password_hash,
                          u.is_active, u.locked_until, u.must_change_password,
                          r.code AS role, r.name AS role_name, r.scope,
                          EXISTS (SELECT 1 FROM user_tenants ut JOIN tenants t ON t.id = ut.tenant_id
                                   WHERE ut.user_id = u.id AND t.is_active) AS has_active_tenant
                     FROM users u JOIN roles r ON r.id = u.role_id
                    WHERE lower(u.username) = lower($1)""", username)
        return dict(row) if row else None

    async def record_attempt(self, username: str, ip: str | None, success: bool, reason: str | None) -> None:
        async with pool.system_transaction() as conn:
            await conn.execute(
                "INSERT INTO login_attempts (username, client_ip, success, reason, auth_source) "
                "VALUES ($1, coalesce($2::inet, '0.0.0.0'::inet), $3, $4, 'local')",
                username[:128], ip, success, reason)

    async def register_failure(self, user_id: int, lockout: dict[str, int]) -> bool:
        """Incrementa o contador; devolve True se a conta acabou de ser bloqueada."""
        async with pool.system_transaction() as conn:
            row = await conn.fetchrow(
                """UPDATE users
                      SET failed_login_count = CASE WHEN failed_login_count + 1 >= $2 THEN 0
                                                    ELSE failed_login_count + 1 END,
                          locked_until = CASE WHEN failed_login_count + 1 >= $2
                                              THEN now() + make_interval(mins => $3) ELSE locked_until END,
                          updated_at = now()
                    WHERE id = $1
                RETURNING locked_until IS NOT NULL AND locked_until > now() AS locked""",
                user_id, lockout["max_failures"], lockout["lock_minutes"])
        return bool(row and row["locked"])

    async def open_session(self, user: dict[str, Any], ip: str | None, ua: str, token_hash: bytes,
                           csrf_hash: bytes, absolute_hours: int, new_hash: str | None) -> datetime:
        async with pool.system_transaction() as conn:
            await conn.execute(
                """UPDATE users SET failed_login_count = 0, locked_until = NULL, last_login_at = now(),
                          last_login_ip = $2::inet, updated_at = now(),
                          password_hash = coalesce($3, password_hash)
                    WHERE id = $1""", user["id"], ip, new_hash)
            expires = await conn.fetchval(
                """INSERT INTO user_sessions (token_hash, user_id, csrf_token_hash, auth_source,
                                              expires_at, client_ip, user_agent)
                   VALUES ($1, $2, $3, 'local', now() + make_interval(hours => $4), $5::inet, $6)
                   RETURNING expires_at""",
                token_hash, user["id"], csrf_hash, absolute_hours, ip, ua)
            await conn.execute(
                """INSERT INTO audit_log (user_id, username, client_ip, user_agent, action, object_type, object_id)
                   VALUES ($1::bigint, $2, $3::inet, $4, 'auth.login', 'user', ($1::bigint)::text)""",
                user["id"], user["username"], ip, ua)
        return expires

    async def load_session(self, token_hash: bytes, idle_minutes: int) -> dict[str, Any] | None:
        async with pool.system_transaction() as conn:
            row = await conn.fetchrow(
                """UPDATE user_sessions s SET last_seen_at = now()
                     FROM users u JOIN roles r ON r.id = u.role_id
                    WHERE s.token_hash = $1 AND u.id = s.user_id
                      AND s.revoked_at IS NULL AND s.expires_at > now()
                      AND s.last_seen_at > now() - make_interval(mins => $2)
                      AND u.is_active
                RETURNING s.csrf_token_hash, s.expires_at, u.id, u.username, u.display_name, u.email,
                          u.auth_source, u.must_change_password, u.last_login_at,
                          r.code AS role, r.name AS role_name, r.scope,
                          ARRAY(SELECT ut.tenant_id FROM user_tenants ut JOIN tenants t ON t.id = ut.tenant_id
                                 WHERE ut.user_id = u.id AND t.is_active ORDER BY t.name) AS tenant_ids,
                          ARRAY(SELECT t.name FROM user_tenants ut JOIN tenants t ON t.id = ut.tenant_id
                                 WHERE ut.user_id = u.id AND t.is_active ORDER BY t.name) AS tenant_names,
                          ARRAY(SELECT rp.permission_code FROM role_permissions rp
                                 WHERE rp.role_id = u.role_id) AS permissions""",
                token_hash, idle_minutes)
        return dict(row) if row else None

    async def password_hash(self, user_id: int) -> str | None:
        async with pool.system_transaction() as conn:
            return await conn.fetchval("SELECT password_hash FROM users WHERE id = $1 AND auth_source = 'local'",
                                       user_id)

    async def change_password(self, user: dict[str, Any], new_hash: str, keep_token_hash: bytes,
                              ip: str | None, ua: str) -> None:
        """Troca a própria senha e encerra as outras sessões do usuário."""
        async with pool.system_transaction() as conn:
            await conn.execute(
                """UPDATE users SET password_hash = $2, must_change_password = false, password_changed_at = now(),
                          failed_login_count = 0, locked_until = NULL, updated_at = now()
                    WHERE id = $1""", user["id"], new_hash)
            await conn.execute(
                "UPDATE user_sessions SET revoked_at = now() WHERE user_id = $1 AND token_hash <> $2 "
                "AND revoked_at IS NULL", user["id"], keep_token_hash)
            await conn.execute(
                """INSERT INTO audit_log (user_id, username, client_ip, user_agent, action, object_type, object_id)
                   VALUES ($1::bigint, $2, $3::inet, $4, 'auth.password_change', 'user', ($1::bigint)::text)""",
                user["id"], user["username"], ip, ua)

    async def revoke_session(self, token_hash: bytes, user: dict[str, Any], ip: str | None, ua: str) -> None:
        async with pool.system_transaction() as conn:
            await conn.execute("UPDATE user_sessions SET revoked_at = now() WHERE token_hash = $1", token_hash)
            await conn.execute(
                """INSERT INTO audit_log (user_id, username, client_ip, user_agent, action, object_type, object_id)
                   VALUES ($1::bigint, $2, $3::inet, $4, 'auth.logout', 'user', ($1::bigint)::text)""",
                user["id"], user["username"], ip, ua)


store: Any = PgAuthStore()


def _db_error(exc: pool.DatabaseUnavailable) -> HTTPException:
    return HTTPException(503, f"Banco de dados indisponível: {exc}")


# -----------------------------------------------------------------------------
# Dependências
# -----------------------------------------------------------------------------
async def current_session(request: Request) -> SessionInfo:
    token = request.cookies.get(COOKIE, "")
    if not token or len(token) > 128:
        raise HTTPException(401, "Sessão expirada. Entre novamente.")
    token_hash = security.sha256(token)
    try:
        settings = await store.settings()
        row = await store.load_session(token_hash, settings["auth.session"]["idle_minutes"])
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    if row is None:
        raise HTTPException(401, "Sessão expirada. Entre novamente.")
    user = {k: row[k] for k in ("id", "username", "display_name", "email", "auth_source", "role",
                                "role_name", "scope", "must_change_password", "last_login_at") if k in row}
    user["tenant_names"] = list(row.get("tenant_names") or [])
    perms = row.get("permissions")
    permissions = frozenset(perms) if perms is not None else BUILTIN_PERMISSIONS.get(user.get("role", ""), frozenset())
    return SessionInfo(token=token, token_hash=token_hash, csrf_hash=row["csrf_token_hash"], user=user,
                       expires_at=row["expires_at"], tenant_ids=list(row.get("tenant_ids") or []),
                       permissions=permissions)


async def require_csrf(session: SessionInfo = Depends(current_session),
                       x_csrf_token: str = Header(default="")) -> SessionInfo:
    if not x_csrf_token or not security.same(security.sha256(x_csrf_token), session.csrf_hash):
        raise HTTPException(403, "Token CSRF inválido.")
    return session


PASSWORD_CHANGE_FIRST = "Troque a sua senha antes de continuar."


def _ready(session: SessionInfo) -> SessionInfo:
    if session.user.get("must_change_password"):
        raise HTTPException(403, PASSWORD_CHANGE_FIRST)
    return session


def require_permission(permission: str, write: bool = False) -> Any:
    """Dependência: sessão válida (CSRF nos métodos de escrita), senha já trocada e a permissão do perfil."""
    async def dep_read(session: SessionInfo = Depends(current_session)) -> SessionInfo:
        return _check(session)

    async def dep_write(session: SessionInfo = Depends(require_csrf)) -> SessionInfo:
        return _check(session)

    def _check(session: SessionInfo) -> SessionInfo:
        _ready(session)
        if not session.can(permission):
            raise HTTPException(403, "Seu perfil não tem acesso a esta função.")
        return session

    return dep_write if write else dep_read


def _public_user(user: dict[str, Any]) -> dict[str, Any]:
    last = user.get("last_login_at")
    return {"id": user["id"], "username": user["username"], "display_name": user.get("display_name"),
            "email": user.get("email"), "role": user["role"], "role_name": user.get("role_name"),
            "scope": user.get("scope"), "must_change_password": bool(user.get("must_change_password")),
            "auth_source": user.get("auth_source", "local"), "tenants": list(user.get("tenant_names") or []),
            "last_login_at": last.isoformat() if isinstance(last, datetime) else last}


# -----------------------------------------------------------------------------
# Rotas
# -----------------------------------------------------------------------------
class LoginForm(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=security.PASSWORD_MAX)


@router.post("/login")
async def login(form: LoginForm, request: Request, response: Response) -> dict[str, Any]:
    ip_text = security.client_ip(request)
    ip = security.inet_or_none(ip_text)
    ua = security.user_agent(request)
    username = form.username.strip()
    try:
        settings = await store.settings()
        lockout = settings["auth.lockout"]
        by_user, by_ip = await store.recent_failures(username, ip, lockout["window_minutes"])
        if by_ip >= IP_MAX_FAILURES:
            authlog.event("auth.rate_limited", ip_text, username=username, source="local")
            raise HTTPException(429, "Muitas tentativas a partir deste endereço. Aguarde alguns minutos.")
        user = await store.find_user(username)
        locked = by_user >= lockout["max_failures"] or bool(
            user and user["locked_until"] and user["locked_until"] > datetime.now(timezone.utc))

        ok, new_hash = False, None
        no_tenant = bool(user and user.get("scope") == "tenant" and not user.get("has_active_tenant", True))
        if user and user["auth_source"] == "local" and user["is_active"] and not locked and not no_tenant:
            ok, new_hash = await asyncio.to_thread(security.verify_password, user["password_hash"], form.password)
        else:
            await asyncio.to_thread(security.verify_password, None, form.password)  # mesmo custo

        if not ok:
            reason = ("locked" if locked else "unknown_user" if not user else
                      "inactive" if not user["is_active"] else
                      "ldap_not_configured" if user["auth_source"] != "local" else
                      "no_active_tenant" if no_tenant else "bad_password")
            await store.record_attempt(username, ip, False, reason)
            just_locked = by_user + 1 >= lockout["max_failures"]
            if user and reason == "bad_password":
                just_locked = await store.register_failure(user["id"], lockout) or just_locked
            authlog.event("auth.locked" if (locked or just_locked) else "auth.failure", ip_text,
                          username=username, source="local", reason=reason)
            if locked:
                raise HTTPException(429, LOCKED_FAIL)
            raise HTTPException(401, GENERIC_FAIL)

        token = security.new_session_token()
        csrf = security.csrf_for(token)
        expires = await store.open_session(user, ip, ua, security.sha256(token), security.sha256(csrf),
                                           settings["auth.session"]["absolute_hours"], new_hash)
        await store.record_attempt(username, ip, True, None)
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc

    authlog.event("auth.success", ip_text, username=user["username"], source="local")
    max_age = max(60, int((expires - datetime.now(timezone.utc)).total_seconds())) \
        if isinstance(expires, datetime) else settings["auth.session"]["absolute_hours"] * 3600
    response.set_cookie(COOKIE, token, max_age=max_age, path="/", secure=True, httponly=True, samesite="strict")
    response.headers["Cache-Control"] = "no-store"
    redirect = "/senha.html" if user.get("must_change_password") else "/home.html"
    return {"user": _public_user(user), "csrf_token": csrf, "redirect": redirect}


@router.get("/me")
async def me(response: Response, session: SessionInfo = Depends(current_session)) -> dict[str, Any]:
    response.headers["Cache-Control"] = "no-store"
    return {"user": _public_user(session.user), "csrf_token": security.csrf_for(session.token),
            "expires_at": session.expires_at.isoformat() if isinstance(session.expires_at, datetime) else None}


@router.post("/logout")
async def logout(request: Request, response: Response,
                 session: SessionInfo = Depends(require_csrf)) -> dict[str, Any]:
    try:
        await store.revoke_session(session.token_hash, session.user,
                                   security.inet_or_none(security.client_ip(request)), security.user_agent(request))
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    authlog.event("auth.logout", security.client_ip(request), username=session.user["username"], source="local")
    response.delete_cookie(COOKIE, path="/", secure=True, httponly=True, samesite="strict")
    return {"ok": True, "redirect": "/login.html"}



class PasswordForm(BaseModel):
    current_password: str = Field(min_length=1, max_length=security.PASSWORD_MAX)
    new_password: str = Field(min_length=1, max_length=security.PASSWORD_MAX)


@router.post("/password")
async def change_password(form: PasswordForm, request: Request,
                          session: SessionInfo = Depends(require_csrf)) -> dict[str, Any]:
    """Troca a própria senha (contas locais). Obrigatória quando o administrador definiu uma senha provisória."""
    user = session.user
    if user.get("auth_source", "local") != "local":
        raise HTTPException(409, "A senha desta conta é gerenciada pelo Active Directory/LDAP.")
    problem = security.password_problem(form.new_password, user["username"])
    if problem:
        raise HTTPException(422, problem)
    if form.new_password == form.current_password:
        raise HTTPException(422, "A nova senha precisa ser diferente da atual.")
    ip_text = security.client_ip(request)
    try:
        stored = await store.password_hash(user["id"])
        ok, _ = await asyncio.to_thread(security.verify_password, stored, form.current_password)
        if not ok:
            authlog.event("auth.password_change_failure", ip_text, username=user["username"], source="local")
            raise HTTPException(422, "A senha atual não confere.")
        new_hash = await asyncio.to_thread(security.hash_password, form.new_password)
        await store.change_password(user, new_hash, session.token_hash, security.inet_or_none(ip_text),
                                    security.user_agent(request))
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    authlog.event("auth.password_change", ip_text, username=user["username"], source="local")
    return {"ok": True, "redirect": "/home.html"}
