"""Assistente de instalação: deploy do banco (VM 2) pela interface web.

Enquanto o OpenMon não tem banco nem usuários, a interface é protegida por um
token de instalação de uso único, gerado pelo instalador em
``/var/lib/openmon/setup.token`` e mostrado no final do ``curl | bash`` (mesmo
padrão de outras plataformas na primeira execução). O token:

* vai no cabeçalho ``X-Setup-Token`` (não em cookie, então não há CSRF);
* é comparado em tempo constante; erros contam para o rate limit por IP e são
  registrados em ``auth.log`` para o Fail2ban;
* continua válido depois do deploy, para a etapa seguinte: criar o primeiro
  administrador global. Só então é apagado e ``setup.done`` é gravado; a partir
  daí a interface leva direto para a tela de login.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import re
import time
from collections import defaultdict, deque
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field, SecretStr, field_validator

from openmon import config
from openmon.api import authlog, security
from openmon.db import pool
from openmon.deploy import provisioner
from openmon.deploy.provisioner import DeployError, DeployRequest, deploy_async
from openmon.deploy.ssh import SshError, SshTarget, fetch_host_key

router = APIRouter(prefix="/api/setup", tags=["setup"])

MAX_FAILURES = 10
FAILURE_WINDOW_S = 15 * 60
_failures: dict[str, deque[float]] = defaultdict(deque)

_FPR_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
_USER_RE = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$")


# -----------------------------------------------------------------------------
# Token de instalação
# -----------------------------------------------------------------------------
def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _read_token() -> str | None:
    try:
        token = config.setup_token_file().read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return None
    return token or None


def _too_many_failures(ip: str) -> bool:
    q = _failures[ip]
    now = time.monotonic()
    while q and now - q[0] > FAILURE_WINDOW_S:
        q.popleft()
    return len(q) >= MAX_FAILURES


def require_setup_token(request: Request, x_setup_token: str = Header(default="")) -> None:
    ip = client_ip(request)
    expected = _read_token()
    if expected is None:
        raise HTTPException(403, "O assistente de instalação está encerrado. Entre pela tela de login; "
                                 "para refazer o deploy do banco, rode o instalador com --new-setup-token.")
    if _too_many_failures(ip):
        authlog.event("auth.rate_limited", ip, username="setup-token", source="setup")
        raise HTTPException(429, "Muitas tentativas inválidas. Aguarde 15 minutos.")
    if not hmac.compare_digest(hashlib.sha256(x_setup_token.encode()).digest(),
                               hashlib.sha256(expected.encode()).digest()):
        _failures[ip].append(time.monotonic())
        authlog.event("auth.failure", ip, username="setup-token", source="setup", reason="bad_setup_token")
        raise HTTPException(401, "Token de instalação inválido.")


# -----------------------------------------------------------------------------
# Modelos
# -----------------------------------------------------------------------------
class SshForm(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(default="root")
    password: SecretStr = Field(default=SecretStr(""), max_length=256)
    sudo_password: SecretStr | None = Field(default=None, max_length=256)
    fingerprint: str | None = None

    @field_validator("host")
    @classmethod
    def _host(cls, v: str) -> str:
        try:
            return provisioner.validate_host(v)
        except DeployError as exc:
            raise ValueError(str(exc)) from exc

    @field_validator("username")
    @classmethod
    def _user(cls, v: str) -> str:
        if not _USER_RE.match(v):
            raise ValueError("usuário SSH inválido")
        return v

    @field_validator("fingerprint")
    @classmethod
    def _fpr(cls, v: str | None) -> str | None:
        if v is not None and not _FPR_RE.match(v):
            raise ValueError("impressão digital SSH inválida")
        return v

    def target(self) -> SshTarget:
        sudo = self.sudo_password.get_secret_value() if self.sudo_password else None
        return SshTarget(host=self.host, port=self.port, username=self.username,
                         password=self.password.get_secret_value() or None,
                         host_fingerprint=self.fingerprint or "", sudo_password=sudo or None)


class DeployForm(SshForm):
    frontend_address: str = Field(min_length=1, max_length=64)

    @field_validator("frontend_address")
    @classmethod
    def _cidr(cls, v: str | None) -> str | None:
        if v in (None, ""):
            return None
        try:
            return provisioner.normalize_cidr(v)
        except DeployError as exc:
            raise ValueError(str(exc)) from exc


class HostForm(BaseModel):
    host: str = Field(min_length=1, max_length=253)


# -----------------------------------------------------------------------------
# Estado do deploy (um por vez; a API roda com 1 worker)
# -----------------------------------------------------------------------------
class DeployJob:
    MAX_EVENTS = 5000

    def __init__(self) -> None:
        self.status = "idle"  # idle | running | success | failed
        self.events: list[dict[str, Any]] = []
        self.result: dict[str, Any] | None = None
        self.started_at: float | None = None
        self.task: asyncio.Task | None = None

    def snapshot(self, since: int = 0) -> dict[str, Any]:
        since = max(0, min(since, len(self.events)))
        return {"status": self.status, "events": self.events[since:], "next": len(self.events),
                "result": self.result}

    async def run(self, request: DeployRequest) -> None:
        def on_event(ev: provisioner.DeployEvent) -> None:
            if len(self.events) < self.MAX_EVENTS:
                self.events.append(ev.as_dict())

        try:
            result = await deploy_async(request, on_event)
        except Exception as exc:  # erro inesperado: nunca deixar o job "running"
            self.status = "failed"
            self.result = {"error": f"erro interno: {type(exc).__name__}"}
            return
        self.result = {
            "success": result.success, "error": result.error, "host": result.host, "port": result.port,
            "database": result.database, "info": result.info, "warnings": result.warnings,
            "tuning": result.tuning,
        }
        self.status = "success" if result.success else "failed"
        if result.success:
            await pool.close_pool()  # próxima consulta usa a configuração recém-gravada


job = DeployJob()


# -----------------------------------------------------------------------------
# Rotas
# -----------------------------------------------------------------------------
@router.get("/status")
async def status() -> dict[str, Any]:
    return {"setup_open": _read_token() is not None, "db_provisioned": config.db_provisioned(),
            "admin_created": config.admin_created(), "deploy_status": job.status}


@router.post("/token/verify", dependencies=[Depends(require_setup_token)])
async def verify_token() -> dict[str, bool]:
    return {"ok": True}


@router.post("/database/frontend-ip", dependencies=[Depends(require_setup_token)])
async def frontend_ip(form: HostForm) -> dict[str, str | None]:
    try:
        host = provisioner.validate_host(form.host)
    except DeployError as exc:
        raise HTTPException(422, str(exc)) from exc
    return {"ip": await asyncio.to_thread(provisioner.route_source_ip, host)}


@router.post("/database/ssh-test", dependencies=[Depends(require_setup_token)])
async def ssh_test(form: SshForm, request: Request) -> dict[str, Any]:
    """Sem fingerprint: só lê a chave do host (nada é enviado). Com fingerprint: autentica e verifica."""
    try:
        if not form.fingerprint:
            key = await asyncio.to_thread(fetch_host_key, form.host, form.port)
            return {"stage": "fingerprint", "key_type": key.key_type, "fingerprint": key.fingerprint}
        if not form.password.get_secret_value():
            raise HTTPException(422, "Informe a senha SSH.")
        info = await asyncio.to_thread(provisioner.probe_target, form.target())
    except (SshError, DeployError) as exc:
        authlog.event("setup.ssh_test", client_ip(request), host=form.host, ok=False)
        raise HTTPException(400, str(exc)) from exc
    authlog.event("setup.ssh_test", client_ip(request), host=form.host, ok=True)
    return {"stage": "verified", "fingerprint": form.fingerprint, **info}


@router.post("/database/deploy", dependencies=[Depends(require_setup_token)], status_code=202)
async def start_deploy(form: DeployForm, request: Request) -> dict[str, Any]:
    if job.status == "running":
        raise HTTPException(409, "Já existe um deploy em andamento.")
    if not form.fingerprint:
        raise HTTPException(422, "Teste a conexão SSH e confirme a impressão digital antes do deploy.")
    if not form.password.get_secret_value():
        raise HTTPException(422, "Informe a senha SSH.")
    req = DeployRequest(
        ssh=form.target(),
        frontend_address=form.frontend_address,
        config_dir=config.db_config_dir(),
    )
    job.status, job.events, job.result, job.started_at = "running", [], None, time.time()
    job.task = asyncio.create_task(job.run(req))
    authlog.event("setup.db_deploy", client_ip(request), host=form.host, frontend=form.frontend_address)
    return {"status": "running"}


@router.get("/database/deploy", dependencies=[Depends(require_setup_token)])
async def deploy_progress(since: int = 0) -> dict[str, Any]:
    return job.snapshot(since)


# -----------------------------------------------------------------------------
# Primeiro administrador (última etapa do assistente)
# -----------------------------------------------------------------------------
_ADMIN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@-]{2,63}$")
_ADMIN_LOCK = 0x4F4D_0001  # pg_advisory_xact_lock: dois navegadores não criam dois "primeiros" admins


class AdminForm(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    display_name: str | None = Field(default=None, max_length=128)
    email: str | None = Field(default=None, max_length=254)
    password: SecretStr = Field(max_length=security.PASSWORD_MAX)
    password_confirm: SecretStr = Field(max_length=security.PASSWORD_MAX)

    @field_validator("username")
    @classmethod
    def _username(cls, v: str) -> str:
        v = v.strip()
        if not _ADMIN_RE.match(v):
            raise ValueError("use 3 a 64 caracteres: letras, números, ponto, hífen, sublinhado ou @")
        return v

    @field_validator("display_name", "email")
    @classmethod
    def _optional(cls, v: str | None) -> str | None:
        v = (v or "").strip()
        return v or None

    @field_validator("email")
    @classmethod
    def _email(cls, v: str | None) -> str | None:
        if v is not None and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v):
            raise ValueError("e-mail inválido")
        return v


def _close_setup() -> None:
    state = config.state_dir()
    tmp = state / ".setup.done.tmp"
    tmp.write_text(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) + "\n", encoding="utf-8")
    tmp.replace(config.setup_done_file())
    config.setup_token_file().unlink(missing_ok=True)


def _require_db() -> None:
    if job.status == "running":
        raise HTTPException(409, "O deploy do banco ainda está em andamento.")
    if not config.db_provisioned():
        raise HTTPException(409, "Faça o deploy do banco de dados antes de criar o administrador.")


async def users_exist() -> bool:
    async with pool.system_transaction() as conn:
        return bool(await conn.fetchval("SELECT EXISTS (SELECT 1 FROM users)"))


async def create_first_admin(form: AdminForm, password_hash: str, ip: str | None, ua: str) -> int | None:
    """Cria o administrador global; None se já existir algum usuário."""
    async with pool.system_transaction() as conn:
        await conn.execute("SELECT pg_advisory_xact_lock($1)", _ADMIN_LOCK)
        if await conn.fetchval("SELECT EXISTS (SELECT 1 FROM users)"):
            return None
        user_id = await conn.fetchval(
            """INSERT INTO users (username, display_name, email, auth_source, password_hash, role_id,
                                  password_changed_at)
               SELECT $1, $2, $3, 'local', $4, r.id, now() FROM roles r WHERE r.code = 'global_admin'
               RETURNING id""",
            form.username, form.display_name, form.email, password_hash)
        await conn.execute(
            """INSERT INTO audit_log (user_id, username, client_ip, user_agent, action, object_type, object_id, details)
               VALUES ($1::bigint, $2, $3::inet, $4, 'setup.admin_create', 'user', ($1::bigint)::text, '{"role":"global_admin"}')""",
            user_id, form.username, ip, ua)
        return user_id


@router.get("/admin", dependencies=[Depends(require_setup_token)])
async def admin_needed() -> dict[str, bool]:
    _require_db()
    try:
        return {"needed": not await users_exist()}
    except pool.DatabaseUnavailable as exc:
        raise HTTPException(503, f"Banco de dados indisponível: {exc}") from exc


@router.post("/admin", dependencies=[Depends(require_setup_token)], status_code=201)
async def create_admin(form: AdminForm, request: Request) -> dict[str, Any]:
    _require_db()
    password = form.password.get_secret_value()
    if password != form.password_confirm.get_secret_value():
        raise HTTPException(422, "As senhas não conferem.")
    problem = security.password_problem(password, form.username)
    if problem:
        raise HTTPException(422, problem)
    ip = client_ip(request)
    try:
        password_hash = await asyncio.to_thread(security.hash_password, password)
    except RuntimeError as exc:  # python3-argon2 ausente
        raise HTTPException(503, f"Não foi possível gerar o hash da senha: {exc}.") from exc
    try:
        user_id = await create_first_admin(form, password_hash, security.inet_or_none(ip),
                                           security.user_agent(request))
    except pool.DatabaseUnavailable as exc:
        raise HTTPException(503, f"Banco de dados indisponível: {exc}") from exc
    except Exception as exc:
        sqlstate = getattr(exc, "sqlstate", None)
        if sqlstate is None:
            raise
        # Erro do PostgreSQL (permissão, schema, restrição): mostra a causa, sem dados sensíveis
        authlog.event("setup.admin_failed", ip, username=form.username, source="setup", sqlstate=sqlstate)
        raise HTTPException(500, f"O banco recusou a criação do administrador ({sqlstate}: "
                                 f"{str(exc).splitlines()[0][:200]}).") from exc
    if user_id is None:
        raise HTTPException(409, "Já existe um administrador. Use \"Ir para o login\".")
    _close_setup()
    authlog.event("setup.admin_created", ip, username=form.username, source="setup")
    return {"ok": True, "username": form.username, "redirect": "/login.html"}


@router.post("/finish", dependencies=[Depends(require_setup_token)])
async def finish_setup(request: Request) -> dict[str, Any]:
    """Encerra o assistente quando o administrador já existe (ex.: deploy refeito com --new-setup-token)."""
    _require_db()
    try:
        exists = await users_exist()
    except pool.DatabaseUnavailable as exc:
        raise HTTPException(503, f"Banco de dados indisponível: {exc}") from exc
    if not exists:
        raise HTTPException(409, "Crie o administrador antes de encerrar o assistente.")
    _close_setup()
    authlog.event("setup.finished", client_ip(request), source="setup")
    return {"ok": True, "redirect": "/login.html"}
