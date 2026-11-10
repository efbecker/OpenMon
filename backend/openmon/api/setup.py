"""Assistente de instalação: deploy do banco (VM 2) pela interface web.

Enquanto o OpenMon não tem banco nem usuários, a interface é protegida por um
token de instalação de uso único, gerado pelo instalador em
``/var/lib/openmon/setup.token`` e mostrado no final do ``curl | bash`` (mesmo
padrão de outras plataformas na primeira execução). O token:

* vai no cabeçalho ``X-Setup-Token`` (não em cookie, então não há CSRF);
* é comparado em tempo constante; erros contam para o rate limit por IP e são
  registrados em ``auth.log`` para o Fail2ban;
* é apagado quando o deploy do banco termina com sucesso, fechando o assistente.
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
from openmon.api import authlog
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
        raise HTTPException(403, "O assistente de instalação está encerrado: o banco já foi provisionado. "
                                 "Para refazer, rode o instalador com --new-setup-token.")
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
    ssh_allow: str | None = Field(default=None, max_length=64)

    @field_validator("frontend_address", "ssh_allow")
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
        self.closed_token_hash: bytes | None = None

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
            # Fecha o assistente; quem acompanhava o deploy ainda lê o resultado final
            token = _read_token()
            if token:
                self.closed_token_hash = hashlib.sha256(token.encode()).digest()
            config.setup_token_file().unlink(missing_ok=True)


job = DeployJob()


# -----------------------------------------------------------------------------
# Rotas
# -----------------------------------------------------------------------------
@router.get("/status")
async def status() -> dict[str, Any]:
    return {"setup_open": _read_token() is not None, "db_provisioned": config.db_provisioned(),
            "deploy_status": job.status}


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
        ssh_allow_cidrs=[form.ssh_allow] if form.ssh_allow else [],
        config_dir=config.db_config_dir(),
    )
    job.status, job.events, job.result, job.started_at = "running", [], None, time.time()
    job.task = asyncio.create_task(job.run(req))
    authlog.event("setup.db_deploy", client_ip(request), host=form.host, frontend=form.frontend_address)
    return {"status": "running"}


def require_progress_access(request: Request, x_setup_token: str = Header(default="")) -> None:
    """O andamento continua legível com o token que acabou de ser consumido pelo deploy."""
    if _read_token() is None and job.closed_token_hash is not None and hmac.compare_digest(
            hashlib.sha256(x_setup_token.encode()).digest(), job.closed_token_hash):
        return
    require_setup_token(request, x_setup_token)


@router.get("/database/deploy", dependencies=[Depends(require_progress_access)])
async def deploy_progress(since: int = 0) -> dict[str, Any]:
    return job.snapshot(since)
