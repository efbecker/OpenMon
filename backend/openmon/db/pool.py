"""Acesso ao banco pela API (asyncpg, TLS verify-full, contexto de RLS por transação).

A configuração vem de ``/etc/openmon/database/database.conf``, gravada pelo deploy
do banco. O pool é criado na primeira consulta, então a API sobe normalmente
antes de o banco existir (assistente de instalação).

Toda consulta roda dentro de :func:`transaction`, que chama
``openmon.set_request_context`` com ``SET LOCAL`` (vale só para a transação):
uma conexão devolvida ao pool nunca carrega o contexto de outro usuário.
"""
from __future__ import annotations

import asyncio
import configparser
import os
import ssl
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from openmon import config


class DatabaseUnavailable(RuntimeError):
    """Banco não configurado ou inacessível."""


def describe_connect_error(exc: BaseException) -> str:
    """Mensagem útil (sem segredos) para falhas ao conectar no PostgreSQL da VM 2."""
    name = type(exc).__name__
    text = str(exc).splitlines()[0][:200] if str(exc) else ""
    if name == "InvalidPasswordError":
        return ("o banco recusou a senha do papel openmon_app; refaça o deploy do banco "
                "(isso regrava /etc/openmon/database/database.conf)")
    if name == "InvalidAuthorizationSpecificationError":
        return (f"o pg_hba.conf do Servidor 2 recusou a conexão deste servidor ({text}); confira o "
                "\"IP do Servidor 1\" usado no deploy")
    if isinstance(exc, ssl.SSLCertVerificationError):
        return f"o certificado TLS do banco não confere com a CA em /etc/openmon/database/pki ({text})"
    if isinstance(exc, (ConnectionRefusedError, asyncio.TimeoutError, TimeoutError)):
        return f"o PostgreSQL do Servidor 2 não respondeu ({name}); confira se ele está ativo e acessível"
    return f"não foi possível conectar ao banco ({name}: {text})"


@dataclass(frozen=True)
class DbSettings:
    host: str
    port: int
    name: str
    user: str
    password: str
    sslmode: str
    sslrootcert: str

    def ssl_context(self) -> ssl.SSLContext:
        if self.sslmode != "verify-full":
            raise DatabaseUnavailable("database.conf: só sslmode=verify-full é aceito")
        ctx = ssl.create_default_context(cafile=self.sslrootcert)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx


def load_settings(path: Path | None = None) -> DbSettings:
    path = path or config.db_config_dir() / "database.conf"
    parser = configparser.ConfigParser(interpolation=None)
    try:
        with path.open(encoding="utf-8") as fh:
            parser.read_file(fh)
        s = parser["database"]
        return DbSettings(host=s["host"], port=int(s.get("port", "5432")), name=s.get("name", "openmon"),
                          user=s["user"], password=s["password"], sslmode=s.get("sslmode", "verify-full"),
                          sslrootcert=s["sslrootcert"])
    except FileNotFoundError as exc:
        raise DatabaseUnavailable("o banco de dados ainda não foi provisionado") from exc
    except (KeyError, ValueError, configparser.Error) as exc:
        raise DatabaseUnavailable(f"database.conf inválido: {type(exc).__name__}") from exc


_pool: Any = None
_lock = asyncio.Lock()


async def get_pool() -> Any:
    global _pool
    if _pool is not None:
        return _pool
    async with _lock:
        if _pool is None:
            try:
                import asyncpg  # type: ignore
            except ImportError as exc:
                raise DatabaseUnavailable("python3-asyncpg não está instalado") from exc
            s = load_settings()
            try:
                _pool = await asyncpg.create_pool(
                    host=s.host, port=s.port, database=s.name, user=s.user, password=s.password,
                    ssl=s.ssl_context(), min_size=0, max_size=int(os.environ.get("OPENMON_DB_POOL_MAX", "10")), timeout=10,
                    command_timeout=int(os.environ.get("OPENMON_DB_COMMAND_TIMEOUT", "30")),
                    max_inactive_connection_lifetime=300,
                    server_settings={"application_name": "openmon-api", "search_path": "openmon"})
            except Exception as exc:  # asyncpg.PostgresError, OSError, ssl.SSLError...
                raise DatabaseUnavailable(describe_connect_error(exc)) from exc
    return _pool


async def close_pool() -> None:
    global _pool
    if _pool is not None:
        pool, _pool = _pool, None
        await pool.close()


@asynccontextmanager
async def transaction(user_id: int | None = None, is_global: bool = False,
                      tenant_ids: Sequence[int] = ()) -> AsyncIterator[Any]:
    """Conexão com transação aberta e o contexto de RLS da requisição aplicado."""
    pool = await get_pool()
    try:
        conn_cm = pool.acquire()
        conn = await conn_cm.__aenter__()
    except Exception as exc:  # a conexão só é aberta aqui (min_size=0)
        raise DatabaseUnavailable(describe_connect_error(exc)) from exc
    try:
        async with conn.transaction():
            await conn.execute("SELECT openmon.set_request_context($1, $2, $3)",
                               user_id, is_global, list(tenant_ids))
            yield conn
    finally:
        await conn_cm.__aexit__(None, None, None)


def system_transaction() -> Any:
    """Contexto global para autenticação e tarefas internas (sem usuário logado)."""
    return transaction(None, True, ())
