"""Cofre de credenciais: AES-256-GCM com a chave mestra de /etc/openmon/master.key.

* O banco guarda só ``nonce`` + ``ciphertext`` (com a tag de 16 bytes) em
  ``credentials``; a cifragem acontece aqui, na VM 1.
* AAD: ``openmon:cred:v1:<id>:<kind>`` amarra o segredo à linha e ao tipo: um
  ciphertext copiado para outra credencial não decifra.
* ``vault_keys`` guarda ``HMAC-SHA256(chave, 'openmon-key-check')`` da versão da
  chave, para avisar com clareza quando o arquivo de chave carregado não é o que
  cifrou os segredos (ex.: VM 1 reinstalada sem restaurar a chave).
"""
from __future__ import annotations

import configparser
import hashlib
import hmac
import os
import uuid
from pathlib import Path
from typing import Any

KEY_VERSION = 1
_CHECK_MSG = b"openmon-key-check"


class VaultError(RuntimeError):
    """Chave mestra ausente/errada ou segredo que não decifra."""


def key_file() -> Path:
    env = os.environ.get("OPENMON_MASTER_KEY_FILE")
    if env:
        return Path(env)
    conf = Path(os.environ.get("OPENMON_CONFIG", "/etc/openmon/openmon.conf"))
    parser = configparser.ConfigParser(interpolation=None)
    try:
        with conf.open(encoding="utf-8") as fh:
            parser.read_file(fh)
        return Path(parser["app"]["master_key_file"])
    except (OSError, KeyError, configparser.Error):
        return Path("/etc/openmon/master.key")


_key: bytes | None = None


def master_key() -> bytes:
    global _key
    if _key is None:
        path = key_file()
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise VaultError(f"chave mestra indisponível em {path} ({type(exc).__name__}); "
                             "rode o instalador de novo") from exc
        if len(data) != 32:
            raise VaultError(f"chave mestra em {path} precisa ter 32 bytes (tem {len(data)})")
        _key = data
    return _key


def reset() -> None:  # testes
    global _key
    _key = None


def key_check(key: bytes | None = None) -> bytes:
    return hmac.new(key or master_key(), _CHECK_MSG, hashlib.sha256).digest()


def _aad(cred_id: str, kind: str) -> bytes:
    return f"openmon:cred:v1:{cred_id}:{kind}".encode()


def _aesgcm() -> Any:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:  # pragma: no cover - python3-cryptography é obrigatório
        raise VaultError("biblioteca de criptografia indisponível (pacote python3-cryptography)") from exc
    return AESGCM(master_key())


def encrypt(cred_id: str, kind: str, secret: str) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    return nonce, _aesgcm().encrypt(nonce, secret.encode(), _aad(cred_id, kind))


def decrypt(cred_id: str, kind: str, nonce: bytes, ciphertext: bytes) -> str:
    try:
        from cryptography.exceptions import InvalidTag
    except ImportError as exc:  # pragma: no cover
        raise VaultError("biblioteca de criptografia indisponível") from exc
    try:
        return _aesgcm().decrypt(bytes(nonce), bytes(ciphertext), _aad(cred_id, kind)).decode()
    except InvalidTag as exc:
        raise VaultError("o segredo não decifra com a chave mestra atual (chave trocada?)") from exc


# -----------------------------------------------------------------------------
# Banco (conexão com contexto global; credentials e vault_keys têm RLS)
# -----------------------------------------------------------------------------
async def ensure_key(conn: Any) -> int:
    """Registra a versão da chave na primeira vez e confere nas seguintes."""
    check = key_check()
    row = await conn.fetchrow("SELECT key_check FROM vault_keys WHERE version = $1", KEY_VERSION)
    if row is None:
        await conn.execute("INSERT INTO vault_keys (version, key_check) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                           KEY_VERSION, check)
        row = await conn.fetchrow("SELECT key_check FROM vault_keys WHERE version = $1", KEY_VERSION)
    if not hmac.compare_digest(bytes(row["key_check"]), check):
        raise VaultError("a chave mestra deste servidor não é a que cifrou o cofre "
                         "(restaure /etc/openmon/master.key do backup)")
    return KEY_VERSION


async def save(conn: Any, *, kind: str, name: str, secret: str, username: str | None = None,
               tenant_id: int | None = None, created_by: int | None = None, cred_id: str | None = None) -> str:
    """Cria ou substitui (mesmo id) uma credencial; devolve o id."""
    version = await ensure_key(conn)
    cid = cred_id or str(uuid.uuid4())
    nonce, ct = encrypt(cid, kind, secret)
    await conn.execute(
        """INSERT INTO credentials (id, tenant_id, name, kind, username, key_version, nonce, ciphertext, created_by)
           VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9)
           ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, username = EXCLUDED.username,
                 key_version = EXCLUDED.key_version, nonce = EXCLUDED.nonce, ciphertext = EXCLUDED.ciphertext,
                 updated_at = now(), rotated_at = now()""",
        cid, tenant_id, name, kind, username, version, nonce, ct, created_by)
    return cid


async def set_username(conn: Any, cred_id: str, username: str | None) -> None:
    await conn.execute("UPDATE credentials SET username = $2, updated_at = now() WHERE id = $1::uuid",
                       cred_id, username)


async def load(conn: Any, cred_id: str) -> tuple[str | None, str]:
    """(username, segredo)."""
    row = await conn.fetchrow(
        "SELECT id::text AS id, kind, username, key_version, nonce, ciphertext FROM credentials WHERE id = $1::uuid",
        cred_id)
    if row is None:
        raise VaultError("credencial não encontrada")
    await ensure_key(conn)
    return row["username"], decrypt(row["id"], row["kind"], row["nonce"], row["ciphertext"])
