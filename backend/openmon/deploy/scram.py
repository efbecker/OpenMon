"""Geração de verificadores SCRAM-SHA-256 do PostgreSQL na VM 1.

A senha em texto puro dos papéis do banco nunca sai da VM 1: o deployer envia
para a VM 2 apenas o verificador (``SCRAM-SHA-256$4096:salt$StoredKey:ServerKey``),
no mesmo formato que o PostgreSQL grava em ``pg_authid``. Assim a senha não
aparece em logs de statement, histórico do psql nem em arquivos temporários.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import string

ITERATIONS = 4096  # padrão do PostgreSQL (scram_iterations)

_ALPHABET = string.ascii_letters + string.digits


def generate_password(length: int = 32) -> str:
    """Senha aleatória só com caracteres seguros para arquivos de configuração."""
    if length < 20:
        raise ValueError("senha muito curta")
    return "".join(secrets.choice(_ALPHABET) for _ in range(length))


def scram_sha256_verifier(password: str, *, salt: bytes | None = None, iterations: int = ITERATIONS) -> str:
    salt = salt if salt is not None else secrets.token_bytes(16)
    salted = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    b64 = lambda b: base64.b64encode(b).decode("ascii")  # noqa: E731
    return f"SCRAM-SHA-256${iterations}:{b64(salt)}${b64(stored_key)}:{b64(server_key)}"
