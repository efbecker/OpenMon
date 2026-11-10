"""Senhas (Argon2id), tokens de sessão e CSRF."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import secrets

from fastapi import Request

_ARGON2_IMPORT_ERROR = ""
try:
    from argon2 import PasswordHasher  # type: ignore
    from argon2 import exceptions as _argon2_exc  # type: ignore
    # argon2-cffi 21.1 (Debian 13) só tem InvalidHash; InvalidHashError surgiu na 21.2
    InvalidHashError = getattr(_argon2_exc, "InvalidHashError", None) or _argon2_exc.InvalidHash
    VerificationError = _argon2_exc.VerificationError
    VerifyMismatchError = _argon2_exc.VerifyMismatchError
except (ImportError, AttributeError) as _exc:  # pragma: no cover - python3-argon2 é obrigatório
    PasswordHasher = None  # type: ignore
    _ARGON2_IMPORT_ERROR = f"{type(_exc).__name__}: {_exc}"

PASSWORD_MIN = 12
PASSWORD_MAX = 256

# Argon2id com os parâmetros recomendados (RFC 9106, perfil de memória 64 MiB)
_hasher = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=4) if PasswordHasher else None
# Hash fixo para gastar o mesmo tempo quando o usuário não existe (evita enumeração por tempo)
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16)) if _hasher else ""


def _require_hasher() -> PasswordHasher:
    if _hasher is None:
        raise RuntimeError("biblioteca Argon2 indisponível (pacote python3-argon2): " + _ARGON2_IMPORT_ERROR)
    return _hasher


def hash_password(password: str) -> str:
    return _require_hasher().hash(password)


def verify_password(stored_hash: str | None, password: str) -> tuple[bool, str | None]:
    """(confere?, novo_hash se os parâmetros mudaram). Bcrypt legado não é aceito por enquanto."""
    h = _require_hasher()
    if not stored_hash or not stored_hash.startswith("$argon2id$"):
        try:
            h.verify(_DUMMY_HASH, password)
        except VerificationError:
            pass
        return False, None
    try:
        h.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False, None
    return True, (h.hash(password) if h.check_needs_rehash(stored_hash) else None)


def password_problem(password: str, username: str = "") -> str | None:
    if len(password) < PASSWORD_MIN:
        return f"A senha precisa ter pelo menos {PASSWORD_MIN} caracteres."
    if len(password) > PASSWORD_MAX:
        return f"A senha pode ter no máximo {PASSWORD_MAX} caracteres."
    if username and username.lower() in password.lower():
        return "A senha não pode conter o nome de usuário."
    if len(set(password)) < 6:
        return "A senha é repetitiva demais."
    return None


# -----------------------------------------------------------------------------
# Sessão e CSRF
# -----------------------------------------------------------------------------
def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def sha256(value: str) -> bytes:
    return hashlib.sha256(value.encode()).digest()


def csrf_for(session_token: str) -> str:
    """Token CSRF derivado do token de sessão: o JS recebe pelo /me, o cookie continua HttpOnly."""
    return hmac.new(session_token.encode(), b"openmon-csrf-v1", hashlib.sha256).hexdigest()


def same(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


# -----------------------------------------------------------------------------
# Requisição
# -----------------------------------------------------------------------------
def client_ip(request: Request) -> str:
    """IP do cliente (o uvicorn já aplica o X-Forwarded-For que o Apache reescreve)."""
    return request.client.host if request.client else "unknown"


def inet_or_none(ip: str) -> str | None:
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return None


def user_agent(request: Request) -> str:
    return request.headers.get("user-agent", "")[:300]
