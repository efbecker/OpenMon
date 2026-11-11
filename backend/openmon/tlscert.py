"""Certificado digital do domínio (HTTPS do Apache na VM 1): validação e leitura.

Usado pela API (ao receber os arquivos) e pelo ``openmon-tls`` (root, antes de
gravar no Apache). Só aceita chave privada sem senha, que precisa casar com o
certificado; o domínio precisa estar nos nomes cobertos (curingas valem).
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
MAX_PEM = 200_000


class CertError(ValueError):
    """Arquivo inválido, com mensagem para a tela."""


def _x509() -> Any:
    from cryptography import x509
    return x509


def _load_certs(pem: str, what: str) -> list[Any]:
    x509 = _x509()
    data = (pem or "").strip()
    if not data:
        return []
    if len(data) > MAX_PEM:
        raise CertError(f"{what}: arquivo grande demais.")
    if "-----BEGIN" not in data:
        # .crt/.cer em DER (binário) chega aqui em base64 pela tela
        raise CertError(f"{what}: envie em formato PEM (texto começando com -----BEGIN CERTIFICATE-----).")
    try:
        certs = x509.load_pem_x509_certificates(data.encode())
    except ValueError as exc:
        raise CertError(f"{what}: não foi possível ler o certificado ({exc}).") from exc
    return certs


def _load_key(pem: str) -> Any:
    from cryptography.hazmat.primitives import serialization
    data = (pem or "").strip()
    if not data:
        raise CertError("Envie a chave privada.")
    if len(data) > MAX_PEM:
        raise CertError("Chave privada: arquivo grande demais.")
    if "ENCRYPTED" in data:
        raise CertError("A chave privada está protegida por senha. Envie a chave sem senha "
                        "(openssl pkey -in chave.key -out chave-sem-senha.key).")
    try:
        return serialization.load_pem_private_key(data.encode(), password=None)
    except TypeError as exc:
        raise CertError("A chave privada está protegida por senha. Envie a chave sem senha.") from exc
    except ValueError as exc:
        raise CertError("Chave privada inválida: envie o arquivo PEM/KEY (-----BEGIN PRIVATE KEY-----).") from exc


def _pub(obj: Any) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return obj.public_key().public_bytes(serialization.Encoding.DER,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)


def _cn(name: Any) -> str:
    from cryptography.x509.oid import NameOID
    for oid in (NameOID.COMMON_NAME, NameOID.ORGANIZATION_NAME):
        attrs = name.get_attributes_for_oid(oid)
        if attrs:
            return str(attrs[0].value)
    return name.rfc4514_string()


def names(cert: Any) -> list[str]:
    x509 = _x509()
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns = [str(n) for n in san.get_values_for_type(x509.DNSName)]
        ips = [str(n) for n in san.get_values_for_type(x509.IPAddress)]
        if dns or ips:
            return dns + ips
    except x509.ExtensionNotFound:
        pass
    return [_cn(cert.subject)]


def covers(cert_names: list[str], domain: str) -> bool:
    d = domain.lower()
    for n in cert_names:
        n = n.lower()
        if n == d:
            return True
        # *.empresa.com.br cobre um nível só (app.empresa.com.br), como os navegadores
        if n.startswith("*."):
            suffix = n[1:]
            label = d[: -len(suffix)] if d.endswith(suffix) else ""
            if label and "." not in label:
                return True
    return False


def _utc(cert: Any, attr: str) -> datetime:
    v = getattr(cert, attr + "_utc", None)
    return v if v is not None else getattr(cert, attr).replace(tzinfo=timezone.utc)


def describe(cert: Any) -> dict[str, Any]:
    from cryptography.hazmat.primitives import hashes
    nb, na = _utc(cert, "not_valid_before"), _utc(cert, "not_valid_after")
    fp = cert.fingerprint(hashes.SHA256()).hex().upper()
    return {"subject": _cn(cert.subject), "issuer": _cn(cert.issuer), "names": names(cert),
            "not_before": nb.isoformat(), "not_after": na.isoformat(),
            "days_left": (na - datetime.now(timezone.utc)).days,
            "sha256": ":".join(fp[i:i + 2] for i in range(0, len(fp), 2)),
            "self_signed": cert.issuer == cert.subject}


def validate(domain: str, cert_pem: str, key_pem: str, chain_pem: str = "") -> dict[str, Any]:
    """Confere tudo e devolve {domain, fullchain, key, info, chain_count}. Erros: CertError."""
    from cryptography.hazmat.primitives import serialization
    domain = (domain or "").strip().lower().rstrip(".")
    if not DOMAIN_RE.match(domain):
        raise CertError("Domínio inválido: use o nome completo, por exemplo openmon.empresa.com.br.")
    certs = _load_certs(cert_pem, "Certificado")
    if not certs:
        raise CertError("Envie o certificado (PEM ou CRT).")
    extra = _load_certs(chain_pem, "Cadeia intermediária")
    key = _load_key(key_pem)
    leaf_idx = next((i for i, c in enumerate(certs) if _pub(c) == _pub(key)), None)
    if leaf_idx is None:
        raise CertError("A chave privada não corresponde ao certificado enviado.")
    leaf = certs[leaf_idx]
    others = [c for i, c in enumerate(certs) if i != leaf_idx]
    seen = {c.fingerprint(_sha()) for c in [leaf] + others}
    for c in extra:
        if c.fingerprint(_sha()) not in seen:
            others.append(c)
            seen.add(c.fingerprint(_sha()))
    now = datetime.now(timezone.utc)
    if _utc(leaf, "not_valid_after") <= now:
        raise CertError(f"O certificado venceu em {_utc(leaf, 'not_valid_after'):%d/%m/%Y}.")
    if _utc(leaf, "not_valid_before") > now:
        raise CertError(f"O certificado só vale a partir de {_utc(leaf, 'not_valid_before'):%d/%m/%Y}.")
    cert_names = names(leaf)
    if not covers(cert_names, domain):
        raise CertError(f"O certificado não cobre {domain} (nomes cobertos: {', '.join(cert_names)}).")
    # Cadeia na ordem: folha, depois quem assinou cada um
    ordered = [leaf]
    pool = list(others)
    while pool:
        nxt = next((c for c in pool if c.subject == ordered[-1].issuer), None)
        if nxt is None:
            break
        ordered.append(nxt)
        pool.remove(nxt)
    ordered += pool
    if len(ordered) == 1 and leaf.issuer != leaf.subject:
        warning = ("Sem a cadeia intermediária: alguns navegadores e clientes vão recusar. Envie o fullchain ou a "
                   "cadeia da autoridade certificadora.")
    else:
        warning = None
    enc = serialization.Encoding.PEM
    fullchain = "".join(c.public_bytes(enc).decode() for c in ordered)
    key_out = key.private_bytes(enc, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    return {"domain": domain, "fullchain": fullchain, "key": key_out, "chain_count": len(ordered),
            "info": describe(leaf), "warning": warning}


def _sha() -> Any:
    from cryptography.hazmat.primitives import hashes
    return hashes.SHA256()


def info_from_pem(fullchain: str) -> dict[str, Any] | None:
    certs = _load_certs(fullchain, "Certificado")
    if not certs:
        return None
    out = describe(certs[0])
    out["chain_count"] = len(certs)
    return out
