"""Autenticação no Active Directory / LDAP (só LDAPS ou StartTLS, certificado validado).

Fluxo de um login:
1. conecta no primeiro servidor da lista que responder (TLS 1.2+, certificado
   conferido contra a CA informada ou as CAs do sistema, e o nome do servidor);
2. faz bind com a conta de serviço e procura o usuário pelo filtro
   (``{username}`` é escapado conforme a RFC 4515);
3. faz bind com o DN encontrado e a senha digitada (senha vazia nunca é
   aceita: seria um bind anônimo "bem-sucedido");
4. lê os grupos: o atributo ``memberOf`` e, no AD, também os grupos aninhados
   (``LDAP_MATCHING_RULE_IN_CHAIN``). Sem ``memberOf`` (OpenLDAP sem o overlay),
   procura grupos com ``member``/``uniqueMember`` = DN do usuário.

Tudo aqui é síncrono (python3-ldap3); a API chama em ``asyncio.to_thread``.
"""
from __future__ import annotations

import ssl
from dataclasses import dataclass, field
from typing import Any

ATTRS_USER = ("displayName", "cn", "mail", "userPrincipalName", "sAMAccountName", "uid")
AD_IN_CHAIN = "1.2.840.113556.1.4.1941"


class LdapError(RuntimeError):
    """Falha de conexão, TLS, bind da conta de serviço ou configuração."""


class LdapAuthFailed(RuntimeError):
    """Usuário inexistente (``reason='unknown_user'``), senha errada ou conta desabilitada no AD."""

    def __init__(self, message: str, reason: str = "bad_password") -> None:
        super().__init__(message)
        self.reason = reason


@dataclass
class Directory:
    urls: list[str]
    security: str               # 'ldaps' | 'starttls'
    base_dn: str
    bind_dn: str
    bind_password: str
    user_filter: str = "(&(objectClass=user)(sAMAccountName={username}))"
    group_attribute: str = "memberOf"
    ca_cert_pem: str | None = None
    timeout: int = 5
    verify_tls: bool = True     # False: TLS continua obrigatório, mas o certificado do DC não é conferido


@dataclass
class LdapUser:
    dn: str
    username: str
    display_name: str | None
    email: str | None
    groups: list[str] = field(default_factory=list)
    server: str = ""


def norm_dn(dn: str) -> str:
    """Comparação de DNs sem diferença de maiúsculas e espaços após vírgulas."""
    return ",".join(part.strip() for part in dn.split(",")).lower()


def _ldap3() -> Any:
    try:
        import ldap3  # type: ignore
    except ImportError as exc:  # pragma: no cover - python3-ldap3 é obrigatório
        raise LdapError("biblioteca LDAP indisponível (pacote python3-ldap3)") from exc
    return ldap3


def _tls(d: Directory) -> Any:
    ldap3 = _ldap3()
    if not d.verify_tls:
        return ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLS_CLIENT)
    kwargs: dict[str, Any] = {"validate": ssl.CERT_REQUIRED, "version": ssl.PROTOCOL_TLS_CLIENT}
    if d.ca_cert_pem and d.ca_cert_pem.strip():
        kwargs["ca_certs_data"] = d.ca_cert_pem.strip()
    tls = ldap3.Tls(**kwargs)
    return tls


def _server(d: Directory, url: str) -> Any:
    ldap3 = _ldap3()
    url = url.strip()
    lower = url.lower()
    if d.security == "ldaps":
        if not lower.startswith("ldaps://"):
            raise LdapError(f"{url}: com LDAPS o endereço precisa começar com ldaps://")
    elif not lower.startswith("ldap://"):
        raise LdapError(f"{url}: com StartTLS o endereço precisa começar com ldap://")
    return ldap3.Server(url, use_ssl=d.security == "ldaps", tls=_tls(d), connect_timeout=d.timeout,
                        get_info=ldap3.NONE)


def _describe(exc: BaseException) -> str:
    full = str(exc) or type(exc).__name__
    text = full.splitlines()[0][:220]
    low = full.lower()
    if "certificate has expired" in low:
        return f"o certificado TLS do servidor está vencido ({text})"
    if "certificate verify failed" in low or "certificate_verify_failed" in low:
        return (f"certificado TLS do servidor não confere ({text}). Informe a CA do AD em \"Certificado da CA\" "
                "ou desmarque \"Verificar o certificado do controlador de domínio\"")
    if "doesn't match" in low or ("hostname" in low and "match" in low):
        return ("o nome usado no endereço não confere com o certificado TLS do servidor. Use o nome DNS "
                "que está no certificado do DC, não o IP")
    if "nosuchobject" in low.replace(" ", ""):
        return "Base DN não encontrada (ou a conta de serviço não tem permissão de leitura nela)"
    if "invalidcredentials" in low.replace(" ", "") or "invalid credentials" in low:
        return "usuário ou senha da conta de serviço recusados pelo servidor"
    return f"{type(exc).__name__}: {text}"


def connect(d: Directory, bind_dn: str, password: str) -> tuple[Any, str]:
    """Conexão autenticada (TLS) no primeiro servidor que responder; devolve (conexão, url)."""
    ldap3 = _ldap3()
    from ldap3.core import exceptions as lx  # type: ignore

    if not password:
        raise LdapError("senha vazia")
    errors = []
    for url in [u for u in d.urls if u.strip()]:
        server = _server(d, url)
        conn = ldap3.Connection(server, user=bind_dn, password=password, auto_bind=ldap3.AUTO_BIND_NONE,
                                receive_timeout=d.timeout, raise_exceptions=True, read_only=True)
        try:
            conn.open()
            if d.security == "starttls":
                conn.start_tls()
            conn.bind()
            return conn, url
        except lx.LDAPInvalidCredentialsResult:
            _close(conn)
            raise
        except (lx.LDAPException, OSError, ssl.SSLError) as exc:
            _close(conn)
            errors.append(f"{url}: {_describe(exc)}")
    raise LdapError("; ".join(errors) or "nenhum servidor configurado")


def _close(conn: Any) -> None:
    try:
        conn.unbind()
    except Exception:  # noqa: BLE001 - fechar nunca deve mascarar o erro original
        pass


def _first(entry: Any, *names: str) -> str | None:
    attrs = entry.get("attributes", {})
    for n in names:
        v = attrs.get(n)
        if isinstance(v, list):
            v = v[0] if v else None
        if v:
            return str(v)
    return None


def find_user(conn: Any, d: Directory, username: str) -> dict[str, Any] | None:
    ldap3 = _ldap3()
    from ldap3.utils.conv import escape_filter_chars  # type: ignore

    if "{username}" not in d.user_filter:
        raise LdapError("o filtro de usuário precisa conter {username}")
    flt = d.user_filter.replace("{username}", escape_filter_chars(username))
    attrs = list(ATTRS_USER) + ([d.group_attribute] if d.group_attribute else [])
    conn.search(d.base_dn, flt, search_scope=ldap3.SUBTREE, attributes=attrs, size_limit=2)
    entries = [e for e in conn.response or [] if e.get("type") == "searchResEntry"]
    if len(entries) > 1:
        raise LdapError(f"o filtro encontrou mais de um usuário para \"{username}\"; ajuste o filtro")
    return entries[0] if entries else None


def groups_of(conn: Any, d: Directory, entry: Any) -> list[str]:
    ldap3 = _ldap3()
    from ldap3.utils.conv import escape_filter_chars  # type: ignore

    dn = entry["dn"]
    found: dict[str, str] = {}
    raw = entry.get("attributes", {}).get(d.group_attribute) if d.group_attribute else None
    for g in (raw if isinstance(raw, list) else [raw] if raw else []):
        found.setdefault(norm_dn(str(g)), str(g))
    esc = escape_filter_chars(dn)
    searches = [f"(member:{AD_IN_CHAIN}:={esc})"]  # AD: grupos aninhados
    if not found:
        searches.append(f"(|(member={esc})(uniqueMember={esc}))")
    for flt in searches:
        try:
            conn.search(d.base_dn, flt, search_scope=ldap3.SUBTREE, attributes=["cn"], size_limit=1000)
        except Exception:  # noqa: BLE001 - servidor que não conhece a regra do AD
            continue
        for e in conn.response or []:
            if e.get("type") == "searchResEntry":
                found.setdefault(norm_dn(e["dn"]), e["dn"])
    return sorted(found.values(), key=str.lower)


def authenticate(d: Directory, username: str, password: str) -> LdapUser:
    """Confere usuário e senha no diretório. LdapAuthFailed = credencial errada; LdapError = infraestrutura."""
    from ldap3.core import exceptions as lx  # type: ignore

    if not password:
        raise LdapAuthFailed("senha vazia")
    try:
        conn, url = connect(d, d.bind_dn, d.bind_password)
    except lx.LDAPInvalidCredentialsResult as exc:
        raise LdapError("usuário ou senha da conta de serviço recusados pelo servidor") from exc
    try:
        entry = find_user(conn, d, username)
        if entry is None:
            raise LdapAuthFailed("usuário não encontrado", "unknown_user")
        groups = groups_of(conn, d, entry)
    except lx.LDAPException as exc:
        raise LdapError(_describe(exc)) from exc
    finally:
        _close(conn)
    try:
        user_conn, _ = connect(Directory(**{**d.__dict__, "urls": [url]}), entry["dn"], password)
        _close(user_conn)
    except lx.LDAPInvalidCredentialsResult as exc:
        raise LdapAuthFailed("senha incorreta ou conta desabilitada") from exc
    login = _first(entry, "sAMAccountName", "uid") or username
    return LdapUser(dn=entry["dn"], username=login, display_name=_first(entry, "displayName", "cn"),
                    email=_first(entry, "mail", "userPrincipalName"), groups=groups, server=url)


def test(d: Directory, username: str | None = None, password: str | None = None) -> dict[str, Any]:
    """Diagnóstico para a tela: conexão + bind de serviço; com usuário, também busca, grupos e senha."""
    from ldap3.core import exceptions as lx  # type: ignore

    out: dict[str, Any] = {"ok": False, "steps": []}

    def step(name: str, ok: bool, detail: str = "") -> None:
        out["steps"].append({"step": name, "ok": ok, "detail": detail})

    try:
        conn, url = connect(d, d.bind_dn, d.bind_password)
    except lx.LDAPInvalidCredentialsResult:
        step("Conta de serviço", False, "usuário ou senha da conta de serviço recusados pelo servidor")
        return out
    except LdapError as exc:
        step("Conexão TLS", False, str(exc))
        return out
    cert = "certificado validado" if d.verify_tls else "certificado NÃO verificado"
    step("Conexão TLS", True, f"{url} ({'LDAPS' if d.security == 'ldaps' else 'StartTLS'}, {cert})")
    step("Conta de serviço", True, d.bind_dn)
    try:
        if not username:
            conn.search(d.base_dn, "(objectClass=*)", search_scope=_ldap3().BASE, attributes=["objectClass"])
            step("Base DN", bool(conn.response), d.base_dn)
            out["ok"] = bool(conn.response)
            return out
        entry = find_user(conn, d, username)
        if entry is None:
            step("Usuário", False, f"\"{username}\" não encontrado com o filtro em {d.base_dn}")
            return out
        step("Usuário", True, entry["dn"])
        groups = groups_of(conn, d, entry)
        out["groups"] = groups
        out["user"] = {"dn": entry["dn"], "display_name": _first(entry, "displayName", "cn"),
                       "email": _first(entry, "mail", "userPrincipalName")}
        step("Grupos", True, f"{len(groups)} grupo(s)")
    except (lx.LDAPException, LdapError) as exc:
        step("Busca", False, _describe(exc) if isinstance(exc, lx.LDAPException) else str(exc))
        return out
    finally:
        _close(conn)
    if password:
        try:
            uc, _ = connect(Directory(**{**d.__dict__, "urls": [url]}), entry["dn"], password)
            _close(uc)
            step("Senha do usuário", True, "conferida")
        except (lx.LDAPInvalidCredentialsResult, LdapError):
            step("Senha do usuário", False, "senha incorreta ou conta desabilitada")
            return out
    out["ok"] = True
    return out


ROLE_STRENGTH = {"global_admin": 3, "operator": 2, "client": 1}


def resolve_access(mappings: list[dict[str, Any]], groups: list[str]) -> tuple[str, list[int]] | None:
    """Perfil e tenants a partir dos grupos do usuário.

    Vale o perfil mais alto entre os grupos mapeados (Administrador global >
    Operador > Cliente); para Cliente, os tenants de todos os grupos de Cliente
    se somam. Sem grupo mapeado (ou Cliente sem tenant ativo), não há acesso.
    """
    mine = {norm_dn(g) for g in groups}
    hits = [m for m in mappings if norm_dn(m["group_dn"]) in mine]
    if not hits:
        return None
    best = max(hits, key=lambda m: (ROLE_STRENGTH.get(m["role"], 0), -int(m.get("priority") or 100)))
    role = best["role"]
    if m_scope(best) == "global":
        return role, []
    tenants = sorted({int(m["tenant_id"]) for m in hits
                      if m["role"] == role and m.get("tenant_id") is not None and m.get("tenant_active", True)})
    return (role, tenants) if tenants else None


def m_scope(m: dict[str, Any]) -> str:
    return m.get("scope") or ("tenant" if m["role"] == "client" else "global")
