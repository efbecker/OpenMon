"""Cadastro das integrações de coleta (vCenter, Hyper-V, Veeam, SNMP) e "Testar conexão".

Gerenciar exige ``integrations.manage`` (Administrador global); perfis globais
listam. Segredos (senha, comunidade SNMP, chaves SNMPv3) vão para o cofre e
nunca voltam para o navegador; ao editar, campo de segredo em branco mantém o
atual. A coleta em si roda nos serviços ``openmon-collector@*``.
"""
from __future__ import annotations

import asyncio
import json
import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from openmon import vault
from openmon.api.admin_tenants import _audit, _db_error, _iso
from openmon.api.auth import SessionInfo, require_permission
from openmon.collector import engine
from openmon.collector.common import CollectorError, Integration
from openmon.db import pool

router = APIRouter(prefix="/api/admin/integrations", tags=["admin"])

CRED_KIND = {"vmware_vcenter": "vmware", "vmware_vcd": "vmware", "hyperv": "winrm", "veeam": "veeam"}
DEFAULT_PORT = {"vmware_vcenter": 443, "vmware_vcd": 443, "hyperv": 5986, "veeam": 9419, "snmp": 161}
DEFAULT_INTERVAL = {"vmware_vcenter": 60, "vmware_vcd": 300, "hyperv": 60, "veeam": 300, "snmp": 60}
HOST_RE = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}"
                     r"[A-Za-z0-9])?$|^[0-9a-fA-F:.]+$")
ASSET_TYPES = ("network_switch", "router", "firewall", "storage", "physical_server", "other")


class IntegrationForm(BaseModel):
    kind: str = Field(pattern="^(vmware_vcenter|vmware_vcd|hyperv|veeam|snmp)$")
    name: str = Field(min_length=2, max_length=120)
    tenant_id: int
    endpoint: str = Field(min_length=1, max_length=255)
    port: int | None = Field(default=None, ge=1, le=65535)
    verify_tls: bool = True
    ca_cert_pem: str | None = Field(default=None, max_length=50000)
    poll_interval_seconds: int | None = Field(default=None, ge=10, le=86400)
    is_enabled: bool = True
    options: dict[str, Any] = Field(default_factory=dict)
    username: str | None = Field(default=None, max_length=256)
    secret: str | None = Field(default=None, max_length=1024)          # senha ou comunidade v2c
    auth_protocol: str | None = Field(default=None, pattern="^(md5|sha|sha256)$")
    auth_password: str | None = Field(default=None, max_length=256)
    priv_protocol: str | None = Field(default=None, pattern="^(aes|des)$")
    priv_password: str | None = Field(default=None, max_length=256)
    context: str | None = Field(default=None, max_length=128)


class TestForm(IntegrationForm):
    integration_id: int | None = None


def _options(form: IntegrationForm) -> dict[str, Any]:
    o = form.options or {}
    if form.kind == "snmp":
        version = str(o.get("version") or "2c")
        if version not in ("2c", "3"):
            raise HTTPException(422, "Versão SNMP inválida (2c ou 3).")
        asset_type = o.get("asset_type") or "network_switch"
        if asset_type not in ASSET_TYPES:
            raise HTTPException(422, "Tipo de equipamento inválido.")
        return {"version": version, "asset_type": asset_type,
                "timeout_ms": _int(o.get("timeout_ms"), 2000, 200, 30000),
                "retries": _int(o.get("retries"), 2, 0, 5),
                "discovery_minutes": _int(o.get("discovery_minutes"), 15, 5, 1440)}
    if form.kind == "hyperv":
        transport = o.get("transport") or "ntlm"
        if transport not in ("ntlm", "kerberos", "credssp"):
            raise HTTPException(422, "Transporte WinRM inválido.")
        hosts = [h.strip() for h in (o.get("hosts") or []) if str(h).strip()]
        for h in hosts:
            if not HOST_RE.match(h):
                raise HTTPException(422, f"Host Hyper-V inválido: {h}")
        return {"transport": transport, "hosts": hosts[:64], "https": o.get("https", True) is not False}
    if form.kind == "veeam":
        return {"api_version": str(o.get("api_version") or "1.1-rev1")[:20]}
    if form.kind == "vmware_vcd":
        version = str(o.get("api_version") or "38.0").strip()
        if not re.match(r"^\d{2}\.\d$", version):
            raise HTTPException(422, "Versão da API do vCloud inválida (ex.: 38.0).")
        auth = o.get("auth") or "password"
        if auth not in ("password", "token"):
            raise HTTPException(422, "Autenticação do vCloud inválida.")
        orgs = [str(x).strip() for x in (o.get("orgs") or []) if str(x).strip()]
        return {"api": "vcd", "api_version": version, "auth": auth, "orgs": [x[:120] for x in orgs[:100]]}
    return {}


def _int(v: Any, default: int, lo: int, hi: int) -> int:
    try:
        n = int(v)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, n))


def _validate(form: IntegrationForm) -> dict[str, Any]:
    endpoint = form.endpoint.strip()
    host = re.sub(r"^https?://", "", endpoint).split("/")[0].split(":")[0] \
        if form.kind in ("vmware_vcenter", "vmware_vcd", "veeam") else endpoint
    if not HOST_RE.match(host):
        raise HTTPException(422, "Endereço inválido: use o nome DNS ou o IP.")
    pem = (form.ca_cert_pem or "").strip() or None
    if pem and "-----BEGIN CERTIFICATE-----" not in pem:
        raise HTTPException(422, "Certificado da CA deve estar em formato PEM.")
    # vCloud Director é um modo da integração VMware (options.api = "vcd"): o banco não muda
    return {"kind": "vmware_vcenter" if form.kind == "vmware_vcd" else form.kind, "name": form.name.strip(),
            "tenant_id": form.tenant_id, "endpoint": host,
            "port": form.port or DEFAULT_PORT[form.kind], "verify_tls": form.verify_tls, "ca_cert_pem": pem,
            "poll_interval_seconds": form.poll_interval_seconds or DEFAULT_INTERVAL[form.kind],
            "is_enabled": form.is_enabled, "options": _options(form)}


def _credential(form: IntegrationForm, v: dict[str, Any], old_params: dict[str, Any] | None,
                old_secret: str | None) -> tuple[str, str | None, str, dict[str, Any]] | None:
    """(kind, username, segredo, params) a gravar, ou None para manter o que existe."""
    if form.kind == "snmp" and v["options"]["version"] == "2c":
        if not form.secret:
            if old_params is not None and old_params.get("_kind") == "snmp_v2c":
                return None
            raise HTTPException(422, "Informe a comunidade SNMP.")
        return "snmp_v2c", None, form.secret, {"_kind": "snmp_v2c"}
    if form.kind == "snmp":
        if not (form.username or "").strip():
            raise HTTPException(422, "Informe o usuário SNMPv3.")
        if form.priv_protocol and not form.auth_protocol:
            raise HTTPException(422, "Privacidade (criptografia) exige autenticação.")
        prev = {}
        if old_params is not None and old_params.get("_kind") == "snmp_v3" and old_secret:
            try:
                prev = json.loads(old_secret)
            except ValueError:
                prev = {}
        auth_pw = form.auth_password or prev.get("auth_password") if form.auth_protocol else None
        priv_pw = form.priv_password or prev.get("priv_password") if form.priv_protocol else None
        if form.auth_protocol and len(auth_pw or "") < 8:
            raise HTTPException(422, "Senha de autenticação SNMPv3 precisa de 8+ caracteres.")
        if form.priv_protocol and len(priv_pw or "") < 8:
            raise HTTPException(422, "Senha de privacidade SNMPv3 precisa de 8+ caracteres.")
        params = {"_kind": "snmp_v3", "auth_protocol": form.auth_protocol, "priv_protocol": form.priv_protocol,
                  "context": (form.context or "").strip()}
        return "snmp_v3", form.username.strip(), json.dumps({"auth_password": auth_pw, "priv_password": priv_pw}), \
            params
    username = (form.username or "").strip()
    token = form.kind == "vmware_vcd" and v["options"].get("auth") == "token"
    if token and not username:
        username = "System"
    if not username:
        raise HTTPException(422, "Informe o usuário.")
    if not form.secret:
        if old_params is not None:
            return None
        raise HTTPException(422, "Informe o API token." if token else "Informe a senha.")
    kind = CRED_KIND[form.kind]
    return kind, username, form.secret, {"_kind": kind}


_SELECT = """
SELECT i.id, i.kind, i.name, i.tenant_id, t.name AS tenant_name, i.endpoint, i.port, i.verify_tls, i.ca_cert_pem,
       i.options, i.poll_interval_seconds, i.is_enabled, i.last_poll_started_at, i.last_poll_finished_at,
       i.last_poll_duration_ms, i.last_status, i.last_error, i.created_at, i.credential_id::text AS cred_id,
       c.username AS cred_username, c.params AS cred_params,
       (SELECT count(*) FROM assets a WHERE a.integration_id = i.id AND a.deleted_at IS NULL) AS assets
  FROM integrations i JOIN tenants t ON t.id = i.tenant_id LEFT JOIN credentials c ON c.id = i.credential_id
"""


def _json(v: Any) -> dict[str, Any]:
    return json.loads(v) if isinstance(v, str) else dict(v or {})


def _ui_kind(kind: str, options: dict[str, Any]) -> str:
    return "vmware_vcd" if kind == "vmware_vcenter" and options.get("api") == "vcd" else kind


def _out(r: Any) -> dict[str, Any]:
    params = _json(r["cred_params"])
    return {"id": r["id"], "kind": _ui_kind(r["kind"], _json(r["options"])), "name": r["name"], "tenant_id": r["tenant_id"],
            "tenant_name": r["tenant_name"], "endpoint": r["endpoint"], "port": r["port"],
            "verify_tls": r["verify_tls"], "ca_cert_pem": r["ca_cert_pem"] or "", "options": _json(r["options"]),
            "poll_interval_seconds": r["poll_interval_seconds"], "is_enabled": r["is_enabled"],
            "last_poll_finished_at": _iso(r["last_poll_finished_at"]), "last_poll_duration_ms": r["last_poll_duration_ms"],
            "last_status": r["last_status"], "last_error": r["last_error"], "created_at": _iso(r["created_at"]),
            "username": r["cred_username"] or "", "has_secret": bool(r["cred_id"]),
            "auth_protocol": params.get("auth_protocol"), "priv_protocol": params.get("priv_protocol"),
            "context": params.get("context") or "", "assets": r["assets"]}


@router.get("")
async def list_integrations(session: SessionInfo = Depends(require_permission("assets.view"))) -> dict[str, Any]:
    if not session.is_global:
        raise HTTPException(403, "Somente perfis do datacenter veem as integrações.")
    try:
        async with session.db() as conn:
            rows = await conn.fetch(_SELECT + " ORDER BY i.kind, lower(i.name)")
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    return {"integrations": [_out(r) for r in rows], "can_manage": session.can("integrations.manage")}


async def _check_tenant(conn: Any, tenant_id: int) -> None:
    if not await conn.fetchval("SELECT 1 FROM tenants WHERE id = $1", tenant_id):
        raise HTTPException(422, "Tenant inexistente.")


async def _save_cred(conn: Any, session: SessionInfo, v: dict[str, Any], cred: tuple[Any, ...] | None,
                     cred_id: str | None) -> str | None:
    if cred is None:
        if cred_id:
            await conn.execute("UPDATE credentials SET name = $2 WHERE id = $1::uuid", cred_id,
                               f"integration:{v['kind']}:{v['name']}")
        return cred_id
    kind, username, secret, params = cred
    if cred_id:
        old_kind = await conn.fetchval("SELECT kind FROM credentials WHERE id = $1::uuid", cred_id)
        if old_kind != kind:  # trocou v2c <-> v3: o AAD inclui o tipo, então é outra credencial
            await conn.execute("UPDATE credentials SET kind = $2 WHERE id = $1::uuid", cred_id, kind)
    cid = await vault.save(conn, kind=kind, name=f"integration:{v['kind']}:{v['name']}", secret=secret,
                           username=username, created_by=session.user["id"], cred_id=cred_id)
    await conn.execute("UPDATE credentials SET params = $2::jsonb WHERE id = $1::uuid", cid, json.dumps(params))
    return cid


@router.post("", status_code=201)
async def create_integration(form: IntegrationForm, request: Request,
                             session: SessionInfo = Depends(require_permission("integrations.manage", write=True))
                             ) -> dict[str, Any]:
    v = _validate(form)
    cred = _credential(form, v, None, None)
    try:
        async with session.db() as conn:
            await _check_tenant(conn, v["tenant_id"])
            if await conn.fetchval("SELECT 1 FROM integrations WHERE kind = $1 AND lower(name) = lower($2)",
                                   v["kind"], v["name"]):
                raise HTTPException(409, f"Já existe uma integração chamada \"{v['name']}\".")
            cid = await _save_cred(conn, session, v, cred, None)
            iid = await conn.fetchval(
                """INSERT INTO integrations (tenant_id, kind, name, endpoint, port, credential_id, verify_tls,
                                             ca_cert_pem, options, poll_interval_seconds, is_enabled)
                   VALUES ($1, $2, $3, $4, $5, $6::uuid, $7, $8, $9::jsonb, $10, $11) RETURNING id""",
                v["tenant_id"], v["kind"], v["name"], v["endpoint"], v["port"], cid, v["verify_tls"], v["ca_cert_pem"],
                json.dumps(v["options"]), v["poll_interval_seconds"], v["is_enabled"])
            await _audit(conn, session, request, "integration.create", "integration", iid, v["tenant_id"],
                         {k: v[k] for k in ("kind", "name", "endpoint", "port", "tenant_id", "is_enabled")})
            row = await conn.fetchrow(_SELECT + " WHERE i.id = $1", iid)
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    except vault.VaultError as exc:
        raise HTTPException(500, f"Cofre de credenciais: {exc}") from exc
    return {"integration": _out(row)}


@router.put("/{integration_id}")
async def update_integration(integration_id: int, form: IntegrationForm, request: Request,
                             session: SessionInfo = Depends(require_permission("integrations.manage", write=True))
                             ) -> dict[str, Any]:
    v = _validate(form)
    try:
        async with session.db() as conn:
            old = await conn.fetchrow(_SELECT + " WHERE i.id = $1", integration_id)
            if old is None:
                raise HTTPException(404, "Integração não encontrada.")
            if _ui_kind(old["kind"], _json(old["options"])) != form.kind:
                raise HTTPException(422, "O tipo da integração não pode mudar; crie outra.")
            await _check_tenant(conn, v["tenant_id"])
            if await conn.fetchval("SELECT 1 FROM integrations WHERE kind = $1 AND lower(name) = lower($2) AND id <> $3",
                                   v["kind"], v["name"], integration_id):
                raise HTTPException(409, f"Já existe uma integração chamada \"{v['name']}\".")
            old_secret = None
            if old["cred_id"] and v["kind"] == "snmp":
                _, old_secret = await vault.load(conn, old["cred_id"])
            cred = _credential(form, v, _json(old["cred_params"]) if old["cred_id"] else None, old_secret)
            cid = await _save_cred(conn, session, v, cred, old["cred_id"])
            await conn.execute(
                """UPDATE integrations SET tenant_id = $2, name = $3, endpoint = $4, port = $5, credential_id = $6::uuid,
                          verify_tls = $7, ca_cert_pem = $8, options = $9::jsonb, poll_interval_seconds = $10,
                          is_enabled = $11, updated_at = now()
                    WHERE id = $1""",
                integration_id, v["tenant_id"], v["name"], v["endpoint"], v["port"], cid, v["verify_tls"],
                v["ca_cert_pem"], json.dumps(v["options"]), v["poll_interval_seconds"], v["is_enabled"])
            if old["tenant_id"] != v["tenant_id"]:
                # Ativos que não tiveram o tenant fixado manualmente acompanham a integração (SNMP: o equipamento)
                await conn.execute("UPDATE assets SET tenant_id = $2 WHERE integration_id = $1 AND NOT tenant_locked "
                                   "AND external_id = 'snmp-device'", integration_id, v["tenant_id"])
            await _audit(conn, session, request, "integration.update", "integration", integration_id, v["tenant_id"],
                         {k: v[k] for k in ("name", "endpoint", "port", "tenant_id", "is_enabled")}
                         | {"secret_changed": cred is not None})
            row = await conn.fetchrow(_SELECT + " WHERE i.id = $1", integration_id)
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    except vault.VaultError as exc:
        raise HTTPException(500, f"Cofre de credenciais: {exc}") from exc
    return {"integration": _out(row)}


@router.delete("/{integration_id}")
async def delete_integration(integration_id: int, request: Request,
                             session: SessionInfo = Depends(require_permission("integrations.manage", write=True))
                             ) -> dict[str, Any]:
    try:
        async with session.db() as conn:
            old = await conn.fetchrow(_SELECT + " WHERE i.id = $1", integration_id)
            if old is None:
                raise HTTPException(404, "Integração não encontrada.")
            # Os ativos ficam (histórico de 5 anos), marcados como removidos do inventário
            await conn.execute("UPDATE assets SET deleted_at = coalesce(deleted_at, now()), status = 'unknown' "
                               "WHERE integration_id = $1", integration_id)
            await conn.execute("DELETE FROM integrations WHERE id = $1", integration_id)
            if old["cred_id"]:
                await conn.execute("DELETE FROM credentials WHERE id = $1::uuid", old["cred_id"])
            await _audit(conn, session, request, "integration.delete", "integration", integration_id,
                         old["tenant_id"], {"name": old["name"], "kind": old["kind"], "assets": old["assets"]})
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    return {"ok": True}


@router.post("/test")
async def test_integration(form: TestForm, request: Request,
                           session: SessionInfo = Depends(require_permission("integrations.manage", write=True))
                           ) -> dict[str, Any]:
    v = _validate(form)
    old_params, old_secret, old_user = None, None, None
    try:
        async with session.db() as conn:
            if form.integration_id:
                cid = await conn.fetchval("SELECT credential_id::text FROM integrations WHERE id = $1",
                                          form.integration_id)
                if cid:
                    old_user, old_secret = await vault.load(conn, cid)
                    old_params = _json(await conn.fetchval("SELECT params FROM credentials WHERE id = $1::uuid", cid))
            await _audit(conn, session, request, "integration.test", "integration", form.integration_id or "-",
                         v["tenant_id"], {"kind": v["kind"], "endpoint": v["endpoint"]})
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    except vault.VaultError as exc:
        raise HTTPException(500, f"Cofre de credenciais: {exc}") from exc
    cred = _credential(form, v, old_params, old_secret)
    if cred is None:
        username, secret, params = old_user, old_secret, old_params or {}
    else:
        _, username, secret, params = cred
    integ = Integration(id=form.integration_id or 0, tenant_id=v["tenant_id"], kind=v["kind"], name=v["name"],
                        endpoint=v["endpoint"], port=v["port"], verify_tls=v["verify_tls"],
                        ca_cert_pem=v["ca_cert_pem"], options=v["options"],
                        poll_interval_seconds=v["poll_interval_seconds"], username=username, secret=secret,
                        cred_params=params)
    try:
        mod = engine.module_for(v["kind"])
        if mod is None:
            raise CollectorError("coletor deste tipo ainda não disponível nesta versão")
        result = await asyncio.wait_for(mod.test(integ), 45)
    except asyncio.TimeoutError:
        return {"ok": False, "error": "sem resposta em 45 s"}
    except CollectorError as exc:
        return {"ok": False, "error": str(exc)}
    return result


@router.post("/{integration_id}/poll")
async def poll_now(integration_id: int, request: Request,
                   session: SessionInfo = Depends(require_permission("integrations.manage", write=True))
                   ) -> dict[str, Any]:
    """Coleta agora (a mesma rotina do serviço de coleta) e devolve o resultado."""
    try:
        async with session.db() as conn:
            if not await conn.fetchval("SELECT 1 FROM integrations WHERE id = $1", integration_id):
                raise HTTPException(404, "Integração não encontrada.")
        status, message = await asyncio.wait_for(engine.poll_once(integration_id, claim=False), 300)
    except asyncio.TimeoutError:
        return {"status": "error", "message": "a coleta passou de 5 minutos"}
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    return {"status": status, "message": message}
