"""Peças comuns aos coletores: integração com a credencial decifrada, gravação de ativos e métricas."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from openmon import vault

KINDS = ("vmware_vcenter", "hyperv", "veeam", "snmp")
# Nome da instância systemd (openmon-collector@<x>) -> tipo de integração
INSTANCE_KIND = {"vmware": "vmware_vcenter", "hyperv": "hyperv", "veeam": "veeam", "snmp": "snmp"}

METRIC = {
    "cpu.usage.pct": 1, "cpu.usage.mhz": 2, "cpu.ready.pct": 3, "cpu.allocated.vcpu": 4,
    "mem.usage.pct": 10, "mem.used.bytes": 11, "mem.allocated.bytes": 12, "mem.swapped.bytes": 13,
    "mem.ballooned.bytes": 14, "disk.capacity.bytes": 20, "disk.used.bytes": 21, "disk.read.latency.ms": 22,
    "disk.write.latency.ms": 23, "disk.read.iops": 24, "disk.write.iops": 25, "disk.read.bps": 26,
    "disk.write.bps": 27, "net.rx.bps": 30, "net.tx.bps": 31, "net.rx.pps": 32, "net.tx.pps": 33,
    "availability.up": 40, "host.uptime.seconds": 41, "storage.capacity.bytes": 50, "storage.free.bytes": 51,
    "storage.used.bytes": 52,
}


class CollectorError(RuntimeError):
    """Falha esperada (credencial, rede, API) com mensagem útil para a tela."""


@dataclass
class Integration:
    id: int
    tenant_id: int
    kind: str
    name: str
    endpoint: str
    port: int | None
    verify_tls: bool
    ca_cert_pem: str | None
    options: dict[str, Any]
    poll_interval_seconds: int
    username: str | None = None
    secret: str | None = None
    cred_params: dict[str, Any] = field(default_factory=dict)


SELECT_INTEGRATION = """
SELECT i.id, i.tenant_id, i.kind, i.name, i.endpoint, i.port, i.verify_tls, i.ca_cert_pem, i.options,
       i.poll_interval_seconds, i.credential_id::text AS cred_id
  FROM integrations i
"""


async def load_integration(conn: Any, row: Any) -> Integration:
    opts = row["options"]
    integ = Integration(id=row["id"], tenant_id=row["tenant_id"], kind=row["kind"], name=row["name"],
                        endpoint=row["endpoint"], port=row["port"], verify_tls=row["verify_tls"],
                        ca_cert_pem=row["ca_cert_pem"], options=json.loads(opts) if isinstance(opts, str) else
                        dict(opts or {}), poll_interval_seconds=row["poll_interval_seconds"])
    if row["cred_id"]:
        integ.username, integ.secret = await vault.load(conn, row["cred_id"])
        params = await conn.fetchval("SELECT params FROM credentials WHERE id = $1::uuid", row["cred_id"])
        integ.cred_params = json.loads(params) if isinstance(params, str) else dict(params or {})
    return integ


def now() -> datetime:
    return datetime.now(timezone.utc)


class Writer:
    """Acumula o resultado de uma coleta e grava numa transação só."""

    def __init__(self, conn: Any, integ: Integration) -> None:
        self.conn, self.integ = conn, integ
        self.samples: list[tuple[datetime, int, int, int, float]] = []
        self.seen_assets: set[int] = set()
        self._rules: list[Any] | None = None

    async def tenant_for(self, facts: dict[str, Any]) -> int:
        """Tenant de um ativo descoberto pelas regras automáticas (tenant_assignment_rules)."""
        if self._rules is None:
            self._rules = list(await self.conn.fetch(
                """SELECT r.tenant_id, r.match_field, r.pattern FROM tenant_assignment_rules r
                     JOIN tenants t ON t.id = r.tenant_id AND t.is_active
                    WHERE r.is_enabled AND (r.integration_id IS NULL OR r.integration_id = $1)
                    ORDER BY r.priority, r.id""", self.integ.id))
        return match_rules(self._rules, facts, self.integ.tenant_id)

    async def asset(self, external_id: str, asset_type: str, name: str, *, tenant_id: int | None = None,
                    parent_id: int | None = None, status: str = "up", hostname: str | None = None,
                    ip: str | None = None, vendor: str | None = None, model: str | None = None,
                    serial: str | None = None, os_name: str | None = None,
                    attributes: dict[str, Any] | None = None) -> tuple[int, int]:
        """Cria/atualiza pelo (integração, external_id). Devolve (asset_id, tenant_id efetivo)."""
        tid = tenant_id if tenant_id is not None else self.integ.tenant_id
        row = await self.conn.fetchrow(
            """INSERT INTO assets (tenant_id, integration_id, parent_id, asset_type, name, external_id, hostname,
                                   ip_address, vendor, model, serial_number, os_name, status, attributes,
                                   last_seen_at, last_status_change_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8::inet, $9, $10, $11, $12, $13, $14::jsonb, now(), now())
               ON CONFLICT (integration_id, external_id) WHERE external_id IS NOT NULL DO UPDATE SET
                   tenant_id = CASE WHEN assets.tenant_locked THEN assets.tenant_id ELSE EXCLUDED.tenant_id END,
                   parent_id = EXCLUDED.parent_id, asset_type = EXCLUDED.asset_type, name = EXCLUDED.name,
                   hostname = coalesce(EXCLUDED.hostname, assets.hostname),
                   ip_address = coalesce(EXCLUDED.ip_address, assets.ip_address),
                   vendor = coalesce(EXCLUDED.vendor, assets.vendor), model = coalesce(EXCLUDED.model, assets.model),
                   serial_number = coalesce(EXCLUDED.serial_number, assets.serial_number),
                   os_name = coalesce(EXCLUDED.os_name, assets.os_name),
                   last_status_change_at = CASE WHEN assets.status <> EXCLUDED.status THEN now()
                                                ELSE assets.last_status_change_at END,
                   status = EXCLUDED.status, attributes = assets.attributes || EXCLUDED.attributes,
                   last_seen_at = now(), deleted_at = NULL, updated_at = now()
               RETURNING id, tenant_id""",
            tid, self.integ.id, parent_id, asset_type, name[:250], external_id, hostname, valid_ip(ip), vendor,
            model, serial, os_name, status, json.dumps(attributes or {}, default=str))
        self.seen_assets.add(row["id"])
        return row["id"], row["tenant_id"]

    def metric(self, asset_id: int, tenant_id: int, key: str, value: float | int | None,
               at: datetime | None = None) -> None:
        if value is None:
            return
        try:
            v = float(value)
        except (TypeError, ValueError):
            return
        if v != v:  # NaN
            return
        self.samples.append((at or now(), tenant_id, asset_id, METRIC[key], v))

    async def flush(self) -> None:
        if self.samples:
            await self.conn.copy_records_to_table(
                "metric_samples", schema_name="openmon", records=self.samples,
                columns=["time", "tenant_id", "asset_id", "metric_id", "value"])
            self.samples = []

    async def retire_missing(self, asset_types: tuple[str, ...]) -> int:
        """Ativos desta integração que sumiram do inventário: marcados como removidos (histórico fica)."""
        res = await self.conn.execute(
            """UPDATE assets SET deleted_at = now(), status = 'unknown', updated_at = now()
                WHERE integration_id = $1 AND asset_type = ANY($2::text[]) AND deleted_at IS NULL
                  AND NOT (id = ANY($3::bigint[]))""",
            self.integ.id, list(asset_types), list(self.seen_assets))
        return int(res.split()[-1]) if res else 0


def valid_ip(ip: str | None) -> str | None:
    import ipaddress
    if not ip:
        return None
    try:
        return str(ipaddress.ip_address(str(ip).split("%")[0]))
    except ValueError:
        return None


def match_rules(rules: list[Any], facts: dict[str, Any], default: int) -> int:
    """Primeira regra que casa decide o tenant; sem regra, fica no tenant da integração.

    ``facts`` traz os valores que o coletor conhece do ativo: folder, resource_pool,
    cluster, vsphere_tag (lista), name (para name_regex), hyperv_host, veeam_job.
    Padrões com ``*`` e ``?`` são curingas; ``name_regex`` é expressão regular.
    """
    import fnmatch
    for r in rules:
        field_ = r["match_field"]
        pattern = r["pattern"]
        if field_ == "name_regex":
            name = facts.get("name") or ""
            try:
                if re.search(pattern, name, re.I):
                    return int(r["tenant_id"])
            except re.error:
                continue
            continue
        values = facts.get(field_)
        if values is None:
            continue
        for v in values if isinstance(values, (list, tuple, set)) else [values]:
            if v and fnmatch.fnmatchcase(str(v).lower(), pattern.lower()):
                return int(r["tenant_id"])
    return default
