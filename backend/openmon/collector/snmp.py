"""Coletor SNMP v2c/v3: equipamento, interfaces (IF-MIB) e tráfego por contadores 64-bit.

Cada integração ``snmp`` é um equipamento. A cada ciclo:

1. ``system`` (sysDescr, sysObjectID, sysName, sysUpTime) -> ativo + disponibilidade;
2. a cada ``discovery_minutes`` (padrão 15) a tabela de interfaces é relida com GETBULK;
3. das interfaces monitoradas lê ``ifHCInOctets``/``ifHCOutOctets`` (64-bit; cai para
   os de 32-bit se o equipamento não tiver), pacotes, erros, descartes e status, e
   grava em ``interface_samples`` o delta desde a leitura anterior
   (``interface_counter_state``). Reinício do equipamento (sysUpTime voltou) e
   contadores zerados não geram picos falsos.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any

from openmon.collector.common import CollectorError, Integration, Writer, now
from openmon.collector.snmp_client import SnmpClient, SnmpError, V3Credentials

SYS = {"descr": "1.3.6.1.2.1.1.1.0", "object_id": "1.3.6.1.2.1.1.2.0", "uptime": "1.3.6.1.2.1.1.3.0",
       "name": "1.3.6.1.2.1.1.5.0", "location": "1.3.6.1.2.1.1.6.0"}

IF_COLUMNS = {
    "descr": "1.3.6.1.2.1.2.2.1.2", "type": "1.3.6.1.2.1.2.2.1.3", "speed": "1.3.6.1.2.1.2.2.1.5",
    "mac": "1.3.6.1.2.1.2.2.1.6", "admin_status": "1.3.6.1.2.1.2.2.1.7", "oper_status": "1.3.6.1.2.1.2.2.1.8",
    "name": "1.3.6.1.2.1.31.1.1.1.1", "high_speed": "1.3.6.1.2.1.31.1.1.1.15", "alias": "1.3.6.1.2.1.31.1.1.1.18",
}

COUNTERS_HC = {"in_octets": "1.3.6.1.2.1.31.1.1.1.6", "out_octets": "1.3.6.1.2.1.31.1.1.1.10",
               "in_pkts": "1.3.6.1.2.1.31.1.1.1.7", "out_pkts": "1.3.6.1.2.1.31.1.1.1.11"}
COUNTERS_32 = {"in_octets": "1.3.6.1.2.1.2.2.1.10", "out_octets": "1.3.6.1.2.1.2.2.1.16",
               "in_pkts": "1.3.6.1.2.1.2.2.1.11", "out_pkts": "1.3.6.1.2.1.2.2.1.17"}
COUNTERS_OTHER = {"in_errors": "1.3.6.1.2.1.2.2.1.14", "out_errors": "1.3.6.1.2.1.2.2.1.20",
                  "in_discards": "1.3.6.1.2.1.2.2.1.13", "out_discards": "1.3.6.1.2.1.2.2.1.19",
                  "oper_status": "1.3.6.1.2.1.2.2.1.8"}

VENDORS = {"1.3.6.1.4.1.14988": "MikroTik", "1.3.6.1.4.1.9": "Cisco", "1.3.6.1.4.1.2636": "Juniper",
           "1.3.6.1.4.1.2011": "Huawei", "1.3.6.1.4.1.25506": "HPE/H3C", "1.3.6.1.4.1.11": "HPE",
           "1.3.6.1.4.1.12356": "Fortinet", "1.3.6.1.4.1.25461": "Palo Alto", "1.3.6.1.4.1.6876": "VMware",
           "1.3.6.1.4.1.674": "Dell", "1.3.6.1.4.1.1588": "Brocade", "1.3.6.1.4.1.789": "NetApp",
           "1.3.6.1.4.1.8072": "Net-SNMP", "1.3.6.1.4.1.30065": "Arista", "1.3.6.1.4.1.6027": "Dell EMC"}

SKIP_TYPES = {24}  # softwareLoopback não é monitorada por padrão
WRAP64, WRAP32 = 2 ** 64, 2 ** 32


def text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").strip().strip("\x00")
    return str(value).strip()


def mac(value: Any) -> str | None:
    if isinstance(value, bytes) and len(value) == 6:
        return ":".join(f"{b:02x}" for b in value)
    return None


def vendor_of(object_id: str) -> str | None:
    for prefix, name in VENDORS.items():
        if object_id == prefix or object_id.startswith(prefix + "."):
            return name
    return None


def client_for(integ: Integration) -> SnmpClient:
    opts = integ.options
    timeout = max(0.2, int(opts.get("timeout_ms") or 2000) / 1000)
    retries = int(opts.get("retries") if opts.get("retries") is not None else 2)
    port = integ.port or 161
    if (opts.get("version") or "2c") == "3":
        p = integ.cred_params
        try:
            secrets = json.loads(integ.secret or "{}")
        except ValueError:
            secrets = {}
        creds = V3Credentials(username=integ.username or "", auth_protocol=p.get("auth_protocol") or None,
                              auth_password=secrets.get("auth_password"), priv_protocol=p.get("priv_protocol") or None,
                              priv_password=secrets.get("priv_password"), context_name=p.get("context") or "")
        return SnmpClient(integ.endpoint, v3=creds, port=port, timeout=timeout, retries=retries)
    return SnmpClient(integ.endpoint, community=integ.secret or "", port=port, timeout=timeout, retries=retries)


async def read_system(c: SnmpClient) -> dict[str, Any]:
    raw = await c.get(list(SYS.values()))
    if not raw:
        raise CollectorError("o equipamento respondeu, mas sem o grupo system (MIB-II)")
    return {k: raw.get(oid) for k, oid in SYS.items()}


async def read_interfaces(c: SnmpClient, max_rep: int = 25) -> dict[int, dict[str, Any]]:
    cols: dict[str, dict[str, Any]] = {}
    for key, oid in IF_COLUMNS.items():
        try:
            cols[key] = await c.walk(oid, max_repetitions=max_rep)
        except SnmpError:
            cols[key] = {}
    idx = sorted({int(i) for col in cols.values() for i in col if i.isdigit()})
    out = {}
    for i in idx:
        k = str(i)
        hs = cols["high_speed"].get(k)
        out[i] = {"name": text(cols["name"].get(k)) or text(cols["descr"].get(k)) or f"ifIndex {i}",
                  "descr": text(cols["descr"].get(k)), "alias": text(cols["alias"].get(k)),
                  "type": cols["type"].get(k), "speed_bps": hs * 1_000_000 if hs else (cols["speed"].get(k) or None),
                  "mac": mac(cols["mac"].get(k)), "admin_status": cols["admin_status"].get(k),
                  "oper_status": cols["oper_status"].get(k)}
    return out


async def test(integ: Integration) -> dict[str, Any]:
    """"Testar conexão" da tela: system + quantidade de interfaces."""
    try:
        async with client_for(integ) as c:
            sysinfo = await read_system(c)
            ifs = await c.walk(IF_COLUMNS["descr"])
            return {"ok": True, "summary": f"{text(sysinfo['name']) or integ.endpoint} · {len(ifs)} interface(s)",
                    "details": {"sysName": text(sysinfo["name"]), "sysDescr": text(sysinfo["descr"])[:300],
                                "vendor": vendor_of(str(sysinfo["object_id"] or "")),
                                "uptime_days": round((sysinfo["uptime"] or 0) / 8_640_000, 1),
                                "ip": c.resolved_ip}}
    except (SnmpError, OSError) as exc:
        raise CollectorError(str(exc)) from exc


async def poll(integ: Integration, w: Writer) -> str:
    conn = w.conn
    asset = await conn.fetchrow("SELECT id, tenant_id, attributes FROM assets WHERE integration_id = $1 "
                                "AND external_id = 'snmp-device'", integ.id)
    try:
        async with client_for(integ) as c:
            s = await read_system(c)
            attrs = json.loads(asset["attributes"]) if asset and isinstance(asset["attributes"], str) else \
                dict(asset["attributes"]) if asset else {}
            last_disc = attrs.get("if_discovered_at")
            need_disc = not last_disc or datetime.fromisoformat(last_disc) < now() - timedelta(
                minutes=int(integ.options.get("discovery_minutes") or 15))
            ifs = await read_interfaces(c, int(integ.options.get("max_repetitions") or 25)) if need_disc else None
            sys_oid = str(s["object_id"] or "")
            new_attrs = {"sys_descr": text(s["descr"])[:500], "sys_object_id": sys_oid,
                         "location": text(s["location"])[:200], "snmp_version": integ.options.get("version") or "2c"}
            if ifs is not None:
                new_attrs["if_discovered_at"] = now().isoformat()
                new_attrs["interfaces"] = len(ifs)
            asset_id, tenant_id = await w.asset(
                "snmp-device", integ.options.get("asset_type") or "network_switch",
                text(s["name"]) or integ.name, status="up", hostname=integ.endpoint, ip=c.resolved_ip,
                vendor=vendor_of(sys_oid), attributes=new_attrs)
            if ifs is not None:
                await _sync_interfaces(conn, asset_id, tenant_id, ifs)
            monitored = await conn.fetch(
                """SELECT i.id, i.if_index, i.tenant_id, i.speed_bps, st.polled_at, st.sys_uptime_cs, st.in_octets,
                          st.out_octets, st.in_ucast_pkts, st.out_ucast_pkts, st.in_errors AS p_in_errors,
                          st.out_errors AS p_out_errors, st.in_discards AS p_in_discards,
                          st.out_discards AS p_out_discards
                     FROM interfaces i LEFT JOIN interface_counter_state st ON st.interface_id = i.id
                    WHERE i.asset_id = $1 AND i.is_monitored ORDER BY i.if_index""", asset_id)
            uptime = int(s["uptime"] or 0)
            n = await _poll_counters(c, conn, asset_id, monitored, uptime, bool(attrs.get("counters_32bit")),
                                     integ, w)
    except (SnmpError, OSError) as exc:
        if asset:
            await conn.execute("UPDATE assets SET status = 'down', last_status_change_at = CASE WHEN status <> 'down' "
                               "THEN now() ELSE last_status_change_at END, updated_at = now() WHERE id = $1",
                               asset["id"])
            w.metric(asset["id"], asset["tenant_id"], "availability.up", 0)
        raise CollectorError(str(exc)) from exc
    w.metric(asset_id, tenant_id, "availability.up", 1)
    w.metric(asset_id, tenant_id, "host.uptime.seconds", uptime / 100)
    return f"{text(s['name']) or integ.endpoint}: {n} interface(s) monitorada(s)"


async def _sync_interfaces(conn: Any, asset_id: int, tenant_id: int, ifs: dict[int, dict[str, Any]]) -> None:
    for i, d in ifs.items():
        monitor = d["admin_status"] == 1 and d["type"] not in SKIP_TYPES
        await conn.execute(
            """INSERT INTO interfaces (asset_id, tenant_id, if_index, if_name, if_alias, if_descr, if_type, speed_bps,
                                       mac_address, admin_status, oper_status, is_monitored)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
               ON CONFLICT (asset_id, if_index) DO UPDATE SET if_name = EXCLUDED.if_name,
                   if_alias = EXCLUDED.if_alias, if_descr = EXCLUDED.if_descr, if_type = EXCLUDED.if_type,
                   speed_bps = EXCLUDED.speed_bps, mac_address = EXCLUDED.mac_address,
                   admin_status = EXCLUDED.admin_status, oper_status = EXCLUDED.oper_status, updated_at = now()""",
            asset_id, tenant_id, i, d["name"][:200], d["alias"][:200] or None, d["descr"][:300] or None, d["type"],
            d["speed_bps"], d["mac"], d["admin_status"], d["oper_status"], monitor)
    # ifIndex que sumiu do equipamento: deixa de ser monitorado (o histórico fica)
    await conn.execute("UPDATE interfaces SET is_monitored = false, oper_status = NULL, updated_at = now() "
                       "WHERE asset_id = $1 AND NOT (if_index = ANY($2::int[])) AND is_monitored",
                       asset_id, list(ifs))


def delta(cur: int | None, prev: Any, wrap: int) -> int | None:
    if cur is None or prev is None:
        return None
    d = int(cur) - int(prev)
    return d if d >= 0 else d + wrap


async def _poll_counters(c: SnmpClient, conn: Any, asset_id: int, rows: list[Any], uptime: int, use32: bool,
                         integ: Integration, w: Writer) -> int:
    if not rows:
        return 0
    counters = COUNTERS_32 if use32 else COUNTERS_HC
    oids = [f"{base}.{r['if_index']}" for r in rows for base in (*counters.values(), *COUNTERS_OTHER.values())]
    values = await c.get(oids)
    if not use32 and not any(f"{COUNTERS_HC['in_octets']}.{r['if_index']}" in values for r in rows):
        # Equipamento sem ifXTable: passa a usar os contadores de 32 bits
        await conn.execute("UPDATE assets SET attributes = attributes || '{\"counters_32bit\": true}' WHERE id = $1",
                           asset_id)
        counters = COUNTERS_32
        values = await c.get([f"{base}.{r['if_index']}" for r in rows for base in counters.values()]) | values
    wrap = WRAP32 if counters is COUNTERS_32 else WRAP64
    t = now()
    samples = []
    for r in rows:
        ix = r["if_index"]
        v = {k: values.get(f"{oid}.{ix}") for k, oid in {**counters, **COUNTERS_OTHER}.items()}
        if v["in_octets"] is None or v["out_octets"] is None:
            continue
        rebooted = r["sys_uptime_cs"] is not None and uptime < int(r["sys_uptime_cs"])
        if r["polled_at"] is not None and not rebooted:
            dt = (t - r["polled_at"]).total_seconds()
            din, dout = delta(v["in_octets"], r["in_octets"], wrap), delta(v["out_octets"], r["out_octets"], wrap)
            if 0 < dt < max(3 * integ.poll_interval_seconds, 900) and din is not None and dout is not None:
                in_bps, out_bps = din * 8 / dt, dout * 8 / dt
                limit = (r["speed_bps"] or 0) * 1.5
                if not limit or (in_bps <= limit and out_bps <= limit):  # acima disso é contador zerado
                    samples.append((t, r["tenant_id"], asset_id, r["id"], dt, din, dout,
                                    delta(v["in_pkts"], r["in_ucast_pkts"], wrap),
                                    delta(v["out_pkts"], r["out_ucast_pkts"], wrap), in_bps, out_bps,
                                    _err(v["in_errors"], r["p_in_errors"]), _err(v["out_errors"], r["p_out_errors"]),
                                    _err(v["in_discards"], r["p_in_discards"]),
                                    _err(v["out_discards"], r["p_out_discards"]), v["oper_status"]))
        await conn.execute(
            """INSERT INTO interface_counter_state (interface_id, polled_at, sys_uptime_cs, in_octets, out_octets,
                                                    in_ucast_pkts, out_ucast_pkts, in_errors, out_errors,
                                                    in_discards, out_discards)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
               ON CONFLICT (interface_id) DO UPDATE SET polled_at = EXCLUDED.polled_at,
                   sys_uptime_cs = EXCLUDED.sys_uptime_cs, in_octets = EXCLUDED.in_octets,
                   out_octets = EXCLUDED.out_octets, in_ucast_pkts = EXCLUDED.in_ucast_pkts,
                   out_ucast_pkts = EXCLUDED.out_ucast_pkts, in_errors = EXCLUDED.in_errors,
                   out_errors = EXCLUDED.out_errors, in_discards = EXCLUDED.in_discards,
                   out_discards = EXCLUDED.out_discards""",
            r["id"], t, uptime, v["in_octets"], v["out_octets"], v["in_pkts"], v["out_pkts"], v["in_errors"],
            v["out_errors"], v["in_discards"], v["out_discards"])
        if v["oper_status"] is not None:
            await conn.execute("UPDATE interfaces SET oper_status = $2 WHERE id = $1 AND oper_status IS DISTINCT FROM $2",
                               r["id"], v["oper_status"])
    if samples:
        await conn.copy_records_to_table(
            "interface_samples", schema_name="openmon", records=samples,
            columns=["time", "tenant_id", "asset_id", "interface_id", "interval_s", "in_bytes", "out_bytes",
                     "in_packets", "out_packets", "in_bps", "out_bps", "in_errors", "out_errors", "in_discards",
                     "out_discards", "oper_status"])
    return len(rows)


def _err(cur: Any, prev: Any) -> int | None:
    """Erros/descartes no intervalo (Counter32 com volta)."""
    d = delta(cur, prev, WRAP32)
    return None if d is None else min(d, 2_147_483_647)
