"""Avaliação dos triggers: abre, atualiza e resolve problemas e enfileira as notificações.

Fontes (``alert_triggers.source``):

- ``metric``: agregação (último, média, mínimo, máximo) de uma métrica na janela, por ativo.
  Para "Espaço usado" (52) o valor comparado é o % da capacidade.
- ``interface``: uso da interface em % da banda contratada (link de cliente) ou da velocidade,
  pelo maior entre entrada e saída.
- ``availability``: equipamento/host/VM fora (``status = down``) há pelo menos a janela.
- ``backup``: job com a última execução falhando ou sem backup bom há mais que o limite
  (limite 0 = SLA do tenant).
- ``integration``: integrações com erro de coleta (um problema só, com a lista).

Histerese: com ``recovery_threshold`` o problema só fecha quando o valor deixa de passar dele.
Escopo: o trigger vale para um tenant (ou todos), um ativo, uma interface ou um tipo de ativo.
"""
from __future__ import annotations

import logging
import operator
from dataclasses import dataclass
from typing import Any

log = logging.getLogger("openmon.scheduler")

OPS = {">": operator.gt, ">=": operator.ge, "<": operator.lt, "<=": operator.le, "=": operator.eq,
       "<>": operator.ne}
AGG = {"avg": "avg(m.value)", "min": "min(m.value)", "max": "max(m.value)",
       "last": "(array_agg(m.value ORDER BY m.time DESC))[1]"}
STORAGE_USED, STORAGE_CAP = 52, 50
SKIP_STATUS = ("powered_off", "maintenance", "suspended")


@dataclass
class Row:
    asset_id: int | None
    interface_id: int | None
    tenant_id: int
    label: str
    value: float | None
    problem: bool | None = None   # None = decide pelo operador; True/False já decidido pela fonte
    detail: str = ""


def _scope_sql(alias: str, first: int) -> str:
    return (f"(${first}::bigint IS NULL OR {alias}.tenant_id = ${first}) "
            f"AND (${first + 1}::bigint IS NULL OR {alias}.id = ${first + 1}) "
            f"AND (${first + 2}::text IS NULL OR {alias}.asset_type = ${first + 2})")


async def _metric_rows(conn: Any, t: Any) -> list[Row]:
    agg = AGG[t["expression"]]
    q = f"""SELECT a.id, a.tenant_id, a.name, {agg} AS value
              FROM assets a JOIN v_metric_samples m ON m.asset_id = a.id
             WHERE m.metric_id = $4 AND m.time > now() - make_interval(secs => $5)
               AND a.deleted_at IS NULL AND a.is_monitored AND NOT (a.status = ANY($6::text[]))
               AND {_scope_sql('a', 1)}
             GROUP BY a.id"""
    args = (t["tenant_id"], t["asset_id"], t["asset_type"], t["metric_id"], t["window_seconds"], list(SKIP_STATUS))
    rows = await conn.fetch(q, *args)
    if t["metric_id"] != STORAGE_USED:
        return [Row(r["id"], None, r["tenant_id"], r["name"], r["value"]) for r in rows]
    caps = {r["id"]: r["value"] for r in await conn.fetch(
        q.replace(agg, AGG["last"]), *args[:3], STORAGE_CAP, *args[4:])}
    out = []
    for r in rows:
        cap = caps.get(r["id"])
        if cap and r["value"] is not None:
            out.append(Row(r["id"], None, r["tenant_id"], r["name"], round(100.0 * r["value"] / cap, 2)))
    return out


async def _interface_rows(conn: Any, t: Any) -> list[Row]:
    agg = AGG[t["expression"]].replace("m.value", "greatest(m.in_bps, m.out_bps)")
    rows = await conn.fetch(
        f"""SELECT f.id, f.asset_id, f.tenant_id, a.name AS asset_name, f.if_name,
                   coalesce(f.contracted_bps, f.speed_bps) AS cap, {agg} AS value
              FROM interfaces f JOIN assets a ON a.id = f.asset_id
              JOIN v_interface_samples m ON m.interface_id = f.id
             WHERE f.is_monitored AND a.deleted_at IS NULL AND m.time > now() - make_interval(secs => $5)
               AND ($1::bigint IS NULL OR f.tenant_id = $1) AND ($2::bigint IS NULL OR f.asset_id = $2)
               AND ($3::text IS NULL OR a.asset_type = $3) AND ($4::bigint IS NULL OR f.id = $4)
             GROUP BY f.id, a.name""",
        t["tenant_id"], t["asset_id"], t["asset_type"], t["interface_id"], t["window_seconds"])
    return [Row(r["asset_id"], r["id"], r["tenant_id"], f"{r['asset_name']} {r['if_name'] or ''}".strip(),
                round(100.0 * r["value"] / r["cap"], 2))
            for r in rows if r["cap"] and r["value"] is not None]


async def _availability_rows(conn: Any, t: Any) -> list[Row]:
    rows = await conn.fetch(
        f"""SELECT a.id, a.tenant_id, a.name, a.status,
                   a.last_status_change_at <= now() - make_interval(secs => $4) AS long_enough
              FROM assets a
             WHERE a.deleted_at IS NULL AND a.is_monitored AND NOT (a.attributes ? 'backup_job_id')
               AND a.status IN ('up', 'warning', 'down') AND {_scope_sql('a', 1)}""",
        t["tenant_id"], t["asset_id"], t["asset_type"], t["window_seconds"])
    out = []
    for r in rows:
        down = r["status"] == "down"
        if down and not r["long_enough"]:
            continue  # caiu agora: espera a janela antes de decidir (nem abre, nem fecha)
        out.append(Row(r["id"], None, r["tenant_id"], r["name"], 0.0 if down else 1.0, problem=down,
                       detail="não responde" if down else ""))
    return out


async def _backup_rows(conn: Any, t: Any) -> list[Row]:
    rows = await conn.fetch(
        """SELECT a.id AS asset_id, j.tenant_id, j.name, j.last_result, j.is_enabled,
                  extract(epoch FROM now() - coalesce(j.last_success_at, j.created_at)) / 3600 AS hours,
                  j.last_success_at IS NULL AS never,
                  coalesce(nullif($2::double precision, 0), j.sla_rpo_hours, tn.backup_sla_hours) AS limit_h
             FROM backup_jobs j JOIN tenants tn ON tn.id = j.tenant_id
             JOIN assets a ON a.integration_id = j.integration_id AND a.external_id = 'job:' || j.external_id
            WHERE j.deleted_at IS NULL AND j.is_enabled AND ($1::bigint IS NULL OR j.tenant_id = $1)
              AND ($3::bigint IS NULL OR a.id = $3)""",
        t["tenant_id"], t["threshold"], t["asset_id"])
    out = []
    for r in rows:
        failed = r["last_result"] == "failed"
        late = r["limit_h"] is not None and r["hours"] is not None and r["hours"] > r["limit_h"]
        why = []
        if failed:
            why.append("última execução falhou")
        if late:
            why.append("sem backup bom " + ("desde o cadastro" if r["never"] else f"há {r['hours']:.0f} h")
                       + f" (SLA {r['limit_h']:.0f} h)")
        out.append(Row(r["asset_id"], None, r["tenant_id"], r["name"], round(r["hours"] or 0, 1),
                       problem=failed or late, detail="; ".join(why)))
    return out


async def _integration_rows(conn: Any, t: Any) -> list[Row]:
    rows = await conn.fetch(
        """SELECT name, last_error FROM integrations
            WHERE is_enabled AND last_status = 'error' AND ($1::bigint IS NULL OR tenant_id = $1)
            ORDER BY name""", t["tenant_id"])
    provider = await conn.fetchval("SELECT id FROM tenants WHERE is_provider ORDER BY id LIMIT 1")
    tenant = t["tenant_id"] or provider
    detail = "; ".join(f"{r['name']}: {(r['last_error'] or '')[:150]}" for r in rows[:10])
    return [Row(None, None, tenant, f"{len(rows)} integração(ões) com erro", float(len(rows)),
                problem=bool(rows), detail=detail)]


SOURCES = {"metric": _metric_rows, "interface": _interface_rows, "availability": _availability_rows,
           "backup": _backup_rows, "integration": _integration_rows}


def _fmt(value: float | None, unit: str) -> str:
    if value is None:
        return "—"
    if unit == "%":
        return f"{value:.1f}%"
    if unit in ("bit/s", "B/s"):
        n, units = float(value), ["", "k", "M", "G", "T"]
        i = 0
        while n >= 1000 and i < len(units) - 1:
            n /= 1000
            i += 1
        return f"{n:.1f} {units[i]}{unit}"
    if unit == "B":
        n, units = float(value), ["B", "KB", "MB", "GB", "TB", "PB"]
        i = 0
        while n >= 1024 and i < len(units) - 1:
            n /= 1024
            i += 1
        return f"{n:.1f} {units[i]}"
    return f"{value:g} {unit}".strip()


def message(t: Any, row: Row, metric: Any | None) -> str:
    src = t["source"]
    if src in ("availability", "backup", "integration"):
        return f"{row.label}: {row.detail}" if row.detail else row.label
    if src == "interface":
        return f"{row.label}: uso {row.value:.1f}% (limite {t['operator']} {t['threshold']:g}%)"
    name, unit = (metric["name"], metric["unit"]) if metric else ("valor", "")
    if t["metric_id"] == STORAGE_USED:
        name, unit = "Espaço usado", "%"
    return f"{row.label}: {name} {_fmt(row.value, unit)} (limite {t['operator']} {_fmt(t['threshold'], unit)})"


async def evaluate(conn: Any) -> dict[str, int]:
    """Uma rodada sobre todos os triggers habilitados. Devolve contadores (abertos, resolvidos)."""
    stats = {"triggers": 0, "opened": 0, "resolved": 0}
    metrics = {r["id"]: r for r in await conn.fetch("SELECT id, name, unit FROM metric_definitions")}
    for t in await conn.fetch("SELECT * FROM alert_triggers WHERE is_enabled ORDER BY id"):
        stats["triggers"] += 1
        try:
            async with conn.transaction():  # savepoint: um trigger com erro não derruba os outros
                o, r = await _apply(conn, t, await SOURCES[t["source"]](conn, t), metrics.get(t["metric_id"]))
            stats["opened"] += o
            stats["resolved"] += r
        except Exception:  # noqa: BLE001
            log.exception("trigger %s (%s) falhou", t["id"], t["name"])
    return stats


async def _apply(conn: Any, t: Any, rows: list[Row], metric: Any | None) -> tuple[int, int]:
    cond = OPS[t["operator"]]
    recovery = t["recovery_threshold"] if t["recovery_threshold"] is not None else t["threshold"]
    open_rows = {(r["asset_id"] or 0, r["interface_id"] or 0): r for r in await conn.fetch(
        "SELECT id, asset_id, interface_id, message FROM alert_problems WHERE trigger_id = $1 AND status = 'problem'",
        t["id"])}
    opened = resolved = 0
    seen: set[tuple[int, int]] = set()
    for row in rows:
        key = (row.asset_id or 0, row.interface_id or 0)
        seen.add(key)
        current = open_rows.get(key)
        if row.problem is not None:
            bad, still_bad = row.problem, row.problem
        else:
            if row.value is None:
                continue
            bad, still_bad = cond(row.value, t["threshold"]), cond(row.value, recovery)
        msg = message(t, row, metric)
        if current is None and bad:
            pid = await conn.fetchval(
                """INSERT INTO alert_problems (tenant_id, trigger_id, asset_id, interface_id, severity, value, message)
                   VALUES ($1, $2, $3, $4, $5, $6, $7)
                   ON CONFLICT (trigger_id, coalesce(asset_id, 0), coalesce(interface_id, 0))
                      WHERE status = 'problem' DO NOTHING RETURNING id""",
                row.tenant_id, t["id"], row.asset_id, row.interface_id, t["severity"], row.value, msg[:2000])
            if pid:
                opened += 1
                await enqueue(conn, pid, "problem")
        elif current is not None and not still_bad:
            await conn.execute("UPDATE alert_problems SET status = 'resolved', resolved_at = now(), value = $2 "
                               "WHERE id = $1", current["id"], row.value)
            resolved += 1
            await enqueue(conn, current["id"], "recovery")
        elif current is not None and msg != current["message"] and t["source"] in ("backup", "integration"):
            await conn.execute("UPDATE alert_problems SET message = $2, value = $3 WHERE id = $1",
                               current["id"], msg[:2000], row.value)
    # Ativo/interface que saiu do escopo (removido, desligado, trigger mudou): o problema fecha
    for key, current in open_rows.items():
        if key not in seen and t["source"] in ("availability", "backup", "integration"):
            await conn.execute("UPDATE alert_problems SET status = 'resolved', resolved_at = now() WHERE id = $1",
                               current["id"])
            resolved += 1
            await enqueue(conn, current["id"], "recovery")
        elif key not in seen:
            gone = await conn.fetchval(
                """SELECT coalesce((SELECT deleted_at IS NOT NULL OR status = ANY($2::text[]) OR NOT is_monitored
                                      FROM assets WHERE id = $1), true)""", current["asset_id"], list(SKIP_STATUS)) \
                if current["asset_id"] else False
            if gone:
                await conn.execute("UPDATE alert_problems SET status = 'resolved', resolved_at = now() WHERE id = $1",
                                   current["id"])
                resolved += 1
                await enqueue(conn, current["id"], "recovery")
    return opened, resolved


async def enqueue(conn: Any, problem_id: int, event: str) -> int:
    """Uma entrega por canal do trigger; canal de um cliente só recebe problemas daquele cliente."""
    res = await conn.execute(
        """INSERT INTO notification_deliveries (tenant_id, problem_id, channel_id, event, status)
           SELECT p.tenant_id, p.id, c.id, $2, 'queued'
             FROM alert_problems p
             JOIN alert_trigger_channels tc ON tc.trigger_id = p.trigger_id
             JOIN notification_channels c ON c.id = tc.channel_id AND c.is_enabled
            WHERE p.id = $1 AND (c.tenant_id IS NULL OR c.tenant_id = p.tenant_id)""", problem_id, event)
    return int(res.split()[-1])
