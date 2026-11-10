"""Motor de coleta: um processo por tipo (``openmon-collector@snmp`` etc.), pool asyncio de workers.

A cada poucos segundos procura as integrações do seu tipo cujo intervalo venceu,
"reserva" cada uma com um UPDATE condicional (dois processos nunca coletam a
mesma integração ao mesmo tempo) e roda a coleta com um limite de concorrência.
Resultado, duração e erro ficam em ``integrations.last_*`` (a tela mostra).
"""
from __future__ import annotations

import asyncio
import importlib
import logging
import os
import signal
import time
from typing import Any

from openmon import vault
from openmon.collector.common import SELECT_INTEGRATION, CollectorError, Writer, load_integration
from openmon.db import pool

log = logging.getLogger("openmon.collector")

MODULES = {"snmp": "openmon.collector.snmp", "vmware_vcenter": "openmon.collector.vmware",
           "hyperv": "openmon.collector.hyperv", "veeam": "openmon.collector.veeam"}
CONCURRENCY = {"snmp": 48, "vmware_vcenter": 4, "hyperv": 16, "veeam": 4}
DB_POOL = {"snmp": 16, "vmware_vcenter": 6, "hyperv": 8, "veeam": 6}
TICK_SECONDS = 5


def module_for(kind: str) -> Any:
    try:
        return importlib.import_module(MODULES[kind])
    except ModuleNotFoundError as exc:
        if exc.name == MODULES[kind]:
            return None
        raise CollectorError(f"biblioteca ausente para {kind}: {exc.name} (rode o instalador de novo)") from exc


async def due(kind: str, exclude: set[int], limit: int = 500) -> list[int]:
    async with pool.system_transaction() as conn:
        rows = await conn.fetch(
            """SELECT id FROM integrations
                WHERE kind = $1 AND is_enabled AND NOT (id = ANY($2::bigint[]))
                  AND (last_poll_started_at IS NULL
                       OR last_poll_started_at <= now() - make_interval(secs => poll_interval_seconds))
                ORDER BY last_poll_started_at NULLS FIRST LIMIT $3""", kind, list(exclude), limit)
    return [r["id"] for r in rows]


async def poll_once(integration_id: int, *, claim: bool = True) -> tuple[str, str]:
    """Coleta uma integração e grava o resultado. Devolve (status, mensagem)."""
    t0 = time.monotonic()
    async with pool.system_transaction() as conn:
        if claim:
            ok = await conn.fetchval(
                """UPDATE integrations SET last_poll_started_at = now()
                    WHERE id = $1 AND is_enabled
                      AND (last_poll_started_at IS NULL
                           OR last_poll_started_at <= now() - make_interval(secs => poll_interval_seconds))
                RETURNING true""", integration_id)
            if not ok:
                return "skipped", ""
        else:
            await conn.execute("UPDATE integrations SET last_poll_started_at = now() WHERE id = $1", integration_id)
    status, message = "ok", ""
    kind = "?"
    try:
        async with pool.system_transaction() as conn:
            row = await conn.fetchrow(SELECT_INTEGRATION + " WHERE i.id = $1", integration_id)
            if row is None:
                return "skipped", ""
            kind = row["kind"]
            mod = module_for(kind)
            if mod is None:
                raise CollectorError("coletor deste tipo ainda não disponível nesta versão")
            integ = await load_integration(conn, row)
            w = Writer(conn, integ)
            timeout = max(120, 3 * integ.poll_interval_seconds)
            message = await asyncio.wait_for(mod.poll(integ, w), timeout) or ""
            await w.flush()
            if message.startswith("warning:"):
                status, message = "warning", message[8:].strip()
    except asyncio.TimeoutError:
        status, message = "error", "a coleta passou do tempo limite"
    except (CollectorError, vault.VaultError) as exc:
        status, message = "error", str(exc)
    except pool.DatabaseUnavailable:
        raise
    except Exception as exc:  # noqa: BLE001 - nunca derruba o processo por um equipamento
        log.exception("coleta %s falhou", integration_id)
        status, message = "error", f"erro inesperado: {type(exc).__name__}: {str(exc)[:200]}"
    ms = int((time.monotonic() - t0) * 1000)
    async with pool.system_transaction() as conn:
        await conn.execute(
            """UPDATE integrations SET last_poll_finished_at = now(), last_poll_duration_ms = $2, last_status = $3,
                      last_error = $4 WHERE id = $1""",
            integration_id, ms, status, message[:1000] if status != "ok" else None)
        if status == "error" and kind == "snmp":
            await _device_down(conn, integration_id)
    if status != "ok":
        log.warning("integração %s (%s): %s", integration_id, kind, message)
    return status, message


async def _device_down(conn: Any, integration_id: int) -> None:
    row = await conn.fetchrow(
        """UPDATE assets SET last_status_change_at = CASE WHEN status <> 'down' THEN now() ELSE last_status_change_at END,
                  status = 'down', updated_at = now()
            WHERE integration_id = $1 AND external_id = 'snmp-device' RETURNING id, tenant_id""", integration_id)
    if row:
        await conn.execute("INSERT INTO metric_samples (time, tenant_id, asset_id, metric_id, value) "
                           "VALUES (now(), $1, $2, 40, 0)", row["tenant_id"], row["id"])


async def run(kind: str) -> None:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:  # pragma: no cover
            pass
    if module_for(kind) is None:
        log.info("coletor %s ainda não disponível nesta versão; aguardando atualização", kind)
        await stop.wait()
        return
    sem = asyncio.Semaphore(int(os.environ.get("OPENMON_COLLECTOR_CONCURRENCY", CONCURRENCY[kind])))
    running: dict[int, asyncio.Task[Any]] = {}

    async def worker(iid: int) -> None:
        async with sem:
            try:
                await poll_once(iid)
            except pool.DatabaseUnavailable as exc:
                log.warning("banco indisponível: %s", exc)
            finally:
                running.pop(iid, None)

    log.info("coletor %s iniciado", kind)
    while not stop.is_set():
        try:
            for iid in await due(kind, set(running)):
                running[iid] = asyncio.create_task(worker(iid))
        except pool.DatabaseUnavailable as exc:
            log.warning("banco indisponível: %s", exc)
            await _sleep(stop, 30)
            continue
        await _sleep(stop, TICK_SECONDS)
    if running:
        await asyncio.wait(list(running.values()), timeout=30)
    await pool.close_pool()


async def _sleep(stop: asyncio.Event, seconds: float) -> None:
    try:
        await asyncio.wait_for(stop.wait(), seconds)
    except asyncio.TimeoutError:
        pass
