"""Agendador (openmon-scheduler.service): avalia os triggers, envia as notificações e faz limpezas."""
from __future__ import annotations

import asyncio
import logging
import signal
import time
from typing import Any

from openmon.db import pool
from openmon.scheduler import evaluator, notify

log = logging.getLogger("openmon.scheduler")

EVAL_SECONDS = 30
CLEANUP_SECONDS = 600
LOCK_KEY = 0x6F6D_0001  # advisory lock: um avaliador por vez, mesmo com dois agendadores


async def tick() -> dict[str, Any]:
    """Uma rodada: avalia (se ninguém mais está avaliando) e envia a fila."""
    out: dict[str, Any] = {}
    async with pool.system_transaction() as conn:
        if await conn.fetchval("SELECT pg_try_advisory_xact_lock($1)", LOCK_KEY):
            out["eval"] = await evaluator.evaluate(conn)
    out["notify"] = await notify.deliver_pending(pool.system_transaction)
    return out


async def cleanup() -> None:
    async with pool.system_transaction() as conn:
        await conn.execute("DELETE FROM user_sessions WHERE expires_at < now() - interval '1 day' "
                           "OR revoked_at < now() - interval '1 day'")
        await conn.execute("DELETE FROM notification_deliveries WHERE created_at < now() - interval '180 days'")


async def run() -> None:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:  # pragma: no cover
            pass
    log.info("agendador iniciado")
    last_cleanup = 0.0
    while not stop.is_set():
        t0 = time.monotonic()
        try:
            out = await tick()
            ev = out.get("eval") or {}
            if ev.get("opened") or ev.get("resolved") or any(out["notify"].values()):
                log.info("alertas: %s · notificações: %s", ev, out["notify"])
            if time.monotonic() - last_cleanup > CLEANUP_SECONDS:
                await cleanup()
                last_cleanup = time.monotonic()
        except pool.DatabaseUnavailable as exc:
            log.warning("banco indisponível: %s", exc)
        except Exception:  # noqa: BLE001 - o agendador não pode morrer por uma rodada
            log.exception("rodada do agendador falhou")
        try:
            await asyncio.wait_for(stop.wait(), max(1.0, EVAL_SECONDS - (time.monotonic() - t0)))
        except asyncio.TimeoutError:
            pass
    await pool.close_pool()
