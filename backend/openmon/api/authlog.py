"""Log estruturado de autenticação em /var/log/openmon/auth.log (lido pelo Fail2ban).

Formato: uma linha JSON por evento, começando sempre por ts, event e ip, que é o
que o filtro packaging/fail2ban/filter.d/openmon-auth.conf espera.
"""
from __future__ import annotations

import json
import logging
import logging.handlers
from datetime import datetime, timezone

from openmon import config

_logger: logging.Logger | None = None


def _get() -> logging.Logger:
    global _logger
    if _logger is None:
        logger = logging.getLogger("openmon.auth")
        logger.propagate = False
        try:
            handler: logging.Handler = logging.handlers.WatchedFileHandler(config.log_dir() / "auth.log")
        except OSError:
            handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        _logger = logger
    return _logger


def event(name: str, ip: str, **fields: object) -> None:
    record = {"ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "event": name, "ip": ip}
    record.update(fields)
    _get().info(json.dumps(record, separators=(",", ":"), ensure_ascii=False))


def reset() -> None:  # testes
    global _logger
    if _logger is not None:
        for h in list(_logger.handlers):
            _logger.removeHandler(h)
            h.close()
    _logger = None
