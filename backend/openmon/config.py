"""Caminhos do OpenMon na VM 1 (FHS). Variáveis OPENMON_* sobrescrevem (testes)."""
from __future__ import annotations

import os
from pathlib import Path


def _path(env: str, default: str) -> Path:
    return Path(os.environ.get(env, default))


def state_dir() -> Path:
    return _path("OPENMON_STATE_DIR", "/var/lib/openmon")


def log_dir() -> Path:
    return _path("OPENMON_LOG_DIR", "/var/log/openmon")


def db_config_dir() -> Path:
    """Configuração gerada pelo deploy do banco (única parte de /etc gravável pela API)."""
    return _path("OPENMON_DB_CONFIG_DIR", "/etc/openmon/database")


def setup_token_file() -> Path:
    return state_dir() / "setup.token"


def db_provisioned() -> bool:
    return (db_config_dir() / "database.conf").is_file()
