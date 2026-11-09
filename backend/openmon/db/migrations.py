"""Migrations SQL do OpenMon.

Cada arquivo ``NNNN_nome.sql`` em ``migrations/`` é aplicado uma única vez, em
ordem, dentro de uma transação e com ``SET LOCAL ROLE openmon_owner`` para que
todos os objetos pertençam ao papel dono (e não ao superusuário ``postgres``).
O controle fica em ``openmon.schema_migrations`` com o SHA-256 de cada arquivo.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

MIGRATIONS_DIR = Path(__file__).parent / "migrations"
OWNER_ROLE = "openmon_owner"
APP_ROLE = "openmon_app"
SCHEMA = "openmon"

_NAME_RE = re.compile(r"^(\d{4})_[a-z0-9_]+\.sql$")


@dataclass(frozen=True)
class Migration:
    version: str  # nome do arquivo sem .sql, ex.: 0001_core_tenancy_auth_vault
    path: Path

    @property
    def sql(self) -> str:
        return self.path.read_text(encoding="utf-8")

    @property
    def checksum(self) -> str:
        return hashlib.sha256(self.path.read_bytes()).hexdigest()

    def wrapped(self) -> str:
        """SQL pronto para ``psql -f``: transação, papel dono e registro da versão."""
        return (
            "\\set ON_ERROR_STOP on\n"
            "\\o /dev/null\n"  # resultados dos SELECT de políticas; erros seguem no stderr
            "BEGIN;\n"
            f"SET LOCAL ROLE {OWNER_ROLE};\n"
            f"{self.sql}\n"
            f"INSERT INTO {SCHEMA}.schema_migrations (version, checksum) "
            f"VALUES ('{self.version}', '{self.checksum}');\n"
            "COMMIT;\n"
        )


def discover(directory: Path = MIGRATIONS_DIR) -> list[Migration]:
    migrations = []
    for path in sorted(directory.glob("*.sql")):
        if not _NAME_RE.match(path.name):
            raise ValueError(f"nome de migration inválido: {path.name}")
        migrations.append(Migration(version=path.stem, path=path))
    numbers = [m.version[:4] for m in migrations]
    if len(numbers) != len(set(numbers)):
        raise ValueError("números de migration duplicados")
    return migrations


def bootstrap_sql() -> str:
    """Executado como superusuário ``postgres`` no banco ``openmon``.

    CREATE EXTENSION timescaledb exige superusuário; o resto pertence ao dono.
    """
    return f"""\\set ON_ERROR_STOP on
CREATE EXTENSION IF NOT EXISTS timescaledb;
CREATE SCHEMA IF NOT EXISTS {SCHEMA} AUTHORIZATION {OWNER_ROLE};
ALTER SCHEMA {SCHEMA} OWNER TO {OWNER_ROLE};
CREATE TABLE IF NOT EXISTS {SCHEMA}.schema_migrations (
    version     text        PRIMARY KEY,
    checksum    text        NOT NULL,
    applied_at  timestamptz NOT NULL DEFAULT now(),
    applied_by  text        NOT NULL DEFAULT session_user
);
ALTER TABLE {SCHEMA}.schema_migrations OWNER TO {OWNER_ROLE};
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO {OWNER_ROLE}, {APP_ROLE};
ALTER ROLE {OWNER_ROLE} IN DATABASE openmon SET search_path = {SCHEMA}, public;
ALTER ROLE {APP_ROLE} IN DATABASE openmon SET search_path = {SCHEMA}, public;
"""
