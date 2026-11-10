"""``python3 -m openmon.collector <vmware|hyperv|veeam|snmp>`` (unit openmon-collector@.service).

``python3 -m openmon.collector poll <id>`` coleta uma integração uma vez e mostra o resultado.
"""
from __future__ import annotations

import asyncio
import logging
import os
import sys

from openmon.collector.common import INSTANCE_KIND


def main(argv: list[str]) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    if len(argv) == 2 and argv[0] == "poll" and argv[1].isdigit():
        from openmon.collector.engine import poll_once
        status, msg = asyncio.run(poll_once(int(argv[1]), claim=False))
        print(f"{status}: {msg}")
        return 0 if status == "ok" else 1
    if len(argv) != 1 or argv[0] not in INSTANCE_KIND:
        print(__doc__, file=sys.stderr)
        return 2
    kind = INSTANCE_KIND[argv[0]]
    from openmon.collector import engine
    os.environ.setdefault("OPENMON_DB_POOL_MAX", str(engine.DB_POOL[kind]))
    os.environ.setdefault("OPENMON_DB_COMMAND_TIMEOUT", "120")
    asyncio.run(engine.run(kind))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
