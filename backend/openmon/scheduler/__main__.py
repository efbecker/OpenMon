"""``python3 -m openmon.scheduler`` (unit openmon-scheduler.service). ``... once`` roda uma rodada e mostra."""
from __future__ import annotations

import asyncio
import logging
import os
import sys


def main(argv: list[str]) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    os.environ.setdefault("OPENMON_DB_POOL_MAX", "4")
    from openmon import scheduler
    if argv == ["once"]:
        print(asyncio.run(scheduler.tick()))
        return 0
    if argv:
        print(__doc__, file=sys.stderr)
        return 2
    asyncio.run(scheduler.run())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
