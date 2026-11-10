"""API do OpenMon (atrás do Apache2, em /run/openmon/api.sock).

    uvicorn openmon.api.main:app --uds /run/openmon/api.sock
"""
from __future__ import annotations

from fastapi import FastAPI

from openmon import __version__
from openmon.api import admin_security, auth, setup

# Sem /docs nem /openapi.json em produção: menos superfície exposta
app = FastAPI(title="OpenMon", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
app.include_router(setup.router)
app.include_router(auth.router)
app.include_router(admin_security.router)


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


# Desenvolvimento/testes sem Apache: OPENMON_DEV_STATIC=<frontend/public> serve os estáticos.
# Em produção quem serve os estáticos é o Apache (DocumentRoot /var/www/openmon/public).
import os as _os  # noqa: E402

if _os.environ.get("OPENMON_DEV_STATIC"):
    from fastapi.staticfiles import StaticFiles

    app.mount("/", StaticFiles(directory=_os.environ["OPENMON_DEV_STATIC"], html=True), name="static")
