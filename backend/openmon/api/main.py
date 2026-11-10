"""API do OpenMon (atrás do Apache2, em /run/openmon/api.sock).

    uvicorn openmon.api.main:app --uds /run/openmon/api.sock
"""
from __future__ import annotations

import logging
import secrets

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from openmon import __version__
from openmon.api import admin_ldap, admin_security, admin_tenants, auth, setup

# Sem /docs nem /openapi.json em produção: menos superfície exposta
app = FastAPI(title="OpenMon", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
app.include_router(setup.router)
app.include_router(auth.router)
app.include_router(admin_security.router)
app.include_router(admin_tenants.router)
app.include_router(admin_ldap.router)

_log = logging.getLogger("openmon.api")
if not _log.handlers:  # stderr -> journal (journalctl -u openmon-api)
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    _log.addHandler(_h)
    _log.propagate = False


@app.exception_handler(Exception)
async def unexpected_error(request: Request, exc: Exception) -> JSONResponse:
    """Erro inesperado: traceback completo no journal e uma mensagem útil (sem segredos) na tela."""
    ref = secrets.token_hex(4)
    _log.error("erro %s em %s %s", ref, request.method, request.url.path, exc_info=exc)
    detail = f"Erro interno {ref} ({type(exc).__name__})"
    if request.url.path.startswith("/api/setup/"):
        # O assistente só é acessível com o token de instalação: vale mostrar a causa
        text = str(exc).splitlines()[0][:200] if str(exc) else ""
        if text:
            detail += f": {text}"
    detail += f". Detalhes no Servidor 1: sudo journalctl -u openmon-api --no-pager | grep -A40 {ref}"
    return JSONResponse({"detail": detail}, status_code=500)


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


# Desenvolvimento/testes sem Apache: OPENMON_DEV_STATIC=<frontend/public> serve os estáticos.
# Em produção quem serve os estáticos é o Apache (DocumentRoot /var/www/openmon/public).
import os as _os  # noqa: E402

if _os.environ.get("OPENMON_DEV_STATIC"):
    from fastapi.staticfiles import StaticFiles

    app.mount("/", StaticFiles(directory=_os.environ["OPENMON_DEV_STATIC"], html=True), name="static")
