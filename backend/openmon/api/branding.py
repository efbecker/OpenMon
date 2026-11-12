"""Branding: logo da empresa, favicon e banner da tela de login.

As imagens ficam no banco (``system_settings``, chaves ``branding.logo``, ``branding.favicon`` e
``branding.banner``, com o conteúdo em base64), então voltam sozinhas numa reinstalação da VM 1 que use
o mesmo banco. Só quem tem ``system.settings`` (Administrador global) envia ou remove.

* ``GET /api/branding``: público (a tela de login também usa). Diz o que está configurado, com a URL de
  cada imagem já versionada pelo hash;
* ``GET /api/branding/{logo|favicon|banner}``: público, devolve a imagem;
* ``PUT /api/admin/branding/{tipo}``: corpo = o arquivo (bytes crus, ``Content-Type`` da imagem);
* ``DELETE /api/admin/branding/{tipo}``: volta ao padrão do OpenMon.

A validação olha o conteúdo (assinatura do arquivo), não a extensão. SVG com script, handlers ``on*``,
``javascript:``, ``foreignObject`` ou referências externas é recusado; além disso a resposta sai com uma
CSP própria que proíbe scripts.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import unquote

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from openmon.api.admin_tenants import _audit, _db_error, _iso
from openmon.api.auth import SessionInfo, require_permission
from openmon.db import pool

router = APIRouter(tags=["branding"])

KB, MB = 1024, 1024 * 1024
KINDS: dict[str, dict[str, Any]] = {
    "logo": {"max": 2 * MB, "types": ("png", "svg", "jpeg"), "label": "Logo", "hint": "PNG, SVG ou JPG — até 2 MB"},
    "favicon": {"max": 512 * KB, "types": ("ico", "png"), "label": "Favicon", "hint": "ICO ou PNG — até 512 KB"},
    "banner": {"max": 5 * MB, "types": ("png", "svg", "webp", "jpeg"), "label": "Banner de login",
               "hint": "PNG, SVG, WebP ou JPG — até 5 MB"},
}
MIME = {"png": "image/png", "jpeg": "image/jpeg", "webp": "image/webp", "svg": "image/svg+xml",
        "ico": "image/x-icon"}
NAME = {"png": "PNG", "jpeg": "JPG", "webp": "WebP", "svg": "SVG", "ico": "ICO"}
CACHE_TTL = 30.0
_cache: tuple[float, dict[str, dict[str, Any]]] | None = None

_SVG_FORBIDDEN = re.compile(
    rb"<\s*script|<\s*foreignobject|<\s*iframe|<\s*embed|<\s*object|\son[a-z]+\s*=|javascript\s*:|"
    rb"<!entity|<!doctype|(?:href|src)\s*=\s*[\"']\s*(?:https?:|//|data:text)|@import|url\(\s*[\"']?\s*(?:https?:|//)",
    re.I)


class BrandingError(ValueError):
    pass


def sniff(data: bytes) -> str | None:
    """Tipo real da imagem pelo conteúdo."""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    if data.startswith(b"\x00\x00\x01\x00") and len(data) >= 22:
        return "ico"
    head = data[:65536].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if head.startswith((b"<svg", b"<?xml", b"<!--", b"<!doctype")) and b"<svg" in head:
        return "svg"
    return None


_DOCTYPE = re.compile(rb"<!DOCTYPE\s[^\[>]*(?:\[(.*?)\])?\s*>", re.I | re.S)
_ENTITY = re.compile(rb"<!ENTITY\s+([A-Za-z_][\w.-]*)\s+(?:\"([^\"<&%]*)\"|'([^'<&%]*)')\s*>", re.S)


def clean_svg(data: bytes) -> bytes:
    """Tira o DOCTYPE que o Illustrator/Inkscape põem no SVG.

    Entidades simples do subconjunto interno (``<!ENTITY ns_svg "http://...">``, comuns no Illustrator) são
    trocadas pelo valor no texto; qualquer outra coisa no DOCTYPE faz o arquivo ser recusado.
    """
    m = _DOCTYPE.search(data)
    out = data if not m else _strip_doctype(data, m)
    if re.search(rb"&(?!(?:amp|lt|gt|quot|apos|#\d+|#x[0-9a-f]+);)[A-Za-z_][\w.-]*;", out, re.I):
        raise BrandingError("SVG com entidades desconhecidas não é aceito. Exporte o logo como SVG simples ou PNG.")
    return out


def _strip_doctype(data: bytes, m: re.Match[bytes]) -> bytes:
    subset = m.group(1) or b""
    entities: dict[bytes, bytes] = {}
    rest = subset
    for e in _ENTITY.finditer(subset):
        entities[e.group(1)] = e.group(2) if e.group(2) is not None else e.group(3)
        rest = rest.replace(e.group(0), b"")
    rest = re.sub(rb"<!--.*?-->", b"", rest, flags=re.S)
    if rest.strip():
        raise BrandingError("SVG com DOCTYPE complexo não é aceito. Exporte o logo como SVG simples ou PNG.")
    out = data[:m.start()] + data[m.end():]
    for name, value in entities.items():
        out = out.replace(b"&" + name + b";", value)
    return out


def validate(kind: str, data: bytes) -> str:
    """Confere tamanho e formato; devolve o tipo (png, jpeg, ...). Use ``prepare`` para o SVG já limpo."""
    return prepare(kind, data)[0]


def prepare(kind: str, data: bytes) -> tuple[str, bytes]:
    """Confere tamanho e formato; devolve o tipo e o conteúdo a guardar (SVG sem DOCTYPE)."""
    spec = KINDS[kind]
    if not data:
        raise BrandingError("Arquivo vazio.")
    if len(data) > spec["max"]:
        raise BrandingError(f"{spec['label']}: arquivo maior que o permitido ({spec['hint']}).")
    fmt = sniff(data)
    if fmt not in spec["types"]:
        found = f" (o arquivo é {NAME[fmt]})" if fmt else ""
        raise BrandingError(f"{spec['label']}: formato não aceito{found}. Use {spec['hint']}.")
    if fmt == "svg":
        try:
            data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise BrandingError("SVG precisa estar em UTF-8.") from exc
        data = clean_svg(data)
        if _SVG_FORBIDDEN.search(data):
            raise BrandingError("SVG com script, eventos, DOCTYPE ou referências externas não é aceito. "
                                "Exporte o logo como SVG simples ou PNG.")
    return fmt, data


def _meta(kind: str, v: dict[str, Any]) -> dict[str, Any]:
    return {"url": f"/api/branding/{kind}?v={v['sha256'][:16]}", "mime": v["mime"], "size": v["size"],
            "filename": v.get("filename"), "uploaded_by": v.get("uploaded_by"), "uploaded_at": v.get("uploaded_at")}


async def _load() -> dict[str, dict[str, Any]]:
    global _cache
    now = time.monotonic()
    if _cache and now - _cache[0] < CACHE_TTL:
        return _cache[1]
    try:
        async with pool.system_transaction() as conn:
            rows = await conn.fetch("SELECT key, value FROM system_settings WHERE key = ANY($1::text[])",
                                    [f"branding.{k}" for k in KINDS])
    except pool.DatabaseUnavailable:
        return {}  # antes do deploy do banco: sem branding, telas com o padrão
    out: dict[str, dict[str, Any]] = {}
    for r in rows:
        v = json.loads(r["value"]) if isinstance(r["value"], str) else dict(r["value"] or {})
        if v.get("data") and v.get("mime"):
            out[r["key"].split(".", 1)[1]] = v
    _cache = (now, out)
    return out


def _invalidate() -> None:
    global _cache
    _cache = None


@router.get("/api/branding")
async def get_branding() -> dict[str, Any]:
    stored = await _load()
    return {k: {kk: vv for kk, vv in _meta(k, stored[k]).items() if kk in ("url", "mime")} if k in stored else None
            for k in KINDS}


@router.get("/api/branding/{kind}")
async def get_image(kind: str) -> Response:
    if kind not in KINDS:
        raise HTTPException(404, "Tipo desconhecido.")
    v = (await _load()).get(kind)
    if v is None:
        raise HTTPException(404, "Nada configurado.")
    return Response(base64.b64decode(v["data"]), media_type=v["mime"], headers={
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:; sandbox",
        "X-Content-Type-Options": "nosniff", "Cache-Control": "public, max-age=300",
        "ETag": f'"{v["sha256"][:32]}"'})


@router.get("/api/admin/branding")
async def admin_get(session: SessionInfo = Depends(require_permission("system.settings"))) -> dict[str, Any]:
    _invalidate()
    stored = await _load()
    return {"items": {k: _meta(k, stored[k]) if k in stored else None for k in KINDS},
            "limits": {k: {"max_bytes": s["max"], "hint": s["hint"], "mimes": sorted({MIME[t] for t in s["types"]})}
                       for k, s in KINDS.items()}}


def _kind(kind: str) -> str:
    if kind not in KINDS:
        raise HTTPException(404, "Tipo desconhecido: use logo, favicon ou banner.")
    return kind


@router.put("/api/admin/branding/{kind}")
async def upload(kind: str, request: Request,
                 session: SessionInfo = Depends(require_permission("system.settings", write=True))
                 ) -> dict[str, Any]:
    kind = _kind(kind)
    limit = KINDS[kind]["max"]
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise HTTPException(413, f"{KINDS[kind]['label']}: arquivo maior que o permitido ({KINDS[kind]['hint']}).")
    data = bytearray()
    async for chunk in request.stream():
        data += chunk
        if len(data) > limit:
            raise HTTPException(413, f"{KINDS[kind]['label']}: arquivo maior que o permitido ({KINDS[kind]['hint']}).")
    try:
        fmt, data = prepare(kind, bytes(data))
    except BrandingError as exc:
        raise HTTPException(422, str(exc)) from exc
    filename = re.sub(r"[^\w .()-]", "_", unquote(request.headers.get("x-filename", "")))[:120].strip() or None
    value = {"mime": MIME[fmt], "size": len(data), "sha256": hashlib.sha256(data).hexdigest(), "filename": filename,
             "uploaded_by": session.user["username"], "uploaded_at": datetime.now(timezone.utc).isoformat(),
             "data": base64.b64encode(data).decode("ascii")}
    try:
        async with session.db() as conn:
            await conn.execute(
                """INSERT INTO system_settings (key, value, updated_at, updated_by) VALUES ($1, $2::jsonb, now(), $3)
                   ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now(),
                                                   updated_by = EXCLUDED.updated_by""",
                f"branding.{kind}", json.dumps(value), session.user["id"])
            await _audit(conn, session, request, "branding.upload", "branding", kind, None,
                         {"mime": value["mime"], "size": value["size"], "sha256": value["sha256"],
                          "filename": filename})
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    _invalidate()
    return {"ok": True, "item": _meta(kind, value)}


@router.delete("/api/admin/branding/{kind}")
async def remove(kind: str, request: Request,
                 session: SessionInfo = Depends(require_permission("system.settings", write=True))
                 ) -> dict[str, Any]:
    kind = _kind(kind)
    try:
        async with session.db() as conn:
            gone = await conn.fetchval("DELETE FROM system_settings WHERE key = $1 RETURNING updated_at",
                                       f"branding.{kind}")
            if gone is not None:
                await _audit(conn, session, request, "branding.remove", "branding", kind, None,
                             {"was_updated_at": _iso(gone)})
    except pool.DatabaseUnavailable as exc:
        raise _db_error(exc) from exc
    _invalidate()
    return {"ok": True, "removed": gone is not None}
