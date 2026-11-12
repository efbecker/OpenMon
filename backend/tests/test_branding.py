"""Branding: validação das imagens e rotas (banco simulado em memória)."""
import json
from contextlib import asynccontextmanager

import pytest

from openmon.api import branding
from openmon.db import pool

from test_auth import client, login  # noqa: F401

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
JPG = b"\xff\xd8\xff\xe0" + b"\x00" * 64
ICO = b"\x00\x00\x01\x00\x01\x00" + b"\x00" * 64
WEBP = b"RIFF\x00\x00\x00\x00WEBPVP8 " + b"\x00" * 32
SVG = b'<?xml version="1.0"?>\n<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><rect width="10" height="10"/></svg>'


def test_sniff_by_content():
    assert [branding.sniff(x) for x in (PNG, JPG, ICO, WEBP, SVG)] == ["png", "jpeg", "ico", "webp", "svg"]
    assert branding.sniff(b"GIF89a....") is None


@pytest.mark.parametrize("kind,data,ok", [
    ("logo", PNG, True), ("logo", SVG, True), ("logo", JPG, True), ("logo", ICO, False), ("logo", WEBP, False),
    ("favicon", ICO, True), ("favicon", PNG, True), ("favicon", SVG, False),
    ("banner", WEBP, True), ("banner", SVG, True), ("banner", ICO, False),
])
def test_formats_per_kind(kind, data, ok):
    if ok:
        branding.validate(kind, data)
    else:
        with pytest.raises(branding.BrandingError, match="formato não aceito"):
            branding.validate(kind, data)


def test_size_limits():
    branding.validate("favicon", PNG + b"\x00" * (512 * 1024 - len(PNG)))
    with pytest.raises(branding.BrandingError, match="maior"):
        branding.validate("favicon", PNG + b"\x00" * (512 * 1024))
    with pytest.raises(branding.BrandingError, match="maior"):
        branding.validate("logo", PNG + b"\x00" * (2 * 1024 * 1024))


@pytest.mark.parametrize("evil", [
    b'<svg><script>alert(1)</script></svg>', b'<svg onload="alert(1)"></svg>',
    b'<svg><a href="javascript:alert(1)"><rect/></a></svg>', b'<svg><foreignObject><div/></foreignObject></svg>',
    b'<svg><image href="https://evil.example/x.png"/></svg>', b'<!DOCTYPE svg [<!ENTITY x "y">]><svg></svg>',
])
def test_dangerous_svg_rejected(evil):
    with pytest.raises(branding.BrandingError, match="SVG"):
        branding.validate("logo", evil)


class FakeConn:
    def __init__(self, db):
        self.db = db

    async def fetch(self, q, keys):
        return [{"key": k, "value": json.dumps(self.db["settings"][k])} for k in keys if k in self.db["settings"]]

    async def execute(self, q, *args):
        if "system_settings" in q:
            self.db["settings"][args[0]] = json.loads(args[1])
        elif "audit_log" in q:
            self.db["audit"].append(args[5])

    async def fetchval(self, q, key):
        return "2026-01-01" if self.db["settings"].pop(key, None) is not None else None


@pytest.fixture()
def db(monkeypatch):
    state = {"settings": {}, "audit": []}

    @asynccontextmanager
    async def transaction(*a, **k):
        yield FakeConn(state)
    monkeypatch.setattr(pool, "transaction", transaction)
    monkeypatch.setattr(pool, "system_transaction", lambda: transaction())
    branding._invalidate()
    yield state
    branding._invalidate()


def test_upload_serve_and_remove(client, db):  # noqa: F811
    assert client.get("/api/branding").json() == {"logo": None, "favicon": None, "banner": None}
    csrf = login(client).json()["csrf_token"]
    put = lambda kind, data, **h: client.put(f"/api/admin/branding/{kind}", content=data,  # noqa: E731
                                             headers={"X-CSRF-Token": csrf, "Content-Type": "image/png", **h})
    assert put("logo", PNG, **{"X-CSRF-Token": "errado"}).status_code == 403
    r = put("logo", PNG, **{"X-Filename": "logo%20empresa.png"})
    assert r.status_code == 200, r.text
    assert r.json()["item"]["filename"] == "logo empresa.png" and db["audit"] == ["branding.upload"]
    assert put("favicon", SVG).status_code == 422
    assert put("banner", PNG + b"\x00" * (5 * 1024 * 1024)).status_code == 413
    assert put("outro", PNG).status_code == 404

    pub = client.get("/api/branding").json()
    assert pub["logo"]["mime"] == "image/png" and pub["logo"]["url"].startswith("/api/branding/logo?v=")
    assert pub["favicon"] is None
    img = client.get(pub["logo"]["url"])
    assert img.status_code == 200 and img.content == PNG and img.headers["content-type"] == "image/png"
    assert "sandbox" in img.headers["content-security-policy"]
    adm = client.get("/api/admin/branding").json()
    assert adm["items"]["logo"]["uploaded_by"] == "admin" and adm["limits"]["banner"]["max_bytes"] == 5 * 1024 * 1024

    r = client.delete("/api/admin/branding/logo", headers={"X-CSRF-Token": csrf})
    assert r.json()["removed"] is True
    assert client.get("/api/branding").json()["logo"] is None
    assert client.get("/api/branding/logo").status_code == 404


def test_admin_requires_login(client, db):  # noqa: F811
    assert client.get("/api/admin/branding").status_code == 401
    assert client.put("/api/admin/branding/logo", content=PNG).status_code == 401
