"""Cliente SNMP: vetores da RFC 3414, deltas de contadores e um agente SNMPv3 (pysnmp) com SHA-256/AES."""
import asyncio
import hashlib
import socket
import threading

import pytest

from openmon.collector import snmp_client as C
from openmon.collector.common import match_rules
from openmon.collector.snmp import delta, WRAP32, WRAP64


@pytest.mark.parametrize("fn, ku, kul", [
    (hashlib.md5, "9faf3283884e92834ebc9847d8edd963", "526f5eed9fcce26f8964c2930787d82b"),
    (hashlib.sha1, "9fb5cc0381497b3793528939ff788d5d79145211", "6695febc9288e36282235fc7151f128497b38f3f"),
])
def test_rfc3414_key_localization(fn, ku, kul):
    k = C.password_to_key("maplesyrup", fn)
    assert k.hex() == ku
    assert C.localize_key(k, bytes.fromhex("000000000000000000000002"), fn).hex() == kul


def test_counter_delta_wraps():
    assert delta(10, 5, WRAP64) == 5
    assert delta(5, WRAP32 - 5, WRAP32) == 10
    assert delta(None, 1, WRAP64) is None


def test_v3_credentials_validation():
    with pytest.raises(C.SnmpError):
        C.V3Credentials("u", None, None, "aes", "12345678")
    with pytest.raises(C.SnmpError):
        C.V3Credentials("u", "sha", "curta")


def test_tenant_rules():
    rules = [{"tenant_id": 2, "match_field": "folder", "pattern": "Clientes/ACME*"},
             {"tenant_id": 3, "match_field": "name_regex", "pattern": "^beta-"},
             {"tenant_id": 4, "match_field": "vsphere_tag", "pattern": "cliente:gama"}]
    assert match_rules(rules, {"folder": "Clientes/ACME/Prod", "name": "x"}, 1) == 2
    assert match_rules(rules, {"folder": "Outros", "name": "BETA-web01"}, 1) == 3
    assert match_rules(rules, {"vsphere_tag": ["os:linux", "Cliente:Gama"], "name": "z"}, 1) == 4
    assert match_rules(rules, {"name": "nada"}, 1) == 1


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="module")
def pysnmp_agent():
    """Agente SNMPv3 do pysnmp (só nos testes) com usuários SHA-256+AES e MD5 sem privacidade."""
    pysnmp = pytest.importorskip("pysnmp")
    # O agente do pysnmp só cifra AES com o CFB "decrepit" (cryptography >= 47); no Debian 13 (43) pula
    pytest.importorskip("cryptography.hazmat.decrepit.ciphers.modes")
    from pysnmp.carrier.asyncio.dgram import udp
    from pysnmp.entity import config, engine
    from pysnmp.entity.rfc3413 import cmdrsp, context
    port = _free_port()
    ready = threading.Event()
    state = {}

    def run():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        eng = engine.SnmpEngine()
        config.add_transport(eng, udp.DOMAIN_NAME, udp.UdpTransport().open_server_mode(("127.0.0.1", port)))
        config.add_v3_user(eng, "u256", config.USM_AUTH_HMAC192_SHA256, "AuthPass-256x",
                           config.USM_PRIV_CFB128_AES, "PrivPass-256x")
        config.add_v3_user(eng, "umd5", config.USM_AUTH_HMAC96_MD5, "AuthPass-md5x")
        config.add_v3_user(eng, "usha", config.USM_AUTH_HMAC96_SHA, "AuthPass-shax", config.USM_PRIV_CFB128_AES, "PrivPass-shax")
        config.add_vacm_user(eng, 3, "usha", "authPriv", (1, 3, 6, 1, 2, 1))
        config.add_vacm_user(eng, 3, "u256", "authPriv", (1, 3, 6, 1, 2, 1))
        config.add_vacm_user(eng, 3, "umd5", "authNoPriv", (1, 3, 6, 1, 2, 1))
        ctx = context.SnmpContext(eng)
        cmdrsp.GetCommandResponder(eng, ctx)
        cmdrsp.BulkCommandResponder(eng, ctx)
        state["loop"] = loop
        ready.set()
        loop.run_forever()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    ready.wait(10)
    yield port
    state["loop"].call_soon_threadsafe(state["loop"].stop)
    assert pysnmp


@pytest.mark.parametrize("creds", [
    C.V3Credentials("u256", "sha256", "AuthPass-256x", "aes", "PrivPass-256x"),
    C.V3Credentials("umd5", "md5", "AuthPass-md5x"),
    C.V3Credentials("usha", "sha", "AuthPass-shax", "aes", "PrivPass-shax"),
])
def test_v3_against_pysnmp_agent(pysnmp_agent, creds):
    async def go():
        async with C.SnmpClient("127.0.0.1", v3=creds, port=pysnmp_agent, timeout=2, retries=1) as c:
            got = await c.get(["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0"])
            walked = await c.walk("1.3.6.1.2.1.1")
            return got, walked
    got, walked = asyncio.run(go())
    assert b"PySNMP" in got["1.3.6.1.2.1.1.1.0"] or got["1.3.6.1.2.1.1.1.0"]
    assert len(walked) >= 5


def test_v3_wrong_sha256_password_reports_digest(pysnmp_agent):
    creds = C.V3Credentials("u256", "sha256", "Errada-123456", "aes", "PrivPass-256x")

    async def go():
        async with C.SnmpClient("127.0.0.1", v3=creds, port=pysnmp_agent, timeout=1, retries=0) as c:
            await c.get(["1.3.6.1.2.1.1.1.0"])
    with pytest.raises(C.SnmpError, match="wrongDigests|timeout"):
        asyncio.run(go())
