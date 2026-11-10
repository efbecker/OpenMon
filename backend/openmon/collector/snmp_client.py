"""Cliente SNMP assíncrono (GET / GETBULK) v2c e v3, sem dependências além de python3-cryptography.

A parte v2c (BER, GETBULK walk) vem do OpenFlow (``backend/app/services/snmp_client.py``).
Aqui foi acrescentado o SNMPv3 com USM:

* autenticação HMAC-MD5-96, HMAC-SHA-96 (RFC 3414) e HMAC-SHA-256-192 (RFC 7860);
* privacidade AES-128-CFB (RFC 3826) e DES-CBC (legado, RFC 3414);
* descoberta do engineID e sincronia de tempo (Report ``usmStatsNotInTimeWindows``).

Um cliente faz uma requisição por vez (o paralelismo vem de muitos equipamentos
consultados ao mesmo tempo pelo coletor).
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import random
import socket
import time
from dataclasses import dataclass
from typing import Any

# BER
INTEGER, OCTET_STRING, NULL, OID = 0x02, 0x04, 0x05, 0x06
SEQUENCE = 0x30
IP_ADDRESS, COUNTER32, GAUGE32, TIMETICKS, OPAQUE, COUNTER64 = 0x40, 0x41, 0x42, 0x43, 0x44, 0x46
NO_SUCH_OBJECT, NO_SUCH_INSTANCE, END_OF_MIB_VIEW = 0x80, 0x81, 0x82
GET_REQUEST, GET_NEXT_REQUEST, RESPONSE, GET_BULK_REQUEST, REPORT = 0xA0, 0xA1, 0xA2, 0xA5, 0xA8

SNMP_ERRORS = {1: "tooBig", 2: "noSuchName", 3: "badValue", 4: "readOnly", 5: "genErr", 6: "noAccess",
               16: "authorizationError"}

USM_REPORTS = {
    "1.3.6.1.6.3.15.1.1.1.0": "nível de segurança não suportado pelo equipamento (unsupportedSecLevels)",
    "1.3.6.1.6.3.15.1.1.2.0": "fora da janela de tempo (notInTimeWindows)",
    "1.3.6.1.6.3.15.1.1.3.0": "usuário SNMPv3 desconhecido no equipamento (unknownUserNames)",
    "1.3.6.1.6.3.15.1.1.4.0": "engineID desconhecido (unknownEngineIDs)",
    "1.3.6.1.6.3.15.1.1.5.0": "senha de autenticação ou algoritmo errado (wrongDigests)",
    "1.3.6.1.6.3.15.1.1.6.0": "senha de privacidade ou algoritmo errado (decryptionErrors)",
}

AUTH_PROTOCOLS = {"md5": (hashlib.md5, 12), "sha": (hashlib.sha1, 12), "sha256": (hashlib.sha256, 24)}
PRIV_PROTOCOLS = ("aes", "des")


class SnmpError(Exception):
    pass


class SnmpTimeout(SnmpError):
    pass


# -----------------------------------------------------------------------------
# BER
# -----------------------------------------------------------------------------
def _encode_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(out)]) + out


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _encode_length(len(value)) + value


def _encode_int(v: int) -> bytes:
    length = max(1, (v.bit_length() + 8) // 8)
    return _tlv(INTEGER, v.to_bytes(length, "big", signed=True))


def _encode_oid(oid: str) -> bytes:
    parts = [int(p) for p in oid.strip(".").split(".")]
    body = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.insert(0, 0x80 | (p & 0x7F))
            p >>= 7
        body += bytes(chunk)
    return _tlv(OID, body)


def _decode_tlv(data: bytes, pos: int) -> tuple[int, bytes, int]:
    if pos + 2 > len(data):
        raise SnmpError("Resposta SNMP truncada")
    tag = data[pos]
    pos += 1
    length = data[pos]
    pos += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    value = data[pos:pos + length]
    if len(value) != length:
        raise SnmpError("Resposta SNMP truncada")
    return tag, value, pos + length


def _decode_oid(value: bytes) -> str:
    if not value:
        return ""
    first = value[0]
    parts = [min(first // 40, 2), first - 40 * min(first // 40, 2)]
    n = 0
    for b in value[1:]:
        n = (n << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(n)
            n = 0
    return ".".join(str(p) for p in parts)


def _decode_value(tag: int, value: bytes) -> Any:
    if tag == INTEGER:
        return int.from_bytes(value, "big", signed=True)
    if tag in (COUNTER32, GAUGE32, TIMETICKS, COUNTER64):
        return int.from_bytes(value, "big", signed=False)
    if tag in (OCTET_STRING, OPAQUE):
        return value
    if tag == OID:
        return _decode_oid(value)
    if tag == IP_ADDRESS and len(value) == 4:
        return socket.inet_ntoa(value)
    if tag in (NULL, NO_SUCH_OBJECT, NO_SUCH_INSTANCE, END_OF_MIB_VIEW):
        return None
    return value


def _int(value: bytes) -> int:
    return int.from_bytes(value, "big", signed=True) if value else 0


def _pdu(pdu_tag: int, request_id: int, oids: list[str], non_repeaters: int = 0, max_repetitions: int = 0) -> bytes:
    varbinds = b"".join(_tlv(SEQUENCE, _encode_oid(o) + _tlv(NULL, b"")) for o in oids)
    return _tlv(pdu_tag, _encode_int(request_id) + _encode_int(non_repeaters) + _encode_int(max_repetitions)
                + _tlv(SEQUENCE, varbinds))


def _parse_pdu(pdu_tag: int, pdu: bytes) -> tuple[int, int, int, list[tuple[str, int, Any]]]:
    p = 0
    _, rid, p = _decode_tlv(pdu, p)
    _, err, p = _decode_tlv(pdu, p)
    _, _, p = _decode_tlv(pdu, p)
    _, vbl, _ = _decode_tlv(pdu, p)
    varbinds = []
    q = 0
    while q < len(vbl):
        _, vb, q = _decode_tlv(vbl, q)
        _, oid_raw, r = _decode_tlv(vb, 0)
        vtag, vval, _ = _decode_tlv(vb, r)
        varbinds.append((_decode_oid(oid_raw), vtag, _decode_value(vtag, vval)))
    return pdu_tag, _int(rid), _int(err), varbinds


# -----------------------------------------------------------------------------
# USM (SNMPv3)
# -----------------------------------------------------------------------------
def password_to_key(password: str, hash_fn: Any) -> bytes:
    """RFC 3414 A.2.1: 1 MiB da senha repetida."""
    pw = password.encode()
    if not pw:
        raise SnmpError("senha SNMPv3 vazia")
    h = hash_fn()
    count = 0
    buf = (pw * (64 // len(pw) + 2))
    while count < 1048576:
        start = count % len(pw)
        h.update(buf[start:start + 64])
        count += 64
    return h.digest()


def localize_key(ku: bytes, engine_id: bytes, hash_fn: Any) -> bytes:
    return hash_fn(ku + engine_id + ku).digest()


@dataclass
class V3Credentials:
    username: str
    auth_protocol: str | None = None   # md5 | sha | sha256 | None
    auth_password: str | None = None
    priv_protocol: str | None = None   # aes | des | None
    priv_password: str | None = None
    context_name: str = ""

    def __post_init__(self) -> None:
        if self.auth_protocol and self.auth_protocol not in AUTH_PROTOCOLS:
            raise SnmpError(f"protocolo de autenticação inválido: {self.auth_protocol}")
        if self.priv_protocol and self.priv_protocol not in PRIV_PROTOCOLS:
            raise SnmpError(f"protocolo de privacidade inválido: {self.priv_protocol}")
        if self.priv_protocol and not self.auth_protocol:
            raise SnmpError("privacidade exige autenticação (authPriv)")
        if self.auth_protocol and len(self.auth_password or "") < 8:
            raise SnmpError("senha de autenticação SNMPv3 precisa de 8+ caracteres")
        if self.priv_protocol and len(self.priv_password or "") < 8:
            raise SnmpError("senha de privacidade SNMPv3 precisa de 8+ caracteres")

    @property
    def flags(self) -> int:
        return (1 if self.auth_protocol else 0) | (2 if self.priv_protocol else 0)


def _cipher(algorithm: Any, mode: Any) -> Any:
    from cryptography.hazmat.primitives.ciphers import Cipher
    return Cipher(algorithm, mode)


def _aes(key: bytes, iv: bytes) -> Any:
    from cryptography.hazmat.primitives.ciphers import algorithms
    try:
        from cryptography.hazmat.decrepit.ciphers.modes import CFB  # cryptography >= 47
    except ImportError:  # Debian 13: cryptography 43
        from cryptography.hazmat.primitives.ciphers.modes import CFB
    return _cipher(algorithms.AES(key[:16]), CFB(iv))


def _des(key: bytes, iv: bytes) -> Any:
    from cryptography.hazmat.primitives.ciphers import modes
    try:
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES  # cryptography >= 43
    except ImportError:  # pragma: no cover - versões antigas
        from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
    return _cipher(TripleDES(key[:8] * 3), modes.CBC(iv))  # 3DES com K1=K2=K3 == DES


class _Usm:
    def __init__(self, creds: V3Credentials) -> None:
        self.c = creds
        self.engine_id = b""
        self.boots = 0
        self.time = 0
        self._time_at = 0.0
        self._salt = random.getrandbits(64)
        self._kul_auth = b""
        self._kul_priv = b""
        self._ku_auth = b""
        self._ku_priv = b""
        self._last_boots_time = (0, 0)
        if creds.auth_protocol:
            fn = AUTH_PROTOCOLS[creds.auth_protocol][0]
            self._ku_auth = password_to_key(creds.auth_password or "", fn)
            if creds.priv_protocol:
                self._ku_priv = password_to_key(creds.priv_password or "", fn)

    def set_engine(self, engine_id: bytes, boots: int, engine_time: int) -> None:
        if engine_id != self.engine_id and self.c.auth_protocol:
            fn = AUTH_PROTOCOLS[self.c.auth_protocol][0]
            self._kul_auth = localize_key(self._ku_auth, engine_id, fn)
            if self.c.priv_protocol:
                self._kul_priv = localize_key(self._ku_priv, engine_id, fn)
        self.engine_id, self.boots, self.time, self._time_at = engine_id, boots, engine_time, time.monotonic()

    def now(self) -> int:
        return self.time + int(time.monotonic() - self._time_at)

    def _sec_params(self, auth: bytes, priv: bytes, user: bytes | None = None, engine: bool = True) -> bytes:
        return _tlv(SEQUENCE,
                    _tlv(OCTET_STRING, self.engine_id if engine else b"")
                    + _encode_int(self.boots if engine else 0) + _encode_int(self.now() if engine else 0)
                    + _tlv(OCTET_STRING, self.c.username.encode() if user is None else user)
                    + _tlv(OCTET_STRING, auth) + _tlv(OCTET_STRING, priv))

    @staticmethod
    def _header(msg_id: int, flags: int) -> bytes:
        return _encode_int(3) + _tlv(SEQUENCE, _encode_int(msg_id) + _encode_int(65507)
                                     + _tlv(OCTET_STRING, bytes([flags | 4])) + _encode_int(3))

    def discovery(self, msg_id: int, request_id: int) -> bytes:
        scoped = _tlv(SEQUENCE, _tlv(OCTET_STRING, b"") + _tlv(OCTET_STRING, b"") + _pdu(GET_REQUEST, request_id, []))
        return _tlv(SEQUENCE, self._header(msg_id, 0)
                    + _tlv(OCTET_STRING, self._sec_params(b"", b"", user=b"", engine=False)) + scoped)

    def wrap(self, msg_id: int, pdu: bytes) -> bytes:
        scoped = _tlv(SEQUENCE, _tlv(OCTET_STRING, self.engine_id) + _tlv(OCTET_STRING, self.c.context_name.encode())
                      + pdu)
        priv_params = b""
        if self.c.priv_protocol:
            self._salt = (self._salt + 1) & 0xFFFFFFFFFFFFFFFF
            if self.c.priv_protocol == "aes":
                priv_params = self._salt.to_bytes(8, "big")
                iv = self.boots.to_bytes(4, "big") + self.now().to_bytes(4, "big") + priv_params
                enc = _aes(self._kul_priv, iv).encryptor()
                scoped = _tlv(OCTET_STRING, enc.update(scoped) + enc.finalize())
            else:
                priv_params = self.boots.to_bytes(4, "big") + (self._salt & 0xFFFFFFFF).to_bytes(4, "big")
                iv = bytes(a ^ b for a, b in zip(self._kul_priv[8:16], priv_params))
                padded = scoped + b"\x00" * (-len(scoped) % 8)
                enc = _des(self._kul_priv, iv).encryptor()
                scoped = _tlv(OCTET_STRING, enc.update(padded) + enc.finalize())
        auth_len = AUTH_PROTOCOLS[self.c.auth_protocol][1] if self.c.auth_protocol else 0
        placeholder = b"\x00" * auth_len
        msg = _tlv(SEQUENCE, self._header(msg_id, self.c.flags)
                   + _tlv(OCTET_STRING, self._sec_params(placeholder, priv_params)) + scoped)
        if self.c.auth_protocol:
            fn = AUTH_PROTOCOLS[self.c.auth_protocol][0]
            digest = hmac.new(self._kul_auth, msg, fn).digest()[:auth_len]
            idx = msg.find(_tlv(OCTET_STRING, placeholder))
            start = idx + len(_tlv(OCTET_STRING, placeholder)) - auth_len
            msg = msg[:start] + digest + msg[start + auth_len:]
        return msg

    def unwrap(self, data: bytes) -> tuple[int, int, bytes, tuple[int, int, int, list]]:
        """(msg_id, flags, engine_id, (pdu_tag, request_id, error, varbinds))."""
        _, msg, _ = _decode_tlv(data, 0)
        p = 0
        _, ver, p = _decode_tlv(msg, p)
        if _int(ver) != 3:
            raise SnmpError("resposta não é SNMPv3")
        _, header, p = _decode_tlv(msg, p)
        h = 0
        _, mid, h = _decode_tlv(header, h)
        _, _, h = _decode_tlv(header, h)
        _, fl, h = _decode_tlv(header, h)
        flags = fl[0] if fl else 0
        _, sec, p = _decode_tlv(msg, p)
        _, usm, _ = _decode_tlv(sec, 0)
        u = 0
        _, engine_id, u = _decode_tlv(usm, u)
        _, boots, u = _decode_tlv(usm, u)
        _, etime, u = _decode_tlv(usm, u)
        _, _, u = _decode_tlv(usm, u)
        _, auth_params, u = _decode_tlv(usm, u)
        _, priv_params, u = _decode_tlv(usm, u)
        tag, body, _ = _decode_tlv(msg, p)
        if flags & 1 and self.c.auth_protocol and self._kul_auth and engine_id == self.engine_id:
            fn, n = AUTH_PROTOCOLS[self.c.auth_protocol]
            zeroed = data.replace(auth_params, b"\x00" * len(auth_params), 1)
            if not hmac.compare_digest(hmac.new(self._kul_auth, zeroed, fn).digest()[:n], auth_params):
                raise SnmpError("assinatura da resposta SNMPv3 não confere")
        if flags & 2:
            if not self._kul_priv:
                raise SnmpError("resposta cifrada sem chave de privacidade")
            if self.c.priv_protocol == "aes":
                iv = _int_u(boots).to_bytes(4, "big") + _int_u(etime).to_bytes(4, "big") + priv_params
                dec = _aes(self._kul_priv, iv).decryptor()
            else:
                iv = bytes(a ^ b for a, b in zip(self._kul_priv[8:16], priv_params))
                dec = _des(self._kul_priv, iv).decryptor()
            plain = dec.update(body) + dec.finalize()
            _, body, _ = _decode_tlv(plain, 0)
        elif tag != SEQUENCE:
            raise SnmpError("ScopedPDU inválido")
        s = 0
        _, _, s = _decode_tlv(body, s)
        _, _, s = _decode_tlv(body, s)
        pdu_tag, pdu, _ = _decode_tlv(body, s)
        self._last_boots_time = (_int_u(boots), _int_u(etime))
        return _int(mid), flags, engine_id, _parse_pdu(pdu_tag, pdu)


def _int_u(v: bytes) -> int:
    return int.from_bytes(v, "big", signed=False) if v else 0


# -----------------------------------------------------------------------------
# Transporte
# -----------------------------------------------------------------------------
class _Proto(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.queue: asyncio.Queue[bytes | Exception] = asyncio.Queue()

    def datagram_received(self, data: bytes, addr: Any) -> None:
        self.queue.put_nowait(data)

    def error_received(self, exc: Exception) -> None:
        self.queue.put_nowait(SnmpError(str(exc)))


class SnmpClient:
    """``SnmpClient(host, community='x')`` para v2c ou ``SnmpClient(host, v3=V3Credentials(...))``."""

    def __init__(self, host: str, community: str | None = None, v3: V3Credentials | None = None, port: int = 161,
                 timeout: float = 2.0, retries: int = 2) -> None:
        if (community is None) == (v3 is None):
            raise SnmpError("informe a comunidade (v2c) ou as credenciais v3")
        self.host, self.community, self.v3, self.port = host, community, v3, port
        self.timeout, self.retries = timeout, retries
        self.resolved_ip = ""
        self._t: Any = None
        self._p: _Proto | None = None
        self._usm = _Usm(v3) if v3 else None
        self._discovered = False

    async def __aenter__(self) -> "SnmpClient":
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(self.host, self.port, type=socket.SOCK_DGRAM)
        if not infos:
            raise SnmpError(f"Não foi possível resolver {self.host}")
        family, _, _, _, sockaddr = infos[0]
        self.resolved_ip = sockaddr[0]
        self._t, self._p = await loop.create_datagram_endpoint(_Proto, remote_addr=sockaddr[:2], family=family)
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._t:
            self._t.close()

    async def _exchange(self, build: Any, match: Any) -> Any:
        assert self._p is not None
        for _ in range(self.retries + 1):
            req_id = random.randint(1, 2**31 - 1)
            while not self._p.queue.empty():
                self._p.queue.get_nowait()  # respostas atrasadas de tentativas anteriores
            self._t.sendto(build(req_id))
            deadline = time.monotonic() + self.timeout
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    break
                try:
                    data = await asyncio.wait_for(self._p.queue.get(), left)
                except asyncio.TimeoutError:
                    break
                if isinstance(data, Exception):
                    if "refused" in str(data).lower():
                        raise SnmpError(f"{self.host}:{self.port} recusou a consulta (nenhum agente SNMP nessa porta "
                                        "UDP)") from data
                    raise SnmpError(f"{self.host}:{self.port}: {data}") from data
                try:
                    out = match(req_id, data)
                except SnmpError:
                    raise
                except Exception:  # noqa: BLE001 - datagrama malformado: ignora
                    continue
                if out is not None:
                    return out
        hint = (" Com SNMPv3, o equipamento descarta sem responder quando a senha ou o algoritmo de privacidade "
                "estão errados." if self._discovered else "")
        raise SnmpTimeout(f"Sem resposta SNMP de {self.host}:{self.port} (timeout). Confira IP, credenciais e se "
                          f"a UDP 161 está liberada até o Servidor 1.{hint}")

    async def _discover(self) -> None:
        usm = self._usm
        assert usm is not None

        def match(rid: int, data: bytes) -> Any:
            _, msg, _ = _decode_tlv(data, 0)
            p = 0
            _, _, p = _decode_tlv(msg, p)
            _, _, p = _decode_tlv(msg, p)
            _, sec, p = _decode_tlv(msg, p)
            _, usm_raw, _ = _decode_tlv(sec, 0)
            u = 0
            _, engine_id, u = _decode_tlv(usm_raw, u)
            _, boots, u = _decode_tlv(usm_raw, u)
            _, etime, u = _decode_tlv(usm_raw, u)
            return engine_id, _int_u(boots), _int_u(etime)

        engine_id, boots, etime = await self._exchange(lambda rid: usm.discovery(rid, rid), match)
        if not engine_id:
            raise SnmpError("o equipamento não informou o engineID SNMPv3")
        usm.set_engine(engine_id, boots, etime)
        self._discovered = True

    async def _request(self, pdu_tag: int, oids: list[str], non_repeaters: int = 0,
                       max_repetitions: int = 0) -> list[tuple[str, int, Any]]:
        if self._usm is None:
            def build(rid: int) -> bytes:
                return _tlv(SEQUENCE, _encode_int(1) + _tlv(OCTET_STRING, (self.community or "").encode())
                            + _pdu(pdu_tag, rid, oids, non_repeaters, max_repetitions))

            def match(rid: int, data: bytes) -> Any:
                _, msg, _ = _decode_tlv(data, 0)
                p = 0
                _, _, p = _decode_tlv(msg, p)
                _, _, p = _decode_tlv(msg, p)
                tag, pdu, _ = _decode_tlv(msg, p)
                parsed = _parse_pdu(tag, pdu)
                return parsed if parsed[1] == rid else None
            tag, _, err, varbinds = await self._exchange(build, match)
        else:
            usm = self._usm
            if not self._discovered:
                await self._discover()
            for attempt in range(2):
                def build(rid: int) -> bytes:
                    return usm.wrap(rid, _pdu(pdu_tag, rid, oids, non_repeaters, max_repetitions))

                def match(rid: int, data: bytes) -> Any:
                    mid, _, _, parsed = usm.unwrap(data)
                    return parsed if mid == rid else None
                tag, _, err, varbinds = await self._exchange(build, match)
                if tag == REPORT:
                    oid = varbinds[0][0] if varbinds else ""
                    if oid in ("1.3.6.1.6.3.15.1.1.2.0", "1.3.6.1.6.3.15.1.1.4.0") and attempt == 0:
                        b, t = usm._last_boots_time
                        usm.set_engine(usm.engine_id, b, t)  # ressincroniza o relógio e tenta de novo
                        continue
                    raise SnmpError("SNMPv3: " + USM_REPORTS.get(oid, f"report {oid}"))
                break
        if tag != RESPONSE:
            raise SnmpError("PDU SNMP inesperado")
        if err:
            raise SnmpError(f"Erro SNMP: {SNMP_ERRORS.get(err, err)}")
        return varbinds

    async def get(self, oids: list[str]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for i in range(0, len(oids), 40):  # PDUs pequenas: evita tooBig e fragmentação
            for oid, tag, val in await self._request(GET_REQUEST, oids[i:i + 40]):
                if tag not in (NO_SUCH_OBJECT, NO_SUCH_INSTANCE, END_OF_MIB_VIEW):
                    out[oid] = val
        return out

    async def walk(self, base_oid: str, max_repetitions: int = 25, limit: int = 10000) -> dict[str, Any]:
        """Percorre uma subárvore com GETBULK. Devolve {sufixo_após_base: valor}."""
        base = base_oid.strip(".")
        prefix = base + "."
        results: dict[str, Any] = {}
        current = base
        while len(results) < limit:
            varbinds = await self._request(GET_BULK_REQUEST, [current], 0, max_repetitions)
            if not varbinds:
                break
            done = False
            for oid, tag, val in varbinds:
                if tag == END_OF_MIB_VIEW or not oid.startswith(prefix) or oid == current:
                    done = True
                    break
                results[oid[len(prefix):]] = val
                current = oid
            if done:
                break
        return results
