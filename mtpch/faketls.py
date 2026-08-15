"""Fake-TLS (``ee`` secret) transport support.

MTProxy's Fake-TLS mode wraps the obfuscated MTProto stream inside a
TLS 1.3-looking session so that DPI sees an ordinary HTTPS connection:

1. The client sends a 517-byte ``ClientHello`` whose 32-byte ``random``
   field is **not** random — it is
   ``HMAC-SHA256(secret, client_hello_with_random_zeroed)`` with the
   current unix timestamp XORed into bytes 28..32.
2. The server replies with ``ServerHello`` + ``ChangeCipherSpec`` +
   a first application-data record.  Its own ``random`` field is
   ``HMAC-SHA256(secret, client_digest || whole_reply_with_random_zeroed)``.
   Verifying it proves the peer knows the secret.
3. Afterwards both sides speak the ordinary obfuscated MTProto
   transport, but every payload is wrapped in TLS application-data
   records (``0x17 0x03 0x03 <len:2>``).

Reference implementation cross-checked against ``alexbers/mtprotoproxy``
(`handle_fake_tls_handshake`) and verified against a live MTProxy.

Only the framing is TLS-shaped; no real TLS cryptography is involved, so
this module deliberately does not use ``ssl``.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from typing import Callable

# --- record types -------------------------------------------------------

TLS_RECORD_CHANGE_CIPHER = 0x14
TLS_RECORD_ALERT = 0x15
TLS_RECORD_HANDSHAKE = 0x16
TLS_RECORD_APPLICATION = 0x17

DIGEST_POS = 11
DIGEST_LEN = 32
SESSION_ID_LEN_POS = DIGEST_POS + DIGEST_LEN  # 43
SESSION_ID_POS = SESSION_ID_LEN_POS + 1       # 44

CLIENT_HELLO_LEN = 517
MAX_TLS_RECORD = 16384 + 512


class FakeTLSError(Exception):
    """Raised when a peer does not complete the Fake-TLS handshake."""


def _hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def gen_x25519_public_key() -> bytes:
    """A 32-byte value shaped like an x25519 public key.

    Mirrors MTProxy: pick ``n`` mod P and send ``n**2 mod P`` so the value
    is a quadratic residue (a plausible curve point) without needing a
    real key exchange.
    """
    p = 2**255 - 19
    n = int.from_bytes(os.urandom(32), "big") % p
    return ((n * n) % p).to_bytes(32, "little")


def _encode_domain(domain: str) -> bytes:
    """Encode an SNI hostname, tolerating the junk found in real secrets.

    Public ``ee`` secrets frequently carry malformed camouflage domains
    (truncated, non-ASCII, or absurdly long).  IDNA-encode when possible,
    fall back to raw ASCII bytes, and reject only what cannot fit the
    fixed-size ClientHello.
    """
    if not domain:
        return b"www.google.com"
    try:
        return domain.encode("idna")
    except UnicodeError:
        return domain.encode("ascii", "ignore")


def build_client_hello(secret16: bytes, domain: str) -> tuple[bytes, bytes, bytes]:
    """Build the 517-byte Fake-TLS ``ClientHello``.

    Returns ``(wire_bytes, client_digest, session_id)``.  ``client_digest``
    is needed later to verify the server's reply.
    """
    dom = _encode_domain(domain)
    session_id = os.urandom(32)

    parts: list[bytes] = [
        b"\x16\x03\x01\x02\x00",          # record: handshake, TLS 1.0, len 512
        b"\x01\x00\x01\xfc",              # client_hello, len 508
        b"\x03\x03",                      # TLS 1.2
        b"\x00" * DIGEST_LEN,             # random -> digest placeholder
        b"\x20",                          # session_id length (32)
        session_id,
        b"\x00\x20",                      # cipher suites length (32)
        bytes.fromhex(
            "fafa13011302130"
            "3c02bc02fc02cc030cca9cca8c013c014"
            "009c009d002f0035"
        ),
        b"\x01\x00",                      # compression: none
        b"\x01\x93",                      # extensions length
        b"\x4a\x4a\x00\x00",              # GREASE
        # --- SNI ---
        b"\x00\x00",
        struct.pack(">H", 2 + 1 + 2 + len(dom)),
        struct.pack(">H", 1 + 2 + len(dom)),
        b"\x00",
        struct.pack(">H", len(dom)),
        dom,
        # --- fixed extension block ---
        b"\x00\x17\x00\x00",              # extended_master_secret
        b"\xff\x01\x00\x01\x00",          # renegotiation_info
        b"\x00\x0a\x00\x0a\x00\x08\xba\xba\x00\x1d\x00\x17\x00\x18",
        b"\x00\x0b\x00\x02\x01\x00",      # ec_point_formats
        b"\x00\x23\x00\x00",              # session_ticket
        b"\x00\x10\x00\x0e\x00\x0c\x02h2\x08http/1.1",
        b"\x00\x05\x00\x05\x01\x00\x00\x00\x00",
        bytes.fromhex("000d0012001004030804040105030805050108060601"),
        b"\x00\x12\x00\x00",              # signed_certificate_timestamp
        # --- key_share (x25519) ---
        b"\x00\x33\x00\x2b\x00\x29",
        b"\xba\xba\x00\x01\x00",
        b"\x00\x1d\x00\x20",
        gen_x25519_public_key(),
        b"\x00\x2d\x00\x02\x01\x01",      # psk_key_exchange_modes
        b"\x00\x2b\x00\x0b\x0a\x9a\x9a\x03\x04\x03\x03\x03\x02\x03\x01",
        b"\x00\x1b\x00\x03\x02\x00\x02",  # compress_certificate
        b"\x1a\x1a\x00\x01\x00",          # GREASE
    ]

    head = b"".join(parts)
    pad_len = CLIENT_HELLO_LEN - (len(head) + 4)
    if pad_len < 0:
        raise FakeTLSError(f"ClientHello overflow for domain {domain!r}")
    hello = head + b"\x00\x15" + struct.pack(">H", pad_len) + b"\x00" * pad_len

    if len(hello) != CLIENT_HELLO_LEN:
        raise FakeTLSError(f"ClientHello is {len(hello)} bytes, expected {CLIENT_HELLO_LEN}")

    digest = _hmac_sha256(secret16, hello)
    now = struct.pack("<I", int(__import__("time").time()))
    stamped = bytearray(digest)
    for i in range(4):
        stamped[28 + i] = digest[28 + i] ^ now[i]
    stamped = bytes(stamped)

    wire = bytearray(hello)
    wire[DIGEST_POS:DIGEST_POS + DIGEST_LEN] = stamped
    return bytes(wire), stamped, session_id


def read_and_verify_server_hello(
    recv_exact: Callable[[int], bytes],
    secret16: bytes,
    client_digest: bytes,
    session_id: bytes,
) -> None:
    """Consume the server's handshake records and authenticate them.

    ``recv_exact(n)`` must return exactly ``n`` bytes or raise.

    Record sizes differ between MTProxy builds (the masked certificate
    length varies), so records are parsed from their headers rather than
    assuming the commonly-quoted 127-byte ``ServerHello``.
    """
    chunks: list[bytes] = []
    saw_handshake = False
    saw_change_cipher = False

    for index in range(8):
        header = recv_exact(5)
        rtype = header[0]

        if index == 0 and header[:3] != b"\x16\x03\x03":
            raise FakeTLSError(
                "peer did not answer with a TLS ServerHello "
                "(not a Fake-TLS proxy, or wrong secret)"
            )
        if rtype == TLS_RECORD_ALERT:
            raise FakeTLSError("TLS alert from peer (secret rejected)")

        (length,) = struct.unpack(">H", header[3:5])
        if length > MAX_TLS_RECORD:
            raise FakeTLSError(f"implausible TLS record length {length}")

        body = recv_exact(length)
        chunks.append(header + body)

        if rtype == TLS_RECORD_HANDSHAKE:
            saw_handshake = True
        elif rtype == TLS_RECORD_CHANGE_CIPHER:
            saw_change_cipher = True
        elif rtype == TLS_RECORD_APPLICATION:
            break
    else:
        raise FakeTLSError("too many TLS records before application data")

    if not saw_handshake or not saw_change_cipher:
        raise FakeTLSError("incomplete Fake-TLS handshake")

    reply = b"".join(chunks)
    if len(reply) < SESSION_ID_POS + 32:
        raise FakeTLSError("ServerHello too short")

    # The server echoes our session_id, which pins the reply to our request.
    if reply[SESSION_ID_LEN_POS] == 0x20:
        echoed = reply[SESSION_ID_POS:SESSION_ID_POS + 32]
        if echoed != session_id:
            raise FakeTLSError("TLS session id mismatch")

    server_digest = reply[DIGEST_POS:DIGEST_POS + DIGEST_LEN]
    zeroed = bytearray(reply)
    zeroed[DIGEST_POS:DIGEST_POS + DIGEST_LEN] = b"\x00" * DIGEST_LEN
    expected = _hmac_sha256(secret16, client_digest + bytes(zeroed))

    if not hmac.compare_digest(server_digest, expected):
        raise FakeTLSError("Fake-TLS server digest mismatch (secret is wrong)")


def wrap_application_data(payload: bytes) -> bytes:
    """Wrap ``payload`` in TLS application-data records."""
    out = bytearray()
    max_chunk = 16384
    for start in range(0, len(payload), max_chunk):
        chunk = payload[start:start + max_chunk]
        out += b"\x17\x03\x03" + struct.pack(">H", len(chunk)) + chunk
    return bytes(out)


class TLSRecordReader:
    """Turn a record-framed stream back into a byte stream."""

    __slots__ = ("_recv_exact", "_buf")

    def __init__(self, recv_exact: Callable[[int], bytes]) -> None:
        self._recv_exact = recv_exact
        self._buf = bytearray()

    def read_exactly(self, n: int) -> bytes:
        while len(self._buf) < n:
            header = self._recv_exact(5)
            rtype = header[0]
            if rtype == TLS_RECORD_ALERT:
                raise FakeTLSError("TLS alert mid-stream")
            if rtype not in (TLS_RECORD_APPLICATION, TLS_RECORD_CHANGE_CIPHER):
                raise FakeTLSError(f"unexpected TLS record type 0x{rtype:02x}")
            (length,) = struct.unpack(">H", header[3:5])
            if length > MAX_TLS_RECORD:
                raise FakeTLSError(f"implausible TLS record length {length}")
            body = self._recv_exact(length)
            if rtype == TLS_RECORD_APPLICATION:
                self._buf += body
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out
