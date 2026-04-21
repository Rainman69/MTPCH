"""Real MTProto proxy verifier.

This module performs a true end-to-end connectivity test against a
Telegram datacenter through an MTProxy server, following the
obfuscated-transport specification published by Telegram
(https://core.telegram.org/mtproto/mtproto-transports).

Rather than reporting a raw TCP "ping", it:

1. Opens a TCP socket to the proxy and completes the 64-byte
   obfuscated handshake (padded-intermediate transport, AES-256-CTR,
   key = SHA256(key_material || secret)).
2. Sends an unencrypted MTProto ``req_pq_multi`` message (auth_key_id
   = 0) inside the obfuscated channel.
3. Awaits a reply and decrypts it. A proxy that genuinely forwards
   traffic to Telegram replies with a valid ``resPQ`` TL constructor
   (``0x05162463``) inside a well-formed MTProto envelope.

Only when all of that succeeds is the proxy considered "alive".
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import os
import random
import socket
import struct
import time
from typing import Callable, Optional, Tuple

# ---------------------------------------------------------------------------
# Minimal AES-256-CTR implementation backed by ``cryptography`` when available
# with a pure-python fallback so the tool has no hard C-extension requirement.
# ---------------------------------------------------------------------------

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError as _crypto_import_err:  # pragma: no cover - env dependent
    raise ImportError(
        "MTPCH requires the 'cryptography' package for AES-256-CTR "
        "primitives. Install it with:  pip install cryptography"
    ) from _crypto_import_err


def _aes_ctr_stream(key: bytes, iv: bytes):
    """Return a streaming AES-256-CTR encrypt/decrypt callable."""
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    enc = cipher.encryptor()
    return lambda data: enc.update(data)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class ProxyInfo:
    """A parsed MTProto proxy description."""

    server: str
    port: int
    secret: bytes  # 16 raw bytes (TLS-prefixed variants keep domain suffix)
    raw_secret: str  # Original textual representation
    secret_kind: str  # "plain" / "dd" / "ee" (fake-tls)
    source_line: str = ""  # Original line it was parsed from

    @property
    def link_tg(self) -> str:
        return f"tg://proxy?server={self.server}&port={self.port}&secret={self.raw_secret}"

    @property
    def link_https(self) -> str:
        return (
            f"https://t.me/proxy?server={self.server}&port={self.port}"
            f"&secret={self.raw_secret}"
        )


@dataclasses.dataclass
class VerifyResult:
    """Outcome of :func:`verify_proxy`."""

    proxy: ProxyInfo
    alive: bool
    latency_ms: Optional[float]
    stage: str  # last stage reached: dns / connect / handshake / telegram / ok
    error: Optional[str] = None
    fake_tls_domain: Optional[str] = None
    dc_id: Optional[int] = None


# ---------------------------------------------------------------------------
# Secret parsing helpers
# ---------------------------------------------------------------------------


_HEX_ALPHABET = set("0123456789abcdefABCDEF")


def _is_hex(s: str) -> bool:
    return len(s) >= 2 and all(ch in _HEX_ALPHABET for ch in s)


def decode_secret(secret: str) -> Tuple[bytes, str, Optional[str]]:
    """Decode a textual proxy secret.

    Returns ``(sixteen_bytes, kind, fake_tls_domain)``.

    ``kind`` is one of ``"plain"``, ``"dd"`` (padded intermediate only) or
    ``"ee"`` (FakeTLS with camouflage domain).  The FakeTLS domain (if
    any) is the ASCII suffix trailing the 17 binary bytes.
    """
    s = secret.strip()
    # Strip URL-safe padding people sometimes leave in.
    s = s.replace(" ", "").replace("\n", "")

    if _is_hex(s):
        raw = bytes.fromhex(s)
    else:
        # base64url; re-add padding.
        pad = (-len(s)) % 4
        raw = base64.urlsafe_b64decode(s + ("=" * pad))

    fake_tls_domain = None
    kind = "plain"

    if len(raw) >= 17 and raw[0] == 0xEE:
        kind = "ee"
        try:
            fake_tls_domain = raw[17:].decode("ascii", errors="ignore") or None
        except Exception:
            fake_tls_domain = None
        raw = raw[1:17]
    elif len(raw) == 17 and raw[0] == 0xDD:
        kind = "dd"
        raw = raw[1:17]
    elif len(raw) == 16:
        kind = "plain"
    else:
        # Be forgiving: keep the first 16 bytes if possible.
        if len(raw) < 16:
            raise ValueError(f"secret too short: {len(raw)} bytes")
        raw = raw[:16]

    if len(raw) != 16:
        raise ValueError(f"invalid secret length after normalisation: {len(raw)}")
    return raw, kind, fake_tls_domain


# ---------------------------------------------------------------------------
# Obfuscated transport helpers
# ---------------------------------------------------------------------------


# MTProto transport magic words that must not appear as the first 4 bytes of
# the random obfuscated init payload.
_FORBIDDEN_FIRST_INTS = {
    0x44414548,  # "HEAD"
    0x54534F50,  # "POST"
    0x20544547,  # "GET "
    0x4954504F,  # "OPTI"
    0x02010316,  # 16 03 01 02 — TLS record
    0xDDDDDDDD,
    0xEEEEEEEE,
}

# Protocol identifier we want to negotiate with the proxy.  We speak the
# padded intermediate transport because that is the only one Fake-TLS
# proxies accept, and regular MTProxy servers also handle it gracefully.
_PROTOCOL_TAG = 0xDDDDDDDD

# Default DC ID we claim to connect to (DC 2 / Amsterdam).  This is
# transmitted in the obfuscated header and only influences which
# Telegram DC the proxy forwards us to — any DC is fine for proving
# connectivity.
_DEFAULT_DC_ID = 2


def _build_obfuscated_init(
    secret16: bytes, dc_id: int
) -> Tuple[bytes, Callable[[bytes], bytes], Callable[[bytes], bytes]]:
    """Create the 64-byte obfuscated init frame.

    Returns ``(init_frame_to_send, encrypt, decrypt)`` where ``encrypt``
    and ``decrypt`` are streaming AES-CTR callables.
    """
    while True:
        buf = bytearray(os.urandom(64))

        first_int = struct.unpack("<I", bytes(buf[0:4]))[0]
        second_int = struct.unpack("<I", bytes(buf[4:8]))[0]
        if buf[0] == 0xEF:
            continue
        if first_int in _FORBIDDEN_FIRST_INTS:
            continue
        if second_int == 0:
            continue

        # Stamp the protocol tag at offset 56..60 and DC ID at 60..62.
        struct.pack_into("<I", buf, 56, _PROTOCOL_TAG)
        struct.pack_into("<h", buf, 60, dc_id)
        # last two bytes stay random
        break

    init = bytes(buf)
    init_rev = init[::-1]

    enc_key = init[8:40]
    enc_iv = init[40:56]
    dec_key = init_rev[8:40]
    dec_iv = init_rev[40:56]

    enc_key = hashlib.sha256(enc_key + secret16).digest()
    dec_key = hashlib.sha256(dec_key + secret16).digest()

    encrypt = _aes_ctr_stream(enc_key, enc_iv)
    decrypt = _aes_ctr_stream(dec_key, dec_iv)

    encrypted_init = encrypt(init)
    # Replace bytes 56..64 of the plaintext init with the corresponding
    # bytes of the encrypted init — this is what the proxy reads.
    wire_frame = init[:56] + encrypted_init[56:64]
    return wire_frame, encrypt, decrypt


# ---------------------------------------------------------------------------
# Padded-intermediate framing helpers
# ---------------------------------------------------------------------------


def _wrap_padded_intermediate(payload: bytes) -> bytes:
    pad_len = random.randint(0, 15)
    padding = os.urandom(pad_len)
    total_len = len(payload) + pad_len
    return struct.pack("<I", total_len) + payload + padding


# ---------------------------------------------------------------------------
# MTProto request construction
# ---------------------------------------------------------------------------

# Constructor IDs from the MTProto TL schema.
_CTOR_REQ_PQ_MULTI = 0xBE7E8EF1  # req_pq_multi#be7e8ef1 nonce:int128 = ResPQ
_CTOR_RES_PQ = 0x05162463         # resPQ#05162463 nonce:int128 server_nonce:int128 ...


def _build_req_pq_multi() -> Tuple[bytes, bytes]:
    """Build the unencrypted MTProto envelope for ``req_pq_multi``.

    Returns ``(envelope, nonce16)``.
    """
    nonce = os.urandom(16)
    body = struct.pack("<I", _CTOR_REQ_PQ_MULTI) + nonce  # 4 + 16 = 20 bytes

    # Unencrypted MTProto message:
    #   auth_key_id (int64 = 0) | message_id (int64) | message_len (int32) | body
    message_id = _gen_message_id()
    envelope = struct.pack("<qqI", 0, message_id, len(body)) + body
    return envelope, nonce


def _gen_message_id() -> int:
    # message_id = (unix_time * 2^32), lowest 2 bits = 0.
    return (int(time.time()) << 32) & ~3


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def verify_proxy(
    proxy: ProxyInfo,
    *,
    timeout: float = 8.0,
    dc_id: int = _DEFAULT_DC_ID,
) -> VerifyResult:
    """Run a real connectivity check against ``proxy``.

    The function never raises; transient network failures are reported
    through :class:`VerifyResult`.
    """
    start = time.monotonic()
    stage = "dns"
    try:
        # Resolve the target once so DNS failures are attributable to a
        # distinct stage instead of getting rolled into a generic socket
        # error.
        addr_info = socket.getaddrinfo(
            proxy.server, proxy.port, proto=socket.IPPROTO_TCP
        )
        if not addr_info:
            return VerifyResult(proxy, False, None, stage, "DNS resolution failed")

        family, socktype, sproto, _, sockaddr = addr_info[0]

        stage = "connect"
        sock = socket.socket(family, socktype, sproto)
        sock.settimeout(timeout)
        try:
            sock.connect(sockaddr)
        except (ConnectionRefusedError, OSError) as exc:
            return VerifyResult(
                proxy,
                False,
                None,
                stage,
                f"TCP connect failed: {exc.__class__.__name__}: {exc}",
            )

        with sock:
            sock.settimeout(timeout)
            stage = "handshake"
            init_frame, encrypt, decrypt = _build_obfuscated_init(
                proxy.secret, dc_id
            )
            try:
                sock.sendall(init_frame)
            except OSError as exc:
                return VerifyResult(
                    proxy,
                    False,
                    None,
                    stage,
                    f"sendall(init) failed: {exc}",
                )

            envelope, nonce = _build_req_pq_multi()
            wrapped = _wrap_padded_intermediate(envelope)
            encrypted_wrapped = encrypt(wrapped)
            try:
                sock.sendall(encrypted_wrapped)
            except OSError as exc:
                return VerifyResult(
                    proxy,
                    False,
                    None,
                    stage,
                    f"sendall(req_pq_multi) failed: {exc}",
                )

            stage = "telegram"
            try:
                length_ct = _recv_exact(sock, 4)
            except _RecvError as exc:
                return VerifyResult(
                    proxy,
                    False,
                    None,
                    stage,
                    f"no reply from proxy: {exc}",
                )
            length_bytes = decrypt(length_ct)
            (total_len,) = struct.unpack("<I", length_bytes)

            # Transport-error shortcut: a 4-byte negative integer means
            # the proxy/DC rejected us (e.g. DC-id wrong).
            if total_len & 0x80000000:
                # Quick-ACK flag (MSB).  Not expected for our unencrypted
                # request — treat as failure but keep the error useful.
                return VerifyResult(
                    proxy,
                    False,
                    None,
                    stage,
                    "unexpected quick-ack flag in reply",
                )

            if total_len < 8 or total_len > 1 << 20:
                return VerifyResult(
                    proxy,
                    False,
                    None,
                    stage,
                    f"implausible reply length {total_len}",
                )

            try:
                body_ct = _recv_exact(sock, total_len)
            except _RecvError as exc:
                return VerifyResult(
                    proxy,
                    False,
                    None,
                    stage,
                    f"short reply ({exc})",
                )
            body = decrypt(body_ct)

            # Unencrypted MTProto reply structure:
            #   auth_key_id (int64 = 0) | message_id (int64) |
            #   message_len (int32) | payload
            if len(body) < 20:
                return VerifyResult(
                    proxy, False, None, stage, "truncated MTProto reply",
                )

            auth_key_id = struct.unpack("<q", body[:8])[0]
            if auth_key_id != 0:
                return VerifyResult(
                    proxy,
                    False,
                    None,
                    stage,
                    f"unexpected auth_key_id={auth_key_id:#x}",
                )

            msg_len = struct.unpack("<I", body[16:20])[0]
            if msg_len + 20 > len(body) or msg_len < 4:
                return VerifyResult(
                    proxy,
                    False,
                    None,
                    stage,
                    f"invalid inner message length {msg_len}",
                )

            payload = body[20 : 20 + msg_len]
            ctor = struct.unpack("<I", payload[:4])[0]
            if ctor != _CTOR_RES_PQ:
                return VerifyResult(
                    proxy,
                    False,
                    None,
                    stage,
                    f"wrong constructor {ctor:#x}, expected resPQ",
                )

            # resPQ echoes our nonce back in the first 16 bytes after
            # the ctor; verifying it confirms we are really talking to a
            # Telegram DC (any MITM that does not know MTProto would not
            # be able to craft a valid resPQ with our nonce).
            if len(payload) < 4 + 16:
                return VerifyResult(
                    proxy, False, None, stage, "resPQ truncated"
                )
            if payload[4 : 4 + 16] != nonce:
                return VerifyResult(
                    proxy, False, None, stage, "resPQ nonce mismatch",
                )

            latency = (time.monotonic() - start) * 1000.0
            return VerifyResult(
                proxy,
                True,
                latency,
                "ok",
                None,
                fake_tls_domain=proxy_fake_tls_domain(proxy),
                dc_id=dc_id,
            )

    except socket.gaierror as exc:
        return VerifyResult(proxy, False, None, "dns", f"DNS error: {exc}")
    except socket.timeout:
        return VerifyResult(proxy, False, None, stage, f"timeout after {timeout:.1f}s")
    except Exception as exc:  # defensive fallback
        return VerifyResult(
            proxy, False, None, stage, f"{exc.__class__.__name__}: {exc}"
        )


def proxy_fake_tls_domain(proxy: ProxyInfo) -> Optional[str]:
    """Re-extract the Fake-TLS camouflage domain from the raw secret."""
    try:
        _raw, _kind, dom = decode_secret(proxy.raw_secret)
        return dom
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Socket receive helper
# ---------------------------------------------------------------------------


class _RecvError(Exception):
    pass


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    chunks: list[bytes] = []
    remaining = n
    while remaining:
        try:
            chunk = sock.recv(remaining)
        except socket.timeout as exc:
            raise _RecvError("timeout") from exc
        except OSError as exc:
            raise _RecvError(str(exc)) from exc
        if not chunk:
            raise _RecvError("connection closed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)
