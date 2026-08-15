"""Fake-TLS (``ee`` secret) tests.

Two layers of coverage:

* pure unit tests on the ClientHello / digest maths (no sockets)
* an in-process fake MTProxy that speaks the real Fake-TLS handshake and
  the obfuscated transport, so ``verify_proxy`` is exercised end to end
  without touching the network
"""

from __future__ import annotations

import hashlib
import hmac
import socket
import struct
import threading
import unittest

from mtpch.faketls import (
    CLIENT_HELLO_LEN,
    DIGEST_LEN,
    DIGEST_POS,
    SESSION_ID_POS,
    FakeTLSError,
    build_client_hello,
    gen_x25519_public_key,
    read_and_verify_server_hello,
    wrap_application_data,
)
from mtpch.verifier import ProxyInfo, decode_secret, verify_proxy

SECRET16 = bytes.fromhex("156f01983bf4d9ffff19e7ce7c5054a1")
DOMAIN = "www.google.com"
EE_SECRET = "ee" + SECRET16.hex() + DOMAIN.encode().hex()


def _hmac(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


# ---------------------------------------------------------------------------
# Unit level
# ---------------------------------------------------------------------------


class TestClientHello(unittest.TestCase):
    def test_exact_length_and_record_header(self):
        hello, digest, sess = build_client_hello(SECRET16, DOMAIN)
        self.assertEqual(len(hello), CLIENT_HELLO_LEN)
        self.assertEqual(hello[:3], b"\x16\x03\x01")
        self.assertEqual(len(digest), DIGEST_LEN)
        self.assertEqual(len(sess), 32)

    def test_digest_is_hmac_of_zeroed_hello(self):
        """MTProxy zeroes the random field, HMACs, then compares 28 bytes."""
        hello, digest, _ = build_client_hello(SECRET16, DOMAIN)
        zeroed = bytearray(hello)
        zeroed[DIGEST_POS:DIGEST_POS + DIGEST_LEN] = b"\x00" * DIGEST_LEN
        expected = _hmac(SECRET16, bytes(zeroed))
        self.assertEqual(digest[:28], expected[:28])

    def test_timestamp_xored_into_last_four_bytes(self):
        hello, digest, _ = build_client_hello(SECRET16, DOMAIN)
        zeroed = bytearray(hello)
        zeroed[DIGEST_POS:DIGEST_POS + DIGEST_LEN] = b"\x00" * DIGEST_LEN
        expected = _hmac(SECRET16, bytes(zeroed))
        stamp = bytes(digest[28 + i] ^ expected[28 + i] for i in range(4))
        (ts,) = struct.unpack("<I", stamp)
        import time

        self.assertLess(abs(time.time() - ts), 120, "timestamp must be current")

    def test_session_id_embedded_at_documented_offset(self):
        hello, _, sess = build_client_hello(SECRET16, DOMAIN)
        self.assertEqual(hello[SESSION_ID_POS:SESSION_ID_POS + 32], sess)

    def test_sni_carries_the_camouflage_domain(self):
        hello, _, _ = build_client_hello(SECRET16, "tv2c.digikala.com")
        self.assertIn(b"tv2c.digikala.com", hello)

    def test_wrong_secret_produces_a_different_digest(self):
        h1, d1, _ = build_client_hello(SECRET16, DOMAIN)
        h2, d2, _ = build_client_hello(b"\xff" * 16, DOMAIN)
        self.assertNotEqual(d1, d2)

    def test_absurdly_long_domain_is_rejected_not_truncated(self):
        with self.assertRaises(FakeTLSError):
            build_client_hello(SECRET16, "a" * 500 + ".com")

    def test_x25519_key_is_32_bytes(self):
        self.assertEqual(len(gen_x25519_public_key()), 32)


class TestApplicationDataFraming(unittest.TestCase):
    def test_single_record(self):
        out = wrap_application_data(b"hello")
        self.assertEqual(out[:3], b"\x17\x03\x03")
        self.assertEqual(struct.unpack(">H", out[3:5])[0], 5)
        self.assertEqual(out[5:], b"hello")

    def test_payload_split_across_records(self):
        payload = b"x" * 40000
        out = wrap_application_data(payload)
        # walk the records back and confirm the payload reassembles
        body, pos = b"", 0
        while pos < len(out):
            length = struct.unpack(">H", out[pos + 3:pos + 5])[0]
            self.assertLessEqual(length, 16384)
            body += out[pos + 5:pos + 5 + length]
            pos += 5 + length
        self.assertEqual(body, payload)


class TestServerHelloVerification(unittest.TestCase):
    def _reader(self, data: bytes):
        buf = {"d": data}

        def recv_exact(n: int) -> bytes:
            if len(buf["d"]) < n:
                raise AssertionError("fake stream exhausted")
            out, buf["d"] = buf["d"][:n], buf["d"][n:]
            return out

        return recv_exact

    def _server_reply(self, secret: bytes, client_digest: bytes, sess: bytes,
                      *, corrupt: bool = False, cert_len: int = 3925) -> bytes:
        ext = b"\x00\x2e\x00\x33\x00\x24\x00\x1d\x00\x20" + gen_x25519_public_key()
        ext += b"\x00\x2b\x00\x02\x03\x04"
        srv = b"\x03\x03" + b"\x00" * 32 + bytes([len(sess)]) + sess
        srv += b"\x13\x01" + b"\x00" + ext
        pkt = b"\x16\x03\x03" + struct.pack(">H", len(srv) + 4)
        pkt += b"\x02" + len(srv).to_bytes(3, "big") + srv
        pkt += b"\x14\x03\x03\x00\x01\x01"
        pkt += b"\x17\x03\x03" + struct.pack(">H", cert_len) + b"\x00" * cert_len
        digest = _hmac(secret, client_digest + pkt)
        if corrupt:
            digest = bytes([digest[0] ^ 0xFF]) + digest[1:]
        return pkt[:DIGEST_POS] + digest + pkt[DIGEST_POS + DIGEST_LEN:]

    def test_valid_reply_accepted(self):
        _, digest, sess = build_client_hello(SECRET16, DOMAIN)
        reply = self._server_reply(SECRET16, digest, sess)
        read_and_verify_server_hello(self._reader(reply), SECRET16, digest, sess)

    def test_variable_certificate_length_accepted(self):
        """Record sizes differ between MTProxy builds — must not be hardcoded."""
        for cert_len in (1024, 3924, 3925, 8000):
            _, digest, sess = build_client_hello(SECRET16, DOMAIN)
            reply = self._server_reply(SECRET16, digest, sess, cert_len=cert_len)
            read_and_verify_server_hello(self._reader(reply), SECRET16, digest, sess)

    def test_corrupt_digest_rejected(self):
        _, digest, sess = build_client_hello(SECRET16, DOMAIN)
        reply = self._server_reply(SECRET16, digest, sess, corrupt=True)
        with self.assertRaisesRegex(FakeTLSError, "digest mismatch"):
            read_and_verify_server_hello(self._reader(reply), SECRET16, digest, sess)

    def test_reply_signed_with_another_secret_rejected(self):
        _, digest, sess = build_client_hello(SECRET16, DOMAIN)
        reply = self._server_reply(b"\xaa" * 16, digest, sess)
        with self.assertRaisesRegex(FakeTLSError, "digest mismatch"):
            read_and_verify_server_hello(self._reader(reply), SECRET16, digest, sess)

    def test_foreign_session_id_rejected(self):
        _, digest, sess = build_client_hello(SECRET16, DOMAIN)
        reply = self._server_reply(SECRET16, digest, b"\x11" * 32)
        with self.assertRaisesRegex(FakeTLSError, "session id mismatch"):
            read_and_verify_server_hello(self._reader(reply), SECRET16, digest, sess)

    def test_non_tls_peer_rejected(self):
        _, digest, sess = build_client_hello(SECRET16, DOMAIN)
        with self.assertRaisesRegex(FakeTLSError, "ServerHello"):
            read_and_verify_server_hello(
                self._reader(b"HTTP/1.1 200 OK\r\n\r\n" + b"\x00" * 200),
                SECRET16, digest, sess,
            )

    def test_tls_alert_reported_clearly(self):
        _, digest, sess = build_client_hello(SECRET16, DOMAIN)
        alert = b"\x16\x03\x03\x00\x02\x00\x00" + b"\x15\x03\x03\x00\x02\x02\x28"
        with self.assertRaises(FakeTLSError):
            read_and_verify_server_hello(self._reader(alert), SECRET16, digest, sess)


# ---------------------------------------------------------------------------
# End-to-end against an in-process fake MTProxy
# ---------------------------------------------------------------------------


class FakeMTProxy(threading.Thread):
    """Minimal MTProxy that accepts one connection and answers resPQ."""

    daemon = True

    def __init__(self, secret: bytes, *, fake_tls: bool, mode: str = "ok"):
        super().__init__()
        self.secret = secret
        self.fake_tls = fake_tls
        self.mode = mode
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.error: str | None = None

    def run(self) -> None:
        try:
            conn, _ = self.sock.accept()
        except OSError:
            return
        with conn:
            conn.settimeout(5)
            try:
                self._serve(conn)
            except Exception as exc:  # surfaced to the test on failure
                self.error = f"{exc.__class__.__name__}: {exc}"

    # -- helpers ---------------------------------------------------------

    def _recv_exact(self, conn: socket.socket, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                raise EOFError("client closed")
            buf += chunk
        return buf

    def _serve(self, conn: socket.socket) -> None:
        from mtpch.verifier import _aes_ctr_stream

        read = lambda n: self._recv_exact(conn, n)  # noqa: E731
        send = conn.sendall

        if self.fake_tls:
            hello = read(CLIENT_HELLO_LEN)
            digest = hello[DIGEST_POS:DIGEST_POS + DIGEST_LEN]
            zeroed = bytearray(hello)
            zeroed[DIGEST_POS:DIGEST_POS + DIGEST_LEN] = b"\x00" * DIGEST_LEN
            expected = _hmac(self.secret, bytes(zeroed))
            if digest[:28] != expected[:28]:
                raise AssertionError("client digest did not authenticate")

            sess = hello[SESSION_ID_POS:SESSION_ID_POS + 32]
            ext = b"\x00\x2e\x00\x33\x00\x24\x00\x1d\x00\x20"
            ext += gen_x25519_public_key() + b"\x00\x2b\x00\x02\x03\x04"
            srv = b"\x03\x03" + b"\x00" * 32 + bytes([32]) + sess
            srv += b"\x13\x01" + b"\x00" + ext
            pkt = b"\x16\x03\x03" + struct.pack(">H", len(srv) + 4)
            pkt += b"\x02" + len(srv).to_bytes(3, "big") + srv
            pkt += b"\x14\x03\x03\x00\x01\x01"
            pkt += b"\x17\x03\x03" + struct.pack(">H", 64) + b"\x00" * 64
            sdig = _hmac(self.secret, digest + pkt)
            send(pkt[:DIGEST_POS] + sdig + pkt[DIGEST_POS + DIGEST_LEN:])

            # everything after the handshake is record-framed
            pending = bytearray()

            def read(n: int) -> bytes:  # noqa: F811
                while len(pending) < n:
                    hdr = self._recv_exact(conn, 5)
                    (length,) = struct.unpack(">H", hdr[3:5])
                    body = self._recv_exact(conn, length)
                    if hdr[0] == 0x17:
                        pending.extend(body)
                out = bytes(pending[:n])
                del pending[:n]
                return out

            def send(data: bytes) -> None:  # noqa: F811
                conn.sendall(wrap_application_data(data))

        # obfuscated transport
        init = read(64)
        dec_key = hashlib.sha256(init[8:40] + self.secret).digest()
        decrypt = _aes_ctr_stream(dec_key, init[40:56])
        decrypt(init)  # client burned 64 bytes of this keystream

        rev = init[::-1]
        enc_key = hashlib.sha256(rev[8:40] + self.secret).digest()
        encrypt = _aes_ctr_stream(enc_key, rev[40:56])

        head = decrypt(read(4))
        (total,) = struct.unpack("<I", head)
        body = decrypt(read(total))
        ctor = struct.unpack("<I", body[20:24])[0]
        if ctor != 0xBE7E8EF1:
            raise AssertionError(f"expected req_pq_multi, got {ctor:#x}")
        nonce = body[24:40]

        if self.mode == "silent":
            return
        if self.mode == "badnonce":
            nonce = b"\x00" * 16

        ctor_out = 0x12345678 if self.mode == "wrongctor" else 0x05162463
        payload = struct.pack("<I", ctor_out) + nonce + b"\x00" * 16
        payload += b"\x08" + b"\x01" * 8 + b"\x00" * 3
        env = struct.pack("<qqI", 0, 0x5F00000000, len(payload)) + payload
        send(encrypt(struct.pack("<I", len(env)) + env))

    def stop(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


class TestEndToEnd(unittest.TestCase):
    def _run(self, secret_text: str, *, fake_tls: bool, mode: str = "ok",
             server_secret: bytes = SECRET16):
        srv = FakeMTProxy(server_secret, fake_tls=fake_tls, mode=mode)
        srv.start()
        self.addCleanup(srv.stop)
        raw, kind, _ = decode_secret(secret_text)
        proxy = ProxyInfo("127.0.0.1", srv.port, raw, secret_text, kind)
        result = verify_proxy(proxy, timeout=4)
        srv.join(timeout=4)
        return result, srv

    def test_plain_secret_alive(self):
        r, _ = self._run(SECRET16.hex(), fake_tls=False)
        self.assertIsNone(r.error)
        self.assertTrue(r.alive)
        self.assertEqual(r.stage, "ok")

    def test_dd_secret_alive(self):
        r, _ = self._run("dd" + SECRET16.hex(), fake_tls=False)
        self.assertTrue(r.alive, r.error)

    def test_ee_faketls_alive(self):
        r, srv = self._run(EE_SECRET, fake_tls=True)
        self.assertIsNone(srv.error)
        self.assertIsNone(r.error)
        self.assertTrue(r.alive)
        self.assertEqual(r.stage, "ok")
        self.assertEqual(r.fake_tls_domain, DOMAIN)

    def test_ee_reports_latency(self):
        r, _ = self._run(EE_SECRET, fake_tls=True)
        self.assertIsNotNone(r.latency_ms)
        self.assertGreaterEqual(r.latency_ms, 0)

    def test_ee_wrong_secret_fails_at_faketls(self):
        r, _ = self._run(EE_SECRET, fake_tls=True, server_secret=b"\xbb" * 16)
        self.assertFalse(r.alive)
        self.assertEqual(r.stage, "faketls")

    def test_wrong_constructor_not_alive(self):
        r, _ = self._run(SECRET16.hex(), fake_tls=False, mode="wrongctor")
        self.assertFalse(r.alive)
        self.assertEqual(r.stage, "telegram")
        self.assertIn("constructor", r.error)

    def test_nonce_mismatch_not_alive(self):
        r, _ = self._run(SECRET16.hex(), fake_tls=False, mode="badnonce")
        self.assertFalse(r.alive)
        self.assertIn("nonce mismatch", r.error)

    def test_silent_proxy_times_out(self):
        r, _ = self._run(SECRET16.hex(), fake_tls=False, mode="silent")
        self.assertFalse(r.alive)
        self.assertEqual(r.stage, "telegram")


if __name__ == "__main__":
    unittest.main()
