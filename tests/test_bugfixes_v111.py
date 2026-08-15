"""Regression tests for the v1.1.1 correctness fixes."""

from __future__ import annotations

import base64
import json
import socket
import unittest
from unittest import mock

from mtpch import parser, sources
from mtpch.sources import DEFAULT_FILTER, _apply_filter
from mtpch.verifier import ProxyInfo, decode_secret, verify_proxy


class TestTrailingPunctuation(unittest.TestCase):
    CLEAN = "4622e21b94d5bd296c4086f4e16297a8"

    def test_extract_strips_trailing_dot(self):
        raw0, _, _ = decode_secret(self.CLEAN)
        text = (
            f"see https://t.me/proxy?server=1.2.3.4&port=443"
            f"&secret={self.CLEAN}."
        )
        got = parser.extract_from_text(text)
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].secret, raw0)
        self.assertFalse(got[0].raw_secret.endswith("."))

    def test_extract_strips_trailing_paren(self):
        raw0, _, _ = decode_secret(self.CLEAN)
        text = (
            f"(https://t.me/proxy?server=1.2.3.4&port=443"
            f"&secret={self.CLEAN})"
        )
        got = parser.extract_from_text(text)
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].secret, raw0)


class TestBase64PlusInLink(unittest.TestCase):
    def test_std_base64_plus_preserved(self):
        raw16 = bytes([0xFB, 0xFF] + [1] * 14)
        secret = base64.b64encode(raw16).decode().rstrip("=")
        self.assertIn("+", secret)
        p = parser.parse_link(
            f"tg://proxy?server=1.2.3.4&port=443&secret={secret}"
        )
        self.assertEqual(p.secret, raw16)
        self.assertEqual(p.raw_secret, secret)


class TestSocketClosedOnConnectFail(unittest.TestCase):
    def test_connect_failure_closes_socket(self):
        raw, kind, _ = decode_secret("4622e21b94d5bd296c4086f4e16297a8")
        proxy = ProxyInfo(
            "127.0.0.1", 1, raw, "4622e21b94d5bd296c4086f4e16297a8", kind
        )
        created = []
        real_socket = socket.socket

        class TrackingSocket:
            def __init__(self, *a, **k):
                self._s = real_socket(*a, **k)
                self.closed = False
                created.append(self)

            def settimeout(self, t):
                return self._s.settimeout(t)

            def connect(self, addr):
                raise ConnectionRefusedError("refused")

            def close(self):
                self.closed = True
                return self._s.close()

            def __enter__(self):
                return self

            def __exit__(self, *a):
                self.close()
                return False

        with mock.patch(
            "mtpch.verifier.socket.socket",
            side_effect=lambda *a, **k: TrackingSocket(*a, **k),
        ), mock.patch(
            "mtpch.verifier.socket.getaddrinfo",
            return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 1))
            ],
        ):
            r = verify_proxy(proxy, timeout=1)

        self.assertEqual(r.stage, "connect")
        self.assertEqual(len(created), 1)
        self.assertTrue(created[0].closed)


class TestFakeTLSNowSupported(unittest.TestCase):
    """``ee`` secrets used to be refused outright; they are now verified."""

    def test_ee_reaches_the_network_instead_of_being_refused(self):
        secret = "ee" + "a" * 32 + bytes("example.com", "ascii").hex()
        raw, kind, dom = decode_secret(secret)
        self.assertEqual(kind, "ee")
        proxy = ProxyInfo("127.0.0.1", 1, raw, secret, kind)
        r = verify_proxy(proxy, timeout=0.5)
        self.assertFalse(r.alive)
        # port 1 refuses: we must fail at connect, never at "unsupported"
        self.assertEqual(r.stage, "connect")
        self.assertNotIn("not supported", (r.error or "").lower())
        self.assertEqual(r.fake_tls_domain, "example.com")


class TestDdSecretTrailingJunk(unittest.TestCase):
    def test_dd_with_extra_byte_still_dd(self):
        # 0xDD + 16 key bytes + trailing 0xFF
        raw, kind, _ = decode_secret("dd" + "ab" * 16 + "ff")
        self.assertEqual(kind, "dd")
        self.assertEqual(raw, bytes.fromhex("ab" * 16))
        self.assertNotEqual(raw[0], 0xDD)


class TestFilterHardening(unittest.TestCase):
    def test_string_metrics_coerced(self):
        out = _apply_filter(
            [
                {
                    "host": "a",
                    "uptime": "99",
                    "ping": "10",
                    "country": "DE",
                    "addTime": "9999999999",
                }
            ],
            {
                "uptime": 95,
                "ping_max": 150,
                "ping_min": 0,
                "countries": [],
                "max_age_hours": 336,
            },
        )
        self.assertEqual(len(out), 1)

    def test_country_case_insensitive(self):
        rules = dict(DEFAULT_FILTER)
        rules["countries"] = ["DE"]
        entries = [
            {
                "host": "a",
                "uptime": 99,
                "ping": 10,
                "country": "de",
                "addTime": 9_999_999_999,
            },
            {
                "host": "b",
                "uptime": 99,
                "ping": 10,
                "country": "DE",
                "addTime": 9_999_999_999,
            },
        ]
        kept = {e["host"] for e in _apply_filter(entries, rules)}
        self.assertEqual(kept, {"a", "b"})

    def test_builtin_all_still_works(self):
        feed = [
            {
                "host": "a.example.com",
                "port": 443,
                "secret": "dd345afe9188a4e5a94dc706e1aa6cef",
                "uptime": "10",
                "ping": "600",
                "country": "xx",
                "addTime": 1,
            },
            {
                "host": "b.example.com",
                "port": 443,
                "secret": "4622e21b94d5bd296c4086f4e16297a8",
                "uptime": "99",
                "ping": "80",
                "country": "de",
                "addTime": 9_999_999_999,
            },
        ]

        def fake_get(url, *a, **k):
            return json.dumps(feed) if "mtpro.xyz" in url else ""

        with mock.patch.object(sources, "_http_get", side_effect=fake_get):
            proxies, meta = sources.load_from_builtin(
                filter_rules={"countries": ["DE"]}
            )
        self.assertEqual(meta["total"], 1)
        self.assertEqual(proxies[0].server, "b.example.com")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
