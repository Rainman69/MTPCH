"""Unit tests for the parser and secret decoder."""

import json
import unittest

from mtpch import parser
from mtpch.verifier import decode_secret


class TestSecretDecoder(unittest.TestCase):
    def test_plain_hex(self):
        raw, kind, dom = decode_secret("dd345afe9188a4e5a94dc706e1aa6cef")
        self.assertEqual(len(raw), 16)
        self.assertEqual(kind, "plain")
        self.assertIsNone(dom)

    def test_dd_prefix(self):
        raw, kind, dom = decode_secret("dd" + "a" * 32)
        self.assertEqual(len(raw), 16)
        self.assertEqual(kind, "dd")

    def test_ee_prefix_with_faketls(self):
        secret = "ee" + "a" * 32 + bytes("example.com", "ascii").hex()
        raw, kind, dom = decode_secret(secret)
        self.assertEqual(len(raw), 16)
        self.assertEqual(kind, "ee")
        self.assertEqual(dom, "example.com")

    def test_base64url(self):
        # 16 random bytes -> 22 base64 chars
        import base64, os
        b = os.urandom(16)
        s = base64.urlsafe_b64encode(b).decode().rstrip("=")
        raw, kind, _ = decode_secret(s)
        self.assertEqual(raw, b)
        self.assertEqual(kind, "plain")


class TestParser(unittest.TestCase):
    LINK_TG = ("tg://proxy?server=1.2.3.4&port=443"
               "&secret=dd345afe9188a4e5a94dc706e1aa6cef")
    LINK_HTTPS = ("https://t.me/proxy?server=host.example.com&port=8443"
                  "&secret=4622e21b94d5bd296c4086f4e16297a8")
    TRIPLET = "9.8.7.6:443:4622e21b94d5bd296c4086f4e16297a8"

    def test_parse_link_tg(self):
        p = parser.parse_link(self.LINK_TG)
        self.assertEqual(p.server, "1.2.3.4")
        self.assertEqual(p.port, 443)
        # 32 hex chars = 16 bytes, no prefix length byte — plain secret.
        self.assertEqual(p.secret_kind, "plain")

    def test_parse_link_https(self):
        p = parser.parse_link(self.LINK_HTTPS)
        self.assertEqual(p.server, "host.example.com")
        self.assertEqual(p.port, 8443)

    def test_parse_triplet(self):
        p = parser.parse_triplet(self.TRIPLET)
        self.assertEqual(p.server, "9.8.7.6")
        self.assertEqual(p.port, 443)

    def test_extract_mixed_text(self):
        text = (f"hello world\n{self.LINK_TG}\nsome noise {self.TRIPLET}\n"
                f"<{self.LINK_HTTPS}>\n")
        got = parser.extract_from_text(text)
        self.assertEqual(len(got), 3)

    def test_extract_json(self):
        blob = json.dumps([
            {"host": "a", "port": 443,
             "secret": "4622e21b94d5bd296c4086f4e16297a8"},
            {"server": "b", "port": 443,
             "secret": "dd345afe9188a4e5a94dc706e1aa6cef"},
        ])
        got = parser.extract_from_text(blob)
        self.assertEqual(len(got), 2)
        self.assertEqual({p.server for p in got}, {"a", "b"})

    def test_deduplicates(self):
        text = self.LINK_TG + "\n" + self.LINK_TG
        self.assertEqual(len(parser.extract_from_text(text)), 1)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
