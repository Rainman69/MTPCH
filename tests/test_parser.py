"""Unit tests for the parser, secret decoder and source helpers."""

import argparse
import io
import json
import sys
import unittest
from unittest import mock

from mtpch import parser, sources
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


class TestBuiltinAllMode(unittest.TestCase):
    """Built-in sources: mtpro filtering, plus the multi-source merge."""

    SAMPLE_FEED = [
        # An entry that would be filtered out by the defaults (low uptime).
        {"host": "a.example.com", "port": 443,
         "secret": "dd345afe9188a4e5a94dc706e1aa6cef",
         "uptime": 10, "ping": 600, "country": "XX",
         "addTime": 1},
        # An entry that passes the defaults.
        {"host": "b.example.com", "port": 443,
         "secret": "4622e21b94d5bd296c4086f4e16297a8",
         "uptime": 99, "ping": 80, "country": "DE",
         "addTime": 9_999_999_999},
    ]

    def _fake_http_get(self, url, *a, **kw):
        """Only mtpro serves the JSON feed; the GitHub lists serve nothing.

        load_from_builtin now fetches the GitHub lists too, so a blanket stub
        would feed the same JSON to every source and the dedup would hide what
        we are asserting about mtpro's filters.
        """
        if "mtpro.xyz" in url:
            return json.dumps(self.SAMPLE_FEED)
        return ""

    def test_filtered_drops_low_quality(self):
        with mock.patch.object(sources, "_http_get", side_effect=self._fake_http_get):
            proxies, meta = sources.load_from_builtin()
        self.assertEqual(meta["mtpro_total"], 2)
        self.assertEqual(meta["total"], 1, "low-uptime entry dropped")
        self.assertFalse(meta["filters_disabled"])
        self.assertEqual(proxies[0].server, "b.example.com")

    def test_all_mode_keeps_every_entry(self):
        with mock.patch.object(sources, "_http_get", side_effect=self._fake_http_get):
            proxies, meta = sources.load_from_builtin(disable_filters=True)
        self.assertEqual(meta["mtpro_total"], 2)
        self.assertEqual(meta["total"], 2)
        self.assertTrue(meta["filters_disabled"])
        self.assertEqual({p.server for p in proxies},
                         {"a.example.com", "b.example.com"})

    def test_merges_every_github_source(self):
        """Each built-in list contributes, and cross-source duplicates collapse."""
        secret = "00112233445566778899aabbccddeeff"

        def fake_get(url, *a, **kw):
            if "mtpro.xyz" in url:
                return json.dumps(self.SAMPLE_FEED)
            if "Argh94" in url:
                # one unique, one that a later source repeats
                return f"1.1.1.1:443:{secret}\n2.2.2.2:443:{secret}\n"
            if "kort0881" in url:
                return f"2.2.2.2:443:{secret}\n3.3.3.3:8443:dd{secret}\n"
            return ""

        with mock.patch.object(sources, "_http_get", side_effect=fake_get):
            proxies, meta = sources.load_from_builtin(disable_filters=True)

        servers = {p.server for p in proxies}
        self.assertIn("1.1.1.1", servers)
        self.assertIn("3.3.3.3", servers)
        self.assertIn("b.example.com", servers, "mtpro still contributes")

        by_source = {s["source"]: s for s in meta["sources"]}
        self.assertEqual(by_source["gh:Argh94/Proxy-List"]["found"], 2)
        self.assertEqual(
            by_source["gh:kort0881/telegram-proxy-collector"]["found"], 1,
            "the repeated proxy is credited to the first source only",
        )

    def test_one_dead_source_does_not_fail_the_run(self):
        def fake_get(url, *a, **kw):
            if "Argh94" in url:
                raise OSError("connection reset")
            if "mtpro.xyz" in url:
                return json.dumps(self.SAMPLE_FEED)
            return ""

        with mock.patch.object(sources, "_http_get", side_effect=fake_get):
            proxies, meta = sources.load_from_builtin(disable_filters=True)

        self.assertEqual(len(proxies), 2, "mtpro entries still came through")
        failed = [s for s in meta["sources"] if s.get("error")]
        self.assertTrue(any("Argh94" in s["source"] for s in failed))
        self.assertIn("connection reset", failed[0]["error"])

    def test_mtpro_failure_leaves_the_other_sources(self):
        secret = "00112233445566778899aabbccddeeff"

        def fake_get(url, *a, **kw):
            if "mtpro.xyz" in url:
                raise RuntimeError("HTTP 401")
            if "Argh94" in url:
                return f"1.1.1.1:443:{secret}\n"
            return ""

        with mock.patch.object(sources, "_http_get", side_effect=fake_get):
            proxies, meta = sources.load_from_builtin()

        self.assertEqual([p.server for p in proxies], ["1.1.1.1"])
        mtpro = next(s for s in meta["sources"] if s["source"] == "mtpro.xyz")
        self.assertIn("401", mtpro["error"])

    def test_builtin_sources_are_github_raw_urls(self):
        self.assertGreaterEqual(len(sources.BUILTIN_GITHUB_SOURCES), 4)
        for url in sources.BUILTIN_GITHUB_SOURCES:
            self.assertIn("raw.githubusercontent.com", url)
        self.assertFalse(
            any("t.me" in u for u in sources.BUILTIN_GITHUB_SOURCES),
            "no Telegram channel scraping in the built-ins",
        )


class TestStartTestPrompt(unittest.TestCase):
    """The pre-test confirmation must respect --yes and non-TTY stdin."""

    def test_auto_yes_returns_true(self):
        from mtpch.cli import _prompt_start_test
        self.assertTrue(_prompt_start_test(auto_yes=True))

    def test_non_tty_returns_true(self):
        from mtpch.cli import _prompt_start_test
        with mock.patch.object(sys.stdin, "isatty", return_value=False):
            self.assertTrue(_prompt_start_test(auto_yes=False))


class TestBannerIsMTPCH(unittest.TestCase):
    """Regression guard for the banner bug where the art spelled MTHPH."""

    def test_banner_does_not_contain_old_glyph_pattern(self):
        from mtpch.cli import BANNER_EN
        # The broken banner had these two tell-tale substrings; the new
        # MTPCH art has neither.
        self.assertNotIn("________  ______  __  __", BANNER_EN)
        self.assertNotIn("/_/ /_/_/   /_/ /_/", BANNER_EN)

    def test_banner_has_new_MTPCH_shape(self):
        from mtpch.cli import BANNER_EN
        # Distinctive fragments of the correct figlet-slant "MTPCH".
        self.assertIn("_____________", BANNER_EN)
        self.assertIn("/_  __/ __ \\/ ____/", BANNER_EN)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
