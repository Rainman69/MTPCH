"""Input sources for MTPCH.

Four kinds of sources are supported:

* ``load_from_file(path)`` — read a local file of arbitrary format
* ``load_from_url(url)``   — download a remote text blob (txt/json/html)
* ``load_from_stdin()``    — pipe proxies into the tool
* ``load_from_builtin()``  — pull from the built-in upstream feed that
  MTPCH bundles; filters are optional and may be disabled entirely so
  that the raw list is returned as-is
"""

from __future__ import annotations

import concurrent.futures as cf
import http.client
import json
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import List, Optional, Tuple

from . import parser as _parser
from .verifier import ProxyInfo

# ---------------------------------------------------------------------------
# Built-in sources — MTPCH ships with ready-to-use upstream lists so users do
# not have to hunt for a feed or pass a path.
#
# GitHub repos that auto-commit fresh MTProto lists are the bulk of it: these
# five yield ~450 unique proxies, against ~40 from any single feed. Each was
# checked live for (a) a parseable list and (b) commit activity at least
# daily.
#
# mtpro.xyz stays as an extra because it is the only source carrying
# country/uptime/ping metadata, which the feed filters use. It is not
# load-bearing: it 401s its JSON API for server-side clients fairly often, and
# a failure there just means fewer proxies, not a failed run.
# ---------------------------------------------------------------------------

BUILTIN_GITHUB_SOURCES = [
    # ~220 proxies, commits every few hours
    "https://raw.githubusercontent.com/Argh94/Proxy-List/main/MTProto.txt",
    # ~220, updated through the day, heavily FakeTLS
    "https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_all_mtproto.txt",
    # ~200, daily
    "https://raw.githubusercontent.com/Grim1313/mtproto-for-telegram/master/all_proxies.txt",
    # ~190, several times a day
    "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
]

BUILTIN_FEED_URL = "https://mtpro.xyz/api/?type=mtprotoS"
BUILTIN_FEED_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
}

# Default quality filters applied to the built-in feed.  ``None`` means
# "do not filter on that field".  Pass ``filter_rules={}`` to keep the
# defaults, or ``disable_filters=True`` to fetch every entry with no
# quality gating whatsoever.
DEFAULT_FILTER = {
    "uptime": 95,          # proxy uptime ≥ 95 (%)
    "ping_max": 150,        # proxy ping ≤ 150 ms
    "ping_min": 0,
    "countries": [],        # empty => any
    "max_age_hours": 336,   # ignore entries added more than 14 days ago
    "newest_first": True,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_DEFAULT_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"
)


_SSL_CTX: Optional[ssl.SSLContext] = None


def _ssl_context() -> ssl.SSLContext:
    """A verifying TLS context that works on stock Python installs.

    Python built from python.org does not use the system keychain, so
    ``urlopen`` raises CERTIFICATE_VERIFY_FAILED on every HTTPS request unless
    it is pointed at a CA bundle.  Prefer certifi when present and fall back to
    the default context — verification stays on either way.
    """
    global _SSL_CTX
    if _SSL_CTX is None:
        try:
            import certifi

            _SSL_CTX = ssl.create_default_context(cafile=certifi.where())
        except Exception:
            _SSL_CTX = ssl.create_default_context()
    return _SSL_CTX


def _http_get(
    url: str,
    *,
    headers: Optional[dict] = None,
    timeout: float = 15.0,
    attempts: int = 3,
) -> str:
    """GET ``url`` as text, retrying on transient network failures.

    ``urllib`` has no Happy Eyeballs: on a host whose IPv6 route is black-holed
    it connects to the AAAA address and blocks for the full timeout, while the
    very next attempt succeeds on IPv4 in milliseconds.  Measured against
    GitHub raw: first attempt timed out at 46s, retry returned 23 KB in 0.5s.
    So a short per-attempt timeout plus a retry beats one long attempt.

    ``IncompleteRead`` has to be caught alongside the socket errors — it is an
    ``HTTPException``, not an ``OSError``, so it escapes an ``OSError``-only
    handler and kills the whole fetch on a merely truncated response.
    """
    hdrs = {"User-Agent": _DEFAULT_UA}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs)

    per_attempt = max(6.0, timeout / attempts)
    last: Optional[BaseException] = None
    for _ in range(attempts):
        try:
            with urllib.request.urlopen(
                req, timeout=per_attempt, context=_ssl_context()
            ) as resp:
                encoding = resp.headers.get_content_charset() or "utf-8"
                return resp.read().decode(encoding, errors="replace")
        except (OSError, http.client.HTTPException) as exc:
            last = exc
    raise last if last else RuntimeError(f"could not fetch {url}")


# ---------------------------------------------------------------------------
# File / URL / stdin
# ---------------------------------------------------------------------------


def load_from_file(path: str | Path) -> Tuple[List[ProxyInfo], int]:
    """Parse a local file.  Any format supported by :mod:`mtpch.parser`."""
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    proxies = _parser.extract_from_text(text)
    # Rough "skipped" count: non-empty lines minus proxies we found.
    skipped = max(0, sum(1 for ln in text.splitlines() if ln.strip()) - len(proxies))
    # That heuristic only makes sense for line-oriented inputs; clamp to
    # zero for JSON arrays so we do not mislead the user.
    if text.strip().startswith(("[", "{")):
        skipped = 0
    return proxies, skipped


def load_from_url(
    url: str, *, headers: Optional[dict] = None, timeout: float = 15.0
) -> Tuple[List[ProxyInfo], int]:
    """Download ``url`` and extract every proxy from the returned body."""
    body = _http_get(url, headers=headers, timeout=timeout)
    proxies = _parser.extract_from_text(body)
    return proxies, 0


def load_from_stdin() -> Tuple[List[ProxyInfo], int]:
    import sys

    data = sys.stdin.read()
    return _parser.extract_from_text(data), 0


# ---------------------------------------------------------------------------
# Built-in (curated) sources
# ---------------------------------------------------------------------------


def load_from_builtin(
    *,
    filter_rules: Optional[dict] = None,
    disable_filters: bool = False,
    timeout: float = 30.0,
) -> Tuple[List[ProxyInfo], dict]:
    """Fetch every built-in source and merge the results.

    Pulls the GitHub lists in :data:`BUILTIN_GITHUB_SOURCES`, then mtpro.xyz
    for its country/uptime metadata.

    Parameters
    ----------
    filter_rules:
        Overrides merged on top of :data:`DEFAULT_FILTER`.  These only apply
        to mtpro entries — the GitHub lists carry no uptime or ping numbers to
        filter on, so they are always returned in full.  Ignored entirely when
        ``disable_filters`` is ``True``.
    disable_filters:
        When ``True``, mtpro entries skip filtering too.
    timeout:
        Per-request HTTP timeout in seconds.

    Returns ``(proxies, meta)``.  ``meta['sources']`` lists what each source
    contributed (or why it failed), so a dead upstream is visible rather than
    silent.  A source that raises is skipped, never fatal.
    """
    if disable_filters:
        rules: dict = {}
    else:
        rules = dict(DEFAULT_FILTER)
        if filter_rules:
            rules.update(filter_rules)

    collected: List[ProxyInfo] = []
    seen: set = set()
    per_source: List[dict] = []

    def _add(proxies: List[ProxyInfo], label: str) -> int:
        added = 0
        for p in proxies:
            key = _parser._dedup_key(p)
            if key not in seen:
                seen.add(key)
                collected.append(p)
                added += 1
        per_source.append({"source": label, "found": added})
        return added

    def _short(url: str) -> str:
        if "raw.githubusercontent.com" in url:
            parts = url.split("raw.githubusercontent.com/", 1)[1].split("/")
            return f"gh:{parts[0]}/{parts[1]}" if len(parts) > 1 else "gh:?"
        return url.split("//", 1)[-1].split("/", 1)[0]

    # --- GitHub lists ------------------------------------------------------
    # Fetched concurrently: six sequential HTTPS round-trips to GitHub raw
    # regularly blew a 15s-per-request budget and half the sources timed out.
    def _fetch(url: str) -> Tuple[str, str, Optional[str]]:
        label = _short(url)
        try:
            return label, _http_get(url, timeout=timeout), None
        except Exception as exc:
            return label, "", f"{exc.__class__.__name__}: {exc}"

    with cf.ThreadPoolExecutor(max_workers=min(8, len(BUILTIN_GITHUB_SOURCES))) as pool:
        for label, body, err in pool.map(_fetch, BUILTIN_GITHUB_SOURCES):
            if err:
                per_source.append({"source": label, "found": 0, "error": err})
            else:
                _add(_parser.extract_from_text(body), label)

    # --- mtpro.xyz: the only source with country/uptime metadata -----------
    mtpro_total = 0
    try:
        body = _http_get(BUILTIN_FEED_URL, headers=BUILTIN_FEED_HEADERS, timeout=timeout)
        data = json.loads(body)
        if not isinstance(data, list):
            raise RuntimeError(f"unexpected shape: {type(data).__name__}")
        mtpro_total = len(data)
        filtered_raw = data if disable_filters else _apply_filter(data, rules)
        mtpro: List[ProxyInfo] = []
        for entry in filtered_raw:
            try:
                mtpro.append(_parser._proxy_from_dict(entry, json.dumps(entry)))
            except Exception:
                continue
        _add(mtpro, "mtpro.xyz")
    except Exception as exc:
        per_source.append(
            {"source": "mtpro.xyz", "found": 0, "error": f"{exc.__class__.__name__}: {exc}"}
        )

    ok_sources = [s for s in per_source if not s.get("error")]
    meta = {
        "sources": per_source,
        "source_count": len(per_source),
        "sources_ok": len(ok_sources),
        "total": len(collected),
        "mtpro_total": mtpro_total,
        "rules": rules,
        "filters_disabled": disable_filters,
    }
    return collected, meta


def _apply_filter(entries: list, rules: dict) -> list:
    now = int(time.time())

    def _num(value):
        if value is None:
            return None
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return float(value)
        try:
            return float(str(value).strip())
        except (TypeError, ValueError):
            return None

    def keep(entry: dict) -> bool:
        uptime = _num(entry.get("uptime"))
        min_uptime = rules.get("uptime")
        if min_uptime is not None and uptime is not None:
            if uptime < min_uptime:
                return False

        ping = _num(entry.get("ping"))
        if ping is not None:
            if rules.get("ping_max") is not None and ping > rules["ping_max"]:
                return False
            if rules.get("ping_min") is not None and ping < rules["ping_min"]:
                return False

        countries = {c.upper() for c in (rules.get("countries") or []) if c}
        if countries:
            country = entry.get("country")
            if country is None or str(country).upper() not in countries:
                return False

        add_time = _num(entry.get("addTime"))
        max_age = rules.get("max_age_hours")
        if max_age is not None and add_time is not None:
            if now - add_time > max_age * 3600:
                return False

        return True

    filtered = [e for e in entries if keep(e)]

    if rules.get("newest_first"):
        filtered.sort(
            key=lambda e: _num(e.get("updateTime"))
            or _num(e.get("addTime"))
            or 0,
            reverse=True,
        )
    return filtered
