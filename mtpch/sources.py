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

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import List, Optional, Tuple

from . import parser as _parser
from .verifier import ProxyInfo

# ---------------------------------------------------------------------------
# Built-in feed — MTPCH ships with a ready-to-use upstream proxy source so
# users do not need to find their own list.  The exact URL is an
# implementation detail; treat it as an opaque feed.
# ---------------------------------------------------------------------------

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


def _http_get(url: str, *, headers: Optional[dict] = None, timeout: float = 15.0) -> str:
    hdrs = {"User-Agent": _DEFAULT_UA}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        encoding = resp.headers.get_content_charset() or "utf-8"
        return resp.read().decode(encoding, errors="replace")


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
# Built-in (curated) feed
# ---------------------------------------------------------------------------


def load_from_builtin(
    *,
    filter_rules: Optional[dict] = None,
    disable_filters: bool = False,
    timeout: float = 15.0,
) -> Tuple[List[ProxyInfo], dict]:
    """Download the built-in feed and (optionally) apply filter rules.

    Parameters
    ----------
    filter_rules:
        Overrides merged on top of :data:`DEFAULT_FILTER`.  Ignored
        entirely when ``disable_filters`` is ``True``.
    disable_filters:
        When ``True``, every entry the feed returns is kept and returned
        in its original order — no uptime, ping, country, age or
        sorting rule is applied.  Useful when the caller wants to
        inspect / test the complete upstream list themselves.
    timeout:
        HTTP request timeout in seconds.

    Returns ``(proxies, meta)`` where ``meta`` contains ``total``,
    ``after_filter`` and ``feed`` for reporting.  When filters are
    disabled, ``after_filter`` equals ``total``.
    """
    if disable_filters:
        rules: dict = {}
    else:
        rules = dict(DEFAULT_FILTER)
        if filter_rules:
            rules.update(filter_rules)

    body = _http_get(BUILTIN_FEED_URL, headers=BUILTIN_FEED_HEADERS, timeout=timeout)
    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:  # pragma: no cover - network dependent
        raise RuntimeError(f"feed did not return JSON: {exc}") from exc

    if not isinstance(data, list):
        raise RuntimeError(
            f"feed returned unexpected shape: {type(data).__name__}"
        )

    total = len(data)
    filtered_raw = data if disable_filters else _apply_filter(data, rules)
    proxies: List[ProxyInfo] = []
    for entry in filtered_raw:
        try:
            proxies.append(_parser._proxy_from_dict(entry, json.dumps(entry)))
        except Exception:
            continue

    meta = {
        "feed": BUILTIN_FEED_URL,
        "total": total,
        "after_filter": len(proxies),
        "rules": rules,
        "filters_disabled": disable_filters,
    }
    return proxies, meta


def _apply_filter(entries: list, rules: dict) -> list:
    now = int(time.time())

    def keep(entry: dict) -> bool:
        uptime = entry.get("uptime")
        if rules.get("uptime") is not None and uptime is not None:
            if uptime < rules["uptime"]:
                return False

        ping = entry.get("ping")
        if ping is not None:
            if rules.get("ping_max") is not None and ping > rules["ping_max"]:
                return False
            if rules.get("ping_min") is not None and ping < rules["ping_min"]:
                return False

        countries = rules.get("countries") or []
        if countries and entry.get("country") not in countries:
            return False

        add_time = entry.get("addTime")
        max_age = rules.get("max_age_hours")
        if max_age is not None and add_time is not None:
            if now - add_time > max_age * 3600:
                return False

        return True

    filtered = [e for e in entries if keep(e)]

    if rules.get("newest_first"):
        filtered.sort(
            key=lambda e: e.get("updateTime") or e.get("addTime") or 0,
            reverse=True,
        )
    return filtered
