"""Flexible proxy-description parser.

The parser recognises every common way MTProto proxies are shared in
the wild:

* ``tg://proxy?server=...&port=...&secret=...``
* ``https://t.me/proxy?server=...&port=...&secret=...``
* ``https://telegram.me/proxy?...`` and ``proxy.me/...`` variants
* Bare ``host:port:secret`` triplets, with `:` or `;` or whitespace as
  separators
* Arbitrary free-form text containing any of the above (regex scan)
* JSON arrays/objects exposing ``host``/``server``, ``port`` and
  ``secret`` keys — compatible with the common feed schema used by
  public MTProto proxy aggregators

All helpers return lists of :class:`~mtpch.verifier.ProxyInfo`
instances and silently skip malformed entries (the caller gets a
``skipped`` counter through :func:`extract_many`).
"""

from __future__ import annotations

import json
import re
from typing import Iterable, List, Tuple
from urllib.parse import parse_qs, urlparse

from .verifier import ProxyInfo, decode_secret


# A tolerant regex that matches both ``tg://proxy?...`` and the various
# ``https://t.me/proxy?...`` / ``https://telegram.me/proxy?...`` links.
_PROXY_LINK_RE = re.compile(
    r"""
    (?:tg://proxy\?|https?://(?:t|telegram)\.me/proxy\?)
    (?P<query>[^\s"'<>`]+)
    """,
    re.VERBOSE,
)

# ``host:port:secret`` triplet (host may be a hostname or IPv4).
_TRIPLET_RE = re.compile(
    r"""
    (?<![A-Za-z0-9._-])
    (?P<host>[A-Za-z0-9][A-Za-z0-9._-]{2,253})
    [\s:;,]+
    (?P<port>[0-9]{1,5})
    [\s:;,]+
    (?P<secret>(?:ee|dd)?[0-9A-Fa-f]{32,}|[A-Za-z0-9_\-]{20,}={0,2})
    """,
    re.VERBOSE,
)


def _build(server: str, port: str | int, secret: str, source_line: str) -> ProxyInfo:
    port_i = int(port)
    if not (0 < port_i < 65536):
        raise ValueError(f"invalid port {port_i}")
    raw, kind, _ = decode_secret(secret)
    return ProxyInfo(
        server=server.strip(),
        port=port_i,
        secret=raw,
        raw_secret=secret.strip(),
        secret_kind=kind,
        source_line=source_line.strip(),
    )


# ---------------------------------------------------------------------------
# Link / triplet parsers
# ---------------------------------------------------------------------------


def parse_link(link: str) -> ProxyInfo:
    """Parse a single ``tg://`` or ``https://t.me/proxy?`` link."""
    link = link.strip().strip("<>\"'`")
    parsed = urlparse(link)
    qs = parse_qs(parsed.query)
    try:
        server = qs["server"][0]
        port = qs["port"][0]
        secret = qs["secret"][0]
    except (KeyError, IndexError) as exc:
        raise ValueError(f"missing parameter in link: {exc}") from exc
    return _build(server, port, secret, link)


def parse_triplet(text: str) -> ProxyInfo:
    """Parse a bare ``host:port:secret`` line."""
    text = text.strip()
    # Accept ``host|port|secret``/``host,port,secret``/``host port secret`` too.
    parts = re.split(r"[\s:;,|]+", text)
    parts = [p for p in parts if p]
    if len(parts) < 3:
        raise ValueError(f"expected host/port/secret, got {len(parts)} fields")
    server, port, secret = parts[0], parts[1], parts[2]
    return _build(server, port, secret, text)


# ---------------------------------------------------------------------------
# JSON handling (common aggregator feed schema & friends)
# ---------------------------------------------------------------------------


def _proxy_from_dict(obj: dict, source: str) -> ProxyInfo:
    server = obj.get("server") or obj.get("host") or obj.get("ip")
    port = obj.get("port")
    secret = obj.get("secret")
    if not server or port is None or not secret:
        raise ValueError("dict missing host/port/secret")
    return _build(str(server), port, str(secret), source)


def parse_json(blob: str) -> List[ProxyInfo]:
    """Parse a JSON string holding one or many proxies."""
    data = json.loads(blob)
    return _normalize_json(data)


def _normalize_json(data) -> List[ProxyInfo]:
    if isinstance(data, list):
        out: List[ProxyInfo] = []
        for entry in data:
            if isinstance(entry, dict):
                try:
                    out.append(_proxy_from_dict(entry, json.dumps(entry)))
                except Exception:
                    continue
            elif isinstance(entry, str):
                try:
                    out.append(parse_link(entry))
                except Exception:
                    try:
                        out.append(parse_triplet(entry))
                    except Exception:
                        continue
        return out
    if isinstance(data, dict):
        # Single proxy or a wrapper ({"proxies": [...]})
        for key in ("proxies", "data", "items", "result"):
            if key in data and isinstance(data[key], list):
                return _normalize_json(data[key])
        try:
            return [_proxy_from_dict(data, json.dumps(data))]
        except Exception:
            return []
    return []


# ---------------------------------------------------------------------------
# Free-form extraction
# ---------------------------------------------------------------------------


def extract_from_text(text: str) -> List[ProxyInfo]:
    """Extract every recognisable proxy from an arbitrary text blob.

    The scan is robust against Markdown/HTML, surrounding noise and
    angle-bracketed URLs.  Duplicates (same ``host:port:secret``) are
    removed while preserving order.
    """
    results: List[ProxyInfo] = []
    seen: set[Tuple[str, int, str]] = set()

    # Short-circuit: if the whole blob is valid JSON treat it as such
    # and skip the regex pass; that avoids re-parsing literal strings
    # from inside the JSON twice.
    stripped = text.strip()
    if stripped.startswith("[") or stripped.startswith("{"):
        try:
            json_proxies = parse_json(stripped)
            for p in json_proxies:
                key = (p.server.lower(), p.port, p.raw_secret.lower())
                if key not in seen:
                    seen.add(key)
                    results.append(p)
            if results:
                return results
        except json.JSONDecodeError:
            pass  # fall through to regex scan

    # Link patterns first so we preserve full raw_secret.
    for match in _PROXY_LINK_RE.finditer(text):
        raw_link = match.group(0)
        try:
            p = parse_link(raw_link)
        except Exception:
            continue
        key = (p.server.lower(), p.port, p.raw_secret.lower())
        if key not in seen:
            seen.add(key)
            results.append(p)

    # Triplets — only look at lines not already consumed by a link to
    # avoid matching fragments of URLs.
    consumed_ranges: list[tuple[int, int]] = [
        m.span() for m in _PROXY_LINK_RE.finditer(text)
    ]

    def _inside_link(pos: int) -> bool:
        return any(start <= pos < end for start, end in consumed_ranges)

    for match in _TRIPLET_RE.finditer(text):
        if _inside_link(match.start()):
            continue
        try:
            p = parse_triplet(match.group(0))
        except Exception:
            continue
        key = (p.server.lower(), p.port, p.raw_secret.lower())
        if key not in seen:
            seen.add(key)
            results.append(p)

    return results


def extract_many(sources: Iterable[str]) -> Tuple[List[ProxyInfo], int]:
    """Extract proxies from a series of text blobs.

    Returns ``(proxies, skipped_count)`` where ``skipped_count`` is an
    informational tally of lines/entries that could not be parsed at
    all (only counted when the blob *looks* like a single entry, i.e.
    a single line).  Callers use it purely for reporting.
    """
    collected: List[ProxyInfo] = []
    seen: set[Tuple[str, int, str]] = set()
    skipped = 0

    for blob in sources:
        proxies = extract_from_text(blob)
        if not proxies:
            # If the blob was a one-liner we count it as skipped so the
            # user can see that we saw it but could not decode it.
            if blob.strip() and "\n" not in blob.strip():
                skipped += 1
            continue
        for p in proxies:
            key = (p.server.lower(), p.port, p.raw_secret.lower())
            if key not in seen:
                seen.add(key)
                collected.append(p)

    return collected, skipped
