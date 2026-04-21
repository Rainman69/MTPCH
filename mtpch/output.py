"""Output writers: plain text, JSON, and colourised console report."""

from __future__ import annotations

import dataclasses
import datetime as _dt
import json
from pathlib import Path
from typing import Iterable, List

from .verifier import VerifyResult

# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------


def result_to_dict(result: VerifyResult) -> dict:
    p = result.proxy
    return {
        "server": p.server,
        "port": p.port,
        "secret": p.raw_secret,
        "secret_kind": p.secret_kind,
        "link_tg": p.link_tg,
        "link_https": p.link_https,
        "alive": result.alive,
        "latency_ms": (
            None if result.latency_ms is None else round(result.latency_ms, 2)
        ),
        "stage": result.stage,
        "error": result.error,
        "fake_tls_domain": result.fake_tls_domain,
        "dc_id": result.dc_id,
    }


def _summary(results: Iterable[VerifyResult]) -> dict:
    results = list(results)
    alive = [r for r in results if r.alive]
    dead = [r for r in results if not r.alive]
    latencies = [r.latency_ms for r in alive if r.latency_ms is not None]
    avg = round(sum(latencies) / len(latencies), 2) if latencies else None
    # ``utcnow()`` is deprecated in Python 3.12+; use a timezone-aware UTC
    # timestamp and render it in the classic trailing-Z ISO-8601 form.
    now_utc = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)
    generated_at = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "generated_at": generated_at,
        "total": len(results),
        "alive": len(alive),
        "dead": len(dead),
        "success_rate": round(100.0 * len(alive) / len(results), 2) if results else 0,
        "average_latency_ms": avg,
    }


# ---------------------------------------------------------------------------
# Text and JSON file writers
# ---------------------------------------------------------------------------


def write_json(results: List[VerifyResult], path: str | Path) -> Path:
    path = Path(path)
    payload = {
        "summary": _summary(results),
        "results": [result_to_dict(r) for r in results],
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def write_text(results: List[VerifyResult], path: str | Path) -> Path:
    path = Path(path)
    summary = _summary(results)
    lines: List[str] = []
    lines.append("=" * 64)
    lines.append(" MTPCH — MTProto Proxy Checker report")
    lines.append("=" * 64)
    lines.append(f" Generated : {summary['generated_at']}")
    lines.append(f" Total     : {summary['total']}")
    lines.append(
        f" Alive     : {summary['alive']}   Dead: {summary['dead']}   "
        f"Success : {summary['success_rate']}%"
    )
    if summary["average_latency_ms"] is not None:
        lines.append(f" Avg RTT   : {summary['average_latency_ms']} ms")
    lines.append("")

    # Alive first, sorted by latency
    alive = sorted(
        (r for r in results if r.alive),
        key=lambda r: r.latency_ms or 1e9,
    )
    dead = [r for r in results if not r.alive]

    if alive:
        lines.append("-" * 64)
        lines.append(" WORKING PROXIES")
        lines.append("-" * 64)
        for r in alive:
            lat = f"{r.latency_ms:6.1f} ms" if r.latency_ms is not None else "  ---  "
            tag = f"[{r.proxy.secret_kind}]"
            lines.append(f"  OK  {lat}  {tag:>5}  {r.proxy.server}:{r.proxy.port}")
            lines.append(f"         tg   : {r.proxy.link_tg}")
            lines.append(f"         https: {r.proxy.link_https}")
            if r.fake_tls_domain:
                lines.append(f"         FakeTLS camouflage: {r.fake_tls_domain}")
            lines.append("")

    if dead:
        lines.append("-" * 64)
        lines.append(" FAILED PROXIES")
        lines.append("-" * 64)
        for r in dead:
            tag = f"[{r.proxy.secret_kind}]"
            lines.append(
                f"  --  {r.stage:<10} {tag:>5}  {r.proxy.server}:{r.proxy.port}"
            )
            if r.error:
                lines.append(f"         reason: {r.error}")
            lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def write_links_txt(results: List[VerifyResult], path: str | Path) -> Path:
    """Write a plain list of working proxy links — one per line."""
    path = Path(path)
    alive = [r for r in results if r.alive]
    alive.sort(key=lambda r: r.latency_ms or 1e9)
    lines = [r.proxy.link_https for r in alive]
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return path
