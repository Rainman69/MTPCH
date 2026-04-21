"""Command-line entry point for MTPCH.

The tool can be driven either through flags (great for scripting and
CI) or through a friendly interactive menu that is shown when it is
launched without any arguments.  Output is colourised with *rich*
when the library is available and falls back to plain ANSI otherwise.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from . import output as _output
from . import sources as _sources
from .verifier import ProxyInfo, VerifyResult, verify_proxy

# ---------------------------------------------------------------------------
# Optional rich import — degrade gracefully when the dep is missing.
# ---------------------------------------------------------------------------

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import (
        BarColumn,
        MofNCompleteColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
        TimeElapsedColumn,
    )
    from rich.table import Table
    from rich.text import Text

    _HAS_RICH = True
    console: "Console" = Console(highlight=False)
except Exception:  # pragma: no cover - exercised in stripped envs
    _HAS_RICH = False

    class _FallbackConsole:  # minimal shim so the rest of the code keeps working
        def print(self, *args, **kwargs):
            msg = " ".join(str(a) for a in args)
            print(msg)

        def rule(self, title: str = ""):
            print(f"--- {title} ---" if title else "-" * 60)

        def input(self, prompt: str = "") -> str:
            return input(prompt)

    console = _FallbackConsole()  # type: ignore


# ---------------------------------------------------------------------------
# Branding
# ---------------------------------------------------------------------------


BANNER_EN = r"""
        __  _____________  ________  __
       /  |/  /_  __/ __ \/ ____/ / / /
      / /|_/ / / / / /_/ / /   / /_/ /
     / /  / / / / / ____/ /___/ __  /
    /_/  /_/ /_/ /_/    \____/_/ /_/
"""

TAGLINE_EN = (
    "MTProto Proxy Checker — a real end-to-end verifier for Telegram MTProxies"
)
TAGLINE_FA = (
    "چکر پراکسی MTProto — تست واقعیِ اتصال پراکسی‌های تلگرام، نه فقط پینگ ساده"
)


def _print_banner() -> None:
    if _HAS_RICH:
        title = Text(BANNER_EN, style="bold cyan")
        console.print(title)
        console.print(f"  [bold]MTPCH[/bold] v{__version__}  —  [italic]{TAGLINE_EN}[/italic]")
        console.print(f"  [magenta]{TAGLINE_FA}[/magenta]")
        console.print()
    else:
        print(BANNER_EN)
        print(f"  MTPCH v{__version__} — {TAGLINE_EN}")
        print(f"  {TAGLINE_FA}\n")


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    description = (
        "MTPCH is a cross-platform MTProto-proxy checker.  It performs the "
        "obfuscated MTProto handshake through each proxy and verifies that a "
        "real Telegram datacenter replies with a valid resPQ message, so "
        "results reflect true end-to-end reachability rather than a raw ping."
    )

    epilog = (
        "Examples:\n"
        "  mtpch --builtin                          # test the curated feed\n"
        "  mtpch -f proxies.txt                     # test a local list\n"
        "  mtpch -u https://example.com/list.txt    # fetch a remote list\n"
        "  mtpch --stdin < list.txt                 # read from stdin\n"
        "  mtpch --builtin --json report.json --text report.txt --links-out live.txt\n"
    )

    p = argparse.ArgumentParser(
        prog="mtpch",
        description=description,
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--version", action="version", version=f"MTPCH {__version__}"
    )

    src = p.add_argument_group("Input sources")
    src.add_argument("-f", "--file", action="append", default=[],
                     help="Path to a file containing proxy links (repeatable)")
    src.add_argument("-u", "--url", action="append", default=[],
                     help="HTTP(S) URL that returns proxy links (repeatable)")
    src.add_argument("--stdin", action="store_true",
                     help="Read proxies from standard input")
    src.add_argument("--builtin", action="store_true",
                     help="Use the built-in upstream proxy feed (quality "
                          "filters applied by default)")
    src.add_argument("--builtin-all", action="store_true",
                     help="Use the built-in upstream feed but return every "
                          "proxy it lists without applying any quality "
                          "filter (implies --builtin)")
    src.add_argument("proxy", nargs="*",
                     help="One or more inline proxies (tg://, https://t.me/proxy?…, "
                          "or host:port:secret triplets)")

    tuning = p.add_argument_group("Testing options")
    tuning.add_argument("-t", "--timeout", type=float, default=8.0,
                        help="Per-proxy socket timeout in seconds (default: 8.0)")
    tuning.add_argument("-c", "--concurrency", type=int, default=32,
                        help="Number of proxies tested in parallel (default: 32)")
    tuning.add_argument("--dc", type=int, default=2,
                        help="Telegram DC id to ask for (default: 2)")
    tuning.add_argument("--retries", type=int, default=1,
                        help="Extra retry attempts per proxy on failure "
                             "(default: 1, meaning up to 2 total tries)")

    flt = p.add_argument_group("Built-in feed filters (ignored without --builtin)")
    flt.add_argument("--feed-min-uptime", type=int,
                     help="Minimum uptime percentage")
    flt.add_argument("--feed-max-ping", type=int, help="Maximum reported ping (ms)")
    flt.add_argument("--feed-country", action="append", default=[],
                     help="Restrict to country code (repeatable)")
    flt.add_argument("--feed-max-age-hours", type=int,
                     help="Ignore entries older than this many hours")

    out = p.add_argument_group("Output options")
    out.add_argument("--json", dest="json_out",
                     help="Write a structured JSON report to this path")
    out.add_argument("--text", dest="text_out",
                     help="Write a human-readable text report to this path")
    out.add_argument("--links-out", dest="links_out",
                     help="Write a plain list of working proxy links to this path")
    out.add_argument("--no-color", action="store_true",
                     help="Disable ANSI colours in the console output")
    out.add_argument("--quiet", action="store_true",
                     help="Only print the final summary line")

    menu = p.add_argument_group("Help & language")
    menu.add_argument("--lang", choices=("en", "fa", "both"), default="both",
                      help="Language of the help banner (default: both)")
    menu.add_argument("--menu", action="store_true",
                      help="Force the interactive menu even when flags are present")
    menu.add_argument("--yes", "--no-pause", dest="auto_yes", action="store_true",
                      help="Skip the 'start the test?' confirmation shown "
                           "between fetching proxies and running the checks. "
                           "Useful for CI / non-interactive runs.")

    return p


# ---------------------------------------------------------------------------
# Interactive menu (shown when no source is specified)
# ---------------------------------------------------------------------------


INTERACTIVE_HELP_EN = """\
MTPCH — What this tool does
----------------------------
It checks whether Telegram MTProto proxies really forward you to the
Telegram network. Each proxy is tested by performing the full
obfuscated MTProto handshake and asking Telegram for a handshake
response (resPQ). Only proxies that answer correctly are reported as
"alive" — a simple TCP ping is not enough.

Choose a source below, pick an output format, and wait for the run to
finish. At the end you can export the results to JSON, a full text
report, and/or a plain links file you can paste into any client.
"""

INTERACTIVE_HELP_FA = """\
MTPCH — این ابزار چه کاری می‌کند؟
---------------------------------
این ابزار بررسی می‌کند که پراکسی‌های MTProto تلگرام «واقعاً» شما را
به سرورهای تلگرام وصل می‌کنند یا نه. برای هر پراکسی هندشِیکِ کاملِ
MTProto اجرا می‌شود و از DC تلگرام پاسخِ resPQ گرفته می‌شود. پس
برخلاف ابزارهای ساده که فقط پورت را پینگ می‌کنند، این‌جا اتصالِ واقعی
سنجیده می‌شود.

از منوی زیر یک منبع (فایل، لینک، یا منبع داخلی) را انتخاب کنید؛ در
پایان می‌توانید گزارش را به صورت JSON، متنِ خوانا، یا لیست لینکِ
آماده‌ی استفاده ذخیره کنید.
"""


def _show_help(lang: str) -> None:
    if lang in ("en", "both"):
        if _HAS_RICH:
            console.print(Panel.fit(INTERACTIVE_HELP_EN, title="How it works (EN)",
                                    border_style="cyan"))
        else:
            console.print(INTERACTIVE_HELP_EN)
    if lang in ("fa", "both"):
        if _HAS_RICH:
            console.print(Panel.fit(INTERACTIVE_HELP_FA, title="راهنما (FA)",
                                    border_style="magenta"))
        else:
            console.print(INTERACTIVE_HELP_FA)


def _menu() -> Optional[argparse.Namespace]:
    """Guide the user through the available options.

    Returns a populated ``argparse.Namespace`` ready for :func:`run`,
    or ``None`` if the user decided to quit.
    """
    _show_help("both")
    console.print()
    console.print("  [bold]1[/bold]) Built-in feed  [dim](recommended filters: "
                  "good uptime, low ping, fresh)[/dim]"
                  if _HAS_RICH else "  1) Built-in feed (recommended filters)")
    console.print("  [bold]2[/bold]) Built-in feed  [dim](ALL proxies — no "
                  "filters applied)[/dim]"
                  if _HAS_RICH else "  2) Built-in feed (all proxies, no filters)")
    console.print("  [bold]3[/bold]) Test a local file" if _HAS_RICH
                  else "  3) Local file")
    console.print("  [bold]4[/bold]) Test a remote URL" if _HAS_RICH
                  else "  4) Remote URL")
    console.print("  [bold]5[/bold]) Paste proxies manually" if _HAS_RICH
                  else "  5) Paste manually")
    console.print("  [bold]6[/bold]) Show help again" if _HAS_RICH
                  else "  6) Show help")
    console.print("  [bold]q[/bold]) Quit" if _HAS_RICH else "  q) Quit")

    ns = argparse.Namespace(
        file=[], url=[], stdin=False, builtin=False, builtin_all=False, proxy=[],
        timeout=8.0, concurrency=32, dc=2, retries=1,
        feed_min_uptime=None, feed_max_ping=None, feed_country=[],
        feed_max_age_hours=None,
        json_out=None, text_out=None, links_out=None,
        no_color=False, quiet=False, lang="both", menu=False,
        auto_yes=False,
    )

    while True:
        choice = console.input("\n  Choose [1-6/q]: ").strip().lower()
        if choice in ("q", "quit", "exit"):
            return None
        if choice == "1":
            ns.builtin = True
            break
        if choice == "2":
            ns.builtin = True
            ns.builtin_all = True
            break
        if choice == "3":
            path = console.input("  Path to the file: ").strip()
            if not path:
                continue
            ns.file.append(path)
            break
        if choice == "4":
            url = console.input("  Full URL (http/https): ").strip()
            if not url:
                continue
            ns.url.append(url)
            break
        if choice == "5":
            console.print("  Paste one proxy per line. End with an empty line:")
            buf: list[str] = []
            while True:
                line = console.input("    > ")
                if not line:
                    break
                buf.append(line)
            if buf:
                ns.proxy = buf
                break
        if choice == "6":
            _show_help("both")
            continue

    _prompt_output_targets(ns)
    _prompt_tuning(ns)
    return ns


def _prompt_output_targets(ns: argparse.Namespace) -> None:
    console.print()
    ans = console.input("  Save JSON report? (path, blank to skip): ").strip()
    if ans:
        ns.json_out = ans
    ans = console.input("  Save text report? (path, blank to skip): ").strip()
    if ans:
        ns.text_out = ans
    ans = console.input("  Save plain links list? (path, blank to skip): ").strip()
    if ans:
        ns.links_out = ans


def _prompt_tuning(ns: argparse.Namespace) -> None:
    console.print()
    ans = console.input(f"  Timeout per proxy (seconds) [default {ns.timeout}]: ").strip()
    if ans:
        try:
            ns.timeout = float(ans)
        except ValueError:
            pass
    ans = console.input(f"  Parallel workers [default {ns.concurrency}]: ").strip()
    if ans:
        try:
            ns.concurrency = max(1, int(ans))
        except ValueError:
            pass


# ---------------------------------------------------------------------------
# Core runner
# ---------------------------------------------------------------------------


def _collect_proxies(args) -> List[ProxyInfo]:
    collected: List[ProxyInfo] = []
    seen: set[tuple] = set()
    reports: list[str] = []

    def _add(proxies: List[ProxyInfo]):
        for p in proxies:
            key = (p.server.lower(), p.port, p.raw_secret.lower())
            if key not in seen:
                seen.add(key)
                collected.append(p)

    if args.builtin or getattr(args, "builtin_all", False):
        disable = bool(getattr(args, "builtin_all", False))
        filter_rules: dict = {}
        if not disable:
            if args.feed_min_uptime is not None:
                filter_rules["uptime"] = args.feed_min_uptime
            if args.feed_max_ping is not None:
                filter_rules["ping_max"] = args.feed_max_ping
            if args.feed_country:
                filter_rules["countries"] = [c.upper() for c in args.feed_country]
            if args.feed_max_age_hours is not None:
                filter_rules["max_age_hours"] = args.feed_max_age_hours

        proxies, meta = _sources.load_from_builtin(
            filter_rules=filter_rules or None,
            disable_filters=disable,
        )
        _add(proxies)
        if disable:
            reports.append(
                f"built-in feed: {meta['after_filter']} proxies "
                f"(all entries, no filter)"
            )
        else:
            reports.append(
                f"built-in feed: {meta['after_filter']} proxies after filter "
                f"(from {meta['total']} upstream)"
            )

    for path in args.file:
        try:
            proxies, skipped = _sources.load_from_file(path)
        except FileNotFoundError:
            _warn(f"file not found: {path}")
            continue
        _add(proxies)
        reports.append(
            f"file {path}: {len(proxies)} proxies"
            + (f" ({skipped} lines skipped)" if skipped else "")
        )

    for url in args.url:
        try:
            proxies, _ = _sources.load_from_url(url)
        except Exception as exc:
            _warn(f"failed to load {url}: {exc}")
            continue
        _add(proxies)
        reports.append(f"url {url}: {len(proxies)} proxies")

    if args.stdin:
        proxies, _ = _sources.load_from_stdin()
        _add(proxies)
        reports.append(f"stdin: {len(proxies)} proxies")

    if args.proxy:
        from . import parser as _p
        inline_proxies: List[ProxyInfo] = []
        for item in args.proxy:
            try:
                if item.lower().startswith(("tg://", "http://", "https://")):
                    inline_proxies.append(_p.parse_link(item))
                else:
                    inline_proxies.extend(_p.extract_from_text(item))
            except Exception as exc:
                _warn(f"ignored argument '{item[:60]}…': {exc}")
        _add(inline_proxies)
        if inline_proxies:
            reports.append(f"inline: {len(inline_proxies)} proxies")

    if reports:
        for line in reports:
            _info(line)

    return collected


def _warn(msg: str) -> None:
    if _HAS_RICH:
        console.print(f"[bold yellow]![/bold yellow] {msg}")
    else:
        console.print(f"! {msg}")


def _info(msg: str) -> None:
    if _HAS_RICH:
        console.print(f"[cyan]·[/cyan] {msg}")
    else:
        console.print(f". {msg}")


# ---------------------------------------------------------------------------
# VPN / start-test confirmation
# ---------------------------------------------------------------------------

_CONFIRM_EN = (
    "Proxies have been fetched.\n"
    "Before the real connectivity test starts, make sure your "
    "internet connection reflects how you actually use Telegram:\n"
    "  •  If you had to enable a VPN to reach the proxy feed (e.g. "
    "because of ISP restrictions), turn it OFF now so that the test "
    "measures real-world reachability from your network.\n"
    "  •  If your normal Telegram usage is already direct, leave the "
    "network as it is."
)

_CONFIRM_FA = (
    "لیستِ پراکسی‌ها دریافت شد.\n"
    "قبل از اینکه تست واقعیِ اتصال شروع شود، وضعیتِ اینترنت خود را "
    "بررسی کنید:\n"
    "  •  اگر برای گرفتنِ این لیست ناچار به روشن کردنِ VPN بوده‌اید "
    "(مثلاً به‌خاطر محدودیت‌های ISP در ایران)، الان VPN را خاموش "
    "کنید تا تست، واقعیتِ اتصالِ شما به تلگرام را نشان دهد.\n"
    "  •  اگر به صورتِ عادی بدون VPN از تلگرام استفاده می‌کنید، "
    "همان وضعیت را نگه دارید."
)


def _prompt_start_test(auto_yes: bool) -> bool:
    """Ask the user whether to begin the verification phase.

    Returns ``True`` to continue, ``False`` to abort the run.  When
    ``auto_yes`` is true, or when stdin is not a TTY (pipelines /
    CI), the prompt is skipped and the function returns ``True`` so
    the tool keeps behaving well in non-interactive environments.
    """
    if auto_yes:
        return True
    if not sys.stdin.isatty():
        return True

    if _HAS_RICH:
        console.print(Panel.fit(_CONFIRM_EN, title="Ready to test (EN)",
                                border_style="yellow"))
        console.print(Panel.fit(_CONFIRM_FA, title="آماده‌ی تست (FA)",
                                border_style="magenta"))
    else:
        console.print(_CONFIRM_EN)
        console.print()
        console.print(_CONFIRM_FA)

    while True:
        try:
            ans = console.input(
                "\n  Start the connectivity test now? [Y/n] / "
                "شروع تست؟ [Y/n]: "
            ).strip().lower()
        except EOFError:
            return True
        if ans in ("", "y", "yes", "بله", "ب"):
            return True
        if ans in ("n", "no", "خیر", "ن"):
            return False
        console.print("  Please answer Y or N.")


def _verify_all(
    proxies: List[ProxyInfo],
    *,
    timeout: float,
    concurrency: int,
    dc_id: int,
    retries: int,
    quiet: bool,
) -> List[VerifyResult]:
    results: List[VerifyResult] = []
    if not proxies:
        return results

    def _run(p: ProxyInfo) -> VerifyResult:
        attempts = max(1, retries + 1)
        last: Optional[VerifyResult] = None
        for _ in range(attempts):
            last = verify_proxy(p, timeout=timeout, dc_id=dc_id)
            if last.alive:
                return last
        assert last is not None
        return last

    max_workers = max(1, min(concurrency, len(proxies)))

    if _HAS_RICH and not quiet:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task("Verifying proxies", total=len(proxies))
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
                futures = [ex.submit(_run, p) for p in proxies]
                for fut in concurrent.futures.as_completed(futures):
                    res = fut.result()
                    results.append(res)
                    progress.advance(task)
                    _live_status(res)
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = [ex.submit(_run, p) for p in proxies]
            for fut in concurrent.futures.as_completed(futures):
                res = fut.result()
                results.append(res)
                if not quiet:
                    _live_status(res)
    return results


def _live_status(res: VerifyResult) -> None:
    if _HAS_RICH:
        if res.alive:
            latency = f"{res.latency_ms:6.1f} ms"
            console.print(
                f"  [green]✓[/green] {latency}  [bold]{res.proxy.server}:{res.proxy.port}[/bold] "
                f"[dim]{res.proxy.secret_kind}[/dim]"
            )
        else:
            console.print(
                f"  [red]✗[/red] [dim]{res.stage:<10}[/dim] "
                f"{res.proxy.server}:{res.proxy.port}  [dim]{res.error or ''}[/dim]"
            )
    else:
        if res.alive:
            console.print(f"  OK  {res.latency_ms:.1f} ms  "
                          f"{res.proxy.server}:{res.proxy.port}")
        else:
            console.print(f"  --  {res.stage}  {res.proxy.server}:{res.proxy.port}  "
                          f"{res.error or ''}")


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def _render_table(results: List[VerifyResult]) -> None:
    if not _HAS_RICH:
        return
    alive = sorted(
        (r for r in results if r.alive),
        key=lambda r: r.latency_ms or 1e9,
    )
    if not alive:
        return

    table = Table(
        title="Working proxies (sorted by latency)",
        header_style="bold cyan",
        title_style="bold green",
        show_lines=False,
    )
    table.add_column("#", justify="right", style="dim")
    table.add_column("Server", overflow="fold")
    table.add_column("Port", justify="right")
    table.add_column("Type", justify="center")
    table.add_column("RTT", justify="right")
    table.add_column("Link", overflow="fold", style="green")

    for i, r in enumerate(alive, 1):
        table.add_row(
            str(i),
            r.proxy.server,
            str(r.proxy.port),
            r.proxy.secret_kind,
            f"{r.latency_ms:.1f} ms" if r.latency_ms is not None else "-",
            r.proxy.link_https,
        )
    console.print(table)


def _render_summary(results: List[VerifyResult]) -> None:
    alive = [r for r in results if r.alive]
    total = len(results)
    dead = total - len(alive)
    if _HAS_RICH:
        pct = (100.0 * len(alive) / total) if total else 0.0
        panel = (
            f"[bold]Total:[/bold]  {total}\n"
            f"[bold green]Alive:[/bold green]  {len(alive)}\n"
            f"[bold red]Dead :[/bold red]  {dead}\n"
            f"[bold]Success rate:[/bold] {pct:0.1f}%\n"
        )
        if alive:
            avg = sum(r.latency_ms for r in alive if r.latency_ms) / max(
                sum(1 for r in alive if r.latency_ms), 1
            )
            panel += f"[bold]Average RTT:[/bold] {avg:0.1f} ms"
        console.print(Panel.fit(panel, title="Summary", border_style="green"))
    else:
        console.print(f"Total:{total}  Alive:{len(alive)}  Dead:{dead}")


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def run(args) -> int:
    global console
    if args.no_color and _HAS_RICH:
        console = Console(no_color=True, highlight=False)

    if not args.quiet:
        _print_banner()
    else:
        if _HAS_RICH:
            console.print(f"[dim]MTPCH v{__version__}[/dim]")

    try:
        proxies = _collect_proxies(args)
    except Exception as exc:
        _warn(f"failed to load proxies: {exc}")
        return 2

    if not proxies:
        _warn("no proxies to test — choose a source first (see --help).")
        return 1

    _info(f"about to verify {len(proxies)} unique proxies "
          f"(timeout={args.timeout}s, workers={args.concurrency})")
    console.print()

    if not _prompt_start_test(getattr(args, "auto_yes", False)):
        _warn("test aborted by user before verification started.")
        return 0

    results = _verify_all(
        proxies,
        timeout=args.timeout,
        concurrency=args.concurrency,
        dc_id=args.dc,
        retries=args.retries,
        quiet=args.quiet,
    )

    console.print()
    _render_summary(results)
    if not args.quiet:
        _render_table(results)

    if args.json_out:
        p = _output.write_json(results, args.json_out)
        _info(f"wrote JSON report → {p}")
    if args.text_out:
        p = _output.write_text(results, args.text_out)
        _info(f"wrote text report → {p}")
    if args.links_out:
        p = _output.write_links_txt(results, args.links_out)
        _info(f"wrote links list → {p}")

    return 0 if any(r.alive for r in results) else 3


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # If no source was supplied at all, drop into the interactive menu.
    no_source = (
        not args.file
        and not args.url
        and not args.stdin
        and not args.builtin
        and not getattr(args, "builtin_all", False)
        and not args.proxy
    )
    if args.menu or no_source:
        if not sys.stdin.isatty():
            # Non-interactive invocation without a source — just print
            # help so automation scripts don't hang forever.
            parser.print_help()
            return 0
        picked = _menu()
        if picked is None:
            return 0
        args = picked

    return run(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
