# MTPCH — MTProto Proxy Checker

> Tells you whether a Telegram MTProto proxy **really** connects you to
> Telegram — not just whether the TCP port is open.

```
        __  _____________  ________  __
       /  |/  /_  __/ __ \/ ____/ / / /
      / /|_/ / / / / /_/ / /   / /_/ /
     / /  / / / / / ____/ /___/ __  /
    /_/  /_/ /_/ /_/    \____/_/ /_/
```

MTPCH performs the **full obfuscated MTProto handshake** through each proxy,
asks a real Telegram datacenter for a handshake reply (`req_pq_multi` →
`resPQ`), and reports a proxy as alive only when Telegram genuinely answers.
Pings and port scanners cannot do that.

Supports all three transports — plain, `dd` (secure), and `ee` (Fake-TLS) —
and ships with built-in proxy sources, so `python3 mtpch.py --builtin` works
with no list to find and no arguments to learn.

- [English guide](#english-guide)
- [راهنمای فارسی](#راهنمای-فارسی)

---

## English guide

**Contents** · [Why](#why-mtpch) · [Install](#installation) ·
[Quick start](#quick-start) · [Reading the output](#reading-the-output) ·
[Why a proxy failed](#why-a-proxy-failed) · [Formats](#supported-proxy-formats) ·
[CLI reference](#command-line-reference) · [Python API](#use-it-as-a-library) ·
[How it works](#how-it-works-technical) · [Changelog](#changelog)

### Why MTPCH?

Most “proxy checkers” send a single TCP SYN to `host:port` and call it a day.
That tells you the port is open, nothing more — a broken, fake, or
ISP-intercepted proxy passes that check happily.

MTPCH does the real thing:

1. Opens a TCP socket to the proxy.
2. Negotiates the **obfuscated MTProto transport** exactly as an official
   Telegram client does (random 64-byte init, AES-256-CTR keyed with the proxy
   secret, padded-intermediate transport). For `ee` secrets it first completes
   a **Fake-TLS handshake** and authenticates the proxy by its HMAC digest.
3. Sends an unencrypted `req_pq_multi` MTProto message through the tunnel.
4. Waits for a `resPQ` reply with the right constructor ID (`0x05162463`) and
   our own client nonce echoed back.

Only a real Telegram datacenter can produce that reply. Anything else is
recorded with the exact stage it failed at.

| | Port scanner | MTPCH |
|---|---|---|
| Port is open | ✔ | ✔ |
| Proxy secret is correct | ✘ | ✔ |
| Traffic actually reaches Telegram | ✘ | ✔ |
| Distinguishes wrong secret from dead host | ✘ | ✔ |
| Real latency through the tunnel | ✘ | ✔ |

### Features

**Verification**

- Real MTProto handshake, not a ping
- All three transports: plain, `dd`, and `ee` (Fake-TLS, HMAC-authenticated)
- A wrong `ee` secret is reported as `faketls`, never as a false “dead”
- Per-proxy latency and a precise failure stage
- Configurable timeout, workers, retries, and target DC

**Input**

- Built-in sources — four auto-updating GitHub lists plus mtpro.xyz, no path
  needed; filtered or raw `--builtin-all` mode
- Local files, remote URLs, stdin, or inline arguments
- `tg://`, `t.me/proxy`, `host:port:secret`, JSON, or free-form text
- Hex **or** Base64 secrets, with or without the `dd`/`ee` prefix

**Output**

- Live table, per-transport counters, summary panel
- JSON, text, and links-only reports
- Working proxies as one full link per line (Telegram copy-paste safe)
- Proper exit codes for CI, `--quiet` and `--no-color` for scripts

**Practical**

- VPN-aware pause between fetching and testing
- Bilingual interactive menu for newcomers
- Pure Python, cross-platform, three dependencies

### Supported secret kinds

| Prefix | Transport | Notes |
|--------|-----------|-------|
| *(none)* | obfuscated, padded-intermediate | plain 16-byte secret |
| `dd` | obfuscated, padded-intermediate | “secure” mode |
| `ee` | **Fake-TLS** + obfuscated | Secret carries a camouflage domain, used as the SNI in a real TLS-shaped handshake. The proxy is authenticated by an HMAC-SHA256 digest in the TLS `random` field, so a wrong secret is reported as `faketls` rather than a misleading “dead”. |

### Installation

```bash
git clone https://github.com/Rainman69/MTPCH.git
cd MTPCH
pip install -r requirements.txt
```

Python 3.8+. Three dependencies, all pure-Python wheels on Windows, Linux and
macOS: [`rich`](https://pypi.org/project/rich/) for the terminal UI,
[`cryptography`](https://pypi.org/project/cryptography/) for fast AES-256-CTR,
and [`certifi`](https://pypi.org/project/certifi/) for CA certificates
(python.org builds don't use the system keychain).

### Quick start

Nothing to configure — the built-in sources mean you don't need a proxy list:

```bash
python3 mtpch.py --builtin
```

Or run with no arguments at all for the **interactive menu**:

```bash
python3 mtpch.py
```

| Goal | Command |
|------|---------|
| Built-in sources, quality-filtered | `python3 mtpch.py --builtin` |
| Built-in sources, everything, no filters | `python3 mtpch.py --builtin-all` |
| Your own file | `python3 mtpch.py -f my_proxies.txt` |
| A remote list | `python3 mtpch.py -u https://example.com/list.txt` |
| Piped in | `cat list.txt \| python3 mtpch.py --stdin` |
| One proxy | `python3 mtpch.py "tg://proxy?server=1.2.3.4&port=443&secret=ee…"` |
| Unattended / CI | `python3 mtpch.py --builtin --yes --quiet --json out.json` |

Two sample files are included if you just want to see the output shape:
[`samples/proxies.txt`](samples/proxies.txt) and
[`samples/proxies.json`](samples/proxies.json).

### Reading the output

```text
· gh:Argh94/Proxy-List: 227
· gh:kort0881/telegram-proxy-collector: 196
!   mtpro.xyz: TimeoutError: The read operation timed out
· built-in sources: 451 proxies from 4/5 sources
· about to verify 451 unique proxies (timeout=8.0s, workers=32)

  ✓   82.4 ms  1.2.3.4:443  plain
  ✓  147.1 ms  proxy.example.com:8443  ee
  ✗ faketls    bad.example.com:443  digest mismatch (wrong secret)
  ✗ connect    5.6.7.8:443  TCP connect failed: timed out

╭────────── Summary ──────────╮
│ Total:  451                 │
│ Alive:  214                 │
│ Dead :  237                 │
│ Success rate: 47.4%         │
│ By secret: plain:71/121 …   │
╰─────────────────────────────╯
```

Every source reports its own count, and a failed source is a warning (`!`)
rather than a fatal error — one dead upstream never stops the run.

`By secret` is worth watching: it breaks the success rate down per transport,
which is how you notice that (for instance) public `ee` proxies die far faster
than `dd` ones.

### Why a proxy failed

The stage tells you exactly how far it got, which separates “wrong secret”
from “host is gone”:

| Stage | Meaning |
|-------|---------|
| `dns` | Hostname does not resolve. |
| `connect` | TCP never connected — firewall, closed port, or dead host. |
| `faketls` | `ee` only: the TLS-shaped handshake failed or the server's HMAC digest didn't match. Almost always a wrong secret, or not really a Fake-TLS proxy. |
| `handshake` | The 64-byte obfuscated init could not be sent. |
| `telegram` | Proxy connected, but Telegram behind it never answered correctly — wrong secret, broken proxy, or unreachable DC. |
| `ok` | Alive and usable. |

Exit codes: `0` at least one proxy alive · `1` nothing to test ·
`2` input error · `3` everything failed.

### Saving results

```bash
python3 mtpch.py --builtin \
    --json  report.json \
    --text  report.txt  \
    --links-out live.txt
```

- `--json` — full structured report, ideal for automation.
- `--text` — formatted text report: every proxy, ready-to-paste links,
  failure reasons, latencies.
- `--links-out` — bare list of working `https://t.me/proxy?...` links, one per
  line, ready to import into Telegram.

### Supported proxy formats

MTPCH auto-detects every common MTProto proxy format:

| Example |
| ------- |
| `tg://proxy?server=HOST&port=PORT&secret=SECRET` |
| `https://t.me/proxy?server=HOST&port=PORT&secret=SECRET` |
| `https://telegram.me/proxy?...` |
| `HOST:PORT:SECRET` (with `:` `;` `,` or whitespace as separators) |
| JSON object `{ "host": ..., "port": ..., "secret": ... }` |
| JSON array of any mix of the above |
| Free-form text containing any of the above (Markdown, HTML, chat logs) |

Secrets can be hexadecimal (with or without the `ee`/`dd` prefix byte) **or**
URL-safe Base64. Fake-TLS secrets keep their trailing camouflage domain: MTPCH
recovers that hostname, uses it as the SNI in a real Fake-TLS handshake, and
authenticates the proxy by verifying its HMAC-SHA256 digest before speaking
MTProto through the tunnel.

### VPN-aware two-phase run

MTPCH runs in **two stages**:

1. **Fetch** — download and parse the proxy list.
2. **Verify** — perform the real MTProto handshake through each proxy.

Between them MTPCH pauses and asks you to confirm. This is deliberate: on a
restricted network (Iran, for instance) you may need a VPN to reach the
upstream sources in stage 1, but you want it **off** for stage 2 so the test
measures reachability from your actual connection.

```text
[fetch]    → got 451 proxies
[confirm]  → "turn off VPN, then press Enter"
[verify]   → runs the MTProto handshake through each proxy
```

Use `--yes` (or `--no-pause`) to skip the prompt in CI and scripts.

### Command-line reference

```
python3 mtpch.py [options] [INLINE_PROXY ...]

Input sources
  -f, --file   FILE       Path to a file (repeatable).
  -u, --url    URL        HTTP(S) URL to download (repeatable).
  --stdin                 Read proxies from standard input.
  --builtin               Use the built-in sources (filters on).
  --builtin-all           Use the built-in sources with NO filters —
                          every proxy the upstream returns.

Testing options
  -t, --timeout    SECS   Per-proxy socket timeout. Default: 8.0.
  -c, --concurrency N     Parallel workers. Default: 32.
  --dc             N      Telegram DC id to request. Default: 2.
  --retries        N      Extra retries per proxy on failure. Default: 1.

Built-in mtpro filters (ignored with --builtin-all)
  --feed-min-uptime N     Minimum uptime percentage.
  --feed-max-ping   N     Maximum reported ping (ms).
  --feed-country    CODE  Restrict to a country code (repeatable).
  --feed-max-age-hours N  Drop entries older than N hours.

Output options
  --json      PATH        Write the structured JSON report.
  --text      PATH        Write the human-readable text report.
  --links-out PATH        Write a bare list of working proxy links.
  --no-color              Disable ANSI colours.
  --quiet                 Only print the summary.

Misc
  --lang en|fa|both       Language of the help banner.
  --menu                  Force the interactive menu.
  --yes, --no-pause       Skip the VPN-aware confirmation prompt shown
                          between the fetch and test stages (CI mode).
  --version               Show version and exit.
```

Exit codes: `0` if at least one proxy is alive, `1` if there was
nothing to test, `2` on input error, `3` if everything failed.

### Filtering examples

The `--feed-*` filters apply to mtpro.xyz entries, which are the only ones
carrying uptime/ping/country metadata. GitHub lists are plain proxy lists with
no metadata to filter on, so they always come through in full.

Only German and Dutch proxies, uptime ≥ 98 %, seen within the last 6 hours:

```bash
python3 mtpch.py --builtin \
    --feed-country DE --feed-country NL \
    --feed-min-uptime 98 \
    --feed-max-age-hours 6
```

Everything, no quality filters, 64 workers, unattended:

```bash
python3 mtpch.py --builtin-all --concurrency 64 --yes \
    --json all.json --links-out all-alive.txt
```

Aggressive timeout on your own list:

```bash
python3 mtpch.py -f list.txt --timeout 4 --concurrency 64
```

### Use it as a library

The CLI is a thin wrapper — the pieces are importable:

```python
from mtpch.parser import extract_from_text
from mtpch.verifier import verify_proxy
from mtpch.sources import load_from_builtin

# parse anything: links, triplets, JSON, or free-form text
proxies = extract_from_text(open("list.txt").read())

# or pull the built-in sources (returns proxies + a per-source report)
proxies, meta = load_from_builtin(disable_filters=True)
print(f"{len(proxies)} proxies from {meta['sources_ok']}/{meta['source_count']} sources")

for p in proxies[:5]:
    r = verify_proxy(p, timeout=8.0)
    detail = f"{r.latency_ms:.0f}ms" if r.alive else r.error
    print(p.server, p.port, p.secret_kind, "→", r.stage, detail)
```

`verify_proxy` returns a `VerifyResult` with `alive`, `stage`, `latency_ms`,
`error`, `fake_tls_domain` and `dc_id`. It never raises on network failure — a
dead proxy is a result, not an exception.

### Is it safe? Does it sign me in?

No. MTPCH never sends your phone number, never logs in, and never touches
`auth_key` generation. The handshake stops at step 1 of Telegram's login
flow — exactly the minimum needed to **prove** the proxy forwards traffic to a
genuine Telegram datacenter.

### How it works (technical)

For the curious: the obfuscated transport protocol is described
formally at <https://core.telegram.org/mtproto/mtproto-transports>.
MTPCH follows that document to the letter:

- Generates a 64-byte random init frame avoiding the forbidden
  magic-number prefixes (`HEAD`, `POST`, `0xdddddddd`, `0xeeeeeeee`,
  TLS record header, …).
- Derives `encrypt_key = SHA256(init[8:40] || secret)` and
  `decrypt_key = SHA256(reverse(init)[8:40] || secret)`, with matching
  IVs from bytes 40–56.
- Stamps the padded-intermediate protocol tag (`0xdddddddd`) and the
  requested DC id into the plaintext, swaps in the encrypted bytes
  56–64 of the init frame and sends it as the first 64 bytes on the
  wire.
- Uses AES-256-CTR for both directions until the socket is closed.
- Sends an unencrypted MTProto message (`auth_key_id = 0`) wrapping
  the `req_pq_multi` constructor with a fresh 128-bit nonce.
- Reads the 4-byte length, then the body; decrypts both; validates
  the `auth_key_id`, message length, `resPQ` constructor and nonce
  echo.

You can read the implementation in
[`mtpch/verifier.py`](mtpch/verifier.py), and the Fake-TLS layer in
[`mtpch/faketls.py`](mtpch/faketls.py).

**Project layout**

```
mtpch/verifier.py   obfuscated transport, resPQ validation
mtpch/faketls.py    ee: ClientHello digest, ServerHello check, record layer
mtpch/parser.py     links, triplets, JSON, free-form text
mtpch/sources.py    built-in GitHub lists + mtpro, files, URLs, stdin
mtpch/output.py     JSON / text / links reports
mtpch/cli.py        argument parsing, interactive menu, live table
```

### Running the tests

```bash
python3 -m pytest tests/ -q          # or:
python3 -m unittest discover -s tests -v
```

54 tests, no external network needed — the handshake runs end to end against
an in-process fake MTProxy on a loopback socket that speaks the real
obfuscated and Fake-TLS protocols, including negative cases (wrong secret,
corrupt digest, foreign session id, silent peer, TLS alert).

### Contributing

Issues and pull requests welcome. Please keep the tests passing and add one
for anything you fix — most of the suite exists because a real proxy behaved
in a way the code didn't expect.

### Changelog

**v1.3.0**

- **`--builtin` now pulls from several sources instead of one.** Four GitHub
  repos that auto-commit fresh MTProto lists (Argh94/Proxy-List,
  kort0881/telegram-proxy-collector, Grim1313/mtproto-for-telegram,
  SoliSpirit/mtproto) plus mtpro.xyz. Measured ~440 unique proxies against
  ~40 from the single feed. Fetched concurrently — six sequential HTTPS
  round-trips to GitHub raw regularly timed out. Per-source counts and
  failures are printed, and any source can fail without failing the run.
- **Fixed: HTML-escaped proxy links were silently unparseable.** Scraped
  pages serve `secret=…&amp;port=…`, which broke the query split and dropped
  the proxy. `extract_from_text` now decodes entities first.
- **Fixed: CERTIFICATE_VERIFY_FAILED on stock Python.** python.org builds do
  not use the system keychain, so every HTTPS fetch failed. Now uses certifi
  when available, still verifying.

**v1.2.0**

- **Fake-TLS (`ee`) proxies are now fully verified** instead of being
  refused. New [`mtpch/faketls.py`](mtpch/faketls.py) implements the real
  handshake: a 517-byte `ClientHello` whose `random` field is
  `HMAC-SHA256(secret, hello_with_random_zeroed)` (timestamp XORed into the
  last 4 bytes), verification of the server's own HMAC digest, and the
  application-data record layer that carries the obfuscated transport.
  A wrong secret now reports stage `faketls` with an explicit
  "digest mismatch" instead of a misleading dead result.
- ServerHello parsing reads TLS record headers rather than assuming the
  commonly-quoted 127-byte record — the masked-certificate length varies
  between MTProxy builds, which silently broke real `ee` proxies.
- **Dedup fix:** plain/`dd`/`ee` forms of the same 16-byte secret are three
  different transports, but the dedup key only used the decoded bytes, so
  two of the three were silently dropped. The key now includes
  `secret_kind` (hex/base64 spellings of the same secret still collapse).
- Malformed camouflage domains in real-world `ee` secrets no longer raise
  from the IDNA codec.
- DNS resolution prefers IPv4 and falls back, instead of failing outright on
  hosts whose first `getaddrinfo` family is unusable.
- Summary panel reports per-transport counters (`plain:6/6 dd:7/7 ee:4/23`).

<details>
<summary><strong>v1.1.1</strong> and earlier</summary>

**v1.1.1**

- Fixed socket FD leak on TCP connect failure (high concurrency).
- Strip trailing punctuation from free-form links so chat logs no longer
  corrupt secrets (e.g. `…secret=ab12.`).
- Preserve `+` in standard base64 secrets (`parse_qs` turned them into spaces).
- Feed filters: coerce string metrics, case-insensitive country codes.
- `dd` secrets with trailing junk no longer keep `0xDD` in the key material.
- Dedup keys use decoded secret bytes; average RTT no longer skips a
  legitimate `0.0` latency.
- Working proxies print as one full link per line so they paste into Telegram
  cleanly.

**v1.1.0**

- Fixed the ASCII banner — it read as `MTHPH`.
- Added `--builtin-all` to skip all quality filters.
- Added the two-phase run with a VPN pause between fetch and test.
- Switched the verification loop to `as_completed` so fast proxies appear
  immediately instead of waiting behind slow ones.
- Clear error if `cryptography` is missing; fixed deprecated
  `datetime.utcnow()` for Python 3.12+.

</details>

### License

MIT — see [LICENSE](LICENSE).

---

## راهنمای فارسی

**فهرست** · [معرفی](#معرفی) · [ویژگی‌ها](#ویژگیها) · [نصب](#نصب) ·
[شروع سریع](#شروعِ-سریع) · [خواندن خروجی](#خواندن-خروجی) ·
[معنی خطاها](#معنی-خطاها) · [فرمت‌ها](#فرمتهای-پشتیبانیشده) ·
[امنیت](#امنیت) · [تغییرات](#تغییرات-نسخه-۱٫۳٫۰)

### معرفی

بیشتر ابزارهایی که ادعا می‌کنن «پراکسی MTProto رو تست می‌کنن»، فقط
یه بسته‌ی TCP می‌فرستن به `host:port` و اگه پورت باز بود می‌گن «سالمه».
اما این اصلاً کافی نیست: یه سرورِ خراب، یا پراکسیِ جعلی، یا حتی
فایروالِ ISP هم می‌تونه جوابِ TCP بده بدون این‌که واقعاً تو رو به
تلگرام وصل کنه.

**MTPCH** تست واقعی می‌کنه:

1. به پراکسی TCP می‌زنه.
2. دقیقاً مثل کلاینتِ رسمیِ تلگرام، هندشِیکِ پوششی (Obfuscated
   Transport) رو انجام می‌ده — یعنی ۶۴ بایت اولیه‌ی تصادفی، رمزنگاری
   AES-256-CTR با سِکرتِ پراکسی، ترنسپورتِ padded-intermediate. برای
   سِکرت‌های `ee` اول هندشِیکِ **Fake-TLS** انجام می‌شه و پراکسی با
   دایجستِ HMAC خودش احراز هویت می‌شه.
3. یه پیامِ MTProto بدون رمز از نوع `req_pq_multi` از داخلِ تونل
   می‌فرسته.
4. منتظرِ جوابِ `resPQ` از سمتِ DCِ تلگرام می‌مونه و چک می‌کنه که
   ConstructorID درست باشه (`0x05162463`) و Nonceِ خودمون برگشته باشه.

فقط یه DCِ واقعیِ تلگرام می‌تونه این جواب رو بده. هر نتیجه‌ی دیگه‌ای
با مرحله‌ی دقیقِ شکست ثبت می‌شه.

| | پورت‌اسکنر | MTPCH |
|---|---|---|
| پورت باز است | ✔ | ✔ |
| سِکرت درست است | ✘ | ✔ |
| ترافیک واقعاً به تلگرام می‌رسد | ✘ | ✔ |
| تفاوتِ «سِکرت غلط» با «سرور مرده» | ✘ | ✔ |
| پینگِ واقعی از داخلِ تونل | ✘ | ✔ |

### ویژگی‌ها

**تست**

- تستِ واقعیِ هندشِیک، نه پینگ ساده
- هر سه ترنسپورت: plain، `dd`، و `ee` (Fake-TLS با احراز هویتِ HMAC)
- سِکرتِ `ee` اشتباه به‌جای «مرده»ی گمراه‌کننده، `faketls` گزارش می‌شه
- پینگِ هر پراکسی و مرحله‌ی دقیقِ شکست
- تایم‌اوت، تعداد ورکر، ریترای و DC قابل تنظیم

**ورودی**

- **منبعِ داخلی — نیازی به دادنِ لیست نیست:** چهار مخزنِ گیت‌هاب که
  خودکار آپدیت می‌شن به‌همراه mtpro.xyz، در دو حالتِ فیلترشده یا
  کاملِ بدون فیلتر (`--builtin-all`)
- فایل، لینکِ اینترنتی، stdin، یا تایپِ مستقیم
- `tg://`، `t.me/proxy`، `host:port:secret`، JSON، یا متنِ آزاد
- سِکرت به‌صورت Hex یا Base64، با یا بدون پیشوندِ `dd`/`ee`

**خروجی**

- جدولِ زنده، شمارشِ تفکیکیِ هر ترنسپورت، پنلِ خلاصه
- گزارشِ JSON، متنی، و فقط-لینک
- پراکسی‌های سالم، هر کدوم یه لینکِ کامل در یه خط (مناسبِ کپی در تلگرام)
- کدِ خروجیِ درست برای CI، و `--quiet` و `--no-color` برای اسکریپت

**عملی**

- مکثِ آگاه‌به‌VPN بین دریافتِ لیست و شروعِ تست
- منویِ تعاملیِ دوزبانه
- کاملاً پایتون، کراس‌پلتفرم (ویندوز، مک، لینوکس)

### نصب

پایتون ۳.۸ یا بالاتر لازم داری. بعد:

```bash
git clone https://github.com/Rainman69/MTPCH.git
cd MTPCH
pip install -r requirements.txt
```

سه پکیج لازمه: `rich` برای UI، `cryptography` برای AES سریع، و `certifi`
برای گواهی‌های CA (بیلدهای رسمیِ پایتون از keychainِ سیستم استفاده نمی‌کنن).

### شروعِ سریع

هیچ تنظیمی لازم نیست — منبعِ داخلی یعنی نیازی به پیدا کردنِ لیست نداری:

```bash
python3 mtpch.py --builtin
```

یا بدون هیچ آرگومان، برای منویِ تعاملی:

```bash
python3 mtpch.py
```

| کار | دستور |
|-----|-------|
| منبعِ داخلی، فیلترشده | `python3 mtpch.py --builtin` |
| منبعِ داخلی، همه، بدون فیلتر | `python3 mtpch.py --builtin-all` |
| فایلِ خودت | `python3 mtpch.py -f my_proxies.txt` |
| لینکِ اینترنتی | `python3 mtpch.py -u https://example.com/list.txt` |
| از stdin | `cat list.txt \| python3 mtpch.py --stdin` |
| یه پراکسیِ تکی | `python3 mtpch.py "tg://proxy?server=1.2.3.4&port=443&secret=ee…"` |
| حالتِ CI | `python3 mtpch.py --builtin --yes --quiet --json out.json` |

دو فایلِ نمونه هم هست اگه فقط می‌خوای شکلِ خروجی رو ببینی:
[`samples/proxies.txt`](samples/proxies.txt) و
[`samples/proxies.json`](samples/proxies.json).

### خواندن خروجی

```text
· gh:Argh94/Proxy-List: 227
!   mtpro.xyz: TimeoutError: The read operation timed out
· built-in sources: 451 proxies from 4/5 sources

  ✓   82.4 ms  1.2.3.4:443  plain
  ✗ faketls    bad.example.com:443  digest mismatch (wrong secret)

╭────────── Summary ──────────╮
│ Total:  451                 │
│ Alive:  214                 │
│ Success rate: 47.4%         │
│ By secret: plain:71/121 …   │
╰─────────────────────────────╯
```

هر منبع تعدادِ خودش رو گزارش می‌کنه و منبعِ خراب فقط یه هشدار (`!`) می‌ده —
هیچ منبعی نمی‌تونه کلِ اجرا رو متوقف کنه.

`By secret` رو حتماً ببین: نرخِ موفقیت رو تفکیکِ ترنسپورت نشون می‌ده، و
همین‌جا می‌فهمی که مثلاً پراکسی‌های عمومیِ `ee` خیلی سریع‌تر از `dd` می‌میرن.

### ذخیره‌ی نتیجه

```bash
python3 mtpch.py --builtin \
    --json  report.json \
    --text  report.txt \
    --links-out live.txt
```

- `report.json` — گزارش کامل به صورتِ JSON، مناسب برای اسکریپت.
- `report.txt` — گزارشِ خوانا با همه جزئیات، پینگ، لینکِ آماده، دلیلِ
  شکستِ هر پراکسی.
- `live.txt` — فقط لیستِ لینک‌هایی که واقعاً کار می‌کنن، هر کدوم تو
  یه خط، آماده برای کپی تو تلگرام.

### فرمت‌های پشتیبانی‌شده

| نمونه |
| ----- |
| `tg://proxy?server=HOST&port=PORT&secret=SECRET` |
| `https://t.me/proxy?server=HOST&port=PORT&secret=SECRET` |
| `HOST:PORT:SECRET` (با : یا ; یا , یا فاصله) |
| JSON تکی `{ "host":..., "port":..., "secret":... }` |
| آرایه‌ی JSON از هر کدوم بالا |
| متنِ آزاد حاوی هر کدوم از بالا — پارسر خودش پیدا می‌کنه |

سِکرت می‌تونه Hex باشه (با یا بدون بایتِ پیشوندِ `ee`/`dd`) یا
Base64. سِکرت‌های Fake-TLS که آخرشون دامنه‌ی پوشش داره هم کاملاً
پشتیبانی می‌شن: MTPCH اون دامنه رو به‌عنوان SNI در هندشِیکِ واقعیِ
Fake-TLS استفاده می‌کنه و پراکسی رو با دایجستِ HMAC-SHA256 خودش
احراز هویت می‌کنه.

### فیلتر کردنِ منبع داخلی

فیلترهای `--feed-*` فقط روی ورودی‌های mtpro.xyz اعمال می‌شن، چون تنها
منبعی‌ست که متادیتای uptime/ping/country داره. لیست‌های گیت‌هاب متادیتا
ندارن، پس همیشه کامل می‌آن.

مثلاً فقط آلمان و هلند، با uptime بالای ۹۸٪ و حداکثر ۶ ساعت قدمت:

```bash
python3 mtpch.py --builtin \
    --feed-country DE --feed-country NL \
    --feed-min-uptime 98 \
    --feed-max-age-hours 6
```

اگر می‌خواهید هیچ فیلتری اعمال نشود و **تمامِ** پراکسی‌ها تست شوند:

```bash
python3 mtpch.py --builtin-all
```

### معنی خطاها

مرحله‌ی شکست دقیقاً می‌گه تا کجا رفته — و همین «سِکرتِ غلط» رو از
«سرورِ مرده» جدا می‌کنه:

| مرحله | یعنی چی؟ |
| ----- | -------- |
| `dns` | اسمِ سرور قابلِ resolve شدن نیست. |
| `connect` | TCP اصلاً وصل نشد (فایروال/پورت بسته/سرور خاموش). |
| `faketls` | فقط `ee`: هندشِیکِ Fake-TLS شکست خورد یا دایجستِ سرور جور نشد. تقریباً همیشه یعنی سِکرت غلطه، یا اصلاً پراکسیِ Fake-TLS نیست. |
| `handshake` | ارسالِ ۶۴ بایتِ اولیه موفق نبود. |
| `telegram` | پراکسی وصل شد، ولی تلگرام پشتش جواب درست نداد (سِکرت اشتباه، پراکسی خراب، یا DC در دسترس نیست). |
| `ok` | سالم و قابل استفاده. |

کدهای خروجی: `0` حداقل یه پراکسی سالم · `1` چیزی برای تست نبود ·
`2` خطای ورودی · `3` همه شکست خوردن.

### امنیت

این ابزار **هیچ‌وقت** به حسابت لاگین نمی‌کنه، شماره‌ی تلفن نمی‌خواد و
`auth_key` هم نمی‌سازه. فقط اولین قدمِ هندشِیکِ تلگرام انجام می‌شه که
برای تاییدِ کار کردنِ پراکسی کافیه.

### مشارکت

هر Issue یا Pull Request‌ای که کد رو بهتر می‌کنه خوش‌آمده. لطفاً
تست‌های موجود رو خراب نکنید:

```bash
python3 -m pytest tests/ -q
```

۵۴ تست، بدون نیاز به اینترنت — هندشِیک به‌صورت کامل روی یه MTProxyِ
جعلیِ درون‌پروسه تست می‌شه که پروتکلِ واقعیِ obfuscated و Fake-TLS رو
حرف می‌زنه، همراه با حالت‌های منفی (سِکرت غلط، دایجستِ خراب، سرورِ ساکت).

### تغییرات — نسخه ۱٫۳٫۰

- **`--builtin` حالا از چند منبع می‌گیرد، نه یکی.** چهار مخزن گیت‌هاب که
  لیست‌های تازهٔ MTProto را خودکار کامیت می‌کنند (Argh94/Proxy-List،
  kort0881/telegram-proxy-collector، Grim1313/mtproto-for-telegram،
  SoliSpirit/mtproto) به‌همراه mtpro.xyz. در تست واقعی ~۴۴۰ پراکسی یکتا
  در مقابل ~۴۰ پراکسی از فیدِ تنها. درخواست‌ها هم‌زمان فرستاده می‌شوند —
  شش درخواستِ پشت‌سرهم به GitHub raw مرتب تایم‌اوت می‌شد. تعداد و خطای
  هر منبع چاپ می‌شود و خرابیِ یک منبع اجرا را متوقف نمی‌کند.
- **رفع باگ: لینک‌هایی که HTML-escape شده بودند بی‌صدا خوانده نمی‌شدند.**
  صفحه‌های اسکرپ‌شده `secret=…&amp;port=…` می‌دهند که تقسیمِ کوئری را
  خراب می‌کرد. حالا اول entityها decode می‌شوند.
- **رفع باگ: خطای CERTIFICATE_VERIFY_FAILED روی پایتونِ رسمی.** بیلدهای
  python.org از keychainِ سیستم استفاده نمی‌کنند و همهٔ درخواست‌های HTTPS
  شکست می‌خورد. حالا در صورت وجود از certifi استفاده می‌شود — تاییدِ
  گواهی همچنان روشن است.

### تغییرات — نسخه ۱٫۲٫۰

- **پراکسی‌های Fake-TLS (`ee`) حالا کاملاً تست می‌شوند** و دیگر رد نمی‌شوند.
  ماژول جدید [`mtpch/faketls.py`](mtpch/faketls.py) هندشِیکِ واقعی را
  پیاده می‌کند: یک `ClientHello` ۵۱۷ بایتی که فیلد `random` آن
  `HMAC-SHA256(secret, hello_با_random_صفرشده)` است (تایم‌استمپ با ۴ بایت
  آخر XOR می‌شود)، سپس تاییدِ دایجستِ خودِ سرور، و لایهٔ رکوردهای
  application-data که ترنسپورتِ obfuscated را حمل می‌کند.
  با secretِ اشتباه، نتیجه `faketls` و پیامِ صریحِ «digest mismatch» است،
  نه یک «مرده»ی گمراه‌کننده.
- خواندنِ ServerHello از روی هدرِ رکوردها انجام می‌شود، نه با فرضِ رکوردِ
  ۱۲۷ بایتی؛ طولِ گواهیِ ماسک بین نسخه‌های MTProxy متفاوت است و همین
  موضوع پراکسی‌های `ee` واقعی را بی‌صدا خراب می‌کرد.
- **رفع باگ حذف تکراری‌ها:** سه شکلِ plain/`dd`/`ee` از یک secret، سه
  ترنسپورتِ متفاوت‌اند، اما کلیدِ dedup فقط بایت‌های decode‌شده را داشت و
  دو مورد از سه مورد بی‌صدا حذف می‌شد. حالا `secret_kind` هم در کلید هست
  (املای hex/base64 از یک secret هنوز درست ادغام می‌شود).
- دامنه‌های پوششِ خراب در secretهای واقعی `ee` دیگر باعث خطای IDNA نمی‌شوند.
- در DNS اول IPv4 امتحان می‌شود و در صورت شکست fallback داریم.
- پنلِ خلاصه، شمارشِ تفکیکی هر ترنسپورت را نشان می‌دهد
  (`plain:6/6 dd:7/7 ee:4/23`).

<details>
<summary><strong>نسخه ۱٫۱٫۱</strong> و قدیمی‌تر</summary>

**نسخه ۱٫۱٫۱**

- رفع نشتِ سوکت هنگام شکستِ TCP connect.
- حذف علائم نگارشیِ انتهای لینک در متن آزاد (مثل نقطهٔ بعد از secret).
- حفظ کاراکتر `+` در secretهای base64 استاندارد.
- فیلترها: تبدیلِ امنِ عددهای رشته‌ای، مقایسهٔ بدون حساسیت به حروفِ کد کشور.
- secretهای `dd` با بایتِ اضافه دیگر پیشوند را داخل کلید نگه نمی‌دارند.
- نمایش پراکسی‌های سالم به‌صورت یک لینک کامل در هر خط.

**نسخه ۱٫۱٫۰**

- رفعِ باگِ بنر ASCII که قبلاً `MTHPH` خوانده می‌شد.
- افزودنِ `--builtin-all` برای تست بدون هیچ فیلترِ کیفیت.
- افزودنِ مکثِ دو مرحله‌ای برای خاموش/روشن کردنِ VPN.
- انتقال حلقهٔ تست به `as_completed` تا پراکسی‌های سریع بلافاصله ظاهر شوند.
- پیغام خطای واضح برای نبودِ `cryptography` و رفعِ هشدارِ `datetime.utcnow()`.

</details>

### لایسنس

MIT — فایلِ [LICENSE](LICENSE) رو ببین.
