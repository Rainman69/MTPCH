# MTPCH — MTProto Proxy Checker

> A cross-platform, no-nonsense tool that tells you whether a Telegram
> MTProto proxy **really** connects you to the Telegram network — not
> just whether the TCP port is open.

```
        __  _____________  ________  __
       /  |/  /_  __/ __ \/ ____/ / / /
      / /|_/ / / / / /_/ / /   / /_/ /
     / /  / / / / / ____/ /___/ __  /
    /_/  /_/ /_/ /_/    \____/_/ /_/
```

MTPCH performs the **full obfuscated MTProto handshake** through each
proxy, asks a real Telegram datacenter for a handshake reply
(`req_pq_multi` → `resPQ`), and only reports a proxy as *alive* when
Telegram genuinely answers. Pings and port scanners cannot do that;
MTPCH can.

- [English guide](#english-guide)
- [راهنمای فارسی](#راهنمای-فارسی)

---

## English guide

### Why MTPCH?

Most “proxy checkers” you will find online send a single TCP SYN packet
to `host:port` and call it a day. That tells you the port is open,
nothing more. A broken, fake, or ISP-intercepted proxy will happily
pass those checks.

MTPCH does the real thing:

1. Opens a TCP socket to the proxy.
2. Negotiates the **obfuscated MTProto transport** exactly the way an
   official Telegram client does (random 64-byte init, AES-256-CTR with
   the proxy secret, padded intermediate transport).
3. Sends an unencrypted `req_pq_multi` MTProto message through the
   tunnel.
4. Waits for a decrypted `resPQ` reply with the right constructor ID
   (`0x05162463`) and our client nonce echoed back.

If all four steps succeed, you truly have a working MTProto path to a
Telegram datacenter. Any other outcome, with a precise explanation,
is recorded.

### Features

| Feature                                     | Details |
| ------------------------------------------- | ------- |
| Real MTProto handshake, not a ping          | ✔ |
| tg:// and https://t.me/proxy links          | ✔ |
| Raw `host:port:secret` triplets             | ✔ |
| Free-form text scanning (mixed formats)     | ✔ |
| JSON input (objects / arrays / feed schemas)| ✔ |
| Local files, remote URLs, stdin, inline     | ✔ |
| Built-in upstream proxy feed                | ✔ |
| &nbsp;&nbsp;— filtered *or* raw "all" mode  | ✔ |
| VPN-aware pause between fetch & test        | ✔ |
| Text / JSON / links-list output             | ✔ |
| Beautiful terminal UI (rich tables & bars)  | ✔ |
| Bilingual, interactive menu for newcomers   | ✔ |
| Parallel testing with configurable workers  | ✔ |
| Proper exit codes for CI / shell scripts    | ✔ |
| 100 % Python, cross-platform                | ✔ |

### Installation

```bash
git clone https://github.com/Rainman69/MTPCH.git
cd MTPCH
pip install -r requirements.txt
```

Python 3.8 or newer is required. The only runtime dependencies are
[`rich`](https://pypi.org/project/rich/) for the terminal UI and
[`cryptography`](https://pypi.org/project/cryptography/) for fast
AES-256-CTR. Both are pure-Python wheels available on Windows, Linux
and macOS.

### Quick start

Test the built-in feed (a ready-to-use upstream proxy source shipped
with MTPCH, quality filters applied by default):

```bash
python3 mtpch.py --builtin
```

Test **every** entry the built-in feed returns, without applying any
quality filter:

```bash
python3 mtpch.py --builtin-all
```

Test your own list:

```bash
python3 mtpch.py -f my_proxies.txt
```

Test a remote list:

```bash
python3 mtpch.py -u https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_all.txt
```

Pipe proxies in:

```bash
cat list.txt | python3 mtpch.py --stdin
```

Test a single proxy from the command line:

```bash
python3 mtpch.py "tg://proxy?server=1.2.3.4&port=443&secret=ee..."
```

Start the **interactive menu** (just run the tool with no arguments):

```bash
python3 mtpch.py
```

### Saving results

Write any combination of the three report formats:

```bash
python3 mtpch.py --builtin \
    --json  report.json \
    --text  report.txt  \
    --links-out live.txt
```

- `--json` — full structured report, ideal for automation.
- `--text` — nicely formatted text report with every proxy, ready-to
  paste links, reasons for failures, latencies.
- `--links-out` — plain list of working `https://t.me/proxy?...` links,
  one per line, ready to import into Telegram.

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

Secrets can be supplied either in hexadecimal form (with or without
the `ee`/`dd` prefix byte) **or** as URL-safe Base64. Fake-TLS
secrets with their trailing camouflage domain are fully supported;
MTPCH will recover and display the camouflage hostname.

### VPN-aware two-phase run

MTPCH runs in **two stages**:

1. **Fetch** — download / parse the proxy list.
2. **Verify** — perform the real MTProto handshake through each proxy.

Between the two, MTPCH pauses and asks you to confirm. This is
intentional: on restricted networks (for example inside Iran) you may
need a VPN to reach the upstream source in stage 1, but for stage 2
you usually want to turn the VPN **off** so the test measures the
real reachability from your actual network.

Typical flow:

```text
[fetch]    → got 523 proxies
[confirm]  → "turn off VPN, then press Enter"
[verify]   → runs the MTProto handshake through each proxy
```

Use `--yes` (or `--no-pause`) to skip the confirmation in CI / scripts.

### Command-line reference

```
python3 mtpch.py [options] [INLINE_PROXY ...]

Input sources
  -f, --file   FILE       Path to a file (repeatable).
  -u, --url    URL        HTTP(S) URL to download (repeatable).
  --stdin                 Read proxies from standard input.
  --builtin               Use the built-in upstream feed (filters on).
  --builtin-all           Use the built-in feed with NO filters —
                          every proxy the upstream returns.

Testing options
  -t, --timeout    SECS   Per-proxy socket timeout. Default: 8.0.
  -c, --concurrency N     Parallel workers. Default: 32.
  --dc             N      Telegram DC id to request. Default: 2.
  --retries        N      Extra retries per proxy on failure. Default: 1.

Built-in feed filters (ignored with --builtin-all)
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

Only German & Dutch proxies, up-time ≥ 98 %, last seen within 6 hours:

```bash
python3 mtpch.py --builtin \
    --feed-country DE --feed-country NL \
    --feed-min-uptime 98 \
    --feed-max-age-hours 6
```

Full built-in feed, no quality filters at all, 64 workers, CI mode
(no interactive pause):

```bash
python3 mtpch.py --builtin-all --concurrency 64 --yes \
    --json all.json --links-out all-alive.txt
```

Aggressive timeout, 64 workers:

```bash
python3 mtpch.py -f list.txt --timeout 4 --concurrency 64
```

### Is it safe? Does it sign me in?

No. MTPCH never sends your phone number, never logs in, never touches
`auth_key` generation. The handshake stops at step 1 of Telegram’s
login flow — exactly the minimum needed to **prove** that the proxy
forwards traffic to a genuine Telegram datacenter.

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
[`mtpch/verifier.py`](mtpch/verifier.py).

### Running the tests

```bash
python3 -m unittest discover -s tests -v
```

### Changelog

**v1.1.0**

- Fixed the ASCII banner — the artwork now actually spells `MTPCH`
  (previously it read as `MTHPH`).
- Added `--builtin-all`: test every proxy the built-in feed returns
  with **no** quality filters applied (menu option 2).
- Added an explicit **two-phase run** — the tool now pauses between
  fetching the proxy list and starting the real connectivity test,
  asking for confirmation. This lets users on restricted networks
  (e.g. Iran) turn a VPN on for the fetch stage and off for the test
  stage so the verification reflects real-world reachability. The
  pause can be skipped with `--yes` / `--no-pause` in CI.
- Switched the verification loop to `as_completed` so fast proxies
  show up in the live table immediately instead of waiting for
  slower ones earlier in the input list.
- Hardened `cryptography` import (clear error message if missing)
  and fixed a deprecated `datetime.utcnow()` call for Python 3.12+.
- Docs / help text no longer name the upstream source; it is
  documented as the "built-in feed".

### License

MIT — see [LICENSE](LICENSE).

---

## راهنمای فارسی

### این ابزار چی کار می‌کنه؟

بیشتر ابزارهایی که ادعا می‌کنن «پراکسی MTProto رو تست می‌کنن»، فقط
یه بسته‌ی TCP می‌فرستن به `host:port` و اگه پورت باز بود می‌گن «سالمه».
اما این اصلاً کافی نیست: یه سرورِ خراب، یا پراکسیِ جعلی، یا حتی
فایروالِ ISP هم می‌تونه جوابِ TCP بده بدون این‌که واقعاً تو رو به
تلگرام وصل کنه.

**MTPCH** تست واقعی می‌کنه:

1. به پراکسی TCP می‌زنه.
2. دقیقاً مثل کلاینتِ رسمیِ تلگرام، هندشِیکِ پوششی (Obfuscated
   Transport) رو انجام می‌ده — یعنی ۶۴ بایت اولیه‌ی تصادفی، رمزنگاری
   AES-256-CTR با سِکرتِ پراکسی، ترنسپورتِ padded-intermediate.
3. یه پیامِ MTProto بدون رمز از نوع `req_pq_multi` از داخلِ تونل
   می‌فرسته.
4. منتظرِ جوابِ `resPQ` از سمتِ DCِ تلگرام می‌مونه و چک می‌کنه که
   ConstructorID درست باشه (`0x05162463`) و Nonceِ خودمون برگشته باشه.

اگر هر چهار مرحله موفق باشه، یعنی پراکسی واقعاً داره ترافیک رو به
سرورهای تلگرام می‌رسونه. هر اتفاقِ دیگه‌ای با یه پیغامِ خطایِ دقیق
گزارش می‌شه (مثلاً TCP رد شد، هندشِیک رد شد، تلگرام جواب نداد و ...).

### ویژگی‌ها

- تستِ واقعیِ اتصال، نه پینگ ساده
- پشتیبانی از همه فرمت‌ها: `tg://proxy?...`, `https://t.me/proxy?...`,
  `host:port:secret`, JSON
- ورودی از فایل، لینک اینترنتی، stdin، یا تایپ مستقیم
- **منبع داخلی:** MTPCH یک backendِ دریافتِ پراکسی از پیش‌آماده دارد،
  با دو حالت: (۱) **فیلترشده** (پیش‌فرض) برای گرفتنِ فقط پراکسی‌های
  باکیفیت، و (۲) **all / بدون فیلتر** (`--builtin-all`) که تمام
  پراکسی‌هایی که backend برمی‌گرداند را بدون هیچ فیلتری می‌دهد.
- **مکثِ بین دو مرحله (مخصوصِ ایران):** بین مرحله‌ی دریافتِ لیست و
  اجرای تست، ابزار از شما می‌پرسد که آیا آماده‌ی شروعِ تست هستید یا
  نه. این کار به شما اجازه می‌دهد اگر برای دریافتِ لیست ناچار به
  روشن کردنِ VPN بوده‌اید، **قبل از شروعِ تست VPN را خاموش کنید** تا
  نتیجه، واقعیتِ اتصالِ شما بدون VPN را نشان دهد (با `--yes` این مکث
  حذف می‌شود).
- خروجی متنی، JSON، و لیستِ لینکِ آماده برای پیست تو تلگرام
- UIِ رنگی و خوانا با جدول و پروگرِس‌بار
- منویِ تعاملی برای کسایی که با خط فرمان راحت نیستن
- کاملاً کراس‌پلتفرم (ویندوز، مک، لینوکس)

### نصب

پایتون ۳.۸ یا بالاتر لازم داری. بعد:

```bash
git clone https://github.com/Rainman69/MTPCH.git
cd MTPCH
pip install -r requirements.txt
```

### شروعِ سریع

اجرا بدون آرگومان تا منویِ تعاملی باز بشه:

```bash
python3 mtpch.py
```

یا مستقیم:

```bash
# استفاده از منبعِ داخلی (با فیلترهای پیش‌فرضِ باکیفیت)
python3 mtpch.py --builtin

# استفاده از منبعِ داخلی بدونِ هیچ فیلتر — همه‌ی پراکسی‌ها
python3 mtpch.py --builtin-all

# فایلِ خودت
python3 mtpch.py -f my_proxies.txt

# یه لینکِ اینترنتی که لیست پراکسی داره
python3 mtpch.py -u https://example.com/proxies.txt

# یه پراکسیِ تکی
python3 mtpch.py "tg://proxy?server=1.2.3.4&port=443&secret=ee..."

# حالت CI — پرشِ خودکار از مکثِ VPN
python3 mtpch.py --builtin-all --yes --json report.json
```

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
پشتیبانی می‌شن و دامنه‌ی پوشش تو گزارش نشون داده می‌شه.

### فیلتر کردنِ منبع داخلی

مثلاً فقط آلمان و هلند، با uptime بالای ۹۸٪ و حداکثر ۶ ساعت قدمت:

```bash
python3 mtpch.py --builtin \
    --feed-country DE --feed-country NL \
    --feed-min-uptime 98 \
    --feed-max-age-hours 6
```

اگر می‌خواهید هیچ فیلتری اعمال نشود و **تمامِ** پراکسی‌هایی که
backend برمی‌گرداند تست شود:

```bash
python3 mtpch.py --builtin-all
```

### خطاها چی می‌گن؟

وقتی یه پراکسی رد می‌شه، تو گزارش دقیقاً می‌بینی کجا گیر کرد:

| مرحله | یعنی چی؟ |
| ----- | -------- |
| `dns` | اسمِ سرور قابلِ resolve شدن نیست. |
| `connect` | TCP اصلاً وصل نشد (فایروال/پورت بسته/سرور خاموش). |
| `handshake` | ارسالِ ۶۴ بایتِ اولیه موفق نبود. |
| `telegram` | پراکسی وصل شد، ولی تلگرام پشتش جواب درست نداد (سِکرت اشتباه، پراکسی خراب، یا DC در دسترس نیست). |
| `ok` | سالم و قابل استفاده. |

### امنیت

این ابزار **هیچ‌وقت** به حسابت لاگین نمی‌کنه، شماره‌ی تلفن نمی‌خواد و
`auth_key` هم نمی‌سازه. فقط اولین قدمِ هندشِیکِ تلگرام انجام می‌شه که
برای تاییدِ کار کردنِ پراکسی کافیه.

### مشارکت

هر Issue یا Pull Request‌ای که کد رو بهتر می‌کنه خوش‌آمده. لطفاً
تست‌های موجود رو خراب نکنید:

```bash
python3 -m unittest discover -s tests -v
```

### تغییرات — نسخه ۱٫۱٫۰

- **رفعِ باگِ بنر:** طرحِ ASCII که قبلاً `MTHPH` خوانده می‌شد اصلاح شد و
  حالا واقعاً `MTPCH` را نشان می‌دهد.
- **گزینه‌ی `--builtin-all`:** تستِ همه‌ی پراکسی‌هایی که backend
  برمی‌گرداند، بدون اعمالِ هیچ‌گونه فیلترِ کیفیت (گزینه‌ی ۲ در منو).
- **مکث بین دو مرحله:** حالا بعد از دریافتِ لیست و قبل از شروعِ تست،
  ابزار از شما تأیید می‌خواهد تا فرصتِ خاموش/روشن کردنِ VPN را داشته
  باشید. در ایران و سایر شبکه‌های محدود، معمولاً برای گرفتنِ لیست
  نیاز به VPN دارید ولی برای تست باید VPN خاموش باشد تا نتیجه
  واقعی باشد. با `--yes` این مکث حذف می‌شود.
- اجرای تست به `as_completed` منتقل شد تا پراکسی‌های سریع بلافاصله
  در جدولِ زنده ظاهر شوند و منتظرِ پراکسی‌های کند نمانند.
- پیغامِ خطای واضح‌تر برای نبودِ پکیجِ `cryptography` و رفعِ هشدارِ
  `datetime.utcnow()` در پایتون ۳٫۱۲+.

### لایسنس

MIT — فایلِ [LICENSE](LICENSE) رو ببین.
