# MTPCH — MTProto Proxy Checker

> A cross-platform, no-nonsense tool that tells you whether a Telegram
> MTProto proxy **really** connects you to the Telegram network — not
> just whether the TCP port is open.

```
        __  ___  ________  ______  __  __
       /  |/  / /_  __/ / / / __ \/ / / /
      / /|_/ /   / / / /_/ / /_/ / /_/ /
     / /  / /   / / / __  / ____/ __  /
    /_/  /_/   /_/ /_/ /_/_/   /_/ /_/
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
| JSON input (objects / arrays / collector)   | ✔ |
| Local files, remote URLs, stdin, inline     | ✔ |
| Built-in curated feed (same backend as the  | ✔ |
| &nbsp;&nbsp;*Mtproto-Collector* project)    | |
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

Test the curated feed (same upstream source used by the
*Mtproto-Collector* Cloudflare Worker):

```bash
python3 mtpch.py --builtin
```

Test your own list:

```bash
python3 mtpch.py -f my_proxies.txt
```

Test a remote list:

```bash
python3 mtpch.py -u https://example.com/mtproxies.txt
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

### Command-line reference

```
python3 mtpch.py [options] [INLINE_PROXY ...]

Input sources
  -f, --file   FILE       Path to a file (repeatable).
  -u, --url    URL        HTTP(S) URL to download (repeatable).
  --stdin                 Read proxies from standard input.
  --builtin               Use the curated upstream feed.

Testing options
  -t, --timeout    SECS   Per-proxy socket timeout. Default: 8.0.
  -c, --concurrency N     Parallel workers. Default: 32.
  --dc             N      Telegram DC id to request. Default: 2.
  --retries        N      Extra retries per proxy on failure. Default: 1.

Built-in feed filters
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
- **منبع داخلی:** همون backend که پروژه‌ی *Mtproto-Collector* استفاده
  می‌کنه — با همون فیلترها
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
# استفاده از منبعِ داخلی (آپدیتِ زنده از mtpro.xyz)
python3 mtpch.py --builtin

# فایلِ خودت
python3 mtpch.py -f my_proxies.txt

# یه لینکِ اینترنتی که لیست پراکسی داره
python3 mtpch.py -u https://example.com/proxies.txt

# یه پراکسیِ تکی
python3 mtpch.py "tg://proxy?server=1.2.3.4&port=443&secret=ee..."
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

### لایسنس

MIT — فایلِ [LICENSE](LICENSE) رو ببین.
