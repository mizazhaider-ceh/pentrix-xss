# pentrix-xss

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![No dependencies](https://img.shields.io/badge/deps-zero%20%28stdlib%20only%29-brightgreen.svg)]()

A reflected XSS scanner with zero dependencies. It injects unique, inert
canary payloads into each URL query parameter, fetches the page, and tells
you **where** each value is reflected: inside a `<script>` block, inside a
quoted attribute, inside an HTML tag, as plain text, or HTML-encoded.

Detection only. It finds reflection contexts; it does not exploit anything.

## Features

- **Per-parameter canary injection.** Each parameter gets a unique token
  (e.g. `pxss0x0`) plus inert probe characters ` <>'" `, so reflections are
  matched exactly, with no false positives from other page content.
- **Context classification.** Every reflection is labeled: `<script>` block,
  double-quoted attribute, single-quoted attribute, HTML tag, plain HTML
  text, or HTML-encoded.
- **Risk hints.** Script context is flagged CRITICAL, attribute contexts
  HIGH, tag/text MEDIUM, encoded LOW.
- **Sane failure handling.** Clear messages for URLs with no parameters,
  connection errors, timeouts, HTTP errors, and non-HTML responses.
- **JSON reports** with `-o` for scripting and record keeping.
- **Custom payloads** via `--payloads` (one template per line, `{CANARY}`
  placeholder).
- Python 3 standard library only. No pip install, no virtualenv.

## How context detection works

1. The query string is parsed and each parameter is tested **one at a time**:
   its value is replaced with the canary payload while the others stay
   untouched.
2. The page is fetched with `urllib` and decoded using the charset from the
   `Content-Type` header (UTF-8 fallback).
3. Every occurrence of the exact canary string is located in the response and
   classified structurally:
   - **Inside `<script>` block:** the offset falls within a
     `<script>...</script>` span.
   - **Inside a quoted attribute:** the nearest `<` before the offset has no
     matching `>` yet (we are inside a tag), and a quote-state walk over the
     tag text shows we are inside `"..."` or `'...'`.
   - **Inside an HTML tag:** inside a tag but outside any quoted value.
   - **Plain HTML text:** none of the above.
   - **HTML-encoded:** the raw canary is absent but its `html.escape`d form
     (including common `&#39;` / `&#34;` variants) is present.

## Install

```bash
git clone <repo-url> pentrix-xss
cd pentrix-xss
python3 xss.py --help
```

That is it. Python 3.8+ is the only requirement.

## Usage

Scan a URL (quote it so the shell does not mangle the query string):

```bash
python3 xss.py "https://target.example/search?q=test"
```

Set a shorter timeout and save a JSON report:

```bash
python3 xss.py "https://target.example/search?q=test" --timeout 5 -o report.json
```

Extend the built-in canary list with your own templates:

```bash
printf '{CANARY}<svg>\n{CANARY}"onfocus="\n' > my_payloads.txt
python3 xss.py "https://target.example/search?q=test" --payloads my_payloads.txt
```

Exit codes: `0` = scan completed, `1` = scan failed, `2` = bad arguments.

### Real example

The repo ships a tiny local test target (`test_server.py`) that reflects
parameters in several contexts. Run it in one terminal, scan it in another:

```bash
# terminal 1
python3 test_server.py
# test target listening on 127.0.0.1:8931

# terminal 2
python3 xss.py "http://127.0.0.1:8931/?q=hello&s=world&e=safe"
```

Actual output from that run:

```
pentrix-xss v1.0.0
Target: http://127.0.0.1:8931/?q=hello&s=world&e=safe
Parameters tested: 3

[+] 'q': REFLECTED
    Contexts:
      - plain HTML text
      - inside double-quoted attribute
      - inside single-quoted attribute
    Risk: HIGH: Reflected inside a double-quoted attribute. A crafted value may break out of the attribute and inject markup or event handlers.

[+] 's': REFLECTED
    Contexts:
      - inside <script> block
    Risk: CRITICAL: Reflected inside a <script> block. JavaScript execution is likely if this page is rendered in a browser.

[+] 'e': REFLECTED
    Contexts:
      - HTML-encoded
    Risk: LOW: Reflected but HTML-encoded. Output encoding appears to neutralize markup.

Reflected in 3 of 3 parameters.
```

A parameter that is never reflected is reported plainly:

```
[-] 'z': not reflected
```

And the edge cases produce clear errors instead of tracebacks:

```
$ python3 xss.py "http://127.0.0.1:8931/"
Error: no query parameters found in the URL. Add at least one, e.g. ?q=test, so there is something to inject into.

$ python3 xss.py "http://127.0.0.1:8931/plain?q=a"
[!] 'q': ERROR: non-HTML response (Content-Type: text/plain). Reflection check skipped.
```

## Ethical use

Only scan sites you own or have explicit written permission to test.
Unauthorized scanning can violate the law and a site's terms of service.
This tool only detects reflection contexts; it does not exploit
vulnerabilities, bypass authentication, or exfiltrate data.

## License

MIT. See [LICENSE](LICENSE).

Copyright (c) 2026 Muhammad Izaz Haider
