#!/usr/bin/env python3
"""pentrix-xss: reflected XSS scanner.

Injects unique, inert canary payloads into each query parameter of a URL,
fetches the page, and reports where each value is reflected, classified by
HTML context: inside a <script> block, inside a quoted attribute, inside an
HTML tag, as plain HTML text, or HTML-encoded.

This tool only detects reflection. It does not exploit anything.
Only scan sites you own or are authorized to test.
"""

import argparse
import html
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

VERSION = "1.0.0"
DEFAULT_TIMEOUT = 10.0
MAX_BODY_BYTES = 2 * 1024 * 1024

# Built-in canary payload templates. {CANARY} is replaced with a unique
# token per parameter and payload, e.g. pxss0x0. The probe characters
# <>,'" are inert on their own but reveal the reflection context.
BUILTIN_PAYLOADS = ["{CANARY}<>'\""]

# Context labels, ordered from most to least dangerous.
CTX_SCRIPT = "inside <script> block"
CTX_DQ_ATTR = "inside double-quoted attribute"
CTX_SQ_ATTR = "inside single-quoted attribute"
CTX_TAG = "inside HTML tag"
CTX_TEXT = "plain HTML text"
CTX_ENCODED = "HTML-encoded"

SEVERITY = {
    CTX_SCRIPT: (
        "CRITICAL",
        "Reflected inside a <script> block. JavaScript execution is likely "
        "if this page is rendered in a browser.",
    ),
    CTX_DQ_ATTR: (
        "HIGH",
        "Reflected inside a double-quoted attribute. A crafted value may "
        "break out of the attribute and inject markup or event handlers.",
    ),
    CTX_SQ_ATTR: (
        "HIGH",
        "Reflected inside a single-quoted attribute. A crafted value may "
        "break out of the attribute and inject markup or event handlers.",
    ),
    CTX_TAG: (
        "MEDIUM",
        "Reflected inside an HTML tag but outside any quoted attribute. "
        "Event-handler injection may be possible.",
    ),
    CTX_TEXT: (
        "MEDIUM",
        "Reflected into page text. Markup injection is possible if the "
        "application does not strip or encode tags.",
    ),
    CTX_ENCODED: (
        "LOW",
        "Reflected but HTML-encoded. Output encoding appears to neutralize "
        "markup.",
    ),
}
SEVERITY_ORDER = [CTX_SCRIPT, CTX_DQ_ATTR, CTX_SQ_ATTR, CTX_TAG, CTX_TEXT, CTX_ENCODED]

SCRIPT_OPEN_RE = re.compile(r"<script\b[^>]*>", re.IGNORECASE)
SCRIPT_CLOSE_RE = re.compile(r"</script\s*>", re.IGNORECASE)
CHARSET_RE = re.compile(r"charset=([\w-]+)", re.IGNORECASE)
HTML_SNIFF_RE = re.compile(
    r"<(html|head|body|div|p|span|input|script|a|title|!doctype)\b", re.IGNORECASE
)


class ScanError(Exception):
    """A scan-level failure with a human-readable message."""


def build_parser():
    """Build the command line argument parser."""
    parser = argparse.ArgumentParser(
        prog="xss.py",
        description=(
            "pentrix-xss: reflected XSS scanner. Injects unique, inert canary "
            "payloads into each URL query parameter and reports where each "
            "value is reflected, classified by HTML context. Detection only, "
            "it does not exploit."
        ),
        epilog=(
            "examples:\n"
            '  python3 xss.py "https://target.example/search?q=test"\n'
            '  python3 xss.py "https://target.example/search?q=test" --timeout 5\n'
            '  python3 xss.py "https://target.example/search?q=test" -o report.json\n'
            "\nexit codes: 0 = scan completed, 1 = scan failed, 2 = bad arguments\n"
            "\nOnly scan sites you own or are authorized to test."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "url",
        help='target URL including its query string, e.g. "https://site/search?q=test"',
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        metavar="SECONDS",
        help="HTTP request timeout in seconds (default: %(default)s)",
    )
    parser.add_argument(
        "--payloads",
        metavar="FILE",
        help=(
            "read extra payload templates from FILE (one per line, # for "
            "comments). Use {CANARY} as the placeholder for the unique canary "
            "token. Extends the built-in canary list."
        ),
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="write the full report as JSON to FILE",
    )
    parser.add_argument(
        "--version", action="version", version="%(prog)s " + VERSION
    )
    return parser


def load_payloads(path, parser):
    """Load extra payload templates from a file."""
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError as exc:
        parser.error("cannot read --payloads file %r: %s" % (path, exc))
    templates = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "{CANARY}" not in line:
            line = "{CANARY}" + line
        templates.append(line)
    if not templates:
        parser.error("no usable payload templates in %r" % path)
    return templates


def make_canary(param_idx, payload_idx):
    """Return a unique, inert canary token for one parameter and payload."""
    return "pxss%dx%d" % (param_idx, payload_idx)


def build_test_url(url, params, target_idx, payload_value):
    """Rebuild the URL with the target parameter replaced by the payload."""
    parts = urllib.parse.urlparse(url)
    new_params = [
        (name, payload_value if i == target_idx else value)
        for i, (name, value) in enumerate(params)
    ]
    query = urllib.parse.urlencode(new_params)
    return urllib.parse.urlunparse(parts._replace(query=query))


def fetch_text(url, timeout):
    """Fetch a URL and return (text, content_type).

    Raises ScanError with a clear message on any request failure.
    """
    request = urllib.request.Request(
        url, headers={"User-Agent": "pentrix-xss/%s" % VERSION}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            content_type = response.headers.get("Content-Type", "")
            raw = response.read(MAX_BODY_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise ScanError("HTTP %d %s for %s" % (exc.code, exc.reason, url))
    except urllib.error.URLError as exc:
        raise ScanError("request failed for %s: %s" % (url, exc.reason))
    except OSError as exc:
        # Covers socket.timeout and other connection-level failures.
        raise ScanError("request failed for %s: %s" % (url, exc))
    if len(raw) > MAX_BODY_BYTES:
        raise ScanError("response too large, skipping %s" % url)
    match = CHARSET_RE.search(content_type or "")
    charset = match.group(1) if match else "utf-8"
    try:
        text = raw.decode(charset, errors="replace")
    except LookupError:
        text = raw.decode("utf-8", errors="replace")
    return text, content_type


def looks_like_html(content_type, text):
    """Decide whether a response is worth scanning for reflections."""
    ctype = (content_type or "").lower()
    if "html" in ctype:
        return True
    if ctype and not any(t in ctype for t in ("text", "xml", "xhtml")):
        return False
    return bool(HTML_SNIFF_RE.search(text.lstrip()[:4096]))


def find_script_spans(text):
    """Return (start, end) spans of <script>...</script> blocks."""
    spans = []
    for match in SCRIPT_OPEN_RE.finditer(text):
        close = SCRIPT_CLOSE_RE.search(text, match.end())
        end = close.end() if close else len(text)
        spans.append((match.start(), end))
    return spans


def classify_raw(text, idx, script_spans):
    """Classify the context of a raw (unencoded) reflection at index idx."""
    if any(start <= idx < end for start, end in script_spans):
        return CTX_SCRIPT
    lt = text.rfind("<", 0, idx)
    gt = text.rfind(">", 0, idx)
    if lt > gt:
        # Inside a tag: walk the tag text tracking quote state to see
        # whether the reflection sits inside a quoted attribute value.
        in_single = in_double = False
        for ch in text[lt:idx]:
            if ch == '"' and not in_single:
                in_double = not in_double
            elif ch == "'" and not in_double:
                in_single = not in_single
        if in_double:
            return CTX_DQ_ATTR
        if in_single:
            return CTX_SQ_ATTR
        return CTX_TAG
    return CTX_TEXT


def encoded_variants(payload):
    """Common HTML-encoded forms of a payload string."""
    base = html.escape(payload, quote=True)
    return {
        base,
        base.replace("&#x27;", "&#39;"),
        base.replace("&quot;", "&#34;"),
        html.escape(payload, quote=False),
    }


def find_reflections(text, payload):
    """Find every reflection of payload in text, classified by context.

    Returns an ordered list of unique context labels. A raw reflection is
    classified structurally; if the payload only appears HTML-encoded, a
    single CTX_ENCODED entry is returned.
    """
    script_spans = find_script_spans(text)
    contexts = []
    start = 0
    while True:
        idx = text.find(payload, start)
        if idx == -1:
            break
        ctx = classify_raw(text, idx, script_spans)
        if ctx not in contexts:
            contexts.append(ctx)
        start = idx + len(payload)
    if not contexts:
        for variant in encoded_variants(payload):
            if variant != payload and variant in text:
                return [CTX_ENCODED]
    return contexts


def worst_context(contexts):
    """Return the most severe context from a list."""
    for ctx in SEVERITY_ORDER:
        if ctx in contexts:
            return ctx
    return None


def scan_url(url, payloads, timeout):
    """Scan every query parameter of url. Returns a report dict."""
    parts = urllib.parse.urlparse(url)
    if parts.scheme not in ("http", "https"):
        raise ScanError(
            "unsupported URL scheme %r. Use an http:// or https:// URL."
            % (parts.scheme or "(none)",)
        )
    params = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    if not params:
        raise ScanError(
            "no query parameters found in the URL. "
            "Add at least one, e.g. ?q=test, so there is something to inject into."
        )

    results = []
    for pidx, (name, _value) in enumerate(params):
        entry = {
            "parameter": name,
            "reflected": False,
            "contexts": [],
            "risk": None,
            "error": None,
        }
        for sidx, template in enumerate(payloads):
            canary = make_canary(pidx, sidx)
            payload_value = template.replace("{CANARY}", canary)
            test_url = build_test_url(url, params, pidx, payload_value)
            try:
                text, content_type = fetch_text(test_url, timeout)
            except ScanError as exc:
                entry["error"] = str(exc)
                break
            if not looks_like_html(content_type, text):
                entry["error"] = (
                    "non-HTML response (Content-Type: %s). "
                    "Reflection check skipped." % (content_type or "unknown")
                )
                break
            for ctx in find_reflections(text, payload_value):
                if ctx not in entry["contexts"]:
                    entry["contexts"].append(ctx)
        if entry["contexts"]:
            entry["reflected"] = True
            worst = worst_context(entry["contexts"])
            level, hint = SEVERITY[worst]
            entry["risk"] = "%s: %s" % (level, hint)
        results.append(entry)

    reflected_count = sum(1 for e in results if e["reflected"])
    return {
        "target": url,
        "parameters": results,
        "summary": {
            "parameters_tested": len(results),
            "reflected_count": reflected_count,
            "errors": sum(1 for e in results if e["error"]),
        },
    }


def print_report(report):
    """Print the human-readable scan report to stdout."""
    print("pentrix-xss v%s" % VERSION)
    print("Target: %s" % report["target"])
    print("Parameters tested: %d" % report["summary"]["parameters_tested"])
    print()
    for entry in report["parameters"]:
        name = entry["parameter"]
        if entry["error"]:
            print("[!] '%s': ERROR: %s" % (name, entry["error"]))
        elif entry["reflected"]:
            print("[+] '%s': REFLECTED" % name)
            print("    Contexts:")
            for ctx in entry["contexts"]:
                print("      - %s" % ctx)
            print("    Risk: %s" % entry["risk"])
        else:
            print("[-] '%s': not reflected" % name)
        print()
    summary = report["summary"]
    print(
        "Reflected in %d of %d parameters."
        % (summary["reflected_count"], summary["parameters_tested"])
    )


def main(argv=None):
    """CLI entry point. Returns a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.timeout <= 0:
        parser.error("--timeout must be a positive number of seconds")

    payloads = list(BUILTIN_PAYLOADS)
    if args.payloads:
        payloads.extend(load_payloads(args.payloads, parser))

    try:
        report = scan_url(args.url, payloads, args.timeout)
    except ScanError as exc:
        print("Error: %s" % exc, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 1

    print_report(report)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                json.dump(report, fh, indent=2)
                fh.write("\n")
        except OSError as exc:
            print("Error: cannot write %s: %s" % (args.output, exc), file=sys.stderr)
            return 1
        print("Report written to %s" % args.output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
