#!/usr/bin/env python3
"""Local test target for pentrix-xss. For development testing only.

Starts a tiny HTTP server on 127.0.0.1:8931 that reflects query parameters
into the page in several different contexts:

  ?q=  -> plain HTML text, a double-quoted attribute, a single-quoted attribute
  ?s=  -> inside a <script> block
  ?e=  -> HTML-escaped (safe control case)

  /plain -> text/plain response (non-HTML control case)

Usage:
    python3 test_server.py
    # in another terminal:
    python3 xss.py "http://127.0.0.1:8931/?q=hello&s=world&e=safe"
"""
import html
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

PORT = 8931


class Handler(BaseHTTPRequestHandler):
    def _send(self, body: bytes, ctype: str):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/plain":
            self._send(b"just some plain text, nothing to see here", "text/plain")
            return
        qs = parse_qs(parsed.query)
        q = qs.get("q", [""])[0]
        s = qs.get("s", [""])[0]
        e = qs.get("e", [""])[0]
        body = (
            "<!DOCTYPE html><html><head><title>pentrix-xss test target</title></head><body>\n"
            "<p>Results for: %s</p>\n" % q
            + '<input type="text" name="q" value="%s">\n' % q
            + "<a href=\"/go\" title='%s'>details</a>\n" % q
            + '<script>var lastSearch = "%s";</script>\n' % s
            + "<p>Filtered echo: %s</p>\n" % html.escape(e)
            + "</body></html>\n"
        ).encode("utf-8")
        self._send(body, "text/html; charset=utf-8")

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print("test target listening on 127.0.0.1:%d" % PORT, flush=True)
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
