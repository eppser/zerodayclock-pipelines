"""One HTTP client for every source. Credentials go in headers, never in the URL.

Every request yields a Response, success or not: a run that got nothing must record
that it got nothing and why (CLAUDE.md, reproducibility contract).
"""

from __future__ import annotations

import hashlib
import re
import threading
import time
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone

import httpx

UA = "zerodayclock.com research (https://zerodayclock.com)"
_SECRET = re.compile(r"(?i)(x-api-key|authorization|bearer|api[_-]?key|token|x-auth-key|(?<=[?&])key)[\"':= ]+[A-Za-z0-9._~+/=-]{8,}")   # bare key= is Shodan's


def redact(text: str) -> str:
    return _SECRET.sub(r"\1=<redacted>", text or "")


@dataclass
class Response:
    url: str
    status: int                       # 0 = transport failure
    body: bytes | None
    error: str | None
    requested_at: datetime
    finished_at: datetime
    headers: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status == 200 and self.body is not None and self.error is None

    @property
    def sha256(self) -> str | None:
        return hashlib.sha256(self.body).hexdigest() if self.body is not None else None

    def json(self):
        import json
        return json.loads(self.body)


MAX_BODY = 2 * 1024 ** 3   # decoded bytes; see Http._fetch


def gunzip_capped(data: bytes, cap: int) -> bytes | None:
    """gzip.decompress with a ceiling on the OUTPUT (security review 2026-10-26). Reads every member of a multi-member
    file, as gzip.decompress does; EOFError on a truncated stream; None when the output passes `cap`."""
    out = bytearray()
    while data:
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        out += d.decompress(data, cap + 1 - len(out))
        if len(out) > cap or d.unconsumed_tail:
            return None
        if not d.eof:
            raise EOFError("truncated gzip stream")
        data = d.unused_data if d.unused_data[:2] == b"\x1f\x8b" else b""
    return bytes(out)


class Refused(Exception):
    """Http._fetch declined on purpose (a downgrade, an oversize body, a redirect loop). Never retried."""


class Http:
    """Polite GET with retries on 429/5xx. `pause` is the minimum gap between requests,
    held across threads, so callers may share one client between workers."""

    def __init__(self, pause: float = 1.0, timeout: float = 120.0, retries: int = 3,
                 transport: httpx.BaseTransport | None = None):
        self.pause, self.retries = pause, retries
        self._last = 0.0
        self._pace = threading.Lock()
        self._c = httpx.Client(timeout=timeout, follow_redirects=True, transport=transport,
                               headers={"User-Agent": UA})

    def _fetch(self, url: str, headers: dict, params: dict | None) -> tuple[httpx.Response, bytes]:
        """One GET, following redirects by hand (security review 2026-10-26).

        httpx's own redirect handling strips Authorization on a cross-origin hop but keeps every other header, so a
        302 from a feed's host (or its CDN, if compromised) to anywhere else received the CrowdSec CTI `x-api-key`.
        Here the caller's headers travel only while the origin (scheme, host, port) stays the same; and no hop may go
        from https down to http, on any host, so nothing is ever re-sent in clear text.

        The body is read with a cap on its DECODED size: a gzip-encoded answer of a few MB can inflate to tens of GB
        and kill the runner. MAX_BODY is far above the largest feed (the VulnCheck backup). The bytes are returned
        alongside the response, which is streamed and so has no `.text` of its own.
        """
        send_headers, cur, prm = dict(headers), httpx.URL(url), params
        origin = (cur.scheme, cur.host, cur.port)
        for _ in range(10):
            with self._c.stream("GET", cur, headers=send_headers, params=prm, follow_redirects=False) as r:
                if r.is_redirect and r.headers.get("location"):
                    nxt = r.url.join(r.headers["location"])
                    if r.url.scheme == "https" and nxt.scheme != "https":
                        raise Refused(f"refused redirect from https to {nxt.scheme}://")
                    if (nxt.scheme, nxt.host, nxt.port) != origin:
                        send_headers = {}
                    cur, prm = nxt, None
                    continue
                buf = bytearray()
                for chunk in r.iter_bytes():
                    buf += chunk
                    if len(buf) > MAX_BODY:
                        raise Refused(f"body larger than {MAX_BODY:,} bytes after decoding")
                return r, bytes(buf)
        raise Refused("more than 10 redirects")

    def get(self, url: str, headers: dict | None = None, params: dict | None = None) -> Response:
        last_err = None
        for attempt in range(self.retries + 1):
            with self._pace:
                wait = self.pause - (time.monotonic() - self._last)
                if wait > 0:
                    time.sleep(wait)
                self._last = time.monotonic()
            t0 = datetime.now(timezone.utc)
            try:
                try:
                    r, content = self._fetch(url, headers or {}, params)
                except Refused as e:   # deliberate and deterministic: no retry
                    return Response(url, 0, None, str(e), t0, datetime.now(timezone.utc))
                t1 = datetime.now(timezone.utc)
                shown = str(r.request.url)
                if r.status_code == 200:
                    return Response(shown, 200, content, None, t0, t1, dict(r.headers))
                last_err = f"HTTP {r.status_code}: {redact(content[:200].decode('utf-8', 'replace'))}"
                if r.status_code in (429, 500, 502, 503, 504) and attempt < self.retries:
                    time.sleep(min(300, 10 * 2 ** attempt))
                    continue
                return Response(shown, r.status_code, None, last_err, t0, t1, dict(r.headers))
            except httpx.HTTPError as e:   # transport failure
                last_err = redact(f"{type(e).__name__}: {e}")
                if attempt < self.retries:
                    time.sleep(10 * 2 ** attempt)
                    continue
                return Response(url, 0, None, last_err, t0, datetime.now(timezone.utc))
        return Response(url, 0, None, last_err, datetime.now(timezone.utc), datetime.now(timezone.utc))
