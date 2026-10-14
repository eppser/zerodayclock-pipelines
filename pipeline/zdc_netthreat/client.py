"""One HTTP client for every source. Credentials go in headers, never in the URL.

Every request yields a Response, success or not: a run that got nothing must record
that it got nothing and why (CLAUDE.md, reproducibility contract).
"""

from __future__ import annotations

import hashlib
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

import httpx

UA = "zerodayclock.com research (https://zerodayclock.com)"
_SECRET = re.compile(r"(?i)(x-api-key|authorization|bearer|api[_-]?key|token|x-auth-key)[\"':= ]+[A-Za-z0-9._~+/=-]{8,}")


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
                r = self._c.get(url, headers=headers or {}, params=params)
                t1 = datetime.now(timezone.utc)
                shown = str(r.request.url)
                if r.status_code == 200:
                    return Response(shown, 200, r.content, None, t0, t1, dict(r.headers))
                last_err = f"HTTP {r.status_code}: {redact(r.text[:200])}"
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
