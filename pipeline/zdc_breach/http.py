"""One polite HTTP GET for every breach source, with what an audit needs recorded.

No source here takes a credential, so nothing secret can reach a URL or a log. Redirects are
followed (regulator portals move pages), but only to https. Every response is sanitised at the
boundary: leak-site text and news quote attackers, and Unicode tag characters were measured
carrying a hidden prompt in another feed (zdc_crowdsec), so they never get past this module.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

from zdc_crowdsec.client import strip_tags

UA = "ZeroDayClock breach research (+https://zerodayclock.com; contact@zerodayclock.com)"


def clean(text: str) -> str:
    return strip_tags(text).replace("\x00", "")


@dataclass
class Fetched:
    url: str
    status: int                 # 0 = transport failure
    body: bytes
    error: str | None
    requested_at: datetime
    finished_at: datetime
    headers: dict

    @property
    def ok(self) -> bool:
        return self.status == 200 and self.error is None

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.body).hexdigest()

    def text(self) -> str:
        return clean(self.body.decode("utf-8", "replace"))

    def json(self):
        return json.loads(self.text())


class _HttpsOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.lower().startswith("https://"):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_HttpsOnly)


def get(url: str, *, timeout: int = 60, retries: int = 2, sleep=time.sleep,
        accept: str = "*/*", opener=None, max_bytes: int = 40_000_000) -> Fetched:
    """429 and 5xx are retried with Retry-After honoured; anything else is returned as is.
    max_bytes refuses a runaway body (one RansomLook group endpoint is 30 MB)."""
    op = opener or _OPENER
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": accept,
                                               "Accept-Encoding": "gzip"})
    started = datetime.now(timezone.utc)
    last = None
    for attempt in range(retries + 1):
        try:
            with op.open(req, timeout=timeout) as r:
                body = r.read(max_bytes + 1)
                if len(body) > max_bytes:
                    return Fetched(url, r.status, b"", f"body over {max_bytes} bytes", started,
                                   datetime.now(timezone.utc), dict(r.headers))
                if r.headers.get("Content-Encoding") == "gzip":
                    body = gzip.decompress(body)
                return Fetched(url, r.status, body, None, started, datetime.now(timezone.utc),
                               dict(r.headers))
        except urllib.error.HTTPError as e:
            last = Fetched(url, e.code, b"", f"HTTP {e.code}", started, datetime.now(timezone.utc),
                           dict(e.headers or {}))
            if e.code in (429, 500, 502, 503, 504) and attempt < retries:
                wait = e.headers.get("Retry-After") if e.headers else None
                sleep(min(int(wait), 90) if wait and wait.isdigit() else 10 * (attempt + 1))
                continue
            return last
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last = Fetched(url, 0, b"", f"{type(e).__name__}: {e}"[:300], started,
                           datetime.now(timezone.utc), {})
            if attempt < retries:
                sleep(10 * (attempt + 1))
                continue
            return last
    return last  # pragma: no cover


def post_form(url: str, form: dict, *, timeout: int = 90, accept: str = "*/*", opener=None) -> Fetched:
    """A form POST (Wikidata's query service takes long queries this way). Same recording as get()."""
    import urllib.parse
    op = opener or _OPENER
    req = urllib.request.Request(url, data=urllib.parse.urlencode(form).encode(), method="POST",
                                 headers={"User-Agent": UA, "Accept": accept,
                                          "Content-Type": "application/x-www-form-urlencoded"})
    started = datetime.now(timezone.utc)
    try:
        with op.open(req, timeout=timeout) as r:
            return Fetched(url, r.status, r.read(20_000_000), None, started, datetime.now(timezone.utc), dict(r.headers))
    except urllib.error.HTTPError as e:
        return Fetched(url, e.code, b"", f"HTTP {e.code}", started, datetime.now(timezone.utc), dict(e.headers or {}))
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return Fetched(url, 0, b"", f"{type(e).__name__}"[:200], started, datetime.now(timezone.utc), {})
