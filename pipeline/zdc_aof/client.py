"""HTTP for the two agentic-C2 sources. One request at a time, spaced, identified.

Two facts shape this module:

  SHODAN TAKES ITS KEY ONLY AS A URL PARAMETER. So the URL that was actually requested can
  never be stored, logged or raised. Every `Response.url` here is rebuilt WITHOUT the key, and
  every error string goes through `redact()` first: urllib puts the full URL in some
  exceptions, and this pipeline's logs are public.

  OFFENSIVE.AGENCY IS A FREE SERVICE RUN BY SOMEONE ELSE. Its guidance is one full download a
  day. Requests are sequential and spaced, and a 4xx is never retried.
"""

from __future__ import annotations

import hashlib
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

USER_AGENT = "zerodayclock.com research (+https://zerodayclock.com)"
OA_ROOT = "https://www.offensive.agency/api/v1/"
SHODAN_COUNT = "https://api.shodan.io/shodan/host/count"
SHODAN_INFO = "https://api.shodan.io/api-info"

_SECRETS: set[str] = set()


def register_secret(value: str) -> None:
    """Anything registered here is cut out of every string `redact()` sees."""
    if value and len(value) >= 8:
        _SECRETS.add(value)
        _SECRETS.add(urllib.parse.quote(value, safe=""))


def redact(text: str) -> str:
    for s in _SECRETS:
        text = text.replace(s, "<redacted>")
    return text


@dataclass(frozen=True, slots=True)
class Response:
    url: str                    # never carries a credential
    status: int                 # 0 = transport failure
    body: bytes | None
    error: str | None
    requested_at: datetime
    finished_at: datetime

    @property
    def content_hash(self) -> str | None:
        return hashlib.sha256(self.body).hexdigest() if self.body is not None else None


class _RefuseRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is never followed. Shodan's key is in the URL, so a `Location` to another
    host or to http would hand it over; and the row would record a URL that was not the one
    answered. A 3xx surfaces as an HTTP error and is recorded as one."""

    def redirect_request(self, *a, **k):
        return None


_OPENER = urllib.request.build_opener(_RefuseRedirect)


class Http:
    """Sequential GETs with a minimum spacing. `opener` is injectable for tests.

    `deadline_seconds` bounds the whole client, not one request: past it every call answers
    with an error instead of going out, so a slow source cannot run the job into its timeout
    with the run row left unfinished."""

    def __init__(self, min_interval: float, *, opener=None, sleep=time.sleep, timeout: int = 45,
                 retries: int = 3, deadline_seconds: float | None = None):
        self.min_interval = min_interval
        self.timeout = timeout
        self.retries = retries
        self._open = opener or _OPENER.open
        self._deadline = None if deadline_seconds is None else time.monotonic() + deadline_seconds
        self._sleep = sleep
        self._last = 0.0
        self.requests = 0

    def get(self, url: str, *, public_url: str | None = None) -> Response:
        """GET `url`; `public_url` is what gets recorded (the same URL minus any credential)."""
        shown = public_url or url
        requested = datetime.now(timezone.utc)
        error = None
        status = 0
        for attempt in range(1, self.retries + 1):
            if self._deadline is not None and time.monotonic() > self._deadline:
                error = "the run's time budget for this source is used up; request not sent"
                break
            wait = self.min_interval - (time.monotonic() - self._last)
            if wait > 0:
                self._sleep(wait)
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                                       "Accept": "application/json"})
            self.requests += 1
            try:
                with self._open(req, timeout=self.timeout) as resp:
                    body = resp.read()
                    self._last = time.monotonic()
                    return Response(shown, resp.status, body, None, requested,
                                    datetime.now(timezone.utc))
            except urllib.error.HTTPError as exc:
                self._last = time.monotonic()
                status = exc.code
                try:
                    detail = exc.read()[:200].decode(errors="replace")
                except Exception:  # noqa: BLE001 - the error body is a courtesy, not a need
                    detail = ""
                error = redact(f"HTTP {exc.code}: {detail}")
                # A 4xx is our request or our access: retrying cannot fix it. 429 and 5xx can pass.
                if exc.code < 500 and exc.code != 429:
                    break
            except Exception as exc:  # noqa: BLE001 - timeouts, resets, DNS
                self._last = time.monotonic()
                status = 0
                error = redact(f"{type(exc).__name__}: {exc}")
            if attempt < self.retries:
                self._sleep(3 * attempt)
        return Response(shown, status, None, error, requested, datetime.now(timezone.utc))


class OffensiveAgency:
    def __init__(self, http: Http, root: str = OA_ROOT):
        self.http = http
        self.root = root

    def get(self, path: str, **params) -> Response:
        """`path` is relative to the API root, or an absolute path the API handed back in
        `meta.next` (which starts with /api/v1/)."""
        if path.startswith("/"):
            url = urllib.parse.urljoin(self.root, path)
        else:
            url = self.root + path
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
        return self.http.get(url)


class Shodan:
    def __init__(self, http: Http, key: str):
        if not key:
            raise ValueError("SHODAN_API_KEY is not set")
        register_secret(key)
        self.http = http
        self._key = key

    def _call(self, base: str, params: dict[str, str]) -> Response:
        public = base + ("?" + urllib.parse.urlencode(params) if params else "")
        full = base + "?" + urllib.parse.urlencode({**params, "key": self._key})
        return self.http.get(full, public_url=public)

    def info(self) -> Response:
        return self._call(SHODAN_INFO, {})

    def count(self, query: str, facets: str = "") -> Response:
        """host/count costs no query credits on any plan (measured on the oss plan)."""
        params = {"query": query}
        if facets:
            params["facets"] = facets
        return self._call(SHODAN_COUNT, params)
