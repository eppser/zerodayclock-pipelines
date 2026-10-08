"""HTTP for OpenSourceMalware and the two registry download counters.

THE TOKEN TRAVELS IN ONE PLACE: the Authorization header of a request to the OSM API.
OSM also accepts `?apikey=` in the query string, which would put the token into every
URL this module records, logs and stores. It is never used, osm_raw.polls refuses such a
URL with a CHECK, and `redact` scrubs anything token-shaped from error text before it
can reach a log line, a run report or the database.

EVERY STRING FROM OSM IS UNTRUSTED. Records are community-submitted, and the descriptions
quote attacker payloads verbatim. `sanitize` removes Unicode tag characters (the U+E0000
block CrowdSec was measured delivering a hidden prompt-injection template in) and NUL,
which Postgres refuses in text and jsonb. It runs at the transport boundary so nothing
downstream can skip it.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from zdc_crowdsec.client import strip_tags

OSM_BASE = "https://api.opensourcemalware.com/functions/v1"
NPM_BASE = "https://api.npmjs.org/downloads/point/last-week"
PYPISTATS_BASE = "https://pypistats.org/api/packages"
UA = "zerodayclock.com data pipeline (+https://zerodayclock.com)"

_TOKEN = re.compile(r"osm_[A-Za-z0-9]{8,}")


def redact(text: str | None) -> str | None:
    if text is None:
        return None
    return _TOKEN.sub("osm_[REDACTED]", text)


def sanitize(obj: Any) -> Any:
    obj = strip_tags(obj)
    if isinstance(obj, str):
        return obj.replace("\x00", "")
    if isinstance(obj, list):
        return [sanitize(x) for x in obj]
    if isinstance(obj, dict):
        return {sanitize(k): sanitize(v) for k, v in obj.items()}
    return obj


@dataclass
class Response:
    url: str
    status: int                  # 0 = transport failure or never sent
    body: Any
    error: str | None
    requested_at: datetime
    finished_at: datetime
    headers: dict


class _RefuseRedirect(urllib.request.HTTPRedirectHandler):
    """urllib forwards request headers - Authorization included - to whatever host a
    redirect names (measured on 3.12: a 302 to another host received the Bearer token).
    The OSM API has no reason to redirect, so a 3xx is refused and becomes an error."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_NO_REDIRECT = urllib.request.build_opener(_RefuseRedirect)


def _open(req, timeout: int, follow_redirects: bool):
    if follow_redirects:
        return urllib.request.urlopen(req, timeout=timeout)
    return _NO_REDIRECT.open(req, timeout=timeout)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _get(url: str, headers: dict, *, timeout: int, retries: int,
         sleep=time.sleep, follow_redirects: bool = True) -> Response:
    """GET with bounded retries on 429/5xx/transport, honouring Retry-After."""
    t0 = _now()
    last = "no attempt made"
    status = 0
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=headers)
            with _open(req, timeout, follow_redirects) as r:
                raw = r.read()
                hdrs = {k.lower(): v for k, v in r.headers.items()}
            try:
                body = sanitize(json.loads(raw or b"null"))
            except ValueError:
                # A CDN or WAF answering 200 with HTML is a block, not an empty feed.
                snippet = " ".join(raw[:200].decode("utf-8", "replace").split())
                return Response(url, 200, None, redact(f"non-JSON body: {snippet}"),
                                t0, _now(), hdrs)
            return Response(url, 200, body, None, t0, _now(), hdrs)
        except urllib.error.HTTPError as e:
            status = e.code
            detail = ""
            try:
                detail = " ".join(e.read(400).decode("utf-8", "replace").split())[:200]
            except Exception:  # noqa: BLE001
                pass
            last = redact(f"HTTP {e.code}" + (f": {detail}" if detail else ""))
            if e.code in (429, 500, 502, 503, 504) and attempt < retries - 1:
                wait = 2 ** attempt
                ra = e.headers.get("Retry-After") if e.headers else None
                if ra and ra.strip().isdigit():
                    wait = min(int(ra), 60)
                sleep(wait)
                continue
            return Response(url, e.code, None, last, t0, _now(), {})
        except Exception as e:  # noqa: BLE001
            status = 0
            last = redact(f"{type(e).__name__}: {e}")
            if attempt < retries - 1:
                sleep(2 ** attempt)
                continue
    return Response(url, status, None, last, t0, _now(), {})


class OsmClient:
    def __init__(self, token: str, *, timeout: int = 60, retries: int = 3,
                 pause: float = 1.1, sleep=time.sleep, base: str = OSM_BASE):
        if not token or not token.startswith("osm_"):
            # Do not echo the value: a mis-set secret is often a different secret.
            raise ValueError("OSM_API_KEY is missing or does not start with osm_")
        self._token = token
        self._timeout, self._retries, self._pause = timeout, retries, pause
        self._sleep = sleep
        self._base = base

    def latest(self, ecosystem: str) -> Response:
        url = f"{self._base}/query-latest?" + urllib.parse.urlencode({"ecosystem": ecosystem})
        r = _get(url, {"Authorization": f"Bearer {self._token}", "accept": "application/json",
                       "User-Agent": UA},
                 timeout=self._timeout, retries=self._retries, sleep=self._sleep,
                 follow_redirects=False)
        # 60 req/min on the free tier; 17 ecosystems at 1.1s stays far inside it.
        if self._pause:
            self._sleep(self._pause)
        return r


# ---- registry download counters ---------------------------------------------
# Package names come from OSM records, i.e. from attackers. They go into a URL path, so
# they are validated against each registry's own naming rule first, and a name that
# fails is recorded as `invalid_name` without any request being sent.
_NPM_NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9_][a-z0-9._~-]*$", re.I)
_PYPI_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")


def valid_name(registry: str, name: str | None) -> bool:
    if not name or len(name) > 214:
        return False
    if registry == "npm":
        return bool(_NPM_NAME.match(name)) and ".." not in name
    if registry == "pypi":
        return bool(_PYPI_NAME.match(name))
    return False


def download_url(registry: str, name: str) -> str:
    if registry == "npm":
        if name.startswith("@"):
            scope, _, pkg = name.partition("/")
            return f"{NPM_BASE}/{urllib.parse.quote(scope, safe='@')}%2F{urllib.parse.quote(pkg, safe='')}"
        return f"{NPM_BASE}/{urllib.parse.quote(name, safe='')}"
    if registry == "pypi":
        return f"{PYPISTATS_BASE}/{urllib.parse.quote(name.lower(), safe='')}/recent"
    raise ValueError(f"no download counter for {registry}")


class DownloadClient:
    """npm: unauthenticated, generous. pypistats: 429s on a third request at 1s spacing
    (measured 2026-10-08), so 2s between calls and Retry-After is honoured."""

    PAUSE = {"npm": 1.5, "pypi": 2.0}

    def __init__(self, *, timeout: int = 30, retries: int = 3, sleep=time.sleep):
        self._timeout, self._retries, self._sleep = timeout, retries, sleep

    def npm_bulk(self, names: list[str]) -> Response:
        """Up to 128 UNSCOPED names in one request (scoped ones answer 400). Measured
        2026-10-08: one-by-one lookups at ~1.3s spacing drew Cloudflare 429s after ~40
        requests, so the bulk form is the polite default, not an optimisation."""
        assert names and len(names) <= 128 and not any(n.startswith("@") for n in names)
        url = f"{NPM_BASE}/" + ",".join(urllib.parse.quote(n, safe="") for n in names)
        r = _get(url, {"accept": "application/json", "User-Agent": UA},
                 timeout=self._timeout, retries=self._retries, sleep=self._sleep)
        self._sleep(self.PAUSE["npm"])
        return r

    def weekly(self, registry: str, name: str) -> Response:
        url = download_url(registry, name)
        r = _get(url, {"accept": "application/json", "User-Agent": UA},
                 timeout=self._timeout, retries=self._retries, sleep=self._sleep)
        self._sleep(self.PAUSE[registry])
        return r
