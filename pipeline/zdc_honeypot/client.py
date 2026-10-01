"""Signed client for Shadowserver's api2.

Auth is HMAC-SHA256 of the exact request body, keyed on the shared secret, sent in the
``HMAC2`` header. The apikey travels inside the body, so the signature covers it.

Two contract facts, both measured against the live API on 2026-09-01 and both load-bearing:

  * ``date`` accepts ONE day. A range ("2026-08-28:2026-08-30") returns HTTP 400
    "validation failed", so a backfill is one request per day and must be throttled.
  * A day returns ~677 rows (~250 KB). There is no pagination parameter on this method
    and no observed truncation, but `honeypot_day_not_truncated` in evals.py watches for
    a suspiciously round row count in case a cap is introduced later.
"""

from __future__ import annotations

import gzip
import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import date

API_ROOT = "https://transform.shadowserver.org/api2/"
METHOD = "honeypot/exploited-vulnerabilities"

# Shadowserver is a non-profit that charges nothing. Identify ourselves, stay slow, and
# never run concurrent requests: politeness is a condition of keeping this access.
USER_AGENT = "zerodayclock.com research (sergej.epp@zerodayclock.com)"
MIN_INTERVAL_SECONDS = 1.5

_last_call = 0.0


class ShadowserverError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class FetchResult:
    url: str
    http_status: int | None
    ok: bool
    body: bytes | None
    content_hash: str | None
    error: str | None
    duration_ms: int


def _credentials() -> tuple[str, str]:
    key = os.environ.get("SHADOWSERVER_API_KEY")
    secret = os.environ.get("SHADOWSERVER_API_SECRET")
    if not key or not secret:
        raise ShadowserverError(
            "SHADOWSERVER_API_KEY and SHADOWSERVER_API_SECRET must be set")
    return key, secret


def fetch_day(day: date, *, timeout: int = 90, retries: int = 3) -> FetchResult:
    """Fetch one day. Retries transient failures; never retries a 4xx."""
    global _last_call
    key, secret = _credentials()
    body = json.dumps({"apikey": key, "date": day.isoformat()}).encode()
    mac = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    url = API_ROOT + METHOD
    last_error = None
    for attempt in range(1, retries + 1):
        wait = MIN_INTERVAL_SECONDS - (time.monotonic() - _last_call)
        if wait > 0:
            time.sleep(wait)
        started = time.monotonic()
        req = urllib.request.Request(
            url, data=body, headers={"HMAC2": mac, "User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = resp.read()
                _last_call = time.monotonic()
                return FetchResult(
                    url=url, http_status=resp.status, ok=True, body=payload,
                    content_hash=hashlib.sha256(payload).hexdigest(), error=None,
                    duration_ms=int((time.monotonic() - started) * 1000))
        except urllib.error.HTTPError as exc:
            _last_call = time.monotonic()
            detail = exc.read()[:300].decode(errors="replace")
            last_error = f"HTTP {exc.code}: {detail}"
            # A 4xx is our fault or a contract change. Retrying cannot fix it and
            # hammering a non-profit's API with a bad request is exactly what gets
            # access withdrawn.
            if 400 <= exc.code < 500 and exc.code != 429:
                return FetchResult(url, exc.code, False, None, None, last_error,
                                   int((time.monotonic() - started) * 1000))
        except Exception as exc:  # noqa: BLE001
            _last_call = time.monotonic()
            last_error = f"{type(exc).__name__}: {exc}"
        if attempt < retries:
            time.sleep(min(2 ** attempt, 30))
    return FetchResult(url, None, False, None, None, last_error, 0)


def gzip_payload(body: bytes) -> bytes:
    return gzip.compress(body)
