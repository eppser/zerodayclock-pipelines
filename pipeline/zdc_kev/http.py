"""Polite, self-recording HTTP client.

Two rules encoded here, both learned from v1:

1. **Every request produces a FetchRecord**, success or failure. A source that returns
   nothing must say why. v1 recorded a Cisco WAF block as 220 successful rows and the
   run "looked successful".
2. **Rate limits are respected by construction.** CIRCL publishes 20 req/min anonymous
   and asks clients to identify themselves; that is not advisory. A public scoreboard
   that gets itself IP-banned from its own sources has no data.
"""

from __future__ import annotations

import hashlib
import logging
import time
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from .models import FetchRecord

log = logging.getLogger(__name__)

# httpx logs full URLs at INFO. Signed download URLs carry AWS credentials in their
# query string, so that would print secrets to CI logs on every run.
logging.getLogger("httpx").setLevel(logging.WARNING)

#: Query parameters whose values are credentials and must never reach a log line or
#: the raw.source_fetches audit trail.
SECRET_PARAM_PREFIXES = (
    "x-amz-", "signature", "token", "apikey", "api_key", "key", "secret", "credential",
)


def redact_url(url: str) -> str:
    """Strip credential-bearing query parameters from a URL before it is recorded.

    VulnCheck's bulk download is a presigned S3 URL: it carries X-Amz-Credential,
    X-Amz-Security-Token and X-Amz-Signature in the query string. Persisting that
    verbatim would write live AWS credentials into the database and the CI log.
    """
    parts = urlsplit(url)
    if not parts.query:
        return url
    kept = [
        (k, "REDACTED" if any(k.lower().startswith(p) for p in SECRET_PARAM_PREFIXES) else v)
        for k, v in parse_qsl(parts.query, keep_blank_values=True)
    ]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(kept), parts.fragment))

USER_AGENT = (
    "ZeroDayClock/2.0 (+https://zerodayclock.com; contact: sergej.epp@zerodayclock.com) "
    "KEV-ingestion"
)

RETRY_STATUS = {429, 500, 502, 503, 504}


class RateLimiter:
    """Simple minimum-interval limiter, per client."""

    def __init__(self, per_minute: int) -> None:
        self.min_interval = 60.0 / per_minute if per_minute > 0 else 0.0
        self._last = 0.0

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        elapsed = time.monotonic() - self._last
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self._last = time.monotonic()


class PoliteClient:
    def __init__(
        self,
        source_id: str,
        *,
        per_minute: int = 30,
        timeout: float = 60.0,
        max_attempts: int = 4,
        headers: dict[str, str] | None = None,
        sleeper=time.sleep,
    ) -> None:
        self.source_id = source_id
        self.limiter = RateLimiter(per_minute)
        self.max_attempts = max_attempts
        self._sleep = sleeper
        self._client = httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT, **(headers or {})},
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> PoliteClient:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def get(
        self,
        url: str,
        *,
        request_mode: str = "full",
        etag: str | None = None,
        last_modified: str | None = None,
        params: dict | None = None,
        headers: dict[str, str] | None = None,
        expect_json: bool = True,
        no_auth: bool = False,
    ) -> FetchRecord:
        """GET a URL, returning a FetchRecord that is never silently empty.

        ``no_auth`` drops the client-level Authorization header for this request.
        Presigned URLs carry their own credentials and S3 rejects a request that
        presents two auth mechanisms with HTTP 400.
        """
        request_headers = dict(headers or {})
        if etag:
            request_headers["If-None-Match"] = etag
        if last_modified:
            request_headers["If-Modified-Since"] = last_modified

        record = FetchRecord(
            source_id=self.source_id,
            url=redact_url(str(httpx.URL(url, params=params or {}))),
            request_mode=request_mode,
        )
        started = time.monotonic()

        last_error: str | None = None
        for attempt in range(1, self.max_attempts + 1):
            record.attempt = attempt
            self.limiter.wait()
            try:
                request = self._client.build_request(
                    "GET", url, params=params, headers=request_headers
                )
                if no_auth:
                    request.headers.pop("Authorization", None)
                response = self._client.send(request, follow_redirects=True)
            except httpx.HTTPError as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                log.warning("%s attempt %d/%d failed: %s", record.url, attempt, self.max_attempts, last_error)
                if attempt < self.max_attempts:
                    self._backoff(attempt)
                    continue
                break

            record.http_status = response.status_code
            record.etag = response.headers.get("ETag")
            record.last_modified = response.headers.get("Last-Modified")

            if response.status_code == 304:
                record.ok = True
                record.not_modified = True
                record.bytes_downloaded = 0
                record.record_count = 0
                break

            if response.status_code in RETRY_STATUS and attempt < self.max_attempts:
                retry_after = response.headers.get("Retry-After")
                last_error = f"HTTP {response.status_code}"
                log.warning("%s -> %s, retrying", record.url, last_error)
                self._backoff(attempt, retry_after)
                continue

            if response.status_code >= 400:
                # A 403 after a healthy run is a block, not absence of data.
                last_error = f"HTTP {response.status_code}: {response.text[:300]}"
                break

            body = response.content
            record.body = body
            record.bytes_downloaded = len(body)
            record.content_hash = hashlib.sha256(body).hexdigest()
            record.media_type = response.headers.get("Content-Type", "application/json").split(";")[0]
            if expect_json and not body.strip():
                last_error = "empty body with HTTP 200"
                break
            record.ok = True
            break

        if not record.ok:
            record.error = last_error or "request failed with no further detail"

        record.finished_at = datetime.now(timezone.utc)
        record.duration_ms = int((time.monotonic() - started) * 1000)
        return record

    def _backoff(self, attempt: int, retry_after: str | None = None) -> None:
        if retry_after:
            try:
                self._sleep(min(float(retry_after), 60.0))
                return
            except (TypeError, ValueError):
                pass
        self._sleep(min(2.0**attempt, 30.0))
