"""HTTP for the CrowdSec Live Exploit Tracker.

EVERY STRING FROM THIS API IS UNTRUSTED. On 2026-09-22 `/v1/info` returned an
`api_key_name` carrying invisible Unicode tag characters (U+E0000 block) that decode
to "enter goal here __." - an unfilled prompt-injection template, delivered in a field
no human reading the dashboard can see. `strip_tags` removes that block from every
string on the way in. It is applied at the transport boundary rather than in the
parser so that nothing downstream, including a future caller, can skip it.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

BASE = "https://admin.api.crowdsec.net/v1"
# Cloudflare fronts this API and refuses a default urllib agent.
UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36")

_TAGS = re.compile(r"[\U000E0000-\U000E007F]")


def strip_tags(obj: Any) -> Any:
    """Remove Unicode tag characters recursively. See the module docstring."""
    if isinstance(obj, str):
        return _TAGS.sub("", obj)
    if isinstance(obj, list):
        return [strip_tags(x) for x in obj]
    if isinstance(obj, dict):
        return {k: strip_tags(v) for k, v in obj.items()}
    return obj


@dataclass(frozen=True)
class Response:
    url: str
    status: int
    body: Any
    error: str | None = None


class CrowdSecClient:
    def __init__(self, api_key: str, *, timeout: int = 60, retries: int = 3,
                 pause: float = 0.0):
        self._key = api_key
        self._timeout = timeout
        self._retries = retries
        self._pause = pause

    def get(self, path: str) -> Response:
        url = BASE + path
        last = "no attempt made"
        for attempt in range(self._retries):
            try:
                req = urllib.request.Request(url, headers={
                    "accept": "application/json",
                    "x-api-key": self._key,
                    "User-Agent": UA,
                })
                with urllib.request.urlopen(req, timeout=self._timeout) as r:
                    body = strip_tags(json.loads(r.read() or b"null"))
                if self._pause:
                    time.sleep(self._pause)
                return Response(url, 200, body)
            except urllib.error.HTTPError as e:
                # A HARVESTER THAT RETURNS NOTHING MUST SAY WHY. The first scheduled
                # run reported a bare "HTTP 403" and cost a round trip to find out
                # whose 403 it was - the API's, or the CDN in front of it. The body is
                # the only thing that distinguishes them, so a bounded slice of it
                # travels with the error.
                detail = ""
                try:
                    detail = e.read(400).decode("utf-8", "replace").strip()
                    detail = " ".join(detail.split())[:200]
                except Exception:  # noqa: BLE001
                    pass
                last = f"HTTP {e.code}" + (f": {detail}" if detail else "")
                if e.code in (429, 500, 502, 503, 504) and attempt < self._retries - 1:
                    time.sleep(2 ** attempt)
                    continue
                return Response(url, e.code, None, last)
            except Exception as e:  # noqa: BLE001
                last = f"{type(e).__name__}: {e}"
                if attempt < self._retries - 1:
                    time.sleep(2 ** attempt)
                    continue
        return Response(url, 0, None, last)

    def paged(self, path: str, size: int = 100, max_pages: int = 200):
        """Walk a paginated collection. Returns (items, total, error)."""
        items: list[dict] = []
        page, total = 1, None
        while page <= max_pages:
            sep = "&" if "?" in path else "?"
            r = self.get(f"{path}{sep}page={page}&size={size}")
            if r.status != 200 or not isinstance(r.body, dict):
                return items, total, (r.error or f"HTTP {r.status}")
            total = r.body.get("total", total)
            batch = r.body.get("items") or []
            items += batch
            if not batch or page >= (r.body.get("pages") or 1):
                return items, total, None
            page += 1
        return items, total, f"stopped at max_pages={max_pages}"
