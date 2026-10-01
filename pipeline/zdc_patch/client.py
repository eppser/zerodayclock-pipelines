"""MSRC CVRF client. One document per month, JSON.

POLITENESS. Microsoft publishes one CVRF document per month and each is ~2.5 MB. The backfill
walks 2016-01 forward, one request at a time with a delay, and records every HTTP status. A run
that fetches nothing records that it fetched nothing and why: an empty result is a block or an
outage, never evidence that no patches exist.
"""
from __future__ import annotations

import logging
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import date

log = logging.getLogger("zdc_patch")

BASE = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf"
# MSRC has no Exploited flag and no CVRF documents before 2016 (see CLAUDE.md); earlier
# months return 404 rather than an empty document, so the window starts here.
FIRST_MONTH = (2016, 1)
UA = "zerodayclock.com patch-date collector (contact: https://zerodayclock.com)"


@dataclass
class Fetch:
    doc_id: str
    url: str
    status: int
    body: dict | None
    error: str | None = None


def months(start: tuple[int, int], end: date) -> list[str]:
    y, m = start
    out = []
    while (y, m) <= (end.year, end.month):
        out.append(f"{y}-{date(y, m, 1).strftime('%b')}")
        m += 1
        if m == 13:
            y, m = y + 1, 1
    return out


def fetch_month(doc_id: str, *, timeout: int = 60, delay: float = 1.5) -> Fetch:
    import json

    url = f"{BASE}/{doc_id}"
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = json.loads(r.read().decode("utf-8"))
            f = Fetch(doc_id, url, r.status, body)
    except urllib.error.HTTPError as e:
        f = Fetch(doc_id, url, e.code, None, f"HTTP {e.code}")
    except Exception as e:  # noqa: BLE001
        f = Fetch(doc_id, url, 0, None, f"{type(e).__name__}: {e}")
    time.sleep(delay)
    return f
