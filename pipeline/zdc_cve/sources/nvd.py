"""NVD API 2.0 — the analysis layer on top of the CNA record.

NVD is not a second copy of the CVE Project. It adds `vulnStatus`, NIST-assigned CVSS
and CPE configurations, and it publishes **later** than the CNA and sometimes scores
differently. Those columns are therefore kept separate from the CNA's — see
migration 0009.

Measured 2026-08-28: **384,191 CVEs**.

Efficiency
----------
* `resultsPerPage` caps at 2000, so a full sweep is ~193 requests.
* Incremental uses `lastModStartDate` / `lastModEndDate`. NVD rejects a span wider than
  **120 days**, so a long gap is walked in chunks rather than requested in one go.
* Rate limit is 50 requests per 30s with an API key, 5 without. The client is
  configured from whether a key is present, so an unkeyed run slows down rather than
  getting itself throttled or blocked.

Two failure modes this adapter refuses to paper over
----------------------------------------------------
* A page whose `totalResults` implies more pages than we fetched means the sweep is
  incomplete; it is reported rather than treated as the whole corpus.
* NVD answers 200 with an empty `vulnerabilities` array for a window with no changes.
  That is legitimately "nothing changed" — but only when the window was valid, so the
  window is always recorded on the fetch row.
"""

from __future__ import annotations

import json
import os
from datetime import date, datetime, timedelta, timezone

from ..models import CveCollectResult, CveRecord, NormalisationError, clamp, parse_timestamp
from .base import CveSource, CveSourceState, register

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE = 2000
#: NVD rejects lastMod spans wider than 120 days.
MAX_SPAN_DAYS = 110
#: Re-read a little before the last success: NVD back-dates lastModified on occasion,
#: and an exactly-abutting window would lose those.
OVERLAP_HOURS = 6
MAX_PAGES = 400          # runaway guard; a full sweep is ~193


@register
class Nvd(CveSource):
    source_id = "nvd"
    requires_credential = True
    credential_env = "NVD_API_KEY"

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key if api_key is not None else os.environ.get("NVD_API_KEY", "")
        # 50 req/30s with a key, 5 req/30s without. Stay under either.
        self.rate_per_minute = 80 if self.api_key else 8

    def headers(self) -> dict[str, str]:
        return {"apiKey": self.api_key} if self.api_key else {}

    def collect(self, client, state: CveSourceState, mode: str,
                *, today: date | None = None) -> CveCollectResult:
        result = CveCollectResult(source_id=self.source_id)
        if not self.api_key:
            # Not fatal — NVD allows unkeyed access — but it must be visible, because
            # an unkeyed full sweep takes ten times as long.
            result.covered.append("no NVD_API_KEY: running at the unauthenticated rate limit")

        now = datetime.now(timezone.utc)
        # last_success_at is only the fallback for a database written before the
        # cursor existed; once a cursor is recorded it is authoritative.
        resume = _parse_cursor(state.cursor) or state.last_success_at
        if mode == "full" or resume is None:
            out = self._sweep(client, result, params={}, label="full corpus", full=True)
            if not out.error:
                out.cursor = now.isoformat()
            return out

        # Resume from the end of the last window that was FULLY ingested, never from
        # when the last ok fetch started: a run whose second page fails still has an
        # ok first page, and resuming from it would skip the window that failed.
        start = resume - timedelta(hours=OVERLAP_HOURS)
        windows = _chunk(start, now)
        for w_start, w_end in windows:
            sub = self._sweep(
                client, result,
                params={"lastModStartDate": _fmt(w_start), "lastModEndDate": _fmt(w_end)},
                label=f"{w_start.date()}..{w_end.date()}", full=False,
            )
            if sub.error:
                return sub      # cursor stays at the last window that completed
            result.cursor = w_end.isoformat()
        return result

    def _sweep(self, client, result: CveCollectResult, params: dict, label: str,
               full: bool) -> CveCollectResult:
        start_index, total = 0, None
        seen: dict[str, CveRecord] = {}

        for page in range(MAX_PAGES):
            fetch = client.get(API, request_mode="full" if full else "incremental",
                               params={**params, "resultsPerPage": PAGE,
                                       "startIndex": start_index})
            result.fetches.append(fetch)
            if not fetch.ok:
                result.error = f"{label} @ startIndex={start_index}: {fetch.error}"
                return result
            try:
                payload = json.loads(fetch.body)
            except (json.JSONDecodeError, TypeError) as exc:
                result.error = f"{label}: unparseable response: {exc}"
                fetch.ok = False
                fetch.error = result.error
                return result

            total = payload.get("totalResults", 0)
            items = payload.get("vulnerabilities") or []
            fetch.record_count = len(items)
            # Bodies are ~10MB each and there are up to 193 of them; the parsed records
            # are what matter and the fetch row still carries url, status and hash.
            fetch.body = None

            for item in items:
                record = _to_record((item or {}).get("cve") or {})
                if record is not None:
                    seen[record.cve_id] = record

            start_index += len(items)
            if not items or start_index >= total:
                break
        else:
            result.error = f"{label}: exceeded {MAX_PAGES} pages; refusing to loop"
            return result

        if total is not None and start_index < total:
            result.error = (f"{label}: fetched {start_index} of {total} results; "
                            "the sweep is incomplete")
            return result

        result.records.extend(seen.values())
        result.covered.append(f"{label} ({total} results)")
        if full:
            result.complete_snapshot = True
        return result


def _parse_cursor(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _fmt(dt: datetime) -> str:
    """ISO-8601 with a 'Z' suffix.

    strftime's %z renders '+0000' with no colon, which NVD rejects with a bare HTTP
    404 and an empty body — indistinguishable from "endpoint not found" unless you
    test the formats side by side. Measured 2026-08-28: '...000Z' and '...000+00:00'
    both return 200; '...000+0000' returns 404.
    """
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _chunk(start: datetime, end: datetime) -> list[tuple[datetime, datetime]]:
    """Split a span into windows NVD will accept (it rejects > 120 days)."""
    windows, cursor = [], start
    while cursor < end:
        stop = min(cursor + timedelta(days=MAX_SPAN_DAYS), end)
        windows.append((cursor, stop))
        cursor = stop
    return windows or [(start, end)]


def _to_record(cve: dict) -> CveRecord | None:
    cve_id = (cve.get("id") or "").strip().upper()
    if not cve_id:
        return None

    version = score = vector = None
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        primary = next((e for e in entries if e.get("type") == "Primary"), None) or \
                  (entries[0] if entries else None)
        if primary:
            data = primary.get("cvssData") or {}
            if data.get("baseScore") is not None:
                version = data.get("version")
                score = float(data["baseScore"])
                vector = data.get("vectorString")
                break

    cwes = []
    for weakness in cve.get("weaknesses") or []:
        for d in (weakness.get("description") or []) if isinstance(weakness, dict) else []:
            value = d.get("value") if isinstance(d, dict) else None
            if value and value.upper().startswith("CWE-"):
                cwes.append(value)

    try:
        return CveRecord(
            cve_id=cve_id,
            source="nvd",
            nvd_published=parse_timestamp(cve.get("published")),
            nvd_last_modified=parse_timestamp(cve.get("lastModified")),
            vuln_status=cve.get("vulnStatus"),
            nvd_cvss_version=str(version) if version else None,
            nvd_cvss_score=score,
            nvd_cvss_vector=vector,
            cwe_ids=clamp(cwes),
        )
    except NormalisationError:
        return None
