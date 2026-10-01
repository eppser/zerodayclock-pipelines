"""VulnCheck canaries — attempt_observed.

VulnCheck runs its own honeypot sensors. When one is hit, the corresponding record in
the ``vulncheck-kev`` index carries ``reported_exploited_by_vulncheck_canaries: true``.

This is the same upstream index the KEV pipeline reads, but it is deliberately a
different pipeline making a different claim:

* KEV pipeline  -> "VulnCheck lists this vulnerability as known-exploited" (a catalogue).
* This adapter  -> "a VulnCheck sensor observed an exploitation attempt" (telemetry).

The two are stored separately and never merged. Whether they agree is a measurement.

**A canary hit is an ATTEMPT, not a compromise.** Someone aimed an exploit at a sensor.
It is evidence that the vulnerability is being actively scanned for in the wild; it is
not evidence that any real system fell over. Nothing here may be promoted to a
"successful exploitation" claim.

Measured 2026-08-27: 25 of 200 sampled index records carried the canary flag.
"""

from __future__ import annotations

import json
import os
import zipfile
from datetime import date, timedelta

from zdc_kev.sources.vulncheck import _read_backup_zip as read_backup_zip

from ..models import ExploitationObservation, ObsCollectResult, parse_date
from .base import ObservationSource, ObsSourceState, register

INDEX_URL = "https://api.vulncheck.com/v3/index/vulncheck-kev"
BACKUP_URL = "https://api.vulncheck.com/v3/backup/vulncheck-kev"
PAGE_LIMIT = 200
MAX_PAGES = 6          # API cap; beyond this the index truncates silently
OVERLAP_DAYS = 3


@register
class VulnCheckCanaries(ObservationSource):
    source_id = "vulncheck_canary"
    observation_type = "attempt_observed"
    rate_per_minute = 60
    requires_credential = True
    credential_env = "VULNCHECK_API_TOKEN"

    def __init__(self, token: str | None = None) -> None:
        self.token = token or os.environ.get(self.credential_env or "", "")

    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    def collect(self, client, state: ObsSourceState, mode: str,
                *, today: date | None = None) -> ObsCollectResult:
        result = ObsCollectResult(source_id=self.source_id)
        if not self.token:
            result.error = f"{self.credential_env} is not set"
            return result

        today = today or date.today()
        full = mode == "full" or state.last_success_at is None

        # A full sweep of the index is 26 pages against a 6-page cap (measured
        # 2026-08-27), so paging cannot see the whole canary set. The backup snapshot
        # is the only complete view; the index is used only for narrow deltas.
        if full:
            return self._collect_full(client, result)

        params: dict = {"limit": PAGE_LIMIT}
        window_start = None
        if not full:
            window_start = state.last_success_at.date() - timedelta(days=OVERLAP_DAYS)
            params["lastModStartDate"] = window_start.isoformat()

        seen: set[str] = set()
        for page in range(1, MAX_PAGES + 1):
            fetch = client.get(INDEX_URL, request_mode="full" if full else "incremental",
                               params={**params, "page": page})
            fetch.window_start, fetch.window_end = window_start, today
            result.fetches.append(fetch)
            if not fetch.ok:
                result.error = f"page {page}: {fetch.error}"
                return result

            try:
                payload = json.loads(fetch.body)
            except (json.JSONDecodeError, TypeError) as exc:
                result.error = f"page {page} unparseable: {exc}"
                fetch.ok = False
                fetch.error = result.error
                return result

            data = payload.get("data") or []
            hits = 0
            for record in data:
                for obs in _to_observations(record):
                    if obs.source_entry_id in seen:
                        continue
                    seen.add(obs.source_entry_id)
                    result.observations.append(obs)
                    hits += 1
            fetch.record_count = hits

            meta = payload.get("_meta") or {}
            total_pages = meta.get("total_pages") or 1
            if page >= min(total_pages, MAX_PAGES):
                if total_pages > MAX_PAGES:
                    # The delta window is wider than the paging cap, so anything past
                    # page 6 would be lost. Escalate to the complete snapshot rather
                    # than ship a truncated delta.
                    result.observations.clear()
                    return self._collect_full(client, result)
                break
        return result

    def _collect_full(self, client, result: ObsCollectResult) -> ObsCollectResult:
        """Complete canary set via the bulk snapshot."""
        pointer = client.get(BACKUP_URL, request_mode="full")
        result.fetches.append(pointer)
        if not pointer.ok:
            result.error = pointer.error
            return result
        try:
            url = (json.loads(pointer.body).get("data") or [{}])[0].get("url")
        except (json.JSONDecodeError, TypeError, IndexError, AttributeError) as exc:
            result.error = f"unparseable backup pointer: {exc}"
            pointer.ok = False
            pointer.error = result.error
            return result
        if not url:
            result.error = "backup pointer contained no download URL"
            return result

        # Presigned S3 URL: it carries its own credentials and returns HTTP 400 if our
        # bearer token is sent alongside ("Only one auth mechanism allowed").
        archive = client.get(url, request_mode="full", expect_json=False, no_auth=True)
        result.fetches.append(archive)
        if not archive.ok:
            result.error = archive.error
            return result
        try:
            records = read_backup_zip(archive.body)
        except (zipfile.BadZipFile, ValueError, json.JSONDecodeError) as exc:
            result.error = f"unreadable backup archive: {exc}"
            archive.ok = False
            archive.error = result.error
            return result
        finally:
            # Keep the multi-MB archive out of the raw payload store; the signed URL
            # is single-use and could never be re-fetched anyway.
            archive.body = None

        seen: set[str] = set()
        for record in records:
            for obs in _to_observations(record):
                if obs.source_entry_id in seen:
                    continue
                seen.add(obs.source_entry_id)
                result.observations.append(obs)
        archive.record_count = len(result.observations)
        result.complete_snapshot = True
        return result


def _to_observations(record: dict) -> list[ExploitationObservation]:
    if not record.get("reported_exploited_by_vulncheck_canaries"):
        return []

    cves = [str(c).strip().upper() for c in (record.get("cve") or []) if str(c).strip()]
    if not cves:
        return []

    date_added = parse_date(record.get("date_added"))
    reports = record.get("vulncheck_reported_exploitation") or []
    report_dates = [d for d in (parse_date(r.get("date_added"))
                                for r in reports if isinstance(r, dict)) if d]
    # Earliest report bounds when the attempt was first seen; the catalogue-add date is
    # a weaker upper bound and is used only as a fallback.
    observed = min(report_dates) if report_dates else date_added
    if observed is None:
        return []

    out = []
    for cve_id in cves:
        vuln_id, vuln_id_type = ObservationSource.primary_id(cve_id, cve_id)
        out.append(
            ExploitationObservation(
                source_id="vulncheck_canary",
                source_entry_id=f"{cve_id}@{observed.isoformat()}",
                observation_type="attempt_observed",
                vuln_id=vuln_id,
                vuln_id_type=vuln_id_type,
                cve_id=cve_id,
                observed_at=observed,
                first_observed_at=min(report_dates) if report_dates else None,
                last_observed_at=max(report_dates) if report_dates else None,
                # VulnCheck publishes no hit count, so this stays unknown rather than
                # being fabricated as 1.
                observation_count=None,
                vendor=record.get("vendorProject"),
                product=record.get("product"),
                title=record.get("vulnerabilityName"),
                raw=record,
            )
        )
    return out
