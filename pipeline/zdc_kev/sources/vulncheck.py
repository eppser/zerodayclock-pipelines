"""VulnCheck KEV (priority 4).

Measured 2026-08-27: 5,185 documents against CISA's 1,682 — the broadest single-vendor
KEV available to us, and it carries per-report exploitation URLs with their own dates,
which is a better exploitation-date estimate than catalogue-add date.

**The paging cap is a correctness trap, not a performance detail.** The index API
reports ``max_pages: 6``; a window wider than 6 pages is silently truncated and the
run would look successful while dropping records. So: incremental pulls page the index
and *escalate to the full backup snapshot* the moment they hit the cap, and full syncs
go straight to ``/v3/backup/vulncheck-kev`` (a signed ZIP of the whole index).

Note on identity: the ``cve`` field is a *list*. An entry covering three CVEs becomes
three observations, one per CVE, all sharing a ``source_entry_id`` suffix so they stay
distinguishable and stable.
"""

from __future__ import annotations

import io
import json
import zipfile
from datetime import date, timedelta

from ..models import (CVE_RE, CollectResult, KevObservation, NormalisationError,
                      parse_date, parse_timestamp)
from .base import KevSource, SourceState, register

INDEX_URL = "https://api.vulncheck.com/v3/index/vulncheck-kev"
BACKUP_URL = "https://api.vulncheck.com/v3/backup/vulncheck-kev"
PAGE_LIMIT = 200
MAX_PAGES = 6  # imposed by the API; exceeding it truncates silently
# Re-fetch a few days before the last success: sources back-date entries, and an
# exactly-abutting window loses anything added late for a prior day.
OVERLAP_DAYS = 3


@register
class VulnCheckKev(KevSource):
    source_id = "vulncheck"
    rate_per_minute = 60
    requires_credential = True
    credential_env = "VULNCHECK_API_TOKEN"

    def __init__(self, token: str | None = None) -> None:
        import os

        self.token = token or os.environ.get(self.credential_env or "", "")

    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    def collect(self, client, state: SourceState, mode: str, *, today: date | None = None) -> CollectResult:
        result = CollectResult(source_id=self.source_id)
        if not self.token:
            result.error = f"{self.credential_env} is not set"
            return result

        today = today or date.today()
        want_full = mode == "full" or state.last_success_at is None
        if not want_full and state.last_full_sync_at is not None:
            age = (today - state.last_full_sync_at.date()).days
            want_full = age >= self.full_sync_interval_days

        if want_full:
            return self._collect_full(client, result)

        since = (state.last_success_at.date() - timedelta(days=OVERLAP_DAYS))
        return self._collect_incremental(client, result, since, today)

    # -- full snapshot -------------------------------------------------------------

    def _collect_full(self, client, result: CollectResult) -> CollectResult:
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

        # Presigned URL: it authenticates itself, and S3 returns 400 if our bearer token
        # is also present ("Only one auth mechanism allowed").
        archive = client.get(url, request_mode="full", expect_json=False, no_auth=True)
        # The signed URL is single-use and enormous; do not persist its body as a raw
        # payload under a URL that cannot be re-fetched. The parsed records are what
        # matters, and the pointer fetch above records provenance.
        archive.body = archive.body if archive.ok else None
        result.fetches.append(archive)
        if not archive.ok:
            result.error = archive.error
            return result

        try:
            records = _read_backup_zip(archive.body)
        except (zipfile.BadZipFile, ValueError, json.JSONDecodeError) as exc:
            result.error = f"unreadable backup archive: {exc}"
            archive.ok = False
            archive.error = result.error
            return result
        finally:
            archive.body = None  # keep the multi-MB archive out of the raw payload store

        for record in records:
            result.observations.extend(_to_observations(record, result.skipped))
        archive.record_count = len(result.observations)
        result.complete_snapshot = True
        return result

    # -- incremental ---------------------------------------------------------------

    def _collect_incremental(self, client, result: CollectResult, since: date, today: date) -> CollectResult:
        for page in range(1, MAX_PAGES + 1):
            fetch = client.get(
                INDEX_URL,
                request_mode="incremental",
                params={
                    "lastModStartDate": since.isoformat(),
                    "limit": PAGE_LIMIT,
                    "page": page,
                },
            )
            fetch.window_start, fetch.window_end = since, today
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
            fetch.record_count = len(data)
            for record in data:
                result.observations.extend(_to_observations(record, result.skipped))

            meta = payload.get("_meta") or {}
            total_pages = meta.get("total_pages") or 1
            if page >= min(total_pages, MAX_PAGES):
                if total_pages > MAX_PAGES:
                    # Window too wide for the paging cap — anything beyond page 6 would
                    # be lost. Fall back to the complete snapshot rather than ship a
                    # truncated delta.
                    result.fetches.append(fetch)
                    result.observations.clear()
                    return self._collect_full(client, result)
                break
        return result


def _read_backup_zip(body: bytes) -> list[dict]:
    records: list[dict] = []
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        for name in archive.namelist():
            if not name.lower().endswith(".json"):
                continue
            with archive.open(name) as handle:
                payload = json.load(handle)
            if isinstance(payload, list):
                records.extend(r for r in payload if isinstance(r, dict))
            elif isinstance(payload, dict):
                data = payload.get("data")
                if isinstance(data, list):
                    records.extend(r for r in data if isinstance(r, dict))
                else:
                    records.append(payload)
    if not records:
        raise ValueError("backup archive contained no JSON records")
    return records


def _to_observations(record: dict, skipped: list[str] | None = None) -> list[KevObservation]:
    """One observation per well-formed CVE; anything else lands in `skipped`.

    `cve[]` has carried non-CVE ids (a GHSA) and placeholders; one of those used to
    raise and take the whole VulnCheck catalogue with it.
    """
    skipped = skipped if skipped is not None else []
    listed = [str(c).strip().upper() for c in (record.get("cve") or []) if str(c).strip()]
    cves = [c for c in listed if CVE_RE.fullmatch(c)]
    skipped.extend(f"{c}: not a well-formed CVE id" for c in listed if c not in cves)
    if not cves:
        return []

    date_added = parse_date(record.get("date_added"))
    reports = record.get("vulncheck_reported_exploitation") or []
    report_dates = [
        d for d in (parse_date(r.get("date_added")) for r in reports if isinstance(r, dict)) if d
    ]
    # Earliest third-party exploitation report is a tighter bound on "when exploitation
    # was known" than the date VulnCheck added the row to its catalogue.
    exploited_since = min(report_dates) if report_dates else None

    urls = tuple(
        dict.fromkeys(
            str(r.get("url")).strip()
            for r in reports
            if isinstance(r, dict) and str(r.get("url", "")).startswith("http")
        )
    )

    observations: list[KevObservation] = []
    for cve_id in cves:
        vuln_id, vuln_id_type = KevSource.primary_id(cve_id, cve_id)
        try:
            observation = KevObservation(
                source_id="vulncheck",
                upstream_source="vulncheck",
                # Suffixed by CVE: one record can cover several, and each must stay
                # independently addressable across runs.
                source_entry_id=f"{cve_id}@{date_added.isoformat() if date_added else 'unknown'}",
                vuln_id=vuln_id,
                vuln_id_type=vuln_id_type,
                cve_id=cve_id,
                # A skipped non-CVE id (a GHSA) is still a true alias; keep it here.
                aliases=tuple(c for c in listed if c != cve_id),
                signal="successful_exploitation",
                status_reason="confirmed",
                confidence=None,
                ransomware_use=record.get("knownRansomwareCampaignUse"),
                date_added=date_added,
                exploited_since=exploited_since,
                due_date=parse_date(record.get("due_date")),
                source_updated=parse_timestamp(record.get("updated_at")),
                vendor_project=record.get("vendorProject"),
                product=record.get("product"),
                vulnerability_name=record.get("vulnerabilityName"),
                short_description=record.get("shortDescription"),
                reference_urls=urls,
                raw=record,
            )
        except NormalisationError as exc:
            skipped.append(f"{cve_id}: {exc}")
            continue
        observations.append(observation)
    return observations
