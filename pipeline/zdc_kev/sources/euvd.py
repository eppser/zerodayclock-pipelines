"""ENISA EU Vulnerability Database — exploited slice (priority 2).

``/api/search?exploited=true`` is paginated as ``{"items": [...], "total": N}``.
Measured 2026-08-27: total 1,689. ``/api/exploitedvulnerabilities`` looks like the
obvious endpoint but returns only 4 records — a "recent" teaser, not the catalogue.

Two normalisation hazards, both handled below:

* The primary id is ``EUVD-YYYY-NNNNN``; the CVE arrives inside a newline-separated
  ``aliases`` string and is sometimes absent entirely.
* Dates are US-format strings with **no timezone** ("Jul 29, 2025, 11:29:31 PM").
  They are parsed as UTC, which is an assumption, and it is recorded here rather than
  buried in a date parser.

EUVD is the only one of the four that publishes ``exploitedSince``, which is a
materially better exploitation-date estimate than "when the catalogue added it".
"""

from __future__ import annotations

import json
from datetime import date

from ..models import CollectResult, KevObservation, extract_cve, parse_date, parse_timestamp
from .base import KevSource, SourceState, register

SEARCH_URL = "https://euvdservices.enisa.europa.eu/api/search"
PAGE_SIZE = 100
MAX_PAGES = 400  # runaway guard; 1,689 entries is ~17 pages


@register
class EuvdKev(KevSource):
    source_id = "euvd"
    rate_per_minute = 60

    def collect(self, client, state: SourceState, mode: str, *, today: date | None = None) -> CollectResult:
        result = CollectResult(source_id=self.source_id)
        seen: set[str] = set()
        total: int | None = None
        page = 0

        while page < MAX_PAGES:
            fetch = client.get(
                SEARCH_URL,
                request_mode="full",
                params={"exploited": "true", "size": PAGE_SIZE, "page": page},
            )
            result.fetches.append(fetch)
            if not fetch.ok:
                # Partial catalogue: keep what we have but refuse to reconcile
                # withdrawals from an incomplete view.
                result.error = f"page {page}: {fetch.error}"
                return result

            try:
                payload = json.loads(fetch.body)
            except (json.JSONDecodeError, TypeError) as exc:
                result.error = f"page {page} unparseable: {exc}"
                fetch.ok = False
                fetch.error = result.error
                return result

            items = payload.get("items") or []
            if total is None:
                total = payload.get("total")
            fetch.record_count = len(items)

            for item in items:
                observation = _to_observation(item)
                if observation is None or observation.source_entry_id in seen:
                    continue
                seen.add(observation.source_entry_id)
                result.observations.append(observation)

            if not items:
                break
            if total is not None and len(seen) >= total:
                break
            page += 1

        if total is not None and len(seen) < total:
            # Say so loudly rather than publishing a quietly short catalogue.
            result.error = f"incomplete pagination: collected {len(seen)} of {total}"
            return result

        result.complete_snapshot = True
        return result


def _to_observation(item: dict) -> KevObservation | None:
    native_id = (item.get("id") or "").strip()
    if not native_id:
        return None

    aliases = tuple(
        part.strip()
        for part in str(item.get("aliases") or "").splitlines()
        if part.strip()
    )
    cve_id = extract_cve(aliases, item.get("id"))
    vuln_id, vuln_id_type = KevSource.primary_id(cve_id, native_id)

    return KevObservation(
        source_id="euvd",
        upstream_source="euvd",
        source_entry_id=native_id,
        vuln_id=vuln_id,
        vuln_id_type=vuln_id_type,
        cve_id=cve_id,
        aliases=aliases,
        # EUVD flags exploitation but publishes no strength-of-evidence gradation and
        # no confidence score, so confidence stays None rather than being invented.
        signal="successful_exploitation",
        status_reason="confirmed",
        confidence=None,
        exploited_since=parse_date(item.get("exploitedSince")),
        source_published=parse_timestamp(item.get("datePublished")),
        source_updated=parse_timestamp(item.get("dateUpdated")),
        vendor_project=item.get("assigner"),
        short_description=item.get("description"),
        reference_urls=_split_references(item.get("references")),
        raw=item,
    )


def _split_references(value: object) -> tuple[str, ...]:
    if not value:
        return ()
    urls = [part.strip() for part in str(value).replace(",", "\n").splitlines()]
    return tuple(dict.fromkeys(u for u in urls if u.startswith("http")))
