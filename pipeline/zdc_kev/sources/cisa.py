"""CISA Known Exploited Vulnerabilities catalogue (priority 1).

One ~1.6MB JSON document. Measured 2026-08-27: 1,682 entries, serves ETag and
Last-Modified but does **not** honour If-None-Match — it returned HTTP 200 with the
full body for a matching ETag. Conditional headers are still sent (costless, and the
behaviour may change), but change detection is by content hash, which is authoritative.

Scope caveat, and it matters: this catalogue is the US federal remediation scope, not a
global census of exploitation. It is the narrowest of the four sources by a factor of
three. Iron Rule 8.
"""

from __future__ import annotations

import json
from datetime import date

from ..models import CollectResult, KevObservation, parse_date, parse_timestamp
from .base import KevSource, SourceState, register

FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


@register
class CisaKev(KevSource):
    source_id = "cisa"
    rate_per_minute = 30

    def collect(self, client, state: SourceState, mode: str, *, today: date | None = None) -> CollectResult:
        result = CollectResult(source_id=self.source_id)
        fetch = client.get(
            FEED_URL,
            request_mode="conditional",
            etag=state.last_etag,
            last_modified=state.last_modified,
        )
        result.fetches.append(fetch)

        if not fetch.ok:
            result.error = fetch.error
            return result

        if fetch.not_modified or (
            fetch.content_hash and fetch.content_hash == state.last_content_hash
        ):
            # Nothing changed upstream. Not a complete snapshot for reconciliation
            # purposes: there is no new information to reconcile against.
            result.unchanged = True
            fetch.record_count = 0
            return result

        try:
            document = json.loads(fetch.body)
        except (json.JSONDecodeError, TypeError) as exc:
            result.error = f"unparseable CISA feed: {exc}"
            fetch.ok = False
            fetch.error = result.error
            return result

        catalog_version = document.get("catalogVersion")
        released = parse_timestamp(document.get("dateReleased"))
        entries = document.get("vulnerabilities") or []

        for entry in entries:
            cve_id = (entry.get("cveID") or "").strip().upper() or None
            if not cve_id:
                continue
            vuln_id, vuln_id_type = self.primary_id(cve_id, cve_id)
            result.observations.append(
                KevObservation(
                    source_id=self.source_id,
                    upstream_source="cisa",
                    source_entry_id=cve_id,
                    vuln_id=vuln_id,
                    vuln_id_type=vuln_id_type,
                    cve_id=cve_id,
                    # CISA states these are *known* exploited, but publishes no
                    # distinction between attempted and successful exploitation, and
                    # no per-entry confidence. 0.8 mirrors the value CIRCL assigns to
                    # the same feed, so the two agree rather than silently differing.
                    signal="successful_exploitation",
                    status_reason="confirmed",
                    confidence=0.8,
                    ransomware_use=entry.get("knownRansomwareCampaignUse"),
                    date_added=parse_date(entry.get("dateAdded")),
                    due_date=parse_date(entry.get("dueDate")),
                    source_published=released,
                    vendor_project=entry.get("vendorProject"),
                    product=entry.get("product"),
                    vulnerability_name=entry.get("vulnerabilityName"),
                    short_description=entry.get("shortDescription"),
                    reference_urls=_notes_to_urls(entry.get("notes")),
                    raw={"catalogVersion": catalog_version, **entry},
                )
            )

        fetch.record_count = len(result.observations)
        # The feed is the entire catalogue every time, so absence here is a genuine
        # withdrawal and reconciliation is safe.
        result.complete_snapshot = True

        declared = document.get("count")
        if isinstance(declared, int) and declared != len(entries):
            result.error = (
                f"CISA count mismatch: envelope declares {declared}, body has {len(entries)}"
            )
        return result


def _notes_to_urls(notes: object) -> tuple[str, ...]:
    if not notes:
        return ()
    urls: list[str] = []
    for chunk in str(notes).replace(",", ";").split(";"):
        chunk = chunk.strip()
        if chunk.startswith("http"):
            urls.append(chunk)
    return tuple(dict.fromkeys(urls))
