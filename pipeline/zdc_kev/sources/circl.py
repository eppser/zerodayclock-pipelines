"""CIRCL Vulnerability-Lookup ``kev_entries`` dump (priority 3).

The widest of the free sources, and both an aggregator *and* a KEV issuer in its own
right. Measured 2026-08-27: 5,803 entries over 2,857 distinct CVEs, issued by five
GCVE origins — kevintel (2,766), cisa-kev (1,683), shadowserver (1,290),
enisa-cnw-kev (43) and **CIRCL itself (21)**.

Those 21 matter out of proportion to their count: 3 appear nowhere else in the dump,
including two GCVE-namespaced ids (``GCVE-1-2026-0020``, ``GCVE-1-2026-20208``) that
have no CVE at all. Treating CIRCL as a mere pipe would silently drop vulnerabilities
that no other source has.

**Issuer and evidence are separate fields.** ``gcve.origin_uuid`` identifies who issued
the entry; ``evidence[].source`` is only what they cite. An entry issued by CIRCL citing
a Check Point report is ONE observation by CIRCL, not two — conflating them inflates
agreement and corrupts coverage estimation. ``core.upstream_canonical`` then folds
issuers that republish another source (CIRCL's ``cisa-kev``, ``enisa-cnw-kev``) back
onto the observer they copy, so our own CISA fetch is not double-counted.

Transport choice is deliberate. CIRCL's published API policy says: *"Do not enumerate
the API to mirror the dataset"*, with a 20 req/min anonymous limit. So we take the
single 9.6MB ``kev_entries.ndjson`` dump under a conditional GET — one request per run
instead of thousands. Never touch ``sightings.ndjson``: it is 2.3GB.
"""

from __future__ import annotations

import json
from datetime import date

from ..models import CollectResult, KevObservation, extract_cve, parse_date, parse_timestamp
from .base import KevSource, SourceState, register

DUMP_URL = "https://vulnerability.circl.lu/dumps/kev_entries.ndjson"

# CIRCL's evidence.signal vocabulary -> our normalised scale. Anything unrecognised
# becomes 'unspecified' rather than being guessed upward: over-stating the strength of
# an exploitation claim is the one error that directly inflates the headline.
#: Evidence types that are SENSOR TELEMETRY, not catalogue listings. CIRCL's
#: kev_entries dump passes Shadowserver honeypot data through in the same shape as a
#: real catalogue entry. Ingesting it here would merge an observation with a listing —
#: the one thing this project never does — and it double-counts a sensor we already
#: ingest properly in obs_core. Measured 2026-09-01: 1,290 honeypot rows, 94% of which
#: duplicated CVEs already present in obs_core.exploitation_observations.
TELEMETRY_EVIDENCE = {"honeypot", "sinkhole"}

SIGNAL_MAP = {
    "confirmed_compromise": "confirmed_compromise",
    "successful_exploitation": "successful_exploitation",
    "in_the_wild_attempts": "in_the_wild_attempts",
}

#: GCVE origin uuid -> the authority that ISSUED the entry.
#:
#: This is the authoritative identity of the issuer: feed names get renamed, uuids do
#: not. Derived empirically from the 2026-08-27 dump, and CIRCL's own uuid is confirmed
#: against ``instance.uuid`` in its published api-policy.json.
#:
#: Must stay in sync with core.kev_origins (migration 0005) — tests assert that, by
#: parsing the migration rather than trusting a comment.
ORIGIN_ISSUERS = {
    "caeb2787-0d58-4236-9039-7c86c3e566f3": "kevintel",
    "405284c2-e461-4670-8979-7fd2c9755a60": "cisa-kev",
    "c8fb6bf1-f81f-4cb8-95b1-eadbb3b54ee8": "shadowserver",
    "cce329bf-df49-4c6e-a027-80be2e6483bd": "enisa-cnw-kev",
    "1a89b78e-f703-45f3-bb86-59eb712668bd": "circl",
}


@register
class CirclKev(KevSource):
    source_id = "circl"
    rate_per_minute = 15  # policy allows 20/min anonymous; stay under it

    def collect(self, client, state: SourceState, mode: str, *, today: date | None = None) -> CollectResult:
        result = CollectResult(source_id=self.source_id)
        fetch = client.get(
            DUMP_URL,
            request_mode="conditional",
            etag=state.last_etag,
            last_modified=state.last_modified,
            expect_json=False,
        )
        result.fetches.append(fetch)

        if not fetch.ok:
            result.error = fetch.error
            return result

        if fetch.not_modified or (
            fetch.content_hash and fetch.content_hash == state.last_content_hash
        ):
            result.unchanged = True
            fetch.record_count = 0
            return result

        bad_lines = 0
        for line in (fetch.body or b"").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                bad_lines += 1
                continue
            result.observations.extend(_explode(entry))

        fetch.record_count = len(result.observations)
        result.complete_snapshot = True

        if bad_lines:
            # Surfaced, not swallowed: a partially corrupt dump is a data-quality event.
            result.error = f"{bad_lines} unparseable NDJSON line(s) in CIRCL dump"
        return result


def _explode(entry: dict) -> list[KevObservation]:
    """One CIRCL entry -> one observation per evidence source."""
    uuid = (entry.get("uuid") or "").strip()
    if not uuid:
        return []

    vulnerability = entry.get("vulnerability") or {}
    native_id = (vulnerability.get("vulnId") or "").strip()
    if not native_id:
        return []

    alt_ids = vulnerability.get("altId") or []
    aliases = tuple(str(a).strip().upper() for a in alt_ids if str(a).strip())
    cve_id = extract_cve(native_id, aliases)
    vuln_id, vuln_id_type = KevSource.primary_id(cve_id, native_id.upper())

    status = entry.get("status") or {}
    gcve = entry.get("gcve") or {}
    origin_uuid = (gcve.get("origin_uuid") or "").strip() or None
    timestamps = entry.get("timestamps") or {}
    scope = entry.get("scope") or {}
    references = tuple(
        str(r.get("url")).strip()
        for r in (entry.get("references") or [])
        if isinstance(r, dict) and str(r.get("url", "")).startswith("http")
    )

    status_reason = status.get("status_reason")
    if status_reason not in ("confirmed", "suspected"):
        status_reason = None

    asserted = parse_date(timestamps.get("asserted_at"))
    first_seen = parse_date(timestamps.get("first_seen_at"))

    evidence_list = entry.get("evidence") or []
    if not evidence_list:
        # Entries with no evidence block do exist and are mostly CIRCL's own KEV
        # entries (13 of 21 measured). Keep them — dropping them would silently shrink
        # the catalogue and lose vulnerabilities that appear in no other source.
        evidence_list = [{"source": None, "signal": None, "confidence": None, "details": {}}]

    observations: list[KevObservation] = []
    for index, evidence in enumerate(evidence_list):
        if not isinstance(evidence, dict):
            continue
        evidence_type = (evidence.get("type") or "").strip().lower() or None
        if evidence_type in TELEMETRY_EVIDENCE:
            # A sensor saw an attempt. That is an observation, not a catalogue listing,
            # and obs_core is where it belongs. Skipping it here is what keeps the two
            # claims separate.
            continue
        evidence_source = (evidence.get("source") or "").strip() or None
        # The ISSUER is who authored the entry, resolved from the GCVE origin. The
        # evidence source is only what they cite. Conflating the two would credit a
        # CIRCL entry citing a Check Point report as two independent observations —
        # and would hide that CIRCL issues KEV entries of its own.
        upstream = ORIGIN_ISSUERS.get(origin_uuid or "")
        if not upstream:
            # Unknown origin: fall back to the citation so nothing is lost, and let the
            # unmapped_origins eval flag it for review.
            upstream = (evidence_source or "circl").lower()
        details = evidence.get("details") or {}
        confidence = evidence.get("confidence")
        try:
            confidence = float(confidence) if confidence is not None else None
        except (TypeError, ValueError):
            confidence = None
        if confidence is not None:
            confidence = min(max(confidence, 0.0), 1.0)

        observations.append(
            KevObservation(
                source_id="circl",
                upstream_source=upstream,
                evidence_source=evidence_source,
                evidence_type=evidence_type,
                origin_uuid=origin_uuid,
                # Index-suffixed so two evidence blocks from the same feed stay distinct
                # and the identity is stable across runs.
                source_entry_id=f"{uuid}#{index}",
                vuln_id=vuln_id,
                vuln_id_type=vuln_id_type,
                cve_id=cve_id,
                aliases=aliases,
                exploited=bool(status.get("exploited", True)),
                signal=SIGNAL_MAP.get(evidence.get("signal"), "unspecified"),
                status_reason=status_reason,
                confidence=confidence,
                ransomware_use=details.get("knownRansomwareCampaignUse"),
                date_added=parse_date(details.get("date_added")) or asserted,
                exploited_since=first_seen,
                due_date=parse_date(details.get("due_date")),
                source_published=parse_timestamp(timestamps.get("asserted_at")),
                source_updated=parse_timestamp(timestamps.get("recorded_at"))
                or parse_timestamp(status.get("status_updated_at")),
                vendor_project=details.get("vendorProject"),
                product=details.get("product"),
                vulnerability_name=details.get("vulnerabilityName"),
                short_description=scope.get("notes"),
                reference_urls=references,
                raw={"uuid": uuid, "evidence_index": index, **entry},
            )
        )
    return observations
