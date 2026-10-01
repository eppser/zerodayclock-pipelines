"""Microsoft Security Response Center — vendor_reports_exploitation.

Microsoft publishes a CVRF document per month at
``api.msrc.microsoft.com/cvrf/v3.0/cvrf/<YYYY-Mon>``. Public, no authentication.

Each vulnerability carries threat entries; ``Threats[].Type == 1`` holds a
semicolon-delimited string:

    Publicly Disclosed:No;Exploited:Yes;Latest Software Release:Exploitation Detected

Three independent facts, and only the middle one is an observation:

* ``Publicly Disclosed`` — was it public before the fix. Stored, not a signal.
* ``Exploited`` — Microsoft's determination that exploitation occurred **in the wild**.
  This is the observation, and only ``Yes`` produces a row.
* ``Latest Software Release`` — Microsoft's exploitability **forecast**
  ("Exploitation More Likely" and friends). A prediction. Stored in `vendor_forecast`
  and never treated as evidence — reading a forecast as an observation is the v1
  PoC-as-exploitation error in a new costume.

Measured 2026-08-27:

* 191 monthly documents exist, back to 1999-Sep, but **the Type-1 threat block does not
  appear before 2016** — 1999/2010/2014/2015 documents are 4-12 KB with zero Type-1
  rows. Backfill therefore starts at 2016-01; earlier fetches return nothing usable.
* Document size grows steeply: 145 KB (2016-01) to 7.2 MB (2026-08). Full 2016+
  backfill is ~130 documents and roughly 0.2 GB, not the 1.3 GB a naive extrapolation
  from a recent document suggests.
* There is no per-CVE endpoint; the monthly document is the only granularity.
* ``Exploited`` can flip No -> Yes on a later revision, so ``RevisionHistory`` dates are
  captured: "flagged at patch time" and "flagged six months later" mean very different
  things for a zero-day metric.
"""

from __future__ import annotations

import json
import re
from datetime import date, timedelta

from ..models import ExploitationObservation, ObsCollectResult, extract_cve, parse_date
from .base import ObservationSource, ObsSourceState, register

UPDATES_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
CVRF_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{doc_id}"

#: The Exploited flag does not exist in documents before this. Measured, not assumed.
EARLIEST_USEFUL_YEAR = 2016
#: Threat entry type carrying the exploit-status string.
EXPLOIT_STATUS_TYPE = 1
#: Incremental runs re-read the trailing months, because Microsoft revises documents
#: in place and a CVE can gain Exploited:Yes weeks after first publication.
INCREMENTAL_MONTHS = 3

FIELD_RE = re.compile(r"(?P<key>[^;:]+):(?P<value>[^;]*)")


@register
class MsrcObservations(ObservationSource):
    source_id = "msrc"
    observation_type = "vendor_reports_exploitation"
    rate_per_minute = 30

    def headers(self) -> dict[str, str]:
        return {"Accept": "application/json"}

    def collect(self, client, state: ObsSourceState, mode: str,
                *, today: date | None = None) -> ObsCollectResult:
        result = ObsCollectResult(source_id=self.source_id)
        today = today or date.today()

        index = client.get(UPDATES_URL, request_mode="full")
        result.fetches.append(index)
        if not index.ok:
            result.error = index.error
            return result

        try:
            documents = json.loads(index.body).get("value") or []
        except (json.JSONDecodeError, TypeError) as exc:
            result.error = f"unparseable updates index: {exc}"
            index.ok = False
            index.error = result.error
            return result

        wanted = _select_documents(documents, mode, today)
        if not wanted:
            result.error = "updates index contained no usable documents"
            return result

        index.record_count = len(wanted)
        failures = 0
        for doc_id in wanted:
            fetch = client.get(CVRF_URL.format(doc_id=doc_id), request_mode="full")
            result.fetches.append(fetch)
            if not fetch.ok:
                # One bad month must not discard the other 129.
                failures += 1
                continue
            try:
                document = json.loads(fetch.body)
            except (json.JSONDecodeError, TypeError):
                failures += 1
                fetch.ok = False
                fetch.error = "unparseable CVRF document"
                continue
            # The monthly documents are multi-megabyte and there are ~130 of them.
            # Keeping every body in memory for the raw store would cost gigabytes for
            # no benefit: the parsed observations are what matter, and the fetch row
            # still records url, status, hash and size.
            fetch.body = None
            observations = _parse_document(doc_id, document)
            fetch.record_count = len(observations)
            result.observations.extend(observations)

        if failures:
            result.error = f"{failures} of {len(wanted)} CVRF documents failed"
        else:
            # Only a clean full sweep is a complete snapshot.
            result.complete_snapshot = mode == "full"
        return result


def _select_documents(documents: list[dict], mode: str, today: date) -> list[str]:
    """Which monthly documents to fetch."""
    usable = []
    for doc in documents:
        doc_id = (doc.get("ID") or "").strip()
        released = parse_date(doc.get("InitialReleaseDate") or doc.get("CurrentReleaseDate"))
        if not doc_id or released is None or released.year < EARLIEST_USEFUL_YEAR:
            continue
        usable.append((released, doc_id))

    usable.sort()
    if mode == "full":
        return [doc_id for _, doc_id in usable]

    cutoff = today - timedelta(days=31 * INCREMENTAL_MONTHS)
    recent = [doc_id for released, doc_id in usable if released >= cutoff]
    # Always fetch at least the newest document, even if the index dates lag.
    return recent or [usable[-1][1]]


def parse_status(value: str) -> dict[str, str]:
    """Split ``Publicly Disclosed:No;Exploited:Yes;Latest Software Release:X``."""
    return {
        m.group("key").strip(): m.group("value").strip()
        for m in FIELD_RE.finditer(value or "")
    }


def _parse_document(doc_id: str, document: dict) -> list[ExploitationObservation]:
    doc_date = parse_date((document.get("DocumentTracking") or {})
                          .get("CurrentReleaseDate")) or parse_date(doc_id)
    observations: list[ExploitationObservation] = []

    for vuln in document.get("Vulnerability") or []:
        statuses = [
            parse_status(t.get("Description", {}).get("Value") or "")
            for t in (vuln.get("Threats") or [])
            if t.get("Type") == EXPLOIT_STATUS_TYPE
            and (t.get("Description") or {}).get("Value")
        ]
        if not statuses:
            continue

        exploited = any(s.get("Exploited", "").lower() == "yes" for s in statuses)
        if not exploited:
            # Exploited:No is not an observation. Recording it would turn "Microsoft
            # has no evidence" into a row that looks like evidence.
            continue

        cve_id = extract_cve(vuln.get("CVE"))
        native = (vuln.get("CVE") or "").strip() or f"{doc_id}-unknown"
        vuln_id, vuln_id_type = ObservationSource.primary_id(cve_id, native)

        disclosed = any(s.get("Publicly Disclosed", "").lower() == "yes" for s in statuses)
        forecasts = [s.get("Latest Software Release") for s in statuses
                     if s.get("Latest Software Release")]
        revisions = tuple(
            d for d in (parse_date(r.get("Date")) for r in (vuln.get("RevisionHistory") or []))
            if d is not None
        )
        asserted = min(revisions) if revisions else doc_date
        if asserted is None:
            continue

        observations.append(
            ExploitationObservation(
                source_id="msrc",
                # Stable across re-fetches of the same month, and distinct per month so
                # a CVE re-flagged in a later document keeps both records.
                source_entry_id=f"{native}@{doc_id}",
                observation_type="vendor_reports_exploitation",
                vuln_id=vuln_id,
                vuln_id_type=vuln_id_type,
                cve_id=cve_id,
                asserted_at=asserted,
                observed_at=None,
                publicly_disclosed=disclosed,
                vendor_forecast=forecasts[0] if forecasts else None,
                revision_dates=tuple(sorted(revisions)),
                vendor="Microsoft",
                title=(vuln.get("Title") or {}).get("Value"),
                raw={"document": doc_id, "cve": native, "statuses": statuses,
                     "title": (vuln.get("Title") or {}).get("Value")},
            )
        )
    return observations
