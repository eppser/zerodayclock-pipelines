"""Extract dated vendor fix records from an MSRC CVRF document.

WHAT MSRC ACTUALLY CARRIES, measured against the live API on 2026-09-01. CLAUDE.md recorded
`Remediations[].Date` as the cheapest candidate for a patch date and noted the field was
unconfirmed. It is now confirmed, and it is empty:

    Remediations[].DateSpecified   false on all 2,874 entries in 2026-Jan
    Vulnerability.ReleaseDateSpecified   false on all 310 vulnerabilities
    Vulnerability.ReleaseDate      0001-01-01T00:00:00 on all 310

So there is no per-remediation date to read. What IS dated, and is first-party, is the
document: `DocumentTracking.InitialReleaseDate` is the day Microsoft shipped that month's
security updates. A CVE carrying a **Type 2 (Vendor Fix)** remediation in that document was
fixed by an update released on that day.

THE RULE, AND THE CASE THAT BROKE ITS FIRST VERSION:
    patch_date = InitialReleaseDate of the document in which the CVE carries a Type 2
                 remediation, ACCEPTED ONLY IF that CVE was in the document when it shipped
    basis      = 'vendor_fix_record'
    evidence   = the KB URL from that remediation

MSRC REVISES DOCUMENTS AND BACK-ADDS CVES TO THEM, which the first version of this rule did
not account for and which produced a wrong date on exactly the vulnerabilities that matter
most. Measured on CVE-2022-41082 (Exchange, ProxyNotShell):

    document                2022-Sep, InitialReleaseDate 2022-09-13
    this CVE's first revision inside it        2022-09-30
    the KB it names                            5019758, the NOVEMBER update

Microsoft published the advisory with mitigations on 30 September and shipped the fix on
8 November. Reading the document date gave 13 September: seven weeks before the fix existed,
and on the wrong side of the KEV listing. That turns "exploited before a patch existed" from
true into false, which is the same class of error as v1's inference and points the same way.

So a document's release date is only this CVE's fix date if the CVE was IN the document when
it shipped. RevisionHistory[0].Date says when the CVE first appeared there; if that is more
than BACKADD_TOLERANCE_DAYS after the document's release, the fix did not ship with it and
NO date is recorded. A missing date is a smaller error than a wrong one.

This is a measurement, not an inference. It does not read a version ceiling and guess when a
release above it appeared, which is the v1 method that ran +98 days late on average and worst
case 674 days. It reads a vendor statement that a fix exists, in a document with a publication
date. Its error is bounded by the monthly cadence of the document, and it can only ever be
LATE by the days between an out-of-band fix and the next Patch Tuesday, never early.

WHAT IT DOES NOT COVER: anything Microsoft does not publish. That is most of the corpus, and
the page must not imply otherwise.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
VENDOR_FIX = 2          # CVRF Remediation/@Type: 2 = Vendor Fix
# A CVE documented within three days of the document shipping was part of that release.
# Beyond that it was back-added and the document date says nothing about when its fix shipped.
BACKADD_TOLERANCE_DAYS = 3


@dataclass(frozen=True)
class PatchRecord:
    cve_id: str
    patch_date: str          # ISO date
    fix_version: str | None  # the KB or release name
    evidence_url: str | None
    product: str | None


def document_release_date(doc: dict) -> str | None:
    """The day Microsoft shipped this month's updates, or None if the document is undated."""
    d = (doc.get("DocumentTracking") or {}).get("InitialReleaseDate")
    if not isinstance(d, str) or len(d) < 10:
        return None
    day = d[:10]
    # 0001-01-01 is CVRF's "unspecified"; treating it as a date would file every fix in
    # the year 1 and make min(patch_date) meaningless for every CVE that touched it.
    return None if day.startswith("0001") else day


def first_documented(v: dict) -> str | None:
    """The day this CVE first appeared in the document, from its own revision history."""
    dates = sorted(
        r["Date"][:10]
        for r in (v.get("RevisionHistory") or [])
        if isinstance(r.get("Date"), str) and len(r["Date"]) >= 10
        and not r["Date"].startswith("0001")
    )
    return dates[0] if dates else None


def _days(a: str, b: str) -> int:
    from datetime import date as _d

    ya, ma, da = (int(x) for x in a.split("-"))
    yb, mb, db = (int(x) for x in b.split("-"))
    return (_d(ya, ma, da) - _d(yb, mb, db)).days


def parse(doc: dict) -> list[PatchRecord]:
    released = document_release_date(doc)
    if released is None:
        return []
    out: list[PatchRecord] = []
    for v in doc.get("Vulnerability") or []:
        cve = (v.get("CVE") or "").strip().upper()
        if not CVE_RE.match(cve):
            continue
        # Back-added CVEs get no date at all. See the module docstring for the measurement.
        first = first_documented(v)
        if first is not None and _days(first, released) > BACKADD_TOLERANCE_DAYS:
            continue
        best: PatchRecord | None = None
        for r in v.get("Remediations") or []:
            if r.get("Type") != VENDOR_FIX:
                continue
            desc = (r.get("Description") or {}).get("Value")
            rec = PatchRecord(
                cve_id=cve,
                patch_date=released,
                fix_version=(r.get("FixedBuild") or desc or None),
                evidence_url=r.get("URL") or None,
                product=None,
            )
            # One row per (cve, document). A document lists the same fix against many
            # product ids; storing each would multiply the corpus by product count for no
            # extra information, since they all share the one release date.
            if best is None or (rec.evidence_url and not best.evidence_url):
                best = rec
        if best is not None:
            out.append(best)
    return out
