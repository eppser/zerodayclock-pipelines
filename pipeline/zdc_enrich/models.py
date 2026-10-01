"""EPSS record and collection result."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, datetime
from decimal import Decimal, InvalidOperation

from zdc_kev.models import FetchRecord

#: The payload's first line, e.g.
#: ``#model_version:v2026.06.15,score_date:2026-08-30T12:03:42Z``
HEADER_RE = re.compile(
    r"#\s*model_version\s*:\s*(?P<model>[^,\s]+)\s*,\s*score_date\s*:\s*(?P<date>\S+)"
)
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


@dataclass(frozen=True, slots=True)
class EpssRecord:
    cve_id: str
    epss_score: Decimal
    epss_percentile: Decimal
    model_version: str
    score_date: date


@dataclass
class EpssCollectResult:
    source_id: str = "epss"
    fetches: list[FetchRecord] = field(default_factory=list)
    records: list[EpssRecord] = field(default_factory=list)
    model_version: str | None = None
    score_date: date | None = None
    skipped_rows: int = 0
    unchanged: bool = False
    #: Set when the source was deliberately not fetched this run (already fetched
    #: today). Distinct from an error and from "returned nothing".
    skipped_reason: str | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        if self.error:
            return False
        if self.skipped_reason:
            return True
        return all(f.ok or f.not_modified for f in self.fetches)


def parse_header(first_line: str) -> tuple[str, date]:
    """Model version and score date, or raise.

    A score without its model version is not reproducible: EPSS has shipped three
    model generations and their scores and percentiles are not comparable. Refusing to
    parse a headerless file is deliberate — a silent default would quietly mix
    generations in one column.
    """
    m = HEADER_RE.search(first_line)
    if not m:
        raise ValueError(f"EPSS payload has no model_version/score_date header: {first_line[:120]!r}")
    raw = m.group("date")
    stamp = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    return m.group("model"), stamp.date()


def parse_epss(text: str) -> tuple[list[EpssRecord], str, date, int]:
    """Parse the decompressed CSV into records.

    Returns (records, model_version, score_date, skipped_rows). Malformed rows are
    counted rather than dropped in silence — a source that starts emitting garbage
    should show up as a rising skip count, not as a shrinking table.
    """
    lines = text.splitlines()
    if not lines:
        raise ValueError("EPSS payload is empty")

    model_version, score_date = parse_header(lines[0])

    # Second line is the CSV header: cve,epss,percentile
    body = lines[1:]
    if body and body[0].lower().startswith("cve,"):
        body = body[1:]

    records: list[EpssRecord] = []
    seen: set[str] = set()
    skipped = 0
    for line in body:
        if not line or line.startswith("#"):
            continue
        parts = line.split(",")
        if len(parts) != 3:
            skipped += 1
            continue
        cve_id, score_s, pct_s = (p.strip() for p in parts)
        if not CVE_RE.match(cve_id):
            skipped += 1
            continue
        # The feed is one row per CVE, but a duplicate would silently become a
        # last-write-wins upsert. Count it instead.
        if cve_id in seen:
            skipped += 1
            continue
        try:
            score = Decimal(score_s)
            pct = Decimal(pct_s)
        except InvalidOperation:
            skipped += 1
            continue
        if not (0 <= score <= 1) or not (0 <= pct <= 1):
            skipped += 1
            continue
        seen.add(cve_id)
        records.append(EpssRecord(cve_id, score, pct, model_version, score_date))

    return records, model_version, score_date, skipped
