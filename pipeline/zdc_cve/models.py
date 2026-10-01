"""CVE registry record model.

Each source contributes a *partial* record and owns only its own columns:

    cve_project  state, assigner, dateReserved/Published/Updated, CNA CVSS, title,
                 description, affected, CWE, reference count
    nvd          nvd_published, nvd_last_modified, vuln_status, NVD CVSS

They are never coalesced. The CNA and NVD disagree about both scores and dates, and a
metric that silently prefers one is a metric nobody can audit.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime

from zdc_kev.models import (  # noqa: F401
    CVE_RE,
    FetchRecord,
    NormalisationError,
    parse_timestamp,
)

SOURCES = ("cve_project", "nvd")
STATES = ("PUBLISHED", "REJECTED", "RESERVED")
#: Bound the row: a handful of CVEs list thousands of affected products, and storing
#: them all would blow up the table for no analytical gain.
MAX_LIST = 20
MAX_TEXT = 8000


def cve_year(cve_id: str) -> int:
    """Year from the identifier — the only year that is stable.

    NVD publication year drifts (a CVE-2019-* can be published by NVD in 2023). v1
    cohorted on NVD publication year and produced cohorts that did not mean what their
    labels said.
    """
    m = re.match(r"^CVE-(\d{4})-", cve_id.upper())
    if not m:
        raise NormalisationError(f"cannot derive a year from {cve_id!r}")
    return int(m.group(1))


def clamp(values, limit: int = MAX_LIST) -> tuple[str, ...]:
    seen, out = set(), []
    for v in values or ():
        v = str(v).strip()
        if v and v.lower() != "n/a" and v not in seen:
            seen.add(v)
            out.append(v)
            if len(out) >= limit:
                break
    return tuple(out)


@dataclass(frozen=True, slots=True)
class CveRecord:
    cve_id: str
    source: str

    # cve_project-owned
    state: str | None = None
    assigner_org_id: str | None = None
    assigner_short_name: str | None = None
    date_reserved: datetime | None = None
    date_published: datetime | None = None
    date_updated: datetime | None = None
    title: str | None = None
    description: str | None = None
    cna_cvss_version: str | None = None
    cna_cvss_score: float | None = None
    cna_cvss_vector: str | None = None
    cwe_ids: tuple[str, ...] = ()
    affected_vendors: tuple[str, ...] = ()
    affected_products: tuple[str, ...] = ()
    reference_count: int | None = None

    # nvd-owned
    nvd_published: datetime | None = None
    nvd_last_modified: datetime | None = None
    vuln_status: str | None = None
    nvd_cvss_version: str | None = None
    nvd_cvss_score: float | None = None
    nvd_cvss_vector: str | None = None

    def __post_init__(self) -> None:
        if not CVE_RE.fullmatch(self.cve_id):
            raise NormalisationError(f"malformed cve_id {self.cve_id!r}")
        if self.source not in SOURCES:
            raise NormalisationError(f"unknown source {self.source!r}")
        if self.state is not None and self.state not in STATES:
            raise NormalisationError(f"bad state {self.state!r}")
        for name in ("cna_cvss_score", "nvd_cvss_score"):
            v = getattr(self, name)
            if v is not None and not 0.0 <= v <= 10.0:
                raise NormalisationError(f"{name} out of range: {v}")

    @property
    def year(self) -> int:
        return cve_year(self.cve_id)

    def content_hash(self) -> str:
        return hashlib.sha256(
            json.dumps(asdict(self), sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()


@dataclass
class CveCollectResult:
    source_id: str
    fetches: list[FetchRecord] = field(default_factory=list)
    records: list[CveRecord] = field(default_factory=list)
    complete_snapshot: bool = False
    unchanged: bool = False
    error: str | None = None
    #: Release tags / windows consumed, so a run can say exactly what it covered.
    covered: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.error is None and all(f.ok or f.not_modified for f in self.fetches)
