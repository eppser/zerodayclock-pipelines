"""Exploitation observation model.

An observation is not a KEV entry. A KEV entry says "organisation X lists this as
known-exploited". An observation says one of two much narrower things:

    attempt_observed             a sensor saw someone try it
    vendor_reports_exploitation  the vendor states it happened in their products

Neither is interchangeable with the other, and neither is interchangeable with a
catalogue listing. The type is therefore a required field with a closed vocabulary,
not a free-text note.

Reuses the KEV pipeline's transport and date parsing (``zdc_kev.http``,
``zdc_kev.models``) rather than duplicating them — those modules are source-agnostic.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import date

from zdc_kev.models import (  # noqa: F401 — re-exported for adapter convenience
    CVE_RE,
    FetchRecord,
    NormalisationError,
    classify_vuln_id,
    extract_cve,
    parse_date,
    parse_timestamp,
)

OBSERVATION_TYPES = ("attempt_observed", "vendor_reports_exploitation")
VULN_ID_TYPES = ("cve", "euvd", "ghsa", "gcve", "other")


@dataclass(frozen=True, slots=True)
class ExploitationObservation:
    source_id: str
    source_entry_id: str
    observation_type: str
    vuln_id: str
    vuln_id_type: str
    raw: dict

    cve_id: str | None = None

    observed_at: date | None = None
    first_observed_at: date | None = None
    last_observed_at: date | None = None
    asserted_at: date | None = None
    #: Only where the source publishes volume. None means unknown — never "one".
    observation_count: int | None = None

    publicly_disclosed: bool | None = None
    #: A vendor's exploitability FORECAST (e.g. Microsoft's "Exploitation More
    #: Likely"). A prediction, not an observation. Never read this as evidence of
    #: exploitation — that is the v1 PoC-as-exploitation error wearing a new hat.
    vendor_forecast: str | None = None
    revision_dates: tuple[date, ...] = ()

    vendor: str | None = None
    product: str | None = None
    title: str | None = None

    def __post_init__(self) -> None:
        if not self.source_id or not self.source_entry_id:
            raise NormalisationError("source_id and source_entry_id are required")
        if self.observation_type not in OBSERVATION_TYPES:
            raise NormalisationError(f"bad observation_type {self.observation_type!r}")
        if not self.vuln_id:
            raise NormalisationError("vuln_id is required")
        if self.vuln_id_type not in VULN_ID_TYPES:
            raise NormalisationError(f"bad vuln_id_type {self.vuln_id_type!r}")
        if self.cve_id is not None and not CVE_RE.fullmatch(self.cve_id):
            raise NormalisationError(f"malformed cve_id {self.cve_id!r}")
        if self.observation_count is not None and self.observation_count < 0:
            raise NormalisationError("observation_count cannot be negative")
        if not any((self.observed_at, self.first_observed_at, self.asserted_at)):
            # An observation with no date at all cannot participate in any time-to-
            # exploitation estimate, and silently keeping it would inflate counts
            # while contributing nothing to the timeline.
            raise NormalisationError("an observation needs at least one date")

    @property
    def identity(self) -> tuple[str, str]:
        return (self.source_id, self.source_entry_id)

    @property
    def effective_date(self) -> date | None:
        return self.observed_at or self.first_observed_at or self.asserted_at

    def content_hash(self) -> str:
        payload = asdict(self)
        payload.pop("raw", None)
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()


@dataclass
class ObsCollectResult:
    source_id: str
    fetches: list[FetchRecord] = field(default_factory=list)
    observations: list[ExploitationObservation] = field(default_factory=list)
    complete_snapshot: bool = False
    unchanged: bool = False
    error: str | None = None
    #: Records left out as malformed ("<id>: <reason>"); see zdc_kev's CollectResult.
    skipped: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.error is None and all(f.ok or f.not_modified for f in self.fetches)
