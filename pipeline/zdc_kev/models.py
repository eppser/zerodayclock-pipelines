"""Normalised KEV observation model.

The grain is deliberately (source, upstream_source, source_entry_id): one row per
*assertion*, never one row per CVE. Several sources routinely assert exploitation of
the same CVE with different dates and different strength of claim, and flattening that
into a single "exploitation date" would throw away exactly the disagreement the
scoreboard needs to show.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, asdict
from datetime import date, datetime, timezone

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# Strength of an exploitation claim, strongest first. PoC or exploit-code availability
# is NOT exploitation and must never be mapped onto this scale (v1 conflated them).
SIGNAL_ORDER = (
    "confirmed_compromise",
    "successful_exploitation",
    "in_the_wild_attempts",
    "unspecified",
)

VULN_ID_TYPES = ("cve", "euvd", "ghsa", "gcve", "other")


class NormalisationError(ValueError):
    """Raised when a source record cannot be turned into a valid observation."""


def classify_vuln_id(vuln_id: str) -> str:
    """Classify an identifier by namespace.

    "CVE-" as a prefix is not sufficient: Shadowserver tracks
    ``CVE-UNASSIGNED-2020-Zyxel-CPE-Command-Injection-RCE-01``, which is explicitly a
    placeholder for a vulnerability with no CVE. Typing that as 'cve' would put a
    non-CVE into CVE-keyed joins.
    """
    v = vuln_id.strip().upper()
    if CVE_RE.fullmatch(v):
        return "cve"
    if v.startswith("EUVD-"):
        return "euvd"
    if v.startswith("GHSA-"):
        return "ghsa"
    if v.startswith("GCVE-"):
        return "gcve"
    return "other"


def extract_cve(*candidates: object) -> str | None:
    """Return the first well-formed CVE id found in any candidate.

    Sources bury the CVE in different places: EUVD puts it in a newline-separated
    ``aliases`` string, CIRCL lowercases it in ``vulnerability.vulnId``. Normalising
    to upper case here is what makes cross-source joins work at all.
    """
    for candidate in candidates:
        if candidate is None:
            continue
        if isinstance(candidate, (list, tuple)):
            found = extract_cve(*candidate)
            if found:
                return found
            continue
        match = CVE_RE.search(str(candidate))
        if match:
            return match.group(0).upper()
    return None


def parse_date(value: object) -> date | None:
    """Parse the date formats these four sources actually emit.

    Returns None rather than guessing. A wrong date is worse than a missing one:
    every downstream statistic is a function of dates.
    """
    if value is None or value == "":
        return None
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()

    text = str(value).strip()
    if not text:
        return None

    # ISO-8601, with or without time and timezone (CISA, CIRCL, VulnCheck).
    iso = text.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(iso).date()
    except ValueError:
        pass

    # EUVD: "Jul 29, 2025, 11:29:31 PM" / "Mar 20, 2026, 12:00:00 AM".
    # No timezone is supplied by the API; treated as UTC and documented as such.
    for fmt in ("%b %d, %Y, %I:%M:%S %p", "%b %d, %Y", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, fmt).date()
        except ValueError:
            continue
    return None


def parse_timestamp(value: object) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value).strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        day = parse_date(text)
        if day is None:
            return None
        return datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


@dataclass(frozen=True, slots=True)
class KevObservation:
    """One exploitation assertion, by one source, about one vulnerability."""

    source_id: str
    #: The authority that ISSUED this assertion. Equals source_id for first-party
    #: sources; for an aggregator it is the issuer inside it (e.g. 'shadowserver').
    upstream_source: str
    source_entry_id: str
    vuln_id: str
    vuln_id_type: str
    raw: dict

    #: What the issuer CITES as evidence. Never an observer in its own right: an
    #: issuer citing a vendor report is one observation, not two.
    evidence_source: str | None = None
    #: CIRCL's evidence[].type. A KEV entry is a CATALOGUE LISTING; a honeypot or
    #: sinkhole hit is sensor telemetry and belongs in obs_core, never here.
    evidence_type: str | None = None
    #: GCVE origin uuid — the stable identity of the issuer. Feed names get renamed.
    origin_uuid: str | None = None
    cve_id: str | None = None
    aliases: tuple[str, ...] = ()
    exploited: bool = True
    signal: str = "unspecified"
    status_reason: str | None = None
    confidence: float | None = None
    ransomware_use: str | None = None

    date_added: date | None = None
    exploited_since: date | None = None
    due_date: date | None = None
    source_published: datetime | None = None
    source_updated: datetime | None = None

    vendor_project: str | None = None
    product: str | None = None
    vulnerability_name: str | None = None
    short_description: str | None = None
    reference_urls: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.source_id or not self.upstream_source or not self.source_entry_id:
            raise NormalisationError("source_id, upstream_source and source_entry_id are required")
        if not self.vuln_id:
            raise NormalisationError("vuln_id is required")
        if self.vuln_id_type not in VULN_ID_TYPES:
            raise NormalisationError(f"bad vuln_id_type {self.vuln_id_type!r}")
        if self.signal not in SIGNAL_ORDER:
            raise NormalisationError(f"bad signal {self.signal!r}")
        if self.status_reason not in (None, "confirmed", "suspected"):
            raise NormalisationError(f"bad status_reason {self.status_reason!r}")
        if self.confidence is not None and not 0.0 <= self.confidence <= 1.0:
            raise NormalisationError(f"confidence out of range: {self.confidence}")
        if self.cve_id is not None and not CVE_RE.fullmatch(self.cve_id):
            raise NormalisationError(f"malformed cve_id {self.cve_id!r}")

    @property
    def identity(self) -> tuple[str, str, str]:
        return (self.source_id, self.upstream_source, self.source_entry_id)

    def content_hash(self) -> str:
        """Hash of the normalised payload, excluding ``raw`` and volatile fields.

        Used to decide whether a re-observed entry actually *changed*. Including
        ``raw`` would make every cosmetic upstream reformat look like a change and
        destroy the value of last_changed_at.
        """
        payload = asdict(self)
        payload.pop("raw", None)
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()


@dataclass
class FetchRecord:
    """One HTTP request attempt — recorded whether or not it succeeded.

    A harvester must never return "no data" without a reason attached. v1 recorded a
    WAF block as 220 successful rows; ``error`` exists so that cannot happen silently.
    """

    source_id: str
    url: str
    request_mode: str  # full | incremental | conditional
    http_status: int | None = None
    ok: bool = False
    not_modified: bool = False
    etag: str | None = None
    last_modified: str | None = None
    content_hash: str | None = None
    media_type: str = "application/json"
    body: bytes | None = None
    record_count: int | None = None
    bytes_downloaded: int | None = None
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    duration_ms: int | None = None
    error: str | None = None
    attempt: int = 1
    window_start: date | None = None
    window_end: date | None = None

    def __post_init__(self) -> None:
        if self.request_mode not in ("full", "incremental", "conditional"):
            raise ValueError(f"bad request_mode {self.request_mode!r}")


@dataclass
class CollectResult:
    """What one source produced during one pipeline run."""

    source_id: str
    fetches: list[FetchRecord] = field(default_factory=list)
    observations: list[KevObservation] = field(default_factory=list)
    # True only when the source returned its *entire* catalogue this run. Withdrawal
    # detection is gated on this: an incremental pull that omits an entry says nothing
    # about whether the source removed it.
    complete_snapshot: bool = False
    unchanged: bool = False
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and all(f.ok or f.not_modified for f in self.fetches)
