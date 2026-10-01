"""Parsing. Nothing here touches the network or the database.

ONE ROW IS ONE (CVE, DAY). That is the grain the timeline endpoint publishes and the
grain obs_core.exploitation_observations already models for shadowserver_api, whose
entry ids read `CVE-2025-58360@2026-08-30`. Using the same convention means the two
sensors can be compared without a translation layer, and means 0029's lesson holds:
one observation store, not a purpose-built table per sensor.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any

# Only CVE identifiers appear in the tracker's CVE endpoints. Fingerprints (product
# probing with no CVE) are a separate population and are NOT collected here.
ID_TYPE = "cve"


def _date(v: Any) -> date | None:
    if not v:
        return None
    if isinstance(v, date):
        return v
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00")).date()
    except ValueError:
        return None


@dataclass(frozen=True)
class CveState:
    """A tracked CVE as the /cves collection describes it on the day we read it."""
    cve_id: str
    title: str | None
    vendor: str | None
    product: str | None
    nb_ips: int | None
    first_seen: date | None
    last_seen: date | None
    rule_release_date: date | None
    published_date: date | None
    phase: str | None
    cvss_score: float | None
    has_public_exploit: bool | None
    crowdsec_score: float | None
    opportunity_score: float | None
    momentum_score: float | None
    cwes: list = field(default_factory=list)
    tags: list = field(default_factory=list)

    @property
    def active(self) -> bool:
        """Worth asking for a timeline. A CVE CrowdSec has never seen has no series."""
        return bool(self.first_seen) or bool(self.nb_ips)


@dataclass(frozen=True)
class DayCount:
    """One (CVE, day) occurrence count.

    `count` is CrowdSec's own word - the endpoint documents it as "Count of occurrences
    at the timestamp". It is NOT stated to be attempts and NOT stated to be distinct
    IPs, and in this data those differ by orders of magnitude. Do not relabel it
    without a measurement.
    """
    cve_id: str
    day: date
    count: int


def parse_cves(items: list[dict]) -> list[CveState]:
    out = []
    for it in items:
        cid = it.get("id") or it.get("name")
        if not isinstance(cid, str) or not cid.startswith("CVE-"):
            continue          # the tracker is CVE-only today; anything else is new
        comp = (it.get("affected_components") or [{}])[0]
        phase = (it.get("exploitation_phase") or {}).get("name")
        out.append(CveState(
            cve_id=cid,
            title=it.get("title"),
            vendor=comp.get("vendor"),
            product=comp.get("product"),
            nb_ips=it.get("nb_ips"),
            first_seen=_date(it.get("first_seen")),
            last_seen=_date(it.get("last_seen")),
            rule_release_date=_date(it.get("rule_release_date")),
            published_date=_date(it.get("published_date")),
            phase=phase,
            cvss_score=it.get("cvss_score"),
            has_public_exploit=it.get("has_public_exploit"),
            crowdsec_score=it.get("crowdsec_score"),
            opportunity_score=it.get("opportunity_score"),
            momentum_score=it.get("momentum_score"),
            cwes=it.get("cwes") or [],
            tags=it.get("tags") or [],
        ))
    return out


def parse_timeline(cve_id: str, points: Any, *, upto: date | None = None) -> list[DayCount]:
    """Daily points for one CVE.

    A ZERO COUNT IS A MEASUREMENT AND IS KEPT. The endpoint returns a contiguous run of
    days, so a zero means "CrowdSec was watching and saw nothing", which is exactly the
    typed absence First Principle 5 asks for. It is not the same as a missing day, and
    only a missing day is unknown.

    `upto` drops the current, partial day: the last point of a live window is a few
    hours of counting and would read as a collapse against yesterday's full day.
    """
    if not isinstance(points, list):
        return []
    out = []
    for p in points:
        if not isinstance(p, dict):
            continue
        d = _date(p.get("timestamp"))
        c = p.get("count")
        if d is None or not isinstance(c, int) or c < 0:
            continue
        if upto is not None and d >= upto:
            continue
        out.append(DayCount(cve_id, d, c))
    return out
