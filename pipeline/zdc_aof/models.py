"""Pure logic for the agentic-C2 pipeline: the Shodan rule config, and the parsers that turn
the two sources' responses into counts. No I/O beyond reading the config file, no database.

NO ADDRESS LEAVES THIS MODULE. offensive.agency's host records carry an IP each;
`aggregate_hosts` counts them per framework and network and returns counts only.
"""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from collections import Counter
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path

CONFIG_PATH = Path(__file__).with_name("shodan_queries.toml")
SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
#: Shodan refuses a larger asn facet on the oss plan ("Facet size too big").
ASN_FACET_CAP = 1000
#: Per-network breakdown only. Shodan's network and country facets are separate marginals and
#: cannot be crossed, and nothing here needs the country one.
FACETS = f"asn:{ASN_FACET_CAP}"


class ConfigError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Rule:
    ordinal: int            # 1-based position inside its framework
    match: str
    exclude: str | None     # the term later rules subtract; None = cannot be negated
    anchor: bool = False


@dataclass(frozen=True, slots=True)
class Framework:
    slug: str
    name: str
    rules: tuple[Rule, ...]


@dataclass(frozen=True, slots=True)
class Config:
    window_days: int
    min_interval_seconds: float
    frameworks: tuple[Framework, ...]
    sha256: str

    @property
    def rule_count(self) -> int:
        return sum(len(f.rules) for f in self.frameworks)


def load_config(path: Path = CONFIG_PATH) -> Config:
    raw = path.read_bytes()
    return parse_config(raw)


def parse_config(raw: bytes) -> Config:
    try:
        doc = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"shodan_queries.toml does not parse: {exc}") from exc
    window = doc.get("window_days")
    interval = doc.get("min_interval_seconds")
    if not isinstance(window, int) or not 1 <= window <= 30:
        raise ConfigError("window_days must be an integer between 1 and 30")
    if not isinstance(interval, (int, float)) or interval < 1.0:
        raise ConfigError("min_interval_seconds must be at least 1.0 (Shodan allows 1 request/second)")
    frameworks, seen, anchors = [], set(), 0
    for fw in doc.get("framework", []):
        slug, name = fw.get("slug"), fw.get("name")
        if not isinstance(slug, str) or not SLUG.match(slug):
            raise ConfigError(f"framework slug {slug!r} must match {SLUG.pattern}")
        if slug in seen:
            raise ConfigError(f"framework {slug!r} is defined twice")
        seen.add(slug)
        if not isinstance(name, str) or not name.strip():
            raise ConfigError(f"framework {slug!r} has no name")
        entries = fw.get("rules") or []
        if not entries:
            raise ConfigError(f"framework {slug!r} has no rules")
        rules, matches = [], set()
        for i, r in enumerate(entries, 1):
            match = r.get("match")
            if not isinstance(match, str) or not match.strip():
                raise ConfigError(f"{slug} rule {i}: match is empty")
            if match in matches:
                raise ConfigError(f"{slug} rule {i}: {match!r} is listed twice")
            matches.add(match)
            # A date filter belongs to the pipeline (it is the window); a key never belongs here.
            if re.search(r"\b(after|before|key)\s*[:=]", match):
                raise ConfigError(f"{slug} rule {i}: a rule must not carry after:, before: or key=")
            exclude = r.get("exclude", match)
            if exclude is False:
                exclude = None
                if i != len(entries):
                    raise ConfigError(f"{slug} rule {i}: exclude = false is only allowed on the last "
                                      "rule, because later rules could not subtract it")
            elif not isinstance(exclude, str) or not exclude.strip():
                raise ConfigError(f"{slug} rule {i}: exclude must be a search term or false")
            elif exclude.lstrip().startswith(("-", '"')) or " " in _outside_quotes(exclude):
                # `-a b` would negate only `a`; a bare quoted phrase cannot be negated by Shodan.
                raise ConfigError(f"{slug} rule {i}: exclude must be one filter:value term")
            anchor = bool(r.get("anchor", False))
            anchors += anchor
            rules.append(Rule(i, match, exclude, anchor))
        frameworks.append(Framework(slug, name.strip(), tuple(rules)))
    if not frameworks:
        raise ConfigError("the config defines no framework")
    if anchors < 1:
        raise ConfigError("mark at least one rule anchor = true")
    return Config(window, float(interval), tuple(frameworks), hashlib.sha256(raw).hexdigest())


def _outside_quotes(term: str) -> str:
    return re.sub(r'"[^"]*"', "", term)


def window_start(day: date, window_days: int) -> date:
    """First day of the window ending on `day`, inclusive at both ends."""
    return day - timedelta(days=window_days - 1)


def build_queries(fw: Framework, day: date, window_days: int) -> list[tuple[Rule, str]]:
    """The exact query string for each rule: its match, minus every earlier rule, inside the
    window. Shodan's `after:` is inclusive of the date given (measured 2026-11-25: after:18/11
    plus before:18/11 added up to the unfiltered total with the 18th on the `after` side)."""
    since = window_start(day, window_days).strftime("%d/%m/%Y")
    out, excluded = [], []
    for rule in fw.rules:
        parts = [rule.match, *(f"-{e}" for e in excluded), f"after:{since}"]
        out.append((rule, " ".join(parts)))
        if rule.exclude is not None:
            excluded.append(rule.exclude)
    return out


# ---- Shodan responses ---------------------------------------------------------

@dataclass(slots=True)
class Count:
    total: int | None = None
    asn: dict[int, int] = field(default_factory=dict)
    asn_truncated: bool = False
    error: str | None = None


def parse_count(body: bytes | None, error: str | None) -> Count:
    if error is not None or body is None:
        return Count(error=error or "no body")
    try:
        doc = json.loads(body)
    except ValueError:
        return Count(error="response is not JSON")
    if not isinstance(doc, dict):
        return Count(error="response is not an object")
    if doc.get("error"):
        return Count(error=f"Shodan: {str(doc['error'])[:160]}")
    total = doc.get("total")
    if not isinstance(total, int) or isinstance(total, bool) or total < 0:
        return Count(error="response carries no total")
    c = Count(total=total)
    facets = doc.get("facets") or {}
    for f in facets.get("asn") or []:
        m = re.fullmatch(r"(?i)as(\d{1,10})", str(f.get("value", "")))
        n = f.get("count")
        if m and isinstance(n, int) and n > 0:
            c.asn[int(m.group(1))] = c.asn.get(int(m.group(1)), 0) + n
    c.asn_truncated = len(facets.get("asn") or []) >= ASN_FACET_CAP
    return c


def parse_plan(body: bytes | None) -> str | None:
    try:
        doc = json.loads(body or b"")
    except ValueError:
        return None
    return doc.get("plan") if isinstance(doc, dict) and isinstance(doc.get("plan"), str) else None


# ---- offensive.agency responses --------------------------------------------------

def envelope(body: bytes | None) -> tuple[dict, object] | None:
    """Every answer is {"meta": {...}, "data": ...}. None when it is not."""
    try:
        doc = json.loads(body or b"")
    except ValueError:
        return None
    if not isinstance(doc, dict) or "data" not in doc or not isinstance(doc.get("meta"), dict):
        return None
    return doc["meta"], doc["data"]


def _day(v) -> date | None:
    try:
        return date.fromisoformat(str(v)[:10])
    except ValueError:
        return None


@dataclass(frozen=True, slots=True)
class Status:
    ref_day: date
    first_day: date | None
    last_collection: str | None
    hosts_active: int | None
    hosts_total: int | None
    active_window_days: int | None


def parse_status(data) -> Status | None:
    if not isinstance(data, dict):
        return None
    ref = _day(data.get("ref_day"))
    if ref is None:
        return None
    num = lambda k: data.get(k) if isinstance(data.get(k), int) else None   # noqa: E731
    return Status(ref, _day(data.get("first_day")), data.get("last_collection"),
                  num("hosts_active"), num("hosts_total"), num("active_window_days"))


@dataclass(frozen=True, slots=True)
class Agent:
    slug: str
    name: str
    tracked: bool
    hosts_active: int | None
    record: dict


def parse_agents(data) -> tuple[list[Agent], int]:
    out, malformed = [], 0
    for a in data if isinstance(data, list) else []:
        slug = a.get("slug") if isinstance(a, dict) else None
        if not isinstance(slug, str) or not SLUG.match(slug):
            malformed += 1
            continue
        ha = a.get("hosts_active")
        out.append(Agent(slug, str(a.get("name") or slug), bool(a.get("tracked")),
                         ha if isinstance(ha, int) else None, a))
    return out, malformed


@dataclass(frozen=True, slots=True)
class Fingerprint:
    family: str
    name: str | None
    query: str


def parse_fingerprints(detail) -> list[Fingerprint]:
    """The detection rules offensive.agency publishes for one framework, in their order."""
    det = detail.get("detection") if isinstance(detail, dict) else None
    out, seen = [], set()
    for f in (det or {}).get("fingerprints") or []:
        q = f.get("query") if isinstance(f, dict) else None
        if not isinstance(q, str) or not q.strip() or q in seen:
            continue
        seen.add(q)
        name = f.get("name")
        out.append(Fingerprint(str(f.get("family") or "unknown"), name if isinstance(name, str) else None, q))
    return out


@dataclass(slots=True)
class HostAggregate:
    """Counts of addresses. Deliberately has nowhere to put an address."""
    records: int = 0
    malformed: int = 0
    #: (framework, asn or 0 when unknown, country or '') -> addresses. Framework '*' is every
    #: framework together with each address counted ONCE: summing the per-framework rows would
    #: count an address running two frameworks twice.
    by_network: Counter = field(default_factory=Counter)
    active: Counter = field(default_factory=Counter)        # framework -> addresses
    confirmed: Counter = field(default_factory=Counter)     # framework -> addresses, level confirmed
    orgs: dict[int, str] = field(default_factory=dict)      # asn -> the source's org name


def aggregate_hosts(agg: HostAggregate, data) -> HostAggregate:
    """Fold one page of /hosts into `agg`. An address running two frameworks counts once in
    each, which is how the source counts it too."""
    for h in data if isinstance(data, list) else []:
        agents = h.get("agents") if isinstance(h, dict) else None
        if not isinstance(agents, list) or not isinstance(h.get("ip"), str):
            agg.malformed += 1
            continue
        agg.records += 1
        net = h.get("network") if isinstance(h.get("network"), dict) else {}
        m = re.fullmatch(r"(?i)(?:as)?(\d{1,10})", str(net.get("asn") or ""))
        asn = int(m.group(1)) if m and 0 < int(m.group(1)) <= 4294967295 else 0
        cc = str(net.get("country") or "").upper()
        cc = cc if re.fullmatch(r"[A-Z]{2}", cc) else ""
        if asn and isinstance(net.get("org"), str) and net["org"].strip():
            agg.orgs.setdefault(asn, net["org"].strip()[:200])
        agg.by_network[("*", asn, cc)] += 1
        seen = set()
        for a in agents:
            slug = a.get("slug") if isinstance(a, dict) else None
            if not isinstance(slug, str) or not SLUG.match(slug) or slug in seen:
                continue
            seen.add(slug)
            agg.by_network[(slug, asn, cc)] += 1
            agg.active[slug] += 1
            if a.get("level") == "confirmed":
                agg.confirmed[slug] += 1
    return agg


def parse_timeline(data) -> tuple[list[tuple[date, str, int]], list[date]]:
    """(day, framework, addresses seen that day) for every day the source holds, plus the days."""
    if not isinstance(data, dict):
        return [], []
    days = [_day(d) for d in data.get("days") or []]
    if not days or any(d is None for d in days):
        return [], []
    out = []
    for slug, series in (data.get("agents") or {}).items():
        if not isinstance(slug, str) or not SLUG.match(slug) or not isinstance(series, list):
            continue
        if len(series) != len(days):
            return [], []                       # a ragged series cannot be aligned to days
        for d, v in zip(days, series):
            if isinstance(v, int) and not isinstance(v, bool) and v >= 0:
                out.append((d, slug, v))
    return out, days
