"""IP hits -> per-network aggregates, in memory. The only place an IP address exists.

Rules, each measured on the 2026-10-12 prototype:
- IPv6 is skipped (the routing table is IPv4).
- IPs on SANS ISC's research-scanner list are removed from every attack feed
  (2,173 of DShield's 10,000 top sources were research scanners).
- An IP counted twice by one source counts once.
- Occupied /24s are the unit the model counts; IPs are kept for context.
"""

from __future__ import annotations

import collections
from dataclasses import dataclass, field

from .sources import Hit


@dataclass
class Agg:
    ips: int = 0
    slash24: set = field(default_factory=set)
    ipset: set = field(default_factory=set)        # in memory only; never stored
    categories: collections.Counter = field(default_factory=collections.Counter)


@dataclass
class AggResult:
    by_asn: dict[int, Agg]
    records: int
    ipv4: int
    unmapped: int
    excluded: int


def aggregate(hits: list[Hit], asn_of, exclude: set[str] = frozenset()) -> AggResult:
    by: dict[int, Agg] = {}
    seen: set[str] = set()
    ipv4 = unmapped = excluded = 0
    for h in hits:
        ip = h.ip
        if ":" in ip or ip.count(".") != 3:
            continue
        if ip in seen:
            continue
        seen.add(ip)
        ipv4 += 1
        if ip in exclude:
            excluded += 1
            continue
        a = asn_of(ip)
        if not a:
            unmapped += 1
            continue
        g = by.setdefault(a, Agg())
        g.ips += 1
        g.ipset.add(ip)
        g.slash24.add(ip.rsplit(".", 1)[0])
        g.categories.update(h.categories)
    return AggResult(by, len(hits), ipv4, unmapped, excluded)


def union(per_source: dict[str, AggResult]) -> dict[int, tuple[int, int]]:
    """Distinct IPs and occupied /24s per network across all IP feeds: an IP seen by four
    sensors counts once."""
    ips: dict[int, set] = {}
    s24: dict[int, set] = {}
    for res in per_source.values():
        for a, g in res.by_asn.items():
            ips.setdefault(a, set()).update(g.ipset)
            s24.setdefault(a, set()).update(g.slash24)
    return {a: (len(ips[a]), len(s24[a])) for a in ips}


def top_categories(c: collections.Counter, cve_limit: int = 5) -> dict:
    """Keep every non-CVE category and only the top CVEs, so a row stays small."""
    out = {k: v for k, v in c.items() if not k.startswith(("cve:", "family:"))}
    out.update(dict(sorted(((k, v) for k, v in c.items() if k.startswith("cve:")), key=lambda x: -x[1])[:cve_limit]))
    out.update(dict(sorted(((k, v) for k, v in c.items() if k.startswith("family:")), key=lambda x: -x[1])[:cve_limit]))
    return out
