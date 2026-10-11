"""The patch prioritisation scorecard, as a pure function of one month's inputs.

Each rule builds a patch list from what was knowable on the first day of the month scored
(KEV entries listed AND collected before that day, that day's EPSS file, the CVSS score) and is
scored against the CVEs the honeypots and CrowdSec saw attacked during the month. "Newly
targeted" keeps only the CVEs not seen attacked in the LOOKBACK_DAYS before the month: most
attacks hit CVEs already being attacked, and VulnCheck and CIRCL list CVEs because these same
sensors reported them, so the all-attacked view flatters the rows that include VulnCheck or CIRCL.

The method and its review are in analysis/patch-prioritisation/README.md. Given the same inputs
this module reproduces that analysis's counts exactly; its bootstrap ranges are drawn reproducibly
(fixed seed, sorted pool) and can differ from the first audit's by up to a point.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

LOOKBACK_DAYS = 50          # 13 Jul - 31 Aug for September 2026, the window the method was set on
BOOTSTRAP = 1000
SEED = 7

# key, label, kind. Order is the chart's order AND the bootstrap's draw order: keep 'epss2'
# last, so adding it did not move the audited ranges of the rules before it.
RULES: list[tuple[str, str, str]] = [
    ('all', 'Patch everything', 'reference'),
    ('cvss7', 'CVSS 7 or higher', 'single'),
    ('cvss9', 'CVSS 9 or higher (critical)', 'single'),
    ('epss1', 'EPSS 1% or higher', 'single'),
    ('epss3', 'EPSS 3% or higher', 'single'),
    ('epss10', 'EPSS 10% or higher', 'single'),
    ('cisa', 'CISA KEV', 'single'),
    ('kev', 'Any KEV catalogue', 'single'),
    ('lane', 'Any KEV or EPSS 10%+', 'lane'),
    ('pick', 'Any KEV or EPSS 3%+', 'pick'),
    ('extra', '… or critical with EPSS 2%+', 'extra'),
    ('epss2', 'EPSS 2% or higher', 'hidden'),
]


@dataclass
class MonthInputs:
    """Everything one month's scorecard reads. Sets hold CVE ids."""
    epss_start: dict[str, float]          # EPSS file of the month's first day
    epss_next: dict[str, float]           # EPSS file of the next month's first day
    cvss: dict[str, float]                # current CVSS (CNA score, else NVD's)
    kev_start: dict[str, set[str]]        # 'all' / 'cisa' / 'clean' -> listed and collected before day 1
    kev_next: dict[str, set[str]]         # the same as of the next month's first day
    attacked: set[str]                    # seen attacked during the month
    seen_before: set[str]                 # seen attacked in the LOOKBACK_DAYS before it


@dataclass
class RuleScore:
    key: str
    label: str
    kind: str
    added: int
    backlog: int
    hit_all: int
    hit_new: int
    new_ci: tuple[float, float]
    hit_new_clean: int


@dataclass
class Scorecard:
    cves: int
    attacked_all: int
    attacked_new: int
    rules: list[RuleScore] = field(default_factory=list)
    lanes_urgent: int = 0
    lanes_regular: int = 0
    lanes_turned: int = 0


def _rule(key: str, epss: dict[str, float], cvss: dict[str, float], kev: dict[str, set[str]],
          *, clean: bool) -> set[str]:
    k = kev['clean'] if clean else kev['all']
    e = lambda t: {c for c, v in epss.items() if v >= t}            # noqa: E731
    crit_with = lambda u: {c for c, v in epss.items() if v >= u and cvss.get(c, -1) >= 9}  # noqa: E731
    if key == 'all':
        return set(epss)
    if key == 'cvss7':
        return {c for c in epss if cvss.get(c, -1) >= 7}
    if key == 'cvss9':
        return {c for c in epss if cvss.get(c, -1) >= 9}
    if key.startswith('epss'):
        return e(int(key[4:]) / 100)
    if key == 'cisa':
        return set(kev['cisa'])
    if key == 'kev':
        return set(k)
    if key == 'lane':
        return set(k) | e(.10)
    if key == 'pick':
        return set(k) | e(.03)
    if key == 'extra':
        return set(k) | e(.03) | crit_with(.02)
    raise ValueError(f'unknown rule {key}')


def score_month(inp: MonthInputs) -> Scorecard:
    u0, u1 = set(inp.epss_start), set(inp.epss_next)
    attacked = inp.attacked & u0
    new = attacked - inp.seen_before
    if not attacked or not new:
        raise ValueError(f'no outcome to score: {len(attacked)} attacked, {len(new)} newly targeted')
    pool = sorted(new)
    rng = random.Random(SEED)

    def boot(s: set[str]) -> tuple[float, float]:
        v = sorted(sum(c in s for c in (rng.choice(pool) for _ in pool)) / len(pool)
                   for _ in range(BOOTSTRAP))
        return v[int(.025 * BOOTSTRAP)], v[int(.975 * BOOTSTRAP) - 1]

    card = Scorecard(cves=len(u0), attacked_all=len(attacked), attacked_new=len(new))
    lists: dict[str, tuple[set[str], set[str]]] = {}
    for key, label, kind in RULES:
        # Each list is cut to its own day's EPSS population. A KEV CVE missing from the next
        # file is not "added" that month just because the start list could not hold it.
        s0 = _rule(key, inp.epss_start, inp.cvss, inp.kev_start, clean=False) & u0
        s1 = _rule(key, inp.epss_next, inp.cvss, inp.kev_next, clean=False) & u1
        clean0 = _rule(key, inp.epss_start, inp.cvss, inp.kev_start, clean=True) & u0
        lists[key] = (s0, s1)
        card.rules.append(RuleScore(
            key=key, label=label, kind=kind, added=len(s1 - s0), backlog=len(s0),
            hit_all=len(s0 & attacked), hit_new=len(s0 & new), new_ci=boot(s0),
            hit_new_clean=len(clean0 & new)))

    p0, p1 = lists['pick']
    l0, l1 = lists['lane']
    added = p1 - p0
    card.lanes_urgent = len(added & l1)
    card.lanes_regular = len(added - l1)
    card.lanes_turned = len((p0 & p1 & l1) - l0)
    return card
