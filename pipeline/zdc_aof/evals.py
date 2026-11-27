"""Gate checks for the agentic-C2 pipeline. ERROR blocks; WARN is visible; INFO is diagnostic.

Everything a check needs is in `Facts`, which the run fills in as it goes, so the whole gate is
one pure function of one value and every check can be made to fail in a test by changing one
field. Each check exists because of a way this pipeline could be wrong and still look fine.

THE REPORT IS PUBLIC (the workflow runs in a public repository). Summaries and details carry
per-framework totals and counts of things, never an address, a network or a network's name.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date

from zdc_crowdsec.evals import ERROR, INFO, WARN, EvalResult

from .db import IPV4
from .models import Status

#: offensive.agency endpoints a run cannot do without.
OA_CRITICAL = ("status", "agents", "timeline")
STORAGE_BUDGET_BYTES = 150 * 1024 * 1024


@dataclass(slots=True)
class Facts:
    today: date
    # ---- offensive.agency
    oa_errors: dict[str, str] = field(default_factory=dict)      # endpoint -> error
    oa_requests: int = 0
    oa_status_before: Status | None = None
    oa_status_after: Status | None = None
    oa_hosts_stated: int | None = None       # meta.total of /hosts
    oa_hosts_counted: int = 0
    oa_hosts_malformed: int = 0
    oa_listed_active: dict[str, int] = field(default_factory=dict)   # framework list: hosts_active
    oa_counted_active: dict[str, int] = field(default_factory=dict)  # our count from /hosts
    oa_tracked: list[str] = field(default_factory=list)
    oa_rules: dict[str, int] = field(default_factory=dict)       # framework -> rules published
    oa_timeline_days: list[date] = field(default_factory=list)
    oa_withheld_unexpected: list[str] = field(default_factory=list)
    # ---- Shodan
    sh_info_status: int = 0
    sh_plan: str | None = None
    sh_rules: int = 0
    sh_rule_errors: dict[str, str] = field(default_factory=dict)  # 'framework#ordinal' -> error
    sh_totals: dict[str, int] = field(default_factory=dict)       # frameworks with every rule answered
    sh_incomplete: list[str] = field(default_factory=list)        # frameworks left out today
    sh_anchor_totals: dict[str, int] = field(default_factory=dict)
    sh_facet_short: list[str] = field(default_factory=list)       # rules whose network breakdown fell short
    # ---- both
    computed_rows: int = 0
    stored_rows: int = 0
    schema_bytes: int | None = None
    report_text: str = ""
    secrets: tuple[str, ...] = ()


def _n(xs) -> str:
    xs = sorted(xs)
    return ", ".join(xs[:6]) + (f" and {len(xs) - 6} more" if len(xs) > 6 else "")


# ---- offensive.agency ----------------------------------------------------------

def check_oa_reachable(f: Facts) -> EvalResult:
    """Without /status there is no day to file anything under."""
    ok = f.oa_status_before is not None and not any(e in f.oa_errors for e in OA_CRITICAL)
    bad = [e for e in OA_CRITICAL if e in f.oa_errors]
    return EvalResult(
        "oa_reachable", ERROR, ok,
        "offensive.agency answered status, the framework list and the timeline" if ok
        else "offensive.agency did not answer: " + ("; ".join(f"{e}: {f.oa_errors[e][:80]}" for e in bad)
                                                     or "status could not be read"),
        {"failed": bad})


def check_oa_fresh(f: Facts) -> EvalResult:
    """THE V1 FAILURE: a source that stopped updating keeps answering 200 with the same day.
    The source collects once a day, so 1 day behind is normal. 2-3 is a warning; from 4 the 7-day
    window we would publish is more than half stale and the run fails."""
    st = f.oa_status_before
    if st is None:
        return EvalResult("oa_fresh", ERROR, False, "no status, so the data's age is unknown", {})
    lag = (f.today - st.ref_day).days
    severity = ERROR if lag >= 4 else WARN
    return EvalResult("oa_fresh", severity, lag <= 1,
                      f"offensive.agency's data runs to {st.ref_day} ({lag} day(s) behind today)",
                      {"ref_day": str(st.ref_day), "lag_days": lag})


def check_oa_snapshot_consistent(f: Facts) -> EvalResult:
    """The host list is paged by offset. If the source's collector publishes between two pages,
    the pages describe different days and the counts are a mixture."""
    a, b = f.oa_status_before, f.oa_status_after
    ok = a is not None and b is not None and (a.ref_day, a.last_collection) == (b.ref_day, b.last_collection)
    return EvalResult(
        "oa_snapshot_consistent", ERROR, ok,
        "the source did not update while it was being read" if ok
        else "the source updated during the run (or status could not be re-read): the pages may mix two days",
        {})


def check_oa_endpoints(f: Facts) -> EvalResult:
    """One framework's profile failing is a transient on a ~95-request run and must not discard
    the day. More than a tenth failing is an outage."""
    share = len(f.oa_errors) / f.oa_requests if f.oa_requests else 1.0
    ok = f.oa_requests > 0 and share <= 0.10
    return EvalResult(
        "oa_endpoints_answered", ERROR, ok,
        f"{f.oa_requests - len(f.oa_errors)} of {f.oa_requests} requests answered"
        + (f"; failed: {_n(f.oa_errors)}" if f.oa_errors else ""),
        {"failed": sorted(f.oa_errors), "share": round(share, 3)})


def check_oa_hosts_complete(f: Facts) -> EvalResult:
    """Every page fetched and every record counted, against the total the API states. A short
    read stored as the day's figure would look like a drop in consoles."""
    stated, got = f.oa_hosts_stated, f.oa_hosts_counted + f.oa_hosts_malformed
    ok = (stated is not None and stated > 0 and got == stated
          and f.oa_hosts_malformed <= max(1, stated // 100))
    return EvalResult(
        "oa_hosts_complete", ERROR, ok,
        f"{f.oa_hosts_counted:,} host records counted of {stated if stated is not None else 'an unstated number'}"
        + (f", {f.oa_hosts_malformed} unreadable" if f.oa_hosts_malformed else ""),
        {"stated": stated, "counted": f.oa_hosts_counted, "malformed": f.oa_hosts_malformed})


def check_oa_counts_agree(f: Facts) -> EvalResult:
    """Two answers from the same source about the same thing: the framework list's active count
    and our own count of its host records. They disagree when the filter, the window or the
    response shape changed under us. Tolerance: 2%, at least 2."""
    off = {}
    for slug, listed in f.oa_listed_active.items():
        ours = f.oa_counted_active.get(slug, 0)
        if abs(ours - listed) > max(2, round(0.02 * max(listed, ours))):
            off[slug] = [listed, ours]
    return EvalResult(
        "oa_counts_agree", ERROR, bool(f.oa_listed_active) and not off,
        f"our count matches the source's own for all {len(f.oa_listed_active)} frameworks it lists as active"
        if not off and f.oa_listed_active
        else ("the source lists no active framework" if not f.oa_listed_active
              else "our count differs from the source's own for: "
                   + "; ".join(f"{s} (listed {a}, counted {b})" for s, (a, b) in sorted(off.items())[:5])),
        {"differ": off})


def check_oa_rules(f: Facts) -> EvalResult:
    """The owner asked for the detection rules, so "no rules at all" is a failed collection.
    A single tracked framework without rules is a warning: the source may simply not publish any."""
    total = sum(f.oa_rules.values())
    missing = sorted(s for s in f.oa_tracked if not f.oa_rules.get(s))
    if total == 0:
        return EvalResult("oa_rules_collected", ERROR, False,
                          "no detection rule was collected for any framework", {})
    return EvalResult(
        "oa_rules_collected", WARN, not missing,
        f"{total} detection rules across {sum(1 for v in f.oa_rules.values() if v)} frameworks"
        + (f"; tracked frameworks without any: {_n(missing)}" if missing else ""),
        {"rules": total, "tracked_without_rules": missing})


def check_oa_timeline(f: Facts) -> EvalResult:
    """A gap in the source's own history. WARN: one outage day upstream would otherwise fail
    every run from then on, and the gap is the source's, typed as not-collected."""
    days = sorted(set(f.oa_timeline_days))
    gaps = [str(a) for a, b in zip(days, days[1:]) if (b - a).days > 1]
    return EvalResult(
        "oa_timeline_contiguous", WARN, bool(days) and not gaps,
        f"the source's daily history covers {len(days)} consecutive days" if days and not gaps
        else ("the timeline is empty" if not days else f"the source's history has a gap after {_n(gaps)}"),
        {"days": len(days), "gaps_after": gaps})


# ---- Shodan ------------------------------------------------------------------

def check_shodan_reachable(f: Facts) -> EvalResult:
    ok = f.sh_info_status == 200 and f.sh_plan is not None
    hint = (" - Shodan refused SHODAN_API_KEY (revoked or mistyped): issue a new key and update the "
            "repository secret" if f.sh_info_status in (401, 403) else "")
    return EvalResult("shodan_reachable", ERROR, ok,
                      f"Shodan accepted the key (plan: {f.sh_plan})" if ok
                      else f"Shodan api-info answered {f.sh_info_status}{hint}",
                      {"status": f.sh_info_status})


def check_shodan_rules(f: Facts) -> EvalResult:
    """A framework with one unanswered rule is LEFT OUT for the day rather than stored short: a
    partial sum would read as a real fall. A few such gaps pass with the frameworks named; more
    than a tenth of all rules failing is an outage or a plan change."""
    share = len(f.sh_rule_errors) / f.sh_rules if f.sh_rules else 1.0
    ok = f.sh_rules > 0 and share <= 0.10
    first = next(iter(sorted(f.sh_rule_errors.items())), None)
    return EvalResult(
        "shodan_rules_answered", ERROR, ok,
        f"{f.sh_rules - len(f.sh_rule_errors)} of {f.sh_rules} rules returned a count"
        + (f"; left out today: {_n(f.sh_incomplete)}" if f.sh_incomplete else "")
        + (f"; first error: {first[1][:100]}" if first and not ok else ""),
        {"failed_rules": sorted(f.sh_rule_errors), "left_out": sorted(f.sh_incomplete), "share": round(share, 3)})


def check_shodan_not_empty(f: Facts) -> EvalResult:
    """Every rule answering 200 with zero is what a renamed filter or a silently downgraded plan
    looks like. It is not what the internet looks like."""
    total = sum(f.sh_totals.values())
    return EvalResult("shodan_not_silently_empty", ERROR, total > 0,
                      f"{total:,} services across {sum(1 for v in f.sh_totals.values() if v)} frameworks"
                      if total else "every rule answered and none found a service", {"services": total})


def check_shodan_anchor(f: Facts) -> EvalResult:
    """The best-known product label finding nothing. WARN, not ERROR: the framework really can
    disappear, and then the label going to zero is the news, not a fault."""
    zero = sorted(k for k, v in f.sh_anchor_totals.items() if v == 0)
    return EvalResult("shodan_anchor_rules", WARN, bool(f.sh_anchor_totals) and not zero,
                      "every anchor rule found services" if f.sh_anchor_totals and not zero
                      else ("no anchor rule returned a count" if not f.sh_anchor_totals
                            else f"anchor rule(s) found nothing: {_n(zero)}"),
                      {"zero": zero})


def check_shodan_facets(f: Facts) -> EvalResult:
    """The per-network breakdown should add up to (nearly) the rule's total. It falls short when
    the breakdown is cut at its size limit, and then small networks are missing from the page."""
    return EvalResult("shodan_network_breakdown_complete", WARN, not f.sh_facet_short,
                      "every rule's network breakdown covers its total" if not f.sh_facet_short
                      else f"{len(f.sh_facet_short)} rule(s) have a network breakdown below 80% of the "
                           f"total or cut at the size limit: {_n(f.sh_facet_short)}",
                      {"rules": sorted(f.sh_facet_short)})


# ---- both --------------------------------------------------------------------

def check_persisted(f: Facts) -> EvalResult:
    """Fetching cleanly and storing nothing once reported "safe to promote" in KEV."""
    ok = f.stored_rows == f.computed_rows and f.computed_rows > 0
    return EvalResult("persisted", ERROR, ok,
                      f"{f.stored_rows:,} of {f.computed_rows:,} computed rows written",
                      {"computed": f.computed_rows, "stored": f.stored_rows})


def check_bodies_kept(f: Facts) -> EvalResult:
    """An answer we meant to keep was withheld because it carries something address-shaped.
    Withholding is right; not noticing would quietly end the stored history of that answer.

    A framework PROFILE is expected to trip this now and then and does not fail the check: its
    free text describes what the framework does, and one (measured 2026-11-25) quotes the
    addresses it puts in a spoofed header. Its detection rules are parsed and stored either way;
    only the verbatim profile is not kept. A structural answer (status, the framework list, the
    timeline, statistics, clusters, co-hosting, map, facets) carrying an address is a change in
    the source and warns."""
    profiles = sorted(e for e in f.oa_withheld_unexpected if e.startswith("agent:"))
    structural = sorted(e for e in f.oa_withheld_unexpected if not e.startswith("agent:"))
    note = f"; {len(profiles)} framework profile(s) not kept verbatim (address-like text)" if profiles else ""
    return EvalResult("bodies_kept", WARN, not structural,
                      ("every structural answer was kept" if not structural
                       else f"withheld because they now carry an address: {_n(structural)}") + note,
                      {"withheld": structural, "profiles_not_kept": len(profiles)})


def check_storage(f: Facts) -> EvalResult:
    """The database is close to its size limit; this pipeline states its own footprint every run."""
    if f.schema_bytes is None:
        return EvalResult("storage_within_budget", INFO, True, "not measured (dry run)", {})
    mb = f.schema_bytes / 1048576
    return EvalResult("storage_within_budget", WARN, f.schema_bytes <= STORAGE_BUDGET_BYTES,
                      f"the three aof schemas hold {mb:.1f} MB (budget {STORAGE_BUDGET_BYTES // 1048576} MB)",
                      {"bytes": f.schema_bytes})


def check_no_secret_in_report(f: Facts) -> EvalResult:
    leaked = any(s and s in f.report_text for s in f.secrets) or bool(re.search(r"[?&]key=", f.report_text))
    return EvalResult("no_secret_in_report", ERROR, not leaked,
                      "no credential appears in the run report" if not leaked
                      else "a credential or a key= parameter is present in the run report", {})


def check_no_address_in_report(f: Facts) -> EvalResult:
    """The report and the logs are public. Counts only."""
    found = bool(IPV4.search(f.report_text.encode()))
    return EvalResult("no_address_in_report", ERROR, not found,
                      "no IP address appears in the run report" if not found
                      else "an IP address is present in the run report", {})


OA_CHECKS = (check_oa_reachable, check_oa_fresh, check_oa_snapshot_consistent, check_oa_endpoints,
             check_oa_hosts_complete, check_oa_counts_agree, check_oa_rules, check_oa_timeline)
SHODAN_CHECKS = (check_shodan_reachable, check_shodan_rules, check_shodan_not_empty,
                 check_shodan_anchor, check_shodan_facets)
COMMON_CHECKS = (check_persisted, check_bodies_kept, check_storage)
REPORT_CHECKS = (check_no_secret_in_report, check_no_address_in_report)


def evaluate(f: Facts, *, sources: tuple[str, ...] = ("offensive_agency", "shodan"),
             persisted: bool = True) -> list[EvalResult]:
    checks = []
    if "offensive_agency" in sources:
        checks += OA_CHECKS
    if "shodan" in sources:
        checks += SHODAN_CHECKS
    if persisted:
        checks += COMMON_CHECKS
    return [c(f) for c in checks]
