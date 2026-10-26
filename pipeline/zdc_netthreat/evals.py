"""Gate checks for the network threat atlas. ERROR blocks; WARN is visible; INFO is diagnostic.

Each exists because of a way this pipeline could be wrong and still look fine.
"""

from __future__ import annotations

import re

from zdc_crowdsec.evals import ERROR, INFO, WARN, EvalResult

#: What a healthy week looked like in the 2026-10-12 prototype, as floors far below it.
#: A source under its floor answered but carried almost nothing: a renamed field, an
#: expired key that returns 200 with an empty list, or a feed that stopped.
FLOORS = {"crowdsec": 10_000, "dshield": 5_000, "blocklist_de": 5_000, "cins": 5_000,
          "vulncheck": 2_000, "threatfox": 300, "urlhaus": 200, "phishing_db": 1_000,
          "shodan": 100, "spamhaus_asndrop": 100, "spamhaus_drop": 100, "uceprotect_l3": 100,
          "tor_exits": 300, "cloudflare": 1_000, "shadowserver_country": 1_000}
REQUIRED = ("crowdsec", "dshield", "blocklist_de", "cins", "vulncheck", "threatfox", "urlhaus",
            "phishing_db", "cloudflare")
#: Sources read as a snapshot of the moment the run fetches them (a trailing window: CrowdSec
#: since=7d, blocklist.de and ThreatFox 48 h, the others "current"), not bounded by the scored week.
#: VulnCheck, Cloudflare and Shadowserver are asked for the week's own dates and are not listed.
SNAPSHOT = ("crowdsec", "dshield", "blocklist_de", "cins", "threatfox", "urlhaus", "phishing_db", "shodan")
IP_RX = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")


def check_sources_answered(status: dict[str, tuple[bool, str | None]]) -> EvalResult:
    """Every scored source must answer. A missing one would score the week on the others
    and silently change what the score means."""
    bad = sorted(s for s in REQUIRED if not status.get(s, (False, "not run"))[0])
    return EvalResult("sources_answered", ERROR, not bad,
                      f"all {len(REQUIRED)} scored sources answered" if not bad
                      else "failed: " + "; ".join(f"{s} ({status.get(s, (0, 'not run'))[1]})" for s in bad),
                      {"failed": bad})


def check_volume_floors(volumes: dict[str, int], asked=()) -> EvalResult:
    """A source that was asked but recorded no volume carried nothing: that is a zero, not
    a pass (DShield answered 200 with an empty table on 2026-10-13 and went unnoticed)."""
    low = {s: volumes.get(s, 0) for s in {*volumes, *asked} if s in FLOORS and volumes.get(s, 0) < FLOORS[s]}
    return EvalResult("volume_floors", ERROR, not low,
                      "every source above its floor" if not low
                      else "below floor: " + ", ".join(f"{s} {v:,} < {FLOORS[s]:,}" for s, v in low.items()),
                      {"low": low})


def check_mapping(ipv4: int, unmapped: int) -> EvalResult:
    """Most attack IPs sit in routed space. A jump in unmapped IPs means the routing
    table is stale or truncated, and every count would be too low."""
    share = unmapped / ipv4 if ipv4 else 1.0
    return EvalResult("ips_mapped", ERROR, share <= 0.05,
                      f"{share:.1%} of {ipv4:,} IPv4 addresses unrouted", {"share": round(share, 4)})


def check_shodan_coverage(coverage: dict | None) -> EvalResult:
    """Shodan's plan caps a facet at 1,000 networks. The adapter splits a capped tag by
    country; if that split failed the count is silently a top-1,000 sample again. WARN when
    any tag's hosts placed in a network fall under 97% of the tag's total (hosts with no
    network in Shodan's index account for about 1%)."""
    if not coverage:
        return EvalResult("shodan_coverage", WARN, False, "no Shodan coverage recorded", {})
    low = {t: c for t, c in coverage.items() if c["total"] and c["in_networks"] / c["total"] < 0.97}
    parts = ", ".join(f"{t} {c['in_networks']:,}/{c['total']:,}" for t, c in coverage.items())
    return EvalResult("shodan_coverage", WARN, not low,
                      f"hosts placed in a network: {parts}", {"coverage": coverage})


def check_no_ip_stored(conn) -> EvalResult:
    """The licence and data protection both forbid storing addresses. The schema has no
    IP column; this checks the free-text and JSON columns too."""
    with conn.cursor() as cur:
        cur.execute("""select count(*) from net_raw.asn_counts where categories::text ~ '\\d+\\.\\d+\\.\\d+\\.\\d+'""")
        a = cur.fetchone()[0]
        cur.execute("""select count(*) from net_raw.fetches where coalesce(error,'') ~ '\\d+\\.\\d+\\.\\d+\\.\\d+'""")
        b = cur.fetchone()[0]
    return EvalResult("no_ip_stored", ERROR, a + b == 0,
                      "no IP address in stored categories or errors" if a + b == 0
                      else f"{a + b} stored rows contain an IP-like string", {"rows": a + b})


def check_no_secret(report_text: str, secrets: dict) -> EvalResult:
    leaked = [k for k, v in secrets.items() if v and len(v) >= 8 and v in report_text]
    return EvalResult("no_secret_in_report", ERROR, not leaked,
                      "no credential in the run report" if not leaked else f"leaked: {leaked}", {})


def check_week_replaced(conn, week_start, method_version: str) -> EvalResult:
    """A rebuild REPLACES its week. Two rows for one network in one week means a rebuild
    appended, and every weekly series would quietly double."""
    with conn.cursor() as cur:
        cur.execute("""select count(*) - count(distinct asn) from net_derived.network_scores
                        where week_start = %s and method_version = %s""", (week_start, method_version))
        dup = cur.fetchone()[0]
        cur.execute("""select count(*) from net_derived.network_scores
                        where week_start = %s and method_version = %s""", (week_start, method_version))
        n = cur.fetchone()[0]
    return EvalResult("week_replaced", ERROR, dup == 0 and n > 0,
                      f"{n:,} networks scored once each" if dup == 0 and n > 0
                      else f"{dup} duplicate rows, {n} rows", {"rows": n, "duplicates": dup})


def check_model_sane(prevalence: float, hit_rates: dict[str, float]) -> EvalResult:
    """A latent-class fit can collapse (prevalence 0 or 1) or swap its classes. Either
    makes the score meaningless while every number stays between 0 and 1."""
    ok = 0.001 < prevalence < 0.5 and max(hit_rates.values(), default=0) > 0.2
    return EvalResult("model_sane", ERROR, ok,
                      f"prevalence {prevalence:.1%}, best hit rate {max(hit_rates.values(), default=0):.0%}",
                      {"prevalence": prevalence, "hit_rates": hit_rates})


def check_dshield_scale(scale: dict | None) -> EvalResult:
    """DShield's table changed scale on 2026-10-09 (10,000th source: 281 targets -> 1).
    Recorded every week, so a future change shows up as a step here and not as a trend."""
    m = (scale or {}).get("min_attacks")
    return EvalResult("dshield_scale", WARN, m is not None,
                      f"10,000th source attacked {m} targets; median {((scale or {}).get('median_attacks'))}",
                      scale or {})


# ---- v2 ------------------------------------------------------------------------------------
def check_v2_converged(summary: dict) -> EvalResult:
    """An EM fit that stopped at its iteration cap is not a result; the rows are stored as
    provisional and the week is red until a human looks."""
    bad = {s: v for s, v in summary.items() if s in ("attack", "host") and v["feeds"] and not v["converged"]}
    return EvalResult("v2_converged", ERROR, not bad,
                      "both sides converged: " + ", ".join(f"{s} {summary[s]['iterations']} it/{summary[s]['seconds']}s"
                                                           for s in ("attack", "host") if summary[s]["feeds"])
                      if not bad else "not converged: " + ", ".join(f"{s} ({v['iterations']} iterations)" for s, v in bad.items()),
                      {s: {"iterations": summary[s]["iterations"], "seconds": summary[s]["seconds"]} for s in ("attack", "host")})


def check_v2_feeds_present(summary: dict) -> EvalResult:
    """A side scored on fewer feeds than it names is a different measurement. WARN, and the
    rows carry provisional = true; ERROR only when a side has no feed at all."""
    absent = {s: summary[s]["absent"] for s in ("attack", "host") if summary[s]["absent"]}
    empty = [s for s in ("attack", "host") if not summary[s]["feeds"]]
    if empty:
        return EvalResult("v2_feeds_present", ERROR, False, f"no feed on side: {', '.join(empty)}", {"absent": absent})
    return EvalResult("v2_feeds_present", WARN, not absent,
                      "every feed present on both sides" if not absent
                      else "absent: " + "; ".join(f"{s}: {', '.join(v)}" for s, v in absent.items()), {"absent": absent})


def check_v2_listed_bounds(summary: dict, lo: dict[str, int] | None = None, hi: int = 300) -> EvalResult:
    """Listed counts far outside the measured range mean a scale change in a feed, a broken
    gate, or an empty week, not a changed internet. The hosting side's list is short by
    construction (three feeds, ~7x less mass than the attack side: 2-3 listed on 2026-10-05),
    so its floor is 1."""
    lo = lo or {"attack": 3, "host": 1}
    counts = {s: summary[s]["listed"] for s in ("attack", "host") if summary[s]["feeds"]}
    bad = {s: n for s, n in counts.items() if not (lo[s] <= n <= hi)}
    return EvalResult("v2_listed_bounds", WARN, not bad,
                      "listed: " + ", ".join(f"{s} {n}" for s, n in counts.items()) + ("" if not bad else " (outside " + ", ".join(f"{s} {lo[s]}..{hi}" for s in bad) + ")"),
                      {"listed": counts})


def check_v2_single_feed(summary: dict, cap: float = 0.75) -> EvalResult:
    """When one feed supplies more than three quarters of a side's appearances the side is
    that feed's opinion. Shown, so the dependence is never silent (CrowdSec was 57% on 2026-10-05)."""
    worst = {}
    for s in ("attack", "host"):
        sh = summary[s].get("top_feed_share") or {}
        if sh:
            f, v = max(sh.items(), key=lambda kv: kv[1])
            worst[s] = (f, v)
    bad = {s: fv for s, fv in worst.items() if fv[1] > cap}
    return EvalResult("v2_single_feed", WARN, not bad,
                      "largest feed share: " + ", ".join(f"{s} {f} {v:.0%}" for s, (f, v) in worst.items()),
                      {"top": {s: {"feed": f, "share": v} for s, (f, v) in worst.items()}})


def check_v2_rows_sane(rows: list) -> EvalResult:
    """No NaN or infinity reaches the table, the floor never exceeds the mode, masses are
    finite and non-negative, and every stored network has both sides or a reason not to."""
    import math as _m
    bad = 0
    for r in rows:
        lo_x, best_x, se, mass = r[2], r[3], r[4], r[5]
        if any(v is None or not _m.isfinite(v) for v in (lo_x, best_x, se, mass)) or lo_x > best_x * 1.0001 or mass < 0 or lo_x <= 0:
            bad += 1
    return EvalResult("v2_rows_sane", ERROR, bad == 0 and len(rows) > 0,
                      f"{len(rows):,} rows, all finite and ordered" if bad == 0 and rows else f"{bad} bad rows of {len(rows)}",
                      {"rows": len(rows), "bad": bad})


def check_v2_week_replaced(conn, week_start, method_version: str) -> EvalResult:
    with conn.cursor() as cur:
        cur.execute("""select count(*) - count(distinct (asn, side)), count(*) from net_derived.network_scores_v2
                        where week_start = %s and method_version = %s""", (week_start, method_version))
        dup, n = cur.fetchone()
    return EvalResult("v2_week_replaced", ERROR, dup == 0 and n > 0,
                      f"{n:,} network-sides scored once each" if dup == 0 and n > 0 else f"{dup} duplicate rows, {n} rows",
                      {"rows": n, "duplicates": dup})


def check_v2_listed_jump(conn, week_start, method_version: str, summary: dict, factor: float = 3.0) -> EvalResult:
    """Against the previous scored week: a listed count that tripled or fell to a third is a
    feed-scale event until proven otherwise (the DShield 2026-10-09 step would have shown here).
    Suppressed (INFO) when the overlap moved from assumed to measured: that step is expected."""
    with conn.cursor() as cur:
        cur.execute("""select side, notes->>'union_source' from net_derived.fits_v2
                        where method_version = %s and not provisional
                          and week_start = (select max(week_start) from net_derived.fits_v2
                                             where method_version = %s and week_start < %s and not provisional)""",
                    (method_version, method_version, week_start))
        prev_src = dict(cur.fetchall())
    changed = [s for s in ("attack", "host") if prev_src.get(s) and prev_src[s] != summary[s].get("union_source")]
    if changed:
        return EvalResult("v2_listed_jump", INFO, True,
                          "overlap source changed (" + ", ".join(f"{s} {prev_src[s]} -> {summary[s].get('union_source')}" for s in changed)
                          + "); the list step this week is expected, not compared", {"changed": changed})
    with conn.cursor() as cur:
        # the baseline is the latest NON-provisional week: a blocked or feed-short week is not a baseline
        cur.execute("""select side, listed from net_derived.fits_v2
                        where method_version = %s and not provisional
                          and week_start = (select max(week_start) from net_derived.fits_v2
                                             where method_version = %s and week_start < %s and not provisional)""",
                    (method_version, method_version, week_start))
        prev = dict(cur.fetchall())
    if not prev:
        return EvalResult("v2_listed_jump", INFO, True, "first scored week; nothing to compare", {})
    jumps = {}
    for s in ("attack", "host"):
        now, before = summary[s]["listed"], prev.get(s)
        if before is None or not summary[s]["feeds"]:
            continue
        if max(now, 1) / max(before, 1) > factor or max(before, 1) / max(now, 1) > factor:
            jumps[s] = (before, now)
    return EvalResult("v2_listed_jump", WARN, not jumps,
                      "listed counts in line with last week" if not jumps
                      else "jump: " + ", ".join(f"{s} {b} -> {n}" for s, (b, n) in jumps.items()), {"previous": prev, "jumps": jumps})


def check_v2_fit_sane(summary: dict) -> EvalResult:
    """The fit's shape, not its answer: the prior spread tau sits in a plausible band (0.5..4 on
    log intensity; 2.2-2.3 measured) and the pinned internet average is 1 (|ref| small). A tau
    near zero means every network collapsed onto the prior; a huge one, a degenerate ridge."""
    bad = {}
    for s in ("attack", "host"):
        v = summary[s]
        if not v["feeds"]:
            continue
        tau, ref = v.get("tau"), v.get("ref")
        if tau is None or not (0.5 <= tau <= 4.0) or ref is None or abs(ref) > 0.05:
            bad[s] = (tau, ref)
    return EvalResult("v2_fit_sane", ERROR, not bad,
                      "tau and the pinned average in range: " + ", ".join(f"{s} tau {summary[s].get('tau')} ref {summary[s].get('ref')}"
                                                                          for s in ("attack", "host") if summary[s]["feeds"])
                      if not bad else "out of range: " + ", ".join(f"{s} tau {t} ref {r}" for s, (t, r) in bad.items()),
                      {s: {"tau": summary[s].get("tau"), "ref": summary[s].get("ref")} for s in ("attack", "host")})


def check_v2_feed_totals(conn, week_start, method_version: str, summary: dict, factor: float = 2.0) -> EvalResult:
    """Each feed's summed appearances against the previous scored week: a doubling or halving
    is a feed-scale event (DShield halved between two fetches of the same week in the review
    and passed every other check), shown so it is never silent."""
    with conn.cursor() as cur:
        cur.execute("""select side, feed_total from net_derived.fits_v2
                        where method_version = %s and not provisional
                          and week_start = (select max(week_start) from net_derived.fits_v2
                                             where method_version = %s and week_start < %s and not provisional)""",
                    (method_version, method_version, week_start))
        prev = {side: ft for side, ft in cur.fetchall()}
    if not prev:
        return EvalResult("v2_feed_totals", INFO, True, "first scored week; nothing to compare", {})
    jumps = {}
    for s in ("attack", "host"):
        for f, now in (summary[s].get("feed_total") or {}).items():
            before = (prev.get(s) or {}).get(f)
            if before and now and (now / before > factor or before / now > factor):
                jumps[f] = (before, now)
    return EvalResult("v2_feed_totals", WARN, not jumps,
                      "every feed within 2x of last week" if not jumps
                      else "scale change: " + ", ".join(f"{f} {b:,} -> {n:,}" for f, (b, n) in jumps.items()),
                      {"jumps": jumps})


# ---- v2, week 2 onwards (review round 6): comparisons against the last non-provisional week ---
def check_v2_union_measured(summary: dict, side_union_stored: dict[str, bool]) -> EvalResult:
    """Once a week's collect stored a per-side union, the fit must have used it. An assumed
    overlap after that means the union insert failed or the wrong run was picked."""
    bad = {s: summary[s].get("union_source") for s in ("attack", "host")
           if summary[s]["feeds"] and side_union_stored.get(s) and summary[s].get("union_source") != "side"}
    return EvalResult("v2_union_measured", ERROR, not bad,
                      "overlap: " + ", ".join(f"{s} {summary[s].get('union_source')}" for s in ("attack", "host") if summary[s]["feeds"])
                      if not bad else "stored union not used: " + ", ".join(f"{s} ({v})" for s, v in bad.items()),
                      {"union_source": {s: summary[s].get("union_source") for s in ("attack", "host")}})


def check_v2_rho_range(summary: dict, lo: float = 0.3, hi: dict | None = None) -> EvalResult:
    """A measured de-duplication factor sits between 0.3 and its side's ceiling; a clamp at 1.0 or
    0.05 is the wrong run's union or a unit error (the first live run clamped at 1).

    The ceiling differs by side. Attack feeds report the same scanners, so their /24s overlap
    (0.85 measured, week of 2026-10-12). Host feeds list different things - C2 addresses,
    malware URLs, phishing hosts - and barely overlap: 9,186 distinct /24s of 9,291 listed
    (0.989) that week. A 0.95 ceiling failed that real measurement; 0.995 still catches the clamp."""
    hi = {"attack": 0.95, "host": 0.995, **(hi or {})}
    bad = {}
    for s in ("attack", "host"):
        v = summary[s]
        if not v["feeds"] or str(v.get("union_source", "")).startswith("assumed"):
            continue
        r = v.get("rho_union")
        if r is None or not (lo <= r <= hi[s]):
            bad[s] = r
    return EvalResult("v2_rho_range", ERROR, not bad,
                      "rho: " + ", ".join(f"{s} {summary[s].get('rho_union')} ({summary[s].get('union_source')})" for s in ("attack", "host") if summary[s]["feeds"])
                      if not bad else "rho out of range: " + ", ".join(f"{s} {r}" for s, r in bad.items()),
                      {"rho": {s: summary[s].get("rho_union") for s in ("attack", "host")}})


def check_v2_param_drift(fits: list[dict], prev: dict[str, dict] | None) -> EvalResult:
    """Against the last non-provisional week: a feed calibration moving by more than 0.5 on
    the log scale, a dispersion by more than 3x, or tau by more than 0.3 is a feed event,
    not a changed internet. `prev` is side -> {alpha, phi, tau}."""
    if not prev:
        return EvalResult("v2_param_drift", INFO, True, "first comparable week; nothing to compare", {})
    moves = []
    for f in fits:
        p = prev.get(f["side"])
        if not p:
            continue
        for feed, a in f["alpha"].items():
            pa = (p.get("alpha") or {}).get(feed)
            if pa is not None and abs(a - pa) > 0.5:
                moves.append(f"{f['side']} {feed} alpha {pa:+.2f}->{a:+.2f}")
        for feed, ph in f["phi"].items():
            pp = (p.get("phi") or {}).get(feed)
            if pp and ph and max(ph / pp, pp / ph) > 3:
                moves.append(f"{f['side']} {feed} phi {pp:.2f}->{ph:.2f}")
        if p.get("tau") is not None and abs(f["tau"] - p["tau"]) > 0.3:
            moves.append(f"{f['side']} tau {p['tau']:.2f}->{f['tau']:.2f}")
    return EvalResult("v2_param_drift", WARN, not moves,
                      "feed calibrations within range of last week" if not moves else "drift: " + "; ".join(moves), {"moves": moves})


def check_v2_floor_stability(rows: list, prev_rows: dict[tuple[int, str], tuple[float, bool]] | None,
                             min_rho: float = 0.85) -> EvalResult:
    """Spearman of this week's floors against last week's over the networks with rows in both,
    per side. Replicate fetches of one week gave 0.98-0.99; two genuine weeks will be lower,
    and under 0.85 something other than the internet moved."""
    if not prev_rows:
        return EvalResult("v2_floor_stability", INFO, True, "first comparable week; nothing to compare", {})
    from .model_v2 import spearman
    import numpy as np
    out, bad = {}, {}
    for side in ("attack", "host"):
        pairs = [(r[2], prev_rows[(r[0], r[1])][0]) for r in rows if r[1] == side and (r[0], r[1]) in prev_rows]
        if len(pairs) < 30:
            continue
        a = np.log(np.array([p[0] for p in pairs])); b = np.log(np.array([p[1] for p in pairs]))
        rho = spearman(a, b)
        out[side] = (None if rho is None else round(rho, 3), len(pairs))
        if rho is not None and rho < min_rho:
            bad[side] = round(rho, 3)
    return EvalResult("v2_floor_stability", WARN, not bad,
                      "floors vs last week: " + ", ".join(f"{s} Spearman {v[0]} over {v[1]:,}" for s, v in out.items())
                      if not bad else "unstable: " + ", ".join(f"{s} Spearman {v}" for s, v in bad.items()), {"spearman": out})


def check_v2_list_exodus(rows: list, prev_rows: dict[tuple[int, str], tuple[float, bool]] | None, cap: float = 0.3) -> EvalResult:
    """More than 30% of last week's list gone in one week is a bad week until proven otherwise.
    A network that left because it has no evidence row this week counts as gone."""
    if not prev_rows:
        return EvalResult("v2_list_exodus", INFO, True, "first comparable week; nothing to compare", {})
    now = {(r[0], r[1]) for r in rows if r[9]}
    out, bad = {}, {}
    for side in ("attack", "host"):
        was = {k for k, v in prev_rows.items() if k[1] == side and v[1]}
        if not was:
            continue
        gone = len(was - now)
        out[side] = (gone, len(was))
        if gone / len(was) > cap:
            bad[side] = out[side]
    return EvalResult("v2_list_exodus", WARN, not bad,
                      "left the list: " + ", ".join(f"{s} {g} of {w}" for s, (g, w) in out.items())
                      if not bad else "exodus: " + ", ".join(f"{s} {g} of {w}" for s, (g, w) in bad.items()), {"left": out})


def check_v2_checks_drift(summary: dict, prev_checks: dict | None, auc_floor: float = 0.6, drop: float = 0.1, net_band: float = 0.3) -> EvalResult:
    """The weekly self-checks against last week's: AUC vs ASN-DROP under 0.6 or down by more
    than 0.1, or the count of evidence networks moving by more than 30%."""
    ck = summary.get("checks") or {}
    bad = []
    for s in ("attack", "host"):
        v = ck.get(f"auc_asndrop_{s}")
        if v is not None and v < auc_floor:
            bad.append(f"{s} AUC {v:.2f} < {auc_floor}")
        pv = (prev_checks or {}).get(f"auc_asndrop_{s}")
        if v is not None and pv is not None and pv - v > drop:
            bad.append(f"{s} AUC {pv:.2f}->{v:.2f}")
    n, pn = ck.get("evidence_networks"), (prev_checks or {}).get("evidence_networks")
    if n and pn and (abs(n - pn) / pn) > net_band:
        bad.append(f"evidence networks {pn:,}->{n:,}")
    sev = WARN if prev_checks else INFO
    return EvalResult("v2_checks_drift", sev, not bad,
                      "self-checks in line" + ("" if prev_checks else " (first comparable week)") if not bad else "; ".join(bad),
                      {"checks": ck, "previous": prev_checks})


def check_v2_forward(conn, method_version: str = "v2") -> EvalResult:
    """Forward validation (0103): printed from week 2, called credible at 8 weeks. INFO only."""
    try:
        with conn.cursor() as cur:
            cur.execute("select week_start, side, n, auc_band2, spearman_mass, survival_k1 from net_derived.v2_forward(%s)", (method_version,))
            rows = cur.fetchall()
    except Exception as exc:  # noqa: BLE001 - the function may not exist yet; this is diagnostic
        conn.rollback()
        return EvalResult("v2_forward", INFO, True, f"forward validation unavailable ({type(exc).__name__})", {})
    if not rows:
        return EvalResult("v2_forward", INFO, True, "forward validation needs two non-provisional weeks", {})
    last = rows[-2:]
    txt = "; ".join(f"{w} {s}: AUC {a if a is None else round(a, 2)}, Spearman {sp if sp is None else round(sp, 2)}, kept {k if k is None else round(k, 2)}"
                    for w, s, n, a, sp, k in last)
    return EvalResult("v2_forward", INFO, True, f"{len(rows)//2} week pair(s); latest: {txt}" + ("" if len(rows) >= 14 else " (credible at 8 weeks)"),
                      {"pairs": [[str(w), s, n, a, sp, k] for w, s, n, a, sp, k in rows]})


def check_netblock(conn, week_start, method_version: str = "v2") -> EvalResult:
    """The netblock map (0112) must add up: its routed /24s equal the routing file's, and its listed
    /24s equal the routed size of the listed networks. WARN: the map is a view, the scores stand."""
    with conn.cursor() as cur:
        cur.execute("select to_regclass('net_derived.netblock_v2') is not null")
        if not cur.fetchone()[0]:
            return EvalResult("netblock", INFO, True, "netblock map not in this schema", {})
        cur.execute("""select coalesce(sum(routed24), 0), coalesce(sum(listed24), 0), count(*), max(routing_file)
                         from net_derived.netblock_v2 where week_start = %s and method_version = %s""", (week_start, method_version))
        routed, listed, cells, f = cur.fetchone()
        if not cells:
            return EvalResult("netblock", WARN, False, "no netblock map written this week", {})
        cur.execute("select routed24 from net_core.routing_files where routing_file = %s", (f,))
        r = cur.fetchone()
        # any origin listed (MOAS runs count once), the same rule the map uses
        cur.execute("""select coalesce(sum(hi24 - lo24 + 1), 0) from net_core.routed_runs r
                        where r.routing_file = %s
                          and exists (select 1 from net_derived.network_scores_v2 s
                                       where s.week_start = %s and s.method_version = %s and s.listed
                                         and s.asn = any(array[r.asn] || coalesce(r.moas, '{}'::bigint[])))""",
                    (f, week_start, method_version))
        want_listed = cur.fetchone()[0]
    ok = r is not None and r[0] == routed and want_listed == listed
    return EvalResult("netblock", WARN, ok,
                      f"{cells:,} routed /16s, {routed:,} /24s, {listed:,} in listed networks" if ok
                      else f"map does not add up: routed {routed:,} vs file {r[0] if r else None}, listed {listed:,} vs {want_listed:,}",
                      {"cells": cells, "routed24": routed, "listed24": listed})


# ---- collection timing (audit 2026-10-26) ----------------------------------------------------
def check_collection_lag(lags: dict[str, float], warn_h: float = 24, block_h: float = 48) -> EvalResult:
    """Hours between the end of the scored week and the fetch of each snapshot source. The week
    labelled 2026-10-12 was fetched on 2026-10-21: blocklist.de's 48 hours lay wholly in the next
    week and CrowdSec's 7 days overlapped the labelled week by 4.6, yet every gate passed. A fetch
    more than `block_h` hours after the week ends scores mostly other days: ERROR, so the week is
    served as provisional. Over `warn_h` (a Tuesday retry) is shown."""
    late = {s: round(h, 1) for s, h in lags.items() if s in SNAPSHOT and h > warn_h}
    worst = max((lags[s] for s in lags if s in SNAPSHOT), default=None)
    if worst is None:
        return EvalResult("collection_lag", WARN, False, "no snapshot fetch recorded for this week", {})
    blocked = {s: h for s, h in late.items() if h > block_h}
    if blocked:
        return EvalResult("collection_lag", ERROR, False,
                          f"fetched {max(blocked.values()):.0f} h after the week ended (limit {block_h:.0f} h): "
                          + ", ".join(sorted(blocked)) + " cover mostly later days", {"late": late})
    return EvalResult("collection_lag", WARN, not late,
                      f"snapshot sources fetched within {worst:.0f} h of the week's end" if not late
                      else "fetched late: " + ", ".join(f"{s} {h:.0f} h" for s, h in sorted(late.items())),
                      {"late": late, "worst_h": round(worst, 1)})


def check_feeds_changed(unchanged: list[str]) -> EvalResult:
    """A scored feed whose content is byte-identical to the previous week's has stopped updating
    upstream (Phishing.Database's IP list last changed 2026-09-26 and was scored for two more weeks
    as if fresh). WARN: the counts are real but old, and the feed's owner needs telling."""
    return EvalResult("feeds_changed", WARN, not unchanged,
                      "every scored feed changed since the previous week" if not unchanged
                      else "unchanged since the previous week (stale upstream?): " + ", ".join(sorted(unchanged)),
                      {"unchanged": sorted(unchanged)})
