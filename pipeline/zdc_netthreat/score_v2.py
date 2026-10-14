"""Scoring a week with network_threat_score v2: from stored counts to rows, no database inside.

`score_week` is a pure function of what the pipeline stored for the week: per-feed counts for
the networks with evidence, the routed size of EVERY network, each network's type, the per-side
unions, and who was listed last week. It returns the rows for net_derived.network_scores_v2 and
net_derived.fits_v2 plus a summary the evals read. Nothing here knows about psycopg, so the
whole scoring path is unit-testable with a dozen synthetic networks.
"""

from __future__ import annotations

import datetime as dt
import math

import numpy as np

from . import model_v2 as m

#: A feed under this many summed appearances this week is ABSENT from its side: it answered
#: but carried nothing (the DShield precedent of 2026-10-13), and fitting it would make the fit
#: believe every network is clean on that feed. Same floors as evals.FLOORS where they exist,
#: counted in /24 appearances rather than IPs.
ABSENT_FLOOR = {"crowdsec": 2_000, "dshield": 500, "blocklist_de": 500, "cins": 500, "vulncheck": 300,
                "threatfox": 100, "urlhaus": 60, "phishing_db": 200, "shodan": 500}
#: A week without a per-side union (collected before 0102) cannot measure its overlap: the
#: all-feed union divided by one side's sum is not a de-duplication factor (its numerator holds
#: the other side's /24s; it clamped at 1 on 2026-10-05 and inflated attack mass ~1.6x). The
#: measured all-feed value from the scoring review is assumed instead.
RHO_ASSUMED = 0.63


#: Feeds that report addresses. Shodan reports host counts per network with no /24 detail.
IP_FEEDS = frozenset(("crowdsec", "dshield", "blocklist_de", "cins", "vulncheck", "threatfox", "urlhaus", "phishing_db"))


def expected_occupied_24s(hosts: float, s24: int) -> float:
    """How many of a network's /24s `hosts` addresses occupy if placed at random: s24 (1 - e^(-h/s24)).
    Two hosts in a /23 occupy 1.26 blocks, not 2; 500 hosts in 20 blocks occupy 20."""
    if hosts <= 0 or s24 <= 0:
        return 0.0
    return float(s24 * (1.0 - math.exp(-hosts / s24)))


def feed_counts(counts: dict[str, dict[int, tuple]], feed: str, size24: dict[int, int]) -> tuple[dict[int, float], int]:
    """Occupied /24s per ASN for one feed, and how many listed ASNs were unrouted (no size this
    week) and therefore dropped: they have no fair share. Shodan is host counts, turned into the
    /24s they would occupy at random placement until the pipeline stores Shodan /24s; the earlier
    cap min(hosts, s24) saturated every small network (58 of them on 2026-10-05)."""
    out, dropped = {}, 0
    for a, v in counts.get(feed, {}).items():
        s = size24.get(a, 0)
        if s <= 0:
            dropped += 1
            continue
        out[a] = expected_occupied_24s(v[0], s) if feed == "shodan" else float(min(v[1], s))
    return out, dropped


def side_input(side: str, counts: dict[str, dict[int, tuple]], size24: dict[int, int], routed_total: int,
               union: dict[int, tuple[int, int]] | None, force_absent: frozenset[str] = frozenset(),
               rho_fixed: float | None = None) -> tuple[m.SideInput | None, list[str], list[str], dict[str, int]]:
    """Build the fit input for one side. Returns (input or None, feeds used, feeds absent,
    unrouted ASNs dropped per feed). A feed in `force_absent` (a coverage failure the caller
    detected) is treated like an absent one."""
    asns = np.array(sorted(a for a, s in size24.items() if s > 0), dtype=np.int64)
    idx = {int(a): i for i, a in enumerate(asns)}
    s24 = np.array([size24[int(a)] for a in asns], dtype=float)
    used, absent, cols, totals, dropped = [], [], [], [], {}
    for f in m.SIDES[side]:
        fc, drop = feed_counts(counts, f, size24)
        dropped[f] = drop
        tot = sum(fc.values())
        if f not in counts or tot < ABSENT_FLOOR[f] or f in force_absent:
            absent.append(f)
            continue
        col = np.zeros(len(asns))
        for a, n in fc.items():
            col[idx[a]] = n
        used.append(f)
        cols.append(col)
        totals.append(float(tot))
    if not used or sum(totals) <= 0:
        return None, [], absent + used, dropped
    union_24s = float(sum(n for _, n in union.values())) if union else None
    return m.SideInput(asns=asns, s24=s24, feeds=used, counts=np.stack(cols, 1), totals=np.array(totals),
                       routed_total=float(routed_total), union_24s=union_24s,
                       ip_feeds=tuple(f in IP_FEEDS for f in used), rho_fixed=rho_fixed), used, absent, dropped


def score_week(week: dt.date, counts: dict[str, dict[int, tuple]], size24: dict[int, int], routed_total: int,
               types: dict[int, str], unions: dict[str, dict[int, tuple[int, int]]], prev_listed: dict[str, set[int]],
               universe: list[int], fallback_union: dict[int, tuple[int, int]] | None = None,
               force_absent: frozenset[str] = frozenset(), asndrop: set[int] | None = None) -> dict:
    """Fit both sides and assemble the rows. `universe` is the set of networks the atlas will show
    (rows are stored for them); `fallback_union` is the all-feed union, used for a side whose own
    union was not stored (weeks before 0102)."""
    censored = week + dt.timedelta(days=6)
    fits: dict[str, m.SideFit | None] = {}
    meta: dict[str, dict] = {}
    for side in m.SIDES:
        uni = unions.get(side) or None
        inp, used, absent, dropped = side_input(side, counts, size24, routed_total, uni, force_absent,
                                                rho_fixed=None if uni else RHO_ASSUMED)
        meta[side] = {"feeds": used, "absent": absent, "union_source": "side" if uni else f"assumed_{RHO_ASSUMED}",
                      "unrouted_dropped": dropped}
        fits[side] = m.fit_side(inp) if inp is not None else None
    # ---- per-network rows for the atlas universe ------------------------------------------
    uset = sorted(set(universe))
    rows, listed_count = [], {"attack": 0, "host": 0}
    per_side_ref: dict[str, dict] = {}
    for side, fit in fits.items():
        if fit is None:
            continue
        idx = {int(a): i for i, a in enumerate(fit.asns)}
        # the type reference and own_x both use the posterior MEAN intensity (E[e^theta]), the same
        # quantity the internet average is pinned on, so own_x = 1 means "average for its type"
        rel_mean = np.log(np.maximum(fit.e_exp, 1e-12)) - fit.ref
        tref = m.type_reference(fit.asns, np.array([size24[int(a)] for a in fit.asns], float), rel_mean, types)
        per_side_ref[side] = {"idx": idx, "tref": tref}
    bands: dict[int, int] = {}
    side_rows: dict[int, dict[str, tuple]] = {}
    for a in uset:
        lo_x, listed_s = {}, {}
        for side, fit in fits.items():
            if fit is None or a not in per_side_ref[side]["idx"]:
                continue
            i = per_side_ref[side]["idx"][a]
            lx = math.exp(fit.lo[i])
            mass = float(fit.mass[i])
            was = a in prev_listed.get(side, set())
            lst = m.listed(lx, mass, was)
            lo_x[side], listed_s[side] = lx, lst
            tref = per_side_ref[side]["tref"].get(types.get(a, ""), None)
            best = math.exp(fit.theta[i])
            mean_rel = float(fit.e_exp[i]) / math.exp(fit.ref)
            comp = {f: round(float(fit.contrib[i, j]), 4) for j, f in enumerate(fit.feeds)} if fit.obs[i] > 0 else None
            n = {f: int(round(float(fit.counts[i, j]))) for j, f in enumerate(fit.feeds)} if fit.obs[i] > 0 else None
            side_rows.setdefault(a, {})[side] = (
                lx, best, float(fit.se[i]), mass, int(fit.obs[i]),
                (mean_rel / tref) if tref else None,
                None if math.isnan(fit.top_share[i]) else float(fit.top_share[i]),
                lst, comp, n)
            if lst:
                listed_count[side] += 1
        bands[a] = m.band(lo_x.get("attack"), lo_x.get("host"), listed_s.get("attack", False), listed_s.get("host", False))
    provisional_side = {side: (fit is None or not fit.converged or bool(meta[side]["absent"])) for side, fit in fits.items()}
    for a, sides in side_rows.items():
        for side, r in sides.items():
            rows.append((a, side, *r[:8], bands[a], r[8], r[9], provisional_side[side], censored))
    # ---- per-side fit rows --------------------------------------------------------------------
    fit_rows = []
    for side, fit in fits.items():
        if fit is None:
            continue
        mass = np.asarray(fit.mass)
        order = np.sort(mass)[::-1]
        tot = float(mass.sum()) or 1.0
        fit_rows.append({
            "side": side, "feeds": fit.feeds, "absent_feeds": meta[side]["absent"],
            "alpha": {f: round(float(v), 4) for f, v in zip(fit.feeds, fit.alpha)},
            "phi": {f: round(float(v), 4) for f, v in zip(fit.feeds, fit.phi)},
            "mu0": fit.mu0, "tau": fit.tau, "ref": fit.ref, "rho_union": fit.rho, "kappa": fit.kappa,
            "feed_total": {f: int(fit.totals[j]) for j, f in enumerate(fit.feeds)},
            "loglik": fit.loglik, "iterations": fit.iterations, "converged": fit.converged, "seconds": fit.seconds,
            "networks": int(len(fit.theta)), "listed": listed_count[side], "mass_total": tot,
            "top10_share": float(order[:10].sum() / tot), "top100_share": float(order[:100].sum() / tot),
            "gini": m.gini(mass), "type_ref": {t: round(v, 4) for t, v in per_side_ref[side]["tref"].items()},
            "provisional": provisional_side[side],
            "notes": {**fit.notes, "union_source": meta[side]["union_source"], "unrouted_dropped": meta[side]["unrouted_dropped"]},
        })
    summary = {side: {"feeds": meta[side]["feeds"], "absent": meta[side]["absent"], "listed": listed_count[side],
                      "unrouted_dropped": meta[side]["unrouted_dropped"],
                      "tau": round(fits[side].tau, 3) if fits[side] else None, "ref": round(fits[side].ref, 4) if fits[side] else None,
                      "feed_total": {f: int(fits[side].totals[j]) for j, f in enumerate(fits[side].feeds)} if fits[side] else {},
                      "converged": bool(fits[side].converged) if fits[side] else False,
                      "iterations": fits[side].iterations if fits[side] else 0,
                      "seconds": round(fits[side].seconds, 1) if fits[side] else 0.0,
                      "rho_union": round(fits[side].rho, 3) if fits[side] else None,
                      "union_source": meta[side]["union_source"],
                      "top_feed_share": top_feed_share(fits[side]) if fits[side] else None,
                      "provisional": provisional_side[side]} for side in m.SIDES}
    summary["bands"] = {b: sum(1 for v in bands.values() if v == b) for b in (0, 1, 2)}
    # Two figures the page used to quote from a one-off study, now measured every week on the
    # networks with evidence: how well each side's floor finds Spamhaus's ASN-DROP list (AUC),
    # and how the two sides rank the same networks (Spearman). Stored in the fit notes.
    checks: dict[str, float | None] = {}
    reported = [a for a in uset if a in side_rows and any(r[4] > 0 for r in side_rows[a].values())]
    if asndrop is not None and reported:
        y = np.array([a in asndrop for a in reported])
        for side in m.SIDES:
            if fits[side] is None:
                continue
            sc = np.array([math.log(side_rows[a][side][0]) if side in side_rows[a] else -99.0 for a in reported])
            checks[f"auc_asndrop_{side}"] = m.auc(y, sc)
        checks["asndrop_positives"] = int(y.sum())
        checks["evidence_networks"] = len(reported)
    both = [a for a in reported if "attack" in side_rows[a] and "host" in side_rows[a]]
    if len(both) >= 3:
        checks["spearman_sides"] = m.spearman(np.array([math.log(side_rows[a]["attack"][0]) for a in both]),
                                             np.array([math.log(side_rows[a]["host"][0]) for a in both]))
    for f in fit_rows:
        f["notes"]["checks"] = {k: (round(v, 4) if isinstance(v, float) else v) for k, v in checks.items()}
    summary["checks"] = checks
    return {"rows": rows, "fits": fit_rows, "summary": summary, "fitted": {s: f for s, f in fits.items() if f}}


def top_feed_share(fit: m.SideFit) -> dict[str, float]:
    tot = {f: float(fit.totals[j]) for j, f in enumerate(fit.feeds)}
    s = sum(tot.values()) or 1.0
    return {f: round(v / s, 3) for f, v in tot.items()}
