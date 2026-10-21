"""network_threat_score v2: the model, the scorer and its gate checks, without a database.

Each test exists for a way the score could be wrong while every number stays finite:
the special functions, the collapse of silent networks, the identifiability pin, Shodan's
host cap, an absent feed, the list gate with hysteresis, and the evals that watch them.
"""

from __future__ import annotations

import datetime as dt
import math

import numpy as np
import pytest

from zdc_netthreat import evals, model_v2 as m, score_v2

WEEK = dt.date(2030, 1, 7)


# ---- special functions ------------------------------------------------------------------------
def test_gammaln_and_digamma_match_the_standard_library():
    xs = np.array([0.03, 0.16, 0.5, 0.999, 1.0, 1.5, 3.3, 12.0, 181.0, 2000.5, 1e6])
    assert np.allclose(m.gammaln(xs), [math.lgamma(x) for x in xs], rtol=1e-12, atol=1e-10)
    # digamma(x) = lgamma'(x): a central difference of lgamma is exact enough below x ~ 1e3
    # (above that the subtraction loses digits), plus two closed forms
    h = 1e-5
    small = xs[(xs >= 0.1) & (xs <= 2000)]
    ref = [(math.lgamma(x + h) - math.lgamma(x - h)) / (2 * h) for x in small]
    assert np.allclose(m.digamma(small), ref, rtol=1e-6, atol=1e-7)
    euler = 0.5772156649015329
    assert abs(float(m.digamma(np.array([1.0]))[0]) + euler) < 1e-10
    assert abs(float(m.digamma(np.array([0.5]))[0]) + euler + 2 * math.log(2)) < 1e-10
    assert abs(float(m.digamma(np.array([1e6]))[0]) - (math.log(1e6) - 0.5e-6)) < 1e-9


def test_nb_logpmf_is_a_distribution():
    # for integer phi the NB is a proper pmf: it sums to one over n
    phi, mu = 3.0, 4.2
    n = np.arange(0, 400)
    assert abs(np.exp(m.nb_logpmf(n, mu, phi)).sum() - 1) < 1e-9


# ---- the fit ------------------------------------------------------------------------------------
def _simulate(seed=1, A=3000, F=3, mu0=-1.2, tau=1.5, alpha=(0.2, -0.3, 0.0), phi=(2.0, 0.7, 0.3)):
    rng = np.random.default_rng(seed)
    s24 = np.clip(np.round(np.exp(rng.normal(3.5, 1.6, A))), 1, None)
    theta = rng.normal(mu0, tau, A)
    rates = np.array([0.03, 0.008, 0.004])[:F]       # dense enough that hundreds of networks carry evidence
    counts = np.zeros((A, F))
    for f in range(F):
        mu = s24 * rates[f] * np.exp(alpha[f] + theta)
        counts[:, f] = np.minimum(rng.negative_binomial(phi[f], phi[f] / (phi[f] + mu)), s24)
    asns = np.arange(64496, 64496 + A)
    inp = m.SideInput(asns=asns, s24=s24, feeds=["a", "b", "c"][:F], counts=counts,
                      totals=counts.sum(0), routed_total=float(s24.sum()), union_24s=None)
    return inp, theta, s24


def test_fit_recovers_simulated_intensities():
    inp, theta, s24 = _simulate()
    fit = m.fit_side(inp)
    assert fit.converged
    # ranks of the mode follow the truth for the networks with enough evidence
    seen = inp.counts.sum(1) >= 5
    r = np.corrcoef(fit.theta[seen], theta[seen])[0, 1]
    assert r > 0.8
    # the floor is below the mode, everywhere
    assert np.all(fit.lo <= fit.theta + 1e-9)
    # the internet average is pinned: routed-weighted mean intensity is 1 (to convergence tolerance)
    assert abs(math.log((s24 * fit.e_exp).sum() / s24.sum())) < 1e-3
    assert abs(fit.ref) < 1e-3
    # pushes sum to the distance from the prior mean to the mode (absolute theta)
    assert np.allclose(fit.contrib.sum(1), fit.theta + fit.ref - fit.mu0, atol=1e-6)


def test_silent_networks_collapse_but_still_count():
    inp, _, _ = _simulate(A=2000)
    inp.counts[: 1500] = 0                                   # most networks silent
    fit = m.fit_side(inp)
    assert fit.notes["unique_rows"] < len(inp.asns)          # collapsed
    assert len(fit.theta) == len(inp.asns)                   # but every network gets a result
    silent = inp.counts.sum(1) == 0
    assert fit.theta[silent].max() < fit.theta[~silent].max()
    assert np.all(np.isnan(fit.top_share[silent])) and np.all(fit.obs[silent] == 0)


def test_counts_are_capped_at_routed_size_and_sizes_must_be_positive():
    inp, _, _ = _simulate(A=300)
    inp.counts[0, 0] = inp.s24[0] * 50                       # Shodan hosts above the block count
    fit = m.fit_side(inp)
    assert fit.counts[0, 0] == inp.s24[0]
    bad = m.SideInput(asns=inp.asns, s24=np.where(np.arange(300) == 3, 0, inp.s24), feeds=inp.feeds, counts=inp.counts,
                      totals=inp.totals, routed_total=inp.routed_total)
    with pytest.raises(ValueError):
        m.fit_side(bad)


def test_a_time_capped_fit_is_not_converged():
    inp, _, _ = _simulate(A=800)
    fit = m.fit_side(inp, max_seconds=0.0)
    assert not fit.converged and fit.notes["time_capped"] and fit.iterations == 1
    assert np.all(np.isfinite(fit.lo)) and np.all(np.isfinite(fit.mass))


def test_fit_is_deterministic():
    inp, _, _ = _simulate(A=500)
    a, b = m.fit_side(inp), m.fit_side(inp)
    assert np.array_equal(a.theta, b.theta) and a.loglik == b.loglik


# ---- the gate ------------------------------------------------------------------------------------
def test_list_gate_with_hysteresis():
    assert m.listed(10.0, 50.0) and not m.listed(9.99, 5000.0) and not m.listed(60.0, 49.9)
    assert m.listed(60.0, 40.0, was_listed=True) and not m.listed(60.0, 34.9, was_listed=True)
    assert not m.listed(9.0, 500.0, was_listed=True)        # the 10x bar has no hysteresis


def test_band_follows_the_worse_side():
    assert m.band(1.0, 1.0, False, False) == 0
    assert m.band(12.0, 0.1, False, False) == 1
    assert m.band(0.5, 11.0, False, False) == 1
    assert m.band(12.0, 0.1, True, False) == 2
    assert m.band(None, 11.0, False, True) == 2


def test_auc_and_spearman_rank_helpers():
    y = np.array([True, True, False, False, False])
    assert m.auc(y, np.array([5, 4, 3, 2, 1])) == 1.0
    assert m.auc(y, np.array([1, 2, 3, 4, 5])) == 0.0
    assert m.auc(y, np.array([1, 1, 1, 1, 1])) == 0.5           # ties share ranks
    assert m.auc(np.array([True, True]), np.array([1, 2])) is None
    assert m.spearman(np.array([1, 2, 3, 4]), np.array([10, 20, 30, 40])) == pytest.approx(1.0)
    assert m.spearman(np.array([1, 2, 3, 4]), np.array([4, 3, 2, 1])) == pytest.approx(-1.0)


def test_score_week_measures_its_own_checks(monkeypatch):
    monkeypatch.setattr(score_v2, "ABSENT_FLOOR", {f: 0 for f in score_v2.ABSENT_FLOOR})
    counts, size = _week_counts()
    out = score_v2.score_week(WEEK, counts, size, 10 ** 6, {}, {}, {"attack": set(), "host": set()}, [64496, 64498, 64497],
                              asndrop={64496})
    ck = out["summary"]["checks"]
    assert ck["asndrop_positives"] == 1 and ck["evidence_networks"] == 2        # the quiet network has no evidence
    assert ck["auc_asndrop_attack"] == 1.0                                       # the dense network outranks the big one
    assert all("checks" in f["notes"] for f in out["fits"])


def test_gini_and_type_reference():
    assert m.gini(np.array([1.0, 1.0, 1.0])) == 0.0
    assert m.gini(np.array([0.0, 0.0, 10.0])) > 0.6
    ref = m.type_reference(np.array([1, 2, 3]), np.array([10.0, 10.0, 5.0]), np.log(np.array([2.0, 4.0, 1.0])),
                           {1: "Hosting & VPS", 2: "Hosting & VPS"})
    assert ref == {"Hosting & VPS": 3.0}                     # routed-weighted mean of 2 and 4; ASN 3 has no type


# ---- the scorer -------------------------------------------------------------------------------------
def _week_counts(bad=64496, big=64498, quiet=64497, n_silent=400):
    """Counts shaped like the pipeline stores them: feed -> asn -> (ips, slash24s, cats, listed, score)."""
    size = {bad: 20, big: 4000, quiet: 50}
    rng = np.random.default_rng(7)
    for i in range(n_silent):
        size[70000 + i] = int(rng.integers(1, 2000))
    counts = {}
    for f in ("crowdsec", "dshield", "blocklist_de", "cins", "vulncheck", "threatfox", "urlhaus", "phishing_db"):
        counts[f] = {bad: (60, 18, {}, False, None), big: (40, 30, {}, False, None)}
        # a thin tail of other networks, so each feed has a total above the floor
        for i in range(150):
            counts[f][70000 + i] = (3, 2, {}, False, None)
    counts["shodan"] = {bad: (500, 0, {}, False, None), big: (300, 0, {}, False, None)}
    for i in range(300):
        counts["shodan"][70000 + i] = (2, 0, {}, False, None)
    return counts, size


def test_score_week_scores_both_sides_and_lists_the_dense_network(monkeypatch):
    monkeypatch.setattr(score_v2, "ABSENT_FLOOR", {f: 0 for f in score_v2.ABSENT_FLOOR})
    counts, size = _week_counts()
    types = {64496: "Hosting & VPS", 64498: "Hyperscale cloud", 64497: "Other"}
    out = score_v2.score_week(WEEK, counts, size, sum(size.values()) * 100, types, {}, {"attack": set(), "host": set()},
                              [64496, 64497, 64498])
    rows = {(r[0], r[1]): r for r in out["rows"]}
    assert set(rows) == {(a, s) for a in (64496, 64497, 64498) for s in ("attack", "host")}
    bad_a, big_a, quiet_a = rows[(64496, "attack")], rows[(64498, "attack")], rows[(64497, "attack")]
    assert bad_a[2] > quiet_a[2] and bad_a[3] >= bad_a[2]                      # floor ordered, mode above floor
    assert bad_a[2] > big_a[2]                                                   # 18 of 20 blocks beats 30 of 4,000
    assert big_a[5] > bad_a[5]                                                   # but the big one holds more bad blocks
    assert bad_a[11] is not None and set(bad_a[11]) == set(out["fits"][0]["feeds"])  # comp per feed for networks with evidence
    assert quiet_a[11] is None and quiet_a[6] == 0                                # none for a silent network
    assert all(r[14] == WEEK + dt.timedelta(days=6) for r in out["rows"])
    assert {f["side"] for f in out["fits"]} == {"attack", "host"}
    assert all(f["converged"] and not f["provisional"] for f in out["fits"])
    # shodan is not fitted on the host side (coverage swings; no /24s yet); its occupancy transform stays for its return
    assert "shodan" not in rows[(64496, "host")][12]
    assert score_v2.expected_occupied_24s(2, 2) == pytest.approx(1.264, abs=1e-3)
    assert score_v2.expected_occupied_24s(0, 5) == 0.0 and score_v2.expected_occupied_24s(10 ** 6, 3) == pytest.approx(3.0)
    assert out["summary"]["bands"][0] + out["summary"]["bands"][1] + out["summary"]["bands"][2] == 3


def test_an_absent_feed_marks_the_side_provisional(monkeypatch):
    monkeypatch.setattr(score_v2, "ABSENT_FLOOR", {f: 10 for f in score_v2.ABSENT_FLOOR})
    counts, size = _week_counts()
    del counts["dshield"]                                      # not fetched at all
    counts["cins"] = {64496: (1, 1, {}, False, None)}          # answered, but almost empty: under the floor
    out = score_v2.score_week(WEEK, counts, size, 10 ** 6, {}, {}, {"attack": set(), "host": set()}, [64496, 64498])
    fit = next(f for f in out["fits"] if f["side"] == "attack")
    assert set(fit["absent_feeds"]) == {"dshield", "cins"} and "dshield" not in fit["feeds"]
    assert fit["provisional"] and all(r[13] for r in out["rows"] if r[1] == "attack")
    chk = evals.check_v2_feeds_present(out["summary"])
    assert chk.severity == evals.WARN and not chk.passed and "dshield" in chk.summary


def test_a_side_with_no_feed_is_an_error_not_a_crash():
    counts, size = _week_counts()
    for f in ("threatfox", "urlhaus", "phishing_db"):
        del counts[f]
    out = score_v2.score_week(WEEK, counts, size, 10 ** 6, {}, {}, {"attack": set(), "host": set()}, [64496])
    assert not any(f["side"] == "host" for f in out["fits"])
    assert all(r[1] == "attack" for r in out["rows"])
    assert evals.check_v2_feeds_present(out["summary"]).blocking


def test_hysteresis_keeps_last_weeks_network_until_35_blocks(monkeypatch):
    monkeypatch.setattr(score_v2, "ABSENT_FLOOR", {f: 0 for f in score_v2.ABSENT_FLOOR})
    counts, size = _week_counts()
    base = score_v2.score_week(WEEK, counts, size, 10 ** 6, {}, {}, {"attack": set(), "host": set()}, [64496, 64498])
    row = next(r for r in base["rows"] if r[0] == 64498 and r[1] == "attack")
    lo_x, mass = row[2], row[5]
    assume_listed_last_week = {"attack": {64498}, "host": set()}
    again = score_v2.score_week(WEEK, counts, size, 10 ** 6, {}, {}, assume_listed_last_week, [64496, 64498])
    row2 = next(r for r in again["rows"] if r[0] == 64498 and r[1] == "attack")
    # same floor and mass; listed iff the gate says so given last week's membership
    assert row2[2] == lo_x and row2[5] == mass
    assert row2[9] == m.listed(lo_x, mass, was_listed=True)


def test_dedup_uses_ip_feeds_only_and_shodan_enters_undiscounted(monkeypatch):
    monkeypatch.setattr(score_v2, "ABSENT_FLOOR", {f: 0 for f in score_v2.ABSENT_FLOOR})
    counts, size = _week_counts()
    unions = {"attack": {}, "host": {64496: (5, 4), 64498: (5, 4)}}
    out = score_v2.score_week(WEEK, counts, size, 10 ** 6, {}, unions, {"attack": set(), "host": set()}, [64496, 64498])
    h = next(f for f in out["fits"] if f["side"] == "host")
    ip_24s = sum(sum(v[1] for v in counts[f].values() if v[1] <= size.get(0, 10 ** 9)) for f in ("threatfox", "urlhaus", "phishing_db"))
    # rho = union / IP-feed appearances, not / (IP + Shodan)
    assert h["rho_union"] == pytest.approx(max(0.05, min(1.0, 8 / h["notes"]["rho_denominator_ip_24s"])), rel=1e-6)
    assert h["notes"]["rho_denominator_ip_24s"] <= ip_24s + 1e-6


def test_a_forced_absent_feed_is_dropped_and_marked(monkeypatch):
    monkeypatch.setattr(score_v2, "ABSENT_FLOOR", {f: 0 for f in score_v2.ABSENT_FLOOR})
    counts, size = _week_counts()
    out = score_v2.score_week(WEEK, counts, size, 10 ** 6, {}, {}, {"attack": set(), "host": set()}, [64496],
                              force_absent=frozenset({"urlhaus"}))
    h = next(f for f in out["fits"] if f["side"] == "host")
    assert "urlhaus" in h["absent_feeds"] and "urlhaus" not in h["feeds"] and h["provisional"]


def test_per_side_union_sets_the_dedup_factor(monkeypatch):
    monkeypatch.setattr(score_v2, "ABSENT_FLOOR", {f: 0 for f in score_v2.ABSENT_FLOOR})
    counts, size = _week_counts()
    unions = {"attack": {64496: (60, 18), 64498: (40, 30)}, "host": {}}
    out = score_v2.score_week(WEEK, counts, size, 10 ** 6, {}, unions, {"attack": set(), "host": set()}, [64496],
                              fallback_union={64496: (60, 18), 64498: (40, 30)})
    a = next(f for f in out["fits"] if f["side"] == "attack")
    h = next(f for f in out["fits"] if f["side"] == "host")
    assert 0 < a["rho_union"] < 1 and a["notes"]["union_source"] == "side"
    assert h["notes"]["union_source"] == f"assumed_{score_v2.RHO_ASSUMED}" and h["rho_union"] == score_v2.RHO_ASSUMED


# ---- evals ----------------------------------------------------------------------------------------------
def _summary(**over):
    s = {"attack": {"feeds": ["crowdsec", "dshield"], "absent": [], "listed": 14, "converged": True, "iterations": 120,
                    "seconds": 40.0, "top_feed_share": {"crowdsec": 0.6, "dshield": 0.4}, "provisional": False},
         "host": {"feeds": ["threatfox", "shodan"], "absent": [], "listed": 10, "converged": True, "iterations": 200,
                  "seconds": 20.0, "top_feed_share": {"threatfox": 0.3, "shodan": 0.7}, "provisional": False}}
    for k, v in over.items():
        side, key = k.split("__")
        s[side][key] = v
    return s


def test_eval_converged_blocks_when_a_side_hit_the_cap():
    assert evals.check_v2_converged(_summary()).passed
    r = evals.check_v2_converged(_summary(host__converged=False))
    assert r.blocking and "host" in r.summary


def test_eval_listed_bounds_and_single_feed_warn_only():
    assert evals.check_v2_listed_bounds(_summary()).passed
    r = evals.check_v2_listed_bounds(_summary(attack__listed=900))
    assert not r.passed and r.severity == evals.WARN and not r.blocking
    assert evals.check_v2_listed_bounds(_summary(host__listed=1)).passed          # a short hosting list is normal
    assert not evals.check_v2_listed_bounds(_summary(attack__listed=1)).passed
    r2 = evals.check_v2_single_feed(_summary(attack__top_feed_share={"crowdsec": 0.9, "dshield": 0.1}))
    assert not r2.passed and "crowdsec 90%" in r2.summary and not r2.blocking


def test_eval_fit_sane_watches_tau_and_the_pin():
    ok = _summary(); ok["attack"].update(tau=2.3, ref=0.002); ok["host"].update(tau=2.2, ref=-0.004)
    assert evals.check_v2_fit_sane(ok).passed
    bad = _summary(); bad["attack"].update(tau=0.1, ref=0.0); bad["host"].update(tau=2.2, ref=0.3)
    r = evals.check_v2_fit_sane(bad)
    assert r.blocking and "attack" in r.summary and "host" in r.summary


def test_eval_rows_sane_catches_nan_and_inverted_bounds():
    good = [(1, "attack", 2.0, 3.0, 0.4, 10.0, 5, 1.1, 0.5, False, 0, None, None, False, WEEK)]
    assert evals.check_v2_rows_sane(good).passed
    nan = [(1, "attack", float("nan"), 3.0, 0.4, 10.0, 5, 1.1, 0.5, False, 0, None, None, False, WEEK)]
    inverted = [(1, "attack", 5.0, 3.0, 0.4, 10.0, 5, 1.1, 0.5, False, 0, None, None, False, WEEK)]
    assert evals.check_v2_rows_sane(nan).blocking and evals.check_v2_rows_sane(inverted).blocking
    assert evals.check_v2_rows_sane([]).blocking


# ---- week-to-week gates (round 6) ----------------------------------------------------------------
def _row(asn, side, lo, listed, mass=100.0):
    return (asn, side, lo, lo * 1.5, 0.3, mass, 10, 1.0, 0.5, listed, 2 if listed else 0, None, None, False, WEEK)


def test_union_measured_and_rho_range_gates():
    s = _summary(); s["attack"].update(union_source="side", rho_union=0.71); s["host"].update(union_source="side", rho_union=0.8)
    assert evals.check_v2_union_measured(s, {"attack": True, "host": True}).passed
    s2 = _summary(); s2["attack"].update(union_source="assumed_0.63", rho_union=0.63); s2["host"].update(union_source="assumed_0.63", rho_union=0.63)
    assert evals.check_v2_union_measured(s2, {"attack": False, "host": False}).passed      # pre-0102 week: nothing stored
    r = evals.check_v2_union_measured(s2, {"attack": True, "host": False})
    assert r.blocking and "attack" in r.summary                                            # stored but not used
    assert evals.check_v2_rho_range(s2).passed                                              # assumed values are not range-checked
    s3 = _summary(); s3["attack"].update(union_source="side", rho_union=1.0); s3["host"].update(union_source="side", rho_union=0.7)
    assert evals.check_v2_rho_range(s3).blocking
    s4 = _summary(); s4["attack"].update(union_source="side", rho_union=0.852); s4["host"].update(union_source="side", rho_union=0.989)
    assert evals.check_v2_rho_range(s4).passed                                              # week of 2026-10-12: host feeds barely overlap
    s5 = _summary(); s5["attack"].update(union_source="side", rho_union=0.852); s5["host"].update(union_source="side", rho_union=1.0)
    assert evals.check_v2_rho_range(s5).blocking                                            # a host clamp at 1 still fails
    s6 = _summary(); s6["attack"].update(union_source="side", rho_union=0.97); s6["host"].update(union_source="side", rho_union=0.9)
    assert evals.check_v2_rho_range(s6).blocking                                            # attack keeps the 0.95 ceiling


def test_param_drift_and_first_week_are_info():
    fits = [{"side": "attack", "alpha": {"crowdsec": 0.03}, "phi": {"crowdsec": 2.8}, "tau": 2.25},
            {"side": "host", "alpha": {"threatfox": 0.4}, "phi": {"threatfox": 0.3}, "tau": 2.16}]
    assert evals.check_v2_param_drift(fits, None).severity == evals.INFO
    prev = {"attack": {"alpha": {"crowdsec": 0.05}, "phi": {"crowdsec": 2.6}, "tau": 2.3}, "host": {"alpha": {"threatfox": 0.4}, "phi": {"threatfox": 0.3}, "tau": 2.2}}
    assert evals.check_v2_param_drift(fits, prev).passed
    prev["attack"]["alpha"]["crowdsec"] = 0.9                                              # moved by 0.87
    r = evals.check_v2_param_drift(fits, prev)
    assert not r.passed and r.severity == evals.WARN and "crowdsec alpha" in r.summary


def test_floor_stability_and_exodus_against_last_week():
    rows = [_row(a, "attack", float(a % 50 + 1), a % 50 > 44) for a in range(1, 101)]
    prev_same = {(r[0], r[1]): (r[2], r[9]) for r in rows}
    assert evals.check_v2_floor_stability(rows, prev_same).passed
    assert evals.check_v2_list_exodus(rows, prev_same).passed
    prev_shuffled = {(r[0], r[1]): (float((r[0] * 37) % 50 + 1), r[9]) for r in rows}
    assert not evals.check_v2_floor_stability(rows, prev_shuffled).passed
    prev_bigger_list = {(a, "attack"): (60.0, True) for a in range(1, 101)}                 # everyone was listed last week
    r = evals.check_v2_list_exodus(rows, prev_bigger_list)
    assert not r.passed and r.severity == evals.WARN
    assert evals.check_v2_floor_stability(rows, None).severity == evals.INFO


def test_checks_drift_watches_auc_and_evidence_count():
    s = _summary(); s["checks"] = {"auc_asndrop_attack": 0.72, "auc_asndrop_host": 0.81, "evidence_networks": 3033}
    assert evals.check_v2_checks_drift(s, None).passed
    assert evals.check_v2_checks_drift(s, {"auc_asndrop_attack": 0.75, "auc_asndrop_host": 0.80, "evidence_networks": 3100}).passed
    r = evals.check_v2_checks_drift(s, {"auc_asndrop_attack": 0.90, "auc_asndrop_host": 0.80, "evidence_networks": 5000})
    assert not r.passed and "attack AUC" in r.summary and "evidence networks" in r.summary
    s["checks"]["auc_asndrop_host"] = 0.5
    assert not evals.check_v2_checks_drift(s, None).passed


def test_forward_check_treats_a_null_auc_as_not_measurable():
    """A pair whose t+1 outcomes are all one class has no AUC; that is INFO, never a failure."""
    class _Cur:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def execute(self, sql, params=None): pass
        def fetchall(self): return [(dt.date(2030, 1, 7), "attack", 3, None, 0.95, 0.5), (dt.date(2030, 1, 7), "host", 1, None, None, 1.0)]
    class _Conn:
        def cursor(self): return _Cur()
        def rollback(self): pass
    r = evals.check_v2_forward(_Conn())
    assert r.passed and r.severity == evals.INFO and "AUC None" in r.summary and "credible at 8 weeks" in r.summary
