"""Record linkage for breach incidents (zdc_breach.linkage). Synthetic data only; no database.

The regression fixtures are the design's stop-the-run cases (docs/decisions/0008): the Allianz
Life breach as eight source rows plus Allianz Global Risks, two "St. Mary's" in different states,
Change Healthcare vs UnitedHealth, and トヨタ vs トヨタ紡織. Shapes follow the design's diagnosis;
no row comes from the live snapshot. The u table and the token frequencies below are rounded
aggregates measured on the 2026-10-19 snapshot (12,331 incidents, 9,833 organisations).
"""

from __future__ import annotations

import hashlib
import json
import math
from collections import Counter
from itertools import combinations

import pytest

from zdc_breach import linkage as L
from zdc_breach import linkage_sample as S

U_TEST = {
    'count': {'other': 1.0, 'same': 3e-06},
    'country': {'agree': 0.51, 'conflict': 0.17, 'missing': 0.32},
    'domain': {'consistent': 5e-06, 'different': 0.008, 'equal': 5e-06, 'missing': 0.99},
    'event:other': {'d0': 7e-05, 'd120': 0.0051, 'd14': 0.00074, 'd3': 0.00022, 'd45': 0.002, 'gt120': 0.15, 'md_match_year_off': 0.0004, 'missing': 0.84},
    'event:press_press': {'d0': 1.3e-05, 'd120': 0.00074, 'd14': 8.6e-05, 'd3': 2e-05, 'd45': 0.00025, 'gt120': 0.0038, 'md_match_year_off': 0.0004, 'missing': 1.0},
    'event:reg_hibp': {'d0': 0.00015, 'd120': 0.022, 'd14': 0.0034, 'd3': 0.00098, 'd45': 0.0091, 'gt120': 0.76, 'md_match_year_off': 0.0004, 'missing': 0.2},
    'event:reg_press': {'d0': 2e-05, 'd120': 0.0024, 'd14': 0.00035, 'd3': 0.00012, 'd45': 0.00092, 'gt120': 0.05, 'md_match_year_off': 0.0004, 'missing': 0.95},
    'event:reg_reg': {'d0': 0.00049, 'd120': 0.022, 'd14': 0.0033, 'd3': 0.0014, 'd45': 0.0089, 'gt120': 0.6, 'md_match_year_off': 0.0004, 'missing': 0.36},
    'event:sec_any': {'d0': 0.00017, 'd120': 0.0026, 'd14': 0.00017, 'd3': 0.00035, 'd45': 0.0012, 'gt120': 0.027, 'md_match_year_off': 0.0004, 'missing': 0.97},
    'impossible': {'impossible': 0.31, 'na': 0.22, 'ok': 0.47},
    'name': {'alias': 1e-06, 'conflict': 0.029, 'contain': 8e-06, 'exact': 0.00015, 'linkkey': 3e-06, 'none': 0.97, 'single': 0.00012, 'soft': 8e-06},
    'public': {'gt365': 0.71, 'p120': 0.067, 'p14': 0.015, 'p365': 0.18, 'p45': 0.03},
    'sector': {'agree': 0.07, 'differ': 0.24, 'missing': 0.69},
    'source': {'diff_reg': 0.11, 'other': 0.72, 'same_reg': 0.17},
}
N_ORGS, N_INC = 9833, 12331
DF = {"allianz": 6, "life": 86, "insurance": 183, "global": 40, "risks": 1, "st": 45, "mary": 2, "s": 400,
      "medical": 302, "center": 357, "hospital": 160, "change": 2, "healthcare": 151, "unitedhealth": 2,
      "of": 1500, "zeta": 3, "widget": 5, "pharma": 30, "logistics": 60, "トヨタ": 1, "トヨタ紡織": 1}
TF = {"allianz": 9, "life": 120, "insurance": 260, "st": 60, "mary": 3, "zeta": 3, "widget": 6}


def idf():
    return L.Idf(DF, N_ORGS, TF, N_INC)


def model():
    return L.provisional_model(U_TEST, idf(), N_INC)


# ---- synthetic rows --------------------------------------------------------------------------
def build(rows):
    """rows: dicts with iid, name, and optionally org, domain, cik, country, sector, ev, pub,
    sources, persons, dup_of, aliases. Returns Rec objects through build_records."""
    orgs, incs, srcs, claims = {}, [], [], []
    for r in rows:
        oid = r.get("org", "org-" + r["iid"])
        orgs.setdefault(oid, {"org_id": oid, "display_name": r["name"], "norm_name": L.norm_name(r["name"]),
                              "domain": r.get("domain"), "country": r.get("country"), "sector": r.get("sector"),
                              "sec_cik": r.get("cik"), "alias_norms": r.get("aliases", []),
                              "is_natural_person": False})
        incs.append({"incident_id": r["iid"], "org_id": oid, "event_date": r.get("ev"),
                     "first_public_date": r["pub"], "suppressed": False, "possible_duplicate_of": r.get("dup_of")})
        for s in r.get("sources", ["ca_ag"]):
            srcs.append({"incident_id": r["iid"], "source_id": s})
        for n in r.get("persons", []):
            claims.append({"incident_id": r["iid"], "field": "people_affected", "value_num": n, "qualifier": "exact",
                           "accepted": True, "superseded_by": None, "review_verdict": None})
    return L.build_records(list(orgs.values()), incs, srcs, claims)


ALLIANZ = [
    # 1 WA + CA: one incident, the full legal name ("Company" stripped, "of North America" kept)
    dict(iid="a1", org="o-wa", name="Allianz Life Insurance Company of North America", country="US",
         sector="Finance", ev="2025-07-16", pub="2025-07-25", sources=["wa_ag", "ca_ag"]),
    # 2 DE: the name without the qualifier
    dict(iid="a2", org="o-de", name="Allianz Life Insurance Company", country="US", sector="insurance",
         ev="2025-07-16", pub="2025-08-01", sources=["de_ag"]),
    # 3 HIBP: no country, a domain, the dump date as BreachDate
    dict(iid="a3", org="o-hibp", name="Allianz Life", domain="allianzlife.com", ev="2025-07-16",
         pub="2025-08-18", sources=["hibp"]),
    # 4-7 press: two dateless, two stating 07-16
    dict(iid="a4", org="o-p1", name="Allianz Life", country="US", sector="insurance", pub="2025-07-26",
         sources=["news_databreaches"]),
    dict(iid="a5", org="o-de", name="Allianz Life Insurance Company", country="US", sector="insurance",
         pub="2025-07-29", sources=["news_hackread"], persons=[1400000], dup_of="a2"),
    dict(iid="a6", org="o-p1", name="Allianz Life", country="US", sector="insurance", ev="2025-07-16",
         pub="2025-08-19", sources=["news_securityaffairs"], persons=[1497036], dup_of="a4"),
    dict(iid="a7", org="o-p3", name="Allianz Life Insurance", country="US", sector="insurance", ev="2025-07-16",
         pub="2025-07-30", sources=["news_bleepingcomputer"]),
    # 8 press: the parent-level name, no date
    dict(iid="a8", org="o-p4", name="Allianz", sector="insurance", pub="2025-09-13", sources=["news_securityaffairs"]),
]
GLOBAL_RISKS = dict(iid="g1", org="o-gr", name="Allianz Global Risks U.S. Insurance Company", country="US",
                    ev="2023-05-29", pub="2024-05-09", sources=["ca_ag"])
LIFE = ["a1", "a2", "a3", "a4", "a5", "a6", "a7"]
DATED = ["a1", "a2", "a3", "a6", "a7"]


def run_fixture(rows, decisions=None):
    recs = build(rows)
    ix = idf()
    m = model()
    cand, dropped, _ = L.block(recs, ix)
    by = {r.iid: r for r in recs}
    scored = {k: m.score(by[k[0]], by[k[1]]) for k in cand}
    cl, notes = L.cluster(recs, scored, m, decisions)
    return recs, cand, scored, cl, notes


def key(a, b):
    return (a, b) if a < b else (b, a)


# ---- link_key, labels, classes --------------------------------------------------------------
def test_link_key_strips_geographic_and_structural_qualifiers_only():
    assert L.link_key("allianz life insurance of north america") == "allianz life insurance"
    assert L.link_key("allianz global risks u s insurance") == "allianz global risks insurance"
    assert L.link_key("acme holdings group") == "acme"
    assert L.link_key("group") == "group"                      # nothing left: keep the name
    assert L.link_key("usaa") == "usaa"                         # whole tokens only
    assert L.link_key("") == ""


def test_link_key_does_not_change_organisation_identity():
    # linkage only: norm_name (ADR 0006) is untouched
    assert L.norm_name("Allianz Life Insurance Company of North America") == "allianz life insurance of north america"


def test_domain_label():
    assert L.domain_label("allianzlife.com") == "allianzlife"
    assert L.domain_label("acme-corp.co.uk") == "acmecorp"
    assert L.domain_label("ab.com") is None


def test_source_and_pair_classes():
    assert [L.source_class(s) for s in ("wa_ag", "hhs_ocr", "sec_8k", "hibp", "news_krebs", "gdelt", "ransomlook")] == \
        ["reg", "reg", "sec", "hibp", "press", "press", "other"]
    assert L.incident_class({"news_krebs", "ca_ag"}) == "reg"
    assert L.pair_class("press", "sec") == "sec_any"
    assert L.pair_class("press", "reg") == "reg_press"
    assert L.date_class("hibp_press") == "other"


def test_sec_period_ending_is_not_an_event_date():
    recs = build([dict(iid="s1", name="Acme Corp", ev="2025-01-10", pub="2025-01-12", sources=["sec_8k"]),
                  dict(iid="s2", name="Acme Corp", ev="2025-01-10", pub="2025-01-12", sources=["sec_8k", "news_krebs"])])
    by = {r.iid: r for r in recs}
    assert by["s1"].ev is None and by["s1"].ev_raw is not None
    assert by["s2"].ev is not None                       # another source stated it


# ---- name levels ----------------------------------------------------------------------------
@pytest.mark.parametrize("a,b,level", [
    ("Allianz Life", "Allianz Life", "exact"),
    ("Allianz Life Insurance Company of North America", "Allianz Life Insurance Company", "linkkey"),
    ("Allianz Life", "Allianz Life Insurance Company", "contain"),
    ("Allianz", "Allianz Life", "single"),
    ("Allianz Life Insurance Company of North America", "Allianz Global Risks U.S. Insurance Company", "conflict"),
    ("Change Healthcare", "UnitedHealth Group", "none"),
    ("トヨタ", "トヨタ紡織", "none"),
])
def test_name_levels(a, b, level):
    ra, rb = build([dict(iid="x", name=a, pub="2025-01-01"), dict(iid="y", name=b, pub="2025-01-01")])
    assert L.name_level(ra, rb, idf()) == level


def test_japanese_names_are_never_fuzzy_kin():
    assert L.jaro_winkler("トヨタ", "トヨタ紡織") >= 0.9       # Jaro-Winkler alone would call them close
    assert L.token_sim("トヨタ", "トヨタ紡織") == 0.0


def test_generic_tokens_do_not_conflict():
    ra, rb = build([dict(iid="x", name="St. Mary's Hospital", pub="2025-01-01"),
                    dict(iid="y", name="St. Mary's Medical Center", pub="2025-01-01")])
    assert L.name_level(ra, rb, idf()) != "conflict"


# ---- blocking -------------------------------------------------------------------------------
def test_every_allianz_life_pair_is_a_candidate():
    recs, cand, *_ = run_fixture(ALLIANZ + [GLOBAL_RISKS])
    for a, b in combinations(sorted(LIFE + ["a8"]), 2):
        assert key(a, b) in cand, (a, b)


def test_block_over_the_cap_is_dropped_and_logged():
    rows = [dict(iid=f"c{i:03d}", name=f"City of Town{i}", pub="2025-01-01") for i in range(30)]
    recs = build(rows)
    cand, dropped, _ = L.block(recs, idf(), cap=100)
    assert {"block": "B2:city of", "pairs": 435} in dropped
    assert not any(any(k == "B2:city of" for k in v) for v in cand.values())


def test_b6_keeps_every_legacy_link_even_outside_the_windows():
    rows = [dict(iid="l1", org="o", name="Zeta Widget", pub="2023-01-01"),
            dict(iid="l2", org="o", name="Zeta Widget", pub="2025-06-01", dup_of="l1")]
    cand, _, _ = L.block(build(rows), idf())
    assert "B6:possible_duplicate_of" in cand[("l1", "l2")]


def test_b2_event_clock_finds_a_late_filing():
    rows = [dict(iid="v1", name="Illuminate Education on behalf of Azusa", ev="2021-12-28", pub="2022-05-01"),
            dict(iid="v2", name="Illuminate Education on behalf of Tracy", ev="2021-12-28", pub="2024-01-05")]
    cand, _, _ = L.block(build(rows), idf())
    assert ("v1", "v2") in cand


# ---- the regression fixtures ------------------------------------------------------------------
def test_allianz_fixture():
    recs, cand, scored, cl, notes = run_fixture(ALLIANZ + [GLOBAL_RISKS])
    # rows 1-3 and the press rows stating 07-16: one auto cluster
    assert len({cl[i] for i in DATED}) == 1
    # the listed member is the earliest seen
    assert cl["a1"] == "a1"
    # dateless press rows (s7 b2): auto only within 45 days on a qualifying name, else review; the
    # design allows either outcome, but never a link to Global Risks or the bare "Allianz"
    for i in ("a4", "a5"):
        assert cl[i] in (i, cl["a1"])
        for j in LIFE:
            k = key(i, j)
            if j != i and k in scored and scored[k]["band"] == "auto" and not scored[k]["legacy"]:
                assert scored[k]["levels"]["public"] in L.DATELESS_PUBLIC
    # the legacy edge a5 -> a2 is an edge source (s7 b1)
    assert scored[key("a2", "a5")]["legacy"] and scored[key("a2", "a5")]["band"] == "auto"
    # "Allianz" alone: never auto
    assert cl["a8"] == "a8"
    assert all(s["band"] != "auto" for k, s in scored.items() if "a8" in k)
    # Global Risks: never linked, and cannot-link against every Allianz Life row
    assert cl["g1"] == "g1"
    m = model()
    by = {r.iid: r for r in recs}
    for i in LIFE:
        c = m.score(by[i], by["g1"])
        assert c["cannot"], i
    assert "distinctive_tokens_conflict" in m.score(by["a1"], by["g1"])["cannot"]
    assert "event_dates_gt_180d" in m.score(by["a1"], by["g1"])["cannot"]


def test_two_st_marys_in_different_states_stay_apart():
    rows = [dict(iid="m1", org="o-wv", name="St. Mary's Medical Center", country="US", sector="Health: Healthcare Provider",
                 ev="2024-01-05", pub="2024-03-01", sources=["hhs_ocr"]),
            dict(iid="m2", org="o-ca", name="St. Mary's Medical Center", country="US", sector="Health: Healthcare Provider",
                 ev="2024-09-20", pub="2024-10-15", sources=["ca_ag"])]
    recs, cand, scored, cl, _ = run_fixture(rows)
    assert cl["m1"] != cl["m2"]
    assert "event_dates_gt_180d" in model().score(*recs)["cannot"]
    # without event dates (HHS states none) and five months apart: still not auto
    rows2 = [dict(r, ev=None) for r in rows]
    recs2, cand2, scored2, cl2, _ = run_fixture(rows2)
    assert cl2["m1"] != cl2["m2"]
    assert model().score(*recs2)["band"] != "auto"


def test_change_healthcare_is_not_unitedhealth():
    rows = [dict(iid="h1", name="Change Healthcare", country="US", sector="Health", ev="2024-02-21",
                 pub="2024-07-29", sources=["hhs_ocr"], persons=[100000000]),
            dict(iid="h2", name="UnitedHealth Group", country="US", sector="Health", ev="2024-02-21",
                 pub="2024-03-07", sources=["sec_8k"], cik="731766")]
    recs, cand, scored, cl, _ = run_fixture(rows)
    assert ("h1", "h2") not in cand
    assert cl["h1"] != cl["h2"]
    assert model().score(*recs)["probability"] < L.REVIEW


def test_toyota_is_not_toyota_boshoku():
    rows = [dict(iid="t1", name="トヨタ自動車株式会社", country="JP", ev="2026-09-01", pub="2026-09-10",
                 sources=["news_jp_securitynext"]),
            dict(iid="t2", name="トヨタ紡織株式会社", country="JP", ev="2026-09-01", pub="2026-09-11",
                 sources=["news_jp_itmedia"])]
    recs, cand, scored, cl, _ = run_fixture(rows)
    assert cl["t1"] != cl["t2"]
    assert model().score(*recs)["band"] != "auto"


# ---- cannot-link rules: each fires, splits, and is load-bearing ----------------------------------
BASE = [dict(iid="z1", org="o-z1", name="Zeta Widget Pharma", country="US", sector="Health", domain="zetawidget.com",
             cik="111", ev="2025-03-01", pub="2025-03-20", sources=["wa_ag"]),
        dict(iid="z2", org="o-z2", name="Zeta Widget Pharma", country="US", sector="Health", domain="zetawidget.com",
             cik="111", ev="2025-03-01", pub="2025-03-25", sources=["de_ag"])]
MUTANTS = {
    "domain_differs": dict(domain="zeta-widget.net"),
    "cik_differs": dict(cik="222"),
    "country_differs": dict(country="CA"),
    "event_dates_gt_180d": dict(ev="2025-09-20", pub="2025-10-01"),
    "distinctive_tokens_conflict": dict(name="Zeta Widget Logistics", domain=None),
}


def test_control_the_base_pair_auto_links():
    recs, cand, scored, cl, _ = run_fixture(BASE)
    assert scored[("z1", "z2")]["band"] == "auto" and not scored[("z1", "z2")]["cannot"]
    assert cl["z1"] == cl["z2"]


@pytest.mark.parametrize("reason", sorted(MUTANTS))
def test_cannot_link_rule_fires_and_splits(reason):
    rows = [BASE[0], dict(BASE[1], **MUTANTS[reason])]
    recs, cand, scored, cl, _ = run_fixture(rows)
    s = model().score(*recs)
    assert reason in s["cannot"]
    assert L.decision_of(s, None) == "cannot_link"
    assert cl["z1"] != cl["z2"]


@pytest.mark.parametrize("reason", sorted(MUTANTS))
def test_cannot_link_rule_is_load_bearing(reason, monkeypatch):
    """Code mutation: drop one rule from compare(). The decision must change, so the test above
    fails if the rule is removed; where the rest of the evidence is strong, the pair then merges."""
    real = L.compare

    def mutated(a, b, idf):
        c = real(a, b, idf)
        c["cannot"] = [r for r in c["cannot"] if r != reason]
        return c
    monkeypatch.setattr(L, "compare", mutated)
    rows = [BASE[0], dict(BASE[1], **MUTANTS[reason])]
    recs, cand, scored, cl, _ = run_fixture(rows)
    s = model().score(*recs)
    assert reason not in s["cannot"] and L.decision_of(s, None) != "cannot_link"
    if reason in ("domain_differs", "cik_differs", "country_differs"):
        assert cl["z1"] == cl["z2"]


def test_human_cannot_link_beats_the_model_and_must_link_merges():
    recs, cand, scored, cl, _ = run_fixture(BASE, decisions={("z1", "z2"): "cannot_link"})
    assert cl["z1"] != cl["z2"]
    rows = [dict(BASE[0], domain=None, cik=None), dict(BASE[1], domain=None, cik=None, ev=None, pub="2026-01-01")]
    recs, cand, scored, cl, _ = run_fixture(rows)
    assert cl["z1"] != cl["z2"]
    recs, cand, scored, cl, _ = run_fixture(rows, decisions={("z1", "z2"): "must_link"})
    assert cl["z1"] == cl["z2"]


# ---- clustering rules on hand-made scores ----------------------------------------------------
def _recs(ids):
    return build([dict(iid=i, name=f"Org {i}", pub=f"2025-01-{n + 1:02d}") for n, i in enumerate(ids)])


def _s(p, cannot=()):
    band = "auto" if p >= L.PROVISIONAL_AUTO else "review" if p >= L.REVIEW else "none"
    return {"probability": p, "band": band, "cannot": list(cannot)}


def test_complete_linkage_stops_a_chain():
    recs = _recs(["A", "B", "C"])
    scored = {("A", "B"): _s(.99), ("B", "C"): _s(.98), ("A", "C"): _s(.2)}
    cl, notes = L.cluster(recs, scored, model())
    assert cl["A"] == cl["B"] != cl["C"]
    assert notes[("B", "C")] == "complete_linkage"


def test_transitive_closure_would_have_merged_it():
    # the control for the test above: with A-C at review level, the chain is allowed
    recs = _recs(["A", "B", "C"])
    scored = {("A", "B"): _s(.99), ("B", "C"): _s(.98), ("A", "C"): _s(.6)}
    cl, _ = L.cluster(recs, scored, model())
    assert cl["A"] == cl["B"] == cl["C"]


def test_cannot_link_spanning_two_components_blocks_the_merge():
    # B is auto to both A and C, but A and C are cannot-link: the merge is refused, and B, now at
    # review level against two clusters that cannot be one, is ambiguous and goes to review.
    recs = _recs(["A", "B", "C"])
    scored = {("A", "B"): _s(.99), ("B", "C"): _s(.98), ("A", "C"): _s(.9, ["domain_differs"])}
    cl, notes = L.cluster(recs, scored, model())
    assert len({cl["A"], cl["B"], cl["C"]}) == 3
    assert notes[("A", "B")] == "ambiguous" and notes[("B", "C")] in ("cannot_link_spans", "ambiguous")


def test_cannot_link_spanning_blocks_a_component_merge():
    # {A, B} and {C, D} are each auto and B-D is auto too, but A-C is cannot-link: the components
    # never merge, and B and D - each auto against a rival cluster - become ambiguous.
    recs = _recs(["A", "B", "C", "D"])
    scored = {("A", "B"): _s(.99), ("C", "D"): _s(.99), ("B", "D"): _s(.97),
              ("A", "C"): _s(.4, ["country_differs"]), ("A", "D"): _s(.3), ("B", "C"): _s(.3)}
    cl, notes = L.cluster(recs, scored, model())
    assert cl["A"] != cl["C"]
    assert cl["B"] != cl["D"]
    assert notes[("B", "D")] in ("cannot_link_spans", "ambiguous")


def test_ambiguous_row_against_a_rival_cluster_goes_to_review():
    # X joins {Y} at auto, but X also reaches review level against Z, and Z is cannot-link with Y
    recs = _recs(["X", "Y", "Z"])
    scored = {("X", "Y"): _s(.99), ("X", "Z"): _s(.7), ("Y", "Z"): _s(.3, ["event_dates_gt_180d"])}
    cl, notes = L.cluster(recs, scored, model())
    assert len({cl["X"], cl["Y"], cl["Z"]}) == 3
    assert notes[("X", "Y")] == "ambiguous"


def test_a_weakly_separated_cluster_is_not_a_rival():
    recs = _recs(["X", "Y", "Z"])
    scored = {("X", "Y"): _s(.99), ("X", "Z"): _s(.7), ("Y", "Z"): _s(.3)}
    cl, _ = L.cluster(recs, scored, model())
    assert cl["X"] == cl["Y"] != cl["Z"]


def test_no_auto_cluster_grows_past_the_cap():
    ids = [f"N{i:02d}" for i in range(14)]
    recs = _recs(ids)
    scored = {(a, b): _s(.999) for a, b in combinations(ids, 2)}
    cl, notes = L.cluster(recs, scored, model())
    sizes = {}
    for c in cl.values():
        sizes[c] = sizes.get(c, 0) + 1
    assert max(sizes.values()) <= L.MAX_AUTO_CLUSTER
    assert "cluster_size_cap" in notes.values()


def test_rows_beyond_the_cap_go_to_review_not_to_a_second_cluster():
    # 14 rows of one story: one cluster of 10; the 4 refused rows stand alone (listed, review
    # pending), never a second, truncated cluster of 4 (advisor s8 d)
    ids = [f"N{i:02d}" for i in range(14)]
    recs = _recs(ids)
    scored = {(a, b): _s(.999) for a, b in combinations(ids, 2)}
    cl, notes = L.cluster(recs, scored, model())
    sizes = Counter(cl.values())
    assert sorted(sizes.values()) == [1, 1, 1, 1, 10]
    alone = [i for i in ids if sizes[cl[i]] == 1]
    assert all(cl[i] == i for i in alone)
    for i in alone:
        refused = [k for k in scored if i in k and notes.get(k) == "cluster_size_cap"]
        assert refused and all(L.decision_of(scored[k], notes[k]) == "review_pending" for k in refused)


def test_cluster_id_is_the_earliest_member_then_the_id():
    recs = build([dict(iid="b", name="Zeta Widget", pub="2025-01-01"), dict(iid="a", name="Zeta Widget", pub="2025-01-01"),
                  dict(iid="0", name="Zeta Widget", pub="2025-02-01")])
    scored = {k: _s(.99) for k in [("0", "a"), ("0", "b"), ("a", "b")]}
    cl, _ = L.cluster(recs, scored, model())
    assert set(cl.values()) == {"a"}


# ---- scoring -----------------------------------------------------------------------------------
def test_single_token_is_capped_unless_close_event_or_domain():
    m = model()
    base = dict(name="Allianz", country="US", sector="insurance", pub="2025-07-20", persons=[5000])
    # single token, event 30 days apart, no domain: capped (s7 b3)
    a, b = build([dict(base, iid="x", ev="2025-06-16", sources=["wa_ag"]),
                  dict(base, iid="y", ev="2025-07-16", pub="2025-07-21", sources=["de_ag"])])
    s = m.score(a, b)
    assert s["probability"] >= L.PROVISIONAL_AUTO and s["cap_reasons"] == ["single_token"] and s["band"] == "review"
    # the same pair with event delta <= 14 days, or an equal domain, may auto-link
    a, b = build([dict(base, iid="x", ev="2025-07-10", sources=["wa_ag"]),
                  dict(base, iid="y", ev="2025-07-16", pub="2025-07-21", sources=["de_ag"])])
    assert m.score(a, b)["band"] == "auto"
    a, b = build([dict(base, iid="x", ev="2025-06-16", domain="allianz.com", sources=["wa_ag"]),
                  dict(base, iid="y", ev="2025-07-16", pub="2025-07-21", domain="allianz.com", sources=["de_ag"])])
    assert m.score(a, b)["band"] == "auto"


def test_dateless_press_rule_is_45_days_and_a_qualifying_name():
    # thresholds at 0 so the band shows the caps alone, not the provisional score
    m = L.Model(L.PROVISIONAL_M, U_TEST, idf(), model().prior, auto=0.0, review=0.0)
    reg = dict(iid="r", name="Zeta Widget Pharma", country="US", sector="Health", ev="2025-03-01", pub="2025-03-20",
               sources=["wa_ag"])
    near = dict(iid="p", name="Zeta Widget Pharma", country="US", sector="Health", pub="2025-04-10",
                sources=["news_krebs"])
    s = m.score(*build([reg, near]))
    assert s["levels"]["public"] == "p45" and not s["capped"] and s["band"] == "auto"
    far = dict(near, pub="2025-06-10")                          # 82 days: review
    s = m.score(*build([reg, far]))
    assert s["cap_reasons"] == ["dateless_press"] and s["band"] != "auto"
    # a single-token name level never qualifies, even within 45 days
    s = m.score(*build([dict(reg, name="Zeta"), dict(near, name="Zeta Widget")]))
    assert s["levels"]["name"] not in L.DATELESS_NAMES and s["band"] != "auto"


def test_card_issuer_notices_are_cannot_link_and_legacy_edges_link():
    rows = [dict(iid="x1", org="o-ax", name="American Express Travel Related Services Company", country="US",
                 ev="2025-01-02", pub="2025-02-01", sources=["ca_ag"]),
            dict(iid="x2", org="o-ax", name="American Express Travel Related Services Company", country="US",
                 ev="2025-01-05", pub="2025-02-03", sources=["ca_ag"], dup_of="x1")]
    recs, cand, scored, cl, _ = run_fixture(rows)
    s = scored[("x1", "x2")]
    assert "card_issuer_notices" in s["cannot"] and s["legacy"]
    assert L.decision_of(s, None) == "cannot_link" and cl["x1"] != cl["x2"]
    # a legacy edge between two ordinary rows at review level or above is taken
    rows = [dict(iid="l1", org="o", name="Zeta Widget", country="US", sector="Health", pub="2025-05-20", sources=["news_krebs"]),
            dict(iid="l2", org="o", name="Zeta Widget", country="US", sector="Health", pub="2025-06-01", sources=["news_krebs"], dup_of="l1")]
    recs, cand, scored, cl, _ = run_fixture(rows)
    s = scored[("l1", "l2")]
    assert L.REVIEW <= s["probability"] < L.PROVISIONAL_AUTO and s["legacy"] and s["band"] == "auto"
    assert cl["l1"] == cl["l2"]
    # and refused when a cannot-link spans it
    rows[1] = dict(rows[1], org="o2", country="CA")
    recs, cand, scored, cl, _ = run_fixture(rows)
    assert cl["l1"] != cl["l2"]


def test_legacy_edge_below_the_floor_is_not_taken(monkeypatch):
    # s9: two years apart the model scores the pair below review; the legacy link is refused
    rows = [dict(iid="l1", org="o", name="Zeta Widget", country="US", pub="2023-01-01", sources=["news_krebs"]),
            dict(iid="l2", org="o", name="Zeta Widget", country="US", pub="2025-06-01", sources=["news_krebs"], dup_of="l1")]
    recs, cand, scored, cl, _ = run_fixture(rows)
    s = scored[("l1", "l2")]
    assert s["probability"] < L.LEGACY_MIN_P and not s["legacy"] and s["band"] != "auto" and cl["l1"] != cl["l2"]
    monkeypatch.setattr(L, "LEGACY_MIN_P", None)
    recs, cand, scored, cl, _ = run_fixture(rows)
    assert scored[("l1", "l2")]["legacy"] and cl["l1"] == cl["l2"]


def test_legacy_edges_can_be_switched_off(monkeypatch):
    monkeypatch.setattr(L, "LEGACY_EDGES", False)
    rows = [dict(iid="l1", org="o", name="Zeta Widget", country="US", pub="2023-01-01", sources=["news_krebs"]),
            dict(iid="l2", org="o", name="Zeta Widget", country="US", pub="2025-06-01", sources=["news_krebs"], dup_of="l1")]
    recs, cand, scored, cl, _ = run_fixture(rows)
    assert not scored[("l1", "l2")]["legacy"] and cl["l1"] != cl["l2"]


def test_bf_is_monotone_in_event_delta_under_the_provisional_m():
    for c in ("reg_reg", "reg_hibp", "reg_press", "press_press", "other"):
        k = f"event:{c}"
        bf = [math.log2(L.PROVISIONAL_M[k][lvl] / U_TEST[k][lvl]) for lvl in ("d0", "d3", "d14", "d45", "d120", "gt120")]
        assert bf == sorted(bf, reverse=True), c


def test_provisional_m_tables_are_distributions():
    for k, levels in L.m_u_keys().items():
        assert set(L.PROVISIONAL_M[k]) == set(levels)
        assert abs(sum(L.PROVISIONAL_M[k].values()) - 1) < 1e-9, k


def test_estimate_u_is_seeded_and_never_zero():
    recs = build([dict(iid=f"r{i}", name=n, pub=f"2025-0{1 + i % 9}-01", ev=None if i % 2 else f"2025-0{1 + i % 9}-01",
                       sources=[["wa_ag", "news_krebs", "hibp"][i % 3]])
                  for i, n in enumerate(["Acme", "Acme Health", "Globex", "Initech", "Umbrella", "Acme", "Hooli", "Soylent"])])
    u1 = L.estimate_u(recs, idf(), n_pairs=2000, seed=7)
    u2 = L.estimate_u(recs, idf(), n_pairs=2000, seed=7)
    assert u1 == u2
    for k in L.m_u_keys():
        assert all(v > 0 for v in u1[k].values()) and abs(sum(u1[k].values()) - 1) < 1e-9


def test_em_returns_distributions_and_finds_the_match_class():
    lv = [({"name": "exact", "domain": "missing", "event": "d0", "public": "p14", "impossible": "ok",
            "source": "diff_reg", "country": "agree", "sector": "agree", "count": "other"}, "reg_reg")] * 50
    lv += [({"name": "none", "domain": "missing", "event": "gt120", "public": "gt365", "impossible": "impossible",
             "source": "same_reg", "country": "conflict", "sector": "differ", "count": "other"}, "reg_reg")] * 150
    m, lam, it, _ = L.em_m(lv, U_TEST, L.PROVISIONAL_M)
    assert 0.15 < lam < 0.35
    for k in m:
        assert abs(sum(m[k].values()) - 1) < 1e-6


# ---- end to end on a tiny snapshot: determinism and the blind labelling files --------------------
def _write_snapshot(d, rows):
    orgs, incs, srcs, claims = {}, [], [], []
    for r in rows:
        oid = r.get("org", "o-" + r["iid"])
        orgs.setdefault(oid, {"org_id": oid, "display_name": r["name"], "norm_name": L.norm_name(r["name"]),
                              "domain": r.get("domain"), "country": r.get("country"), "sector": r.get("sector"),
                              "sec_cik": r.get("cik"), "aliases": [], "alias_norms": [], "is_natural_person": False})
        incs.append({"incident_id": r["iid"], "org_id": oid, "event_date": r.get("ev"), "first_public_date": r["pub"],
                     "suppressed": False, "possible_duplicate_of": r.get("dup_of")})
        for n, s in enumerate(r.get("sources", ["ca_ag"])):
            srcs.append({"incident_id": r["iid"], "source_id": s, "source_record_id": f"{r['iid']}-{n}",
                         "doc_sha256": "", "match_method": "new"})
        for n in r.get("persons", []):
            claims.append({"claim_id": f"c-{r['iid']}-{n}", "incident_id": r["iid"], "field": "people_affected",
                           "value_num": n, "value_text": None, "unit": "persons", "qualifier": "exact",
                           "basis": "news", "source_id": r.get("sources", ["ca_ag"])[0], "as_of": r["pub"],
                           "accepted": True, "superseded_by": None, "extraction_id": None, "review_verdict": None})
    for name, data in (("organizations", orgs.values()), ("incidents", incs), ("incident_sources", srcs), ("claims", claims)):
        (d / f"{name}.jsonl").write_text("".join(json.dumps(x) + "\n" for x in data))


def test_run_twice_is_byte_identical_and_labels_are_blind(tmp_path):
    snap = tmp_path / "snap"
    snap.mkdir()
    _write_snapshot(snap, ALLIANZ + [GLOBAL_RISKS] + BASE)
    (snap / "source_records.jsonl").write_text(json.dumps(
        {"source_id": "wa_ag", "source_record_id": "a1-0", "version": 1,
         "record": {"entitystate": "MN", "datestart": "2025-07-16", "name": "Allianz Life"}}) + "\n")
    s1 = L.run(snap, tmp_path / "r1", n_u=3000, seed=1, em=False)
    s2 = L.run(snap, tmp_path / "r2", n_u=3000, seed=1, em=False)
    assert s1["sha256"] == s2["sha256"]
    summ = S.sample(snap, tmp_path / "r1", tmp_path / "labels")
    hold = (tmp_path / "labels" / "holdout_pairs.jsonl").read_bytes()
    assert summ["holdout_sha256"] == hashlib.sha256(hold).hexdigest()
    forbidden = {"p", "p_provisional", "band", "levels", "weights", "match_weight", "block_keys", "cannot",
                 "decision", "probability", "features", "possible_duplicate_of", "norm_name"}

    def keys(o):
        if isinstance(o, dict):
            for k, v in o.items():
                yield k
                yield from keys(v)
        elif isinstance(o, list):
            for v in o:
                yield from keys(v)
    for f in ("holdout_pairs.jsonl", "dev_pairs.jsonl", "seeds.jsonl"):
        for line in (tmp_path / "labels" / f).read_text().splitlines():
            assert not (set(keys(json.loads(line))) & forbidden), f
    meta = [json.loads(x) for x in (tmp_path / "labels" / "pairs_meta.jsonl").read_text().splitlines()]
    assert not ({m["group"] for m in meta if m["split"] == "holdout"} & {m["group"] for m in meta if m["split"] == "dev"})
    assert all(m["stratum"] and m["weight"] >= 1 and m["n_h_pool"] <= m["N_h_pool"] for m in meta)
    for split in ("holdout", "dev"):
        per = Counter(m["group"] for m in meta if m["split"] == split and not m["stratum"].startswith("census"))
        assert max(per.values(), default=0) <= S.GROUP_CAP
    # the regulator's own state reaches the labeller
    corpus = {json.loads(x)["incident_id"]: json.loads(x) for x in (tmp_path / "labels" / "search_corpus.jsonl").read_text().splitlines()}
    assert corpus["a1"]["regulator_states"] == ["MN"]
    wa = [s for s in corpus["a1"]["sources"] if s["source_id"] == "wa_ag"][0]
    assert wa["regulator_fields"]["entitystate"] == "MN"


def test_strata_are_exclusive_and_in_precedence_order():
    base = {"a": "x", "b": "y", "p": 0.9, "block_keys": ["B2:k"], "cannot": [],
            "levels": {"name": "exact", "domain": "missing"}}
    assert S.stratum_of(dict(base, pair_class="hibp_press", cannot=["distinctive_tokens_conflict"]), set()) == "census:hibp_press"
    assert S.stratum_of(dict(base, pair_class="reg_reg", levels={"name": "exact", "domain": "different"},
                             cannot=["domain_differs"]), set()) == "domain_diff"
    assert S.stratum_of(dict(base, pair_class="reg_reg", cannot=["distinctive_tokens_conflict"],
                             block_keys=["B6:o"]), set()) == "conflict"
    assert S.stratum_of(dict(base, pair_class="reg_reg", block_keys=["B6:o"]), {"x"}) == "legacy_amexdisc"
    assert S.stratum_of(dict(base, pair_class="reg_reg", block_keys=["B2:k", "B6:possible_duplicate_of"]), set()) == "legacy"
    assert S.stratum_of(dict(base, pair_class="reg_reg"), set()) == "main"


# ---- _lacks: abbreviations, prefixes, acronyms (advisor ruling 2026-10-19) ---------------------
DFX = dict(DF, florida=40, washington=60, retina=5, hshs=1, sisters=20, mass=9, massachusetts=30,
           justice=15, finance=60, metro=12, metropolitan=25, baker=10)


def lacks(t, own, other):
    return L._lacks(t, tuple(own.split()), tuple(other.split()), L.Idf(DFX, N_ORGS))


@pytest.mark.parametrize("short,long_", [("st", "saint"), ("mt", "mount"), ("ctr", "center"), ("hosp", "hospital"),
                                         ("med", "medical"), ("intl", "international"), ("natl", "national"),
                                         ("assn", "association"), ("svcs", "services"), ("dept", "department"),
                                         ("univ", "university")])
def test_every_abbreviation_is_kin(short, long_):
    assert not lacks(short, f"acme {short}", f"acme {long_}")
    assert not lacks(long_, f"acme {long_}", f"acme {short}")


def test_prefix_of_three_or_more_is_kin_but_not_shorter_or_cjk():
    assert not lacks("mass", "mass general", "massachusetts general")
    assert not lacks("massachusetts", "massachusetts general", "mass general")
    assert not lacks("metro", "los angeles metro", "los angeles county metropolitan")
    assert lacks("ma", "ma general", "massachusetts general")
    assert L._kin("トヨタ", "トヨタ紡織") is False


def test_acronym_of_consecutive_tokens_is_kin_in_both_directions():
    assert not lacks("hshs", "hshs", "hospital sisters health system")
    assert not lacks("sisters", "hospital sisters health system", "hshs")
    assert not lacks("na", "flagstar bank na", "flagstar bank n a")


def test_a_common_word_is_never_an_acronym():
    # "of florida" has the initials "of": it must not cover "florida"
    assert lacks("florida", "retina of florida", "retina of washington")
    assert lacks("justice", "california department of justice", "california department of finance")


def test_the_fix_keeps_real_conflicts_and_drops_spelling_ones():
    def lvl(a, b):
        ra, rb = build([dict(iid="x", name=a, pub="2025-01-01"), dict(iid="y", name=b, pub="2025-01-01")])
        return L.name_level(ra, rb, L.Idf(DFX, N_ORGS))
    assert lvl("Retina Group of Florida", "Retina Group of Washington") == "conflict"
    assert lvl("Allianz Life Insurance Company", "Allianz Global Risks U.S. Insurance Company") == "conflict"
    assert lvl("Northwest Radiologists and Mount Baker Imaging", "Northwest Radiologists and Mt. Baker Imaging") != "conflict"
    assert lvl("Hospital Sisters Health System", "HSHS Hospital Sisters") != "conflict"


def test_b2p_pairs_are_capped_at_review():
    # a bare parent name against a longer one, events a month apart: capped (s7 b3 allows <= 14 d only)
    rows = [dict(iid="p1", name="Allianz", country="US", ev="2025-06-16", pub="2025-07-20", sources=["wa_ag"]),
            dict(iid="p2", name="Allianz Life", country="US", ev="2025-07-16", pub="2025-07-21", sources=["de_ag"])]
    recs, cand, scored, cl, _ = run_fixture(rows)
    assert any(k.startswith("B2p:") for k in cand[("p1", "p2")])
    assert scored[("p1", "p2")]["capped"] and scored[("p1", "p2")]["band"] != "auto"


def test_block_membership_is_not_a_scoring_input():
    recs = build(BASE)
    m = model()
    s = m.score(*recs)
    assert "block_keys" not in s and set(s["weights"]) <= set(L.FEATURES) | {"name_tf"}


# ---- R3: anomalous event dates and a one-year typo (advisor, 2026-10-19) -----------------------
def test_event_after_own_publication_or_before_1990_is_anomalous():
    recs = build([dict(iid="e1", name="Zeta Widget", ev="2025-06-01", pub="2025-05-01"),
                  dict(iid="e2", name="Zeta Widget", ev="1971-01-01", pub="2025-05-01"),
                  dict(iid="e3", name="Zeta Widget", ev="2025-04-01", pub="2025-05-01")])
    by = {r.iid: r for r in recs}
    assert by["e1"].ev_anomalous and by["e1"].ev is None and by["e1"].evb is not None
    assert by["e2"].ev_anomalous and by["e2"].ev is None
    assert not by["e3"].ev_anomalous and by["e3"].ev is not None


def test_anomalous_date_is_out_of_delta_event_and_the_event_cannot_link():
    a, b = build([dict(iid="x", name="Zeta Widget", ev="2026-01-01", pub="2025-05-01"),
                  dict(iid="y", name="Zeta Widget", ev="2025-04-01", pub="2025-05-03")])
    c = L.compare(a, b, idf())
    assert c["levels"]["event"] == "missing" and "event_dates_gt_180d" not in c["cannot"]


def test_anomalous_date_is_out_of_the_impossibility_feature():
    # x's (anomalous) event is after y's publication: without R3 that reads "impossible"
    a, b = build([dict(iid="x", name="Zeta Widget", ev="2025-06-01", pub="2025-05-01"),
                  dict(iid="y", name="Zeta Widget", pub="2025-05-10")])
    assert L.compare(a, b, idf())["levels"]["impossible"] == "na"


def test_anomalous_date_still_blocks():
    rows = [dict(iid="x", name="Zeta Widget Alpha", ev="2025-06-01", pub="2025-05-01"),
            dict(iid="y", name="Zeta Gadget Alpha", ev="2025-06-02", pub="2023-01-01")]
    cand, _, _ = L.block(build(rows), L.Idf({"zeta": 3, "alpha": 400, "widget": 5, "gadget": 5}, N_ORGS))
    assert any(k.startswith("B3:") for k in cand.get(("x", "y"), []))


def test_same_month_day_one_year_apart_is_its_own_level_and_not_cannot_link():
    a, b = build([dict(iid="x", name="Zeta Widget", ev="2024-03-05", pub="2025-04-01"),
                  dict(iid="y", name="Zeta Widget", ev="2025-03-05", pub="2025-04-02")])
    c = L.compare(a, b, idf())
    assert c["levels"]["event"] == "md_match_year_off" and "event_dates_gt_180d" not in c["cannot"]
    a, b = build([dict(iid="x", name="Zeta Widget", ev="2023-03-05", pub="2025-04-01"),
                  dict(iid="y", name="Zeta Widget", ev="2025-03-05", pub="2025-04-02")])
    c = L.compare(a, b, idf())
    assert c["levels"]["event"] == "gt120" and "event_dates_gt_180d" in c["cannot"]


# ---- step 4: m from labels, the mechanical threshold, class caps, the frozen model -----------------
LV_MATCH = {"name": "exact", "domain": "missing", "event": "d0", "public": "p14", "impossible": "ok",
            "source": "diff_reg", "country": "agree", "sector": "agree", "count": "other"}


U_NORM = {k: {lvl: v / sum(row.values()) for lvl, v in row.items()} for k, row in U_TEST.items()}


def test_estimate_m_is_a_distribution_smoothed_towards_u():
    lab = [(LV_MATCH, "reg_reg", 1.0)] * 40 + [(dict(LV_MATCH, name="contain"), "reg_reg", 1.0)] * 10
    m = L.estimate_m(lab, U_NORM, alpha=4.0)
    for k, levels in L.m_u_keys().items():
        assert set(m[k]) == set(levels) and abs(sum(m[k].values()) - 1) < 1e-9, k
        assert all(v > 0 for v in m[k].values()), k
    # an unseen level: m = alpha * u / (n_eff + alpha), so its BF is log2(alpha / (n_eff + alpha))
    assert m["name"]["none"] == pytest.approx(4 * U_NORM["name"]["none"] / 54)
    assert m["name"]["exact"] == pytest.approx((50 * 0.8 + 4 * U_NORM["name"]["exact"]) / 54)
    # a date class with no labelled match keeps m = u (BF 0): no evidence, no weight
    assert m["event:sec_any"] == pytest.approx(U_NORM["event:sec_any"])


def test_estimate_m_uses_the_horvitz_thompson_weights():
    lab = [(LV_MATCH, "reg_reg", 9.0)] + [(dict(LV_MATCH, name="contain"), "reg_reg", 1.0)]
    m = L.estimate_m(lab, U_NORM, alpha=0.0)
    assert m["name"]["exact"] == pytest.approx(0.9)
    assert m["event:press_press"] == U_NORM["event:press_press"]       # no data and no prior: m = u
    assert m["_meta"]["per_key"]["name"]["n_eff"] == pytest.approx(100 / 82, abs=1e-3)


def test_wilson_lower_bound():
    assert L.wilson_lower(1.0, 59) == pytest.approx(0.93887, abs=1e-4)
    assert L.wilson_lower(0.95, 100) == pytest.approx(0.8882, abs=1e-3)
    assert L.wilson_lower(0.5, 0) == 0.0
    assert L.wilson_lower(1.0, 73) >= 0.95 > L.wilson_lower(1.0, 72)


def test_auto_threshold_is_the_lowest_qualifying_posterior():
    rows = [(0.99, True, 1.0, True)] * 80 + [(0.6, False, 1.0, True)] * 5 + [(0.7, True, 1.0, True)] * 10
    t, r = L.auto_threshold(rows)
    assert t == 0.7 and r["n"] == 90 and r["precision"] == 1.0
    # an ineligible (cannot-link) pair never counts
    assert L.auto_threshold(rows + [(0.995, False, 1.0, False)] * 50)[0] == 0.7


def test_auto_threshold_requires_the_weighted_bound_too():
    # unweighted 199/200 passes; the one false positive carries much of the weight, so HT fails
    rows = [(0.99, True, 1.0, True)] * 199 + [(0.99, False, 1.0, True)]
    assert L.auto_threshold(rows)[0] == 0.99
    heavy = [(0.99, True, 1.0, True)] * 199 + [(0.99, False, 40.0, True)]
    assert L.wilson_lower(199 / 200, 200) >= 0.95
    assert L.auto_threshold(heavy) == (None, None)


def test_auto_threshold_is_none_when_too_few_pairs():
    assert L.auto_threshold([(0.99, True, 1.0, True)] * 72) == (None, None)
    assert L.auto_threshold([(0.4, True, 1.0, True)] * 500) == (None, None)    # below the review floor


def test_class_cap_and_model_thresholds():
    a, b = build(BASE)
    free = L.Model(L.PROVISIONAL_M, U_TEST, idf(), model().prior, auto=0.9)
    assert free.score(a, b)["band"] == "auto"
    capped = L.Model(L.PROVISIONAL_M, U_TEST, idf(), model().prior, auto=0.9, auto_classes=["press_press"])
    s = capped.score(a, b)
    assert s["pair_class"] == "reg_reg" and s["capped"] and s["band"] == "review"
    allowed = L.Model(L.PROVISIONAL_M, U_TEST, idf(), model().prior, auto=0.9, auto_classes=["reg_reg"])
    assert allowed.score(a, b)["band"] == "auto"
    strict = L.Model(L.PROVISIONAL_M, U_TEST, idf(), model().prior, auto=1.01)
    assert strict.score(a, b)["band"] == "review"


def _frozen(path, **over):
    f = {"method_version": L.METHOD_VERSION, "code_sha256": "x", "m": L.PROVISIONAL_M, "u": U_TEST,
         "prior": model().prior, "auto": 0.95, "review": 0.5, "auto_classes": ["reg_reg"]}
    f.update(over)
    path.write_text(json.dumps(f))
    return path


def test_load_frozen_refuses_another_method_version_or_a_missing_key(tmp_path):
    with pytest.raises(ValueError):
        L.load_frozen(_frozen(tmp_path / "f.json", method_version="breach-linkage-v0"), idf())
    p = tmp_path / "g.json"
    p.write_text(json.dumps({"method_version": L.METHOD_VERSION}))
    with pytest.raises(ValueError):
        L.load_frozen(p, idf())
    mdl, _ = L.load_frozen(_frozen(tmp_path / "h.json"), idf())
    assert mdl.name == "frozen" and mdl.auto_classes == frozenset({"reg_reg"})


def test_frozen_run_twice_is_byte_identical_and_uses_the_frozen_tables(tmp_path):
    snap = tmp_path / "snap"
    snap.mkdir()
    _write_snapshot(snap, ALLIANZ + [GLOBAL_RISKS] + BASE)
    fz = _frozen(tmp_path / "model_frozen.json")
    s1 = L.run(snap, tmp_path / "r1", frozen=fz)
    s2 = L.run(snap, tmp_path / "r2", frozen=fz)
    assert s1["sha256"] == s2["sha256"] and s1["model"] == "frozen"
    assert json.loads((tmp_path / "r1" / "u.json").read_text()) == U_TEST
    assert not (tmp_path / "r1" / "m_provisional.json").exists()
    pairs = [json.loads(x) for x in (tmp_path / "r1" / "pairs.jsonl").read_text().splitlines()]
    # only reg_reg may auto-link under this frozen model, apart from legacy edges (s7 b1)
    assert all(p["pair_class"] == "reg_reg" for p in pairs if p["band"] == "auto" and not p["legacy"])
    assert any(p["band"] == "auto" for p in pairs)


# ---- s9: an explicit repeat event never auto-links across to the earlier one ------------------------
def _with_titles(rows):
    """build() plus source documents: rows carry `title`."""
    orgs, incs, srcs, docs = {}, [], [], []
    for r in rows:
        oid = r.get("org", "org-" + r["iid"])
        orgs.setdefault(oid, {"org_id": oid, "display_name": r["name"], "norm_name": L.norm_name(r["name"]),
                              "domain": r.get("domain"), "country": r.get("country"), "sector": r.get("sector"),
                              "sec_cik": None, "alias_norms": [], "is_natural_person": False})
        incs.append({"incident_id": r["iid"], "org_id": oid, "event_date": r.get("ev"), "first_public_date": r["pub"],
                     "suppressed": False, "possible_duplicate_of": r.get("dup_of")})
        sha = hashlib.sha256(r["iid"].encode()).hexdigest()
        srcs.append({"incident_id": r["iid"], "source_id": r.get("source", "news_databreaches"), "doc_sha256": f"{sha}:{r['name']}"})
        docs.append({"doc_sha256": sha, "title": r.get("title", "")})
    return L.build_records(list(orgs.values()), incs, srcs, [], docs)


INST = [dict(iid=f"i{n}", org="o-i", name="Instructure", country="US", sector="education", pub=f"2026-05-0{n}",
             title=f"Instructure data breach update {n}") for n in (4, 5, 6)]
# The fixture (advisor s10 a): the 7 May 2026 DataBreaches headline on Instructure's second compromise.
AGAIN = dict(iid="i7", org="o-i", name="Instructure", country="US", sector="education", pub="2026-05-07",
             title="Developing:  ShinyHunters Hacks Instructure Again; Canvas Down (1)")


@pytest.mark.parametrize("title,repeat", [("Developing:  ShinyHunters Hacks Instructure Again; Canvas Down (1)", True),
                                          ("Cybercriminals say they hacked Winona County, MN (again)", True),
                                          ("Prudential Insurance suffers second data breach within a year", True),
                                          ("OH: West Chester Township investigates second cyberattack this month", True),
                                          ("Acme says it was re-breached", True),
                                          ("大阪府に再び不正アクセス", True),
                                          ("Chattanooga Heart Institute raises cyber attack victim count (again) to 550,000 people", False),
                                          ("Bojangles sued again by workers over Russian hacker data breach", False),
                                          ("Kido had a second incident to address", False),
                                          ("Harrods alerts customers to new data breach", False),
                                          ("Instructure discloses data breach", False),
                                          ("Second-quarter results", False)])
def test_repeat_title(title, repeat):
    assert bool(L.REPEAT_TITLE.search(title)) is repeat


def test_repeat_event_row_goes_to_review_and_the_first_cluster_holds():
    recs = _with_titles(INST + [AGAIN])
    by = {r.iid: r for r in recs}
    assert by["i7"].repeat and not by["i4"].repeat
    free = L.Model(L.PROVISIONAL_M, U_TEST, idf(), model().prior, auto=0.0, review=0.0)
    s = free.score(by["i4"], by["i7"])
    assert "repeat_event" in s["cap_reasons"] and s["band"] != "auto"
    assert free.score(by["i4"], by["i5"])["band"] == "auto"
    scored = {k: free.score(by[k[0]], by[k[1]]) for k in combinations(sorted(by), 2)}
    cl, _ = L.cluster(recs, scored, free, review=0.0)
    assert len({cl[i] for i in ("i4", "i5", "i6")}) == 1 and cl["i7"] == "i7"


def test_repeat_rule_lets_matching_event_dates_through_and_blocks_a_legacy_edge(monkeypatch):
    free = L.Model(L.PROVISIONAL_M, U_TEST, idf(), model().prior, auto=0.0, review=0.0)
    a, b = _with_titles([dict(INST[0], ev="2026-05-01"), dict(AGAIN, ev="2026-05-03")])
    assert "repeat_event" not in free.score(a, b)["cap_reasons"]
    a, b = _with_titles([dict(INST[0], ev="2026-04-20"), dict(AGAIN, ev="2026-05-03")])
    assert "repeat_event" in free.score(a, b)["cap_reasons"]
    a, b = _with_titles([INST[0], dict(AGAIN, dup_of="i4")])
    s = free.score(a, b)
    assert not s["legacy"] and s["band"] != "auto"
    monkeypatch.setattr(L, "REPEAT_EVENT", False)
    assert free.score(a, b)["band"] == "auto"


def test_a_row_covering_both_events_does_not_chain_them():
    both = dict(iid="i9", org="o-i", name="Instructure", country="US", sector="education", pub="2026-05-12",
                title="Government to scrutinize Instructure over Canvas breach")
    recs = _with_titles(INST + [AGAIN, both])
    by = {r.iid: r for r in recs}
    free = L.Model(L.PROVISIONAL_M, U_TEST, idf(), model().prior, auto=0.0, review=0.0)
    scored = {k: free.score(by[k[0]], by[k[1]]) for k in combinations(sorted(by), 2)}
    cl, _ = L.cluster(recs, scored, free, review=0.0)
    assert cl["i7"] == "i7" and cl["i9"] == cl["i4"]


# ---- v2 (advisor s15, R11): title evidence -----------------------------------------------------------
def _titled(rows, aliases=()):
    """build_records with source documents (rows carry `title`) and an actor alias table."""
    orgs, incs, srcs, docs = {}, [], [], []
    for r in rows:
        oid = r.get("org", "org-" + r["iid"])
        orgs.setdefault(oid, {"org_id": oid, "display_name": r["name"], "norm_name": L.norm_name(r["name"]),
                              "domain": r.get("domain"), "country": r.get("country"), "sector": r.get("sector"),
                              "sec_cik": None, "alias_norms": [], "is_natural_person": False})
        incs.append({"incident_id": r["iid"], "org_id": oid, "event_date": r.get("ev"), "first_public_date": r["pub"],
                     "suppressed": False, "possible_duplicate_of": r.get("dup_of")})
        sha = hashlib.sha256(r["iid"].encode()).hexdigest()
        srcs.append({"incident_id": r["iid"], "source_id": r.get("source", "news_databreaches"), "doc_sha256": f"{sha}:x"})
        docs.append({"doc_sha256": sha, "title": r.get("title", "")})
    al = [{"alias_norm": a, "actor_id": x} for a, x in aliases]
    return L.build_records(list(orgs.values()), incs, srcs, [], docs, {"aliases": al, "claims": [], "leak_claims": []})


ALIASES = (("shinyhunters", "shinyhunters"), ("yanluowang", "yanluowang"), ("acmesoft", "acme-crew"))
CISCO = [dict(iid="c1", org="o-c", name="Zeta Netsys", country="US", pub="2025-10-03",
              title="ShinyHunters Launches Data Leak Site: Trinity of Chaos"),
         dict(iid="c2", org="o-c", name="Zeta Netsys", country="US", pub="2025-11-01",
              title="Russian national pleads guilty to Yanluowang ransomware attacks")]


def test_actor_index_resolves_titles_and_drops_aliases_that_are_organisation_words():
    recs = _titled(CISCO + [dict(iid="c3", org="o-x", name="Acmesoft Ltd", pub="2025-01-01", title="Acmesoft hit")], ALIASES)
    by = {r.iid: r for r in recs}
    assert by["c1"].actors == {"shinyhunters"} and by["c2"].actors == {"yanluowang"}
    assert by["c3"].actors == frozenset()          # "acmesoft" names an organisation: not actor evidence
    assert L.actor_norm("LockBit Ransomware") == "lockbit" and L.actor_norm("INC Ransom") == "incransom"


def test_different_named_actors_are_capped_at_review_never_cannot_link(monkeypatch):
    free = L.Model(L.PROVISIONAL_M, U_TEST, idf(), model().prior, auto=0.0, review=0.0)
    a, b = _titled(CISCO, ALIASES)
    s = free.score(a, b)
    assert "actor_conflict" in s["cap_reasons"] and s["band"] == "review" and not s["cannot"]
    monkeypatch.setattr(L, "ACTOR_CONFLICT", False)
    assert free.score(a, b)["band"] == "auto"


def test_one_side_without_an_actor_is_not_a_conflict():
    a, b = _titled([CISCO[0], dict(CISCO[1], title="Zeta Netsys confirms breach")], ALIASES)
    assert not L.compare(a, b, idf())["raw"]["actor_conflict"]


FBI = [dict(iid="f1", org="o-f", name="Zeta Bureau", country="US", pub="2026-03-10",
            title="Zeta Bureau investigates intrusion into surveillance system"),
       dict(iid="f2", org="o-f", name="Zeta Bureau", country="US", pub="2026-03-20",
            title="Foreign hacker in 2023 compromised files held by Zeta Bureau")]


def test_a_title_stating_an_earlier_year_blocks_auto(monkeypatch):
    free = L.Model(L.PROVISIONAL_M, U_TEST, idf(), model().prior, auto=0.0, review=0.0)
    a, b = _titled(FBI)
    s = free.score(a, b)
    assert "year_conflict" in s["cap_reasons"] and s["band"] != "auto"
    monkeypatch.setattr(L, "YEAR_CONFLICT", False)
    assert free.score(a, b)["band"] == "auto"


def test_a_stated_year_that_matches_the_other_rows_event_year_or_is_recent_is_no_conflict():
    free = L.Model(L.PROVISIONAL_M, U_TEST, idf(), model().prior, auto=0.0, review=0.0)
    a, b = _titled([dict(FBI[0], ev="2023-06-01", pub="2026-03-10"), FBI[1]])
    assert "year_conflict" not in free.score(a, b)["cap_reasons"]
    a, b = _titled([FBI[0], dict(FBI[1], title="Zeta Bureau 2025 breach update")])
    assert "year_conflict" not in free.score(a, b)["cap_reasons"]


def _cedar(monkeypatch=None):
    rows = [dict(iid="r1", org="o-s", name="Cedar Valley Services", country="US", pub="2025-05-01", sources=["hhs_ocr"]),
            dict(iid="r2", org="o-h", name="Cedar Valley Hospice", country="US", pub="2025-05-20", sources=["hhs_ocr"]),
            dict(iid="p1", org="o-s", name="Cedar Valley Services", country="US", pub="2025-05-10", sources=["news_hipaajournal"])]
    recs = build(rows)
    m = L.Model(L.PROVISIONAL_M, U_TEST, idf(), model().prior, auto=0.0, review=0.0)
    by = {r.iid: r for r in recs}
    scored = {k: m.score(by[k[0]], by[k[1]]) for k in combinations(sorted(by), 2)}
    return recs, scored, m


def test_two_regulator_rows_of_different_organisations_never_share_a_cluster_through_a_bridge(monkeypatch):
    monkeypatch.setattr(L, "QUALIFIER_CONFLICT", False)      # isolate the guard from the s16(2) conflict
    recs, scored, m = _cedar()
    assert scored[("r1", "r2")]["raw"]["one_sided_distinct"] and not scored[("r1", "r2")]["cannot"]
    cl, notes = L.cluster(recs, scored, m, review=0.0)
    assert cl["r1"] != cl["r2"]
    monkeypatch.setattr(L, "REG_BRIDGE_GUARD", False)
    cl, _ = L.cluster(recs, scored, m, review=0.0)
    assert cl["r1"] == cl["r2"]


def test_guard_scope_either_also_separates_the_press_row_from_the_other_filing(monkeypatch):
    monkeypatch.setattr(L, "QUALIFIER_CONFLICT", False)
    monkeypatch.setattr(L, "REG_GUARD_SCOPE", "either")
    recs, scored, m = _cedar()
    cl, _ = L.cluster(recs, scored, m, review=0.0)
    assert cl["p1"] == cl["r1"] and cl["r2"] == "r2"


def test_a_stripped_qualifier_against_a_distinctive_token_is_conflict_not_contain(monkeypatch):
    a, b = build([dict(iid="x", name="Cedar Valley Services", pub="2025-05-01"),
                  dict(iid="y", name="Cedar Valley Hospice", pub="2025-05-02")])
    assert L.name_level(a, b, idf()) == "conflict"
    assert "distinctive_tokens_conflict" in L.compare(a, b, idf())["cannot"]
    # no qualifier stripped: still containment ("Cedar Valley" vs "Cedar Valley Hospice")
    c, d = build([dict(iid="x", name="Cedar Valley", pub="2025-05-01"), dict(iid="y", name="Cedar Valley Hospice", pub="2025-05-02")])
    assert L.name_level(c, d, idf()) == "contain"
    monkeypatch.setattr(L, "QUALIFIER_CONFLICT", False)
    assert L.name_level(a, b, idf()) == "contain"


def test_the_qualifier_conflict_keeps_all_cedar_valley_services_rows_apart_from_the_hospice():
    recs, scored, m = _cedar()
    cl, _ = L.cluster(recs, scored, m, review=0.0)
    assert cl["p1"] == cl["r1"] and cl["r2"] == "r2"


def test_a_title_capped_pair_never_shares_a_cluster_through_a_bridge(monkeypatch):
    # FBI-shaped: f1 and f2 are year-capped; f3 is close to both. Without the guard f3 bridges them.
    rows = FBI + [dict(iid="f3", org="o-f", name="Zeta Bureau", country="US", ev="2023-06-01", pub="2026-03-15",
                       title="Zeta Bureau breach")]   # its 2023 event year matches f2: no cap with either side
    recs = _titled(rows)
    by = {r.iid: r for r in recs}
    free = L.Model(L.PROVISIONAL_M, U_TEST, idf(), model().prior, auto=0.0, review=0.0)
    scored = {k: free.score(by[k[0]], by[k[1]]) for k in combinations(sorted(by), 2)}
    assert scored[("f1", "f2")]["band"] == "review" and not scored[("f1", "f2")]["cannot"]
    cl, notes = L.cluster(recs, scored, free, review=0.0)
    assert cl["f1"] != cl["f2"] and "title_conflict" in notes.values()
    monkeypatch.setattr(L, "TITLE_CAP_GUARD", False)
    cl, _ = L.cluster(recs, scored, free, review=0.0)
    assert cl["f1"] == cl["f2"]


def test_a_japanese_press_pair_is_held_at_review(monkeypatch):
    free = L.Model(L.PROVISIONAL_M, U_TEST, idf(), model().prior, auto=0.0, review=0.0)
    a, b = build([dict(iid="j1", name="大阪市", country="JP", pub="2026-09-01", sources=["news_jp_itmedia"]),
                  dict(iid="j2", name="大阪市", country="JP", pub="2026-09-05", sources=["news_jp_securitynext"])])
    s = free.score(a, b)
    assert "ja_press" in s["cap_reasons"] and s["band"] == "review" and not s["cannot"]
    # a Latin-named row from a Japanese outlet counts too; two English press rows do not
    c, d = build([dict(iid="k1", name="Zeta Widget KK", pub="2026-09-01", sources=["news_jp_itmedia"]),
                  dict(iid="k2", name="Zeta Widget KK", pub="2026-09-02", sources=["news_krebs"])])
    assert "ja_press" in free.score(c, d)["cap_reasons"]
    e, f = build([dict(iid="e1", name="Zeta Widget", pub="2026-09-01", sources=["news_krebs"]),
                  dict(iid="e2", name="Zeta Widget", pub="2026-09-02", sources=["news_hackread"])])
    assert "ja_press" not in free.score(e, f)["cap_reasons"]
    monkeypatch.setattr(L, "JA_PRESS_CAP", False)
    assert free.score(a, b)["band"] == "auto"
