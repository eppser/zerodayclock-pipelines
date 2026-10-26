"""R2 reported date v2 (r2x-reported-v2): event-level earliest non-follow-up member date. No network, no DB."""

from __future__ import annotations

from datetime import date

from zdc_breach import r2_reported as rr
from zdc_breach.r2_reported import MemberDate

TODAY = date(2026, 10, 24)
D = date.fromisoformat


def m(kind, mid, day, sk, role="member"):
    return MemberDate(kind, mid, role, D(day) if day else None, sk)


def test_min_over_members():
    v = rr.event_reported([m("claim", "a", "2025-03-10", "leak"), m("incident", "i", "2025-03-02", "press")], TODAY)
    assert v == ("accepted", D("2025-03-02"), "press", None)


def test_follow_up_never_sets_the_date():
    v = rr.event_reported([m("incident", "f", "2019-01-01", "press", "follow_up"),
                           m("incident", "i", "2025-03-02", "regulator")], TODAY)
    assert v[1] == D("2025-03-02") and v[2] == "regulator"


def test_follow_up_only_event_abstains():
    v = rr.event_reported([m("incident", "f", "2025-01-01", "press", "follow_up")], TODAY)
    assert v == ("abstain", None, None, "follow_up_only")


def test_no_dated_member_abstains():
    assert rr.event_reported([m("claim", "a", None, "leak")], TODAY)[0:4:3] == ("abstain", "no_member_date")


def test_tie_precedence_regulator_first():
    v = rr.event_reported([m("claim", "a", "2025-03-02", "leak"), m("incident", "p", "2025-03-02", "press"),
                           m("incident", "r", "2025-03-02", "regulator"), m("incident", "x", "2025-03-02", "index")], TODAY)
    assert v[2] == "regulator"
    v = rr.event_reported([m("claim", "a", "2025-03-02", "leak"), m("incident", "p", "2025-03-02", "press")], TODAY)
    assert v[2] == "press"
    v = rr.event_reported([m("claim", "a", "2025-03-02", "leak"), m("incident", "x", "2025-03-02", "index")], TODAY)
    assert v[2] == "index"


def test_future_and_implausible_rejected():
    assert rr.event_reported([m("claim", "a", "2026-11-01", "leak")], TODAY)[0::3] == ("rejected", "future_date")
    assert rr.event_reported([m("claim", "a", "1985-01-01", "leak")], TODAY)[0::3] == ("rejected", "implausible_year")
    assert rr.event_reported([m("claim", "a", "2026-10-24", "leak")], TODAY)[0] == "accepted"


def test_incident_date_kind():
    assert rr.incident_date(D("2025-01-05"), {"regulator", "press"}, [D("2025-01-05")]) == (D("2025-01-05"), "regulator")
    assert rr.incident_date(D("2025-01-05"), {"index"}, []) == (D("2025-01-05"), "index")
    assert rr.incident_date(D("2025-01-05"), {"index", "regulator"}, []) == (D("2025-01-05"), "regulator")
    assert rr.incident_date(D("2025-01-05"), {"press"}, [D("2025-01-07")]) == (D("2025-01-05"), "press")
    assert rr.incident_date(None, {"press"}, [D("2025-01-09"), D("2025-01-07")]) == (D("2025-01-07"), "press")
    assert rr.incident_date(None, set(), []) == (None, None)
    assert rr.incident_date(D("2025-01-05"), set(), []) == (D("2025-01-05"), None)


EV = {"e1": {"status": "active", "merged_into": None}, "e2": {"status": "merged", "merged_into": "e1"},
      "e3": {"status": "withdrawn", "merged_into": None}, "e4": {"status": "active", "merged_into": None},
      "e5": {"status": "active", "merged_into": None}, "e6": {"status": "merged", "merged_into": None}}
MEM = [{"event_id": "e1", "member_kind": "claim", "member_id": "c1", "role": "member"},
       {"event_id": "e2", "member_kind": "incident", "member_id": "i1", "role": "member"},
       {"event_id": "e3", "member_kind": "incident", "member_id": "i2", "role": "member"},
       {"event_id": "e4", "member_kind": "incident", "member_id": "i3", "role": "follow_up"},
       {"event_id": "e5", "member_kind": "doc", "member_id": "d1", "role": "member"},
       {"event_id": "e5", "member_kind": "incident", "member_id": "i4", "role": "member"},
       {"event_id": "e6", "member_kind": "claim", "member_id": "c1", "role": "member"}]
CLAIMS = {"c1": D("2025-06-10")}
INC = {"i1": {"first_public": D("2025-06-01"), "kinds": {"regulator"}, "doc_days": []},
       "i2": {"first_public": D("2020-01-01"), "kinds": {"press"}, "doc_days": [D("2020-01-01")]},
       "i3": {"first_public": D("2024-01-01"), "kinds": {"press"}, "doc_days": [D("2024-01-01")]},
       "i4": {"first_public": D("2023-05-05"), "kinds": {"index"}, "doc_days": []}}


def test_build_rows():
    rows = {r["subject_id"]: r for r in rr.build_rows(EV, MEM, CLAIMS, INC, TODAY)}
    assert set(rows) == {"e1", "e4", "e5"}                          # merged -> survivor; withdrawn and survivor-less merged dropped
    assert rows["e1"]["value"] == "2025-06-01" and rows["e1"]["source_kind"] == "regulator" \
        and rows["e1"]["basis"] == "filing" and rows["e1"]["verdict"] == "accepted"
    assert rows["e4"]["verdict"] == "abstain" and rows["e4"]["value"] is None and rows["e4"]["value_precision"] is None
    assert rows["e5"]["value"] == "2023-05-05" and rows["e5"]["basis"] == "index_added"   # doc members are not dated
    r = rows["e1"]
    assert (r["subject_kind"], r["field"], r["engine"], r["engine_version"], r["value_precision"]) == \
        ("event", "reported_date", "structured", "r2x-reported-v2", "day")


def test_basis_names():
    assert rr.BASIS == {"regulator": "filing", "index": "index_added", "press": "published_at", "leak": "leak_site"}
