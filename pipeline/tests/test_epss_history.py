"""scripts/epss_history_backfill.py: the EPSS lifecycle rules, on simulated CVEs.

CVE-1 lives a whole life: it rises, dips into the 7-10% band, flaps below 7% for three days,
is knocked down by a new model, is missing from a day's file, and rises again. Each step is a
property of what ZDC2 records. supabase/tests/0091_epss_lifecycle_test.sql replays the same
life through the daily SQL record and must reach the same transitions.
"""

from __future__ import annotations

import importlib.util
from datetime import date, timedelta

from conftest import REPO_ROOT, requires_repo_files

pytestmark = requires_repo_files("scripts/epss_history_backfill.py")


def _mod():
    spec = importlib.util.spec_from_file_location("epss_hist", REPO_ROOT / "scripts/epss_history_backfill.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


D0 = date(2022, 2, 4)


def d(i: int) -> str:
    return (D0 + timedelta(i)).isoformat()


# The life of CVE-1, one score per day (None = absent from that day's file). The model is v2
# until day 14, when v3 starts. The SQL test replays this exact list.
LIFE = (
    [0.02]                 # 0     low on the first day of history
    + [0.15] * 7           # 1-7   rises and holds a week          -> up, dated day 1
    + [0.08] * 2           # 8-9   dips into the 7-10% band        -> nothing (hysteresis)
    + [0.05] * 3           # 10-12 below 7%, but only three days   -> nothing (dwell)
    + [0.12]               # 13    back above
    + [0.03] * 7           # 14-20 the new model rescores it low   -> down, dated 14, model_change
    + [None]               # 21    absent from the file            -> no move, state kept
    + [0.04]               # 22    still low
    + [0.60] * 7           # 23-29 rises again on its own          -> up, dated 23, organic
)
MODEL_FROM_DAY_14 = "v3"


def run(life=LIFE, others=None):
    m = _mod()
    h = m.History()
    for i, score in enumerate(life):
        rows = [] if score is None else [("CVE-1", score)]
        rows += (others or {}).get(i, [])
        h.day(D0 + timedelta(i), "v2" if i < 14 else MODEL_FROM_DAY_14, rows, first=(i == 0))
    return h


def moves(h, cve="CVE-1"):
    return [(t["changed_on"], t["direction"], t["cause"]) for t in h.transitions if t["cve_id"] == cve]


def test_the_whole_life_of_one_cve():
    h = run()
    assert moves(h) == [(d(1), "up", "organic"), (d(14), "down", "model_change"),
                        (d(23), "up", "organic")]
    s = h.summary["CVE-1"]
    assert s["confirmed_high"] is True
    assert (s["peak_score"], s["peak_date"], s["peak_model"]) == (0.6, d(23), "v3")
    assert (s["last_score"], s["last_date"]) == (0.6, d(29))
    assert s["cand_since"] is None


def test_each_move_carries_the_score_before_and_after():
    up, down, _ = run().transitions
    assert (up["score"], up["prev_score"]) == (0.15, 0.02)
    assert (down["score"], down["prev_score"], down["model_version"]) == (0.03, 0.12, "v3")


def test_a_move_still_inside_its_dwell_is_pending_not_recorded():
    h = run(LIFE[:26])          # the second rise has held three days of seven
    assert moves(h)[-1] == (d(14), "down", "model_change")
    s = h.summary["CVE-1"]
    assert (s["cand_high"], s["cand_since"], s["cand_score"], s["cand_prev"]) == (True, d(23), 0.6, 0.04)


def test_already_high_when_history_starts_and_high_on_its_first_score():
    h = run(others={0: [("CVE-2", 0.9)], 5: [("CVE-3", 0.3)]})
    assert moves(h, "CVE-2") == [(d(0), "up", "already_high")]
    assert moves(h, "CVE-3") == [(d(5), "up", "first_scored")]


def test_exactly_ten_percent_is_high_and_exactly_seven_is_not_low():
    h = run([0.02] + [0.10] * 7 + [0.07] * 10)
    assert moves(h) == [(d(1), "up", "organic")]


def test_the_peak_keeps_its_first_day():
    h = run([0.5, 0.5, 0.4])
    assert h.summary["CVE-1"]["peak_date"] == d(0)


def test_load_sql_is_one_transaction_that_replaces_history():
    m = _mod()
    h = run()
    sql = m.load_sql(h.transitions, list(h.summary.values()))
    assert sql.startswith("begin;") and sql.rstrip().endswith("commit;")
    assert "delete from core.epss_transitions" in sql and "cand_since" in sql
