"""Unit tests: the weekly chart check (zdc_breach.r2_chart_check). Fixed clocks, synthetic counts, no database.
Every check has a test that makes it fail; the clock tests cover a month boundary, a year boundary and future months."""

from __future__ import annotations

import json
from datetime import date, datetime, timedelta, timezone

import pytest

from zdc_breach import r2_chart_check as C

U = timezone.utc


def at(y, m, d, h=9):
    return datetime(y, m, d, h, tzinfo=U)


def months_through(last: date, n=36, base=800):
    """n consecutive months ending at `last`, `base` events each."""
    return [{"month": C.add_months(last, -k).isoformat(), "breaches": base} for k in range(n - 1, -1, -1)]


def payload(now, last=None, base=800, undated=10, built_age_days=0.5, **over):
    ms = months_through(last or C.add_months(C.month_start(now.date()), -1), base=base)
    if last is None:                       # the month in progress, a few days' worth (unless the clock is on the 1st-3rd)
        ms.append({"month": C.month_start(now.date()).isoformat(), "breaches": base * now.day // 30})
    p = {"months": ms, "undated": undated, "events": sum(m["breaches"] for m in ms) + undated,
         "built": {"at": (now - timedelta(days=built_age_days)).isoformat(), "rows": 1}}
    p.update(over)
    return p


def run(p, now, shadow=None):
    return C.evaluate(p, p["events"] if shadow is None else shadow, now)


def st(rep, cid):
    return {c["id"]: c["status"] for c in rep["checks"]}.get(cid)


def test_healthy_mid_month():
    now = at(2026, 10, 26)
    rep = run(payload(now), now)
    assert rep["status"] == "ok" and C.EXIT[rep["status"]] == 0
    assert all(c["status"] == "ok" for c in rep["checks"])


def test_stale_shadow_fails_and_warns():
    now = at(2026, 10, 26)
    assert st(run(payload(now, built_age_days=8.5), now), "built_fresh") == "fail"
    assert st(run(payload(now, built_age_days=7.8), now), "built_fresh") == "warn"
    assert st(run(payload(now, built_age_days=7.2), now), "built_fresh") == "ok"


def test_missing_or_future_build_stamp_fails():
    now = at(2026, 10, 26)
    p = payload(now); p["built"] = None
    assert st(run(p, now), "built_present") == "fail"
    p = payload(now); p["built"] = {"at": (now + timedelta(days=1)).isoformat()}
    assert st(run(p, now), "built_present") == "fail"
    p = payload(now); p["built"] = {"at": "not a date"}
    assert run(p, now)["status"] == "fail"


def test_events_must_equal_shadow_distinct_events():
    now = at(2026, 10, 26)
    p = payload(now)
    assert st(run(p, now, shadow=p["events"] + 1), "events_match") == "fail"
    p["undated"] += 5                       # months + undated no longer add up to events
    assert st(run(p, now), "events_match") == "fail"


def test_future_month_fails():
    now = at(2026, 10, 26)
    p = payload(now)
    p["months"].append({"month": "2026-12-01", "breaches": 3}); p["events"] += 3
    rep = run(p, now)
    assert st(rep, "no_future") == "fail" and rep["status"] == "fail"


def test_month_structure_errors_fail():
    now = at(2026, 10, 26)
    for mutate in (lambda m: m.append(dict(m[-1])),                       # duplicate
                   lambda m: m.insert(0, {"month": "2030-01-01", "breaches": 1}),   # out of order
                   lambda m: m[3].update(month="2024-05-15"),             # not first of month
                   lambda m: m[3].update(breaches=-4),                    # negative
                   lambda m: m[3].update(breaches=1.5)):                  # not an integer
        p = payload(now)
        mutate(p["months"])
        assert st(run(p, now), "months_valid") == "fail"


def test_running_total_decrease_detected():
    # a negative count is the only way a cumulative total can fall: both months_valid and monotonic must fire
    now = at(2026, 10, 26)
    p = payload(now); p["months"][5]["breaches"] = -50
    rep = run(p, now)
    assert st(rep, "monotonic") == "fail" and st(rep, "months_valid") == "fail"


def test_last_complete_month_missing_or_zero_fails():
    now = at(2026, 10, 26)
    p = payload(now, last=date(2026, 8, 1))                    # September missing
    assert st(run(p, now), "last_complete") == "fail"
    p = payload(now); p["months"][-2]["breaches"] = 0
    assert st(run(p, now), "last_complete") == "fail"


def test_month_boundary_rotation_grace():
    # Nov 2: October is not required yet (sources report late); Sep must be there. Nov 5: October is required.
    p_sep = lambda now: payload(now, last=date(2026, 9, 1))
    now = at(2026, 11, 2)
    rep = run(p_sep(now), now)
    assert st(rep, "last_complete") == "ok" and rep["checks"][-1]
    assert [c["month"] for c in rep["checks"] if c["id"] == "last_complete"] == ["2026-09"]
    now = at(2026, 11, 5)
    rep = run(p_sep(now), now)
    assert st(rep, "last_complete") == "fail"
    assert [c["month"] for c in rep["checks"] if c["id"] == "last_complete"] == ["2026-10"]
    # and the current-month count of Oct (in progress) never makes the run red
    p = payload(now, last=date(2026, 10, 1))
    assert run(p, now)["status"] == "ok"


def test_year_boundary_rotation():
    # Jan 2: December is not required yet; Jan 5: December (previous YEAR) is required and November no longer enough
    now = at(2027, 1, 2)
    rep = run(payload(now, last=date(2026, 11, 1)), now)
    assert st(rep, "last_complete") == "ok"
    assert [c["month"] for c in rep["checks"] if c["id"] == "last_complete"] == ["2026-11"]
    now = at(2027, 1, 5)
    assert st(run(payload(now, last=date(2026, 11, 1)), now), "last_complete") == "fail"
    rep = run(payload(now, last=date(2026, 12, 1)), now)
    assert rep["status"] == "ok"
    assert [c["month"] for c in rep["checks"] if c["id"] == "last_complete"] == ["2026-12"]
    # December events are NOT 'future' in January; a January event at Dec 31 is
    now = at(2026, 12, 31)
    p = payload(now, last=date(2026, 11, 1)); p["months"].append({"month": "2027-01-01", "breaches": 2}); p["events"] += 2
    assert st(run(p, now), "no_future") == "fail"


def test_yoy_last_month_thresholds():
    now = at(2026, 10, 26)
    def with_last(n):
        p = payload(now); p["months"][-2]["breaches"] = n; p["events"] = sum(m["breaches"] for m in p["months"]) + p["undated"]
        return run(p, now)
    assert st(with_last(100), "yoy_last") == "fail"      # 0.125
    assert st(with_last(300), "yoy_last") == "warn"      # 0.375
    assert st(with_last(800), "yoy_last") == "ok"
    assert st(with_last(2000), "yoy_last") == "warn"     # 2.5
    assert st(with_last(4500), "yoy_last") == "fail"     # 5.6


def test_yoy_current_month_is_warn_only_and_projected():
    now = at(2026, 10, 26)
    p = payload(now, last=date(2026, 10, 1)); p["months"][-1]["breaches"] = 20   # projected ~24 vs 800
    p["events"] = sum(m["breaches"] for m in p["months"]) + p["undated"]
    rep = run(p, now)
    assert st(rep, "yoy_current") == "warn" and rep["status"] == "warn" and C.EXIT[rep["status"]] == 2
    now = at(2026, 10, 5)                                  # before day 10 no projection is made
    p = payload(now, last=date(2026, 10, 1)); p["months"][-1]["breaches"] = 20
    p["events"] = sum(m["breaches"] for m in p["months"]) + p["undated"]
    assert st(run(p, now), "yoy_current") is None


def test_short_history_warns_instead_of_guessing():
    now = at(2026, 10, 26)
    p = payload(now); p["months"] = p["months"][-8:]
    p["events"] = sum(m["breaches"] for m in p["months"]) + p["undated"]
    rep = run(p, now)
    assert st(rep, "history") == "warn" and st(rep, "yoy_last") is None


def test_undated_share_thresholds():
    now = at(2026, 10, 26)
    def with_undated(u):
        p = payload(now, undated=u); return run(p, now)
    total = sum(m["breaches"] for m in payload(now)["months"])
    assert st(with_undated(10), "undated_share") == "ok"
    assert st(with_undated(int(total * 0.08)), "undated_share") == "warn"
    assert st(with_undated(int(total * 0.25)), "undated_share") == "fail"


def test_main_exit_codes_and_report_is_counts_only(tmp_path, monkeypatch):
    now = at(2026, 10, 26)
    p = payload(now)
    class Conn: pass
    monkeypatch.setattr(C, "read_db", lambda conn: (p, p["events"]))
    out = tmp_path / "r.json"
    assert C.main(["--report", str(out)], now=now, conn=Conn()) == 0
    rep = json.loads(out.read_text())
    assert rep["exit_code"] == 0 and "months" in rep and isinstance(rep["months"], int)
    p2 = payload(now, built_age_days=9)
    monkeypatch.setattr(C, "read_db", lambda conn: (p2, p2["events"]))
    assert C.main([], now=now, conn=Conn()) == 1
    p3 = payload(now); p3["months"][-2]["breaches"] = 300; p3["events"] = sum(m["breaches"] for m in p3["months"]) + p3["undated"]
    monkeypatch.setattr(C, "read_db", lambda conn: (p3, p3["events"]))
    assert C.main([], now=now, conn=Conn()) == 2


def test_unreadable_database_is_a_failure_not_a_pass(monkeypatch, capsys):
    def boom(conn): raise RuntimeError("password=secret host=h")
    monkeypatch.setattr(C, "read_db", boom)
    assert C.main([], now=at(2026, 10, 26), conn=object()) == 1
    out = capsys.readouterr().out
    assert "secret" not in out and "RuntimeError" in out
