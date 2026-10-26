"""Chart check for the staging chart "Breaches made public, running total per year".

The chart reads public.admin_breach_r2_monthly_events() -> breach_core.r2_monthly_events() (0192), computed live from the
private shadow breach_core.r2_victims_shadow, which only breach_core.rebuild_r2_shadow() refreshes. This check reads that
function (read-only, statement_timeout 60 s) plus one count over the shadow and says whether the chart data can be trusted.
Run it after the weekly R2 chain (workflow breach-r2-weekly.yml); the run goes red when the data is wrong or stale.

CHECKS (id: rule -> severity)
  built_present   shadow build stamp missing / unparseable / in the future (> 5 min ahead)   -> fail
  built_fresh     shadow built more than 8 days ago -> fail; more than 7.5 days ago -> warn
                  (a weekly cron runs 5-7 h late; 7.5 days is a late weekly run, 8 days is a missed one)
  events_match    events reported by the function != distinct events of the shadow
                  (coalesce(r2_event_id::text, victim_id)), or sum(months)+undated != events      -> fail
  months_valid    a month not first-of-month, duplicated, out of order, with a non-integer or negative count -> fail
  no_future       a month with events later than the current month                                -> fail
  monotonic       a per-year running total that ever decreases (cumulative sum of counts)          -> fail
  last_complete   the last complete month absent or 0 events -> fail. The first GRACE_DAYS (3) days of a month the
                  month before is allowed to be the newest, because sources report a few days late.
  yoy_last        last complete month vs the median of the 12 months before it:
                  ratio < 0.20 or > 5.00 -> fail;  ratio < 0.50 or > 2.00 -> warn
  yoy_current     current month, projected to a full month (count * days_in_month / day) from day PROJECT_FROM_DAY
                  (10) on, vs the same median: outside 0.20..5.00 -> warn only (a month in progress never fails a run)
  undated_share   events with no released reported date / events: > 15% fail, > 5% warn (2026-10-26: 1.6%)
  history         fewer than 12 months before the compared month: the yoy checks are skipped with a warn

Exit codes: 0 ok · 1 at least one fail (or the database could not be read) · 2 warnings only.
The JSON report is COUNTS ONLY: check ids, severities, numbers, month keys. No record, name or connection detail.

CLI (DATABASE_URL):  python -m zdc_breach.r2_chart_check [--report r2-chart-check.json]
"""

from __future__ import annotations

import argparse
import calendar
import json
import os
import statistics
import sys
from datetime import date, datetime, timedelta, timezone

STATEMENT_TIMEOUT = "60s"
FRESH_FAIL_DAYS = 8.0
FRESH_WARN_DAYS = 7.5
GRACE_DAYS = 3
PROJECT_FROM_DAY = 10
YOY_FAIL = (0.20, 5.0)
YOY_WARN = (0.50, 2.0)
UNDATED_FAIL = 0.15
UNDATED_WARN = 0.05
CLOCK_SKEW = timedelta(minutes=5)

OK, WARN, FAIL = "ok", "warn", "fail"


def month_start(d: date) -> date:
    return d.replace(day=1)


def add_months(d: date, n: int) -> date:
    i = d.year * 12 + d.month - 1 + n
    return date(i // 12, i % 12 + 1, 1)


def parse_ts(s) -> datetime | None:
    try:
        t = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def _f(checks: list, cid: str, sev: str, **nums):
    checks.append({"id": cid, "status": sev, **nums})


def evaluate(payload: dict, shadow_events: int, now: datetime) -> dict:
    """Pure: the function's payload + the shadow's distinct event count + a clock -> counts-only report."""
    checks: list = []
    today = now.astimezone(timezone.utc).date()
    cur = month_start(today)

    # built_present / built_fresh
    built = payload.get("built")
    at = parse_ts(built.get("at")) if isinstance(built, dict) else None
    if at is None or at > now + CLOCK_SKEW:
        _f(checks, "built_present", FAIL, built_at_parsed=at is not None)
    else:
        _f(checks, "built_present", OK)
        age = (now - at).total_seconds() / 86400
        sev = FAIL if age > FRESH_FAIL_DAYS else WARN if age > FRESH_WARN_DAYS else OK
        _f(checks, "built_fresh", sev, age_days=round(age, 2), fail_after_days=FRESH_FAIL_DAYS)

    # months_valid
    raw = payload.get("months") or []
    bad, months, seen = 0, [], set()
    prev = None
    for r in raw:
        try:
            d = date.fromisoformat(str(r["month"])[:10])
            n = r["breaches"]
        except (KeyError, ValueError, TypeError):
            bad += 1
            continue
        if d.day != 1 or isinstance(n, bool) or not isinstance(n, int) or n < 0 or d in seen or (prev and d <= prev):
            bad += 1
        seen.add(d)
        prev = d
        if isinstance(n, int) and not isinstance(n, bool):
            months.append((d, n))
    _f(checks, "months_valid", FAIL if bad else OK, months=len(raw), invalid=bad)
    counts = {d: n for d, n in months}

    # events_match
    events, undated = payload.get("events"), payload.get("undated")
    dated_sum = sum(n for _, n in months)
    ok_ev = (isinstance(events, int) and isinstance(undated, int)
             and events == shadow_events and dated_sum + undated == events)
    _f(checks, "events_match", OK if ok_ev else FAIL, events=events, shadow_distinct_events=shadow_events,
       dated=dated_sum, undated=undated)

    # no_future
    future = sorted(d for d, n in months if d > cur and n > 0)
    _f(checks, "no_future", FAIL if future else OK, future_months=len(future),
       first_future=future[0].isoformat()[:7] if future else None)

    # monotonic: per-year running totals (cumulative sums of non-negative counts never decrease)
    drops = 0
    for y in sorted({d.year for d, _ in months}):
        run = 0
        for m in range(1, 13):
            nxt = run + counts.get(date(y, m, 1), 0)
            if nxt < run:
                drops += 1
            run = nxt
    _f(checks, "monotonic", FAIL if drops else OK, decreasing_steps=drops)

    # last_complete
    last_complete = add_months(cur, -1)
    expected = add_months(cur, -2) if today.day <= GRACE_DAYS else last_complete
    n_exp = counts.get(expected, 0)
    _f(checks, "last_complete", OK if n_exp > 0 else FAIL, month=expected.isoformat()[:7], events=n_exp,
       grace_days=GRACE_DAYS)

    # year-over-year sanity
    def median_before(m: date):
        hist = [counts.get(add_months(m, -k), 0) for k in range(1, 13)]
        first = min(counts) if counts else None
        if first is None or add_months(m, -12) < first:
            return None
        return statistics.median(hist)

    def ratio_status(r, warn_only=False):
        if r < YOY_FAIL[0] or r > YOY_FAIL[1]:
            return WARN if warn_only else FAIL
        return WARN if (r < YOY_WARN[0] or r > YOY_WARN[1]) else OK

    med = median_before(last_complete)
    if med is None or med <= 0:
        _f(checks, "history", WARN, months_before=len([d for d in counts if d < last_complete]))
    else:
        r = counts.get(last_complete, 0) / med
        _f(checks, "yoy_last", ratio_status(r), month=last_complete.isoformat()[:7],
           events=counts.get(last_complete, 0), median_prev12=med, ratio=round(r, 3))
        if today.day >= PROJECT_FROM_DAY:
            dim = calendar.monthrange(today.year, today.month)[1]
            proj = counts.get(cur, 0) * dim / today.day
            medc = median_before(cur)
            if medc:
                r = proj / medc
                _f(checks, "yoy_current", ratio_status(r, warn_only=True), month=cur.isoformat()[:7],
                   events=counts.get(cur, 0), projected=round(proj), median_prev12=medc, ratio=round(r, 3))

    # undated_share
    if isinstance(events, int) and isinstance(undated, int) and events > 0:
        share = undated / events
        _f(checks, "undated_share", FAIL if share > UNDATED_FAIL else WARN if share > UNDATED_WARN else OK,
           share=round(share, 4), undated=undated, events=events)
    else:
        _f(checks, "undated_share", FAIL, events=events, undated=undated)

    status = FAIL if any(c["status"] == FAIL for c in checks) else WARN if any(c["status"] == WARN for c in checks) else OK
    return {"checked_at": now.astimezone(timezone.utc).isoformat(timespec="seconds"), "status": status,
            "events": events, "undated": undated, "months": len(raw),
            "last_month": max(counts).isoformat()[:7] if counts else None,
            "built_at": at.isoformat(timespec="seconds") if at else None, "checks": checks}


EXIT = {OK: 0, FAIL: 1, WARN: 2}


def read_db(conn) -> tuple[dict, int]:
    with conn.transaction(), conn.cursor() as cur:
        cur.execute("set transaction read only")
        cur.execute(f"set local statement_timeout = '{STATEMENT_TIMEOUT}'")
        cur.execute("select breach_core.r2_monthly_events()")
        payload = cur.fetchone()[0]
        cur.execute("select count(distinct coalesce(r2_event_id::text, victim_id)) from breach_core.r2_victims_shadow")
        n = cur.fetchone()[0]
    return payload, n


def error_label(e: BaseException) -> str:
    code = getattr(e, "sqlstate", None) or getattr(getattr(e, "diag", None), "sqlstate", None)
    return type(e).__name__ + (f":{code}" if code else "")


def main(argv=None, now: datetime | None = None, conn=None) -> int:
    ap = argparse.ArgumentParser(prog="zdc_breach.r2_chart_check")
    ap.add_argument("--report", help="write the counts-only report JSON here")
    a = ap.parse_args(argv)
    now = now or datetime.now(timezone.utc)
    try:
        if conn is None:
            import psycopg
            conn = psycopg.connect(os.environ["DATABASE_URL"], connect_timeout=20, autocommit=True)
        payload, n = read_db(conn)
        report = evaluate(payload, n, now)
    except Exception as e:                      # unreadable data is a failed check, never a pass
        report = {"checked_at": now.isoformat(timespec="seconds"), "status": FAIL,
                  "checks": [{"id": "read", "status": FAIL, "error": error_label(e)}]}
    code = EXIT[report["status"]]
    report["exit_code"] = code
    if a.report:
        with open(a.report, "w") as f:
            json.dump(report, f, indent=1)
    print(json.dumps(report))
    return code


if __name__ == "__main__":
    sys.exit(main())
