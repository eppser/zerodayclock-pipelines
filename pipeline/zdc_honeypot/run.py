"""Shadowserver honeypot pipeline.

    python -m zdc_honeypot.run                          # yesterday + today
    python -m zdc_honeypot.run --days 7                 # trailing 7 days
    python -m zdc_honeypot.run --start 2022-07-01 --end 2026-09-01 --backfill

The API takes one day per request (ranges are rejected, measured), so a range is a loop.
--backfill skips days already stored, which makes the whole thing resumable: if it dies
at day 900 of 1,523, running it again continues rather than restarting.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
from datetime import date, datetime, timedelta

from zdc_obs import db as obs_db
from zdc_obs.models import FetchRecord

from . import db, evals
from .client import fetch_day
from .models import parse_response

PIPELINE = "honeypot"
SOURCE_ID = "shadowserver_api"
log = logging.getLogger("zdc_honeypot")


def git_sha() -> str | None:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"],
                                       stderr=subprocess.DEVNULL, text=True).strip()
    except Exception:  # noqa: BLE001
        return None


def daterange(start: date, end: date):
    d = start
    while d <= end:
        yield d
        d += timedelta(days=1)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="zdc-honeypot")
    ap.add_argument("--start", help="first day (YYYY-MM-DD)")
    ap.add_argument("--end", help="last day (YYYY-MM-DD)")
    ap.add_argument("--days", type=int, help="trailing N days ending yesterday")
    ap.add_argument("--backfill", action="store_true",
                    help="skip days already stored, so the run is resumable")
    ap.add_argument("--max-days", type=int, default=400,
                    help="safety stop; a backfill of the full history needs --max-days 1600")
    ap.add_argument("--censored-at", help="override the censoring date")
    ap.add_argument("--trigger", default="manual")
    ap.add_argument("--dry-run", action="store_true", help="fetch and parse, write nothing")
    ap.add_argument("--report", help="write a JSON run report here")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")

    today = date.today()
    if args.days:
        end = today - timedelta(days=1)
        start = end - timedelta(days=args.days - 1)
    else:
        end = date.fromisoformat(args.end) if args.end else today
        start = date.fromisoformat(args.start) if args.start else end - timedelta(days=1)
    if start > end:
        log.error("start %s is after end %s", start, end)
        return 2
    censored_at = date.fromisoformat(args.censored_at) if args.censored_at else end

    wanted = list(daterange(start, end))
    if len(wanted) > args.max_days:
        log.error("%d days requested but --max-days is %d; raise it deliberately",
                  len(wanted), args.max_days)
        return 2

    if args.dry_run:
        conn = None
    else:
        conn = obs_db.connect()
        if args.backfill:
            have = db.days_present(conn, start, end)
            skipped = len(wanted)
            wanted = [d for d in wanted if d not in have]
            log.info("backfill: %d of %d days already stored, %d to fetch",
                     skipped - len(wanted), skipped, len(wanted))

    run_id = None
    if conn is not None:
        run_id = obs_db.start_run(conn, PIPELINE, "backfill" if args.backfill else "incremental",
                                  args.trigger, git_sha())
        conn.commit()

    fetches, all_errors, rows_by_day = [], [], {}
    total_rows = ins_d = upd_d = 0
    try:
        for n, day in enumerate(wanted, 1):
            res = fetch_day(day)
            fetches.append(res)
            if not res.ok:
                log.warning("%s: fetch failed — %s", day, res.error)
                if conn is not None:
                    obs_db.record_fetch(conn, run_id, FetchRecord(
                        source_id=SOURCE_ID, url=res.url, request_mode="full",
                        window_start=day, window_end=day, http_status=res.http_status,
                        ok=False, error=res.error, body=None, content_hash=None,
                        record_count=0, duration_ms=res.duration_ms))
                    conn.commit()
                continue
            body = res.body.decode()
            parsed, errors = parse_response(body, day)
            all_errors.extend(f"{day} {e}" for e in errors)
            rows_by_day[day] = len(parsed)
            total_rows += len(parsed)
            if conn is None:
                log.info("%s: %d rows (dry run)", day, len(parsed))
                continue
            fetch_id = obs_db.record_fetch(conn, run_id, FetchRecord(
                source_id=SOURCE_ID, url=res.url, request_mode="full",
                window_start=day, window_end=day, http_status=res.http_status,
                ok=True, error=None, body=res.body, content_hash=res.content_hash,
                record_count=len(parsed), duration_ms=res.duration_ms))
            a, b = db.upsert_observations(conn, parsed, fetch_id)
            ins_d += a; upd_d += b
            conn.commit()
            if n % 25 == 0 or n == len(wanted):
                log.info("%s (%d/%d): %d rows — inserted %d, revised %d",
                         day, n, len(wanted), len(parsed), ins_d, upd_d)
    except KeyboardInterrupt:
        log.warning("interrupted — committed work is kept; rerun with --backfill to resume")

    results = [evals.check_fetch_succeeded(fetches), evals.check_parse_errors(all_errors, range(total_rows)),
               evals.check_day_not_truncated(rows_by_day)]
    if conn is not None:
        results += evals.run_db_evals(conn, censored_at, total_rows,
                                      start if args.backfill else None,
                                      end if args.backfill else None)
    ok = not any(r.blocking for r in results)

    if conn is not None:
        obs_db.finish_run(
            conn, run_id, ok=ok,
            error=None if ok else "; ".join(r.summary for r in results if r.blocking),
            sources_attempted=1, sources_ok=1 if any(f.ok for f in fetches) else 0,
            observations_seen=total_rows, observations_inserted=ins_d,
            observations_updated=upd_d,
            notes={"days_requested": len(wanted), "daily_rows": total_rows,
                   "coverage": {k: str(v) for k, v in db.coverage(conn).items()}})
        conn.commit()
        conn.close()

    print(evals.render(results))
    if args.report:
        with open(args.report, "w") as fh:
            json.dump({"ok": ok, "days": len(wanted), "rows": total_rows,
                       "evals": [{"name": r.name, "severity": r.severity,
                                  "passed": r.passed, "summary": r.summary}
                                 for r in results]}, fh, indent=2)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
