"""CrowdSec Live Exploit Tracker pipeline.

    python -m zdc_crowdsec.run                 # daily: 30-day window, active CVEs
    python -m zdc_crowdsec.run --all           # include CVEs CrowdSec has never seen
    python -m zdc_crowdsec.run --dry-run       # fetch and parse, write nothing

WHY A 30-DAY WINDOW EVERY DAY. /cves/{id}/timeline is a ROLLING window - there is no
history endpoint, and whatever is not captured is gone. Re-reading 30 days on every run
costs the same requests as re-reading one and means up to 29 consecutive missed runs
leave no hole. It is also why every write is an upsert keyed on CVE@day: a re-read
revises, it never duplicates.

DELIBERATELY NO LOCAL-HOUR GUARD, for the reason honeypot-pipeline.yml records: that
pattern was measured dropping 20 of 21 scheduled runs. A daily aggregate does not care
which hour it runs.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta, timezone

from zdc_kev.models import FetchRecord
from zdc_obs import db as obs_db

from . import db, evals
from .client import CrowdSecClient
from .models import parse_cves, parse_timeline

PIPELINE = "crowdsec"
SOURCE_ID = "crowdsec"
log = logging.getLogger("zdc_crowdsec")


def git_sha() -> str | None:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"],
                                       stderr=subprocess.DEVNULL, text=True).strip()
    except Exception:  # noqa: BLE001
        return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="zdc-crowdsec")
    ap.add_argument("--since-days", type=int, default=30, choices=[1, 7, 30],
                    help="timeline window the API is asked for (its only three options)")
    ap.add_argument("--all", action="store_true",
                    help="also ask for CVEs CrowdSec has never observed")
    ap.add_argument("--workers", type=int, default=8,
                    help="parallel timeline fetches; the run is ~780 requests")
    ap.add_argument("--limit", type=int, help="stop after N CVEs (development only)")
    ap.add_argument("--trigger", default="manual")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--report", help="write a JSON run report here")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")

    key = os.environ.get("CROWDSEC_TRACKER_API_KEY")
    if not key:
        log.error("CROWDSEC_TRACKER_API_KEY is not set")
        return 2
    client = CrowdSecClient(key)
    today = datetime.now(timezone.utc).date()
    results: list = []
    report: dict = {"pipeline": PIPELINE, "since_days": args.since_days,
                    "censored_at": today.isoformat()}

    # ---- 1. the catalogue -------------------------------------------------
    t0 = datetime.now(timezone.utc)
    items, total, err = client.paged("/cves?detailed=true")
    rejected: list[str] = []
    states = {s.cve_id: s for s in parse_cves(items, rejected)}
    results.append(evals.check_catalogue_fetched(total or len(states), err))
    results.append(evals.check_rejected_ids(rejected))
    log.info("tracker catalogue: %s CVEs (total reported %s)", len(states), total)
    cat_fetch = FetchRecord(
        source_id=SOURCE_ID, url="https://admin.api.crowdsec.net/v1/cves?detailed=true",
        request_mode="full", http_status=200 if err is None else 0, ok=err is None,
        record_count=len(states), started_at=t0,
        finished_at=datetime.now(timezone.utc), error=err)

    wanted = [s for s in states.values() if args.all or s.active]
    if args.limit:
        wanted = wanted[:args.limit]
    log.info("timelines to fetch: %d of %d tracked", len(wanted), len(states))

    # ---- 2. the timelines -------------------------------------------------
    counts, failed = [], []

    def one(s):
        r = client.get(f"/cves/{s.cve_id}/timeline?since_days={args.since_days}")
        if r.status != 200:
            return s.cve_id, (r.error or f"HTTP {r.status}"), []
        # `upto=today` drops the partial current day: a few hours of counting would
        # read as a collapse against yesterday's full day.
        return s.cve_id, None, parse_timeline(s.cve_id, r.body, upto=today)

    t1 = datetime.now(timezone.utc)
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        for cid, e, pts in pool.map(one, wanted):
            if e:
                failed.append((cid, e))
            counts += pts
    log.info("timelines: %d ok, %d failed, %d day-counts in %.0fs",
             len(wanted) - len(failed), len(failed), len(counts),
             (datetime.now(timezone.utc) - t1).total_seconds())

    results.append(evals.check_timelines_fetched(len(wanted), failed))
    # Fetching cleanly and receiving nothing is the failure mode this project
    # keeps meeting; freshness would catch it three days later, which is three
    # days of green runs serving a series that stopped moving.
    results.append(evals.check_not_silently_empty(len(wanted), len(counts)))
    days_seen = len({c.day for c in counts})
    results.append(evals.check_window_complete(days_seen, max(1, args.since_days - 2)))
    results.append(evals.check_tag_characters_stripped(
        [{"title": s.title or "", "vendor": s.vendor or "", "product": s.product or ""}
         for s in states.values()]))
    results.append(evals.check_no_per_ip_data(
        [db._raw(states[c.cve_id], c) for c in counts[:200] if c.cve_id in states]))

    report.update({"tracked": len(states), "rejected_ids": len(rejected), "asked": len(wanted),
                   "timeline_failures": len(failed), "day_counts": len(counts),
                   "days_seen": days_seen})

    # ---- 3. persist -------------------------------------------------------
    inserted = updated = 0
    if args.dry_run:
        log.info("dry run: %d day-counts parsed, nothing written", len(counts))
    else:
        with obs_db.connect() as conn:
            run_id = obs_db.start_run(conn, PIPELINE, "incremental", args.trigger, git_sha())
            try:
                fetch_id = obs_db.record_fetch(conn, run_id, cat_fetch)
                inserted, updated = db.upsert_observations(conn, states, counts, fetch_id)
                conn.commit()
                log.info("stored: %d inserted, %d revised", inserted, updated)
                results.append(evals.check_persisted(inserted, updated, len(counts)))
                results.append(evals.check_not_in_kev_layer(conn))
                # The registry declares max_silence_days for this source and zdc_obs
                # will never read it - its freshness check is scoped to its own
                # collector. This is the only thing that does.
                results.append(evals.check_freshness(conn, today))
                span = db.stored_day_span(conn)
                report["stored_span"] = [str(span[0]), str(span[1]), span[2], span[3]]
                log.info("crowdsec now holds %s rows over %s CVEs, %s..%s",
                         f"{span[2]:,}", f"{span[3]:,}", span[0], span[1])
                ok = not any(r.blocking for r in results)
                obs_db.finish_run(conn, run_id, ok=ok, error=None if ok else "eval blocked",
                                  notes={"day_counts": len(counts), "tracked": len(states),
                                         "rejected_ids": len(rejected)})
                conn.commit()
            except Exception as exc:  # noqa: BLE001
                conn.rollback()
                obs_db.finish_run(conn, run_id, ok=False, error=f"{type(exc).__name__}: {exc}")
                conn.commit()
                log.exception("persistence failed")
                return 1

    report["inserted"], report["updated"] = inserted, updated
    report["checks"] = [{"name": r.name, "severity": r.severity, "passed": r.passed,
                         "summary": r.summary, **r.detail} for r in results]
    blocking = [r for r in results if r.blocking]
    report["ok"] = not blocking
    for r in results:
        log.info("[%s] %-5s %s: %s", "PASS" if r.passed else "FAIL",
                 r.severity, r.name, r.summary)
    if args.report:
        open(args.report, "w").write(json.dumps(report, indent=1, default=str))
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main())
