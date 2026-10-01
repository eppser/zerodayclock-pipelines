"""Harvest dated vendor fix records from MSRC CVRF.

  python -m zdc_patch.run --start 2016-01            # backfill from the first document
  python -m zdc_patch.run --months 2                 # the trailing two months, incrementally

Documents are REVISED after publication, so the trailing months are re-read on every run. The
write is keyed on (cve_id, source_id, patch_date) and revises rather than duplicates.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
from datetime import date

import psycopg

from zdc_kev import db as runs_db      # shared raw.pipeline_runs recorder

from . import client, db, parse

#: Recorded so the watchdog can tell "ran and found nothing" from "did not run" (0069).
#: Before this, patch and export left no trace of a run anywhere, so a workflow that
#: silently stopped firing was invisible in the database and to every eval.
PIPELINE = "patch"

log = logging.getLogger("zdc_patch")


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", help="YYYY-MM, backfill from this month")
    ap.add_argument("--months", type=int, default=2, help="trailing months for an incremental run")
    ap.add_argument("--delay", type=float, default=1.5)
    ap.add_argument("--report")
    args = ap.parse_args()

    today = date.today()
    if args.start:
        y, m = (int(x) for x in args.start.split("-"))
        wanted = client.months((y, m), today)
        mode = "backfill"
    else:
        y, m = today.year, today.month
        back = []
        for _ in range(max(1, args.months)):
            back.append(f"{y}-{date(y, m, 1).strftime('%b')}")
            m -= 1
            if m == 0:
                y, m = y - 1, 12
        wanted = list(reversed(back))
        mode = "incremental"

    log.info("%s: %d document(s), %s .. %s", mode, len(wanted), wanted[0], wanted[-1])

    url = os.environ["DATABASE_URL"]
    fetched = ok = 0
    statuses: dict[str, int] = {}
    written = 0
    purged = 0
    with psycopg.connect(url, connect_timeout=60) as conn:
        run_id = runs_db.start_run(conn, PIPELINE, mode, os.environ.get("GITHUB_EVENT_NAME", "manual"),
                                   os.environ.get("GITHUB_SHA"))
        conn.commit()
        db.ensure_source(conn)
        if mode == "backfill":
            # A backfill re-reads every document, so it is a complete snapshot and may
            # reconcile removals. A rule change that stops qualifying a record has to be able
            # to un-publish it; an upsert-only rebuild would leave the old answer standing.
            purged = db.purge(conn)
            log.info("backfill: purged %d existing rows before re-reading", purged)
        conn.commit()
        for doc_id in wanted:
            f = client.fetch_month(doc_id, delay=args.delay)
            fetched += 1
            statuses[str(f.status)] = statuses.get(str(f.status), 0) + 1
            if f.body is None:
                # 404 is expected for months Microsoft never published; anything else is
                # recorded and surfaced rather than silently treated as "no patches".
                log.warning("%s: %s", doc_id, f.error)
                continue
            ok += 1
            recs = parse.parse(f.body)
            written += db.upsert(conn, recs)
            conn.commit()
            log.info("%s: %d vendor fix records (release %s)",
                     doc_id, len(recs), parse.document_release_date(f.body))
        cov = db.coverage(conn)

        report_ok = ok > 0
        runs_db.finish_run(
            conn, run_id, ok=report_ok,
            error=None if report_ok else "no document parsed — a block or an outage",
            entries_seen=fetched, entries_inserted=written,
            notes={"documents_requested": len(wanted), "documents_fetched": fetched,
                   "documents_parsed": ok, "http_statuses": statuses,
                   "rows_purged": purged, "coverage": cov})
        conn.commit()

    report = {"mode": mode, "rows_purged": purged,
              "documents_requested": len(wanted), "documents_fetched": fetched,
              "documents_parsed": ok, "http_statuses": statuses, "records_written": written,
              "coverage": cov,
              # A run that fetched nothing is a block or an outage, never evidence that no
              # patches exist. Say which.
              "ok": ok > 0}
    log.info("coverage: %s", cov)
    if args.report:
        with open(args.report, "w") as fh:
            json.dump(report, fh, indent=2)
    print(json.dumps(report, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
