"""CVE registry pipeline orchestrator.

    python -m zdc_cve.run --mode incremental   # deltas + NVD lastMod window
    python -m zdc_cve.run --mode full          # 562MB baseline + full NVD sweep
    python -m zdc_cve.run --dry-run

The incremental path is the point: the CVE Project republishes a 562 MB baseline every
midnight, but the end-of-day delta is ~4.5 MB and carried 2,439 changed records on
2026-08-27. Resumption is by release tag, so a missed run is picked up rather than
skipped, and the cursor only advances past releases that were actually consumed.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
from datetime import date, datetime, timezone

from . import db, evals
from .evals import EvalReport
from .models import CveCollectResult
from .sources import get_source, registered_ids
from .sources.base import CveSourceState

log = logging.getLogger("zdc_cve")
PIPELINE = "cve"


def git_sha() -> str | None:
    sha = os.environ.get("GITHUB_SHA")
    if sha:
        return sha
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"],
                                       stderr=subprocess.DEVNULL, text=True).strip()
    except (subprocess.SubprocessError, FileNotFoundError):
        return None


def collect_all(source_ids, mode, today, states):
    results = []
    for source_id in source_ids:
        state = states.get(source_id, CveSourceState())
        try:
            source = get_source(source_id)
        except KeyError as exc:
            log.error("%s: %s", source_id, exc)
            continue
        log.info("collecting %s (mode=%s, cursor=%s)", source_id, mode, state.cursor)
        try:
            with source.make_client() as client:
                result = source.collect(client, state, mode, today=today)
        except Exception as exc:  # noqa: BLE001
            log.exception("%s adapter raised", source_id)
            result = CveCollectResult(source_id=source_id, error=f"adapter raised: {exc!r}")
        if result.error:
            log.error("%s: %s (%d records kept)", source_id, result.error, len(result.records))
        elif result.unchanged:
            log.info("%s: nothing new upstream", source_id)
        else:
            log.info("%s: %d records from %s", source_id, len(result.records),
                     ", ".join(result.covered[:3]) or "?")
        results.append(result)
    return results


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="zdc-cve")
    ap.add_argument("--mode", choices=["incremental", "full"], default="incremental")
    ap.add_argument("--trigger", default="manual")
    ap.add_argument("--sources")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--report")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    today = date.today()
    report = EvalReport()

    if args.dry_run:
        ids = args.sources.split(",") if args.sources else registered_ids()
        results = collect_all(ids, args.mode, today, {})
        records = [r for res in results for r in res.records]
        report.add(evals.check_no_silent_empty(results))
        report.add(evals.check_sources_reported(results))
        report.add(evals.check_cve_ids_wellformed(records))
        report.add(evals.check_year_from_identifier(records))
        print(report.render())
        _write_report(args.report, report, records, results)
        return 0 if report.ok else 1

    conn = db.connect()
    registry = {s["source_id"]: s for s in db.enabled_sources(conn)}
    requested = args.sources.split(",") if args.sources else list(registry)
    source_ids = [s for s in requested if s in registry]
    if skipped := [s for s in requested if s not in registry]:
        log.warning("not enabled in core.cve_sources: %s", skipped)

    states = {s: db.get_source_state(conn, s) for s in source_ids}
    run_id = db.start_run(conn, PIPELINE, args.mode, args.trigger, git_sha())
    conn.commit()

    counters = dict(sources_attempted=len(source_ids), sources_ok=0,
                    entries_seen=0, entries_inserted=0, entries_updated=0)
    results = collect_all(source_ids, args.mode, today, states)
    all_records, persistence_errors, cursors = [], {}, {}

    for result in results:
        try:
            fetch_ids = [db.record_fetch(conn, run_id, f) for f in result.fetches]
            if result.records and fetch_ids:
                ins, upd = db.upsert_records(conn, result.records, fetch_ids[-1], result.source_id)
                counters["entries_inserted"] += ins
                counters["entries_updated"] += upd
                counters["entries_seen"] += len(result.records)
                all_records.extend(result.records)
            if result.ok:
                counters["sources_ok"] += 1
                # Advance the cursor ONLY on a clean run. A partial fetch must be
                # replayed next time, not skipped.
                if result.covered and result.source_id == "cve_project":
                    cursors[result.source_id] = result.covered[-1].split(":")[0]
            conn.commit()
        except Exception as exc:  # noqa: BLE001
            conn.rollback()
            persistence_errors[result.source_id] = f"{type(exc).__name__}: {exc}"
            log.exception("%s: persistence failed", result.source_id)

    corpus = db.corpus_counts(conn)
    log.info("corpus: %(total)s CVEs (%(in_cve_project)s CVE Project, %(in_nvd)s NVD)", corpus)

    report.add(evals.check_no_silent_empty(results))
    report.add(evals.check_sources_reported(results))
    report.add(evals.check_cve_ids_wellformed(all_records))
    report.add(evals.check_year_from_identifier(all_records))
    for r in evals.run_db_evals(conn):
        report.add(r)

    run_ok = report.ok and counters["sources_ok"] == counters["sources_attempted"] \
        and not persistence_errors
    failures = "; ".join(f"{r.source_id}: {r.error}" for r in results if r.error) or None
    db.finish_run(conn, run_id, ok=run_ok, error=failures,
                  notes={"corpus_total": corpus["total"], "cursor": cursors,
                         "covered": {r.source_id: r.covered for r in results}},
                  **counters)
    conn.commit()
    conn.close()

    print(report.render())
    if not run_ok:
        print("RUN NOT OK: " + (failures or "a source did not complete"))
    _write_report(args.report, report, all_records, results, counters, str(run_id), corpus)
    return 0 if (report.ok and run_ok) else 1


def _write_report(path, report, records, results, counters=None, run_id=None, corpus=None):
    if not path:
        return
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id, "ok": report.ok, "counters": counters or {},
        "corpus": corpus or {}, "records": len(records),
        "per_source": {r.source_id: {"records": len(r.records), "unchanged": r.unchanged,
                                     "complete_snapshot": r.complete_snapshot,
                                     "error": r.error, "fetches": len(r.fetches),
                                     "covered": r.covered[:5]} for r in results},
        "checks": [{"name": c.name, "severity": c.severity, "passed": c.passed,
                    "summary": c.summary, "detail": c.detail} for c in report.results],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)


if __name__ == "__main__":
    sys.exit(main())
