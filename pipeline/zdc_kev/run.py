"""KEV pipeline orchestrator.

    python -m zdc_kev.run --mode incremental          # normal scheduled run
    python -m zdc_kev.run --mode full                 # complete re-pull + reconciliation
    python -m zdc_kev.run --dry-run                   # fetch + normalise + eval, no writes

Design commitments worth stating explicitly:

* **One dead source cannot take down the run.** Each adapter's failure is recorded and
  the others continue; the run is marked not-ok, and the evals decide whether the
  result is publishable.
* **Withdrawal reconciliation only ever runs on a complete snapshot.** Treating an
  incremental delta's silence as removal would delete the back-catalogue — the exact
  opposite of "priority is the most comprehensive dataset".
* **The eval gate is part of the pipeline, not a separate ritual.** A run whose data
  fails an ERROR-severity check exits non-zero so CI refuses to promote it.
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
from .sources import get_source, registered_ids
from .sources.base import SourceState

log = logging.getLogger("zdc_kev")

PIPELINE = "kev"
CONSOLIDATION_METHOD = "v1"
AGREEMENT_METHOD = "v1"


def git_sha() -> str | None:
    sha = os.environ.get("GITHUB_SHA")
    if sha:
        return sha
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL, text=True
        ).strip()
    except (subprocess.SubprocessError, FileNotFoundError):
        return None


def collect_all(source_ids, mode, today, states):
    """Fetch and normalise every source. Never raises for an upstream failure."""
    results = []
    for source_id in source_ids:
        state = states.get(source_id, SourceState())
        try:
            source = get_source(source_id)
        except KeyError as exc:
            log.error("%s: %s", source_id, exc)
            continue

        log.info("collecting %s (mode=%s)", source_id, mode)
        try:
            with source.make_client() as client:
                result = source.collect(client, state, mode, today=today)
        except Exception as exc:  # noqa: BLE001 — an adapter bug must not kill the run
            log.exception("%s adapter raised", source_id)
            from .models import CollectResult

            result = CollectResult(source_id=source_id, error=f"adapter raised: {exc!r}")

        if result.unchanged:
            log.info("%s: unchanged upstream, nothing to do", source_id)
        elif result.error:
            log.error("%s: %s (%d observations kept)", source_id, result.error, len(result.observations))
        else:
            log.info("%s: %d observations", source_id, len(result.observations))
        results.append(result)
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="zdc-kev", description="Zero Day Clock KEV pipeline")
    parser.add_argument("--mode", choices=["incremental", "full"], default="incremental")
    parser.add_argument("--trigger", default="manual")
    parser.add_argument("--sources", help="comma-separated subset; default = all enabled")
    parser.add_argument("--dry-run", action="store_true", help="no database writes")
    parser.add_argument("--censored-at", help="ISO date; default = today (UTC)")
    parser.add_argument("--report", help="write the eval report as JSON to this path")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )

    today = date.today()
    censored_at = date.fromisoformat(args.censored_at) if args.censored_at else today
    report = EvalReport()

    # ---- dry run: no database, pure evals only --------------------------------
    if args.dry_run:
        source_ids = args.sources.split(",") if args.sources else registered_ids()
        results = collect_all(source_ids, args.mode, today, {})
        observations = [o for r in results for o in r.observations]
        report.add(evals.check_no_silent_empty(results))
        report.add(evals.check_sources_reported(results))
        report.add(evals.check_cve_shape(observations))
        report.add(evals.check_no_future_dates(observations, censored_at))
        report.add(evals.check_signal_not_inflated(observations))
        print(report.render())
        _write_report(args.report, report, observations, results)
        return 0 if report.ok else 1

    # ---- live run --------------------------------------------------------------
    conn = db.connect()
    registry = {s["source_id"]: s for s in db.enabled_sources(conn)}
    requested = args.sources.split(",") if args.sources else list(registry)
    source_ids = [s for s in requested if s in registry]
    skipped = [s for s in requested if s not in registry]
    if skipped:
        log.warning("skipping sources not enabled in core.kev_sources: %s", skipped)

    states = {sid: db.get_source_state(conn, sid) for sid in source_ids}
    run_id = db.start_run(conn, PIPELINE, args.mode, args.trigger, git_sha())
    conn.commit()

    counters = dict(
        sources_attempted=len(source_ids), sources_ok=0, entries_seen=0,
        entries_inserted=0, entries_updated=0, entries_withdrawn=0,
    )
    results = collect_all(source_ids, args.mode, today, states)
    all_observations = []
    persistence_errors: dict[str, str] = {}

    for result in results:
        try:
            fetch_ids = [db.record_fetch(conn, run_id, f) for f in result.fetches]
            last_fetch_id = fetch_ids[-1] if fetch_ids else None

            if result.observations and last_fetch_id:
                inserted, updated = db.upsert_observations(conn, result.observations, last_fetch_id)
                counters["entries_inserted"] += inserted
                counters["entries_updated"] += updated
                counters["entries_seen"] += len(result.observations)
                all_observations.extend(result.observations)

                if result.complete_snapshot and result.error is None:
                    withdrawn = db.reconcile_withdrawals(
                        conn,
                        result.source_id,
                        ((o.upstream_source, o.source_entry_id) for o in result.observations),
                    )
                    counters["entries_withdrawn"] += withdrawn
                    if withdrawn:
                        log.info("%s: %d entries withdrawn upstream", result.source_id, withdrawn)
                elif result.error:
                    log.warning(
                        "%s: snapshot incomplete, skipping withdrawal reconciliation",
                        result.source_id,
                    )

            if result.ok:
                counters["sources_ok"] += 1
            conn.commit()
        except Exception as exc:  # noqa: BLE001
            conn.rollback()
            persistence_errors[result.source_id] = f"{type(exc).__name__}: {exc}"
            log.exception("%s: persistence failed", result.source_id)

    withdrawn_by_decision = db.apply_assertion_withdrawals(conn)
    if withdrawn_by_decision:
        log.info("applied %d recorded assertion withdrawal(s)", withdrawn_by_decision)
    rows = db.rebuild_consolidated(conn, CONSOLIDATION_METHOD, censored_at, run_id)
    log.info("consolidated %d vulnerabilities", rows)
    pairs = db.rebuild_source_agreement(conn, AGREEMENT_METHOD, censored_at)
    log.info("computed agreement for %d observer pairs", pairs)
    conn.commit()

    expected = {sid: registry[sid].get("expected_min_entries") for sid in source_ids}
    report.add(evals.check_no_silent_empty(results))
    report.add(evals.check_sources_reported(results))
    report.add(evals.check_source_yield(results, expected))
    report.add(evals.check_cve_shape(all_observations))
    report.add(evals.check_no_future_dates(all_observations, censored_at))
    report.add(evals.check_signal_not_inflated(all_observations))
    for result in evals.run_db_evals(conn, results, persistence_errors):
        report.add(result)

    run_ok = report.ok and counters["sources_ok"] == counters["sources_attempted"]
    failures = "; ".join(f"{r.source_id}: {r.error}" for r in results if r.error) or None
    db.finish_run(
        conn, run_id, ok=run_ok, error=failures,
        notes={"consolidated_rows": rows, "agreement_pairs": pairs,
               # Stored counts, so the next run's coverage check compares like with like.
               "source_counts": db.live_entry_counts(conn),
               "evals": [r.name for r in report.results if r.blocking]},
        **counters,
    )
    conn.commit()
    conn.close()

    print(report.render())
    if not run_ok:
        print("RUN NOT OK: " + (failures or "one or more sources did not complete"))
    _write_report(args.report, report, all_observations, results, counters=counters, run_id=str(run_id))
    # Exit non-zero on either a failed eval or a failed run. Previously only the eval
    # report gated the exit code, so a run that fetched cleanly but persisted nothing
    # exited 0.
    return 0 if (report.ok and run_ok) else 1


def _write_report(path, report, observations, results, counters=None, run_id=None) -> None:
    if not path:
        return
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id,
        "ok": report.ok,
        "counters": counters or {},
        "observations": len(observations),
        "per_source": {
            r.source_id: {
                "observations": len(r.observations),
                "unchanged": r.unchanged,
                "complete_snapshot": r.complete_snapshot,
                "error": r.error,
                "fetches": len(r.fetches),
            }
            for r in results
        },
        "checks": [
            {
                "name": r.name, "severity": r.severity, "passed": r.passed,
                "summary": r.summary, "detail": r.detail,
            }
            for r in report.results
        ],
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, default=str)


if __name__ == "__main__":
    sys.exit(main())
