"""Enrichment pipeline orchestrator.

    python -m zdc_enrich.run                       # fetch EPSS if due, rebuild detail
    python -m zdc_enrich.run --skip-epss           # rebuild only
    python -m zdc_enrich.run --censored-at 2026-08-27
    python -m zdc_enrich.run --dry-run             # fetch and parse, persist nothing

Runs AFTER the KEV, observation and CVE pipelines. It reads what they wrote and
produces ``derived.cve_detail`` — one row per CVE.

The censoring date is derived from the last successful CVE registry fetch, not from
the clock, and is passed into the SQL transform as a parameter. Two runs over the same
snapshot with the same censoring date produce identical output.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
from datetime import date, datetime, timezone

from . import db, epss, evals
from .evals import EvalReport
from .models import EpssCollectResult

log = logging.getLogger("zdc_enrich")
PIPELINE = "enrich"
# v2 since 2026-09-01: classification draws on three evidence tiers rather than
# registry CPE data alone (migration 0036). The pipeline stamps ONE version across
# every table it rebuilds, so this moves for all of them; core.method_registry says
# which methods actually changed and which merely follow the pipeline.
# v3 since 2026-09-02: the pressure projection damps its fitted slope (migration 0040),
# and classification runs on five evidence tiers (0039). One version across every table
# this pipeline rebuilds; core.method_registry says which methods actually changed.
METHOD_VERSION = "v3"


def git_sha() -> str | None:
    sha = os.environ.get("GITHUB_SHA")
    if sha:
        return sha
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"],
                                       stderr=subprocess.DEVNULL, text=True).strip()
    except (subprocess.SubprocessError, FileNotFoundError):
        return None


def _write_report(path: str | None, report: EvalReport, payload: dict) -> None:
    if not path:
        return
    with open(path, "w") as fh:
        json.dump({
            "ok": report.ok,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            **payload,
            "checks": [{"name": r.name, "severity": r.severity, "passed": r.passed,
                        "summary": r.summary, "detail": r.detail} for r in report.results],
        }, fh, indent=2, default=str)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="zdc-enrich")
    ap.add_argument("--trigger", default="manual")
    ap.add_argument("--skip-epss", action="store_true",
                    help="rebuild the detail table without touching EPSS")
    ap.add_argument("--skip-technology", action="store_true",
                    help="skip the technology cohort rebuild")
    ap.add_argument("--force-epss", action="store_true",
                    help="fetch EPSS even if it was already fetched today")
    ap.add_argument("--censored-at", type=date.fromisoformat, default=None,
                    help="override the censoring date (default: last successful CVE fetch)")
    ap.add_argument("--method-version", default=METHOD_VERSION)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--report")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    report = EvalReport()

    # ---- dry run: fetch and parse, touch nothing -----------------------------
    if args.dry_run:
        with epss.make_client() as client:
            result = epss.collect(client, last_fetch_date=None, force=True)
        report.add(evals.check_epss_collected(result))
        report.add(evals.check_epss_rows_not_skipped(result))
        print(report.render())
        _write_report(args.report, report, {
            "epss_rows": len(result.records),
            "epss_model_version": result.model_version,
            "epss_score_date": result.score_date,
        })
        return 0 if report.ok else 1

    conn = db.connect()
    run_id = db.start_run(conn, PIPELINE, "incremental", args.trigger, git_sha())
    conn.commit()

    counters = dict(sources_attempted=0, sources_ok=0, entries_seen=0,
                    entries_inserted=0, entries_updated=0)
    result = EpssCollectResult()
    persistence_error: str | None = None

    # ---- 1. EPSS -------------------------------------------------------------
    if not args.skip_epss:
        counters["sources_attempted"] = 1
        last = db.last_epss_fetch_date(conn)
        with epss.make_client() as client:
            result = epss.collect(client, last_fetch_date=last, force=args.force_epss)

        report.add(evals.check_epss_collected(result))
        report.add(evals.check_epss_rows_not_skipped(result))

        try:
            fetch_ids = [db.record_fetch(conn, run_id, f) for f in result.fetches]
            if result.records and fetch_ids:
                ins, upd = db.upsert_epss(conn, result.records, fetch_ids[-1])
                counters.update(entries_seen=len(result.records),
                                entries_inserted=ins, entries_updated=upd)
                log.info("epss: %d inserted, %d updated", ins, upd)
            if result.ok:
                counters["sources_ok"] = 1
            conn.commit()
        except Exception as exc:  # noqa: BLE001
            conn.rollback()
            persistence_error = f"{type(exc).__name__}: {exc}"
            log.exception("epss: persistence failed")

    # ---- 2. Rebuild the detail table ----------------------------------------
    censored_at = args.censored_at or db.censoring_date(conn)
    # Same rule as the other ten: the registry owns the version, --method-version is
    # only the fallback for a metric that has not been registered.
    detail_version = db.current_method_versions(conn).get(
        "cve_detail", args.method_version)
    log.info("rebuilding derived.cve_detail (method=%s, censored_at=%s)",
             detail_version, censored_at)
    rebuilt = 0
    try:
        rebuilt = db.rebuild_cve_detail(conn, method_version=detail_version,
                                        censored_at=censored_at, run_id=run_id)
        conn.commit()
        log.info("derived.cve_detail: %d rows", rebuilt)
    except Exception as exc:  # noqa: BLE001
        conn.rollback()
        persistence_error = f"rebuild failed: {type(exc).__name__}: {exc}"
        log.exception("rebuild failed")

    # ---- 3. Derived tables, each in ITS OWN TRANSACTION ---------------------
    # ONE FAILURE MUST NOT ROLL BACK THE OTHERS. These ten rebuilds shared a single
    # transaction and a single try block: the first exception skipped every rebuild after it
    # and discarded every one before it. On 2026-09-01 a DEADLOCK inside rebuild_technology,
    # caused by a migration being applied concurrently, threw away the whole batch including
    # the three tables the Explorer reads, which had already succeeded.
    #
    # They are independent by construction: each reads derived.cve_detail and writes its own
    # table. Isolated, a flaky one costs its own output and nothing else, and the run reports
    # exactly which failed instead of blaming whichever ran first.
    REBUILDS = [
        ("technology_rows", "derived.technology_cohorts", db.rebuild_technology),
        ("corpus_rows", "derived.corpus_cohorts", db.rebuild_corpus_cohorts),
        ("patch_window_rows", "derived.patch_window_cohorts", db.rebuild_patch_window_cohorts),
        ("kev_technology_rows", "derived.kev_technology_cohorts", db.rebuild_kev_technology),
        ("severity_rows", "derived.severity_predictiveness", db.rebuild_severity_predictiveness),
        ("scan_pressure_rows", "derived.scan_pressure", db.rebuild_scan_pressure),
        ("scan_age_mix_rows", "derived.scan_age_mix", db.rebuild_scan_age_mix),
        # 0086, CrowdSec beside Shadowserver. Both are guarded in db.py: absent the
        # migration they return 0 instead of failing the run.
        ("scan_pressure_mix_rows", "derived.scan_pressure_mix", db.rebuild_scan_pressure_mix),
        ("scan_pressure_combined_rows", "derived.scan_pressure_combined", db.rebuild_scan_pressure_combined),
        ("scan_age_mix_combined_rows", "derived.scan_age_mix_combined", db.rebuild_scan_age_mix_combined),
        ("scan_age_mix_crowdsec_rows", "derived.scan_age_mix_crowdsec",
         db.rebuild_scan_age_mix_crowdsec),
        ("pressure_index_rows", "derived.pressure_index", db.rebuild_pressure_index),
        ("explorer_list_rows", "derived.explorer_list", db.rebuild_explorer_list),
        ("explorer_strata_rows", "derived.explorer_strata", db.rebuild_explorer_strata),
        ("cve_activity_rows", "derived.cve_activity_daily", db.rebuild_cve_activity),
        ("kev_lag_points_rows", "derived.kev_lag_points", db.rebuild_kev_lag_points),
    ]
    rebuild_rows: dict[str, int] = {key: 0 for key, _, _ in REBUILDS}
    rebuild_errors: dict[str, str] = {}
    rebuild_seconds: dict[str, float] = {}
    if not args.skip_technology and not persistence_error:
        rebuild_rows, rebuild_errors, rebuild_seconds = db.run_rebuilds(
            conn, REBUILDS, method_version=args.method_version,
            censored_at=censored_at, run_id=run_id, log=log)
        if rebuild_errors:
            # Still an error for the run: a table that did not rebuild is stale, and the
            # freshness evals below name which one.
            persistence_error = "rebuild failed - " + "; ".join(
                f"{k}: {v}" for k, v in rebuild_errors.items())

    # ---- 4. Assert against the database, not against the adapters ------------
    for r in evals.run_db_evals(conn):
        report.add(r)

    run_ok = report.ok and not persistence_error
    db.finish_run(conn, run_id, ok=run_ok, error=persistence_error,
                  notes={"censored_at": str(censored_at),
                         "method_version": args.method_version,
                         "detail_rows": rebuilt,
                         **rebuild_rows,
                         "rebuild_errors": rebuild_errors or None,
                         "rebuild_seconds": rebuild_seconds or None,
                         "epss_skipped": result.skipped_reason,
                         "epss_model_version": result.model_version},
                  **counters)
    conn.commit()

    print(report.render())
    _write_report(args.report, report, {
        "censored_at": censored_at,
        "method_version": args.method_version,
        "detail_rows": rebuilt,
        **rebuild_rows,
        "rebuild_errors": rebuild_errors or None,
        "rebuild_seconds": rebuild_seconds or None,
        "epss_rows": len(result.records),
        "epss_model_version": result.model_version,
        "epss_score_date": result.score_date,
        "epss_skipped": result.skipped_reason,
    })
    conn.close()
    return 0 if run_ok else 1


if __name__ == "__main__":
    sys.exit(main())
