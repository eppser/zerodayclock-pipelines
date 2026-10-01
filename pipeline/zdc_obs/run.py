"""Exploitation observation pipeline orchestrator.

    python -m zdc_obs.run --mode incremental
    python -m zdc_obs.run --mode full          # MSRC 2016->now backfill (~130 documents)
    python -m zdc_obs.run --dry-run            # fetch + normalise + eval, no writes

Same commitments as the KEV orchestrator: one dead source cannot take the run down,
withdrawal-style reconciliation only ever acts on a complete snapshot, and the eval
gate is part of the pipeline rather than a separate ritual.
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
from .models import ObsCollectResult
from .sources import get_source, registered_ids
from .sources.base import ObsSourceState

log = logging.getLogger("zdc_obs")

PIPELINE = "observations"
ROLLUP_METHOD = "v1"


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
        state = states.get(source_id, ObsSourceState())
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
            result = ObsCollectResult(source_id=source_id, error=f"adapter raised: {exc!r}")
        if result.error:
            log.error("%s: %s (%d observations kept)", source_id, result.error,
                      len(result.observations))
        else:
            log.info("%s: %d observations", source_id, len(result.observations))
        results.append(result)
    return results


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="zdc-obs")
    ap.add_argument("--mode", choices=["incremental", "full"], default="incremental")
    ap.add_argument("--trigger", default="manual")
    ap.add_argument("--sources")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--censored-at")
    ap.add_argument("--report")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")

    today = date.today()
    censored_at = date.fromisoformat(args.censored_at) if args.censored_at else today
    report = EvalReport()

    if args.dry_run:
        ids = args.sources.split(",") if args.sources else registered_ids()
        results = collect_all(ids, args.mode, today, {})
        obs = [o for r in results for o in r.observations]
        report.add(evals.check_no_silent_empty(results))
        report.add(evals.check_sources_reported(results))
        report.add(evals.check_observation_types(obs))
        report.add(evals.check_forecast_not_used_as_evidence(obs))
        report.add(evals.check_dates_present(obs, censored_at))
        print(report.render())
        _write_report(args.report, report, obs, results)
        return 0 if report.ok else 1

    conn = db.connect()
    registry = {s["source_id"]: s for s in db.enabled_sources(conn)}
    requested = args.sources.split(",") if args.sources else list(registry)
    source_ids = [s for s in requested if s in registry]
    skipped = [s for s in requested if s not in registry]
    if skipped:
        log.warning("not enabled in obs_core.observation_sources: %s", skipped)

    states = {s: db.get_source_state(conn, s) for s in source_ids}
    run_id = db.start_run(conn, PIPELINE, args.mode, args.trigger, git_sha())
    conn.commit()

    counters = dict(sources_attempted=len(source_ids), sources_ok=0,
                    observations_seen=0, observations_inserted=0, observations_updated=0)
    results = collect_all(source_ids, args.mode, today, states)
    all_obs, persistence_errors = [], {}

    for result in results:
        try:
            fetch_ids = [db.record_fetch(conn, run_id, f) for f in result.fetches]
            if result.observations and fetch_ids:
                ins, upd = db.upsert_observations(conn, result.observations, fetch_ids[-1])
                counters["observations_inserted"] += ins
                counters["observations_updated"] += upd
                counters["observations_seen"] += len(result.observations)
                all_obs.extend(result.observations)
            if result.ok:
                counters["sources_ok"] += 1
            conn.commit()
        except Exception as exc:  # noqa: BLE001
            conn.rollback()
            persistence_errors[result.source_id] = f"{type(exc).__name__}: {exc}"
            log.exception("%s: persistence failed", result.source_id)

    rows = db.rebuild_rollup(conn, ROLLUP_METHOD, censored_at, run_id)
    log.info("rolled up %d vulnerabilities", rows)
    conn.commit()

    report.add(evals.check_no_silent_empty(results))
    report.add(evals.check_sources_reported(results))
    report.add(evals.check_observation_types(all_obs))
    report.add(evals.check_forecast_not_used_as_evidence(all_obs))
    report.add(evals.check_dates_present(all_obs, censored_at))
    report.add(evals.check_collectors_have_adapters(conn))
    report.add(evals.check_source_freshness(conn, censored_at))
    for r in evals.run_db_evals(conn, results, persistence_errors):
        report.add(r)

    run_ok = report.ok and counters["sources_ok"] == counters["sources_attempted"]
    failures = "; ".join(f"{r.source_id}: {r.error}" for r in results if r.error) or None
    db.finish_run(conn, run_id, ok=run_ok, error=failures,
                  notes={"rollup_rows": rows}, **counters)
    conn.commit()
    conn.close()

    print(report.render())
    if not run_ok:
        print("RUN NOT OK: " + (failures or "a source did not complete"))
    _write_report(args.report, report, all_obs, results, counters, str(run_id))
    return 0 if (report.ok and run_ok) else 1


def _write_report(path, report, observations, results, counters=None, run_id=None) -> None:
    if not path:
        return
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id, "ok": report.ok, "counters": counters or {},
        "observations": len(observations),
        "per_source": {r.source_id: {"observations": len(r.observations),
                                     "unchanged": r.unchanged,
                                     "complete_snapshot": r.complete_snapshot,
                                     "error": r.error, "fetches": len(r.fetches)}
                       for r in results},
        "checks": [{"name": c.name, "severity": c.severity, "passed": c.passed,
                    "summary": c.summary, "detail": c.detail} for c in report.results],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)


if __name__ == "__main__":
    sys.exit(main())
