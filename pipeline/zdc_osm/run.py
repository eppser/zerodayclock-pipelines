"""OpenSourceMalware feed pipeline.

    python -m zdc_osm.run                      # poll every ecosystem, then look up downloads
    python -m zdc_osm.run --dry-run            # fetch and parse, write nothing
    python -m zdc_osm.run --ecosystems npm,pypi

WHY TWICE A DAY AND NOT HOURLY. query-latest returns the 100 most recently updated
records per ecosystem and cannot page. Measured 2026-10-08, npm - the busiest - turns
over ~33 records a day, so a 12h poll uses about a sixth of the window. A burst that
overruns it is detected per poll (`window_complete`) rather than prevented by polling
24 times a day against a free quota of 2,000.

WHY DOWNLOADS ARE LOOKED UP IN THE SAME RUN. npm stops answering for a package once it
removes it, and it removes malicious ones quickly. Each run looks up every npm/pypi
threat captured since the last run, so a figure is read within ~12h of capture.

Each ecosystem commits on its own: a crash on the ninth keeps the first eight.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone

import psycopg

from zdc_kev import db as runs_db

from . import db, evals
from .client import DownloadClient, OsmClient, download_url, redact, valid_name
from .models import (Downloads, parse_downloads, parse_latest, parse_npm_bulk,
                     window_complete)

PIPELINE = "osm"
log = logging.getLogger("zdc_osm")

#: The values that returned data on 2026-10-08. The documented `repository` and
#: `container` return nothing; `repositories`, `docker` and `dockerhub` are what work.
#: An unknown value answers 200 with zero records, so this list is checked by evals,
#: not trusted.
ECOSYSTEMS = ("npm", "pypi", "crates", "nuget", "maven", "go", "packagist", "rubygems",
              "vscode", "openvsx", "skills", "github", "chrome", "docker", "dockerhub",
              "repositories", "domains")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="zdc-osm")
    ap.add_argument("--ecosystems", default=",".join(ECOSYSTEMS))
    ap.add_argument("--max-lookups", type=int, default=400,
                    help="download lookups per run; the rest carry to the next run")
    ap.add_argument("--skip-downloads", action="store_true")
    ap.add_argument("--trigger", default=os.environ.get("GITHUB_EVENT_NAME", "manual"))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--report")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    # urllib does not log headers, but a DEBUG-level http.client would print them.
    logging.getLogger("http.client").setLevel(logging.WARNING)

    token = os.environ.get("OSM_API_KEY", "")
    try:
        client = OsmClient(token)
    except ValueError as e:
        log.error("%s", e)
        return 2
    ecosystems = [e.strip() for e in args.ecosystems.split(",") if e.strip()]
    return run(client, DownloadClient(), ecosystems, args, token)


def run(client, downloads, ecosystems, args, token) -> int:
    t_start = time.monotonic()
    report: dict = {"pipeline": PIPELINE, "started_at": datetime.now(timezone.utc).isoformat(),
                    "ecosystems": {}}
    statuses: dict[str, int] = {}
    errors: dict[str, str] = {}
    counts: dict[str, int] = {}
    incomplete: dict[str, str] = {}
    went_empty: list[str] = []
    parsed_total = malformed_total = stored_total = mismatches = 0
    lookups: dict[str, int] = {}
    results = []

    conn = None if args.dry_run else psycopg.connect(os.environ["DATABASE_URL"],
                                                     connect_timeout=60)
    run_id = None
    try:
        if conn:
            run_id = runs_db.start_run(conn, PIPELINE, "incremental", args.trigger,
                                       os.environ.get("GITHUB_SHA"))
            conn.commit()

        # ---- 1. poll ---------------------------------------------------------
        for eco in ecosystems:
            t0 = time.monotonic()
            r = client.latest(eco)
            statuses[eco] = r.status
            threats, malformed, perr = ([], 0, None)
            err = r.error
            if err is None:
                threats, malformed, perr = parse_latest(r.body, eco)
                err = perr
            if err:
                errors[eco] = err
            counts[eco] = len(threats)
            parsed_total += len(threats)
            malformed_total += malformed
            mismatches += sum(1 for t in threats if t.ecosystem != eco)
            lus = [t.last_updated for t in threats]
            oldest, newest = (min(lus), max(lus)) if lus else (None, None)
            info = {"status": r.status, "records": len(threats), "malformed": malformed,
                    "fetch_s": round(time.monotonic() - t0, 2)}
            if err:
                info["error"] = err

            if conn:
                t1 = time.monotonic()
                prev = db.previous_newest(conn, eco)
                complete = None if err else window_complete(len(threats), oldest, prev)
                if complete is False:
                    incomplete[eco] = f"oldest {oldest:%Y-%m-%d %H:%M} > previous {prev:%Y-%m-%d %H:%M}"
                if not err and not threats and db.stored_count(conn, eco) > 0:
                    went_empty.append(eco)
                current = db.load_current(conn, [t.threat_id for t in threats])
                new, changed, unchanged = db.classify(threats, current)
                poll_id = db.insert_poll(
                    conn, run_id, eco, r, record_count=len(threats), malformed=malformed,
                    oldest=oldest, newest=newest, previous=prev, complete=complete,
                    counts=(len(new), len(changed), len(unchanged)), error=err)
                db.write_threats(conn, poll_id, r.finished_at, new, changed, unchanged, current)
                conn.commit()
                stored_total += len(new) + len(changed) + len(unchanged)
                info.update({"new": len(new), "changed": len(changed),
                             "unchanged": len(unchanged), "window_complete": complete,
                             "write_s": round(time.monotonic() - t1, 2)})
            report["ecosystems"][eco] = info
            log.info("%-12s %s %3d records %s", eco, r.status, len(threats),
                     {k: v for k, v in info.items() if k in ("new", "changed", "error")})

        # ---- 2. downloads ----------------------------------------------------
        t2 = time.monotonic()
        if conn and not args.skip_downloads:
            lookups, paused = lookup_downloads(conn, run_id, downloads, args.max_lookups)
            report["downloads_paused"] = paused
        report["downloads"] = {"outcomes": lookups, "seconds": round(time.monotonic() - t2, 1)}

        # ---- 3. gate ---------------------------------------------------------
        results += [
            evals.check_authenticated(statuses),
            evals.check_polls_answered(statuses, errors),
            evals.check_not_silently_empty(counts),
            evals.check_malformed(parsed_total, malformed_total),
            evals.check_registry_mismatch(mismatches),
        ]
        if conn:
            results += [
                evals.check_ecosystem_went_empty(went_empty),
                evals.check_window_complete(incomplete),
                evals.check_persisted(parsed_total, stored_total),
                evals.check_downloads(lookups),
            ]
            report["stored"] = db.summary(conn)

        report["seconds"] = round(time.monotonic() - t_start, 1)
        report["checks"] = [{"name": r.name, "severity": r.severity, "passed": r.passed,
                             "summary": r.summary, **r.detail} for r in results]
        leak = evals.check_no_token_leak(json.dumps(report, default=str), token)
        results.append(leak)
        report["checks"].append({"name": leak.name, "severity": leak.severity,
                                 "passed": leak.passed, "summary": leak.summary})
        blocking = [r for r in results if r.blocking]
        report["ok"] = not blocking

        if conn:
            runs_db.finish_run(conn, run_id, ok=report["ok"],
                               error=None if report["ok"] else
                               "; ".join(r.name for r in blocking),
                               sources_attempted=len(ecosystems),
                               sources_ok=len(ecosystems) - len(errors),
                               entries_seen=parsed_total, entries_inserted=sum(
                                   v.get("new", 0) for v in report["ecosystems"].values()),
                               entries_updated=sum(
                                   v.get("changed", 0) for v in report["ecosystems"].values()),
                               notes={"downloads": lookups, "incomplete": incomplete,
                                      "seconds": report["seconds"]})
            conn.commit()
    except Exception as exc:  # noqa: BLE001
        msg = redact(f"{type(exc).__name__}: {exc}")
        log.error("run failed: %s", msg)
        if conn:
            conn.rollback()
            if run_id:
                runs_db.finish_run(conn, run_id, ok=False, error=msg)
                conn.commit()
        report.update({"ok": False, "error": msg})
        _write(args.report, report)
        return 1
    finally:
        if conn:
            conn.close()

    for r in results:
        log.info("[%s] %-5s %s: %s", "PASS" if r.passed else "FAIL", r.severity, r.name, r.summary)
    _write(args.report, report)
    return 0 if report["ok"] else 1


#: Bulk size for unscoped npm names; the endpoint accepts 128.
NPM_BULK = 100
#: Consecutive 429s after which a registry is left alone for the rest of the run.
BREAKER = 2


def lookup_downloads(conn, run_id, downloads, limit: int) -> tuple[dict[str, int], list[str]]:
    """Weekly downloads for every npm/pypi threat still lacking a conclusive figure.

    A 429 is the counter's limit, not the package's fault: it is recorded in the raw layer
    but does not use up one of the package's attempts, and two in a row stop that
    registry for this run - the rest stay pending for the next one.
    """
    outcomes: dict[str, int] = {}
    pending = db.pending_downloads(conn, limit)
    stopped: set[str] = set()
    strikes = {"npm": 0, "pypi": 0}

    def store(tid, registry, name, url, now, status, d):
        limited = status == 429
        db.record_lookup(conn, run_id, tid, registry, name, url, now, status, d,
                         count_attempt=not limited)
        outcomes[d.outcome] = outcomes.get(d.outcome, 0) + 1
        strikes[registry] = strikes[registry] + 1 if limited else 0
        if strikes[registry] >= BREAKER:
            stopped.add(registry)

    singles, bulk = [], []
    for tid, registry, name, _ in pending:
        if not valid_name(registry, name):
            store(tid, registry, name, None, datetime.now(timezone.utc), 0,
                  Downloads("invalid_name", None, None, None, "name fails the registry naming rule"))
        elif registry == "npm" and not name.startswith("@"):
            bulk.append((tid, name))
        else:
            singles.append((tid, registry, name))
    conn.commit()

    for i in range(0, len(bulk), NPM_BULK):
        if "npm" in stopped:
            break
        chunk = bulk[i:i + NPM_BULK]
        names = sorted({n for _, n in chunk})
        now = datetime.now(timezone.utc)
        r = downloads.npm_bulk(names)
        parsed = parse_npm_bulk(r.status, r.body, r.error, names)
        for tid, name in chunk:
            store(tid, "npm", name, r.url, now, r.status, parsed[name])
        conn.commit()

    for tid, registry, name in singles:
        if registry in stopped:
            continue
        now = datetime.now(timezone.utc)
        r = downloads.weekly(registry, name)
        store(tid, registry, name, download_url(registry, name), now, r.status,
              parse_downloads(registry, r.status, r.body, r.error))
        conn.commit()
    if stopped:
        log.warning("download counters rate-limited us, paused for this run: %s", sorted(stopped))
    return outcomes, sorted(stopped)


def _write(path, report) -> None:
    if path:
        with open(path, "w") as fh:
            fh.write(json.dumps(report, indent=1, default=str))


if __name__ == "__main__":
    sys.exit(main())
