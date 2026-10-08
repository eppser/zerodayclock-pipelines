"""Export every published view as gzipped CSV, with a manifest.

WHY THIS EXISTS. The reproducibility contract promises that derived tables are
exported "to a public location on each production run, so a reviewer never needs
database access to check the arithmetic", and the mission says every number on the
site must be reproducible by a stranger. Neither was true: there was no export step
in any workflow, /data /exports /downloads all returned 404, and the only snapshot
tool wrote to a gitignored directory. This closes that.

WHAT IT GUARANTEES.

* Every file is deterministic for a given database state — rows come out in an
  explicit ORDER BY on the view's own key, never in heap order, so re-running
  against unchanged data produces byte-identical output and `git` sees no change.
  Without that a twice-daily export churns the branch even when nothing moved.
* Nothing is written until every table has been read. A partial export published
  next to a manifest claiming completeness is worse than no export.
* The manifest carries the censoring date, the per-metric method_version and a
  sha256 per file, so a downloaded CSV can be tied back to the run that made it
  and to the method that produced the numbers.

COMPRESSION IS mtime-STABLE. gzip writes the source mtime into its header by
default, so the same bytes gzip to different files on every run and every export
looks changed. `mtime=0` pins it.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import json
import logging
import os
import sys
from datetime import date, datetime, timezone
from pathlib import Path

import psycopg

from zdc_kev import db as runs_db      # shared raw.pipeline_runs recorder

#: Recorded so the watchdog can tell "ran and exported nothing" from "did not run"
#: (0069). Before this, export left no trace of a run anywhere, so a workflow that
#: silently stopped firing was invisible in the database and to every eval.
PIPELINE = "export"

log = logging.getLogger("zdc-export")

#: (view, sort key). Chart-backing tables first — small, and what a reviewer checks
#: arithmetic against — then the corpus that makes those charts re-derivable.
#:
#: THE KEY IS DECLARED AND THEN VERIFIED. A first version guessed the keys and got
#: three wrong (`corpus_cohorts` has no `month_start`). The second dropped keys
#: entirely and ordered by every column, which is total but sorts 685k wide rows and
#: blew the statement timeout. So: declare the key, and assert at export time that it
#: is actually unique — a key that stops being unique fails the run instead of
#: silently making the export non-deterministic.
EXPORTS: list[tuple[str, str]] = [
    ("corpus_cohorts",            "metric, cohort_year, month_index"),
    ("patch_window_cohorts",      "period_label"),
    ("technology_cohorts",        "category, cohort_year, month_index"),
    ("kev_technology_cohorts",    "kev_scope, category, cohort_year"),
    ("severity_predictiveness",   "window_days, cohort_year, band"),
    ("pressure_index",            "indicator, period_end"),
    ("pressure_monthly",          "indicator, month_start"),
    ("scan_pressure",             "vuln_id, window_days, offset_weeks"),
    ("scan_age_mix",              "month, age_band"),
    ("kev_lag_points",            "cve_id"),
    ("technology_coverage",       "censored_at, window_start_year"),
    ("technology_categories",     "category"),
    ("kev_bulk_loads",            "event_date, source_id"),
    ("kev_source_agreement",      "observer_a, observer_b"),
    ("kev_sources",               "source_id"),
    ("observation_sources",       "source_id"),
    ("kev_pipeline_health",       "pipeline, started_at"),
    ("explorer_strata",           "published, catalogued, scanned"),
    ("kev_consolidated",          "vuln_id"),
    ("observation_rollup",        "vuln_id"),
    ("explorer_rows",             "cve_id"),
    ("kev_entries",               "entry_id"),
    ("cve_activity_daily",        "cve_id, observed_on"),
    ("cve_detail",                "cve_id"),
    ("exploitation_observations", "observation_id"),
]


def _assert_key_is_unique(conn, view: str, key: str) -> None:
    """A sort key with ties makes the export non-deterministic. Fail, don't drift.

    RuntimeError, not SystemExit: SystemExit is a BaseException, so main()'s
    `except Exception` let it straight past and the run row stopped at started_at,
    which the watchdog cannot tell from a run that never happened.
    """
    with conn.cursor() as cur:
        cur.execute(f"select count(*), count(distinct ({key})) from public.{view}")
        total, distinct = cur.fetchone()
    if total != distinct:
        raise RuntimeError(
            f"public.{view}: sort key ({key}) has {total - distinct} duplicate(s) "
            f"across {total} rows — the export would not be reproducible"
        )


def _copy_csv(conn, view: str, order_by: str) -> bytes:
    """Stream one view to CSV bytes in a pinned order."""
    buf = io.BytesIO()
    sql = f"copy (select * from public.{view} order by {order_by}) to stdout with (format csv, header true)"
    with conn.cursor() as cur, cur.copy(sql) as cp:
        for chunk in cp:
            buf.write(chunk)
    return buf.getvalue()


def _gzip(payload: bytes) -> bytes:
    """Deterministic gzip: no source mtime, no filename in the header."""
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="wb", compresslevel=9, mtime=0) as fh:
        fh.write(payload)
    return out.getvalue()


def _method_versions(conn) -> dict[str, str]:
    with conn.cursor() as cur:
        cur.execute("""
            select distinct on (metric_id) metric_id, method_version
              from core.method_registry where superseded_at is null
             order by metric_id, introduced_at desc nulls last, method_version desc
        """)
        return dict(cur.fetchall())


def _censoring_date(conn) -> str | None:
    with conn.cursor() as cur:
        cur.execute("select max(censored_at)::text from derived.cve_detail")
        return cur.fetchone()[0]


def export(conn, out_dir: Path, *, only: list[str] | None = None) -> dict:
    """Read everything first, then write. A partial export is not published."""
    wanted = [(v, k) for v, k in EXPORTS if not only or v in only]
    if only:
        missing = sorted(set(only) - {v for v, _ in EXPORTS})
        if missing:
            raise RuntimeError(f"unknown view(s): {', '.join(missing)}")

    staged: dict[str, bytes] = {}
    files: list[dict] = []
    for view, order_by in wanted:
        _assert_key_is_unique(conn, view, order_by)
        raw = _copy_csv(conn, view, order_by)
        blob = _gzip(raw)
        rows = max(raw.count(b"\n") - 1, 0)          # minus the header
        staged[f"{view}.csv.gz"] = blob
        files.append({
            "file": f"{view}.csv.gz",
            "view": f"public.{view}",
            "rows": rows,
            "bytes_csv": len(raw),
            "bytes_gz": len(blob),
            "sha256": hashlib.sha256(blob).hexdigest(),
            "order_by": order_by,
        })
        log.info("%-28s %8d rows  %7.1f KB gz", view, rows, len(blob) / 1024)

    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "censoring_date": _censoring_date(conn),
        "method_versions": _method_versions(conn),
        "note": (
            "Every number published on zerodayclock.com is derived from these files. "
            "Each is a gzipped CSV of the identically-named view, ordered by the key in "
            "`order_by` so the export is byte-identical for an unchanged database. "
            "Read `censoring_date` before comparing cohorts: recent ones are "
            "right-censored and are not comparable to older ones as raw counts."
        ),
        "files": sorted(files, key=lambda f: f["file"]),
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    for name, blob in staged.items():
        (out_dir / name).write_bytes(blob)
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="zdc-export")
    ap.add_argument("--out", default="export", type=Path)
    ap.add_argument("--only", nargs="*", help="export only these views")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format="%(message)s")
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        print("DATABASE_URL is not set", file=sys.stderr)
        return 2
    with psycopg.connect(dsn) as conn:
        # Same reasoning as zdc_enrich.db.connect: Supabase gives this role a two-minute
        # statement_timeout, and one export is genuinely bigger than that. Measured
        # 2026-09-03 against staging: exploitation_observations (685,743 rows) is
        # cancelled at 125s, while everything else finishes inside 33s. Raised for THIS
        # SESSION only, and the per-table timings print on every run so a slow export is
        # visible rather than discovered as a cancelled one.
        with conn.cursor() as cur:
            cur.execute("select set_config('statement_timeout', %s, false)",
                        (os.environ.get("ZDC_STATEMENT_TIMEOUT", "15min"),))
        conn.commit()

        run_id = runs_db.start_run(conn, PIPELINE, "full",
                                   os.environ.get("GITHUB_EVENT_NAME", "manual"),
                                   os.environ.get("GITHUB_SHA"))
        conn.commit()
        try:
            m = export(conn, args.out, only=args.only)
        except Exception as exc:  # noqa: BLE001 — a failed export must still leave a record
            # Recorded and re-raised. A run row that stops at started_at is exactly as
            # invisible to the watchdog as no run row at all.
            runs_db.finish_run(conn, run_id, ok=False,
                               error=f"{type(exc).__name__}: {exc}")
            conn.commit()
            raise
        total_gz = sum(f["bytes_gz"] for f in m["files"])
        runs_db.finish_run(
            conn, run_id, ok=bool(m["files"]),
            error=None if m["files"] else "export produced no files",
            entries_seen=sum(f.get("rows", 0) for f in m["files"]),
            notes={"files": len(m["files"]), "bytes_gz": total_gz,
                   "censoring_date": str(m["censoring_date"])})
        conn.commit()

    total = sum(f["bytes_gz"] for f in m["files"])
    print(f"{len(m['files'])} files, {total / 1048576:.1f} MB, "
          f"censoring date {m['censoring_date']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
