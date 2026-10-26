"""R2 hourly job: every record ingested since the last run gets an event, a reported date and its other R2 fields, and the
private shadow list is rebuilt. Idempotent: a second run right after the first writes nothing.

Why it exists (2026-10-26): the R2 modules were run once as backfills (events 2026-10-22, reported 2026-10-24) and nothing
R2 ran in the scheduled job, so every record ingested afterwards had no event, hence no event-level reported date
(r2x-reported-v2 shows a reported date only on a breach event), and staging showed 'unknown' for the leak posts of the
last days. This job is that missing step. Order matters and is fixed:

  1. events    r2_events run --new-only      units with no stored membership are matched against the stored events
                                              (same method as the backfill) or get an event of their own; additive only
  2. reported  r2_reported run --new-only    one structured reported-date row per event the stored rows do not cover
  3. combined  r2_combined run --new-only    the other R2 fields of the new records (module owned by another track: if it is
                                              not installed the step is skipped with a warning, nothing else changes)
  4. shadow    breach_core.rebuild_r2_shadow()   private table that staging reads; runs even when a step above failed, so
                                              whatever was written becomes visible

Run it after the hourly breach pipeline (which refreshes victims_list, the table the shadow is built from).

PUBLIC LOGS: counts only. No record, victim name, leak text, key or connection detail is printed or written to the
report; an error is reported by its class and SQLSTATE only. The output of the combined step is not echoed either: only the
numbers in its last JSON line are carried into the report.

Exit codes: 0 ok (a skipped step is not a failure) · 1 a step failed · 2 deadline reached before a step started (the
steps done are kept) · 3 TypeSafe account out of funds · 5 another R2 hourly run holds the lock.

CLI (DATABASE_URL, TYPESAFE_API_KEY):
  python -m zdc_breach.r2_hourly --report r2-hourly-report.json [--max-usd 0.5] [--combined-max-usd 0.5]
                                 [--deadline-min 25] [--dry-run]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

STATEMENT_TIMEOUT = "60s"
LOCK_KEY = "zdc_r2_hourly"
STEPS = ("events", "reported", "structured", "combined", "shadow")


def numbers_only(x, depth: int = 0):
    """Keep only numbers, booleans and short keys of a (possibly foreign) JSON report: nothing textual survives."""
    if isinstance(x, bool) or isinstance(x, (int, float)):
        return x
    if isinstance(x, dict) and depth < 3:
        out = {str(k)[:40]: numbers_only(v, depth + 1) for k, v in x.items()}
        return {k: v for k, v in out.items() if v is not None}
    return None


def last_json_line(text: str):
    for line in reversed((text or "").strip().splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                return json.loads(line)
            except ValueError:
                return None
    return None


def error_label(e: BaseException) -> str:
    """Class and SQLSTATE only: a driver message can carry row data."""
    code = getattr(e, "sqlstate", None) or getattr(getattr(e, "diag", None), "sqlstate", None)
    return type(e).__name__ + (f":{code}" if code else "")


RECENT_DAYS = 7
# shadow field -> its release flag: the staging API shows a field as unknown when it is null OR not released
EFFECTIVE_FIELDS = ("name", "industry", "size_band", "country", "breach_type", "reported_date")


def effective_null_sql(field: str) -> str:
    """SQL counting a shadow row whose r2 field staging renders as unknown: no value, or a value whose
    (field, source, basis) stratum is not released (projectRow in src/lib/breach-r2.ts nulls it)."""
    return f"count(*) filter (where r2_{field} is null or not r2_{field}_released)"


def coverage(conn) -> dict:
    """Health counts. 'effective' means what staging renders: a null value OR an unreleased one is unknown.
    The raw null counts alone hide every value the release gate withholds."""
    with conn.transaction(), conn.cursor() as cur:
        cur.execute("set transaction read only")
        cur.execute(f"set local statement_timeout = '{STATEMENT_TIMEOUT}'")
        cur.execute("select value from breach_core.breach_settings where key = 'r2_membership_version'")
        ver = (cur.fetchone() or [None])[0]
        cur.execute("""select count(*) from breach_core.victims_list v where not exists
                        (select 1 from breach_core.r2_event_members m where m.method_version = %s and m.victim_id = v.victim_id)""",
                    (ver,))
        no_member = cur.fetchone()[0]
        cur.execute("""select count(*), count(*) filter (where r2_event_id is null),
                              count(*) filter (where r2_reported_date is null),
                              count(*) filter (where r2_reported_date is not null and not r2_reported_date_released),
                              count(*) filter (where r2_reported_date is null or not r2_reported_date_released)
                         from breach_core.r2_victims_shadow""")
        total, no_event, no_rd, rd_unreleased, rd_effective = cur.fetchone()
        cols = ", ".join(effective_null_sql(f) for f in EFFECTIVE_FIELDS)
        cur.execute(f"""select count(*), {cols} from breach_core.r2_victims_shadow
                         where seen_date >= current_date - {RECENT_DAYS}""")
        rec = cur.fetchone()
    return {"listed_without_event": no_member, "shadow_rows": total, "shadow_without_event": no_event,
            "shadow_without_reported_date": no_rd, "shadow_reported_date_unreleased": rd_unreleased,
            "shadow_reported_date_unknown_effective": rd_effective,
            "recent_days": RECENT_DAYS, "recent_rows": rec[0],
            **{f"recent_{f}_unknown_effective": n for f, n in zip(EFFECTIVE_FIELDS, rec[1:])}}


def degraded(steps: dict) -> list[str]:
    """Steps that did not do their job though the run itself did not fail. A skipped combined step leaves the new
    records without name, industry, size, country and breach type: the run is NOT healthy, whatever the exit code."""
    return sorted(f"{n}:{s.get('status')}" for n, s in steps.items()
                  if s.get("status") not in ("ok", "skipped_dry_run"))


def step_events(conn, a) -> dict:
    from zdc_breach import r2_events
    rep = r2_events.run_new_only(conn, max_usd=a.max_usd, workers=a.workers, write_db=not a.dry_run, run_id="r2-hourly")
    return numbers_only(rep)


def step_reported(conn, a) -> dict:
    from zdc_breach import r2_reported
    return numbers_only(r2_reported.run_new_only(conn, write_db=not a.dry_run))


def step_combined(conn, a, remaining_s: float) -> dict | None:
    """Another track's module. Missing -> None (skipped); present -> run as a child process, output not echoed."""
    if importlib.util.find_spec("zdc_breach.r2_combined") is None:
        print("::warning::zdc_breach.r2_combined is not installed: the combined R2 step is skipped; records ingested since the last combined run show unknown name, industry, size, country and breach type", flush=True)
        return None
    p = subprocess.run([sys.executable, "-m", "zdc_breach.r2_combined", "run", "--new-only", "--write", "--max-usd", str(a.combined_max_usd)],
                       capture_output=True, text=True, timeout=max(60, remaining_s), env=os.environ.copy())
    rep = {"exit_code": p.returncode}
    j = last_json_line(p.stdout)
    if j is not None:
        rep["report"] = numbers_only(j)
    if p.returncode:
        raise RuntimeError(f"r2_combined exited {p.returncode}")
    return rep


def step_structured(a, remaining_s: float) -> dict:
    """Structured and deterministic values (no Jev) for records that have none yet: the leak-site rule
    (a leak-site listing -> ransomware_extortion), regulator and index codes, a stated headcount."""
    cmd = [sys.executable, "-m", "zdc_breach.r2_classify", "structured", "--write"]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=max(60, remaining_s), env=os.environ.copy())
    rep = {"exit_code": p.returncode}
    j = last_json_line(p.stdout)
    if j is not None:
        rep["report"] = numbers_only({k: j.get(k) for k in ("subjects", "written", "cleared")})
    if p.returncode:
        raise RuntimeError(f"r2_classify structured exited {p.returncode}")
    return rep


def step_shadow(conn) -> dict:
    t = time.time()
    with conn.transaction(), conn.cursor() as cur:
        cur.execute(f"set local statement_timeout = '{STATEMENT_TIMEOUT}'")
        cur.execute("select breach_core.rebuild_r2_shadow()")
        n = cur.fetchone()[0]
    return {"rows": n, "seconds": round(time.time() - t, 1)}


def run(a, conn=None) -> tuple[dict, int]:
    """Run the steps in order; returns (counts-only report, exit code)."""
    import psycopg
    t0 = time.time()
    report = {"started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "dry_run": a.dry_run,
              "max_usd": a.max_usd, "combined_max_usd": a.combined_max_usd, "steps": {}}
    code = 0
    own = conn is None
    if own:
        conn = psycopg.connect(os.environ["DATABASE_URL"], connect_timeout=20, autocommit=True)
    lock_conn = None
    try:
        if own:                                           # a session lock on its own connection: a second run exits
            lock_conn = psycopg.connect(os.environ["DATABASE_URL"], connect_timeout=20, autocommit=True)
            got = lock_conn.execute("select pg_try_advisory_lock(hashtext(%s))", (LOCK_KEY,)).fetchone()[0]
            if not got:
                report["error"] = "locked"
                return report, 5
        report["before"] = coverage(conn)
        from zdc_breach.profile import OutOfFunds
        for name in STEPS:
            if time.time() - t0 > a.deadline_min * 60:
                report["steps"][name] = {"status": "deadline"}
                code = code or 2
                continue
            if a.dry_run and name in ("structured", "combined", "shadow"):
                report["steps"][name] = {"status": "skipped_dry_run"}
                continue
            s = time.time()
            try:
                if name == "events":
                    out = step_events(conn, a)
                elif name == "reported":
                    out = step_reported(conn, a)
                elif name == "structured":
                    out = step_structured(a, a.deadline_min * 60 - (time.time() - t0))
                elif name == "combined":
                    out = step_combined(conn, a, a.deadline_min * 60 - (time.time() - t0))
                else:
                    out = step_shadow(conn)
                report["steps"][name] = ({"status": "skipped_module_missing"} if out is None
                                         else {"status": "ok", "report": out})
            except OutOfFunds:
                report["steps"][name] = {"status": "failed", "error": "OutOfFunds"}
                code = 3
            except (Exception, SystemExit) as e:      # a failed step must not stop the shadow rebuild
                report["steps"][name] = {"status": "failed", "error": error_label(e)}
                code = code or 1
            report["steps"][name]["seconds"] = round(time.time() - s, 1)
        if not a.dry_run:
            try:
                report["after"] = coverage(conn)
            except Exception as e:
                report["after"] = {"error": error_label(e)}
    finally:
        for c in (lock_conn, conn if own else None):
            if c is not None:
                try:
                    c.close()
                except Exception:
                    pass
    report["degraded"] = degraded(report["steps"])
    report["seconds"] = round(time.time() - t0, 1)
    return report, code


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="zdc_breach.r2_hourly")
    ap.add_argument("--report", help="write the counts-only report JSON here")
    ap.add_argument("--max-usd", type=float, default=0.5, help="Jev spend cap of the events step")
    ap.add_argument("--combined-max-usd", type=float, default=0.5, help="Jev spend cap of the combined step")
    ap.add_argument("--deadline-min", type=float, default=25.0, help="do not start a step after this many minutes")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--dry-run", action="store_true", help="events and reported compute only; combined and shadow skipped")
    a = ap.parse_args(argv)
    report, code = run(a)
    report["exit_code"] = code
    if a.report:
        with open(a.report, "w") as f:
            json.dump(report, f, indent=1)
    print(json.dumps(report))
    return code


if __name__ == "__main__":
    sys.exit(main())
