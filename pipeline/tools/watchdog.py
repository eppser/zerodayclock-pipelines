"""Fail loudly when a pipeline stops running at all.

Every other freshness check in this project runs INSIDE the pipeline it watches, so a
pipeline that stops firing runs no check and reports nothing. The only signal was a human
opening the Actions tab. That is v1's silent-collector death moved up a level — from a
source to a whole workflow.

Three decisions worth keeping:

  IT IS ITS OWN WORKFLOW, not an eval inside enrich. An eval there would turn enrich red
  because PATCH is late, and a pipeline going red for another's absence is the
  alert-fatigue pattern that let the observation pipeline sit red for four days.

  IT MEASURES THE LAST *SUCCESSFUL* RUN, not the last attempt. A pipeline failing every
  run on schedule is still silent about its data — that is exactly what obs and enrich
  did for two days — and a watchdog satisfied by an attempt would have said nothing.

  IT READS ITS EXPECTATIONS FROM THE DATABASE (core.pipeline_expectations, 0069), so the
  thresholds are data with a recorded calibration rather than constants here. A pipeline
  nobody registered is reported as UNREGISTERED rather than ignored: an unwatched
  pipeline is the failure this exists to prevent, so silence about one is not acceptable.

Usage:
    python -m tools.watchdog            report; exit 1 if any pipeline is overdue
    python -m tools.watchdog --json     same, machine-readable
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import psycopg

#: Pipelines that write a run row. Anything here without a row in
#: core.pipeline_expectations is reported, never silently skipped.
KNOWN_RUNS_TABLES = ("raw.pipeline_runs", "obs_raw.pipeline_runs")


def collect(conn) -> list[dict]:
    with conn.cursor() as cur:
        cur.execute("""select pipeline, display_name, runs_table, workflow, cron,
                              max_silence_hours, monitor_from, enabled
                         from core.pipeline_expectations order by pipeline""")
        expectations = cur.fetchall()

        # One query per distinct table, not one per pipeline: the set is tiny and fixed,
        # and this keeps the last-OK lookup identical for every pipeline in a table.
        last_ok: dict[str, object] = {}
        for table in KNOWN_RUNS_TABLES:
            cur.execute(f"""select pipeline, max(started_at) filter (where ok),
                                   max(started_at)
                              from {table} group by pipeline""")   # noqa: S608 — fixed set
            for name, ok_at, any_at in cur.fetchall():
                last_ok[f"{table}:{name}"] = (ok_at, any_at)

        cur.execute("select now()")
        now = cur.fetchone()[0]

    rows = []
    registered = set()
    for (pipeline, display, table, workflow, cron,
         max_hours, monitor_from, enabled) in expectations:
        registered.add(f"{table}:{pipeline}")
        ok_at, any_at = last_ok.get(f"{table}:{pipeline}", (None, None))
        silent_h = None if ok_at is None else (now - ok_at).total_seconds() / 3600
        # Not yet due: registered so recently that even a healthy pipeline need not have
        # run. Distinguished from OK so the report never claims evidence it lacks.
        in_grace = (now - monitor_from).total_seconds() / 3600 < max_hours
        if not enabled:
            state = "DISABLED"
        elif ok_at is None:
            state = "PENDING" if in_grace else "NEVER RAN"
        elif silent_h > max_hours:
            state = "OVERDUE"
        else:
            state = "OK"
        rows.append({
            "pipeline": pipeline, "display_name": display, "workflow": workflow,
            "cron": cron, "state": state, "max_silence_hours": max_hours,
            "hours_since_ok": None if silent_h is None else round(silent_h, 1),
            "last_ok": ok_at.isoformat() if ok_at else None,
            "last_attempt": any_at.isoformat() if any_at else None,
            "failing_since_last_ok": bool(ok_at and any_at and any_at > ok_at),
        })

    for key in sorted(set(last_ok) - registered):
        table, name = key.split(":", 1)
        ok_at, any_at = last_ok[key]
        rows.append({
            "pipeline": name, "display_name": f"{name} (in {table})", "workflow": None,
            "cron": None, "state": "UNREGISTERED", "max_silence_hours": None,
            "hours_since_ok": None, "last_ok": ok_at.isoformat() if ok_at else None,
            "last_attempt": any_at.isoformat() if any_at else None,
            "failing_since_last_ok": bool(ok_at and any_at and any_at > ok_at),
        })
    return rows


def render(rows: list[dict]) -> str:
    width = max((len(r["pipeline"]) for r in rows), default=8)
    out = []
    for r in sorted(rows, key=lambda r: (r["state"] == "OK", r["pipeline"])):
        since = "never" if r["hours_since_ok"] is None else f"{r['hours_since_ok']}h ago"
        limit = "" if r["max_silence_hours"] is None else f" (limit {r['max_silence_hours']}h)"
        note = "  [failing since]" if r["failing_since_last_ok"] else ""
        out.append(f"  {r['state']:<12} {r['pipeline']:<{width}}  last ok {since}{limit}{note}")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        print("DATABASE_URL is not set", file=sys.stderr)
        return 2

    with psycopg.connect(dsn, connect_timeout=60) as conn:
        rows = collect(conn)

    bad = [r for r in rows if r["state"] in ("OVERDUE", "NEVER RAN", "UNREGISTERED")]
    if args.json:
        print(json.dumps({"ok": not bad, "pipelines": rows}, indent=2))
    else:
        print(render(rows))
        print()
        if bad:
            for r in bad:
                print(f"{r['state']}: {r['display_name']} — {r['workflow'] or 'no workflow'}")
            print(f"\nRESULT: {len(bad)} pipeline(s) not running as expected")
        else:
            print(f"RESULT: OK — {len(rows)} pipeline(s) within their expected cadence")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
