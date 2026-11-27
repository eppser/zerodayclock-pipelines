"""Agentic C2 pipeline: internet-exposed consoles of agentic offensive frameworks, daily.

    python -m zdc_aof.run                       # both sources, then the gate
    python -m zdc_aof.run --dry-run             # fetch, parse and check; write nothing
    python -m zdc_aof.run --sources shodan      # one source (the run then reports only its checks)

TWO SOURCES, ONE RUN, TWO COMMITS. offensive.agency and Shodan are collected one after the
other and each commits on its own, so one failing never discards the other's day. The run is
`ok` only if both pass: the watchdog reads the last successful run, so either source dying
turns the pipeline overdue.

NOTHING BUT THE REQUEST LOG IS WRITTEN FROM A SOURCE THAT FAILED ITS OWN CHECKS. A short host
list or a framework with an unanswered rule would otherwise be stored as a fall in consoles, and
an answer that suddenly lists no detection rules would retire every rule we hold. So frameworks,
rules and counts are held in memory and written in one transaction after the source's checks
pass. The requests themselves are recorded in aof_raw as they are made, each in its own commit,
so a crash halfway leaves the record of what was asked and answered.

EACH SOURCE KEEPS ITS OWN DAY. offensive.agency's rows are filed under the day its data runs to
(`ref_day`), so a stale source re-writes the same day and never mints a new one. Shodan's are
filed under the UTC date of this run.

THE LOG AND THE REPORT ARE PUBLIC. They carry per-framework totals and check results. No
address, no network, no network name.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from collections import Counter
from datetime import date, datetime, timezone

import re

import psycopg

from zdc_kev import db as runs_db

from . import db, evals, models
from .client import Http, OffensiveAgency, Shodan, redact, register_secret
from .evals import Facts

PIPELINE = "aof"
log = logging.getLogger("zdc_aof")

#: offensive.agency answers kept verbatim besides status, the framework list and each
#: framework's profile. None of them carries an address (measured 2026-11-25); `store_fetch`
#: checks every body regardless.
OA_KEPT = ("timeline", "stats", "clusters", "c2", "map", "facets")
OA_HOST_PAGE = 5000
OA_MAX_HOST_PAGES = 40           # 200,000 addresses: far above today's ~5,600, and a stop for a looping `next`
OA_INTERVAL = 0.5
#: Time budget per source. Both together stay under the workflow's 20-minute job limit, so the
#: run always reaches the point where it records how it ended.
SOURCE_BUDGET_SECONDS = 420


def safe_error(exc: BaseException) -> str:
    """An exception as it may appear in a public log, a run row and the report. A database error
    is reduced to its class and SQLSTATE: psycopg appends the failing row, which here can hold a
    network and its name. Everything else loses any credential and any address it quotes."""
    if isinstance(exc, psycopg.Error):
        return f"{type(exc).__name__} (SQLSTATE {getattr(exc, 'sqlstate', None) or 'unknown'})"
    return db.scrub(redact(f"{type(exc).__name__}: {exc}"))[:300]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="zdc-aof")
    ap.add_argument("--sources", default="offensive_agency,shodan")
    ap.add_argument("--trigger", default=os.environ.get("GITHUB_EVENT_NAME", "manual"))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--report")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    sources = tuple(s.strip() for s in args.sources.split(",") if s.strip())
    if not sources or set(sources) - {db.OA, db.SHODAN}:
        log.error("--sources takes offensive_agency and/or shodan")
        return 2
    try:
        cfg = models.load_config()
    except models.ConfigError as e:
        log.error("%s", e)
        return 2
    shodan = None
    if db.SHODAN in sources:
        try:
            shodan = Shodan(Http(cfg.min_interval_seconds, deadline_seconds=SOURCE_BUDGET_SECONDS),
                            os.environ.get("SHODAN_API_KEY", ""))
        except ValueError as e:
            log.error("%s", e)
            return 2
    oa = OffensiveAgency(Http(OA_INTERVAL, deadline_seconds=SOURCE_BUDGET_SECONDS)) if db.OA in sources else None
    conn = None if args.dry_run else psycopg.connect(os.environ["DATABASE_URL"], connect_timeout=60)
    return run(oa, shodan, cfg, conn, trigger=args.trigger, report_path=args.report,
               secrets=(os.environ.get("SHODAN_API_KEY", ""),))


def run(oa, shodan, cfg: models.Config, conn, *, trigger: str = "manual", report_path: str | None = None,
        today: date | None = None, secrets: tuple[str, ...] = ()) -> int:
    t_start = time.monotonic()
    today = today or datetime.now(timezone.utc).date()
    for secret in secrets:
        register_secret(secret)          # redaction must not depend on which client was built
    sources = tuple(s for s, c in ((db.OA, oa), (db.SHODAN, shodan)) if c is not None)
    facts = Facts(today=today, secrets=tuple(s for s in secrets if s))
    report: dict = {"pipeline": PIPELINE, "started_at": datetime.now(timezone.utc).isoformat(),
                    "today": str(today), "sources": list(sources), "config_sha256": cfg.sha256}
    run_id = None
    try:
        if conn:
            run_id = runs_db.start_run(conn, PIPELINE, "full", trigger, os.environ.get("GITHUB_SHA"))
            conn.commit()
        for name, collect, client in ((db.OA, collect_offensive_agency, oa), (db.SHODAN, collect_shodan, shodan)):
            if client is None:
                continue
            try:
                report[name] = collect(client, cfg, conn, run_id, facts)
                if conn:
                    conn.commit()
            except Exception as exc:  # noqa: BLE001 - one source must not take the other down
                msg = safe_error(exc)
                if conn:
                    conn.rollback()      # frameworks, rules and counts of this source: all or nothing
                log.error("%s failed: %s", name, msg)
                report[name] = {"error": msg}
                if name == db.OA:
                    facts.oa_errors["status"] = msg
                    facts.oa_status_before = facts.oa_status_after = None
                else:
                    facts.sh_info_status, facts.sh_plan = 0, None

        if conn:
            newest = max([d for d in (report.get(db.OA, {}).get("stored_day"),
                                      report.get(db.SHODAN, {}).get("stored_day")) if d] or [None],
                         default=None)
            if newest:
                report["network_days_pruned"] = db.prune_network_days(conn, date.fromisoformat(newest))
            conn.commit()
            facts.schema_bytes = db.stored_bytes(conn)

        results = evals.evaluate(facts, sources=sources, persisted=conn is not None)
        report["seconds"] = round(time.monotonic() - t_start, 1)
        report["checks"] = [_check(r) for r in results]
        if conn:
            report["stored"] = db.summary(conn)
        facts.report_text = json.dumps(report, default=str)
        for c in evals.REPORT_CHECKS:
            r = c(facts)
            results.append(r)
            report["checks"].append(_check(r))
        blocking = [r for r in results if r.blocking]
        report["ok"] = not blocking

        if conn:
            runs_db.finish_run(
                conn, run_id, ok=report["ok"],
                error=None if report["ok"] else "; ".join(r.name for r in blocking),
                sources_attempted=len(sources),
                sources_ok=sum(1 for s in sources if report.get(s, {}).get("stored_day")),
                entries_seen=facts.computed_rows, entries_inserted=facts.stored_rows,
                notes={"config_sha256": cfg.sha256, "method_version": db.METHOD_VERSION,
                       "days": {s: report.get(s, {}).get("stored_day") for s in sources},
                       "seconds": report["seconds"]})
            conn.commit()
    except Exception as exc:  # noqa: BLE001
        msg = safe_error(exc)
        log.error("run failed: %s", msg)
        try:
            # A run row that stops at started_at is as invisible to the watchdog as no row.
            if conn and run_id:
                conn.rollback()
                runs_db.finish_run(conn, run_id, ok=False, error=msg)
                conn.commit()
        except Exception as again:  # noqa: BLE001 - a dead connection: say so, do not mask the first error
            log.error("could not record the failed run: %s", safe_error(again))
        report.update({"ok": False, "error": msg})
        _write(report_path, report)
        return 1
    finally:
        if conn:
            conn.close()

    for r in results:
        log.info("[%s] %-5s %s: %s", "PASS" if r.passed else "FAIL", r.severity, r.name, r.summary)
    _write(report_path, report)
    return 0 if report["ok"] else 1


def _check(r) -> dict:
    return {"name": r.name, "severity": r.severity, "passed": r.passed, "summary": r.summary, **r.detail}


def _store(conn, *a, **k) -> None:
    """Record one request and commit it. Nothing else is written until a source's checks have
    passed, so this commit carries the request row alone."""
    if conn:
        db.store_fetch(conn, *a, **k)
        conn.commit()


# ---- offensive.agency ----------------------------------------------------------

def collect_offensive_agency(oa: OffensiveAgency, cfg: models.Config, conn, run_id, facts: Facts) -> dict:
    out: dict = {}

    def fetch(endpoint: str, path: str, day: date, *, keep: bool = True, **params):
        """One request, recorded. Returns (meta, data), or None with the error noted."""
        r = oa.get(path, **params)
        facts.oa_requests += 1
        env = models.envelope(r.body) if r.error is None else None
        err = r.error or (None if env else "the answer is not the documented {meta, data} envelope")
        count = len(env[1]) if env and isinstance(env[1], list) else None
        if err:
            facts.oa_errors[endpoint] = err
        elif keep and conn and db.carries_addresses(r.body):
            facts.oa_withheld_unexpected.append(endpoint)
        _store(conn, run_id, db.OA, endpoint, day, r, record_count=count, error=err, keep_body=keep)
        return env

    # ---- 1. status: the day everything else is filed under
    env = fetch("status", "status", facts.today)
    st = models.parse_status(env[1]) if env else None
    if st is None:
        facts.oa_errors.setdefault("status", "status carries no ref_day")
        return out
    facts.oa_status_before = st
    day = st.ref_day
    out["day"] = str(day)
    log.info("offensive.agency: data to %s", day)

    # ---- 2. frameworks and their detection rules
    env = fetch("agents", "agents", day)
    agents, malformed = models.parse_agents(env[1]) if env else ([], 0)
    if env and not agents:
        facts.oa_errors["agents"] = "the framework list is empty"
    facts.oa_tracked = sorted(a.slug for a in agents if a.tracked)
    facts.oa_listed_active = {a.slug: a.hosts_active for a in agents if a.hosts_active}
    rules_of: dict[str, list] = {}          # only frameworks whose profile answered
    for a in agents:
        env = fetch(f"agent:{a.slug}", f"agents/{a.slug}", day)
        if not env:
            continue
        rules_of[a.slug] = models.parse_fingerprints(env[1])
        facts.oa_rules[a.slug] = len(rules_of[a.slug])
    out.update({"frameworks": len(agents), "tracked": len(facts.oa_tracked), "malformed_frameworks": malformed,
                "rules": sum(facts.oa_rules.values())})

    # ---- 3. the answers kept verbatim; the timeline is also the daily history
    timeline_rows: list = []
    for name in OA_KEPT:
        env = fetch(name, name, day)
        if name == "timeline" and env:
            timeline_rows, facts.oa_timeline_days = models.parse_timeline(env[1])
            if not timeline_rows:
                facts.oa_errors["timeline"] = "the timeline could not be aligned to its days"

    # ---- 4. host records: counted, never kept
    agg = models.HostAggregate()
    offset = 0
    for page in range(OA_MAX_HOST_PAGES):
        env = fetch(f"hosts:{page}", "hosts", day, keep=False, scope="active", limit=OA_HOST_PAGE, offset=offset)
        if not env:
            break
        meta, data = env
        if page == 0 and isinstance(meta.get("total"), int):
            facts.oa_hosts_stated = meta["total"]
        models.aggregate_hosts(agg, data)
        # The next page's URL is built here from the offset the source names, never taken as
        # given: the URL is stored, and a server-supplied one could carry anything. A `next`
        # that is not a later offset of this same list ends the paging; a list cut short that
        # way fails `oa_hosts_complete`.
        m = re.fullmatch(r"/api/v1/hosts\?(?:[a-z_]+=[A-Za-z0-9_]+&)*offset=(\d{1,9})(?:&[a-z_]+=[A-Za-z0-9_]+)*", str(meta.get("next") or ""))
        if not m or int(m.group(1)) <= offset or not data:
            break
        offset = int(m.group(1))
    facts.oa_hosts_counted, facts.oa_hosts_malformed = agg.records, agg.malformed
    facts.oa_counted_active = dict(agg.active)

    # ---- 5. status again: did the source update under us?
    env = fetch("status:after", "status", day)
    facts.oa_status_after = models.parse_status(env[1]) if env else None

    out.update({"requests": facts.oa_requests, "addresses": agg.records,
                "active": {k: v for k, v in sorted(agg.active.items(), key=lambda kv: -kv[1])}})

    # ---- 6. derived rows, only from a source that passed its checks
    failed = [r.name for r in (c(facts) for c in evals.OA_CHECKS) if r.blocking]
    if failed:
        log.warning("offensive.agency: not stored, failed %s", ", ".join(failed))
        out["not_stored_because"] = failed
        return out
    # A tracked framework with no address today is a measured zero, and gets a row saying so:
    # without it the framework would vanish from the day and read as "not listed".
    fw_values = {(slug, "active_7d_addresses"): agg.active.get(slug, 0)
                 for slug in {*facts.oa_tracked, *agg.active}}
    fw_values[("*", "active_7d_addresses")] = agg.records
    computed = len(fw_values) + len(agg.by_network)
    facts.computed_rows += computed
    if conn:
        db.upsert_frameworks(conn, agents, day)
        new_rules = retired = 0
        for slug, rules in rules_of.items():
            n, r = db.upsert_rules(conn, slug, rules, day)
            new_rules, retired = new_rules + n, retired + r
        out.update({"rules_new": new_rules, "rules_retired": retired})
        facts.stored_rows += db.replace_day(conn, run_id, db.OA, day, day, framework_values=fw_values,
                                            network_values=dict(agg.by_network))
        db.upsert_network_names(conn, agg.orgs, day)
        out["timeline_rows_changed"] = db.upsert_timeline(conn, run_id, timeline_rows, day)
    else:
        facts.stored_rows += computed
    out["stored_day"] = str(day)
    log.info("offensive.agency: %s addresses across %s frameworks for %s", agg.records, len(agg.active), day)
    return out


# ---- Shodan ------------------------------------------------------------------

def collect_shodan(shodan: Shodan, cfg: models.Config, conn, run_id, facts: Facts) -> dict:
    day = facts.today
    out: dict = {"day": str(day), "window_days": cfg.window_days}
    r = shodan.info()
    facts.sh_info_status = r.status
    facts.sh_plan = models.parse_plan(r.body)
    _store(conn, run_id, db.SHODAN, "api-info", day, r)
    out["plan"] = facts.sh_plan
    if r.status != 200 or facts.sh_plan is None:
        return out                       # a refused key: do not send 45 more requests to learn it again

    facts.sh_rules = cfg.rule_count
    networks: Counter = Counter()
    for fw in cfg.frameworks:
        total, complete, per_asn = 0, True, Counter()
        for rule, query in models.build_queries(fw, day, cfg.window_days):
            label = f"{fw.slug}#{rule.ordinal}"
            r = shodan.count(query, models.FACETS)
            c = models.parse_count(r.body, r.error)
            if c.error is not None:
                c.error = db.scrub(redact(c.error))      # Shodan's own error text goes to a public log
            _store(conn, run_id, db.SHODAN, f"count:{label}", day, r, record_count=c.total, error=c.error)
            if c.error is not None:
                facts.sh_rule_errors[label] = c.error
                complete = False
                continue
            if rule.anchor:
                facts.sh_anchor_totals[label] = c.total
            if c.total and (c.asn_truncated or sum(c.asn.values()) < 0.8 * c.total):
                facts.sh_facet_short.append(label)
            total += c.total
            per_asn.update(c.asn)
        if complete:
            facts.sh_totals[fw.slug] = total
            for asn, n in per_asn.items():
                networks[(fw.slug, asn, "")] += n
        else:
            facts.sh_incomplete.append(fw.slug)
    out.update({"requests": shodan.http.requests, "services": dict(sorted(facts.sh_totals.items(), key=lambda kv: -kv[1])),
                "left_out": sorted(facts.sh_incomplete)})
    if conn:
        out["previous"] = db.previous_services(conn, day)

    failed = [r.name for r in (c(facts) for c in evals.SHODAN_CHECKS) if r.blocking]
    if failed:
        log.warning("shodan: not stored, failed %s", ", ".join(failed))
        out["not_stored_because"] = failed
        return out
    fw_values = {(slug, "services_7d"): n for slug, n in facts.sh_totals.items()}
    computed = len(fw_values) + len(networks)
    facts.computed_rows += computed
    if conn:
        facts.stored_rows += db.replace_day(conn, run_id, db.SHODAN, day, day, framework_values=fw_values,
                                            network_values=dict(networks))
    else:
        facts.stored_rows += computed
    out["stored_day"] = str(day)
    log.info("shodan: %s services across %s frameworks for %s", sum(facts.sh_totals.values()), len(facts.sh_totals), day)
    return out


def _write(path, report) -> None:
    if path:
        with open(path, "w") as fh:
            fh.write(json.dumps(report, indent=1, default=str))


if __name__ == "__main__":
    sys.exit(main())
