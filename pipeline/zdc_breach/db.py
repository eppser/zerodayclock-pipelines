"""Persistence for the breach pipeline. Every function takes an open connection; the caller
owns the transaction, so one source's failure rolls back only that source."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone

from psycopg.types.json import Jsonb

from .http import Fetched

LEAK_WINDOW = timedelta(days=14)


def content_hash(record) -> str:
    return hashlib.sha256(json.dumps(record, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def record_fetch(cur, run_id, source_id: str, f: Fetched, n_records: int | None) -> str:
    cur.execute(
        """insert into breach_raw.fetches (run_id, source_id, url, requested_at, finished_at,
                                           http_status, bytes, sha256, n_records, error)
           values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) returning fetch_id""",
        (run_id, source_id, f.url, f.requested_at, f.finished_at, f.status, len(f.body),
         f.sha256 if f.body else None, n_records, f.error))
    return cur.fetchone()[0]


def store_records(cur, source_id: str, items: list[tuple[str, dict]], fetch_id,
                  limit: int | None = None) -> tuple[dict, set]:
    """Insert a new version only when a record's content changed. Returns the counts and the
    ids that are new or changed - the only rows the caller needs to apply again.

    `limit` caps how many new or changed records one run writes. The rest are left unwritten,
    so the next run sees them as new and takes the next slice: a first fill of thousands of
    regulator rows spreads over several hourly runs instead of outliving the job's timeout."""
    if not items:
        return {"new": 0, "changed": 0, "unchanged": 0}, set()
    ids = list({i for i, _ in items})
    cur.execute(
        """select distinct on (source_record_id) source_record_id, version, content_hash
             from breach_raw.source_records
            where source_id = %s and source_record_id = any(%s)
            order by source_record_id, version desc""", (source_id, ids))
    current = {r[0]: (r[1], r[2]) for r in cur.fetchall()}
    counts = {"new": 0, "changed": 0, "unchanged": 0}
    seen, changed = set(), set()
    rows = []
    for rid, rec in items:
        if rid in seen:
            continue
        seen.add(rid)
        h = content_hash(rec)
        cur_v = current.get(rid)
        if cur_v and cur_v[1] == h:
            counts["unchanged"] += 1
            continue
        if limit is not None and len(changed) >= limit:
            counts["deferred"] = counts.get("deferred", 0) + 1
            continue
        version = (cur_v[0] + 1) if cur_v else 1
        counts["changed" if cur_v else "new"] += 1
        changed.add(rid)
        rows.append((source_id, rid, version, h, Jsonb(rec), fetch_id))
    # One pipelined batch: a runner is ~100 ms from the database, and one round trip per
    # record made a 2,000-row first fill take minutes (measured 2026-10-14).
    if rows:
        with cur.connection.pipeline():
            cur.executemany(
                """insert into breach_raw.source_records (source_id, source_record_id, version,
                                                          content_hash, record, fetch_id)
                   values (%s,%s,%s,%s,%s,%s)""", rows)
    return counts, changed


def mark_source(cur, source_id: str, ok: bool, error: str | None = None, watermark: dict | None = None):
    cur.execute(
        """insert into breach_core.source_state (source_id, last_attempt_at, last_success_at, last_error, watermark)
           values (%s, now(), case when %s then now() end, %s, coalesce(%s, '{}'::jsonb))
           on conflict (source_id) do update set
               last_attempt_at = now(),
               last_success_at = case when %s then now() else breach_core.source_state.last_success_at end,
               last_error = %s,
               watermark = coalesce(%s, breach_core.source_state.watermark)""",
        (source_id, ok, error, Jsonb(watermark) if watermark is not None else None,
         ok, error, Jsonb(watermark) if watermark is not None else None))


def watermark(cur, source_id: str) -> dict:
    cur.execute("select watermark from breach_core.source_state where source_id = %s", (source_id,))
    r = cur.fetchone()
    return (r[0] or {}) if r else {}


def _raw(name: str | None) -> str:
    return " ".join((name or "").split()).lower()


def upsert_leak_posts(cur, posts) -> dict:
    """Fold tracker posts into posting episodes. A post joins an existing claim when the
    group matches and the victim matches by domain or normalised name within 14 days;
    otherwise it opens a new claim. Re-running over the same posts changes nothing.

    In memory, then one pipelined write batch: the 12-month backfill is ~11,000 posts, and two
    round trips each from a runner ~100 ms away would outlive the job (2026-10-14)."""
    counts = {"new_claims": 0, "joined": 0, "already": 0}
    posts = sorted(posts, key=lambda p: p.seen_at)
    if not posts:
        return counts
    groups = sorted({p.actor_group for p in posts})
    cur.execute("""select claim_key, actor_group, victim_domain, victim_norm, first_seen_at, last_seen_at,
                          trackers, tracker_refs, country, sector, employees_stated, demand_text, victim_name
                     from breach_core.leak_claims
                    where actor_group = any(%s) and first_seen_at between %s and %s""",
                (groups, posts[0].seen_at - LEAK_WINDOW, posts[-1].seen_at + LEAK_WINDOW))
    by_group: dict = {}
    for key, grp, dom, norm, first, last, trackers, refs, country, sector, emp, dem, vname in cur.fetchall():
        by_group.setdefault(grp, []).append({"key": key, "domain": dom, "norm": norm, "first": first, "last": last,
                                             "name": vname,
                                             "trackers": list(trackers), "refs": list(refs or []),
                                             "country": country, "sector": sector, "employees": emp,
                                             "demand": (dem, None, None) if dem else None, "demand_new": False,
                                             "dirty": False, "new": False})
    for p in posts:
        ref = {"source_id": p.source_id, "id": p.source_record_id}
        cands = [c for c in by_group.get(p.actor_group, [])
                 # an empty normalised name (a Korean, Cyrillic, Greek or Arabic name) matches nothing
                 # (the raw name, spacing and case aside, stands in for it there)
                 if ((c["domain"] is not None and c["domain"] == p.victim_domain)
                     or (p.victim_norm and c["norm"] == p.victim_norm)
                     or (not p.victim_norm and not c["norm"] and _raw(c.get("name")) == _raw(p.victim_name)))
                 and abs(c["first"] - p.seen_at) <= LEAK_WINDOW]
        if cands:
            c = min(cands, key=lambda c: abs((c["first"] - p.seen_at).total_seconds()))
            if ref in c["refs"]:
                counts["already"] += 1
                if c["employees"] is None and p.employees:
                    c["employees"], c["dirty"] = p.employees, True
                if c["demand"] is None and p.demand:
                    c["demand"], c["demand_new"], c["dirty"] = p.demand, True, True
                continue
            c["refs"].append(ref)
            c["trackers"] = sorted(set(c["trackers"]) | {p.source_id})
            c["domain"] = c["domain"] or p.victim_domain
            c["country"] = c["country"] or p.country
            c["sector"] = c["sector"] or p.sector
            c["employees"] = c["employees"] or p.employees
            if c["demand"] is None and p.demand:
                c["demand"], c["demand_new"] = p.demand, True
            c["first"], c["last"] = min(c["first"], p.seen_at), max(c["last"], p.seen_at)
            c["dirty"] = True
            counts["joined"] += 1
        else:
            # with no domain and an empty normalised name the raw name keys the claim, so two such
            # victims of one group on one day stay two claims
            who = p.victim_domain or p.victim_norm or "name:" + _raw(p.victim_name)
            key = f"{p.actor_group}|{who}|{p.seen_at.date().isoformat()}"
            existing = next((c for c in by_group.get(p.actor_group, []) if c["key"] == key), None)
            if existing:            # the same key opened earlier in this batch or a previous run
                counts["already"] += 1
                continue
            by_group.setdefault(p.actor_group, []).append(
                {"key": key, "domain": p.victim_domain, "norm": p.victim_norm, "first": p.seen_at, "last": p.seen_at,
                 "trackers": [p.source_id], "refs": [ref], "country": p.country, "sector": p.sector,
                 "employees": p.employees, "demand": p.demand, "demand_new": p.demand is not None,
                 "dirty": True, "new": True, "group": p.actor_group, "name": p.victim_name})
            counts["new_claims"] += 1
    inserts, updates, demands = [], [], []
    for grp, cs in by_group.items():
        for c in cs:
            if not c["dirty"]:
                continue
            if c.get("demand_new") and c["demand"]:
                demands.append((c["demand"][0], c["demand"][1], c["demand"][2], c["key"]))
            if c["new"]:
                inserts.append((c["key"], grp, c["name"], c["norm"], c["domain"], c["country"], c["sector"],
                                c["first"], c["last"], c["trackers"], Jsonb(c["refs"]), c["employees"]))
            else:
                updates.append((c["trackers"], Jsonb(c["refs"]), c["domain"], c["country"], c["sector"],
                                c["first"], c["last"], c["employees"], c["key"]))
    with cur.connection.pipeline():
        if inserts:
            cur.executemany("""insert into breach_core.leak_claims (claim_key, actor_group, victim_name, victim_norm,
                                   victim_domain, country, sector, first_seen_at, last_seen_at, trackers, tracker_refs,
                                   employees_stated)
                               values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) on conflict (claim_key) do nothing""", inserts)
        if demands:
            cur.executemany("""update breach_core.leak_claims set demand_text = %s, demand_amount = %s,
                                   demand_currency = %s where claim_key = %s""", demands)
        if updates:
            cur.executemany("""update breach_core.leak_claims set trackers = %s, tracker_refs = %s,
                                   victim_domain = %s, country = %s, sector = %s,
                                   first_seen_at = %s, last_seen_at = %s, employees_stated = %s
                                where claim_key = %s""", updates)
    return counts


def llm_spend(cur) -> tuple[float, float]:
    cur.execute(
        """select coalesce(sum(cost_usd) filter (where called_at >= date_trunc('month', now())), 0),
                  coalesce(sum(cost_usd) filter (where called_at >= date_trunc('day', now())), 0)
             from breach_core.llm_calls""")
    m, d = cur.fetchone()
    return float(m), float(d)


def record_llm_call(cur, run_id, res, prompt_hash: str, doc_sha256: str | None) -> str:
    cur.execute(
        """insert into breach_core.llm_calls (run_id, model, provider, prompt_hash, doc_sha256,
               input_tokens, output_tokens, cost_usd, latency_ms, ok, error)
           values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) returning call_id""",
        (run_id, res.model, res.provider, prompt_hash, doc_sha256, res.input_tokens,
         res.output_tokens, res.cost_usd, res.latency_ms, res.ok, res.error))
    return cur.fetchone()[0]


def now() -> datetime:
    return datetime.now(timezone.utc)
