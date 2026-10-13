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


def store_records(cur, source_id: str, items: list[tuple[str, dict]], fetch_id) -> tuple[dict, set]:
    """Insert a new version only when a record's content changed. Returns the counts and the
    ids that are new or changed - the only rows the caller needs to apply again."""
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
    for rid, rec in items:
        if rid in seen:
            continue
        seen.add(rid)
        h = content_hash(rec)
        cur_v = current.get(rid)
        if cur_v and cur_v[1] == h:
            counts["unchanged"] += 1
            continue
        version = (cur_v[0] + 1) if cur_v else 1
        counts["changed" if cur_v else "new"] += 1
        changed.add(rid)
        cur.execute(
            """insert into breach_raw.source_records (source_id, source_record_id, version,
                                                      content_hash, record, fetch_id)
               values (%s,%s,%s,%s,%s,%s)""", (source_id, rid, version, h, Jsonb(rec), fetch_id))
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


def upsert_leak_posts(cur, posts) -> dict:
    """Fold tracker posts into posting episodes. A post joins an existing claim when the
    group matches and the victim matches by domain or normalised name within 14 days;
    otherwise it opens a new claim. Re-running over the same posts changes nothing."""
    counts = {"new_claims": 0, "joined": 0, "already": 0}
    for p in sorted(posts, key=lambda p: p.seen_at):
        ref = {"source_id": p.source_id, "id": p.source_record_id}
        cur.execute(
            """select claim_key, tracker_refs from breach_core.leak_claims
                where actor_group = %s
                  and ((victim_domain is not null and victim_domain = %s) or victim_norm = %s)
                  and first_seen_at between %s and %s
                order by abs(extract(epoch from first_seen_at - %s)) limit 1""",
            (p.actor_group, p.victim_domain, p.victim_norm, p.seen_at - LEAK_WINDOW,
             p.seen_at + LEAK_WINDOW, p.seen_at))
        row = cur.fetchone()
        if row:
            key, refs = row
            if ref in (refs or []):
                counts["already"] += 1
                continue
            cur.execute(
                """update breach_core.leak_claims set
                       trackers = (select array_agg(distinct t order by t) from unnest(trackers || %s::text) t),
                       tracker_refs = tracker_refs || %s::jsonb,
                       victim_domain = coalesce(victim_domain, %s),
                       country = coalesce(country, %s), sector = coalesce(sector, %s),
                       first_seen_at = least(first_seen_at, %s), last_seen_at = greatest(last_seen_at, %s)
                    where claim_key = %s""",
                (p.source_id, json.dumps([ref]), p.victim_domain, p.country, p.sector,
                 p.seen_at, p.seen_at, key))
            counts["joined"] += 1
        else:
            key = f"{p.actor_group}|{p.victim_domain or p.victim_norm}|{p.seen_at.date().isoformat()}"
            cur.execute(
                """insert into breach_core.leak_claims (claim_key, actor_group, victim_name, victim_norm,
                       victim_domain, country, sector, first_seen_at, last_seen_at, trackers, tracker_refs)
                   values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                   on conflict (claim_key) do nothing""",
                (key, p.actor_group, p.victim_name, p.victim_norm, p.victim_domain, p.country,
                 p.sector, p.seen_at, p.seen_at, [p.source_id], Jsonb([ref])))
            counts["new_claims"] += cur.rowcount
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
