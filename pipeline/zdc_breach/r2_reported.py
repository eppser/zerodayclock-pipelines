"""R2 reported date v2 (engine_version r2x-reported-v2): one STRUCTURED value per breach event.

RUBRIC_R2 s2: reported date = the earliest member record. v1 (r2-struct-v1) wrote a reported date on every leak claim and
every press document, including documents that are not breach reports (gate 2026-10-24: press 148/499 = 0.297). v2
shows a reported date only on a BREACH EVENT: an active (or merged-into) r2_events event of the current membership
version with at least one non-follow-up member. The value is the minimum over those members of the record date:

    leak claim          -> leak_claims.first_seen_at          (basis leak_site,   source_kind leak)
    incident            -> incidents.first_public_date, i.e. the least as_of of its records (resolve.py): the press
                           published_at, the regulator filing/notice date, the index added date. The source kind of
                           that date is the incident's highest-precedence record kind (regulator > index > press)
                           (basis filing | index_added | published_at)

Follow-up members (role follow_up, 0171) never set the date. An event whose members are all follow-ups, or that has no
dated member, gets an 'abstain' row. Ties: regulator > index > press > leak. Dates after the run date or before 1990 are
data errors of their record: left out of the minimum; an event whose every member date is one is rejected (never shown). Merged events: their members count for the survivor (as in rebuild_r2_shadow).

Stored as r2_values rows: subject_kind 'event', field 'reported_date', precision 'day', engine 'structured'. The shadow
rule for reported_date is "earliest top-rank value" (migration 0187), so an event value never conflicts with the
member-level r2-struct-v1 values; release is still per (source_kind, basis, engine_version) in r2_field_release.

CLI (counts only, never a name):
  python -m zdc_breach.r2_reported run --out FILE.json            # read-only: compute rows, write them to a local file
  python -m zdc_breach.r2_reported load --rows FILE.json          # insert (refuses if v2 rows exist for this version)
  python -m zdc_breach.r2_reported run --new-only [--write]       # hourly: only the events the stored rows do not cover

Incremental (--new-only; the full `load` guard stays as it is). Events are added hourly (r2_events --new-only), so a
row set computed once leaves every later event without a reported date. --new-only recomputes every event from live data
(the same build_rows) and keeps only what is missing: a row is written for an event that has NO r2x-reported-v2 row, and
for an event whose recomputed ACCEPTED day is earlier than every accepted row it has (a record that joined later and is
older; the shadow rule takes the earliest accepted value). Nothing is updated or deleted; a second run writes nothing.
It refuses to start when no v2 row exists at all (that is the first backfill: use run --out / load).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from datetime import date

ENGINE_VERSION = "r2x-reported-v2"
ENGINE = "structured"
MIN_YEAR = 1990
PRECEDENCE = {"regulator": 0, "index": 1, "press": 2, "leak": 3}
BASIS = {"regulator": "filing", "index": "index_added", "press": "published_at", "leak": "leak_site"}
STATEMENT_TIMEOUT = "60s"


@dataclass(frozen=True)
class MemberDate:
    member_kind: str          # claim | incident
    member_id: str
    role: str                 # member | follow_up
    day: date | None
    source_kind: str | None   # leak | regulator | index | press


def incident_date(first_public: date | None, record_kinds: set, doc_days: list) -> tuple[date | None, str | None]:
    """(date, source_kind) of one incident. The date is first_public_date, the least as_of of all its records
    (resolve.py); without it, the earliest linked document. The source kind is the incident's highest-precedence record
    kind (regulator > index > press): per-record as_of of regulator/index records is not stored, so a tie cannot be
    told from a later filing; the precedence rule decides."""
    if first_public is None:
        days = sorted(d for d in doc_days if d)
        return (days[0], "press") if days else (None, None)
    for k in ("regulator", "index", "press"):
        if k in record_kinds:
            return first_public, k
    return (first_public, "press") if doc_days else (first_public, None)


def event_reported(members: list[MemberDate], today: date) -> tuple[str, date | None, str | None, str | None]:
    """(verdict, day, source_kind, reason) for one event."""
    core = [m for m in members if m.role != "follow_up"]
    if not core:
        return "abstain", None, None, "follow_up_only"
    dated = [m for m in core if m.day is not None and m.source_kind is not None]
    if not dated:
        return "abstain", None, None, "no_member_date"
    key = lambda m: (m.day, PRECEDENCE[m.source_kind], m.member_kind, m.member_id)
    # an implausible member date (a 1971-01-01 placeholder, a date in the future) is a data error of THAT record: it is
    # left out, it must not hide the plausible date of another member. The event is rejected only when no member date
    # is plausible.
    ok = [m for m in dated if MIN_YEAR <= m.day.year and m.day <= today]
    if ok:
        best = min(ok, key=key)
        return "accepted", best.day, best.source_kind, None
    best = min(dated, key=key)
    return "rejected", best.day, best.source_kind, ("future_date" if best.day > today else "implausible_year")


def build_rows(events: dict, members: list[dict], claims: dict, incidents: dict, today: date) -> list[dict]:
    """events: event_id -> {status, merged_into}; members: [{event_id, member_kind, member_id, role}];
    claims: claim_key -> first_seen date; incidents: incident_id -> {first_public, kinds:set, doc_days:list}."""
    by_event: dict[str, list[MemberDate]] = {}
    for m in members:
        e = events.get(m["event_id"])
        if e is None:
            continue
        eid = (e["merged_into"] or m["event_id"]) if e["status"] == "merged" else m["event_id"]
        if m["member_kind"] == "claim":
            d, sk = claims.get(m["member_id"]), "leak"
        elif m["member_kind"] == "incident":
            i = incidents.get(m["member_id"])
            d, sk = incident_date(i["first_public"], i["kinds"], i["doc_days"]) if i else (None, None)
        else:
            continue
        by_event.setdefault(eid, []).append(MemberDate(m["member_kind"], m["member_id"], m["role"], d, sk))
    rows = []
    for eid in sorted(by_event):
        if events.get(eid, {}).get("status") != "active":      # withdrawn, or a merged event without a survivor
            continue
        verdict, d, sk, reason = event_reported(by_event[eid], today)
        rows.append(_row(eid, verdict, d, sk, reason))
        if verdict == "accepted" and sk == "press" and tie_leak_member(by_event[eid], d, today):
            rows.append(_row(eid, verdict, d, "leak", reason))
    return rows


def _row(eid: str, verdict: str, d: date | None, sk: str | None, reason: str | None) -> dict:
    return {"subject_kind": "event", "subject_id": eid, "field": "reported_date",
            "value": d.isoformat() if d else None, "value_precision": "day" if verdict != "abstain" else None,
            "source_kind": sk or "press", "basis": BASIS.get(sk or "press"), "engine": ENGINE,
            "engine_version": ENGINE_VERSION, "verdict": verdict, "verdict_reason": reason}


def tie_leak_member(members: list[MemberDate], day: date, today: date) -> bool:
    """True when a non-follow-up leak post of the event carries exactly the event's reported day. The tie-break labels
    the day 'press' (that stratum is withheld: the 2026-10-24 gate had no sealed press units), but a leak post of that
    very day is the same value from a released stratum (leak_site), so the event also gets a leak-labelled row of that
    day. Only an equal day: an earlier press date is never replaced by a later leak post, the definition is the earliest."""
    return any(m.role != "follow_up" and m.source_kind == "leak" and m.day == day and MIN_YEAR <= day.year and day <= today
               for m in members)


# =====================================================================================================================
# DB (read-only fetch; insert-only load)
# =====================================================================================================================
KIND_MAP = {"regulator": "regulator", "breach_index": "index", "news": "press"}


def fetch(conn) -> tuple[dict, list, dict, dict, str]:
    with conn.transaction(), conn.cursor() as cur:
        cur.execute("set transaction read only")
        cur.execute(f"set local statement_timeout = '{STATEMENT_TIMEOUT}'")
        cur.execute("select value from breach_core.breach_settings where key = 'r2_membership_version'")
        ver = cur.fetchone()[0]
        cur.execute("select event_id::text, status, merged_into::text from breach_core.r2_events where method_version = %s", (ver,))
        events = {e: {"status": s, "merged_into": mi} for e, s, mi in cur.fetchall()}
        cur.execute("""select event_id::text, member_kind, member_id, role from breach_core.r2_event_members
                        where method_version = %s""", (ver,))
        members = [dict(zip(("event_id", "member_kind", "member_id", "role"), r)) for r in cur.fetchall()]
        cur.execute("select claim_key, first_seen_at::date from breach_core.leak_claims")
        claims = dict(cur.fetchall())
        cur.execute("select incident_id::text, first_public_date from breach_core.incidents")
        incidents = {i: {"first_public": d, "kinds": set(), "doc_days": []} for i, d in cur.fetchall()}
        cur.execute("""select s.incident_id::text, src.kind, d.published_at::date
                         from breach_core.incident_sources s join breach_core.sources src using (source_id)
                         left join breach_raw.documents d on d.doc_sha256 = nullif(s.doc_sha256, '')""")
        for iid, kind, pub in cur.fetchall():
            i = incidents.get(iid)
            if i is None:
                continue
            if kind in KIND_MAP:
                i["kinds"].add(KIND_MAP[kind])
            if pub is not None:
                i["doc_days"].append(pub)
    return events, members, claims, incidents, ver


def fetch_existing(cur) -> dict:
    """event id -> {'any': True, 'accepted_min': earliest accepted day or None, 'kinds_at_min': the source kinds of the
    stored accepted rows carrying that day} over the stored v2 rows."""
    cur.execute("""select subject_id, source_kind, min(value::date) filter (where verdict = 'accepted')
                     from breach_core.r2_values
                    where engine_version = %s and subject_kind = 'event' and field = 'reported_date' group by 1, 2""",
                (ENGINE_VERSION,))
    per: dict = {}
    for sid, sk, d in cur.fetchall():
        per.setdefault(sid, {})[sk] = d
    out = {}
    for sid, kinds in per.items():
        days = [d for d in kinds.values() if d is not None]
        m = min(days) if days else None
        out[sid] = {"any": True, "accepted_min": m, "kinds_at_min": {k for k, d in kinds.items() if d is not None and d == m}}
    return out


def select_new(rows: list[dict], existing: dict) -> list[dict]:
    """The rows to add: events with no stored v2 row (any verdict), and events whose recomputed accepted day is earlier
    than every stored accepted day (or that only have a stored abstain/rejected row and now compute an accepted day),
    and an accepted row of the stored minimum day whose source kind no stored accepted row of that day carries (the
    leak-labelled twin of a press day, see tie_leak_member: it makes the same day releasable)."""
    out = []
    for r in rows:
        e = existing.get(r["subject_id"])
        if e is None:
            out.append(r)
        elif r["verdict"] == "accepted":
            d = date.fromisoformat(r["value"])
            if e["accepted_min"] is None or d < e["accepted_min"]:
                out.append(r)
            elif d == e["accepted_min"] and r["source_kind"] not in e.get("kinds_at_min", {r["source_kind"]}):
                out.append(r)
    return out


def load_new(conn, rows: list[dict]) -> dict:
    """Additive insert of select_new() rows, re-checked under an advisory lock inside the transaction (two runs never
    both insert the same event). Refuses when no v2 row exists yet (the first backfill goes through load)."""
    cols = ["subject_kind", "subject_id", "field", "value", "value_precision", "source_kind", "basis", "engine",
            "engine_version", "verdict", "verdict_reason"]
    with conn.transaction(), conn.cursor() as cur:
        cur.execute(f"set local statement_timeout = '{STATEMENT_TIMEOUT}'")
        cur.execute("select pg_advisory_xact_lock(hashtext('zdc_r2_reported_v2'))")
        existing = fetch_existing(cur)
        if not existing:
            raise SystemExit(f"no {ENGINE_VERSION} rows exist: this is the first backfill, use run --out / load")
        todo = select_new(rows, existing)
        if todo:
            with cur.copy(f"copy breach_core.r2_values ({', '.join(cols)}) from stdin") as cp:
                for r in todo:
                    cp.write_row([r[c] for c in cols])
    return {"inserted": len(todo), "earlier_than_stored": sum(1 for r in todo if r["subject_id"] in existing)}


def run_new_only(conn, today: date | None = None, write_db: bool = True) -> dict:
    """Recompute from live data, keep what is missing, optionally write it. Counts only."""
    events, members, claims, incidents, ver = fetch(conn)
    rows = build_rows(events, members, claims, incidents, today or date.today())
    with conn.transaction(), conn.cursor() as cur:
        cur.execute("set transaction read only")
        cur.execute(f"set local statement_timeout = '{STATEMENT_TIMEOUT}'")
        existing = fetch_existing(cur)
    todo = select_new(rows, existing)
    by: dict = {}
    for r in todo:
        k = f"{r['verdict']}:{r['source_kind']}:{r['verdict_reason'] or r['basis']}"
        by[k] = by.get(k, 0) + 1
    rep = {"membership_version": ver, "events": len(events), "event_rows": len(rows), "stored_event_rows": len(existing),
           "missing": len(todo), "by": dict(sorted(by.items())), "written": False}
    if write_db:
        rep["write"] = load_new(conn, rows)
        rep["written"] = True
    return rep


def load(conn, rows: list[dict]) -> int:
    cols = ["subject_kind", "subject_id", "field", "value", "value_precision", "source_kind", "basis", "engine",
            "engine_version", "verdict", "verdict_reason"]
    with conn.transaction(), conn.cursor() as cur:
        cur.execute(f"set local statement_timeout = '{STATEMENT_TIMEOUT}'")
        cur.execute("select count(*) from breach_core.r2_values where engine_version = %s", (ENGINE_VERSION,))
        if cur.fetchone()[0]:
            raise SystemExit(f"{ENGINE_VERSION} rows exist: never overwritten; use a new engine_version")
        with cur.copy(f"copy breach_core.r2_values ({', '.join(cols)}) from stdin") as cp:
            for r in rows:
                cp.write_row([r[c] for c in cols])
    return len(rows)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="zdc_breach.r2_reported")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("run"); a.add_argument("--out"); a.add_argument("--today")
    a.add_argument("--new-only", action="store_true", help="incremental against the live DB; dry run unless --write")
    a.add_argument("--write", action="store_true")
    b = sub.add_parser("load"); b.add_argument("--rows", required=True)
    args = ap.parse_args(argv)
    import psycopg
    conn = psycopg.connect(os.environ["DATABASE_URL"], connect_timeout=20)
    if args.cmd == "run" and args.new_only:
        rep = run_new_only(conn, date.fromisoformat(args.today) if args.today else None, args.write)
        if args.out:
            json.dump(rep, open(args.out, "w"), indent=1)
        print(json.dumps(rep))
        return 0
    if args.cmd == "run":
        if not args.out:
            ap.error("run needs --out (or --new-only)")
        events, members, claims, incidents, ver = fetch(conn)
        rows = build_rows(events, members, claims, incidents, date.fromisoformat(args.today) if args.today else date.today())
        json.dump({"membership_version": ver, "engine_version": ENGINE_VERSION, "rows": rows}, open(args.out, "w"))
        c: dict = {}
        for r in rows:
            k = f"{r['verdict']}:{r['source_kind']}:{r['verdict_reason'] or r['basis']}"
            c[k] = c.get(k, 0) + 1
        print(json.dumps({"membership_version": ver, "events": len(events), "rows": len(rows), "by": dict(sorted(c.items()))}))
    else:
        print(json.dumps({"inserted": load(conn, json.load(open(args.rows))["rows"])}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
