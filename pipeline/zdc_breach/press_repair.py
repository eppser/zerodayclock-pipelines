"""One-off repair of press-only incidents that are follow-ups or same-organisation duplicates (dates audit fix 4).

Dry run by default: reads the database (in a READ ONLY transaction), decides, and writes a JSON plan. Nothing is
changed unless --apply is given, and --apply only replays a plan file that a person has read.

WHICH ROWS. Every public press-only victim: a list row (breach_core.victims_list) of kind incident whose status is
reported_in_press and whose every source is a news feed - the audit's 774. For each, the same rules the pipeline
now applies to new documents (zdc_breach.doc_kind, extract coarse dates, resolve.coarse_window):

- follow_up        every document behind the row is a follow-up (lawsuit, settlement, fine, OCR resolution,
                   sentencing, arrest, ruling, anniversary, re-notice) - the audit's court/settlement titles;
- old_year         a breach year two or more years before the row's date is grounded next to a breach noun in a
                   sentence naming the organisation (the audit's "names a year >= 2y earlier");
- older_same_org   another incident of the same organisation (same org or same normalised name) was first public
                   180+ days earlier (the audit's 61, 52 of them regulator or leak rows).

WHAT IS PROPOSED, per flagged row:
- possible_duplicate_of <older incident>: an earlier incident of the same organisation that is the same breach by
  evidence, in this order: the row's stated event date (within 30 days, or an incident known only by its filing
  date filed within resolve.FILING_LAG after it); a grounded breach year/month (resolve.matches_coarse); for a
  follow-up with no date at all, the organisation's only older incident. Structured (regulator / breach index /
  leak) incidents first, then roots, then the earliest. The row then counts once, behind it (0144's survivor
  rule still applies). A row that is itself already a 0144 survivor goes to review instead.
- review: a follow-up no older incident can be named for - held in breach_core.press_review (0171), which hides
  it until a person attaches, dismisses or releases it.
- keep: not flagged; or a late FIRST notice of an old breach with no older incident (its first public date is
  right - the audit judged these correct); or only an older same-organisation row with no shared date (more
  often a new breach than the same one). Kept rows are listed in the plan with their flags for a person.

    python -m zdc_breach.press_repair --out plan.json                 # dry run against DATABASE_URL
    python -m zdc_breach.press_repair --from-json rows.json --out plan.json   # plan from gathered rows
    python -m zdc_breach.press_repair --apply plan.json               # the only writing path
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from datetime import date, datetime, timedelta, timezone

from . import doc_kind, extract, resolve

METHOD = "press-repair-v1"
OLDER_DAYS = 180       # the audit's "older same-organisation row": first public 180+ days earlier
OLD_YEARS = 2          # the audit's "names a year >= 2y earlier"

# One row per public press-only victim, with its documents and every other incident of its organisation.
# Paged (offset/limit) so a run through the Management API stays light; text is capped per document.
GATHER_SQL = """
with pv as (
  select v.victim_id, i.incident_id, i.org_id, o.display_name, o.norm_name, i.first_public_date, i.event_date,
         i.possible_duplicate_of
    from breach_core.victims_list v
    join breach_core.incidents i on 'incident:' || i.incident_id::text = v.victim_id
    join breach_core.organizations o on o.org_id = i.org_id
   where v.kind = 'incident' and v.status = 'reported_in_press'
     and (select bool_and(s like 'news\\_%%') from unnest(v.sources) s)
   order by v.victim_id offset %(offset)s limit %(limit)s)
select pv.victim_id, pv.incident_id::text, pv.org_id::text, pv.display_name as name, pv.norm_name,
       pv.first_public_date::text as fpd, pv.event_date::text as ev, pv.possible_duplicate_of::text as dup_of,
       (select coalesce(json_agg(json_build_object('sha', d.doc_sha256, 'title', d.title,
                                                   'pub', d.published_at::date::text, 'text', left(d.text, %(text_cap)s))
                                 order by d.published_at, d.doc_sha256), '[]'::json)
          from (select distinct split_part(s.doc_sha256, ':', 1) as sha from breach_core.incident_sources s
                 where s.incident_id = pv.incident_id and s.doc_sha256 <> '') x
          join breach_raw.documents d on d.doc_sha256 = x.sha) as docs,
       (select coalesce(json_agg(json_build_object(
                    'incident_id', j.incident_id::text, 'name', oj.display_name, 'ev', j.event_date::text,
                    'fpd', j.first_public_date::text, 'dup_of', j.possible_duplicate_of::text,
                    'structured', (j.regulator_filed or j.victim_confirmed
                                   or exists (select 1 from breach_core.leak_claims l where l.incident_id = j.incident_id)
                                   or exists (select 1 from breach_core.incident_sources s2
                                                join breach_core.sources src using (source_id)
                                               where s2.incident_id = j.incident_id
                                                 and src.kind in ('regulator', 'breach_index', 'leak_tracker')
                                                 and src.publication <> 'private')),
                    'listed', exists (select 1 from breach_core.victims_list w
                                       where w.victim_id = 'incident:' || j.incident_id::text))
                  order by j.first_public_date, j.incident_id), '[]'::json)
          from breach_core.incidents j join breach_core.organizations oj on oj.org_id = j.org_id
         where (j.org_id = pv.org_id or (oj.norm_name = pv.norm_name and pv.norm_name <> ''))
           and j.incident_id <> pv.incident_id and not j.suppressed
           and j.incident_id not in (select incident_id from breach_core.private_only_incidents)) as others
  from pv
"""


def _d(s):
    return date.fromisoformat(s) if s else None


def _coarse(row) -> list[tuple[int, int | None]]:
    """Grounded breach years/months from the row's documents: sentences naming the organisation, and the titles."""
    fpd = _d(row["fpd"])
    out = set()
    for doc in row["docs"]:
        for c in extract._coarse_candidates(doc.get("text") or "", row["name"], single=False):
            out |= extract.coarse_mentions(c.quote)
        out |= extract.coarse_mentions(doc.get("title") or "")
    return sorted(((y, m) for y, m in out if y <= fpd.year), key=lambda t: (t[0], t[1] or 0))


def decide(row) -> dict:
    """The plan entry for one press-only row (pure: no database)."""
    fpd, ev = _d(row["fpd"]), _d(row["ev"])
    kinds = [doc_kind.classify(d.get("title"), {"is_incident_report": True})
             for d in row["docs"]]
    follow_up = bool(kinds) and all(k.follow_up for k in kinds)
    coarse = _coarse(row)
    old_year = any(y <= fpd.year - OLD_YEARS for y, _ in coarse)
    # earlier incidents of the organisation; never one that already points at this row (no cycles)
    others = [o for o in row["others"] if _d(o["fpd"]) <= fpd and o["dup_of"] != row["incident_id"]]
    older = [o for o in others if _d(o["fpd"]) <= fpd - timedelta(days=OLDER_DAYS)]
    flags = [f for f, on in (("follow_up", follow_up), ("old_year", old_year), ("older_same_org", bool(older))) if on]
    entry = {"victim_id": row["victim_id"], "incident_id": row["incident_id"], "name": row["name"], "fpd": row["fpd"],
             "ev": row["ev"], "dup_of": row.get("dup_of"), "titles": [d.get("title") for d in row["docs"]],
             "kind_reasons": [k.reason for k in kinds], "coarse": [f"{y}" + (f"-{m:02d}" if m else "") for y, m in coarse],
             "flags": flags, "older_listed_structured": any(o["listed"] and o["structured"] for o in older),
             "action": "keep", "target": None, "how": None}
    if not flags:
        return entry

    def best(cands):
        # structured first, a root before a duplicate, then the earliest
        return sorted(cands, key=lambda o: (not o["structured"], o["dup_of"] is not None, o["fpd"], o["incident_id"]))[0]

    # The same breach, in order of evidence: the stated event date; a grounded breach year; for a follow-up
    # with no date at all, the organisation's only older incident (resolve.attach_follow_up's rules).
    target, how = None, None
    by_event = [o for o in others if ev and ((o["ev"] and abs(_d(o["ev"]) - ev) <= resolve.EVENT_WINDOW)
                                             or (not o["ev"] and timedelta(0) <= _d(o["fpd"]) - ev <= resolve.FILING_LAG))]
    by_year = [o for o in others if resolve.matches_coarse(_d(o["ev"]), _d(o["fpd"]), coarse)]
    roots = [o for o in older if o["dup_of"] is None]
    if by_event:
        target, how = best(by_event), "event_window"
    elif by_year and not ev:
        target, how = best(by_year), "coarse_year"
    elif follow_up and not ev and not coarse and len(roots) == 1:
        target, how = roots[0], "only_older_incident"
    if target:
        entry.update(action="possible_duplicate_of", target=target["incident_id"], how=how,
                     target_name=target["name"], target_fpd=target["fpd"], target_ev=target["ev"],
                     target_structured=target["structured"])
        if row.get("dup_of"):
            # already a survivor of a chain 0144 restored: re-pointing it is a person's call
            entry.update(action="review", how="already_linked_elsewhere")
    elif follow_up:
        # news about an old breach, and no incident to put it behind: held for a person
        entry.update(action="review", how="no_older_incident_named")
    elif old_year:
        # a late FIRST notice of an old breach: its first public date is right (the audit judged these correct)
        entry.update(action="keep", how="late_notice_no_older_incident")
    else:
        # only an older row of the same organisation, and no date ties this one to it: more often a new breach
        # (Hasbro 2026 beside Hasbro 2017) than the same one. Kept public, listed for a person in the plan.
        entry.update(action="keep", how="older_row_no_shared_date")
    return entry


def plan(rows: list[dict]) -> dict:
    entries = [decide(r) for r in rows]
    flags = Counter(f for e in entries for f in e["flags"])
    return {
        "method": METHOD,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "applied": False,
        "counts": {
            "press_only_public_rows": len(entries),
            "flag_follow_up": flags["follow_up"],
            "flag_old_year": flags["old_year"],
            "flag_follow_up_or_old_year": sum(1 for e in entries if {"follow_up", "old_year"} & set(e["flags"])),
            "flag_older_same_org": flags["older_same_org"],
            "flagged_any": sum(1 for e in entries if e["flags"]),
            "action": dict(Counter(e["action"] for e in entries)),
            "how": dict(Counter(e["how"] for e in entries if e["how"])),
            "target_structured": sum(1 for e in entries if e.get("target_structured")),
        },
        "rows": [e for e in entries if e["flags"]],
    }


def gather(conn, page: int = 400, text_cap: int = 20000) -> list[dict]:
    """All rows, read in pages inside one READ ONLY transaction (the database serves production)."""
    rows, offset = [], 0
    with conn.transaction(), conn.cursor() as cur:
        cur.execute("set transaction read only")
        cur.execute("set local statement_timeout = '60s'")
        while True:
            cur.execute(GATHER_SQL, {"offset": offset, "limit": page, "text_cap": text_cap})
            cols = [d.name for d in cur.description]
            got = [dict(zip(cols, r)) for r in cur.fetchall()]
            rows += got
            if len(got) < page:
                return rows
            offset += page


def apply(conn, plan_doc: dict, who: str) -> dict:
    """Replay a reviewed plan: possible_duplicate_of only where it is still unset; review rows are added.
    One transaction - all or nothing."""
    from .normalize import norm_name
    n = Counter()
    with conn.transaction(), conn.cursor() as cur:
        for e in plan_doc["rows"]:
            if e["action"] == "possible_duplicate_of":
                cur.execute("""update breach_core.incidents set possible_duplicate_of = %s, updated_at = now()
                                where incident_id = %s and possible_duplicate_of is null""", (e["target"], e["incident_id"]))
                n["possible_duplicate_of"] += cur.rowcount
            elif e["action"] == "review":
                cur.execute("""insert into breach_core.press_review (organization, org_norm, incident_id, doc_kind, kind_reason,
                                                                     reason, coarse_dates, title, published_at)
                               values (%s,%s,%s,%s,%s,%s,%s,%s,%s) on conflict do nothing""",
                            (e["name"][:300], norm_name(e["name"])[:300], e["incident_id"],
                             "follow_up" if "follow_up" in e["flags"] else "incident_report",
                             ",".join(r for r in e["kind_reasons"] if r) or None, "repair:" + "+".join(e["flags"]),
                             e["coarse"], (e["titles"][0] if e["titles"] else None), e["fpd"]))
                n["review"] += cur.rowcount
    return dict(n, applied_by=who)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="zdc-breach-press-repair")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--from-json", nargs="+", help="gathered rows (GATHER_SQL output) instead of DATABASE_URL")
    g.add_argument("--apply", metavar="PLAN", help="replay a reviewed plan file (writes)")
    ap.add_argument("--out", default="press_repair_plan.json")
    ap.add_argument("--applied-by", default=os.environ.get("USER", "manual"))
    a = ap.parse_args(argv)
    if a.apply:
        import psycopg
        doc = json.load(open(a.apply))
        if doc.get("method") != METHOD:
            raise SystemExit(f"plan method {doc.get('method')!r} is not {METHOD!r}")
        with psycopg.connect(os.environ["DATABASE_URL"], autocommit=False) as conn:
            print(json.dumps(apply(conn, doc, a.applied_by), indent=2))
        return 0
    if a.from_json:
        rows = [r for f in a.from_json for r in json.load(open(f))]
    else:
        import psycopg
        with psycopg.connect(os.environ["DATABASE_URL"], autocommit=False) as conn:
            rows = gather(conn)
    out = plan(rows)
    json.dump(out, open(a.out, "w"), indent=1, default=str)
    print(json.dumps(out["counts"], indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
