"""Record linkage in the hourly breach run: score, cluster and store, for the ACTIVE method only.

ADR 0008, migration 0134. The scoring code is linkage.py, unchanged from the frozen method
(breach-linkage-v1); this module only reads the tables, calls it and writes the result.

- Nothing happens unless breach_core.link_methods has an active row with a non-empty
  active_classes. Rollback is the flag (active = false, or active_classes = '{}'): every incident
  is then its own cluster again for the list, and nothing is deleted.
- The method row pins the code: code_sha must be a prefix of linkage.py's sha256, or the run
  refuses (a changed scorer is a new method version, never a silent edit).
- Clusters are built from auto links in the ACTIVE classes only. An auto link in another class
  (reg_reg, which failed its hold-out gate) is stored as review_pending with reason
  "class_not_active" and takes no part in clustering; legacy possible_duplicate_of keeps governing
  those rows in the list (0118's filter is untouched).
- One read of the tables (plain column-list selects), scoring in memory (no similarity function in
  SQL), then delete-then-insert in batches. Every statement runs under statement_timeout and
  lock_timeout. Deterministic: same tables, same rows written in the same order.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from . import linkage as L

BATCH = 1000
STATEMENT_TIMEOUT = "60s"
LOCK_TIMEOUT = "5s"

_READS = {
    "organizations": "select org_id, display_name, norm_name, domain, country, sector, sec_cik, alias_norms, "
                     "is_natural_person from breach_core.organizations",
    # an incident only private sources know (0137) never enters a block: a cluster joining it to a public
    # incident would publish the merge once the linked list goes public (review 2026-10-20, s10)
    "incidents": "select incident_id, org_id, event_date, first_public_date, possible_duplicate_of, suppressed "
                 "from breach_core.incidents "
                 "where incident_id not in (select incident_id from breach_core.private_only_incidents)",
    "incident_sources": "select incident_id, source_id, doc_sha256 from breach_core.incident_sources",
    "claims": "select incident_id, field, value_num, qualifier, accepted, superseded_by, review_verdict "
              "from breach_core.claims where field = 'people_affected'",
    "documents": "select doc_sha256, title from breach_raw.documents",
    "actor_aliases": "select alias_norm, actor_id from breach_core.actor_aliases",
    "actor_claims": "select incident_id, value_text from breach_core.claims where field = 'actor' and accepted "
                    "and superseded_by is null and coalesce(review_verdict, '') <> 'rejected'",
    "leak_claims": "select incident_id, actor_group from breach_core.leak_claims where incident_id is not null",
}


def code_sha256() -> str:
    return hashlib.sha256(Path(L.__file__).read_bytes()).hexdigest()


def active_method(cur) -> dict | None:
    cur.execute("""select method_version, m_table, u_table, thresholds, code_sha, active_classes
                     from breach_core.link_methods where active""")
    row = cur.fetchone()
    if not row:
        return None
    mv, m, u, th, sha, classes = row
    return {"method_version": mv, "m": m, "u": u, "thresholds": th, "code_sha": sha,
            "active_classes": sorted(classes or [])}


def _read(cur) -> dict:
    out = {}
    for name, sql in _READS.items():
        cur.execute(sql)
        cols = [d.name for d in cur.description]
        out[name] = [dict(zip(cols, r)) for r in cur.fetchall()]
    return out


def _decisions(cur) -> dict:
    cur.execute("select incident_a::text, incident_b::text, verdict from breach_core.link_decisions")
    return {(a, b): v for a, b, v in cur.fetchall()}


def compute(tables: dict, method: dict, decisions: dict | None = None) -> dict:
    """Pure: score and cluster. Returns the rows to write plus the checks the evals report."""
    actors = ({"aliases": tables["actor_aliases"], "claims": tables.get("actor_claims") or [],
               "leak_claims": tables.get("leak_claims") or []} if tables.get("actor_aliases") is not None else None)
    recs = L.build_records(tables["organizations"], tables["incidents"], tables["incident_sources"],
                           tables["claims"], tables.get("documents"), actors)
    idf = L.build_idf(recs)
    by = {r.iid: r for r in recs}
    th = method["thresholds"]
    model = L.Model({k: v for k, v in method["m"].items() if not k.startswith("_")},
                    {k: v for k, v in method["u"].items() if not k.startswith("_")}, idf, th["prior"],
                    name=method["method_version"], auto=th["auto"], review=th["review"],
                    auto_classes=th["model_auto_classes"])
    active = set(method["active_classes"])
    cand, _, _ = L.block(recs, idf)
    scored, inactive = {}, set()
    for (a, b), keys in cand.items():
        s = model.score(by[a], by[b])
        s["block_keys"] = keys
        if s["band"] == "auto" and s["pair_class"] not in active:
            inactive.add((a, b))
            s = dict(s, band="review")       # no edge in clustering; still >= review for complete linkage
        scored[(a, b)] = s
    cluster_of, notes = L.cluster(recs, scored, model, decisions or {}, review=model.review)
    links = []
    for (a, b), s in sorted(scored.items()):
        # 0133's CHECK allows no decision for a pair below review, so the store holds the auto and
        # review bands and every cannot-link (the rest are recomputed each run and decide nothing).
        if s["band"] == "none" and not s["cannot"] and (a, b) not in inactive:
            continue
        if s["cannot"]:
            decision, reason = "cannot_link", ",".join(s["cannot"])
        elif (a, b) in inactive:
            decision, reason = "review_pending", "class_not_active"
        else:
            decision, reason = L.decision_of(s, notes.get((a, b))), notes.get((a, b))
        band = "auto" if (a, b) in inactive else s["band"]     # the model's band, as scored
        links.append((a, b, s["block_keys"],
                      json.dumps({"levels": s["levels"], "raw": s["raw"], "pair_class": s["pair_class"],
                                  "cap_reasons": s["cap_reasons"], "legacy": s["legacy"]}, sort_keys=True),
                      json.dumps({k: round(v, 6) for k, v in s["weights"].items()}, sort_keys=True),
                      round(s["match_weight"], 6), round(s["probability"], 6), band, decision, reason))
    clusters = [(i, cluster_of[i]) for i in sorted(cluster_of)]
    members: dict = {}
    for i, c in clusters:
        members.setdefault(c, []).append(i)
    multi = {c: ms for c, ms in members.items() if len(ms) > 1}
    cross = sorted(c for c, ms in multi.items()
                   if len({by[i].domain for i in ms} - {None}) > 1 or len({by[i].cik for i in ms} - {None}) > 1)
    return {"links": links, "clusters": clusters,
            "checks": {"incidents": len(recs), "candidate_pairs": len(cand), "links_stored": len(links),
                       "auto_links": sum(1 for x in links if x[8] == "auto_link"),
                       "inactive_class_auto": len(inactive), "clusters_multi": len(multi),
                       "rows_hidden": sum(len(ms) - 1 for ms in multi.values()),
                       "max_cluster": max((len(ms) for ms in members.values()), default=0),
                       "clusters_across_domain_or_cik": len(cross)}}


def _batched(cur, sql: str, rows: list) -> None:
    for i in range(0, len(rows), BATCH):
        cur.executemany(sql, rows[i:i + BATCH])


def refresh(cur) -> dict:
    """Score, cluster and store for the active method. Runs inside the caller's transaction."""
    method = active_method(cur)
    if not method or not method["active_classes"]:
        return {"active": False}
    sha = code_sha256()
    if not sha.startswith(method["code_sha"]):
        raise RuntimeError(f"linkage.py sha256 {sha[:12]} does not match the active method's code_sha "
                           f"{method['code_sha'][:12]}: a changed scorer is a new method version")
    cur.execute(f"set local statement_timeout = '{STATEMENT_TIMEOUT}'")
    cur.execute(f"set local lock_timeout = '{LOCK_TIMEOUT}'")
    out = compute(_read(cur), method, _decisions(cur))
    mv = method["method_version"]
    cur.execute("delete from breach_core.incident_clusters where method_version = %s", (mv,))
    cur.execute("delete from breach_core.incident_links where method_version = %s", (mv,))
    _batched(cur, """insert into breach_core.incident_links
                         (incident_a, incident_b, method_version, block_keys, features, weights, match_weight,
                          probability, band, decision, reason)
                     values (%s, %s, %s, %s, %s::jsonb, %s::jsonb, %s, %s, %s, %s, %s)""",
             [(a, b, mv, k, f, w, mw, p, band, d, r) for a, b, k, f, w, mw, p, band, d, r in out["links"]])
    _batched(cur, "insert into breach_core.incident_clusters (incident_id, cluster_id, method_version) values (%s, %s, %s)",
             [(i, c, mv) for i, c in out["clusters"]])
    return {"active": True, "method_version": mv, "active_classes": method["active_classes"], **out["checks"]}
