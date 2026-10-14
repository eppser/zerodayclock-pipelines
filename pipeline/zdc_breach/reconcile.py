"""Build breach_core.incident_facts: one value per incident and field, chosen by rule.

PRECEDENCE IS PER FIELD (migration 0101, rule 3):
- counts (persons, records, accounts, bytes): regulator_filing > victim_statement >
  news_citing_victim > news > breach_index. A threat actor never supplies a count (the
  claims table refuses it).
- ransom: victim_statement > news_citing_victim > news > regulator_filing > threat_actor_claim.
- vector, actor, everything else: regulator_filing > victim_statement > news_citing_victim >
  news > breach_index > threat_actor_claim.
Within a basis: exact > approx > at_least/at_most > placeholder, then the latest as_of.

NEVER AVERAGED. When accepted, comparable claims for a count differ by more than 10%, the
chosen value stands, the range is kept (min/max) and has_disagreement is set: the page shows
the range and says sources differ.

DETERMINISTIC. Same claims in, byte-identical facts out: every choice is ordered by stable keys,
ties broken by claim_id.
"""

from __future__ import annotations

from collections import defaultdict
from decimal import Decimal

METHOD_VERSION = "breach-facts-v1"

COUNT_ORDER = ["regulator_filing", "victim_statement", "news_citing_victim", "news", "breach_index"]
RANSOM_ORDER = ["victim_statement", "news_citing_victim", "news", "regulator_filing", "threat_actor_claim"]
OTHER_ORDER = ["regulator_filing", "victim_statement", "news_citing_victim", "news", "breach_index",
               "threat_actor_claim"]
QUAL_RANK = {"exact": 0, "approx": 1, "at_least": 2, "at_most": 2, "range": 2,
             "not_applicable": 0, "placeholder": 9}


def _rank(order):
    def key(c):
        return (order.index(c["basis"]) if c["basis"] in order else 99,
                QUAL_RANK.get(c["qualifier"], 5),
                # latest as_of first
                -c["as_of"].toordinal(),
                str(c["claim_id"]))
    return key


def choose(claims, order):
    cands = [c for c in claims if c["basis"] in order]
    return sorted(cands, key=_rank(order))[0] if cands else None


def _count(claims):
    best = choose(claims, COUNT_ORDER)
    if not best:
        return None
    comparable = [Decimal(c["value_num"]) for c in claims
                  if c["value_num"] is not None and c["qualifier"] in ("exact", "approx")]
    lo, hi = (min(comparable), max(comparable)) if comparable else (None, None)
    disagree = bool(lo and hi and hi > lo * Decimal("1.10"))
    n = len({c["source_id"] for c in claims})
    return best, lo, hi, disagree, n


def build(cur) -> int:
    cur.execute("""select c.claim_id, c.incident_id, c.field, c.value_num, c.value_text, c.unit::text,
                          c.qualifier::text, c.basis::text, c.as_of, c.source_id, c.money_kind::text,
                          c.currency, c.amount_usd, c.value_num as original
                     from breach_core.claims c
                     join breach_core.incidents i using (incident_id)
                     left join breach_core.extractions e using (extraction_id)
                     left join breach_core.extractor_versions v using (extractor_id)
                    where c.accepted and c.superseded_by is null and not i.suppressed
                      -- machine-extracted facts count only from an extractor version that
                      -- passed its gold-set check and was activated
                      and (c.extraction_id is null or (v.active and c.field = any(v.active_fields)))
                    order by c.incident_id, c.field, c.claim_id""")
    cols = [d.name for d in cur.description]
    by = defaultdict(lambda: defaultdict(list))
    for row in cur.fetchall():
        c = dict(zip(cols, row))
        by[c["incident_id"]][c["field"]].append(c)
    # A CVE counts only if an accepted claim from a rule or an ACTIVE extractor backs it - the
    # same gate as every other fact (an integration test caught incident_cves bypassing it).
    cur.execute("""select ic.incident_id, array_agg(distinct ic.cve_id order by ic.cve_id)
                     from breach_core.incident_cves ic
                    where ic.role <> 'mentioned'
                      and exists (select 1 from breach_core.claims c
                                    left join breach_core.extractions e using (extraction_id)
                                    left join breach_core.extractor_versions v using (extractor_id)
                                   where c.incident_id = ic.incident_id and c.field = 'cve_id'
                                     and upper(c.value_text) = ic.cve_id and c.accepted
                                     and c.superseded_by is null
                                     and (c.extraction_id is null or (v.active and 'cve_id' = any(v.active_fields))))
                    group by 1""")
    cves = dict(cur.fetchall())
    cur.execute("""select s.incident_id, count(distinct s.source_id) from breach_core.incident_sources s
                     join breach_core.incidents i using (incident_id) where not i.suppressed group by 1""")
    nsrc = dict(cur.fetchall())

    cur.execute("delete from breach_core.incident_facts")
    n = 0
    rows: list[dict] = []
    for inc in sorted(set(by) | set(nsrc), key=str):
        f = by.get(inc, {})
        row = {"incident_id": inc, "n_sources": nsrc.get(inc, 0), "method_version": METHOD_VERSION,
               "has_disagreement": False, "cve_ids": cves.get(inc)}
        for field, prefix in (("people_affected", "people"), ("records_affected", "records"),
                              ("accounts_affected", "accounts"), ("data_bytes", "data_bytes")):
            r = _count(f.get(field, []))
            if not r:
                continue
            best, lo, hi, dis, k = r
            col = {"people": "people_affected", "records": "records_affected",
                   "accounts": "accounts_affected", "data_bytes": "data_bytes"}[prefix]
            row[col] = best["value_num"]
            row[f"{prefix}_qualifier"] = best["qualifier"]
            row[f"{prefix}_basis"] = best["basis"]
            if prefix == "people":
                row.update(people_min=lo, people_max=hi, people_n_sources=k)
            row["has_disagreement"] |= dis
        dt = choose(f.get("data_types", []), OTHER_ORDER)
        if dt:
            row["data_types"] = sorted({t.strip() for t in dt["value_text"].split(",") if t.strip()})
        for field, col in (("vector", "vector"), ("actor", "actor")):
            best = choose(f.get(field, []), OTHER_ORDER)
            if best:
                row[col], row[f"{col}_basis"] = best["value_text"], best["basis"]
                tops = {c["value_text"] for c in f[field] if c["basis"] == best["basis"]}
                row["has_disagreement"] |= len(tops) > 1
        demands = [c for c in f.get("ransom_demand_amount", []) if c["amount_usd"] is not None]
        best = choose(demands, RANSOM_ORDER)
        if best:
            row["ransom_demand_usd"] = best["amount_usd"]
            row["ransom_demand_original"] = f"{best['currency']} {Decimal(best['value_num']):,.0f}"
            row["ransom_demand_basis"] = best["basis"]
        paid = choose(f.get("ransom_paid", []), RANSOM_ORDER)
        if paid:
            row["ransom_paid"] = (paid["value_text"] or "").lower() == "true"
            row["ransom_paid_basis"] = paid["basis"]
        dtext = choose(f.get("demand_text", []), RANSOM_ORDER)
        if dtext:
            row["demand_text"] = dtext["value_text"][:600]
        rows.append(row)
        n += 1
    # One pipelined batch with a fixed column list: one insert per incident cost ~7 minutes
    # from a runner ~100 ms from the database (4,500 incidents, measured 2026-10-14).
    if rows:
        cols = sorted({k for r in rows for k in r})
        with cur.connection.pipeline():
            cur.executemany(f"insert into breach_core.incident_facts ({', '.join(cols)}) "
                            f"values ({', '.join(['%s'] * len(cols))})",
                            [[r.get(c, False if c == "has_disagreement" else None) for c in cols] for r in rows])
    return n
