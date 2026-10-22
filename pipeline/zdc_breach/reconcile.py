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

DATA TYPES (0170): the claim is chosen by breach_core.incident_data_types in SQL - the gate above, OTHER_ORDER,
and within a basis a structured value before a machine-read one - and its items are split_data_types', stored
per claim in claims.value_items when it is filed and refreshed here. The public view reads the same function, so
a claim filed between runs (agent_load) reaches the list on the next list rebuild.

NOT HERE (0137, ADR 0009): which CVEs a breach is linked to. That is breach_core.cve_link_gate, the one
gate, applied by rebuild_cve_links in the list rebuild; incident_facts.cve_ids is no longer written. A
private source (sources.publication = 'private') feeds no fact and counts as no source.
"""

from __future__ import annotations

import re
from collections import defaultdict
from decimal import Decimal

METHOD_VERSION = "breach-facts-v1"

COUNT_ORDER = ["regulator_filing", "victim_statement", "news_citing_victim", "news", "breach_index"]
RANSOM_ORDER = ["victim_statement", "news_citing_victim", "news", "regulator_filing", "threat_actor_claim"]
OTHER_ORDER = ["regulator_filing", "victim_statement", "news_citing_victim", "news", "breach_index",
               "threat_actor_claim"]
QUAL_RANK = {"exact": 0, "approx": 1, "at_least": 2, "at_most": 2, "range": 2,
             "not_applicable": 0, "placeholder": 9}


# ---- data_types: one claim's text -> the items it lists (R2, ruling 2026-10-21) --------------------------
# Delaware's form offers the statute's elements (6 Del. C. 12B-101) as checkboxes, and three of them contain
# commas of their own. Splitting the text on every comma turned one element into four items, two of them junk
# ("access code", "in combination with any required security code") that tagged a card number as Credentials.
# Each element is matched whole, in the spellings and truncations the filings carry; its inner separators are
# masked, and only the separators left over split the list.
_DE_ELEMENTS = [
    re.compile(r"account number\W+credit card account number\W+(?:or\s+)?debit card number"
               r"(?:\W+in combination with any required security code(?:\W+access(?: code)?)?"
               r"(?:\W+or(?: password(?: that would permit access to a financial account)?)?)?)?", re.I),
    re.compile(r"health insurance policy number\W+subscriber ID(?: number)?\W+(?:or\s+)?any other unique "
               r"(?:identifier|ID number) used by health ins(?:urer)?\.? to (?:identify|ID) person", re.I),
    re.compile(r"username or email address,?\s*in combination w(?:i)?th password or security question"
               r"(?:\s+and answer(?: to access online account)?)?", re.I),
]
_MASK = {",": "\x00", ";": "\x01", "\n": "\x02"}    # separators inside an element, restored after the split
_LEAD = re.compile(r"^(?:and/or|and|or)\s+", re.I)
_CONTINUES = re.compile(r"^in combination\b", re.I)
_AND_LABEL = re.compile(r"\s+(?:and|&)\s+(?=[A-Z])")


def split_data_types(text: str | None) -> list[str]:
    """The items a data_types claim lists, split only at top-level separators (comma, semicolon, line break, and
    'and'/'&' before a capitalised label; outside parentheses and outside a statutory element). A leading 'and'/'or' is dropped; a fragment that
    begins 'in combination ...' qualifies the item before it and stays with it. Order kept, duplicates once."""
    s = (text or "").replace("�", " ")
    for rx in _DE_ELEMENTS:
        s = rx.sub(lambda m: m.group(0).translate(str.maketrans(_MASK)), s)
    parts, buf, depth = [], [], 0
    for ch in s:
        if ch in "([":
            depth += 1
        elif ch in ")]" and depth:
            depth -= 1
        if ch in ",;\n" and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    # Delaware's checkbox labels are capitalised, so "Social Security number and Medical history" is two of them;
    # a lower-case "and" ("names and addresses", "question and answer") is left alone.
    parts = [q for p in parts for q in _AND_LABEL.split(p)]
    out: list[str] = []
    for p in parts:
        item = re.sub(r"\s+", " ", p.translate(str.maketrans({v: k for k, v in _MASK.items()}))).strip(" .'\"\t")
        item = _LEAD.sub("", item).strip()
        if sum(c.isalpha() for c in item) < 2:
            continue
        if out and _CONTINUES.match(item):
            out[-1] = f"{out[-1]}, {item}"
            continue
        out.append(item)
    seen: set[str] = set()
    return [x for x in out if not (x in seen or seen.add(x))]


def refresh_value_items(cur) -> int:
    """claims.value_items := split_data_types(value_text) for every data_types claim where it differs (0170).
    Filing writes it (resolve.add_claim, Resolver.claim); this catches every other writer and any change to the
    split rules, and runs before the facts and the list are rebuilt. One pipelined batch."""
    cur.execute("select claim_id, value_text, value_items from breach_core.claims where field = 'data_types'")
    todo = []
    for cid, text, have in cur.fetchall():
        items = split_data_types(text)
        if have is None or items != have:
            todo.append((items, cid))
    if todo:
        with cur.connection.pipeline():
            cur.executemany("update breach_core.claims set value_items = %s where claim_id = %s", todo)
    return len(todo)


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
    """The chosen count, the range ACROSS SOURCES and whether they disagree.

    A range is only ever between sources. Two values from one source (two Delaware notices
    filed the same day) are not a disagreement between sources - an earlier version printed
    "sources differ: 6,083-1,185,755" for exactly that (advisor review 2, 2026-10-14). The
    page reads people_n_sources to say which it is."""
    best = choose(claims, COUNT_ORDER)
    if not best:
        return None
    comparable = [c for c in claims if c["value_num"] is not None and c["qualifier"] in ("exact", "approx")]
    values = [Decimal(c["value_num"]) for c in comparable]
    lo, hi = (min(values), max(values)) if values else (None, None)
    n = len({c["source_id"] for c in comparable})
    disagree = bool(n > 1 and lo and hi and hi > lo * Decimal("1.10"))
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
                      -- a private source's claims are kept for evaluation, never published (0137)
                      and c.source_id not in (select source_id from breach_core.private_sources)
                      -- machine-extracted facts count only from an extractor version that
                      -- passed its gold-set check and was activated
                      -- (0104) a person's confirmation also counts; a rejection never does
                      and coalesce(c.review_verdict, '') <> 'rejected'
                      and (c.extraction_id is null or c.review_verdict = 'confirmed'
                           or (v.active and c.field = any(v.active_fields)))
                    order by c.incident_id, c.field, c.claim_id""")
    cols = [d.name for d in cur.description]
    by = defaultdict(lambda: defaultdict(list))
    for row in cur.fetchall():
        c = dict(zip(cols, row))
        by[c["incident_id"]][c["field"]].append(c)
    cur.execute("""select s.incident_id, count(distinct s.source_id) from breach_core.incident_sources s
                     join breach_core.incidents i using (incident_id)
                    where not i.suppressed and s.source_id not in (select source_id from breach_core.private_sources)
                    group by 1""")
    nsrc = dict(cur.fetchall())
    refresh_value_items(cur)
    # Data types: the CLAIM is chosen in SQL (breach_core.incident_data_types, 0170) - the same gate and order
    # public.breach_incidents applies at list time - and its items are split_data_types' (claims.value_items),
    # so incident_facts and the public view cannot disagree, and a claim filed between runs reaches the list on
    # the next rebuild_victims_list(), not the next run.
    cur.execute("""select i.incident_id, breach_core.incident_data_types(i.incident_id)
                     from breach_core.incidents i
                    where not i.suppressed
                      and exists (select 1 from breach_core.claims c
                                   where c.incident_id = i.incident_id and c.field = 'data_types')""")
    dtypes = {i: d for i, d in cur.fetchall() if d is not None}

    cur.execute("delete from breach_core.incident_facts")
    n = 0
    rows: list[dict] = []
    for inc in sorted(set(by) | set(nsrc) | set(dtypes), key=str):
        f = by.get(inc, {})
        row = {"incident_id": inc, "n_sources": nsrc.get(inc, 0), "method_version": METHOD_VERSION,
               "has_disagreement": False}
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
        if inc in dtypes:
            row["data_types"] = dtypes[inc]
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
