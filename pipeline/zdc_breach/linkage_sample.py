"""The labelling sample for breach record linkage (design s3, step 3 preparation).

Redrawn 2026-10-19 on the advisor's ruling (the first draw was never labelled or viewed).
Every pair falls in exactly ONE stratum, by this precedence:

  census:<class>   every pair of the rare source-pair classes (hibp_hibp, hibp_press, reg_hibp,
                   sec_any) - inclusion probability 1
  domain_diff      name exact / contain / link_key but the domains differ - all, up to 60
  conflict         cannot-link on conflicting distinctive tokens - >= 60 hold-out / >= 100 dev
  legacy_amexdisc  B6-only pairs and possible_duplicate_of edges of American Express / Discover
  legacy           every other B6-only pair or possible_duplicate_of edge - >= 50 / >= 80 together
  main:b:c:ja      the rest, by provisional score band x class x Japanese, bands near 0.5 and
                   the high bands oversampled

The split is BY BLOCK GROUP (union of B2/B3 keys; otherwise the pair's own keys, with the
legacy edge key replaced by its organisation so it does not chain every legacy pair together).
Each group goes wholly to the hold-out pool (p = 1/3) or the dev pool; the hold-out is drawn
first. At most GROUP_CAP pairs per group per split, outside the census: an excess draw is skipped
and the next one in the stratum's random order taken ("Hugging Face" and "Jaguar Land Rover"
would otherwise be 33 and 28 pairs of one story). pairs_meta.jsonl carries the stratum, its
pool population and draw, the weight N/n (approximate where the cap skipped draws: cap_skipped)
and the group, for Horvitz-Thompson estimates and a group bootstrap.

The label files carry ONLY raw records: names, aliases, domain, country, sector, the regulators'
own fields (state, dates, entity type, the Delaware notice), sources with links, and the date
and count claims. No score, band, level, block key or stratum.

Deterministic: same snapshot, same run, same seed -> byte-identical files.
"""

from __future__ import annotations

import hashlib
import json
import random
from collections import Counter, defaultdict
from pathlib import Path

from . import linkage as L

SEED = 20261020                    # redraw seed; the first draw (20261019) was discarded unviewed
HOLDOUT_SHARE = 1 / 3
GROUP_CAP = 8
MIN_PER_CLASS = 30
MIN_JA = 30
CENSUS_CLASSES = ("hibp_hibp", "hibp_press", "reg_hibp", "sec_any")
DOMAIN_DIFF_MAX = 60
TARGETS = {"conflict": (60, 100), "legacy_amexdisc": (8, 10), "legacy": (50, 80)}   # (hold-out, dev)
# Main bands (linkage.BAND_EDGES): near 0.5 (4, 5) and high (7, 8, 9) oversampled; 900 in all.
BAND_TARGET = {0: 45, 1: 50, 2: 65, 3: 85, 4: 115, 5: 115, 6: 95, 7: 105, 8: 110, 9: 115}
BAND_PRIORITY = (4, 5, 8, 9, 7, 6, 3, 2, 1, 0)
SEED_TARGET = {"reg": 90, "press": 50, "hibp": 20, "sec": 10, "ja": 30}
AMEX_DISCOVER = ("american express", "discover financial")

REG_URL = {"wa_ag": "https://www.atg.wa.gov/data-breach-notifications",
           "ca_ag": "https://oag.ca.gov/privacy/databreach/list",
           "de_ag": "https://data.delaware.gov/d/dir6-wx8v",
           "hhs_ocr": "https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf"}
REGULATOR_FIELDS = {
    "hhs_ocr": ("state", "entity_type", "type_of_breach", "location", "business_associate_present", "submitted"),
    "wa_ag": ("entitystate", "businesstype", "industrytype", "datestart", "dateend", "dateaware", "datesubmitted"),
    "de_ag": ("date_of_breach", "breach_discovered", "date_of_notice"),
    "ca_ag": ("Date(s) of Breach  (if known)", "Reported Date"),
    "sec_8k": ("biz_states", "period_ending", "file_date", "sics"),
}
SALT = "zdc-breach-linkage-v1-pair"


def pair_id(a: str, b: str) -> str:
    return hashlib.sha256(f"{SALT}|{a}|{b}".encode()).hexdigest()[:16]


def _jl(path: Path):
    return [json.loads(x) for x in path.open()]


def _states(srcs) -> list:
    out = set()
    for sr in srcs:
        f = sr.get("regulator_fields") or {}
        for k in ("state", "entitystate", "biz_states"):
            v = f.get(k)
            for x in (v if isinstance(v, list) else [v]):
                if x:
                    out.add(str(x))
    return sorted(out)


class Records:
    """Raw display records for the labellers, from the snapshot only."""

    def __init__(self, snap_dir: Path):
        self.org = {o["org_id"]: o for o in _jl(snap_dir / "organizations.jsonl")}
        self.inc = {i["incident_id"]: i for i in _jl(snap_dir / "incidents.jsonl")}
        self.src = defaultdict(list)
        for s in _jl(snap_dir / "incident_sources.jsonl"):
            self.src[s["incident_id"]].append(s)
        self.claims = defaultdict(list)
        for c in _jl(snap_dir / "claims.jsonl"):
            if c["accepted"] and not c["superseded_by"] and (c["review_verdict"] or "") != "rejected":
                self.claims[c["incident_id"]].append(c)
        self.docs = {d["doc_sha256"]: d for d in _jl(snap_dir / "documents.jsonl")} \
            if (snap_dir / "documents.jsonl").exists() else {}
        self.sources = {s["source_id"]: s for s in _jl(snap_dir / "sources.jsonl")} \
            if (snap_dir / "sources.jsonl").exists() else {}
        self.raw = {}                      # latest version of each regulator source record
        if (snap_dir / "source_records.jsonl").exists():
            for r in _jl(snap_dir / "source_records.jsonl"):
                k = (r["source_id"], r["source_record_id"])
                if k not in self.raw or r["version"] > self.raw[k]["version"]:
                    self.raw[k] = r

    def _regulator(self, s) -> dict | None:
        """The regulator's own fields, as filed: state / address, dates and type. Never a score."""
        r = (self.raw.get((s["source_id"], s["source_record_id"])) or {}).get("record")
        if not r:
            return None
        keep = REGULATOR_FIELDS.get(s["source_id"], ())
        out = {k: r.get(k) for k in keep if r.get(k) not in (None, "", [])}
        if s["source_id"] == "de_ag" and isinstance(r.get("sample_of_notice"), dict):
            out["notice_pdf"] = r["sample_of_notice"].get("url")
        return out or None

    def _url(self, s, org):
        sid = s["source_id"]
        if sid == "de_ag":
            pdf = (self._regulator(s) or {}).get("notice_pdf")
            return pdf or REG_URL[sid], None
        if sid in REG_URL:
            return REG_URL[sid], None
        if sid == "hibp":
            return f"https://haveibeenpwned.com/Breach/{s['source_record_id']}", None
        if sid == "sec_8k" and org.get("sec_cik"):
            return f"https://www.sec.gov/Archives/edgar/data/{org['sec_cik']}/{s['source_record_id'].replace('-', '')}/", None
        d = self.docs.get(s["doc_sha256"][:64])     # press rows store "<sha256>:<victim>"
        return (d["url"], d.get("title")) if d else (None, None)

    def record(self, iid: str) -> dict:
        i = self.inc[iid]
        o = self.org[i["org_id"]]
        srcs = []
        for s in sorted(self.src[iid], key=lambda s: (s["source_id"], s["source_record_id"], s["doc_sha256"])):
            url, title = self._url(s, o)
            srcs.append({"source_id": s["source_id"],
                         "source": (self.sources.get(s["source_id"]) or {}).get("display_name", s["source_id"]),
                         "record": s["source_record_id"] or None, "url": url, "title": title,
                         "seen": (self.docs.get(s["doc_sha256"][:64]) or {}).get("published_at"),
                         "regulator_fields": self._regulator(s)})
        states = _states(srcs)
        only_sec = bool(srcs) and all(s["source_id"] == "sec_8k" for s in srcs)
        claims = [{"field": c["field"], "value": c["value_num"] if c["value_num"] is not None else c["value_text"],
                   "unit": c["unit"], "qualifier": c["qualifier"], "basis": c["basis"], "source_id": c["source_id"],
                   "as_of": c["as_of"], "machine_extracted": c["extraction_id"] is not None}
                  for c in sorted(self.claims[iid], key=lambda c: (c["field"], c["source_id"], c["as_of"], c["claim_id"]))]
        return {"incident_id": iid, "organization": o["display_name"], "aliases": o.get("aliases") or [],
                "domain": o.get("domain"), "country": o.get("country"), "sector": o.get("sector"),
                "sec_cik": o.get("sec_cik"), "first_public_date": i["first_public_date"],
                "event_date": i["event_date"],
                "event_date_note": ("SEC 8-K period_ending: the date of report, not the breach date"
                                    if only_sec and i["event_date"] else None),
                "regulator_states": states, "sources": srcs, "claims": claims}


def _groups(pairs, org_of):
    """Union-find over B2/B3 block keys; a pair with neither is grouped by its own keys, the
    shared legacy-edge key replaced by the pair's organisation."""
    par: dict = {}

    def f(x):
        while par.setdefault(x, x) != x:
            par[x] = par[par[x]]
            x = par[x]
        return x
    keys = {}
    for p in pairs:
        ks = [k for k in p["block_keys"] if k.split(":")[0] in ("B2", "B3")]
        if not ks:
            ks = sorted({f"B6:{org_of[p['a']]}" if k == "B6:possible_duplicate_of" else k for k in p["block_keys"]})
        keys[(p["a"], p["b"])] = ks
        r = f(ks[0])
        for k in ks[1:]:
            par[f(k)] = r
    return {k: f(v[0]) for k, v in keys.items()}


def _class(pc: str) -> str:
    return pc if pc in ("reg_reg", "reg_hibp", "reg_press", "press_press", "sec_any", "hibp_press", "hibp_hibp") else "other"


def stratum_of(p, amexdisc: set) -> str:
    c = _class(p["pair_class"])
    if c in CENSUS_CLASSES:
        return f"census:{c}"
    if p["levels"]["name"] in ("exact", "contain", "linkkey") and p["levels"]["domain"] == "different":
        return "domain_diff"
    if "distinctive_tokens_conflict" in p["cannot"]:
        return "conflict"
    legacy = all(k.startswith("B6:") for k in p["block_keys"]) or "B6:possible_duplicate_of" in p["block_keys"]
    if legacy:
        return "legacy_amexdisc" if (p["a"] in amexdisc or p["b"] in amexdisc) else "legacy"
    return "main"


def _largest_remainder(total: int, weights: dict, caps: dict) -> dict:
    out = {k: 0 for k in weights}
    left = total
    while left > 0:
        live = {k: w for k, w in weights.items() if out[k] < caps[k] and w > 0}
        if not live:
            break
        s = sum(live.values())
        exact = {k: left * w / s for k, w in live.items()}
        add = {k: min(int(x), caps[k] - out[k]) for k, x in exact.items()}
        if not sum(add.values()):
            k = max(live, key=lambda k: (exact[k] - int(exact[k]), str(k)))
            add = {k: 1}
        for k, n in add.items():
            out[k] += n
            left -= n
    return out


def allocate(N: dict, band_target: dict) -> dict:
    """N[(band, class, ja)] -> n to draw overall. Band targets, proportional within band, then the
    class and Japanese minimums topped up in band-priority order."""
    alloc = {h: 0 for h in N}
    spare = 0
    for b in BAND_PRIORITY[::-1]:
        hs = {h: N[h] for h in N if h[0] == b}
        avail = sum(hs.values())
        want = band_target.get(b, 0)
        if avail <= want:
            for h in hs:
                alloc[h] = N[h]
            spare += want - avail
            continue
        got = _largest_remainder(want, hs, hs)
        alloc.update(got)
    for b in BAND_PRIORITY:                         # spare capacity to the priority bands
        if spare <= 0:
            break
        hs = {h: N[h] - alloc[h] for h in N if h[0] == b and N[h] > alloc[h]}
        if not hs:
            continue
        got = _largest_remainder(min(spare, sum(hs.values())), hs, hs)
        for h, n in got.items():
            alloc[h] += n
            spare -= n

    def top_up(pred, minimum):
        have = sum(n for h, n in alloc.items() if pred(h))
        while have < minimum:
            moved = False
            for b in BAND_PRIORITY:
                for h in sorted(x for x in N if x[0] == b and pred(x)):
                    if alloc[h] < N[h] and have < minimum:
                        alloc[h] += 1
                        have += 1
                        moved = True
            if not moved:
                break
    for c in sorted({h[1] for h in N}):
        top_up(lambda h, c=c: h[1] == c, MIN_PER_CLASS)
    top_up(lambda h: h[2], MIN_JA)
    return alloc


def sample(snapshot: str | Path, run_dir: str | Path, out: str | Path, seed: int = SEED) -> dict:
    snapshot, run_dir, out = Path(snapshot), Path(run_dir), Path(out)
    out.mkdir(parents=True, exist_ok=True)
    rec = Records(snapshot)
    pairs = _jl(run_dir / "pairs.jsonl")
    cjk = {iid: L.has_cjk(rec.org[i["org_id"]]["display_name"]) for iid, i in rec.inc.items()}
    org_of = {iid: i["org_id"] for iid, i in rec.inc.items()}
    amexdisc = {iid for iid, i in rec.inc.items()
                if rec.org[i["org_id"]]["norm_name"].startswith(AMEX_DISCOVER)}
    group = _groups(pairs, org_of)
    rnd = random.Random(seed)
    hold_groups = {g for g in sorted(set(group.values())) if rnd.random() < HOLDOUT_SHARE}
    pools: dict = defaultdict(lambda: {"hold": [], "dev": []})
    for p in sorted(pairs, key=lambda p: (p["a"], p["b"])):
        p["_group"] = group[(p["a"], p["b"])]
        st = stratum_of(p, amexdisc)
        if st == "main":
            st = f"main:{L.band_index(p['p'])}:{_class(p['pair_class'])}:{int(bool(cjk[p['a']] or cjk[p['b']]))}"
        p["_stratum"] = st
        pools[st]["hold" if p["_group"] in hold_groups else "dev"].append(p)

    # How many to draw per stratum and pool.
    take: dict = {}
    for st, v in pools.items():
        if st.startswith("census:"):
            take[st] = [len(v["hold"]), len(v["dev"])]
        elif st == "domain_diff":
            n = min(DOMAIN_DIFF_MAX, len(v["hold"]) + len(v["dev"]))
            th = min(len(v["hold"]), round(n * len(v["hold"]) / max(1, len(v["hold"]) + len(v["dev"]))))
            take[st] = [th, min(len(v["dev"]), n - th)]
        elif st in TARGETS:
            take[st] = [min(TARGETS[st][0], len(v["hold"])), min(TARGETS[st][1], len(v["dev"]))]
    main = {st: len(v["hold"]) + len(v["dev"]) for st, v in pools.items() if st.startswith("main:")}
    keyed = {tuple(int(x) if x.isdigit() else x for x in st.split(":")[1:]): st for st in main}
    alloc = allocate({h: main[st] for h, st in keyed.items()}, BAND_TARGET)
    for h, st in keyed.items():
        nh, cap_h, cap_d = alloc[h], len(pools[st]["hold"]), len(pools[st]["dev"])
        th = min(round(nh * HOLDOUT_SHARE), cap_h)
        td = min(nh - th, cap_d)
        take[st] = [min(nh - td, cap_h), td]

    order = sorted(pools, key=lambda st: (0 if st.startswith("census:") else 1 if st == "domain_diff" else
                                          2 if st == "conflict" else 3 if st == "legacy_amexdisc" else
                                          4 if st == "legacy" else 5, st))
    chosen = {"hold": [], "dev": []}
    meta = []
    for pool, idx in (("hold", 0), ("dev", 1)):         # the hold-out is drawn first
        per_group = Counter()
        for st in order:
            cand = list(pools[st][pool])
            rnd.shuffle(cand)
            want, got, skipped = take.get(st, [0, 0])[idx], [], 0
            census = st.startswith("census:")
            for p in cand:
                if len(got) >= want:
                    break
                if not census and per_group[p["_group"]] >= GROUP_CAP:
                    skipped += 1
                    continue
                got.append(p)
                per_group[p["_group"]] += 1
            for p in got:
                chosen[pool].append(p)
                meta.append({"pair_id": pair_id(p["a"], p["b"]), "split": "holdout" if pool == "hold" else "dev",
                             "a": p["a"], "b": p["b"], "stratum": st, "band": L.band_index(p["p"]),
                             "pair_class": _class(p["pair_class"]), "ja": bool(cjk[p["a"]] or cjk[p["b"]]),
                             "p_provisional": p["p"], "block_keys": p["block_keys"], "group": p["_group"],
                             "N_h_pool": len(pools[st][pool]), "n_h_pool": len(got),
                             "weight": len(pools[st][pool]) / len(got), "cap_skipped": skipped,
                             "pool_share": HOLDOUT_SHARE if pool == "hold" else 1 - HOLDOUT_SHARE})
    hold_g = {p["_group"] for p in chosen["hold"]}
    dev_g = {p["_group"] for p in chosen["dev"]}
    assert not (hold_g & dev_g), "a block group is in both splits"

    def write(path: Path, items):
        rows = sorted(({"pair_id": pair_id(p["a"], p["b"]), "a": rec.record(p["a"]), "b": rec.record(p["b"])}
                       for p in items), key=lambda r: r["pair_id"])
        with path.open("w") as f:
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")
    write(out / "holdout_pairs.jsonl", chosen["hold"])
    write(out / "dev_pairs.jsonl", chosen["dev"])
    holdout_sha = hashlib.sha256((out / "holdout_pairs.jsonl").read_bytes()).hexdigest()
    (out / "HOLDOUT.sha256").write_text(f"{holdout_sha}  holdout_pairs.jsonl\n")
    with (out / "pairs_meta.jsonl").open("w") as f:
        for m in sorted(meta, key=lambda m: (m["split"], m["pair_id"])):
            f.write(json.dumps(m, sort_keys=True) + "\n")
    # Seeds: incidents stratified by class (Japanese-named separately), drawn from all incidents.
    by_cls = defaultdict(list)
    for iid in sorted(rec.inc):
        if rec.inc[iid]["suppressed"]:
            continue
        cls = "ja" if cjk[iid] else L.incident_class({s["source_id"] for s in rec.src[iid]})
        by_cls[cls].append(iid)
    seeds = []
    for cls in sorted(SEED_TARGET):
        pool = by_cls.get(cls, [])
        seeds += [(cls, x) for x in rnd.sample(pool, min(SEED_TARGET[cls], len(pool)))]
    with (out / "seeds.jsonl").open("w") as f:
        for cls, iid in sorted(seeds, key=lambda s: hashlib.sha256(f"{SALT}|seed|{s[1]}".encode()).hexdigest()):
            f.write(json.dumps({"seed_id": hashlib.sha256(f"{SALT}|seed|{iid}".encode()).hexdigest()[:12],
                                "record": rec.record(iid)}, ensure_ascii=False, sort_keys=True) + "\n")
    with (out / "seeds_meta.jsonl").open("w") as f:
        for cls, iid in sorted(seeds):
            f.write(json.dumps({"incident_id": iid, "stratum": cls, "N": len(by_cls[cls]),
                                "n": min(SEED_TARGET[cls], len(by_cls[cls]))}) + "\n")
    with (out / "search_corpus.jsonl").open("w") as f:
        for iid in sorted(rec.inc):
            if not rec.inc[iid]["suppressed"]:
                f.write(json.dumps(rec.record(iid), ensure_ascii=False, sort_keys=True) + "\n")

    def by(key, split):
        return dict(sorted(Counter(key(m) for m in meta if m["split"] == split).items()))
    fam = lambda m: m["stratum"].split(":")[0] if m["stratum"].startswith("main") else m["stratum"]
    summ = {"holdout": len(chosen["hold"]), "dev": len(chosen["dev"]), "seeds": len(seeds),
            "by_stratum": {s: by(fam, s) for s in ("holdout", "dev")},
            "by_class": {s: by(lambda m: m["pair_class"], s) for s in ("holdout", "dev")},
            "population": {"census": {c: len(pools[f"census:{c}"]["hold"]) + len(pools[f"census:{c}"]["dev"])
                                      for c in CENSUS_CLASSES if f"census:{c}" in pools},
                           **{st: len(pools[st]["hold"]) + len(pools[st]["dev"])
                              for st in ("domain_diff", "conflict", "legacy_amexdisc", "legacy") if st in pools}},
            "amexdisc_sampled": sum(1 for m in meta if m["stratum"] == "legacy_amexdisc"),
            "ja": {s: sum(m["ja"] for m in meta if m["split"] == s) for s in ("holdout", "dev")},
            "max_pairs_per_group": {s: max(Counter(m["group"] for m in meta if m["split"] == s).values(), default=0)
                                    for s in ("holdout", "dev")},
            "max_pairs_per_group_outside_census": {s: max(Counter(m["group"] for m in meta if m["split"] == s
                                                                  and not m["stratum"].startswith("census")).values(), default=0)
                                                   for s in ("holdout", "dev")},
            "cap_skipped": sum(m["cap_skipped"] for m in {(m["split"], m["stratum"]): m for m in meta}.values()),
            "holdout_sha256": holdout_sha, "seed": seed}
    json.dump(summ, (out / "SAMPLE_SUMMARY.json").open("w"), indent=1, sort_keys=True)
    return summ


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="Draw the linkage labelling sample from a snapshot and a linkage run.")
    ap.add_argument("--snapshot", required=True)
    ap.add_argument("--run", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--seed", type=int, default=SEED)
    a = ap.parse_args(argv)
    print(json.dumps(sample(a.snapshot, a.run, a.out, a.seed), indent=1))


if __name__ == "__main__":
    main()
