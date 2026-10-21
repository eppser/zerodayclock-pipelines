"""Score an extractor version against a labelled gold set; the activation gate.

    python -m zdc_breach.gold --labels gold_labels.jsonl --docs gold_docs.jsonl \
        --outputs outputs.jsonl [--min-precision 0.95] [--activate EXTRACTOR_ID]

`outputs` holds the stored model output per document (breach_core.extractions.output); the
CURRENT validator is re-applied, so a stricter gate is scored without paying for new calls.

PRECISION IS WHAT IS PUBLISHED, SO PRECISION IS WHAT IS GATED. A fact the extractor accepts is
correct when the gold set holds the same field for the same organisation with the same value:
numbers within 2% (articles round), dates equal, CVE IDs equal, vectors equal, text fields by
token overlap. Recall is reported but not gated - a missed fact costs coverage, a wrong one
costs the scoreboard its credibility.

The gate needs every field with at least 5 accepted facts to reach the threshold; fields
below it stay inactive (the extractor_versions row records which).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from collections import defaultdict
from datetime import datetime, timezone
from decimal import Decimal

from . import cve_extract, extract
from .normalize import norm_name


# The fields the gold-set instructions define (scratchpad gold prompt, 2026-10-14).
LABELLED = {"people_affected", "records_affected", "accounts_affected", "data_bytes", "data_types",
            "data_exfiltrated", "vector", "cve_id", "actor", "ransomware_family", "ransom_demand_amount",
            "ransom_paid_amount", "ransom_paid", "demand_text", "event_date", "discovery_date",
            "disclosure_date"}


def _same_org(a: str, b: str) -> bool:
    x, y = set(norm_name(a).split()), set(norm_name(b).split())
    return bool(x and y) and (x <= y or y <= x or len(x & y) >= 2)


def _same_value(field: str, got, want) -> bool:
    if field in extract.UNIT_FOR:
        try:
            g, w = Decimal(str(got)), Decimal(str(want))
        except Exception:
            return False
        return w != 0 and abs(g - w) / w <= Decimal("0.02")
    if field in ("ransom_paid", "data_exfiltrated", "operations_disrupted"):
        return str(got).lower() == str(want).lower()
    if field in ("event_date", "discovery_date", "disclosure_date", "vector"):
        return str(got) == str(want)
    if field == "cve_id":
        return str(got).upper() == str(want).upper()
    g, w = set(norm_name(str(got)).split()), set(norm_name(str(want)).split())
    return bool(g and w) and len(g & w) / min(len(g), len(w)) >= 0.5


def score(labels: dict, docs: dict, outputs: dict, prompt_hash: str | None = None) -> dict:
    tp, fp, gold_n = defaultdict(int), defaultdict(int), defaultdict(int)
    mistakes = []
    for doc, lab in labels.items():
        for inc in lab.get("incidents", []):
            for f in inc.get("facts", []):
                gold_n[f["field"]] += 1
        text = docs.get(doc)
        out = outputs.get(doc)
        if text is None or out is None:
            continue
        for ei in extract.validate(out, text):
            gold_incs = [g for g in lab.get("incidents", []) if _same_org(ei.organization, g["organization"])]
            for c in ei.candidates:
                if not c.accepted:
                    continue
                ok = any(_same_value(c.field, c.value, gf["value"])
                         for g in gold_incs for gf in g.get("facts", []) if gf["field"] == c.field)
                (tp if ok else fp)[c.field] += 1
                if not ok:
                    mistakes.append({"doc": doc[:12], "org": ei.organization, "field": c.field,
                                     "value": str(c.value)[:80], "quote": c.quote[:160]})
    # A field the gold set does not label cannot be scored: it is reported, never passed.
    unlabelled = sorted(set(tp) | set(fp)) if not gold_n else sorted(f for f in set(tp) | set(fp) if f not in LABELLED)
    for f in unlabelled:
        tp.pop(f, None), fp.pop(f, None)
    fields = sorted(set(tp) | set(fp) | set(gold_n))
    per = {f: {"accepted": tp[f] + fp[f], "correct": tp[f],
               "precision": round(tp[f] / (tp[f] + fp[f]), 3) if tp[f] + fp[f] else None,
               "gold": gold_n[f], "recall": round(tp[f] / gold_n[f], 3) if gold_n[f] else None}
           for f in fields}
    total_tp, total_fp = sum(tp.values()), sum(fp.values())
    # Which language the scored documents are in (0130): activation refuses a score file whose
    # language is not the extractor version's.
    langs = sorted({extract.language(docs[d]) for d in labels if docs.get(d) is not None and outputs.get(d) is not None})
    return {"languages": langs, "prompt_hash": prompt_hash, "fields": per, "unlabelled_fields": unlabelled, "overall_precision": round(total_tp / (total_tp + total_fp), 3) if total_tp + total_fp else None,
            "documents": len(labels), "mistakes": mistakes}


def passing_fields(result: dict, min_precision: float, min_support: int = 5) -> tuple[list, list]:
    ok, held = [], []
    for f, v in result["fields"].items():
        if v["accepted"] >= min_support and v["precision"] is not None and v["precision"] >= min_precision:
            ok.append(f)
        elif v["accepted"]:
            held.append(f)
    return ok, held


# ---- cve_id: pairs, a Wilson lower bound, and a sealed hold-out (ADVISOR 2026-10-20 s5) -------------
# A point precision of 0.95 on 5 facts is far too weak for a field that names a breached
# organisation next to a CVE. cve_id passes only with point precision >= 0.95 AND a Wilson 95% lower
# bound >= 0.90 over >= 100 accepted pairs, a mentioned->public leak rate <= 2%, and recall >= 0.50.
# Split-rule ruling (ADVISOR 2026-10-20, "campaign clustering"): pairs cluster in documents, so the
# gate is a DOCUMENT-cluster bootstrap lower bound (Wilson on pairs overstates n and is reported only);
# support is >= 60 named accepted pairs (floor) or 100; and precision with the largest CVE group removed
# must still be >= 0.95, which fails a prompt that only works on one campaign's phrasing.
CVE_THRESHOLDS = {"min_precision": 0.95, "lower_bound": 0.90, "min_support": 60,
                  "max_leak_rate": 0.02, "min_recall": 0.50, "campaign_removed_precision": 0.95,
                  "role_wilson_lb": 0.85, "role_min_support": 40}
BOOTSTRAP_DRAWS = 2000
BOOTSTRAP_SEED = 20261020


def cluster_bootstrap_lb(per_doc: dict, draws: int = BOOTSTRAP_DRAWS, seed: int = BOOTSTRAP_SEED,
                         alpha: float = 0.05) -> float | None:
    """Lower (alpha/2) percentile of precision over documents resampled with replacement.
    per_doc: {doc: (correct, accepted)}; documents with no accepted pair carry no weight."""
    import random
    cells = [v for v in per_doc.values() if v[1]]
    if not cells:
        return None
    rng = random.Random(seed)
    stats = []
    for _ in range(draws):
        k = n = 0
        for _ in range(len(cells)):
            c, a = cells[rng.randrange(len(cells))]
            k += c
            n += a
        stats.append(k / n)
    stats.sort()
    return round(stats[int(alpha / 2 * draws)], 4)


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float | None, float | None]:
    """Wilson score interval for k successes in n trials (None, None when n == 0)."""
    if n == 0:
        return None, None
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    r = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return round((c - r) / d, 4), round((c + r) / d, 4)


def _gold_pairs(lab: dict) -> dict:
    """{(CVE, org): link} for every gold link that names an organisation."""
    out = {}
    for g in lab.get("links") or []:
        if g.get("organization"):
            out[(g["cve_id"].upper(), g["organization"])] = g
    return out


def _match(cve: str, org: str, gold: dict):
    for (gc, go), g in gold.items():
        if gc == cve and _same_org(org, go):
            return g
    return None


def score_cve(labels: dict, docs: dict, outputs: dict, cve_meta: dict | None = None,
              prompt_hash: str | None = None) -> dict:
    """labels {doc: {"links": [...], "stratum": "s1"|"s2"|"s3"}}, docs {doc: text}, outputs {doc: model JSON}.
    A predicted pair counts when the gate mirror makes it a public candidate; it is correct when gold
    holds a non-mentioned link for the same CVE and organisation."""
    tp = fp = 0
    role_ia_tp = role_ia_n = 0
    leak = mentioned_n = 0
    rec = defaultdict(lambda: [0, 0])          # stratum -> [found, gold] (named_in_sentence pairs)
    rec_all = [0, 0]
    mistakes, misses = [], []
    per_doc = {}
    by_cve = defaultdict(lambda: [0, 0])     # predicted CVE -> [correct, accepted]
    gold_named_by_cve = defaultdict(int)
    for doc, lab in labels.items():
        text, out = docs.get(doc), outputs.get(doc)
        gold = _gold_pairs(lab)
        stratum = lab.get("stratum") or doc.split(":")[0]
        pred = [lk for lk in cve_extract.validate(out or {}, text or "", cve_meta) if lk.public_candidate] \
            if text is not None and out is not None else []
        dc = da = 0
        for lk in pred:
            g = _match(lk.cve_id, lk.organization, gold)
            da += 1
            by_cve[lk.cve_id][1] += 1
            if g is not None and g["role"] != "mentioned":
                tp += 1
                dc += 1
                by_cve[lk.cve_id][0] += 1
                if lk.role == "initial_access":
                    role_ia_n += 1
                    role_ia_tp += g["role"] == "initial_access"
            else:
                fp += 1
                mistakes.append({"doc": doc[:20], "cve": lk.cve_id, "org": lk.organization, "role": lk.role,
                                 "gold": g["role"] if g else None, "quote": lk.quote[:200]})
        per_doc[doc] = (dc, da)
        for (gc, go), g in gold.items():
            if g["role"] != "mentioned" and g.get("named_in_sentence"):
                gold_named_by_cve[gc] += 1
            hit = any(lk.cve_id == gc and _same_org(lk.organization, go) for lk in pred)
            if g["role"] == "mentioned":
                mentioned_n += 1
                leak += hit
                continue
            rec_all[1] += 1
            rec_all[0] += hit
            if g.get("named_in_sentence"):
                rec[stratum][1] += 1
                rec[stratum][0] += hit
                if not hit:
                    misses.append({"doc": doc[:20], "cve": gc, "org": go, "role": g["role"]})
    n = tp + fp
    lb, ub = wilson(tp, n)
    largest = max(gold_named_by_cve, key=lambda c: (gold_named_by_cve[c], c)) if gold_named_by_cve else None
    rk = tp - by_cve[largest][0] if largest else tp
    rn = n - by_cve[largest][1] if largest else n
    r_found = sum(v[0] for v in rec.values())
    r_gold = sum(v[1] for v in rec.values())
    res = {
        "field": "cve_id", "prompt_hash": prompt_hash, "documents": len(labels),
        "accepted_pairs": n, "correct_pairs": tp,
        "precision": round(tp / n, 4) if n else None, "wilson_lb": lb, "wilson_ub": ub,
        "cluster_bootstrap_lb": cluster_bootstrap_lb(per_doc), "documents_with_accepted": sum(1 for v in per_doc.values() if v[1]),
        "bootstrap": {"draws": BOOTSTRAP_DRAWS, "seed": BOOTSTRAP_SEED, "unit": "document"},
        "largest_cve_group": {"cve_id": largest, "gold_named": gold_named_by_cve.get(largest, 0),
                              "share_of_gold_named": round(gold_named_by_cve[largest] / sum(gold_named_by_cve.values()), 4) if largest else None,
                              "precision_without": round(rk / rn, 4) if rn else None, "accepted_without": rn},
        "recall_named": round(r_found / r_gold, 4) if r_gold else None, "gold_named_pairs": r_gold,
        "recall_named_by_stratum": {k: {"found": v[0], "gold": v[1], "recall": round(v[0] / v[1], 4) if v[1] else None}
                                    for k, v in sorted(rec.items())},
        "recall_all": round(rec_all[0] / rec_all[1], 4) if rec_all[1] else None, "gold_pairs": rec_all[1],
        "mentioned_pairs": mentioned_n, "leaked_mentioned": leak,
        "leak_rate": round(leak / mentioned_n, 4) if mentioned_n else None,
        "leak_rate_wilson_ub": wilson(leak, mentioned_n)[1],
        "initial_access": {"predicted": role_ia_n, "correct": role_ia_tp,
                           "precision": round(role_ia_tp / role_ia_n, 4) if role_ia_n else None,
                           "wilson_lb": wilson(role_ia_tp, role_ia_n)[0]},
        "mistakes": mistakes, "misses": misses,
    }
    res["verdict"] = cve_verdict(res)
    return res


def cve_verdict(res: dict, t: dict = CVE_THRESHOLDS) -> dict:
    """Which thresholds a cve_id score meets. pass = all of them; role_specific = initial_access may be
    shown as such (otherwise every public role is shown as 'exploited'). The lower bound gated is the
    document-cluster bootstrap one; Wilson is reported beside it."""
    checks = {
        "support": res["accepted_pairs"] >= t["min_support"],
        "precision": (res["precision"] or 0) >= t["min_precision"],
        "lower_bound": (res.get("cluster_bootstrap_lb") or 0) >= t["lower_bound"],
        "campaign_removed": ((res.get("largest_cve_group") or {}).get("precision_without") or 0) >= t["campaign_removed_precision"],
        "leak_rate": res["leak_rate"] is not None and res["leak_rate"] <= t["max_leak_rate"],
        "recall": (res["recall_named"] or 0) >= t["min_recall"],
    }
    ia = res["initial_access"]
    return {"checks": checks, "pass": all(checks.values()), "min_support_used": t["min_support"],
            "role_specific": ia["predicted"] >= t["role_min_support"] and (ia["wilson_lb"] or 0) >= t["role_wilson_lb"]}


class SealedHoldout(RuntimeError):
    pass


def _sha256_file(path: str) -> str:
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def check_seal(labels_path: str, manifest_path: str | None, final: bool) -> str | None:
    """Refuse to score a sealed hold-out unless --final is given and it was never opened before.
    Returns the hold-out's name when this call opens it (the caller records the opening)."""
    if not manifest_path:
        if final:
            raise SealedHoldout("--final needs --manifest")
        return None
    with open(manifest_path) as fh:
        manifest = json.load(fh)
    sha = _sha256_file(labels_path)
    for name, h in (manifest.get("holdouts") or {}).items():
        if h.get("labels_sha256") != sha:
            continue
        if not final:
            raise SealedHoldout(f"{name} is a sealed hold-out: score it only with --final, once")
        if h.get("opened_at"):
            raise SealedHoldout(f"{name} was already opened at {h['opened_at']}; a hold-out is opened once")
        return name
    if final:
        raise SealedHoldout("--final given but these labels are not a sealed hold-out in the manifest")
    return None


def record_opening(manifest_path: str, name: str, prompt_hash: str | None, result: dict) -> None:
    with open(manifest_path) as fh:
        manifest = json.load(fh)
    manifest["holdouts"][name].update(opened_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                                      opened_with_prompt=prompt_hash, result_pass=result["verdict"]["pass"])
    tmp = manifest_path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
    os.replace(tmp, manifest_path)


def _jsonl(path, key):
    out = {}
    with open(path) as fh:
        for line in fh:
            if line.strip():
                o = json.loads(line)
                out[o[key]] = o
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="zdc-breach-gold")
    ap.add_argument("--labels", required=True)
    ap.add_argument("--docs", required=True)
    ap.add_argument("--outputs", required=True, help="jsonl of {doc, output}")
    ap.add_argument("--min-precision", type=float, default=0.95)
    ap.add_argument("--model", required=True,
                    help="the model whose outputs these are; its prompt hash is recorded so activation can check it")
    ap.add_argument("--cve", action="store_true",
                    help="score the CVE pass (cve_extract) with the cve_id thresholds: Wilson LB, support 100, leak, recall")
    ap.add_argument("--cve-meta", help="json {CVE: {vendors: [...], assigner: str}} for the vendor/reporter rule")
    ap.add_argument("--manifest", help="hold-out manifest; a sealed hold-out is scored only with --final, once")
    ap.add_argument("--final", action="store_true", help="open a sealed hold-out (once)")
    ap.add_argument("--cve-min-support", type=int, choices=(60, 100), default=60,
                    help="named accepted pairs required: 100, or the 60 floor (recorded in the result)")
    args = ap.parse_args(argv)
    labels = _jsonl(args.labels, "doc")
    docs = {k: v["text"] for k, v in _jsonl(args.docs, "doc").items()}
    outputs = {k: v["output"] for k, v in _jsonl(args.outputs, "doc").items()}
    if args.cve:
        opening = check_seal(args.labels, args.manifest, args.final)
        meta = json.load(open(args.cve_meta)) if args.cve_meta else None
        ph = cve_extract.prompt_hash(args.model)
        res = score_cve(labels, docs, outputs, meta, prompt_hash=ph)
        res["verdict"] = cve_verdict(res, {**CVE_THRESHOLDS, "min_support": args.cve_min_support})
        if opening:
            record_opening(args.manifest, opening, ph, res)
        print(json.dumps(res, indent=2, default=str))
        return 0
    res = score(labels, docs, outputs, prompt_hash=extract.prompt_hash(args.model))
    ok, held = passing_fields(res, args.min_precision)
    res["passing_fields"], res["held_fields"] = ok, held
    print(json.dumps(res, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
