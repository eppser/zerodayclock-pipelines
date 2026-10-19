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
import json
from collections import defaultdict
from decimal import Decimal

from . import extract
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
    args = ap.parse_args(argv)
    labels = _jsonl(args.labels, "doc")
    docs = {k: v["text"] for k, v in _jsonl(args.docs, "doc").items()}
    outputs = {k: v["output"] for k, v in _jsonl(args.outputs, "doc").items()}
    res = score(labels, docs, outputs, prompt_hash=extract.prompt_hash(args.model))
    ok, held = passing_fields(res, args.min_precision)
    res["passing_fields"], res["held_fields"] = ok, held
    print(json.dumps(res, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
