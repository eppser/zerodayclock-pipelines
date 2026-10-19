"""File extractions made by Claude subagents (owner, 2026-10-14: "use the current subscription
for filling up the data; at a later stage we are going to use OpenRouter").

The subagent is given extract.SYSTEM (the same prompt the OpenRouter path sends) and one stored
document at a time, and writes {"doc": sha256, "output": {...}} lines. This loader files them
through run.file_output - the SAME validator and gate as every other extractor - under its own
extractor version (kind 'llm', model e.g. claude-haiku-5-5, the prompt's hash). Its facts stay
out of public views until `python -m zdc_breach.gold` activates fields that pass the gold set.

    python -m zdc_breach.agent_load --model claude-haiku-5-5 --outputs out.jsonl [--dry-run]
    python -m zdc_breach.agent_load --model claude-haiku-5-5 --activate people_affected,event_date \
        --gold analysis/breach-gold-20261014/score_holdout_agent_haiku_v3.json ...
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import psycopg

from . import extract, run


def extractor_id(model: str, lang: str = "en") -> str:
    """Per model, prompt and language, as run.extractor_id (0130)."""
    base = f"agent:{model}@{extract.prompt_hash(model)}"
    return base if lang == "en" else f"{base}:{lang}"


def load(conn, model: str, lines: list[dict], dry_run: bool = False) -> dict:
    ext_id = extractor_id(model)

    class _Args:
        max_docs = 0
    ctx = run.Ctx(conn, None, _Args())
    out = {"extractor_id": ext_id, "filed": 0, "already": 0, "no_document": 0}
    with conn.transaction(), conn.cursor() as cur:
        registered = set()
        for row in lines:
            sha, output = row.get("doc"), extract.parse_model_json(row.get("output"))
            cur.execute("""select d.text, d.url, d.title, d.published_at, d.source_id, d.source_record_id
                             from breach_raw.documents d where d.doc_sha256 = %s""", (sha,))
            doc = cur.fetchone()
            if doc is None:
                out["no_document"] += 1
                continue
            text, url, title, published, source_id, rid = doc
            # A Japanese document files under the ":ja" version, which only a Japanese gold set
            # can activate (0130).
            ext_id = extractor_id(model, extract.language(text, source_id))
            if ext_id not in registered:
                cur.execute("""insert into breach_core.extractor_versions (extractor_id, kind, model_id, prompt_hash, schema_hash, active, note)
                               values (%s, 'llm', %s, %s, %s, false,
                                       'Claude subagent on the owner''s subscription; awaiting gold-set result before activation')
                               on conflict (extractor_id) do nothing""",
                            (ext_id, model, extract.prompt_hash(model), extract.SCHEMA_VERSION))
                registered.add(ext_id)
            cur.execute("select 1 from breach_core.extractions where doc_sha256 = %s and extractor_id = %s", (sha, ext_id))
            if cur.fetchone():
                out["already"] += 1
                continue
            forced = None
            if source_id == "sec_8k":
                cur.execute("""select incident_id from breach_core.incident_sources
                                where source_id = 'sec_8k' and source_record_id = %s""", (rid,))
                r = cur.fetchone()
                forced = r[0] if r else None
            run.file_output(ctx, cur, sha, text, output, ext_id, published=published, source_id=source_id,
                            forced_incident=forced, forced_basis="regulator_filing" if forced else None)
            out["filed"] += 1
        out["claims"] = ctx.report["claims"]
        out["extractor_ids"] = sorted(registered)
        if dry_run:
            raise _Rollback(out)
    return out


def activate(conn, model: str, fields: list[str], gold_files: list[str], lang: str = "en") -> dict:
    """Record the gold-set scores that justify it and switch on exactly these fields. Every field
    must reach 0.95 combined over the given score files, with at least 5 accepted facts. The
    score files must have been scored on documents of the version's language (0130): an English
    gold set cannot activate the Japanese version, nor the reverse."""
    ext_id = extractor_id(model, lang)
    scores = {f: json.load(open(f)) for f in gold_files}
    want_hash = extract.prompt_hash(model)
    for f, sc in scores.items():
        # score files written before 0130 carry no language and were all English
        if sc.get("languages", ["en"]) != [lang]:
            raise SystemExit(f"{f} was scored on {sc.get('languages', ['en'])} documents, not [{lang!r}]; not activated")
        # A score is evidence about the prompt that produced the outputs it scored. A file that does
        # not name its prompt (every file before this check) cannot activate a version.
        if sc.get("prompt_hash") != want_hash:
            raise SystemExit(f"{f} scored prompt {sc.get('prompt_hash')!r}, not {want_hash!r}; not activated")
    for fld in fields:
        acc = sum((s["fields"].get(fld) or {}).get("accepted", 0) for s in scores.values())
        ok = sum((s["fields"].get(fld) or {}).get("correct", 0) for s in scores.values())
        if acc < 5 or ok / acc < 0.95:
            raise SystemExit(f"{fld}: {ok}/{acc} does not pass; not activated")
    with conn.transaction(), conn.cursor() as cur:
        cur.execute("""update breach_core.extractor_versions set gold = %s, active = true, active_fields = %s,
                           note = note || ' | activated ' || now()::date || ' for ' || %s
                        where extractor_id = %s returning extractor_id""",
                    (json.dumps({k: {"fields": v["fields"], "overall_precision": v.get("overall_precision")}
                                 for k, v in scores.items()}), fields, ",".join(fields), ext_id))
        if cur.fetchone() is None:
            raise SystemExit(f"{ext_id} is not registered; load its outputs first")
    return {"extractor_id": ext_id, "active_fields": fields}


class _Rollback(Exception):
    pass


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="zdc-breach-agent-load")
    ap.add_argument("--model", required=True)
    ap.add_argument("--outputs", nargs="+", default=[])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--activate", help="comma-separated fields that passed the gold set")
    ap.add_argument("--gold", nargs="+", default=[], help="score files from zdc_breach.gold")
    ap.add_argument("--language", default="en", choices=("en", "ja"), help="which extractor version to activate")
    a = ap.parse_args(argv)
    if a.activate:
        conn = psycopg.connect(os.environ["DATABASE_URL"], autocommit=False)
        print(json.dumps(activate(conn, a.model, a.activate.split(","), a.gold, a.language), indent=2))
        return 0
    lines = [json.loads(l) for f in a.outputs for l in open(f) if l.strip()]
    conn = psycopg.connect(os.environ["DATABASE_URL"], autocommit=False)
    try:
        res = load(conn, a.model, lines, a.dry_run)
    except _Rollback as r:
        res = {**r.args[0], "dry_run": True}
    print(json.dumps(res, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
