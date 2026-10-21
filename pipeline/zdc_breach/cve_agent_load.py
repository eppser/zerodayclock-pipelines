"""File CVE-pass extractions made by Claude subagents (owner, 2026-10-20: "do all the enrichment
locally and use the OpenRouter key only when we push it to production").

The subagent is given the CVE rubric (prompts/cve_extraction.md, the same text the OpenRouter CVE
pass sends) and one stored document at a time - `cve_extract.user_message(title, url, text)` - and
writes {"doc": sha256, "output": {...}} lines. This loader files them through run.file_output, the
SAME validator, gate and claim path as every other extractor, under its own extractor version:

    agent:<model>@<cve prompt hash>        kind 'llm', schema breach-cve-v1

The CVE pass is a separate extractor from the main one: its prompt hash is the CVE prompt's, so the
main extractor's active fields never cover a CVE claim, and the CVE version's active fields never
cover anything but cve_id. Only documents whose text carries a CVE ID are filed (cve_extract.has_cve).
Its facts stay out of public views until `cve_id` is activated for that version by a CI migration
after the gold result and the owner's approval (ADVISOR 2026-10-20 s7).

NEVER CREATES AN ORGANISATION OR AN INCIDENT (RULING verify-B1, 2026-10-21). file_cve_output is the ONLY filer
of CVE-pass output; load() here and run.run_cve_extraction (patch 0001, which exposes it as run.file_cve_output)
both call it. A link is filed only on the ONE incident this document already resolved to whose organisation
matches by norm_name/alias (cve_extract.resolve_target), or through an exact domain/CIK carried by the link.
Everything else is counted as unattached (no_target / ambiguous_target / name_not_in_doc_incidents) and never
filed. The dry run before this rule would have created 40 duplicate organisations.

    python -m zdc_breach.cve_agent_load --model claude-haiku-5-5 --outputs out.jsonl [--dry-run]
    python -m zdc_breach.cve_agent_load --model claude-haiku-5-5 --outputs out.jsonl --count-only
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

from . import cve_extract, extract


def extractor_id(model: str) -> str:
    return f"agent:{model}@{cve_extract.prompt_hash(model)}"


def plan(lines: list[dict], texts: dict, doc_targets: dict | None = None, cve_meta: dict | None = None,
         key_orgs: list | None = None, published: dict | None = None) -> dict:
    """What file_cve_output would do, without a database. texts {doc_sha256: text}; doc_targets {doc_sha256:
    [targets]} as _doc_targets returns them; key_orgs / published as resolve_target takes them."""
    out = {"documents": 0, "no_document": 0, "out_of_scope": 0, "accepted_non_mentioned": 0, "attached": 0,
           "attached_by": {}, "unattached": {}, "organisations_created": 0, "incidents_created": 0, "rows": []}
    for row in lines:
        sha, output = row.get("doc"), extract.parse_model_json(row.get("output"))
        text = texts.get(sha)
        if text is None:
            out["no_document"] += 1
            continue
        if not cve_extract.has_cve(text):
            out["out_of_scope"] += 1
            continue
        out["documents"] += 1
        for lk in cve_extract.validate(output or {}, text, cve_meta):
            if not lk.accepted or lk.role == "mentioned" or not lk.organization:
                continue
            out["accepted_non_mentioned"] += 1
            r = cve_extract.resolve_target(lk.organization, (doc_targets or {}).get(sha, []), link_domain=lk.domain,
                                           link_cik=lk.cik, key_orgs=key_orgs, published=(published or {}).get(sha))
            if r.unattached:
                out["unattached"][r.unattached] = out["unattached"].get(r.unattached, 0) + 1
            else:
                out["attached"] += 1
                out["attached_by"][r.how] = out["attached_by"].get(r.how, 0) + 1
            out["rows"].append({"doc": sha, "cve_id": lk.cve_id, "organization": lk.organization, "role": lk.role,
                                "incident_id": r.incident_id, "org_id": r.org_id, "how": r.how,
                                "unattached": r.unattached, "public_candidate": lk.public_candidate,
                                "hold_reason": lk.hold_reason})
    return out


def _doc_targets(cur, sha: str) -> list[dict]:
    """The incidents this document already resolved to (RULING verify-B1 step 2)."""
    cur.execute("""with t as (
                       select c.incident_id from breach_core.claims c
                         join breach_core.extractions e on e.extraction_id = c.extraction_id
                         join breach_core.extractor_versions x on x.extractor_id = e.extractor_id
                        where c.doc_sha256 = %s and c.accepted and coalesce(x.schema_hash, '') <> %s
                       union
                       select s.incident_id from breach_core.incident_sources s where s.doc_sha256 = %s
                       union
                       select s.incident_id from breach_core.incident_sources s
                         join breach_raw.documents d on d.doc_sha256 = %s
                        where d.source_id = 'sec_8k' and s.source_id = 'sec_8k' and s.source_record_id = d.source_record_id)
                   select distinct i.incident_id::text, o.org_id::text, o.norm_name, coalesce(o.alias_norms, '{}'),
                          o.domain, o.sec_cik
                     from t join breach_core.incidents i on i.incident_id = t.incident_id
                     join breach_core.organizations o on o.org_id = i.org_id
                    where not i.suppressed and not o.is_natural_person""",
                (sha, cve_extract.SCHEMA_VERSION, sha, sha))
    return [{"incident_id": a, "org_id": b, "norm_name": n, "alias_norms": list(al), "domain": d, "sec_cik": k}
            for a, b, n, al, d, k in cur.fetchall()]


def _key_orgs(cur, domain: str | None, cik: str | None) -> list[dict]:
    """Organisations with exactly this domain or SEC CIK, with their live incidents (RULING verify-B1 step 4)."""
    if not domain and not cik:
        return []
    cur.execute("""select o.org_id::text, o.domain, o.sec_cik,
                          coalesce(json_agg(json_build_object('incident_id', i.incident_id::text,
                                                              'first_public_date', i.first_public_date))
                                   filter (where i.incident_id is not null), '[]')
                     from breach_core.organizations o
                     left join breach_core.incidents i on i.org_id = o.org_id and not i.suppressed
                    where not o.is_natural_person and ((%s::text is not null and o.domain = %s)
                                                       or (%s::text is not null and o.sec_cik = %s))
                    group by 1, 2, 3""", (domain, domain, cik, cik))
    from datetime import date
    out = []
    for oid, d, k, incs in cur.fetchall():
        for i in incs:
            if i.get("first_public_date"):
                i["first_public_date"] = date.fromisoformat(str(i["first_public_date"])[:10])
        out.append({"org_id": oid, "domain": d, "sec_cik": k, "incidents": incs})
    return out


def file_cve_output(ctx, cur, sha: str, text: str, output: dict | None, ext_id: str, *, call_id=None,
                    published=None, source_id=None) -> dict:
    """THE filer of CVE-pass output (RULING verify-B1). Stores the extraction (raw output, re-gateable later),
    then files each accepted, non-mentioned link on its single target incident via run.file_candidate, which
    writes the claim and incident_cves with claim_id. Never creates an organisation or an incident."""
    from . import run
    cur.execute("""insert into breach_core.extractions (doc_sha256, extractor_id, output, ok, error, call_id)
                   values (%s,%s,%s,true,null,%s) returning extraction_id""",
                (sha, ext_id, json.dumps(output) if output is not None else None, call_id))
    extraction_id = cur.fetchone()[0]
    pub = published.date() if hasattr(published, "date") else published
    as_of = pub or datetime.now(timezone.utc).date()   # as run.file_output
    targets = _doc_targets(cur, sha)
    res = {"attached": 0, "unattached": {}}
    for lk in cve_extract.validate(output or {}, text):
        if not lk.accepted or lk.role == "mentioned" or not lk.organization:
            continue
        r = cve_extract.resolve_target(lk.organization, targets, link_domain=lk.domain, link_cik=lk.cik,
                                       key_orgs=_key_orgs(cur, lk.domain, lk.cik), published=pub)
        if r.unattached:
            res["unattached"][r.unattached] = res["unattached"].get(r.unattached, 0) + 1
            continue
        run.file_candidate(ctx, cur, r.incident_id, cve_extract.to_candidate(lk, text), lk.basis,
                           source_id or "news", sha, extraction_id, as_of, text)
        res["attached"] += 1
    return res


def load(conn, model: str, lines: list[dict], dry_run: bool = False) -> dict:
    ext_id = extractor_id(model)
    from . import run   # imported here so plan() needs no database driver

    class _Args:
        max_docs = 0
    ctx = run.Ctx(conn, None, _Args())
    out = {"extractor_id": ext_id, "filed_docs": 0, "already": 0, "no_document": 0, "out_of_scope": 0,
           "attached": 0, "unattached": {}, "organisations_created": 0, "incidents_created": 0}
    with conn.transaction(), conn.cursor() as cur:
        cur.execute("""insert into breach_core.extractor_versions (extractor_id, kind, model_id, prompt_hash, schema_hash, active, note)
                       values (%s, 'llm', %s, %s, %s, false,
                               'CVE pass by a Claude subagent; prompt file sha256 ' || %s || '; awaiting gold-set result and owner approval')
                       on conflict (extractor_id) do nothing""",
                    (ext_id, model, cve_extract.prompt_hash(model), cve_extract.SCHEMA_VERSION, cve_extract.file_hash()))
        cur.execute("select (select count(*) from breach_core.organizations), (select count(*) from breach_core.incidents)")
        orgs_before, incs_before = cur.fetchone()
        for row in lines:
            sha, output = row.get("doc"), extract.parse_model_json(row.get("output"))
            cur.execute("select d.text, d.published_at, d.source_id from breach_raw.documents d where d.doc_sha256 = %s", (sha,))
            doc = cur.fetchone()
            if doc is None:
                out["no_document"] += 1
                continue
            text, published, source_id = doc
            if not cve_extract.has_cve(text):
                out["out_of_scope"] += 1
                continue
            cur.execute("select 1 from breach_core.extractions where doc_sha256 = %s and extractor_id = %s", (sha, ext_id))
            if cur.fetchone():
                out["already"] += 1
                continue
            out["filed_docs"] += 1
            r = file_cve_output(ctx, cur, sha, text, output, ext_id, published=published, source_id=source_id)
            out["attached"] += r["attached"]
            for k, v in r["unattached"].items():
                out["unattached"][k] = out["unattached"].get(k, 0) + v
        cur.execute("select (select count(*) from breach_core.organizations), (select count(*) from breach_core.incidents)")
        o2, i2 = cur.fetchone()
        out["organisations_created"], out["incidents_created"] = o2 - orgs_before, i2 - incs_before
        if out["organisations_created"] or out["incidents_created"]:
            raise RuntimeError("the CVE pass created an organisation or an incident")   # rolls back
        out["claims"] = ctx.report["claims"]
        if dry_run:
            raise _Rollback(out)
    return out


class _Rollback(Exception):
    def __init__(self, result):
        super().__init__("dry run")
        self.result = result


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="zdc-breach-cve-agent-load")
    ap.add_argument("--model", required=True)
    ap.add_argument("--outputs", required=True)
    ap.add_argument("--dry-run", action="store_true", help="file inside a transaction, then roll back")
    ap.add_argument("--count-only", action="store_true",
                    help="no database at all: needs --texts (jsonl of {doc, text}) and prints what a load would file")
    ap.add_argument("--texts")
    args = ap.parse_args(argv)
    lines = [json.loads(l) for l in open(args.outputs) if l.strip()]
    if args.count_only:
        texts = {o["doc"]: o["text"] for o in (json.loads(l) for l in open(args.texts) if l.strip())}
        print(json.dumps({"extractor_id": extractor_id(args.model), **plan(lines, texts)}, indent=2))
        return 0
    import psycopg
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
        try:
            res = load(conn, args.model, lines, dry_run=args.dry_run)
        except _Rollback as r:
            res = {**r.result, "dry_run": True}
    print(json.dumps(res, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
