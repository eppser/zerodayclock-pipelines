"""Breach tracking pipeline - one hourly run.

    python -m zdc_breach.run                    # every source that is due
    python -m zdc_breach.run --sources wa_ag,hibp --force
    python -m zdc_breach.run --dry-run          # fetch and parse; roll everything back
    python -m zdc_breach.run --max-docs 40      # LLM extractions this run (default 40)

Each source commits on its own: a failure in one rolls back that source only. Sources have
their own cadence inside the hourly run (a regulator list that changes daily is not fetched
24 times a day). The run report holds COUNTS ONLY - it is a public artifact in the public
pipelines repository, so it never carries a victim's name.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import os
import re
import sys
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal

import psycopg

from zdc_kev import db as runs_db

from . import db, evals, extract, http, reconcile, resolve, sources_leak, sources_news, sources_reg
from .fx import Fx
from .llm import MODEL, BudgetExceeded, OpenRouter
from .normalize import norm_country, norm_domain

PIPELINE = "breach"
log = logging.getLogger("zdc_breach")

# source_id -> minimum hours between fetches
CADENCE_H = {"ransomlook": 1, "ransomfeed": 1, "sec_8k": 1, "wa_ag": 6, "de_ag": 6, "hibp": 6,
             "ca_ag": 24, "hhs_ocr": 24}
CADENCE_H.update({f.source_id: 1 for f in sources_news.FEEDS})

RANSOMLOOK_URL = "https://www.ransomlook.io/api/last/2"
RANSOMFEED_URL = "https://api.ransomfeed.it/offset/300"
ACTOR_LINK_WINDOW = timedelta(days=60)
CONFIRM = re.compile(r"\b(confirmed|said in a statement|announced|disclosed|notif(?:ied|ying)|"
                     r"acknowledged|told (?:\w+ ){0,3}(?:that|it)|a spokesperson)\b", re.I)


def extractor_id(model: str) -> str:
    return f"llm:{model}@{extract.prompt_hash(model)}"


class Ctx:
    def __init__(self, conn, run_id, args, getter=http.get, llm=None, fx=None):
        self.conn, self.run_id, self.args = conn, run_id, args
        self.get = getter
        self.llm = llm
        self.fx = fx or Fx(getter)
        self.report: dict = {"sources": {}, "llm": {"docs": 0, "calls_ok": 0, "calls_failed": 0,
                                                    "cost_usd": 0.0, "budget_stopped": None},
                             "claims": {"accepted": 0, "rejected": 0, "reject_reasons": {}}}
        self.docs_left = args.max_docs
        self.new_quotes: list[tuple[str, str]] = []   # (quote, doc text) for quote_offsets_valid


# ---------------------------------------------------------------------------------------------
def due(cur, source_id: str, force: bool) -> bool:
    if force:
        return True
    cur.execute("select last_success_at from breach_core.source_state where source_id = %s", (source_id,))
    r = cur.fetchone()
    if not r or not r[0]:
        return True
    return datetime.now(timezone.utc) - r[0] >= timedelta(hours=CADENCE_H.get(source_id, 1)) - timedelta(minutes=10)


def _fetch(ctx, cur, source_id, url, **kw) -> http.Fetched:
    f = ctx.get(url, **kw)
    ctx.report["sources"].setdefault(source_id, {})["http"] = f.status
    return f


# ---- leak trackers ---------------------------------------------------------------------------
def run_leak(ctx, cur, source_id: str) -> dict:
    url = RANSOMLOOK_URL if source_id == "ransomlook" else RANSOMFEED_URL
    f = _fetch(ctx, cur, source_id, url, accept="application/json")
    if not f.ok:
        db.record_fetch(cur, ctx.run_id, source_id, f, None)
        raise RuntimeError(f.error or f"HTTP {f.status}")
    rows = f.json()
    posts, bad = (sources_leak.parse_ransomlook if source_id == "ransomlook" else sources_leak.parse_ransomfeed)(rows)
    fid = db.record_fetch(cur, ctx.run_id, source_id, f, len(rows) if isinstance(rows, list) else 0)
    counts, _ = db.store_records(cur, source_id, [(p.source_record_id, p.record) for p in posts], fid)
    folded = db.upsert_leak_posts(cur, posts)
    linked = link_leak_claims(cur)
    return {"records": len(rows) if isinstance(rows, list) else 0, "parsed": len(posts), "malformed": bad,
            **counts, **folded, "actor_links": linked}


def link_leak_claims(cur) -> int:
    """A leak claim attaches to a confirmed or filed incident only through an exact domain match
    within 60 days. A name match is never enough to tell readers who attacked an organisation."""
    cur.execute(
        """select l.claim_key, l.actor_group, l.first_seen_at, i.incident_id
             from breach_core.leak_claims l
             join breach_core.organizations o on o.domain = l.victim_domain
             join breach_core.incidents i on i.org_id = o.org_id
            where l.incident_id is null and l.victim_domain is not null
              and abs(coalesce(i.event_date, i.first_public_date) - l.first_seen_at::date) <= %s""",
        (ACTOR_LINK_WINDOW.days,))
    n = 0
    for key, group, seen, inc in cur.fetchall():
        cur.execute("update breach_core.leak_claims set incident_id = %s where claim_key = %s", (inc, key))
        resolve.set_flag(cur, inc, "threat_actor_claim")
        resolve.add_claim(cur, incident_id=inc, field="actor", value_text=group, as_of=seen.date(),
                          basis="threat_actor_claim", source_id=_tracker(cur, key),
                          source_record_id=key)
        n += 1
    return n


def _tracker(cur, key):
    cur.execute("select trackers[1] from breach_core.leak_claims where claim_key = %s", (key,))
    return cur.fetchone()[0]


# ---- regulators and indexes ------------------------------------------------------------------
US_REGULATORS = {"wa_ag", "de_ag", "ca_ag", "hhs_ocr", "sec_8k"}


def apply_disclosure(ctx, cur, d: sources_reg.Disclosure) -> str:
    country = "US" if d.source_id in US_REGULATORS else None
    org, how = resolve.find_or_create_org(cur, name=d.organization, domain=d.domain, cik=d.sec_cik,
                                          country=country, sector=d.sector)
    inc, _ = resolve.resolve_incident(cur, org_id=org, org_how=how, source_id=d.source_id,
                                      record_id=d.source_record_id, event_date=d.event_date,
                                      public_date=d.as_of)
    resolve.set_flag(cur, inc, d.basis)
    for f in d.facts:
        resolve.add_claim(cur, incident_id=inc, field=f.field, value_num=f.value_num,
                          value_text=f.value_text, unit=f.unit, qualifier=f.qualifier, as_of=d.as_of,
                          basis=d.basis, source_id=d.source_id, source_record_id=d.source_record_id)
    return inc


def run_structured(ctx, cur, source_id: str) -> dict:
    if source_id == "wa_ag":
        f = _fetch(ctx, cur, source_id, sources_reg.WA_URL, accept="application/json")
        parse = lambda: sources_reg.parse_wa(f.json())
    elif source_id == "de_ag":
        f = _fetch(ctx, cur, source_id, sources_reg.DE_URL, accept="application/json")
        parse = lambda: sources_reg.parse_de(f.json())
    elif source_id == "ca_ag":
        f = _fetch(ctx, cur, source_id, sources_reg.CA_URL, accept="text/csv")
        parse = lambda: sources_reg.parse_ca(f.text())
    elif source_id == "hibp":
        f = _fetch(ctx, cur, source_id, sources_reg.HIBP_URL, accept="application/json")
        parse = lambda: sources_reg.parse_hibp(f.json())
    elif source_id == "hhs_ocr":
        f = fetch_hhs(ctx)
        parse = lambda: sources_reg.parse_hhs(f.text())
    else:
        raise ValueError(source_id)
    if not f.ok:
        db.record_fetch(cur, ctx.run_id, source_id, f, None)
        raise RuntimeError(f.error or f"HTTP {f.status}")
    items, bad = parse()
    fid = db.record_fetch(cur, ctx.run_id, source_id, f, len(items) + bad)
    counts, changed = db.store_records(cur, source_id, [(d.source_record_id, d.record) for d in items], fid,
                                       limit=ctx.args.max_apply)
    applied = 0
    r = resolve.Resolver(cur)
    for d in items:
        if d.source_record_id in changed:
            apply_disclosure_batched(r, d)
            applied += 1
    r.flush()
    return {"parsed": len(items), "malformed": bad, **counts, "applied": applied}


def apply_disclosure_batched(r: "resolve.Resolver", d: sources_reg.Disclosure):
    country = "US" if d.source_id in US_REGULATORS else None
    org, how = r.org(name=d.organization, domain=d.domain, cik=d.sec_cik, country=country, sector=d.sector)
    inc, _ = r.incident(org_id=org, org_how=how, source_id=d.source_id, record_id=d.source_record_id,
                        event_date=d.event_date, public_date=d.as_of)
    r.flag(inc, d.basis)
    for f in d.facts:
        r.claim(incident_id=inc, field=f.field, value_num=f.value_num, value_text=f.value_text, unit=f.unit,
                qualifier=f.qualifier, as_of=d.as_of, basis=d.basis, source_id=d.source_id,
                source_record_id=d.source_record_id)


def fetch_hhs(ctx) -> http.Fetched:
    """HHS publishes no CSV URL; the export sits behind a JSF postback. Three requests with a
    session cookie, the button ids found on the page rather than hard-coded."""
    import http.cookiejar as cookiejar
    import urllib.request
    jar = cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    g = lambda url: ctx.get(url, opener=opener, accept="text/html")
    front = g(sources_reg.HHS_FRONT)
    if not front.ok:
        return front
    vs = sources_reg.viewstate(front.text())
    btn = sources_reg.jsf_button(front.text(), r"View HIPAA Breach Reports")
    if not vs or not btn:
        return http.Fetched(front.url, 0, b"", "HHS front page changed: no ViewState or report link",
                            front.requested_at, front.finished_at, {})
    post = lambda url, data: _post(opener, url, data)
    page = post(sources_reg.HHS_FRONT, {"ocrForm": "ocrForm", btn: btn, "javax.faces.ViewState": vs})
    if not page.ok:
        return page
    vs2 = sources_reg.viewstate(page.text())
    csv_btn = sources_reg.jsf_button(page.text(), r"[^>]*csv")
    if not vs2 or not csv_btn:
        return http.Fetched(page.url, 0, b"", "HHS report page changed: no CSV link", page.requested_at,
                            page.finished_at, {})
    return post(sources_reg.HHS_REPORT, {"ocrForm": "ocrForm", csv_btn: csv_btn, "javax.faces.ViewState": vs2})


def _post(opener, url, data) -> http.Fetched:
    import urllib.error
    import urllib.parse
    import urllib.request
    started = datetime.now(timezone.utc)
    req = urllib.request.Request(url, data=urllib.parse.urlencode(data).encode(), method="POST",
                                 headers={"User-Agent": http.UA,
                                          "Content-Type": "application/x-www-form-urlencoded"})
    try:
        with opener.open(req, timeout=90) as r:
            return http.Fetched(r.geturl(), r.status, r.read(20_000_000), None, started,
                                datetime.now(timezone.utc), dict(r.headers))
    except urllib.error.HTTPError as e:
        return http.Fetched(url, e.code, b"", f"HTTP {e.code}", started, datetime.now(timezone.utc), {})
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return http.Fetched(url, 0, b"", f"{type(e).__name__}"[:200], started, datetime.now(timezone.utc), {})


# ---- SEC 8-K Item 1.05 -----------------------------------------------------------------------
def run_sec(ctx, cur) -> dict:
    today = datetime.now(timezone.utc).date()
    start = today - timedelta(days=ctx.args.sec_days)
    items, bad, n_fetch = [], 0, 0
    for form in ("8-K", "8-K/A"):
        f = _fetch(ctx, cur, "sec_8k", sources_reg.efts_url(start, today, form=form), accept="application/json")
        n_fetch += 1
        if not f.ok:
            db.record_fetch(cur, ctx.run_id, "sec_8k", f, None)
            raise RuntimeError(f.error or f"HTTP {f.status}")
        got, b = sources_reg.parse_efts(f.json())
        db.record_fetch(cur, ctx.run_id, "sec_8k", f, len(got))
        items += got
        bad += b
    counts, changed = db.store_records(cur, "sec_8k", [(d.source_record_id, d.record) for d in items], None)
    extracted = 0
    for d in items:
        if d.source_record_id not in changed:
            continue
        apply_disclosure(ctx, cur, d)
        if d.url:
            page = ctx.get(d.url, accept="text/html")
            if page.ok:
                text = sources_news.strip_html(page.text())
                store_doc(cur, "sec_8k", d.url, f"{d.organization} 8-K", None, text, d.source_record_id)
                extracted += 1
    return {"parsed": len(items), "malformed": bad, **counts, "documents": extracted}


# ---- news ------------------------------------------------------------------------------------
def store_doc(cur, source_id, url, title, published_at, text, record_id=None) -> str:
    sha = sources_news.doc_sha(text)
    cur.execute("""insert into breach_raw.documents (doc_sha256, source_id, url, title, published_at, text, source_record_id)
                   values (%s,%s,%s,%s,%s,%s,%s) on conflict (doc_sha256) do nothing""",
                (sha, source_id, url, (title or "")[:500], published_at, text, record_id))
    return sha


def run_feed(ctx, cur, feed: sources_news.Feed) -> dict:
    f = _fetch(ctx, cur, feed.source_id, feed.url, accept="application/rss+xml, application/atom+xml, */*")
    if not f.ok:
        db.record_fetch(cur, ctx.run_id, feed.source_id, f, None)
        raise RuntimeError(f.error or f"HTTP {f.status}")
    items = sources_news.parse_feed(feed.source_id, f.body)
    fid = db.record_fetch(cur, ctx.run_id, feed.source_id, f, len(items))
    rel = [i for i in items if i.relevant]
    counts, changed = db.store_records(cur, feed.source_id, [(i.guid, {"url": i.url, "title": i.title,
                                       "published_at": i.published_at.isoformat() if i.published_at else None,
                                       "summary": i.summary[:4000]}) for i in rel], fid)
    extracted = 0
    for it in rel:
        if it.guid not in changed:
            continue
        text = it.summary
        if feed.fetch_page and not feed.full_text_in_feed:
            page = ctx.get(it.url, accept="text/html")
            if page.ok:
                body = sources_news.article_text(page.text())
                if len(body) > len(text):
                    text = body
        if len(text) < 200:
            continue
        store_doc(cur, feed.source_id, it.url, it.title, it.published_at, text, it.guid)
        extracted += 1
    return {"items": len(items), "relevant": len(rel), **counts, "documents": extracted}


def run_extraction(ctx, conn) -> dict:
    """The backlog: every stored document from the last 21 days without an extraction by the
    current extractor version, newest first, up to --max-docs. A document whose call failed
    twice is left alone (and counted), so a pathological article cannot drain the budget.

    ONE TRANSACTION PER DOCUMENT. The spend of every call must be on record the moment it is
    made: if the job dies at document 30, the 29 calls before it still count toward the cap."""
    if ctx.llm is None:
        return {"skipped": "no LLM key"}
    ext_id = extractor_id(MODEL)
    ph = extract.prompt_hash(MODEL)
    with conn.transaction(), conn.cursor() as cur:
        cur.execute("""insert into breach_core.extractor_versions (extractor_id, kind, model_id, prompt_hash, schema_hash, active, note)
                       values (%s, 'llm', %s, %s, %s, false, 'Awaiting gold-set result before activation')
                       on conflict (extractor_id) do nothing""", (ext_id, MODEL, ph, extract.SCHEMA_VERSION))
        cur.execute("""select d.doc_sha256, d.source_id, d.url, d.title, d.published_at, d.text, d.source_record_id
                         from breach_raw.documents d
                        where d.captured_at > now() - interval '21 days'
                          and not exists (select 1 from breach_core.extractions e
                                           where e.doc_sha256 = d.doc_sha256 and e.extractor_id = %s)
                          and (select count(*) from breach_core.llm_calls c
                                where c.doc_sha256 = d.doc_sha256 and c.prompt_hash = %s and not c.ok) < 2
                        order by d.captured_at desc limit %s""", (ext_id, ph, ctx.args.max_docs))
        todo = cur.fetchall()
    done = 0
    for sha, source_id, url, title, published, text, rid in todo:
        try:
            with conn.transaction(), conn.cursor() as cur:
                forced = None
                if source_id == "sec_8k":
                    cur.execute("""select incident_id from breach_core.incident_sources
                                    where source_id = 'sec_8k' and source_record_id = %s""", (rid,))
                    r = cur.fetchone()
                    forced = r[0] if r else None
                    if forced is None:
                        continue
                done += extract_doc(ctx, cur, sha, text, url, title, published=published, source_id=source_id,
                                    forced_incident=forced, forced_basis="regulator_filing" if forced else None)
                if ctx.args.dry_run:
                    raise _DryRun()
        except _DryRun:
            pass
        if ctx.report["llm"]["budget_stopped"]:
            break
    with conn.cursor() as cur:
        cur.execute("""select count(*) from breach_raw.documents d where d.captured_at > now() - interval '21 days'
                         and not exists (select 1 from breach_core.extractions e where e.doc_sha256 = d.doc_sha256 and e.extractor_id = %s)""",
                    (ext_id,))
        left = cur.fetchone()[0]
    return {"extracted": done, "backlog_left": left}


def extract_doc(ctx, cur, sha, text, url, title, *, forced_incident=None, forced_basis=None,
                published=None, source_id=None) -> int:
    """Run the model on one document (cached per extractor version) and file its claims."""
    if ctx.llm is None or ctx.docs_left <= 0 or ctx.report["llm"]["budget_stopped"]:
        return 0
    ext_id = extractor_id(MODEL)
    cur.execute("select 1 from breach_core.extractions where doc_sha256 = %s and extractor_id = %s", (sha, ext_id))
    if cur.fetchone():
        return 0
    try:
        res = ctx.llm.json(extract.SYSTEM, extract.USER_TEMPLATE.format(title=title or "", url=url, text=text[:14000]))
    except BudgetExceeded as e:
        ctx.report["llm"]["budget_stopped"] = str(e)
        return 0
    ctx.docs_left -= 1
    call_id = db.record_llm_call(cur, ctx.run_id, res, extract.prompt_hash(MODEL), sha)
    ctx.report["llm"]["docs"] += 1
    ctx.report["llm"]["calls_ok" if res.ok else "calls_failed"] += 1
    ctx.report["llm"]["cost_usd"] = round(ctx.report["llm"]["cost_usd"] + res.cost_usd, 6)
    if not res.ok:
        return 0   # no extraction row: the backlog retries it once more
    cur.execute("""insert into breach_core.extractions (doc_sha256, extractor_id, output, ok, error, call_id)
                   values (%s,%s,%s,%s,%s,%s) returning extraction_id""",
                (sha, ext_id, json.dumps(res.data) if res.data is not None else None, res.ok, res.error, call_id))
    extraction_id = cur.fetchone()[0]
    cur.execute("select active and 'vector' = any(active_fields) from breach_core.extractor_versions where extractor_id = %s", (ext_id,))
    active = cur.fetchone()[0]
    as_of = (published or datetime.now(timezone.utc)).date()
    for ei in extract.validate(res.data, text):
        basis = forced_basis or ei.basis
        if forced_incident:
            inc = forced_incident
        else:
            org, how = resolve.find_or_create_org(cur, name=ei.organization, domain=norm_domain(ei.domain),
                                                  country=norm_country(ei.country), sector=ei.sector)
            ev = next((date.fromisoformat(c.value) for c in ei.candidates
                       if c.accepted and c.field == "event_date" and len(str(c.value)) == 10), None)
            inc, _ = resolve.resolve_incident(cur, org_id=org, org_how=how, source_id=source_id or "news",
                                              doc=sha + ":" + resolve_key(ei.organization), event_date=ev,
                                              public_date=as_of)
            # From an article, the only flags set directly are "reported" and "claimed". A model's
            # reading that a regulator or the victim said something does not unlock a name.
            resolve.set_flag(cur, inc, "threat_actor_claim" if basis == "threat_actor_claim" else "news")
            if active and basis in ("victim_statement", "news_citing_victim") and any(
                    c.accepted and CONFIRM.search(c.quote) for c in ei.candidates):
                resolve.set_flag(cur, inc, "victim_statement")
        for c in ei.candidates:
            # The candidate's own basis wins when its sentence reports an attacker's claim.
            cb = c.basis if (c.basis == "threat_actor_claim" and not forced_basis) else basis
            file_candidate(ctx, cur, inc, c, cb, source_id or "sec_8k", sha, extraction_id, as_of, text)
    return 1


def resolve_key(org: str) -> str:
    from .normalize import norm_name
    return norm_name(org)[:80]


def file_candidate(ctx, cur, inc, c: extract.Candidate, basis, source_id, sha, extraction_id, as_of, text):
    rep = ctx.report["claims"]
    rep["accepted" if c.accepted else "rejected"] += 1
    if not c.accepted:
        rep["reject_reasons"][c.reject_reason] = rep["reject_reasons"].get(c.reject_reason, 0) + 1
    if basis == "threat_actor_claim" and c.field in ("people_affected", "records_affected", "accounts_affected"):
        return  # the claims table refuses it; the rejection is already counted
    value_num = value_text = None
    unit = extract.UNIT_FOR.get(c.field, "none")
    money = {}
    if c.field in extract.UNIT_FOR:
        try:
            value_num = Decimal(str(c.value))
        except Exception:
            value_text = str(c.value)[:500]
        if unit == "money" and value_num is not None and c.currency:
            cur_code = str(c.currency).upper()
            money = {"money_kind": c.money_kind if c.money_kind in ("demand_initial", "demand_final", "offer", "paid") else "demand_initial",
                     "currency": cur_code if re.fullmatch(r"[A-Z]{3}|BTC|XMR|ETH|USDT", cur_code) else None}
            if money["currency"] and c.accepted:
                r = ctx.fx.usd_rate(money["currency"], as_of)
                if r:
                    rate, fx_date, fx_src = r
                    money.update(amount_usd=(value_num * rate).quantize(Decimal("1")), fx_rate=rate,
                                 fx_date=fx_date, fx_source=fx_src)
            if not money["currency"]:
                return
    elif isinstance(c.value, bool):
        value_text = "true" if c.value else "false"
    else:
        value_text = str(c.value)[:2000] if c.value is not None else None
    if value_num is None and value_text is None:
        return
    if unit == "money" and not money:
        return
    resolve.add_claim(cur, incident_id=inc, field=c.field, value_num=value_num, value_text=value_text,
                      unit=unit, qualifier=c.qualifier if c.qualifier in reconcile.QUAL_RANK else "exact",
                      as_of=as_of, basis=basis, source_id=source_id, doc_sha256=sha, quote=c.quote[:2000] or None,
                      quote_start=c.quote_start, quote_end=c.quote_end, subject_match=c.subject_match,
                      extraction_id=extraction_id, accepted=c.accepted, reject_reason=c.reject_reason, **money)
    if c.accepted and c.field == "cve_id":
        cur.execute("""insert into breach_core.incident_cves (incident_id, cve_id, role, basis)
                       values (%s,%s,%s,%s) on conflict do nothing""",
                    (inc, str(c.value).upper(), c.cve_role or "mentioned", basis))
    if c.accepted and c.quote:
        ctx.new_quotes.append((c.quote, text))


# ---------------------------------------------------------------------------------------------
def run(conn, args, getter=http.get, llm=None, fx=None) -> dict:
    with conn.cursor() as cur:
        run_id = None if args.dry_run else runs_db.start_run(conn, PIPELINE, "incremental", args.trigger,
                                                            os.environ.get("GITHUB_SHA"))
    if not args.dry_run:
        conn.commit()
    ctx = Ctx(conn, run_id, args, getter, llm, fx)
    wanted = [s for s in args.sources.split(",") if s] if args.sources else list(CADENCE_H)
    sources = [s for s in wanted if s != "extract"]
    feeds = {f.source_id: f for f in sources_news.FEEDS}
    for source_id in sources:
        with conn.cursor() as cur:
            if not due(cur, source_id, args.force):
                ctx.report["sources"][source_id] = {"skipped": "not due"}
                continue
        try:
            with conn.transaction():
                with conn.cursor() as cur:
                    if source_id in ("ransomlook", "ransomfeed"):
                        res = run_leak(ctx, cur, source_id)
                    elif source_id == "sec_8k":
                        res = run_sec(ctx, cur)
                    elif source_id in feeds:
                        res = run_feed(ctx, cur, feeds[source_id])
                    else:
                        res = run_structured(ctx, cur, source_id)
                    db.mark_source(cur, source_id, True)
                    if args.dry_run:
                        raise _DryRun()
            ctx.report["sources"].setdefault(source_id, {}).update(ok=True, **res)
        except _DryRun:
            ctx.report["sources"].setdefault(source_id, {}).update(ok=True, dry_run=True, **res)
        except Exception as e:  # noqa: BLE001 - one source must not stop the others
            log.warning("source %s failed: %s", source_id, type(e).__name__)
            ctx.report["sources"].setdefault(source_id, {}).update(ok=False, error=f"{type(e).__name__}: {str(e)[:200]}")
            if not args.dry_run:
                with conn.transaction(), conn.cursor() as cur:
                    db.mark_source(cur, source_id, False, f"{type(e).__name__}: {str(e)[:300]}")
    if not args.sources or "extract" in wanted:
        ctx.report["extraction"] = run_extraction(ctx, conn)
    try:
        with conn.transaction(), conn.cursor() as cur:
            # Leak claims attach by domain to incidents created by any source this run,
            # including the ones that ran after the trackers.
            ctx.report["actor_links"] = link_leak_claims(cur)
            ctx.report["incident_facts"] = reconcile.build(cur)
            results = evals.run_all(cur, ctx)
            if args.dry_run:
                raise _DryRun()
    except _DryRun:
        pass
    ctx.report["evals"] = [dataclasses.asdict(r) for r in results]
    ok = not any(r.severity == "ERROR" and not r.passed for r in results)
    ctx.report["ok"] = ok
    if not args.dry_run:
        runs_db.finish_run(conn, run_id, ok=ok,
                           sources_attempted=sum(1 for v in ctx.report["sources"].values() if "ok" in v),
                           sources_ok=sum(1 for v in ctx.report["sources"].values() if v.get("ok")),
                           notes={"llm": ctx.report["llm"], "claims": ctx.report["claims"]})
        conn.commit()
    return ctx.report


class _DryRun(Exception):
    pass


def backfill_leaks(conn, args, getter=http.get) -> dict:
    """Explicitly invoked, never part of the hourly stream (CLAUDE.md: backfills are separate
    workflows): RansomLook's monthly archive, /api/posts/{year}/{MM}, for the last N complete
    months plus the current one. Folding is the same as hourly, so re-running is harmless."""
    today = datetime.now(timezone.utc).date()
    out = {}
    y, m = today.year, today.month
    months = []
    for _ in range(args.backfill_leak_months + 1):
        months.append((y, m))
        y, m = (y, m - 1) if m > 1 else (y - 1, 12)
    for y, m in reversed(months):
        url = f"https://www.ransomlook.io/api/posts/{y}/{m:02d}"
        f = getter(url, accept="application/json", timeout=120)
        with conn.transaction(), conn.cursor() as cur:
            if not f.ok:
                db.record_fetch(cur, None, "ransomlook", f, None)
                out[f"{y}-{m:02d}"] = {"ok": False, "error": f.error}
                continue
            rows = f.json()
            posts, bad = sources_leak.parse_ransomlook(rows)
            fid = db.record_fetch(cur, None, "ransomlook", f, len(rows) if isinstance(rows, list) else 0)
            counts, _ = db.store_records(cur, "ransomlook", [(p.source_record_id, p.record) for p in posts], fid)
            folded = db.upsert_leak_posts(cur, posts)
            out[f"{y}-{m:02d}"] = {"ok": True, "parsed": len(posts), "malformed": bad, **counts, **folded}
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="zdc-breach")
    ap.add_argument("--sources", default="")
    ap.add_argument("--force", action="store_true", help="ignore per-source cadence")
    ap.add_argument("--max-docs", type=int, default=40)
    ap.add_argument("--sec-days", type=int, default=3)
    ap.add_argument("--max-apply", type=int, default=2000,
                    help="new or changed rows applied per regulator source per run; the rest wait")
    ap.add_argument("--no-llm", action="store_true")
    ap.add_argument("--trigger", default=os.environ.get("GITHUB_EVENT_NAME", "manual"))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--report")
    ap.add_argument("--backfill-leak-months", type=int, default=0,
                    help="backfill RansomLook's monthly archive for N months, then exit")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    conn = psycopg.connect(os.environ["DATABASE_URL"], autocommit=False)
    if args.backfill_leak_months:
        res = backfill_leaks(conn, args)
        text = json.dumps({"backfill": res}, indent=2)
        if args.report:
            with open(args.report, "w") as fh:
                fh.write(text)
        print(text)
        return 0 if all(v.get("ok") for v in res.values()) else 1
    llm = None
    if not args.no_llm:
        key = os.environ.get("OPENROUTER_API_KEY", "")
        if key:
            with conn.cursor() as cur:
                m, d = db.llm_spend(cur)
            conn.rollback()
            llm = OpenRouter(key, m, d)
    report = run(conn, args, llm=llm)
    text = json.dumps(report, indent=2, default=str)
    if args.report:
        with open(args.report, "w") as fh:
            fh.write(text)
    for r in report["evals"]:
        print(f"{'PASS' if r['passed'] else 'FAIL'} [{r['severity']}] {r['name']}: {r['summary']}")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
