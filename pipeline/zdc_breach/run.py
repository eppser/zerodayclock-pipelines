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

from . import (confidence, db, evals, extract, http, reconcile, resolve, sources_actors, sources_leak, sources_media,
               sources_news, sources_reg, sources_size, thumbs)
from .fx import Fx
from .llm import MODEL, BudgetExceeded, OpenRouter
from .normalize import norm_country, norm_domain

PIPELINE = "breach"
log = logging.getLogger("zdc_breach")

# source_id -> minimum hours between fetches
CADENCE_H = {"ransomlook": 1, "ransomfeed": 1, "sec_8k": 1, "wa_ag": 6, "de_ag": 6, "hibp": 6,
             "ca_ag": 24, "hhs_ocr": 24, "wikidata": 1, "misp_galaxy": 168, "thumbs": 1}
# "gdelt" runs only when asked for (--sources gdelt): from GitHub's runners it answered 4 of 29
# searches in two 30-minute runs (2026-10-14), so in the hourly run it only burns the deadline.
# "thumbs" (owner decision 2026-10-14): header crops are STORED again but never served - 0115
# found them readable at 400 px, so nothing reads them until a human approves each one.
CADENCE_H.update({f.source_id: 1 for f in sources_news.FEEDS})

RANSOMLOOK_URL = "https://www.ransomlook.io/api/last/2"
RANSOMFEED_URL = "https://api.ransomfeed.it/offset/300"
ACTOR_LINK_WINDOW = timedelta(days=60)

def extractor_id(model: str, lang: str = "en") -> str:
    """One extractor version per model, prompt AND language (0130): a Japanese document is
    extracted under "...:ja", which the English gold set never activated. Fields are activated
    per extractor version, so no Japanese fact can publish until a Japanese gold set passes it."""
    base = f"llm:{model}@{extract.prompt_hash(model)}"
    return base if lang == "en" else f"{base}:{lang}"


# A feed summary shorter than this is not worth a model call. Japanese packs about three times
# the content per character: ITmedia's one-sentence summaries (50-180 characters) state the
# organisation, the count and the cause.
MIN_DOC_CHARS = {"en": 200, "ja": 60}


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
        # efts returns 100 hits a page; a backfill (--sec-days 700) needs every page.
        for offset in range(0, 2000, 100):
            f = _fetch(ctx, cur, "sec_8k", sources_reg.efts_url(start, today, offset=offset, form=form),
                       accept="application/json")
            n_fetch += 1
            if not f.ok:
                db.record_fetch(cur, ctx.run_id, "sec_8k", f, None)
                raise RuntimeError(f.error or f"HTTP {f.status}")
            payload = f.json()
            got, b = sources_reg.parse_efts(payload)
            db.record_fetch(cur, ctx.run_id, "sec_8k", f, len(got))
            items += got
            bad += b
            if len((payload.get("hits") or {}).get("hits") or []) < 100:
                break
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


# ---- organisation size (Wikidata) ------------------------------------------------------------
SIZE_BATCH = 25
SIZE_PER_RUN = 300
SIZE_RETRY_DAYS = 90


def run_size(ctx, cur) -> dict:
    """Employees for domains we hold (organisations and leak victims) that were never looked up,
    or whose last lookup is older than 90 days, newest victims first."""
    cur.execute("""with d as (
                       select victim_domain as domain, max(first_seen_at) as seen from breach_core.leak_claims
                        where victim_domain is not null group by 1
                       union all
                       select domain, max(created_at) from breach_core.organizations where domain is not null group by 1)
                   select d.domain from d
                     left join breach_core.org_sizes z using (domain)
                    where z.domain is null or z.looked_up_at < now() - make_interval(days => %s)
                    group by d.domain order by max(d.seen) desc limit %s""", (SIZE_RETRY_DAYS, SIZE_PER_RUN))
    todo = [r[0] for r in cur.fetchall()]
    found = missing = errors = 0
    rows = []
    for i in range(0, len(todo), SIZE_BATCH):
        batch = todo[i:i + SIZE_BATCH]
        f = http.post_form(sources_size.ENDPOINT, {"query": sources_size.query(batch), "format": "json"},
                           accept="application/sparql-results+json")
        ctx.report["sources"].setdefault("wikidata", {})["http"] = f.status
        db.record_fetch(cur, ctx.run_id, "wikidata", f, len(batch) if f.ok else None)
        if not f.ok:
            errors += len(batch)
            rows += [(d, "error", None, None, None) for d in batch]
            continue
        hit = sources_size.parse(sources_size.body_json(f.body), batch)
        for d in batch:
            if d in hit:
                emp, as_of, qid = hit[d]
                rows.append((d, "ok", emp, as_of, qid))
                found += 1
            else:
                rows.append((d, "not_found", None, None, None))
                missing += 1
    if rows:
        with cur.connection.pipeline():
            cur.executemany("""insert into breach_core.org_sizes (domain, outcome, employees, employees_as_of, wikidata_qid, looked_up_at)
                               values (%s,%s,%s,%s,%s, now())
                               on conflict (domain) do update set outcome = excluded.outcome, employees = excluded.employees,
                                   employees_as_of = excluded.employees_as_of, wikidata_qid = excluded.wikidata_qid,
                                   looked_up_at = now()""", rows)
    if todo and errors == len(todo):
        raise RuntimeError("every Wikidata batch failed")
    return {"looked_up": len(todo), "found": found, "not_found": missing, "errors": errors}


# ---- leak-post header thumbnails -------------------------------------------------------------
THUMBS_PER_RUN = 150
THUMB_DAYS = 3650


def run_thumbs(ctx, cur) -> dict:
    """Header crops, stored privately (0115 withdrew serving them; the owner kept storing them,
    2026-10-14). Also records RansomLook's own screenshot URL on every claim that has one."""
    cur.execute("""update breach_core.leak_claims c set screenshot_url = 'https://www.ransomlook.io/' || replace(r.screen, ' ', '%20')
                     from (select distinct on (c2.claim_key) c2.claim_key, r2.record->>'screen' as screen
                             from breach_core.leak_claims c2
                             cross join lateral jsonb_array_elements(c2.tracker_refs) ref
                             join lateral (select record from breach_raw.source_records x
                                            where x.source_id = 'ransomlook' and x.source_record_id = ref->>'id'
                                            order by version desc limit 1) r2 on true
                            where c2.screenshot_url is null and ref->>'source_id' = 'ransomlook'
                              and coalesce(r2.record->>'screen', '') ~ '^screenshots/[^.][^[:space:]]*$'
                            order by c2.claim_key) r
                    where c.claim_key = r.claim_key""")
    linked = cur.rowcount
    cur.execute("""select c.claim_key, r.record->>'screen'
                     from breach_core.leak_claims c
                     cross join lateral jsonb_array_elements(c.tracker_refs) ref
                     join lateral (select record from breach_raw.source_records x
                                    where x.source_id = 'ransomlook' and x.source_record_id = ref->>'id'
                                    order by version desc limit 1) r on true
                     left join breach_core.leak_thumbs t using (claim_key)
                     left join breach_core.thumb_attempts a using (claim_key)
                    where ref->>'source_id' = 'ransomlook' and t.claim_key is null
                      and coalesce(a.attempts, 0) < 3
                      and c.first_seen_at > now() - make_interval(days => %s)
                      and coalesce(r.record->>'screen', '') <> ''
                      and not breach_core.is_generic_name(c.victim_name)
                    order by c.first_seen_at desc limit %s""", (THUMB_DAYS, THUMBS_PER_RUN))
    made = failed = 0
    for key, path in cur.fetchall():
        url = thumbs.screenshot_url(path)
        if not url:
            continue
        f = ctx.get(url, accept="image/*", timeout=60, max_bytes=8_000_000)
        try:
            if not f.ok:
                raise RuntimeError(f.error or f"HTTP {f.status}")
            webp, w, h = thumbs.header_thumb(f.body)
            cur.execute("""insert into breach_core.leak_thumbs (claim_key, source_url, webp, width, height)
                           values (%s,%s,%s,%s,%s) on conflict (claim_key) do nothing""", (key, url, webp, w, h))
            made += 1
        except Exception as e:  # noqa: BLE001 - a bad image is recorded and retried, never fatal
            failed += 1
            cur.execute("""insert into breach_core.thumb_attempts (claim_key, last_error) values (%s,%s)
                           on conflict (claim_key) do update set attempts = breach_core.thumb_attempts.attempts + 1,
                               last_error = excluded.last_error, last_at = now()""", (key, f"{type(e).__name__}"[:200]))
    return {"made": made, "failed": failed, "screenshot_urls": linked}


# ---- actor registry (MISP galaxies + RansomLook groups) ---------------------------------------
def run_actors(ctx, cur) -> dict:
    got = {}
    for sid, url in (("misp_galaxy", sources_actors.MISP_ACTORS), ("misp_galaxy", sources_actors.MISP_RANSOMWARE),
                     ("ransomlook_groups", sources_actors.RANSOMLOOK_GROUPS)):
        f = _fetch(ctx, cur, sid, url, accept="application/json", timeout=120, max_bytes=40_000_000)
        db.record_fetch(cur, ctx.run_id, sid, f, None)
        if not f.ok:
            raise RuntimeError(f"{url.rsplit('/', 1)[-1]}: {f.error or f'HTTP {f.status}'}")
        got[url] = sources_actors.body_json(f.body)
    actors, aliases = sources_actors.build(got[sources_actors.MISP_ACTORS], got[sources_actors.MISP_RANSOMWARE],
                                           got[sources_actors.RANSOMLOOK_GROUPS])
    if len(actors) < 500:
        raise RuntimeError(f"only {len(actors)} actors parsed; refusing to replace the registry")
    # A rebuild replaces: an actor the galaxies dropped must not linger.
    cur.execute("delete from breach_core.actor_aliases")
    cur.execute("delete from breach_core.actors")
    with cur.connection.pipeline():
        cur.executemany("""insert into breach_core.actors (actor_id, display_name, kind, motive, sponsor_country,
                               listed_ransomware, aliases, sources, refs) values (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                        [(a.actor_id, a.display_name[:200], a.kind, a.motive, a.sponsor_country, a.listed_ransomware,
                          sorted(a.aliases)[:200], sorted(a.sources), a.refs) for a in actors])
        cur.executemany("insert into breach_core.actor_aliases (alias_norm, actor_id, alias, source) values (%s,%s,%s,%s)",
                        [(n, aid, alias[:200], src) for n, (aid, alias, src) in aliases.items()])
    db.mark_source(cur, "ransomlook_groups", True)
    return {"actors": len(actors), "aliases": len(aliases),
            "state_sponsored": sum(a.kind == "state_sponsored" for a in actors)}


# ---- what leak posts state about the victim --------------------------------------------------
def parse_leak_facts(cur, limit=20000) -> dict:
    """Data size and revenue the group states, parsed once per claim from the stored posts."""
    cur.execute("""select c.claim_key, string_agg(coalesce(r.record->>'description', '') || ' ' ||
                                               coalesce(r.record->>'victim_notes', ''), ' || ')
                     from breach_core.leak_claims c
                     cross join lateral jsonb_array_elements(c.tracker_refs) ref
                     join lateral (select record from breach_raw.source_records x
                                    where x.source_id = ref->>'source_id' and x.source_record_id = ref->>'id'
                                    order by version desc limit 1) r on true
                    where c.stated_parsed_at is null
                    group by c.claim_key limit %s""", (limit,))
    rows = []
    for key, text in cur.fetchall():
        rows.append((sources_leak.data_size_stated(text), sources_leak.revenue_stated(text), key))
    if rows:
        with cur.connection.pipeline():
            cur.executemany("""update breach_core.leak_claims set data_bytes_stated = %s, revenue_usd_stated = %s,
                                   stated_parsed_at = now() where claim_key = %s""", rows)
    return {"parsed": len(rows), "size": sum(1 for r in rows if r[0]), "revenue": sum(1 for r in rows if r[1])}


# ---- news coverage per victim (GDELT) --------------------------------------------------------
MEDIA_PER_RUN = 300           # searches; in practice the run's deadline decides
MEDIA_RESEARCH_DAYS = 30


def run_media(ctx, cur) -> dict:
    """Victims never searched first - regulator-filed and press-reported before leak claims,
    newest first; a recent victim (<180 days) is searched again after 30 days, as coverage grows."""
    import time
    cur.execute("""select v.victim_id, v.name, v.seen_date
                     from breach_core.victims_list v
                     left join breach_core.media_search_state s using (victim_id)
                    where v.name is not null
                      and (s.victim_id is null
                           or (s.status = 'ok' and s.searched_at < now() - make_interval(days => %s)
                               and v.seen_date > current_date - 180))
                    order by (s.victim_id is null) desc, (v.kind = 'incident') desc, v.seen_date desc nulls last
                    limit %s""", (MEDIA_RESEARCH_DAYS, MEDIA_PER_RUN * 3))
    todo = cur.fetchall()
    today = datetime.now(timezone.utc).date()
    searched = found = skipped = unanswered = 0
    state = []
    for vid, name, seen in todo:
        if searched >= MEDIA_PER_RUN or datetime.now(timezone.utc) > ctx.deadline - timedelta(minutes=2):
            break
        url = sources_media.query_url(name, seen or today, today) if sources_media.searchable(name) else None
        if url is None:
            state.append((vid, "not_searchable", 0))
            skipped += 1
            continue
        if searched:
            time.sleep(sources_media.PACE_S)
        searched += 1
        for attempt in range(sources_media.RETRIES_429 + 1):
            f = _fetch(ctx, cur, "gdelt", url, accept="application/json", timeout=60)
            if f.status != 429:
                break
            db.record_fetch(cur, ctx.run_id, "gdelt", f, None)
            ctx.report["sources"].setdefault("gdelt", {})["throttled"] = \
                ctx.report["sources"].get("gdelt", {}).get("throttled", 0) + 1
            time.sleep(sources_media.RETRY_SLEEP_S)
        if f.status == 429:
            unanswered += 1
            if unanswered >= sources_media.GIVE_UP_AFTER:
                ctx.report["sources"].setdefault("gdelt", {})["rate_limited"] = True
                break      # GDELT is refusing this runner; the rest wait for the next run
            continue       # this victim is not marked searched; it is retried next run
        unanswered = 0
        if not f.ok:
            db.record_fetch(cur, ctx.run_id, "gdelt", f, None)
            state.append((vid, "error", 0))
            continue
        try:
            payload = f.json()
        except ValueError:
            payload = {}    # GDELT answers a bad query with a plain-text message
        hits = sources_media.parse(payload, name)
        db.record_fetch(cur, ctx.run_id, "gdelt", f, len(hits))
        for h in hits:
            cur.execute("""insert into breach_core.victim_media (victim_id, url, title, outlet, published_at, language,
                               found_via, match_basis) values (%s,%s,%s,%s,%s,%s,'gdelt','title_names_victim_and_breach')
                           on conflict (victim_id, url) do nothing""",
                        (vid, h["url"], h["title"], h["outlet"], h["published_at"], h["language"]))
        found += len(hits)
        state.append((vid, "ok", len(hits)))
    if state:
        cur.executemany("""insert into breach_core.media_search_state (victim_id, status, n_found) values (%s,%s,%s)
                           on conflict (victim_id) do update set status = excluded.status, n_found = excluded.n_found,
                               searched_at = now()""", state)
    answered = [x for x in state if x[1] in ("ok", "error")]
    if ctx.report["sources"].get("gdelt", {}).get("rate_limited") and not any(x[1] == "ok" for x in answered):
        raise RuntimeError("GDELT rate-limited this runner before any search completed")
    if answered and all(x[1] == "error" for x in answered):
        raise RuntimeError("every GDELT search failed")
    return {"searched": searched, "links": found, "not_searchable": skipped}


def link_media_from_feeds(cur) -> dict:
    """Every stored news-feed item whose TITLE names a victim (a distinctive name, as a whole
    phrase) and a breach term becomes a media link for that victim (0124). Links only."""
    cur.execute("select victim_id, name, seen_date from breach_core.victims_list where name is not null")
    idx = sources_media.index_names(cur.fetchall())
    cur.execute("""select distinct on (r.record->>'url') r.source_id, r.record->>'url', r.record->>'title', r.record->>'published_at'
                     from breach_raw.source_records r join breach_core.sources s using (source_id)
                    where s.kind = 'news' and r.source_id <> 'gdelt' and coalesce(r.record->>'url', '') ~ '^https?://'
                    order by r.record->>'url', r.version desc""")
    rows = []
    for sid, url, title, published in cur.fetchall():
        if not title or not sources_media.TITLE_EVENT.search(title):
            continue
        try:
            pub = datetime.fromisoformat(published).date() if published else None
        except ValueError:
            pub = None
        for vid, seen in set(sources_media.find_in_title(title, idx)):
            if sources_media.in_window(pub, seen):
                rows.append((vid, url[:2000], title[:500], url.split("/")[2][:200], published, "rss:" + sid))
    # A rebuild replaces: a link that no longer passes the current rule is removed.
    cur.execute("delete from breach_core.victim_media where found_via like 'rss:%'")
    if rows:
        with cur.connection.pipeline():
            cur.executemany("""insert into breach_core.victim_media (victim_id, url, title, outlet, published_at, found_via, match_basis)
                               values (%s,%s,%s,%s,%s,%s,'title_names_victim_and_breach')
                               on conflict (victim_id, url) do nothing""", rows)
    return {"names_indexed": len(idx), "links": len(rows)}


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
        if not feed.extract or len(text) < MIN_DOC_CHARS[extract.language(text, feed.source_id)]:
            continue      # a titles-only feed (ScanNetSecurity) is read for headline links only
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
    ext_id, ext_ja = extractor_id(MODEL), extractor_id(MODEL, "ja")
    ph = extract.prompt_hash(MODEL)
    with conn.transaction(), conn.cursor() as cur:
        for eid, note in ((ext_id, "Awaiting gold-set result before activation"),
                          (ext_ja, "Japanese documents; awaiting a Japanese gold-set result before activation")):
            cur.execute("""insert into breach_core.extractor_versions (extractor_id, kind, model_id, prompt_hash, schema_hash, active, note)
                           values (%s, 'llm', %s, %s, %s, false, %s)
                           on conflict (extractor_id) do nothing""", (eid, MODEL, ph, extract.SCHEMA_VERSION, note))
        cur.execute("""select d.doc_sha256, d.source_id, d.url, d.title, d.published_at, d.text, d.source_record_id
                         from breach_raw.documents d
                        where d.captured_at > now() - interval '21 days'
                          and not exists (select 1 from breach_core.extractions e
                                           where e.doc_sha256 = d.doc_sha256 and e.extractor_id in (%s, %s))
                          and (select count(*) from breach_core.llm_calls c
                                where c.doc_sha256 = d.doc_sha256 and c.prompt_hash = %s and not c.ok) < 2
                        order by d.captured_at desc limit %s""", (ext_id, ext_ja, ph, ctx.args.max_docs))
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
        if datetime.now(timezone.utc) > getattr(ctx, "deadline", datetime.max.replace(tzinfo=timezone.utc)):
            ctx.report["llm"]["deadline_stopped"] = True
            break
    with conn.cursor() as cur:
        cur.execute("""select count(*) from breach_raw.documents d where d.captured_at > now() - interval '21 days'
                         and not exists (select 1 from breach_core.extractions e where e.doc_sha256 = d.doc_sha256
                                                                                 and e.extractor_id in (%s, %s))""",
                    (ext_id, ext_ja))
        left = cur.fetchone()[0]
    return {"extracted": done, "backlog_left": left}


def extract_doc(ctx, cur, sha, text, url, title, *, forced_incident=None, forced_basis=None,
                published=None, source_id=None) -> int:
    """Run the model on one document (cached per extractor version) and file its claims."""
    if ctx.llm is None or ctx.docs_left <= 0 or ctx.report["llm"]["budget_stopped"]:
        return 0
    ext_id = extractor_id(MODEL, extract.language(text, source_id))
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
    return file_output(ctx, cur, sha, text, res.data, ext_id, call_id=call_id, published=published,
                       source_id=source_id, forced_incident=forced_incident, forced_basis=forced_basis)


def file_output(ctx, cur, sha, text, output, ext_id, *, call_id=None, published=None, source_id=None,
                forced_incident=None, forced_basis=None) -> int:
    """Store one extractor output and file its claims through the gate - shared by the OpenRouter
    path above and by zdc_breach.agent_load (Claude subagents), so both pass the same validator."""
    cur.execute("""insert into breach_core.extractions (doc_sha256, extractor_id, output, ok, error, call_id)
                   values (%s,%s,%s,true,null,%s) returning extraction_id""",
                (sha, ext_id, json.dumps(output) if output is not None else None, call_id))
    extraction_id = cur.fetchone()[0]
    as_of = (published or datetime.now(timezone.utc)).date()
    for ei in extract.validate(output, text):
        basis = forced_basis or ei.basis
        if forced_incident:
            inc = forced_incident
        else:
            org, how = resolve.find_or_create_org(cur, name=ei.organization, domain=norm_domain(ei.domain),
                                                  country=norm_country(ei.country), sector=ei.sector,
                                                  name_en=ei.organization_en,
                                                  name_en_in_text=ei.organization_en_in_text)
            ev = next((date.fromisoformat(c.value) for c in ei.candidates
                       if c.accepted and c.field == "event_date" and len(str(c.value)) == 10), None)
            inc, _ = resolve.resolve_incident(cur, org_id=org, org_how=how, source_id=source_id or "news",
                                              doc=sha + ":" + resolve_key(ei.organization), event_date=ev,
                                              public_date=as_of)
            # From an article, the only flags set directly are "reported" and "claimed". A model's
            # reading that a regulator or the victim said something does not unlock a name.
            resolve.set_flag(cur, inc, "threat_actor_claim" if basis == "threat_actor_claim" else "news")
            # No victim confirmation from an article, ever, even with an active extractor:
            # activating one field must not unlock names (advisor review 2). Confirmation
            # comes only from a first-party document - a regulator filing or the victim's own
            # notice - which arrive through the structured sources.
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
    deadline = datetime.now(timezone.utc) + timedelta(minutes=args.deadline_minutes)
    ctx.deadline = deadline
    wanted = [s for s in args.sources.split(",") if s] if args.sources else list(CADENCE_H)
    # GDELT runs last: it uses whatever time the run has left, so it must not starve the others.
    sources = sorted((s for s in wanted if s != "extract"), key=lambda s: s == "gdelt")
    feeds = {f.source_id: f for f in sources_news.FEEDS}
    for source_id in sources:
        # A run that has used its time stops starting new work, finishes cleanly and records
        # itself: the next hourly run picks up what is still due. A job killed by the runner's
        # timeout records nothing, which the watchdog would read as a dead pipeline.
        if datetime.now(timezone.utc) > deadline:
            ctx.report["sources"][source_id] = {"skipped": "run deadline"}
            continue
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
                    elif source_id == "wikidata":
                        res = run_size(ctx, cur)
                    elif source_id == "thumbs":
                        res = run_thumbs(ctx, cur)
                    elif source_id == "misp_galaxy":
                        res = run_actors(ctx, cur)
                    elif source_id == "gdelt":
                        res = run_media(ctx, cur)
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
            ctx.report["confidence_rows"] = confidence.build(cur)
            ctx.report["leak_facts"] = parse_leak_facts(cur)
            ctx.report["feed_media"] = link_media_from_feeds(cur)
            # The public list and its facet counts (0117, 0118): computed once per run, not per
            # request - the live view took 17 s with the API's column list.
            # The shared database's default statement timeout is minutes, not hours; the rebuild
            # reads every victim, so it gets an explicit budget (0120 made it ~3 s locally).
            cur.execute("set local statement_timeout = '10min'")
            cur.execute("select breach_core.rebuild_victims_list()")
            ctx.report["victims_listed"] = cur.fetchone()[0]
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


# Outlets whose WordPress feed pages back through its archive (?paged=N), checked 2026-10-19.
ARCHIVE_FEEDS = ("news_hipaajournal", "news_databreaches", "news_securityaffairs", "news_hackread",
                 "news_comparitech", "news_securityweek", "news_cyberscoop", "news_industrialcyber",
                 # Japanese publishers on WordPress: ?paged=N reaches back months (checked 2026-10-19)
                 "news_jp_securitynext", "news_jp_cybersecurityjp")


def backfill_news(conn, args, getter=http.get) -> dict:
    """Explicitly invoked, never hourly (CLAUDE.md: backfills are separate): an outlet's feed
    archive, page by page (?paged=N, 10 items a page), back to --backfill-news-since. Items are
    stored exactly as the hourly feed run stores them - relevant ones only, feed text only, pages
    never fetched - so the headline-to-victim links and the extractor treat them alike. Stops at
    the first page that fails, is empty, or is entirely older than the cut-off."""
    import time
    since = datetime.fromisoformat(args.backfill_news_since).replace(tzinfo=timezone.utc)
    feeds = {f.source_id: f for f in sources_news.FEEDS}
    wanted = [s for s in (args.sources.split(",") if args.sources else ARCHIVE_FEEDS) if s in ARCHIVE_FEEDS]
    deadline = datetime.now(timezone.utc) + timedelta(minutes=args.deadline_minutes)
    out = {}
    for sid in wanted:
        feed = feeds[sid]
        pages = stored = docs = 0
        stop = "page limit"
        for n in range(args.backfill_news_start_page, args.backfill_news_start_page + args.backfill_news_pages):
            if datetime.now(timezone.utc) > deadline:
                stop = "run deadline"
                break
            url = feed.url + ("&" if "?" in feed.url else "?") + f"paged={n}"
            f = getter(url, accept="application/rss+xml, application/atom+xml, */*", timeout=60)
            with conn.transaction(), conn.cursor() as cur:
                if not f.ok:
                    db.record_fetch(cur, None, sid, f, None)
                    stop = f"HTTP {f.status} at page {n}"
                    break
                try:
                    items = sources_news.parse_feed(sid, f.body)
                except Exception:  # noqa: BLE001 - an unparseable page ends this outlet's backfill
                    db.record_fetch(cur, None, sid, f, None)
                    stop = f"unparseable page {n}"
                    break
                fid = db.record_fetch(cur, None, sid, f, len(items))
                if not items:
                    stop = f"empty page {n}"
                    break
                rel = [i for i in items if i.relevant and (i.published_at is None or i.published_at >= since)]
                counts, changed = db.store_records(cur, sid, [(i.guid, {"url": i.url, "title": i.title,
                                                   "published_at": i.published_at.isoformat() if i.published_at else None,
                                                   "summary": i.summary[:4000]}) for i in rel], fid)
                for it in rel:
                    if it.guid in changed and len(it.summary) >= 200:
                        store_doc(cur, sid, it.url, it.title, it.published_at, it.summary, it.guid)
                        docs += 1
                stored += len(changed)
            pages += 1
            if all(i.published_at is not None and i.published_at < since for i in items):
                stop = f"reached {args.backfill_news_since} at page {n}"
                break
            time.sleep(1.5)
        out[sid] = {"pages": pages, "stored": stored, "documents": docs, "stopped": stop,
                    "next_page": args.backfill_news_start_page + pages}
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="zdc-breach")
    ap.add_argument("--sources", default="")
    ap.add_argument("--force", action="store_true", help="ignore per-source cadence")
    ap.add_argument("--max-docs", type=int, default=15)
    ap.add_argument("--deadline-minutes", type=float, default=15,
                    help="stop starting new sources or documents after this long; the next run continues")
    ap.add_argument("--sec-days", type=int, default=3)
    ap.add_argument("--max-apply", type=int, default=2000,
                    help="new or changed rows applied per regulator source per run; the rest wait")
    ap.add_argument("--no-llm", action="store_true")
    ap.add_argument("--trigger", default=os.environ.get("GITHUB_EVENT_NAME", "manual"))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--report")
    ap.add_argument("--backfill-leak-months", type=int, default=0,
                    help="backfill RansomLook's monthly archive for N months, then exit")
    ap.add_argument("--backfill-news-pages", type=int, default=0,
                    help="backfill N archive pages per outlet (WordPress ?paged=N), then exit")
    ap.add_argument("--backfill-news-start-page", type=int, default=2)
    ap.add_argument("--backfill-news-since", default="2024-01-01")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    conn = psycopg.connect(os.environ["DATABASE_URL"], autocommit=False)
    if args.backfill_news_pages:
        res = backfill_news(conn, args)
        text = json.dumps({"backfill_news": res}, indent=2, default=str)
        if args.report:
            with open(args.report, "w") as fh:
                fh.write(text)
        print(text)
        return 0
    if args.backfill_leak_months:
        res = backfill_leaks(conn, args)
        text = json.dumps({"backfill": res}, indent=2)
        if args.report:
            with open(args.report, "w") as fh:
                fh.write(text)
        print(text)
        return 0 if all(v.get("ok") for v in res.values()) else 1
    llm = None
    # OpenRouter extraction is OFF unless BREACH_LLM=openrouter (owner, 2026-10-14: fill the data
    # with Claude subagents for now - zdc_breach.agent_load - and bring OpenRouter back later).
    if not args.no_llm and os.environ.get("BREACH_LLM", "") == "openrouter":
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
