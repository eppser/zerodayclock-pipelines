"""Network threat atlas pipeline: collect a week, then score it.

    python -m zdc_netthreat.run                    # collect + score the ISO week that just ended
    python -m zdc_netthreat.run --week 2026-10-05  # a specific week (its Monday)
    python -m zdc_netthreat.run --score-only       # rebuild derived for a week from stored raw
    python -m zdc_netthreat.run --score-only --no-write   # fit and gate a week, write nothing

WHY WEEKLY. CrowdSec's feed answers at most 7 days back and blocklist.de lists 48 hours,
so a monthly run would read a week-long sample and call it a month. One run on Monday
covers the ISO week (Mon-Sun, UTC) that just ended. See migration 0094 and ADR 0006.

THE SCORE IS A PURE FUNCTION OF STORED RAW ROWS. `score` reads net_raw and net_core and
writes net_derived for one week, replacing whatever that week held. No clock inside:
the censoring date is the last day of the scored week.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import math
import os
import signal
import sys
import time

import psycopg

from zdc_kev import db as runs_db

from . import db, evals, model, reference, score_v2, sources
from .aggregate import aggregate, top_categories, union
from .client import Http, Response, redact

PIPELINE = "netthreat"
METHOD = "v1"
METHOD_V2 = "v2"
log = logging.getLogger("zdc_netthreat")
SECRET_ENVS = ("CROWDSEC_CTI_API_KEY", "VULNCHECK_API_TOKEN", "SHODAN_API_KEY",
               "CLOUDFLARE_RADAR_TOKEN", "CLOUDFLARE_EMAIL", "CLOUDFLARE_API_KEY")
#: Research scanners are removed from these feeds only: they are what scanners pollute.
EXCLUDE_RESEARCH = {"crowdsec", "dshield", "blocklist_de", "cins"}


def utc_today() -> dt.date:
    """Today in UTC; a function so tests can move the clock."""
    return dt.datetime.now(dt.timezone.utc).date()


def last_complete_week(today: dt.date) -> dt.date:
    """Monday of the ISO week that ended before `today`."""
    return today - dt.timedelta(days=today.isoweekday() - 1 + 7)


#: Size bands (routed /24s, lower edges, powers of two). The atlas's "worse than 99% of
#: networks this size" line needs how many networks of each size exist, clean ones included.
SIZE_EDGES = [1 << i for i in range(0, 25)]


def size_histogram(size24) -> dict[str, int]:
    hist: dict[str, int] = {}
    for n in size24.values():
        if n <= 0:
            continue
        lo = 1 << (n.bit_length() - 1)
        hist[str(lo)] = hist.get(str(lo), 0) + 1
    return hist


def logical_response(source_id: str, rs: list[Response]) -> Response:
    """Fold a source's requests into one fetch row: first URL, overall window, all-ok,
    and a hash over the list of sub-request hashes."""
    if not rs:
        now = dt.datetime.now(dt.timezone.utc)
        return Response(f"source:{source_id}", 0, None, "no request made", now, now)
    all_ok = all(r.ok for r in rs)
    first_err = next((r.error for r in rs if r.error), None)
    out = Response(rs[0].url, 200 if all_ok else next(r.status for r in rs if not r.ok),
                   None, None if all_ok else first_err, rs[0].requested_at, rs[-1].finished_at)
    # The stored hash is over the list of sub-request hashes: one value that changes if any
    # page changed. Bytes are the real total.
    out.body = "\n".join(f"{r.status} {r.sha256}" for r in rs).encode() if all_ok else None
    out.total_bytes = sum(len(r.body or b"") for r in rs)
    return out


def requests_note(rs: list[Response]) -> list[dict]:
    return [{"url": r.url, "status": r.status, "bytes": len(r.body or b""), "sha256": r.sha256} for r in rs]


# =========================================================================== collect
def collect(conn, run_id, week: dt.date, http: Http, secrets: dict, wanted: list[str], report: dict) -> dict:
    week_end = week + dt.timedelta(days=7)
    ref = {}
    # ---- reference data ----------------------------------------------------------
    t = http.get(reference.PFX_LOG)
    path = reference.latest_pfx2as_path(t.body.decode()) if t.ok else None
    r = http.get(reference.PFX_BASE + path) if path else t
    routing = reference.Routing(r.body) if r.ok else None
    if routing is None:
        raise RuntimeError(f"routing table unavailable: {r.error}")
    total_24 = sum(routing.size24.values())
    fid = db.insert_fetch(conn, run_id, "reference", week, r, records=routing.rows,
                          notes={"kind": "pfx2as", "file": path, "routed_24s_total": total_24,
                                 "size_hist": size_histogram(routing.size24)})
    db.insert_reference(conn, fid, "pfx2as", path, routing.rows)
    # Every routed network's size, for the v2 fit (silent networks are its zeros) and for score-only re-runs.
    report["routed_sizes"] = db.insert_routed_sizes(conn, fid, routing.size24)
    # The same table at /24 grain, for the IP lookup and the netblock map (0112). Public routing data.
    report["routed_runs"] = db.store_routed_runs(conn, path, routing.runs())
    ref["routing_fetch"] = fid
    idx = http.get(reference.ORG_INDEX)
    org_file = reference.latest_org_file(idx.body.decode()) if idx.ok else None
    o = http.get(reference.ORG_INDEX + org_file) if org_file else idx
    orgs, siblings = reference.parse_org(o.body) if o.ok else ({}, {})
    db.insert_reference(conn, db.insert_fetch(conn, run_id, "reference", week, o, records=len(orgs),
                                              notes={"kind": "as_org", "file": org_file}), "as_org", org_file or "", len(orgs))
    rir_texts = {}
    for k, u in reference.RIR_URLS.items():
        x = http.get(u)
        if x.ok:
            rir_texts[k] = x.body.decode("utf-8", "replace")
        db.insert_reference(conn, db.insert_fetch(conn, run_id, "reference", week, x, notes={"kind": "rir_delegated", "rir": k}),
                            "rir_delegated", k, x.body.count(b"|asn|") if x.ok else 0)
    rir = reference.parse_rir(rir_texts)
    p = http.get(reference.PDB_URL)
    pdb = reference.parse_pdb(p.body) if p.ok else {}
    db.insert_reference(conn, db.insert_fetch(conn, run_id, "reference", week, p, records=len(pdb), notes={"kind": "peeringdb"}),
                        "peeringdb", week.isoformat(), len(pdb))
    bt = http.get(reference.BGPTOOLS_URL, headers={"User-Agent": reference.BGPTOOLS_UA})
    bgptools = reference.parse_bgptools(bt.body) if bt.ok else {}
    db.insert_reference(conn, db.insert_fetch(conn, run_id, "reference", week, bt, records=len(bgptools), notes={"kind": "as_names"}),
                        "as_names", week.isoformat(), len(bgptools))
    rs = http.get(reference.RESEARCH_URL)
    research = reference.parse_research(rs.body) if rs.ok else set()
    db.insert_reference(conn, db.insert_fetch(conn, run_id, "reference", week, rs, records=len(research), notes={"kind": "research_scanners"}),
                        "research_scanners", week.isoformat(), len(research))
    conn.commit()
    report["reference"] = {"pfx2as": path, "routed_24s": total_24, "as_org": org_file, "rir": sorted(rir_texts),
                           "peeringdb": len(pdb), "as_names": len(bgptools), "research_scanners": len(research)}

    # ---- sources -------------------------------------------------------------------
    ctx = sources.SourceContext(week, week_end, secrets, routing.asn)
    status, volumes, cs_shares, universe, cf_names = {}, {}, {}, set(), {}
    per_source = {}
    for sid in wanted:
        t0 = time.monotonic()
        try:
            res = sources.ALL[sid](http, ctx)
        except Exception as exc:  # noqa: BLE001 - one source must not sink the others
            res = sources.SourceResult(sid, [], parse_error=redact(f"{type(exc).__name__}: {exc}"))
        lr = logical_response(sid, res.responses)
        notes = {"requests": requests_note(res.responses)[:500], **{k: v for k, v in res.extra.items()
                 if k not in ("cloudflare_lists", "country_rows")}}
        err = res.parse_error
        if res.hits:
            agg = aggregate(res.hits, routing.asn, research if sid in EXCLUDE_RESEARCH else set())
            fid = db.insert_fetch(conn, run_id, sid, week, lr, records=agg.records, ipv4=agg.ipv4,
                                  unmapped=agg.unmapped, excluded=agg.excluded, error=err, notes=notes)
            db.insert_asn_counts(conn, fid, ((a, g.ips, len(g.slash24), top_categories(g.categories), False, None)
                                             for a, g in agg.by_asn.items()))
            volumes[sid] = agg.ipv4
            if sid in sources.IP_SCORED:
                per_source[sid] = agg
            universe |= {a for a, g in agg.by_asn.items() if g.ips >= (3 if sid != "tor_exits" else 1)}
            if sid == "crowdsec":
                cs_shares = {a: (g.categories["data_centre"] / g.ips, g.categories["home_connection"] / g.ips)
                             for a, g in agg.by_asn.items() if g.ips >= 5}
            report.setdefault("mapping", {})[sid] = {"ipv4": agg.ipv4, "unmapped": agg.unmapped, "excluded": agg.excluded}
        elif res.nets:
            fid = db.insert_fetch(conn, run_id, sid, week, lr, records=len(res.nets), error=err, notes=notes)
            db.insert_asn_counts(conn, fid, ((n.asn, n.count, 0, n.categories, n.listed, n.score) for n in res.nets))
            volumes[sid] = len(res.nets) if sid != "shodan" else sum(n.count for n in res.nets)
            universe |= {n.asn for n in res.nets}
        else:
            fid = db.insert_fetch(conn, run_id, sid, week, lr, error=err, notes=notes)
            if "cloudflare_lists" in res.extra:
                rows = res.extra["cloudflare_lists"]
                db.insert_cloudflare(conn, fid, rows)
                volumes[sid] = len(rows)
                universe |= {a for l, rng, a, n, s, k in rows if a and not k and l in ("traffic", "waf", "ip_reputation") and rng == "12w"}
                cf_names.update({a: n for l, rng, a, n, s, k in rows if a and n})
            if "country_rows" in res.extra:
                db.insert_country(conn, fid, res.extra["country_rows"])
                volumes[sid] = len(res.extra["country_rows"])
        conn.commit()
        status[sid] = (lr.status == 200 and not err, err or lr.error)
        log.info("%-22s %s %8s in %.0fs", sid, "ok " if status[sid][0] else "ERR", f"{volumes.get(sid, 0):,}", time.monotonic() - t0)
    report["sources"] = {s: {"ok": status[s][0], "error": status[s][1], "volume": volumes.get(s, 0)} for s in wanted}

    # ---- distinct IPs and /24s per network across all IP feeds (union, not sum) --------------
    db.insert_union(conn, run_id, week, [(a, i, n) for a, (i, n) in union(per_source).items()])
    # ...and per side, so each side's expected bad /24s are de-duplicated over its own feeds (v2).
    for side, feeds in score_v2.m.SIDES.items():
        sub = {sid: per_source[sid] for sid in feeds if sid in per_source}
        db.insert_union_side(conn, run_id, week, side, [(a, i, n) for a, (i, n) in union(sub).items()])
    conn.commit()

    # ---- network profiles for everything with evidence -------------------------------
    rows = []
    for a in sorted(universe):
        if not routing.size24.get(a):
            continue
        og = orgs.get(a)
        pd = pdb.get(a, {})
        rr = rir.get(a, ("", "", ""))
        name = reference.network_name(a, cf_names.get(a), pd.get("name"), bgptools.get(a),
                                      og.org_name if og else None, og.handle if og else None)
        if og and not reference.org_belongs(name, og.handle, og.org_name, rr[0]):
            og = reference.Org(og.handle, None, None, og.cc)   # keep the handle and country, drop the wrong organisation
        dc, home = cs_shares.get(a, (None, None))
        typ, basis = reference.network_type(a, f"{name} {og.handle if og else ''}", pd.get("info_type"), dc, home)
        rows.append(dict(asn=a, name=name[:120], handle=og.handle if og else None, org_id=og.org_id if og else None,
                         org_name=og.org_name if og else None, siblings=max(0, siblings.get(og.org_id, 1) - 1) if og and og.org_id else 0,
                         cc=(og.cc if og and og.cc else rr[1]) or None, rir=rr[0] or None,
                         registered=rr[2] or None, network_type=typ, type_basis=basis,
                         routed_24s=routing.size24.get(a, 0), announced_ipv4=routing.announced.get(a, 0),
                         prefixes=routing.prefixes.get(a, 0), pdb_type=pd.get("info_type") or None,
                         pdb_traffic=pd.get("info_traffic") or None, pdb_scope=pd.get("info_scope") or None,
                         pdb_policy=pd.get("policy_general") or None, website=(pd.get("website") or None),
                         scanner=bool(reference.SCANNER_RX.search(f"{name} {og.org_name if og else ''} {og.handle if og else ''}")),
                         updated_week=week, routing_fetch_id=ref["routing_fetch"]))
    db.upsert_networks(conn, rows)
    conn.commit()
    report["networks"] = len(rows)
    return {"status": status, "volumes": volumes, "routing": routing, "universe": [r["asn"] for r in rows]}


def abuse_contacts(conn, http: Http, asns: list[int], limit: int) -> dict:
    """RIPEstat abuse-contact-finder answers for every RIR. Only role addresses are kept;
    a personal address is recorded as present and dropped."""
    done = {"role": 0, "personal": 0, "none": 0, "error": 0}
    rx = __import__("re").compile(r"^(abuse|noc|security|soc|cert|csirt|support|info|hostmaster|admin|network|ripe|ops|netops|ipadmin)[a-z0-9._+-]*@", __import__("re").I)
    for a in db.abuse_due(conn, asns, limit):
        r = http.get("https://stat.ripe.net/data/abuse-contact-finder/data.json",
                     params={"resource": f"AS{a}", "sourceapp": "zerodayclock"})
        if not r.ok:
            done["error"] += 1
            continue
        contacts = (r.json().get("data") or {}).get("abuse_contacts") or []
        role = next((c for c in contacts if rx.match(c)), None)
        db.set_abuse(conn, a, role, bool(contacts) and role is None)
        done["role" if role else "personal" if contacts else "none"] += 1
        conn.commit()
    return done


# =========================================================================== score
def cf_ratios(rows: list[tuple]) -> dict[int, dict]:
    """Per network, per window: WAF and IP-reputation block share over request share,
    with the bound that applies when one side fell below its ranking."""
    lists, loc, in_cc = {}, {}, {}
    for l, rng, a, s, k in rows:
        if k.startswith("loc:"):
            loc[k[4:]] = float(s)
            continue
        if k.startswith("cc:"):
            in_cc.setdefault(a, []).append((k[3:], float(s)))
            continue
        if l == "bot_class":
            if k == "human" and not a:
                lists.setdefault((l, rng), {})[0] = float(s)
            elif k == "bot" and a:                              # asked per network
                lists.setdefault(("bot_asn", rng), {})[a] = float(s)
            continue
        lists.setdefault((l, rng), {})[a] = float(s)
    out: dict[int, dict] = {}
    for rng in ("12w", "52w"):
        T = lists.get(("traffic", rng), {})
        if not T:
            continue
        tcut = min(T.values())
        for prod, key in (("waf", "waf"), ("ip_reputation", "rep")):
            P = lists.get((prod, rng), {})
            if not P:
                continue
            pcut = min(P.values())
            for a in set(P) | set(T):
                t = T.get(a)
                if a in P:
                    v = (P[a] / (t or tcut), "" if t else "lo")
                else:
                    v = (pcut / t, "hi")
                out.setdefault(a, {})[f"{key}{rng}"] = v
        H = lists.get(("human", rng), {})
        gh = lists.get(("bot_class", rng), {}).get(0)          # global human share, %
        if rng == "12w" and H and gh:
            hcut = min(H.values())
            for a, t in T.items():
                out.setdefault(a, {})["traffic"] = t
                out[a]["bot"] = max(0.0, 1 - (H.get(a, hcut) * gh / 100) / t)
    # Global request share for networks outside the global top 300: the sum over countries of
    # the country's share times the network's share within it. Kept apart from "traffic",
    # which also decides the week's universe and must stay the global ranking.
    for a, parts in in_cc.items():
        if a not in lists.get(("traffic", "12w"), {}):
            out.setdefault(a, {})["traffic_est"] = sum(loc.get(cc, 0.0) * v / 100 for cc, v in parts)
    # A network's own bot share, where it was asked for directly, replaces the estimate
    # derived from the two top-300 lists (they agree within a few points where both exist).
    for a, v in lists.get(("bot_asn", "12w"), {}).items():
        out.setdefault(a, {})["bot"] = v / 100
    return out


def bot_shares(conn, run_id: str, http: Http, secrets: dict, universe: list[int], report: dict) -> None:
    """Ask Radar for the bot share of every network in the week's universe that the top-300
    traffic list did not already cover, and store the rows on this run's Cloudflare fetch
    (raw tables are insert-only, so the rows are appended to it, never rewritten)."""
    with conn.cursor() as cur:
        cur.execute("""select fetch_id from net_raw.fetches where run_id = %s and source_id = 'cloudflare' and ok
                        order by finished_at desc limit 1""", (run_id,))
        r = cur.fetchone()
        if not r:
            report["bot_shares"] = {"skipped": "no Cloudflare fetch in this run"}
            return
        cur.execute("""select asn from net_raw.cloudflare_lists where fetch_id = %s and list = 'traffic'
                        and date_range = '12w' and key = ''""", (r[0],))   # the global list, not the per-country ones
        ranked = {a for (a,) in cur.fetchall()}
    want = [a for a in universe if a not in ranked]
    rows, failed = sources.cloudflare_bot_shares(http, secrets, want)
    db.insert_cloudflare(conn, r[0], rows)
    conn.commit()
    report["bot_shares"] = {"asked": len(want), "answered": len({x[2] for x in rows}), "failed": failed}
    log.info("cloudflare bot share   %d of %d networks answered, %d failed", report["bot_shares"]["answered"], len(want), failed)


def score(conn, week: dt.date, report: dict, http: Http | None = None, run_id: str | None = None, write: bool = True) -> dict:
    # Every routed network's size first, in its own transaction: a refetch for a pre-0102 week is
    # stored before any derived row is touched, so v1 and v2 still land together or not at all.
    size24, size_note = ensure_routed_sizes(conn, week, http, run_id, write)
    routing_file = ensure_routed_runs(conn, week, http, write)
    fetches = db.latest_fetches(conn, week)
    counts = db.counts_for(conn, list(fetches.values()))
    nets = db.networks(conn)
    with conn.cursor() as cur:
        cur.execute("""select notes->>'routed_24s_total' from net_raw.fetches
                        where week_start = %s and source_id = 'reference' and notes->>'kind' = 'pfx2as'
                        order by finished_at desc limit 1""", (week,))
        row = cur.fetchone()
    total_routed = int(row[0]) if row and row[0] else sum(n["routed_24s"] for n in nets.values())
    routed = {a: n["routed_24s"] for a, n in nets.items()}

    # ---- per feed excess -------------------------------------------------------------
    feeds = {s: {a: v[1] for a, v in counts.get(s, {}).items()} for s in sources.IP_SCORED}
    feeds["shodan"] = {a: v[0] for a, v in counts.get("shodan", {}).items()}
    ips = {s: {a: v[0] for a, v in counts.get(s, {}).items()} for s in feeds}
    ex = {s: model.score_feed(c, routed, total_routed) for s, c in feeds.items()}
    pairs = [(e.p, (s, a)) for s, d in ex.items() for a, e in d.items() if e.n > 0]
    chosen, pcut = model.bfdr_select(pairs)
    above = {(s, a) for s, a in chosen if ex[s][a].n >= model.MIN_COUNT and not nets.get(a, {}).get("scanner")}

    # ---- Cloudflare ----------------------------------------------------------------------
    cf = cf_ratios(db.cloudflare_rows(conn, fetches["cloudflare"])) if "cloudflare" in fetches else {}

    # ---- groups and the latent-class fit ---------------------------------------------------
    groups = ["sensors", "cloudflare", "vulncheck", "abusech", "phishing", "shodan"]
    # The week's universe: every network with a count in any source this week or a
    # Cloudflare ranking, and a routed profile. Not every network ever seen.
    seen = set()
    for d in counts.values():
        seen |= set(d)
    seen |= {a for a, c in cf.items() if "traffic" in c or "waf12w" in c}
    universe = sorted(a for a in seen if a in nets and nets[a]["routed_24s"] > 0)
    obs = {}
    for a in universe:
        f = {s: (s, a) in above for s in sources.SENSORS}
        c = cf.get(a, {})
        obs[a] = {
            "sensors": model.sensor_group(f, list(sources.SENSORS)),
            "cloudflare": model.cloudflare_rule(c.get("waf12w"), c.get("rep12w"), c.get("waf52w"), c.get("rep52w"))
                          and not nets[a]["scanner"],
            "vulncheck": ("vulncheck", a) in above,
            "abusech": ("threatfox", a) in above or ("urlhaus", a) in above,
            "phishing": ("phishing_db", a) in above,
            "shodan": ("shodan", a) in above,
            "_sensors": [s for s in sources.SENSORS if f[s]],
        }
    fit = model.lca([[int(obs[a][g]) for g in groups] for a in universe], groups)
    post = dict(zip(universe, fit.posterior))

    # ---- rows ---------------------------------------------------------------------------------
    src_rows = []
    for s, d in ex.items():
        for a, e in d.items():
            cat = (counts.get(s, {}).get(a) or (0, 0, {}))[2] or {}
            src_rows.append((a, s, e.n, ips[s].get(a, 0), e.expected, e.mean, e.lo90, e.hi90, e.p, (s, a) in above, cat))
    uni = db.latest_union(conn, week)
    censored = week + dt.timedelta(days=6)
    net_rows = []
    for a in universe:
        c = cf.get(a, {})
        lst = lambda sid: counts.get(sid, {}).get(a)   # noqa: E731
        net_rows.append((a, post[a], [g for g in groups if obs[a][g]], obs[a]["_sensors"],
                         uni.get(a, (0, 0))[0], uni.get(a, (0, 0))[1],
                         bool(lst("spamhaus_asndrop")), (lst("spamhaus_drop") or (0,))[0],
                         (lst("uceprotect_l3") or (0, 0, {}, False, None))[4], (lst("tor_exits") or (0,))[0],
                         (c.get("waf12w") or (None,))[0], (c.get("rep12w") or (None,))[0],
                         (c.get("waf12w") or (None, None))[1], (c.get("rep12w") or (None, None))[1],
                         c.get("traffic") if c.get("traffic") is not None else c.get("traffic_est"), c.get("bot"), censored))
    model_rows = [(g, fit.hit_rate[i], fit.false_flag_rate[i], fit.prevalence, len(universe), len(pairs), len(chosen), pcut)
                  for i, g in enumerate(groups)]

    # ---- Shadowserver, per internet user -----------------------------------------------------
    crow = db.country_rows(conn, fetches["shadowserver_country"]) if "shadowserver_country" in fetches else []
    country = []
    for ds in ("sinkhole", "honeypot", "honeypot_ddos_amp"):
        by: dict[str, list] = {}
        for d, day, cc, n, pu in crow:
            if d == ds:
                by.setdefault(cc, []).append((n, pu))
        users = {cc: sum(n for n, _ in v) / len(v) / (sum(float(p) for _, p in v if p) / max(1, sum(1 for _, p in v if p))) * 1e6
                 for cc, v in by.items() if any(p for _, p in v)}
        world = sum(sum(n for n, _ in by[cc]) / len(by[cc]) for cc in users) / sum(users.values()) * 1e6 if users else None
        for cc, v in by.items():
            mean = sum(n for n, _ in v) / len(v)
            pus = [float(p) for _, p in v if p]
            pu = sum(pus) / len(pus) if pus else None
            country.append((ds, cc, mean, pu, (pu / world) if pu and world else None))

    # v1 and v2 are written in ONE transaction: a v2 failure must not leave a week with fresh v1
    # rows beside a previous run's v2 rows (the page would show stale v2 against fresh v1).
    if write:
        db.replace_week(conn, week, METHOD, src_rows, net_rows, model_rows, country)
    report["score"] = {"week": week.isoformat(), "networks": len(universe), "pairs": len(pairs), "above": len(above),
                       "p_cutoff": round(pcut, 4), "prevalence": round(fit.prevalence, 4),
                       "score_ge_0_9": sum(1 for v in post.values() if v >= 0.9),
                       "hit_rates": {g: round(h, 3) for g, h in zip(groups, fit.hit_rate)}}

    # ---- v2: two sides, every routed network ---------------------------------------------------
    v2 = score_v2_week(conn, week, counts, nets, total_routed, universe, size24, size_note)
    if write:
        db.replace_week_v2(conn, week, METHOD_V2, v2["rows"], v2["fits"])
        if routing_file:
            report["netblock"] = {"cells": db.replace_netblock_v2(conn, week, METHOD_V2, routing_file), "routing_file": routing_file}
        conn.commit()
    else:
        conn.rollback()
    report["score_v2"] = v2["summary"]
    return {"fit": fit, "groups": groups, "v2": v2}


def shodan_coverage_failed(conn, week: dt.date, floor: float = 0.97) -> bool:
    """True when the week's newest Shodan fetch left a tag under 97% placed (the same rule as
    evals.check_shodan_coverage), or recorded no coverage at all."""
    with conn.cursor() as cur:
        cur.execute("""select notes->'coverage' from net_raw.fetches
                        where week_start = %s and source_id = 'shodan' and ok order by finished_at desc limit 1""", (week,))
        r = cur.fetchone()
    if not r:
        return False                     # no Shodan fetch: the floor marks it absent anyway
    cov = r[0] or {}
    if not cov:
        return True
    return any(c.get("total") and c.get("in_networks", 0) / c["total"] < floor for c in cov.values())


def ensure_routed_sizes(conn, week: dt.date, http: Http | None, run_id: str | None, write: bool) -> tuple[dict[int, int], str]:
    """Every routed network's /24 count for the week. Stored by collect since 0102; a week
    collected before that has none, so the routing file the week was mapped with is fetched
    again from CAIDA by its stored name (read-only, public), recorded as a reference fetch with
    notes.kind = 'pfx2as_refetch' and stored, so it happens once. Commits its own insert."""
    with conn.cursor() as cur:
        cur.execute("select to_regclass('net_derived.fits_v2') is not null and to_regclass('net_raw.routed_sizes') is not null")
        if not cur.fetchone()[0]:
            raise RuntimeError("v2: migration 0102 is not applied to this database (net_derived.fits_v2 missing)")
    size24, routing_file = db.routed_sizes(conn, week)
    if size24:
        return size24, "stored"
    if not routing_file or http is None:
        raise RuntimeError("v2: no routed sizes stored for the week and no routing file to refetch")
    r = http.get(reference.PFX_BASE + routing_file)
    if not r.ok:
        raise RuntimeError(f"v2: routing file {routing_file} unavailable: {r.error}")
    routing = reference.Routing(r.body)
    size24 = dict(routing.size24)
    log.info("v2: routed sizes refetched from %s (%d networks)", routing_file, len(size24))
    if write and run_id:
        # notes.kind tells the two apart; reference_snapshots.kind is constrained to the 0094 set,
        # so the snapshot row keeps kind 'pfx2as' (it IS the same file)
        fid = db.insert_fetch(conn, run_id, "reference", week, r, records=routing.rows,
                              notes={"kind": "pfx2as_refetch", "file": routing_file, "routed_24s_total": sum(size24.values())})
        db.insert_reference(conn, fid, "pfx2as", routing_file, routing.rows)
        db.insert_routed_sizes(conn, fid, size24)
        conn.commit()
    return size24, "refetched:" + routing_file


def ensure_routed_runs(conn, week: dt.date, http: Http | None, write: bool) -> str | None:
    """The week's routing table as /24 runs (0112). Stored by collect; a week collected before 0112
    refetches its routing file by name from CAIDA (public, read-only) once. None when the week has
    no routing file or the schema predates 0112; the scores do not depend on it."""
    with conn.cursor() as cur:
        cur.execute("select to_regclass('net_core.routed_runs') is not null and to_regclass('net_derived.netblock_v2') is not null")
        if not cur.fetchone()[0]:
            log.warning("netblock: migration 0112 not applied; map skipped")
            return None
    routing_file = db.week_routing_file(conn, week)
    if not routing_file:
        return None
    if db.routed_runs_stored(conn, routing_file):
        return routing_file
    if http is None or not write:
        return None
    r = http.get(reference.PFX_BASE + routing_file)
    if not r.ok:
        log.warning("netblock: routing file %s unavailable (%s); map skipped", routing_file, r.error)
        return None
    n = db.store_routed_runs(conn, routing_file, reference.Routing(r.body).runs())
    conn.commit()
    log.info("netblock: %d runs stored from %s", n, routing_file)
    return routing_file


def score_v2_week(conn, week: dt.date, counts: dict, nets: dict, total_routed: int, universe: list[int],
                  size24: dict[int, int], size_note: str) -> dict:
    """Gather the rest of v2's inputs from the stored week and fit both sides."""
    types = {a: n["type"] for a, n in nets.items() if n.get("type")}
    unions, union_runs = {}, {}
    for side, feeds in score_v2.m.SIDES.items():
        unions[side], union_runs[side] = db.latest_union_side(conn, week, side, feeds)
    fallback = db.latest_union(conn, week) if not all(unions.values()) else None
    prev, prev_week = db.previously_listed(conn, week, METHOD_V2)
    # Shodan's facet cap: when a tag's hosts could not all be placed in networks, the count is a
    # top-1,000 sample and the week's test-retest on the host side collapses (review, 2026-10-14).
    # Such a week is scored without Shodan and the side marked provisional.
    force_absent = frozenset({"shodan"}) if shodan_coverage_failed(conn, week) else frozenset()
    t0 = time.monotonic()
    out = score_v2.score_week(week, counts, size24, total_routed, types, unions, prev, universe, fallback_union=fallback,
                              force_absent=force_absent, asndrop={a for a in counts.get("spamhaus_asndrop", {})})
    for f in out["fits"]:
        f["notes"].update({"prev_week": prev_week.get(f["side"]), "union_run_id": union_runs.get(f["side"]),
                           "routed_sizes": size_note})
    out["summary"]["seconds_total"] = round(time.monotonic() - t0, 1)
    out["summary"]["prev_week"] = prev_week
    for side in ("attack", "host"):
        sm = out["summary"][side]
        log.info("v2 %-6s feeds %s absent %s listed %d converged %s in %d it / %.0fs", side, sm["feeds"], sm["absent"],
                 sm["listed"], sm["converged"], sm["iterations"], sm["seconds"])
    return out


# =========================================================================== main
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="zdc-netthreat")
    ap.add_argument("--week", help="Monday of the ISO week to collect/score (default: last complete week)")
    ap.add_argument("--sources", default=",".join(sources.ALL))
    ap.add_argument("--score-only", action="store_true")
    ap.add_argument("--no-write", action="store_true", help="fit and run the gates, write no derived rows (implies --score-only)")
    ap.add_argument("--skip-if-collected", action="store_true",
                    help="exit 0 without a run row when the week already has a successful full collection (the Tuesday retry)")
    ap.add_argument("--abuse-limit", type=int, default=500)
    ap.add_argument("--trigger", default=os.environ.get("GITHUB_EVENT_NAME", "manual"))
    ap.add_argument("--report")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)     # httpx logs URLs, Shodan's carries the key

    if args.no_write:
        args.score_only = True
    # A runner kill must still close the run row. GitHub's cancel sequence is SIGINT, then SIGTERM
    # ~7 s later, then SIGKILL; the workflow wraps this process in `timeout -s TERM` so a TERM
    # arrives from a parent we control. Both are turned into an ordinary exception, which the
    # handler below records as a failed run (KeyboardInterrupt would escape `except Exception`).
    def _killed(signum, _frame):
        raise RuntimeError(f"killed by {signal.Signals(signum).name} (job timeout or cancel?)")
    signal.signal(signal.SIGTERM, _killed)
    signal.signal(signal.SIGINT, _killed)
    week = dt.date.fromisoformat(args.week) if args.week else last_complete_week(utc_today())
    if week.isoweekday() != 1:
        log.error("--week must be a Monday, got %s", week)
        return 2
    if week + dt.timedelta(days=7) > utc_today():
        # a week not yet over would be stored as the newest week and served (audit 2026-10-26)
        log.error("--week %s has not ended yet", week)
        return 2
    secrets = {k: os.environ.get(k, "") for k in SECRET_ENVS}
    wanted = [s.strip() for s in args.sources.split(",") if s.strip()]
    report: dict = {"pipeline": PIPELINE, "week": week.isoformat(), "method": METHOD,
                    "started_at": dt.datetime.now(dt.timezone.utc).isoformat()}
    conn = psycopg.connect(os.environ["DATABASE_URL"], connect_timeout=60)
    if args.skip_if_collected and not args.score_only and db.week_collected(conn, week):
        log.info("week %s already has a successful collection; nothing to retry", week)
        conn.close()
        return 0
    closed = db.close_abandoned_runs(conn)
    if closed:
        log.warning("closed %d abandoned run row(s)", closed)
    conn.commit()
    run_id = runs_db.start_run(conn, PIPELINE, "incremental" if args.score_only else "full", args.trigger,
                               os.environ.get("GITHUB_SHA"))
    conn.commit()
    results = []
    try:
        if not args.score_only:
            http = Http(pause=1.0)
            got = collect(conn, run_id, week, http, secrets, wanted, report)
            report["abuse"] = abuse_contacts(conn, Http(pause=0.8), got["universe"], args.abuse_limit)
            if "cloudflare" in wanted:
                bot_shares(conn, run_id, Http(pause=0.27), secrets, got["universe"], report)
            ipv4 = sum(v["ipv4"] for v in report.get("mapping", {}).values())
            unm = sum(v["unmapped"] for v in report.get("mapping", {}).values())
            results += [evals.check_sources_answered(got["status"]), evals.check_volume_floors(got["volumes"], got["status"]),
                        evals.check_mapping(ipv4, unm)]
            ds = report.get("sources", {}).get("dshield")
            with conn.cursor() as cur:
                cur.execute("""select notes->'scale' from net_raw.fetches where run_id = %s and source_id = 'dshield'""", (run_id,))
                r = cur.fetchone()
            results.append(evals.check_dshield_scale(r[0] if r else None))
            with conn.cursor() as cur:
                cur.execute("""select notes->'coverage' from net_raw.fetches where run_id = %s and source_id = 'shodan'""", (run_id,))
                r = cur.fetchone()
            results.append(evals.check_shodan_coverage(r[0] if r else None))
        else:
            # A score-only rebuild still answers for the week it rebuilds: the collection gates
            # are re-applied to what the week's fetches recorded.
            status, volumes = db.week_fetch_status(conn, week)
            results += [evals.check_sources_answered(status), evals.check_volume_floors(volumes, status)]
        # when the week's snapshot sources were really read, and whether any stopped changing; both
        # judged on the fetches the scores use, so a score-only rebuild answers for them too
        lags = db.week_collection_lag(conn, week)
        report["collection_lag_h"] = {k: round(v, 1) for k, v in lags.items()}
        results += [evals.check_collection_lag(lags),
                    evals.check_feeds_changed(db.feeds_unchanged(conn, week, sources.IP_SCORED))]
        sc = score(conn, week, report, http=Http(pause=1.0), run_id=run_id, write=not args.no_write)
        v2s = sc["v2"]["summary"]
        results += [evals.check_model_sane(sc["fit"].prevalence, dict(zip(sc["groups"], sc["fit"].hit_rate))),
                    evals.check_v2_feeds_present(v2s), evals.check_v2_converged(v2s), evals.check_v2_rows_sane(sc["v2"]["rows"]),
                    evals.check_v2_fit_sane(v2s), evals.check_v2_listed_bounds(v2s), evals.check_v2_single_feed(v2s),
                    evals.check_v2_listed_jump(conn, week, METHOD_V2, v2s), evals.check_v2_feed_totals(conn, week, METHOD_V2, v2s),
                    evals.check_v2_union_measured(v2s, db.side_union_stored(conn, week)), evals.check_v2_rho_range(v2s),
                    evals.check_no_ip_stored(conn)]
        # week-to-week gates against the last non-provisional week (review round 6)
        prev_fits, prev_rows = db.previous_week_v2(conn, week, METHOD_V2)
        results += [evals.check_v2_param_drift(sc["v2"]["fits"], prev_fits),
                    evals.check_v2_floor_stability(sc["v2"]["rows"], prev_rows),
                    evals.check_v2_list_exodus(sc["v2"]["rows"], prev_rows),
                    evals.check_v2_checks_drift(v2s, (prev_fits or {}).get("attack", {}).get("checks") if prev_fits else None)]
        if not args.no_write:
            results.append(evals.check_v2_forward(conn, METHOD_V2))
            results.append(evals.check_netblock(conn, week, METHOD_V2))
        if not args.no_write:
            results += [evals.check_week_replaced(conn, week, METHOD), evals.check_v2_week_replaced(conn, week, METHOD_V2)]
        report["checks"] = [{"name": r.name, "severity": r.severity, "passed": r.passed, "summary": r.summary} for r in results]
        leak = evals.check_no_secret(json.dumps(report, default=str), secrets)
        results.append(leak)
        report["checks"].append({"name": leak.name, "severity": leak.severity, "passed": leak.passed, "summary": leak.summary})
        blocking = [r for r in results if r.blocking]
        report["ok"] = not blocking
        if blocking and not args.no_write:
            # The week stays stored (its raw rows are evidence) but is served as PROVISIONAL, never
            # as a clean latest week: the atlas reads the newest scored week without looking here.
            db.mark_week_blocked(conn, week, METHOD_V2, [r.name for r in blocking])
            report["score_v2"]["blocked"] = [r.name for r in blocking]
            for side in ("attack", "host"):
                if isinstance(report["score_v2"].get(side), dict):
                    report["score_v2"][side]["provisional"] = True
        runs_db.finish_run(conn, run_id, ok=report["ok"], error=None if report["ok"] else "; ".join(r.name for r in blocking),
                           sources_attempted=len(wanted), sources_ok=sum(1 for v in report.get("sources", {}).values() if v["ok"]),
                           entries_seen=sum(v["volume"] for v in report.get("sources", {}).values()),
                           entries_inserted=report.get("score", {}).get("networks", 0),
                           notes={"score": report.get("score"), "score_v2": report.get("score_v2"), "no_write": args.no_write})
        conn.commit()
    except Exception as exc:  # noqa: BLE001
        msg = redact(f"{type(exc).__name__}: {exc}")
        log.error("run failed: %s", msg)
        conn.rollback()
        runs_db.finish_run(conn, run_id, ok=False, error=msg)
        conn.commit()
        report.update({"ok": False, "error": msg})
        _write(args.report, report)
        return 1
    finally:
        conn.close()
    for r in results:
        log.info("[%s] %-5s %s: %s", "PASS" if r.passed else "FAIL", r.severity, r.name, r.summary)
    _write(args.report, report)
    return 0 if report["ok"] else 1


def _write(path, report):
    if path:
        with open(path, "w") as fh:
            json.dump(report, fh, indent=1, default=str)


if __name__ == "__main__":
    sys.exit(main())
