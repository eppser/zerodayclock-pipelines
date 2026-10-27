"""Source adapters. Each returns the HTTP responses it made and what it parsed.

IP feeds yield Hit(ip, categories); the pipeline maps and aggregates them in memory and
stores only per-network counts (no IP address is persisted - see migration 0094).
Network-level sources (listings, facets) yield NetRow(asn, ...). Every adapter is a
plain function of an Http client and a SourceContext so tests can feed it fixtures.

Measured quirks are documented where they are handled; the full list is in
docs/decisions/0006-network-threat-atlas.md.
"""

from __future__ import annotations

import csv
import datetime as dt
import gzip
import zlib
import io
import json
import logging
import re
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from .client import Http, Response

log = logging.getLogger("zdc_netthreat")

IPV4 = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
TAG = re.compile("[\U000E0000-\U000E007F]")   # invisible prompt-injection carrier (CrowdSec /info)


@dataclass
class Hit:
    ip: str
    categories: tuple[str, ...] = ()


@dataclass
class NetRow:
    asn: int
    count: int = 0
    listed: bool = False
    score: float | None = None
    categories: dict = field(default_factory=dict)


@dataclass
class SourceResult:
    source_id: str
    responses: list[Response]
    hits: list[Hit] = field(default_factory=list)
    nets: list[NetRow] = field(default_factory=list)
    extra: dict = field(default_factory=dict)       # cloudflare lists, country rows, notes
    parse_error: str | None = None


@dataclass
class SourceContext:
    week_start: dt.date
    week_end: dt.date                    # exclusive
    secrets: dict
    routing_asn: callable = None         # ip -> asn, for prefix lists


def _lines_ips(body: bytes) -> list[str]:
    out = []
    for line in body.decode("utf-8", "replace").splitlines():
        m = IPV4.match(line.strip())
        if m:
            out.append(m.group(1))
    return out


# ---- CrowdSec CTI malicious feed ---------------------------------------------------------
CS_FIRE = "https://cti.api.crowdsec.net/v2/fire"
CS_KEYS = {"ssh:bruteforce": "ssh_bruteforce", "pop3/imap:bruteforce": "mail_bruteforce",
           "http:bruteforce": "web_bruteforce", "http:exploit": "web_exploit", "http:dos": "http_flood",
           "http:crawl": "bad_crawling"}


def crowdsec(http: Http, ctx: SourceContext, max_pages: int = 400) -> SourceResult:
    """fire?since=7d, 500 per page (1,000 answers 502), followed until there is no `next`.
    `since` is capped at 7 days by the API (since=30d -> 400), which is why the pipeline
    is weekly. Categories kept per IP: six behaviours, connection type, proxy/botnet
    profile, up to 3 CVEs, and whether CrowdSec first saw it in the last 30 days."""
    key = ctx.secrets.get("CROWDSEC_CTI_API_KEY")
    res = SourceResult("crowdsec", [])
    if not key:
        res.parse_error = "CROWDSEC_CTI_API_KEY is not set"
        return res
    for page in range(1, max_pages + 1):
        r = http.get(CS_FIRE, headers={"x-api-key": key}, params={"since": "7d", "limit": 500, "page": page})
        res.responses.append(r)
        if not r.ok:
            break
        try:
            body = json.loads(TAG.sub("", r.body.decode("utf-8", "replace")))
        except ValueError as e:
            res.parse_error = f"page {page}: {e}"
            break
        for it in body.get("items", []):
            ip = it.get("ip") or ""
            if ":" in ip:
                continue
            cats = [CS_KEYS[b["name"]] for b in it.get("behaviors") or [] if b.get("name") in CS_KEYS]
            cls = {c.get("name") for c in (it.get("classifications") or {}).get("classifications") or []}
            if "connection-type:data-center" in cls: cats.append("data_centre")
            if "connection-type:residential" in cls: cats.append("home_connection")
            if it.get("proxy_or_vpn") or cls & {"proxy:vpn", "proxy:tor", "crowdsec:ai_vpn_proxy", "profile:proxy"}:
                cats.append("proxy_or_vpn")
            if cls & {"profile:likely_botnet", "profile:router", "device:microtik"} or any(c.startswith("botnet:") for c in cls):
                cats.append("router_or_botnet")
            cats += [f"cve:{c}" for c in (it.get("cves") or [])[:3]]
            first = ((it.get("history") or {}).get("first_seen") or "")[:10]
            if first and first >= (ctx.week_end - dt.timedelta(days=30)).isoformat():
                cats.append("first_seen_30d")
            res.hits.append(Hit(ip, tuple(cats)))
        if "next" not in (body.get("_links") or {}) or not body.get("items"):
            break
    return res


# ---- SANS ISC DShield ------------------------------------------------------------------
def dshield(http: Http, ctx: SourceContext) -> SourceResult:
    """The top 10,000 attacking source IPs. `sources/attacks` ranks by distinct targets; it
    answered an empty list for every date from 2026-10-13, so `topips/records` (the same
    sensors' top sources, ranked by reports) stands in when it is empty. Which table was
    used is recorded with the scale."""
    r = http.get("https://isc.sans.edu/api/sources/attacks/10000?json")
    res = SourceResult("dshield", [r])
    endpoint = "sources/attacks"
    try:
        rows = json.loads(r.body) if r.ok else []
        if r.ok and not rows:
            r2 = http.get("https://isc.sans.edu/api/topips/records/10000?json")
            res.responses.append(r2)
            rows = [{"ip": x.get("source"), "attacks": x.get("targets")} for x in json.loads(r2.body)] if r2.ok else []
            endpoint = "topips/records"
        if r.ok:
            res.hits = [Hit(x["ip"]) for x in rows if x.get("ip") and ":" not in x["ip"]]
            att = sorted(int(x.get("attacks") or 0) for x in rows)
            res.extra["scale"] = {"rows": len(rows), "endpoint": endpoint, "min_attacks": att[0] if att else None,
                                  "median_attacks": att[len(att) // 2] if att else None}
    except (ValueError, KeyError, TypeError) as e:
        res.parse_error = str(e)
    return res


# ---- blocklist.de: all.txt, plus per-service lists as categories --------------------------
BL_SERVICES = ("ssh", "mail", "imap", "apache", "bruteforcelogin", "ftp", "sip", "bots")


def blocklist_de(http: Http, ctx: SourceContext) -> SourceResult:
    res = SourceResult("blocklist_de", [])
    svc = {}
    for s in BL_SERVICES:
        r = http.get(f"https://lists.blocklist.de/lists/{s}.txt")
        res.responses.append(r)
        if r.ok:
            for ip in _lines_ips(r.body):
                svc.setdefault(ip, []).append(s)
    r = http.get("https://lists.blocklist.de/lists/all.txt")
    res.responses.append(r)
    if r.ok:
        res.hits = [Hit(ip, tuple(svc.get(ip, ()))) for ip in _lines_ips(r.body)]
    return res


def cins(http: Http, ctx: SourceContext) -> SourceResult:
    r = http.get("https://cinsscore.com/list/ci-badguys.txt")
    return SourceResult("cins", [r], hits=[Hit(ip) for ip in _lines_ips(r.body)] if r.ok else [])


# ---- VulnCheck attacker infrastructure (bulk backup) -------------------------------------
def vc_category(classes: list[str]) -> str:
    s = " ".join(classes)
    if "c2:" in s: return "c2_server"
    if "botnet" in s or "iptv" in s: return "botnet_node"
    if "interactsh" in s or "acunetix" in s or "wrthug" in s: return "attack_tooling"
    return "other_infrastructure"


def vulncheck(http: Http, ctx: SourceContext) -> SourceResult:
    """The backup endpoint returns a signed URL to a zip of JSON lines. Kept: records whose
    last_seen falls in the scored week. cdn:* records (CDN edges in front of something)
    are excluded and counted."""
    key = ctx.secrets.get("VULNCHECK_API_TOKEN")
    res = SourceResult("vulncheck", [])
    if not key:
        res.parse_error = "VULNCHECK_API_TOKEN is not set"
        return res
    r = http.get("https://api.vulncheck.com/v3/backup/vulncheck-attacker-infrastructure",
                 headers={"Authorization": f"Bearer {key}", "Accept": "application/json"})
    res.responses.append(r)
    if not r.ok:
        return res
    try:
        meta = r.json()["data"][0]
    except (ValueError, KeyError, IndexError) as e:
        res.parse_error = f"backup index: {e}"
        return res
    z = http.get(meta["url"])
    z.url = z.url.split("?")[0]           # the signed query string is a credential
    res.responses.append(z)
    if not z.ok:
        return res
    if meta.get("sha256") and z.sha256 != meta["sha256"]:
        res.parse_error = "backup checksum mismatch"
        return res
    lo, hi = ctx.week_start.isoformat(), ctx.week_end.isoformat()
    cdn = 0
    with zipfile.ZipFile(io.BytesIO(z.body)) as zf:
        for name in zf.namelist():
            for line in zf.open(name):
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                ip = rec.get("ip") or ""
                if not ip or ":" in ip:
                    continue
                if not (lo <= (rec.get("last_seen") or "")[:10] < hi):
                    continue
                classes = rec.get("classifications") or []
                if any(c.startswith("cdn:") for c in classes):
                    cdn += 1
                    continue
                res.hits.append(Hit(ip, (vc_category(classes),)))
    res.extra["cdn_excluded"] = cdn
    return res


# ---- abuse.ch -------------------------------------------------------------------------------
def threatfox(http: Http, ctx: SourceContext) -> SourceResult:
    r = http.get("https://threatfox.abuse.ch/export/csv/ip-port/recent/")
    res = SourceResult("threatfox", [r])
    if r.ok:
        rows = csv.reader((l for l in r.body.decode("utf-8", "replace").splitlines() if not l.startswith("#")),
                          skipinitialspace=True)
        for row in rows:
            if len(row) > 7 and row[3] == "ip:port":
                ip = row[2].rsplit(":", 1)[0]
                if IPV4.match(ip):
                    res.hits.append(Hit(ip, (f"family:{(row[7] or row[5])[:40]}",)))
    return res


def urlhaus(http: Http, ctx: SourceContext) -> SourceResult:
    r = http.get("https://urlhaus.abuse.ch/downloads/csv_online/")
    res = SourceResult("urlhaus", [r])
    if r.ok:
        rows = csv.reader(l for l in r.body.decode("utf-8", "replace").splitlines() if not l.startswith("#"))
        for row in rows:
            if len(row) > 2:
                m = re.match(r"https?://(\d+\.\d+\.\d+\.\d+)", row[2])
                if m:
                    res.hits.append(Hit(m.group(1)))
    return res


def phishing_db(http: Http, ctx: SourceContext) -> SourceResult:
    r = http.get("https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-IPs-ACTIVE.txt")
    return SourceResult("phishing_db", [r], hits=[Hit(ip) for ip in _lines_ips(r.body)] if r.ok else [])


# ---- Shodan facets ----------------------------------------------------------------------------
SHODAN_TAGS = ("compromised", "c2", "malware", "doublepulsar")
SHODAN_FACET_CAP = 1000     # the oss plan refuses a larger facet ("Facet size too big")


def shodan(http: Http, ctx: SourceContext) -> SourceResult:
    """host/count with facets=asn:1000 for each compromise tag. Counts cost no query credits
    (verified on the oss plan). The plan caps a facet at 1,000 networks, and tag:compromised
    spans more than that (2026-10-12: 1,000 networks returned 18,622 of 20,324 hosts). A tag
    that fills the cap is therefore re-asked one country at a time: a host has one country,
    so per-country network counts add up exactly, and no country comes near 1,000 networks.
    `extra` records each tag's total against what the facets returned."""
    key = ctx.secrets.get("SHODAN_API_KEY")
    res = SourceResult("shodan", [])
    if not key:
        res.parse_error = "SHODAN_API_KEY is not set"
        return res

    def count(query: str, facet: str):
        # Shodan only accepts the key as a query parameter. The stored URL is rebuilt
        # without it (see the url CHECK in net_raw.fetches).
        r = http.get("https://api.shodan.io/shodan/host/count",
                     params={"key": key, "query": query, "facets": facet})
        r.url = f"https://api.shodan.io/shodan/host/count?query={query}&facets={facet}"
        res.responses.append(r)
        return r.json() if r.ok else None

    nets: dict[int, NetRow] = {}
    coverage: dict[str, dict] = {}
    for tag in SHODAN_TAGS:
        d = count(f"tag:{tag}", f"asn:{SHODAN_FACET_CAP}")
        if d is None:
            continue
        facets = [d.get("facets", {}).get("asn", [])]
        split = len(facets[0]) >= SHODAN_FACET_CAP
        if split:
            c = count(f"tag:{tag}", "country:300")
            countries = [f["value"] for f in (c or {}).get("facets", {}).get("country", [])]
            per = [count(f"tag:{tag} country:{cc}", f"asn:{SHODAN_FACET_CAP}") for cc in countries]
            if c is not None and all(x is not None for x in per):
                facets = [x.get("facets", {}).get("asn", []) for x in per]
            else:
                split = False           # a country failed: keep the capped global answer
        got = 0
        for fl in facets:
            for f in fl:
                a = int(str(f["value"]).lower().lstrip("as"))
                row = nets.setdefault(a, NetRow(a))
                row.count += int(f["count"])
                row.categories[tag] = row.categories.get(tag, 0) + int(f["count"])
                got += int(f["count"])
        coverage[tag] = {"total": int(d.get("total", 0)), "in_networks": got, "split_by_country": split}
    res.nets = list(nets.values())
    res.extra = {"coverage": coverage}
    return res


def cloudflare_bot_shares(http: Http, secrets: dict, asns: list[int], rng: str = "12w",
                          workers: int = 8, budget: float = 2400.0) -> tuple[list[tuple], int]:
    """Radar's bot share for each network, asked one network at a time. The top-AS lists stop
    at 300 networks, so without this most scored networks have no bot share. Radar allows
    1,200 calls per 5 minutes; the caller's `http` sets the pace. A 12-week per-network
    summary takes about 3 s to answer, so the calls run on `workers` threads (the shared
    pace still caps the rate), and calls not started within `budget` seconds count as
    failed rather than holding up the run. A network Radar has too little traffic for
    answers with an empty summary and is skipped. Returns the rows (in the
    cloudflare_lists shape) and the number of failed calls."""
    h = _cf_headers(secrets)
    if not h:
        return [], len(asns)
    deadline = time.monotonic() + budget

    def one(a: int):
        if time.monotonic() > deadline:
            return None
        r = http.get(CF + "http/summary/bot_class", headers=h, params={"asn": a, "dateRange": rng})
        if not r.ok:
            return None
        return [("bot_class", rng, int(a), None, float(v), k)
                for k, v in (r.json().get("result", {}).get("summary_0") or {}).items() if k in ("bot", "human")]

    rows, failed = [], 0
    with ThreadPoolExecutor(workers) as pool:
        for i, got in enumerate(pool.map(one, asns), 1):
            if got is None:
                failed += 1
            else:
                rows += got
            if i % 500 == 0:
                log.info("cloudflare bot share   %d of %d asked", i, len(asns))
    return rows, failed


# ---- listings ------------------------------------------------------------------------------------
def spamhaus_asndrop(http: Http, ctx: SourceContext) -> SourceResult:
    r = http.get("https://www.spamhaus.org/drop/asndrop.json")
    res = SourceResult("spamhaus_asndrop", [r])
    if r.ok:
        for line in r.body.decode().splitlines():
            if line.startswith('{"asn"'):
                res.nets.append(NetRow(int(json.loads(line)["asn"]), listed=True))
    return res


def spamhaus_drop(http: Http, ctx: SourceContext) -> SourceResult:
    """DROP lists address ranges; each is charged to the network announcing it today."""
    r = http.get("https://www.spamhaus.org/drop/drop_v4.json")
    res = SourceResult("spamhaus_drop", [r])
    if r.ok and ctx.routing_asn:
        cnt: dict[int, int] = {}
        for line in r.body.decode().splitlines():
            if not line.startswith('{"cidr"'):
                continue
            ip, ln = json.loads(line)["cidr"].split("/")
            o = list(map(int, ip.split(".")))
            n = 1 << max(0, 24 - int(ln))
            base = (o[0] << 16) | (o[1] << 8) | o[2]
            seen = set()
            for k in range(base, base + min(n, 65536), max(1, n // 64)):
                a = ctx.routing_asn(f"{k >> 16}.{(k >> 8) & 255}.{k & 255}.0")
                if a and a not in seen:
                    seen.add(a)
                    cnt[a] = cnt.get(a, 0) + 1
        res.nets = [NetRow(a, count=c, listed=True) for a, c in cnt.items()]
    return res


def _gunzip_capped(data: bytes, cap: int = 512 * 1024 ** 2) -> bytes:
    """gzip.decompress with an output ceiling: the list is fetched over plain http (the mirror offers no https), so
    anyone on the path could hand the runner a decompression bomb (security review 2026-10-26)."""
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out = d.decompress(data, cap + 1)
    if len(out) > cap or d.unconsumed_tail:
        raise ValueError(f"uceprotect list inflates past {cap:,} bytes")
    return out


def uceprotect_l3(http: Http, ctx: SourceContext) -> SourceResult:
    r = http.get("http://wget-mirrors.uceprotect.net/rbldnsd-all/dnsbl-3.uceprotect.net.gz")
    res = SourceResult("uceprotect_l3", [r])
    if r.ok:
        scores: dict[int, float] = {}
        # The server sends Content-Encoding: gzip on some mirrors, so the client may have
        # decompressed it already (measured 2026-10-12). Accept either.
        raw = _gunzip_capped(r.body) if r.body[:2] == b"\x1f\x8b" else r.body
        for line in raw.decode("utf-8", "replace").splitlines():
            if True:
                m = re.search(r"/AS(\d+) is UCEPROTECT-Level3 listed because of a spamscore of (\d+(?:\.\d+)?)", line)
                if m:
                    scores[int(m.group(1))] = float(m.group(2))
        res.nets = [NetRow(a, listed=True, score=s) for a, s in scores.items()]
    return res


def tor_exits(http: Http, ctx: SourceContext) -> SourceResult:
    r = http.get("https://check.torproject.org/torbulkexitlist")
    return SourceResult("tor_exits", [r], hits=[Hit(ip) for ip in _lines_ips(r.body)] if r.ok else [])


# ---- Cloudflare Radar ------------------------------------------------------------------------
CF = "https://api.cloudflare.com/client/v4/radar/"


def _cf_headers(secrets: dict) -> dict | None:
    if secrets.get("CLOUDFLARE_RADAR_TOKEN"):
        return {"Authorization": f"Bearer {secrets['CLOUDFLARE_RADAR_TOKEN']}"}
    if secrets.get("CLOUDFLARE_EMAIL") and secrets.get("CLOUDFLARE_API_KEY"):
        return {"X-Auth-Email": secrets["CLOUDFLARE_EMAIL"], "X-Auth-Key": secrets["CLOUDFLARE_API_KEY"]}
    return None


def cloudflare(http: Http, ctx: SourceContext) -> SourceResult:
    """Top-300 traffic and human lists and top-200 attack-origin lists per product, for
    the 12- and 52-week windows the rule uses and for the scored week itself."""
    res = SourceResult("cloudflare", [])
    h = _cf_headers(ctx.secrets)
    if not h:
        res.parse_error = "no Cloudflare Radar credential"
        return res
    rows = []
    end = f"{ctx.week_end.isoformat()}T00:00:00Z"
    for rng in ("7d", "12w", "52w"):
        q = ({"dateStart": f"{ctx.week_start.isoformat()}T00:00:00Z", "dateEnd": end} if rng == "7d"
             else {"dateRange": rng})
        jobs = [("traffic", "http/top/ases", {"limit": 300}), ("human", "http/top/ases", {"limit": 300, "botClass": "LIKELY_HUMAN"}),
                ("waf", "attacks/layer7/top/ases/origin", {"limit": 200, "mitigationProduct": "WAF"}),
                ("ip_reputation", "attacks/layer7/top/ases/origin", {"limit": 200, "mitigationProduct": "IP_REPUTATION"}),
                ("ddos", "attacks/layer7/top/ases/origin", {"limit": 200, "mitigationProduct": "DDOS"})]
        for name, path, p in jobs:
            r = http.get(CF + path, headers=h, params={**q, **p})
            res.responses.append(r)
            if r.ok:
                for x in r.json().get("result", {}).get("top_0", []):
                    a = x.get("clientASN") or x.get("originAsn")
                    rows.append((name, rng, int(a), x.get("clientASName") or x.get("originAsnName"), float(x["value"]), ""))
        r = http.get(CF + "http/summary/bot_class", headers=h, params=q)
        res.responses.append(r)
        if r.ok:
            for k, v in (r.json().get("result", {}).get("summary_0") or {}).items():
                rows.append(("bot_class", rng, 0, None, float(v), k))
        r = http.get(CF + "attacks/layer7/summary/mitigation_product", headers=h, params=q)
        res.responses.append(r)
        if r.ok:
            for k, v in (r.json().get("result", {}).get("summary_0") or {}).items():
                rows.append(("mix", rng, 0, None, float(v), k))
    # Traffic share beyond the global top 300: each country's top 300 networks, weighted by
    # the country's share of global requests, place about ten times as many networks
    # (AS13238 Yandex is 5% of Russia's requests and not in the global top 300). Stored as
    # key 'loc:CC' (a country's global share) and 'cc:CC' (a network's share within it).
    r = http.get(CF + "http/top/locations", headers=h, params={"dateRange": "12w", "limit": 300})
    res.responses.append(r)
    if r.ok:
        for x in r.json().get("result", {}).get("top_0", []):
            cc, v = x.get("clientCountryAlpha2"), float(x["value"])
            if not cc or v <= 0:
                continue
            rows.append(("traffic", "12w", 0, None, v, f"loc:{cc}"))
            q = http.get(CF + "http/top/ases", headers=h, params={"dateRange": "12w", "limit": 300, "location": cc})
            res.responses.append(q)
            if q.ok:
                for y in q.json().get("result", {}).get("top_0", []):
                    rows.append(("traffic", "12w", int(y["clientASN"]), y.get("clientASName"), float(y["value"]), f"cc:{cc}"))
    res.extra["cloudflare_lists"] = rows
    return res


# ---- Shadowserver dashboard, per country ---------------------------------------------------------
SS_MAP = "https://dashboard.shadowserver.org/statistics/combined/map/"


def shadowserver_country(http: Http, ctx: SourceContext) -> SourceResult:
    """Seven days x three datasets x (count, count per million internet users). The
    dashboard groups by country only; per-network reports go to network owners."""
    res = SourceResult("shadowserver_country", [])
    rows = []
    for ds in ("sinkhole", "honeypot", "honeypot_ddos_amp"):
        for i in range(7):
            day = ctx.week_start + dt.timedelta(days=i)
            got = {}
            for data_set in ("count", "count_per_internet_users"):
                r = http.get(SS_MAP, params={"json": 1, "date_range": "other_value", "day": day.isoformat(),
                                             "source": ds, "geo": "all", "data_set": data_set})
                res.responses.append(r)
                if r.ok:
                    try:
                        got[data_set] = {k: v["count"] for k, v in (r.json().get("geo_data") or {}).items()}
                    except (ValueError, AttributeError, KeyError) as e:
                        res.parse_error = f"{ds} {day}: {e}"
            for cc, n in got.get("count", {}).items():
                if re.fullmatch(r"[A-Z]{2}", cc or ""):
                    rows.append((ds, day, cc, int(n), got.get("count_per_internet_users", {}).get(cc)))
    res.extra["country_rows"] = rows
    return res


ALL = {"crowdsec": crowdsec, "dshield": dshield, "blocklist_de": blocklist_de, "cins": cins,
       "vulncheck": vulncheck, "threatfox": threatfox, "urlhaus": urlhaus, "phishing_db": phishing_db,
       "shodan": shodan, "spamhaus_asndrop": spamhaus_asndrop, "spamhaus_drop": spamhaus_drop,
       "uceprotect_l3": uceprotect_l3, "tor_exits": tor_exits, "cloudflare": cloudflare,
       "shadowserver_country": shadowserver_country}
#: Sources whose IP hits are scored, and the feed id their counts carry in net_derived.
IP_SCORED = ("crowdsec", "dshield", "blocklist_de", "cins", "vulncheck", "threatfox", "urlhaus", "phishing_db")
SENSORS = ("crowdsec", "dshield", "blocklist_de", "cins")
