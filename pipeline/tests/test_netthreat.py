"""zdc_netthreat unit tests: the model, aggregation and source parsers.

All addresses are from the documentation ranges (RFC 5737: 192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24) and all networks are private-use ASNs (64496-64511, RFC 5398).
"""

from __future__ import annotations

import datetime as dt
import gzip
import io
import json
import math
import random
import zipfile

import pytest

from zdc_netthreat import aggregate as ag
from zdc_netthreat import model as m
from zdc_netthreat import reference as ref
from zdc_netthreat import run as nrun
from zdc_netthreat import sources as src
from zdc_netthreat.client import Response, redact


# ---- model ---------------------------------------------------------------------------------
def test_poisson_cdf_known_values():
    assert m.poisson_cdf(0, 1.0) == pytest.approx(math.exp(-1))
    assert m.poisson_cdf(5, 3.0) == pytest.approx(0.916082, abs=1e-6)
    assert m.poisson_cdf(6, 3.0) == pytest.approx(0.966491, abs=1e-6)
    # Large lambda must not underflow to 0 (the first term is e^-2000).
    assert 0.4 < m.poisson_cdf(2000, 2000.0) < 0.6


def test_tiny_network_needs_six_slash24s():
    """The page says a network with no expected traffic needs ~6 occupied /24s. This is
    that sentence as arithmetic; it fails if the prior or threshold changes."""
    assert m.p_excess(5, 0.0) < 0.95 <= m.p_excess(6, 0.0)


def test_large_network_needs_many():
    # 10 /24s where 10 are expected is not an excess.
    assert m.p_excess(10, 10.0) < 0.01
    # 100 where 10 are expected is.
    assert m.p_excess(100, 10.0) > 0.999


def test_gamma_quantile_inverts_cdf():
    e = m.excess(20, 4.0)
    assert e.lo90 < e.mean < e.hi90
    shape, rate = 21, 5.0
    assert 1 - m.poisson_cdf(shape - 1, rate * e.lo90) == pytest.approx(0.05, abs=1e-6)
    assert 1 - m.poisson_cdf(shape - 1, rate * e.hi90) == pytest.approx(0.95, abs=1e-6)


def test_score_feed_uses_whole_internet_denominator():
    routed = {64496: 10, 64497: 90}
    # 10 /24s seen in a feed over an internet of 1,000 routed /24s: rate 0.01 per /24.
    r = m.score_feed({64496: 10}, routed, total_routed=1000)
    assert r[64496].expected == pytest.approx(0.1)
    # If the denominator were only the networks present (100), expected would be 1.0.
    assert r[64496].expected != pytest.approx(1.0)


def test_bfdr_keeps_mean_false_rate_under_level():
    pairs = [(0.999, "a"), (0.99, "b"), (0.9, "c"), (0.5, "d"), (0.1, "e")]
    keep, cut = m.bfdr_select(pairs, 0.05)
    assert keep == {"a", "b", "c"}            # mean(1-p) = (0.001+0.01+0.1)/3 = 0.037
    assert cut == 0.9
    keep2, _ = m.bfdr_select(pairs, 0.01)
    assert keep2 == {"a", "b"}
    # a alone has mean (1-p) 0.04; adding b makes it 0.095, over 5% but under 15%.
    keep3, _ = m.bfdr_select([(0.96, "a"), (0.85, "b")], 0.05)
    assert keep3 == {"a"}
    assert m.bfdr_select([(0.5, "z")], 0.05) == (set(), 1.0)


def test_lca_recovers_simulated_parameters():
    rnd = random.Random(7)
    se, fp, pi = [0.8, 0.6, 0.5], [0.02, 0.05, 0.01], 0.1
    rows, truth = [], []
    for _ in range(4000):
        bad = rnd.random() < pi
        truth.append(bad)
        rows.append([int(rnd.random() < (se[j] if bad else fp[j])) for j in range(3)])
    fit = m.lca(rows, ["a", "b", "c"])
    assert fit.prevalence == pytest.approx(pi, abs=0.03)
    for j in range(3):
        assert fit.hit_rate[j] == pytest.approx(se[j], abs=0.08)
        assert fit.false_flag_rate[j] == pytest.approx(fp[j], abs=0.03)
    # The posterior ranks truly bad networks above clean ones.
    bad_mean = sum(p for p, t in zip(fit.posterior, truth) if t) / sum(truth)
    clean_mean = sum(p for p, t in zip(fit.posterior, truth) if not t) / (len(truth) - sum(truth))
    assert bad_mean > 0.6 > 0.1 > clean_mean


def test_lca_is_deterministic():
    rows = [[1, 0, 1], [0, 0, 0], [1, 1, 1], [0, 1, 0]] * 50
    assert m.lca(rows, list("abc")).posterior == m.lca(rows, list("abc")).posterior


def test_sensor_quorum():
    s = ["crowdsec", "dshield", "blocklist_de", "cins"]
    assert not m.sensor_group({"crowdsec": True, "dshield": False, "blocklist_de": False, "cins": False}, s)
    assert m.sensor_group({"crowdsec": True, "dshield": True, "blocklist_de": False, "cins": False}, s)
    # With only one sensor active, one is enough.
    assert m.sensor_group({"crowdsec": True}, s)


def test_cloudflare_rule_needs_both_signals_both_windows():
    ok = (3.0, "")
    assert m.cloudflare_rule(ok, ok, ok, ok)
    assert not m.cloudflare_rule(ok, (1.9, ""), ok, ok)          # reputation below 2x
    assert not m.cloudflare_rule(ok, ok, ok, (5.0, "hi"))        # an upper bound is never enough
    assert m.cloudflare_rule((4.0, "lo"), ok, ok, ok)            # a lower bound above 2x is enough
    assert not m.cloudflare_rule(None, ok, ok, ok)


# ---- aggregation ------------------------------------------------------------------------------
ASN = {"192.0.2": 64496, "198.51.100": 64497, "203.0.113": 64498}


def asn_of(ip):
    return ASN.get(ip.rsplit(".", 1)[0], 0)


def test_aggregate_dedupes_excludes_and_skips_ipv6():
    hits = [src.Hit("192.0.2.1", ("ssh",)), src.Hit("192.0.2.1", ("ssh",)), src.Hit("192.0.2.2"),
            src.Hit("2001:db8::1"), src.Hit("198.51.100.7"), src.Hit("10.9.9.9")]
    r = ag.aggregate(hits, asn_of, exclude={"198.51.100.7"})
    assert r.ipv4 == 4 and r.excluded == 1 and r.unmapped == 1
    assert r.by_asn[64496].ips == 2 and len(r.by_asn[64496].slash24) == 1
    assert r.by_asn[64496].categories["ssh"] == 1


def test_union_counts_an_ip_once_across_feeds():
    a = ag.aggregate([src.Hit("192.0.2.1"), src.Hit("192.0.2.2")], asn_of)
    b = ag.aggregate([src.Hit("192.0.2.1"), src.Hit("203.0.113.5")], asn_of)
    u = ag.union({"x": a, "y": b})
    assert u[64496] == (2, 1)                 # not 3
    assert u[64498] == (1, 1)


def test_top_categories_caps_cves():
    import collections
    c = collections.Counter({f"cve:CVE-2030-{i}": i for i in range(1, 20)})
    c["ssh"] = 4
    out = ag.top_categories(c)
    assert out["ssh"] == 4 and sum(1 for k in out if k.startswith("cve:")) == 5


# ---- reference ---------------------------------------------------------------------------------
def pfx2as_gz(lines):
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as g:
        g.write("\n".join(lines).encode())
    return buf.getvalue()


def test_routing_most_specific_wins_and_moas_takes_first():
    r = ref.Routing(pfx2as_gz(["192.0.0.0\t16\t64496", "192.0.2.0\t24\t64497_64498", "198.51.100.0\t25\t64499"]))
    assert r.asn("192.0.2.9") == 64497        # the /24 beats the /16
    assert r.asn("192.0.3.1") == 64496
    assert r.asn("198.51.100.1") == 0         # longer than /24 is ignored
    assert r.asn("2001:db8::1") == 0 and r.asn("not.an.ip") == 0
    assert r.size24[64496] == 255 and r.size24[64497] == 1


def test_network_type_order():
    assert ref.network_type(16509, "anything", None, 0.0, 1.0)[0] == "Hyperscale cloud"   # list first
    assert ref.network_type(64496, "Example Telecom", None, 0.9, 0.0)[0] == "Hosting & VPS"  # measured dc share beats name
    assert ref.network_type(64496, "Example Telecom", None, None, None)[0] == "Broadband & mobile"
    assert ref.network_type(64496, "Example", "NSP", None, None)[0] == "Transit & backbone"
    assert ref.network_type(64496, "Example", None, None, None) == ("Other", "none")


def test_latest_pfx2as_path():
    log = "# comment\n6765\t1\t2030/01/routeviews-rv2-20300101-1200.pfx2as.gz\n6766\t2\t2030/01/routeviews-rv2-20300102-1200.pfx2as.gz\n"
    assert ref.latest_pfx2as_path(log).endswith("20300102-1200.pfx2as.gz")


# ---- sources (fake HTTP) -----------------------------------------------------------------------
class FakeHttp:
    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def get(self, url, headers=None, params=None):
        self.calls.append((url, headers or {}, params or {}))
        now = dt.datetime(2030, 1, 7, tzinfo=dt.timezone.utc)
        for k, v in self.routes.items():
            if k in url:
                body = v(params) if callable(v) else v
                if isinstance(body, int):
                    return Response(url, body, None, f"HTTP {body}", now, now)
                return Response(url, 200, body, None, now, now)
        return Response(url, 404, None, "HTTP 404", now, now)


CTX = src.SourceContext(dt.date(2030, 1, 7), dt.date(2030, 1, 14),
                        {"CROWDSEC_CTI_API_KEY": "k" * 40, "VULNCHECK_API_TOKEN": "v" * 40, "SHODAN_API_KEY": "s" * 32})


def test_crowdsec_pages_until_no_next_and_strips_tag_characters():
    def page(p):
        n = p["page"]
        items = [{"ip": f"192.0.2.{n}", "behaviors": [{"name": "ssh:bruteforce"}],
                  "classifications": {"classifications": [{"name": "connection-type:data-center"}]},
                  "cves": ["CVE-2030-0001"], "history": {"first_seen": "2030-01-08T00:00:00Z"},
                  "note": "\U000E0041\U000E0042"},
                 {"ip": "2001:db8::1"}]
        links = {"next": {"href": "x"}} if n < 3 else {}
        return json.dumps({"items": items, "_links": links}).encode()
    http = FakeHttp({"cti.api.crowdsec.net": page})
    r = src.crowdsec(http, CTX)
    assert len(r.responses) == 3 and len(r.hits) == 3
    assert set(r.hits[0].categories) >= {"ssh_bruteforce", "data_centre", "cve:CVE-2030-0001", "first_seen_30d"}
    assert all(c[1].get("x-api-key") for c in http.calls)          # key in a header
    assert all("k" * 40 not in c[0] for c in http.calls)            # never in the URL


def test_crowdsec_without_key_is_an_error_not_an_empty_week():
    r = src.crowdsec(FakeHttp({}), src.SourceContext(CTX.week_start, CTX.week_end, {}))
    assert r.parse_error and not r.hits


def test_shodan_stored_url_has_no_key():
    body = json.dumps({"total": 7, "facets": {"asn": [{"value": "as64496", "count": 7}]}}).encode()
    r = src.shodan(FakeHttp({"api.shodan.io": body}), CTX)
    assert all("key" not in x.url.split("?")[1].split("&")[0] for x in r.responses)
    assert all("s" * 32 not in x.url for x in r.responses)
    assert r.nets[0].asn == 64496 and r.nets[0].count == 7 * len(src.SHODAN_TAGS)
    assert r.nets[0].categories == {t: 7 for t in src.SHODAN_TAGS}
    assert not any(c["split_by_country"] for c in r.extra["coverage"].values())


def test_shodan_splits_a_capped_tag_by_country():
    cap = src.SHODAN_FACET_CAP
    def answer(params):
        q, f = params["query"], params["facets"]
        if f.startswith("country"):
            return json.dumps({"facets": {"country": [{"value": "AA", "count": 9}, {"value": "BB", "count": 3}]}}).encode()
        if q == "tag:compromised":       # the capped global answer: 1,000 networks of 1 host
            return json.dumps({"total": cap + 12, "facets": {"asn": [{"value": f"as{i}", "count": 1} for i in range(1, cap + 1)]}}).encode()
        if "country:AA" in q:
            return json.dumps({"facets": {"asn": [{"value": "as64496", "count": 6}, {"value": "as64497", "count": 3}]}}).encode()
        if "country:BB" in q:
            return json.dumps({"facets": {"asn": [{"value": "as64496", "count": 3}]}}).encode()
        return json.dumps({"total": 0, "facets": {"asn": []}}).encode()
    r = src.shodan(FakeHttp({"api.shodan.io": answer}), CTX)
    by = {n.asn: n for n in r.nets}
    assert set(by) == {64496, 64497}                     # the capped global list was replaced
    assert by[64496].categories["compromised"] == 9      # summed across countries
    cov = r.extra["coverage"]["compromised"]
    assert cov == {"total": cap + 12, "in_networks": 12, "split_by_country": True}
    assert all("s" * 32 not in x.url for x in r.responses)


def test_shodan_coverage_eval_warns_on_a_truncated_tag():
    from zdc_netthreat import evals
    ok = evals.check_shodan_coverage({"c2": {"total": 100, "in_networks": 99, "split_by_country": False}})
    bad = evals.check_shodan_coverage({"compromised": {"total": 20324, "in_networks": 18622, "split_by_country": False}})
    assert ok.passed and not bad.passed and bad.severity == evals.WARN


def test_vulncheck_filters_week_drops_cdn_and_strips_signed_url():
    lines = [{"ip": "192.0.2.1", "classifications": ["c2:sliver"], "last_seen": "2030-01-08T00:00:00Z"},
             {"ip": "192.0.2.2", "classifications": ["cdn:google"], "last_seen": "2030-01-08T00:00:00Z"},
             {"ip": "192.0.2.3", "classifications": ["attacker-infrastructure"], "last_seen": "2029-12-01T00:00:00Z"}]
    zb = io.BytesIO()
    with zipfile.ZipFile(zb, "w") as z:
        z.writestr("out.json", "\n".join(json.dumps(x) for x in lines))
    import hashlib
    blob = zb.getvalue()
    meta = json.dumps({"data": [{"url": "https://serve.test/x.zip?Signature=SECRET", "sha256": hashlib.sha256(blob).hexdigest()}]}).encode()
    r = src.vulncheck(FakeHttp({"api.vulncheck.com": meta, "serve.test": blob}), CTX)
    assert [h.ip for h in r.hits] == ["192.0.2.1"] and r.hits[0].categories == ("c2_server",)
    assert r.extra["cdn_excluded"] == 1
    assert all("Signature" not in x.url for x in r.responses)


def test_vulncheck_checksum_mismatch_is_refused():
    meta = json.dumps({"data": [{"url": "https://serve.test/x.zip", "sha256": "0" * 64}]}).encode()
    r = src.vulncheck(FakeHttp({"api.vulncheck.com": meta, "serve.test": b"PK"}), CTX)
    assert r.parse_error == "backup checksum mismatch" and not r.hits


def test_threatfox_and_urlhaus_parse():
    tf = (b'# comment\n"2030-01-08 00:00:00", "1", "192.0.2.5:443", "ip:port", "botnet_cc", "win.x", "X", "XRat", "", "100"\n')
    r = src.threatfox(FakeHttp({"threatfox": tf}), CTX)
    assert r.hits[0].ip == "192.0.2.5" and r.hits[0].categories == ("family:XRat",)
    uh = b'# c\n"1","2030-01-08","http://198.51.100.9:8080/bin.sh","online"\n"2","2030-01-08","http://example.test/a","online"\n'
    r = src.urlhaus(FakeHttp({"urlhaus": uh}), CTX)
    assert [h.ip for h in r.hits] == ["198.51.100.9"]


def test_uceprotect_scores():
    zone = (b"$SOA 3600 x\n192.0.2.0/24 Your ISP Example/AS64496 is UCEPROTECT-Level3 listed because of a spamscore of 395.9. See: x\n")
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as g:
        g.write(zone)
    r = src.uceprotect_l3(FakeHttp({"uceprotect": buf.getvalue()}), CTX)
    assert r.nets[0].asn == 64496 and r.nets[0].score == 395.9


def test_uceprotect_already_decompressed_by_the_client():
    zone = b"192.0.2.0/24 x/AS64497 is UCEPROTECT-Level3 listed because of a spamscore of 7. See\n"
    r = src.uceprotect_l3(FakeHttp({"uceprotect": zone}), CTX)
    assert r.nets[0].asn == 64497 and r.nets[0].score == 7.0


def test_spamhaus_drop_charges_the_announcing_network():
    body = b'{"cidr":"192.0.2.0/24","sblid":"SBL1"}\n{"type":"metadata"}\n'
    ctx = src.SourceContext(CTX.week_start, CTX.week_end, {}, asn_of)
    r = src.spamhaus_drop(FakeHttp({"spamhaus": body}), ctx)
    assert [(n.asn, n.count) for n in r.nets] == [(64496, 1)]


def test_redact_hides_keys():
    assert "abcdefgh12345678" not in redact("x-api-key: abcdefgh12345678")


def test_last_complete_week():
    assert nrun.last_complete_week(dt.date(2030, 1, 14)) == dt.date(2030, 1, 7)     # a Monday
    assert nrun.last_complete_week(dt.date(2030, 1, 20)) == dt.date(2030, 1, 7)     # a Sunday


def test_size_histogram_bands_are_powers_of_two():
    h = nrun.size_histogram({1: 1, 2: 3, 3: 4, 4: 255, 5: 256, 6: 0})
    assert h == {"1": 1, "2": 1, "4": 1, "128": 1, "256": 1}


def test_bot_share_asked_per_network_replaces_the_derived_estimate():
    from zdc_netthreat.run import cf_ratios
    rows = [("traffic", "12w", 64496, 2.0, ""), ("human", "12w", 64496, 1.0, ""),
            ("traffic", "12w", 64497, 1.0, ""), ("human", "12w", 64497, 0.5, ""),
            ("bot_class", "12w", 0, 60.0, "human"), ("bot_class", "12w", 0, 40.0, "bot"),
            ("bot_class", "12w", 64496, 91.0, "bot"), ("bot_class", "12w", 64496, 9.0, "human"),
            ("bot_class", "12w", 64498, 30.0, "bot")]
    out = cf_ratios(rows)
    assert out[64496]["bot"] == 0.91                       # asked directly: wins
    assert abs(out[64497]["bot"] - 0.7) < 1e-9             # derived: 1 - 0.5*60/100/1.0
    assert out[64498]["bot"] == 0.30 and "traffic" not in out[64498]   # only asked, never ranked


def test_cloudflare_bot_shares_keeps_answers_and_counts_failures():
    def answer(params):
        if params["asn"] == 64497:
            return 500
        if params["asn"] == 64498:
            return json.dumps({"result": {"summary_0": {}}}).encode()
        return json.dumps({"result": {"summary_0": {"bot": "88.5", "human": "11.5"}}}).encode()
    rows, failed = src.cloudflare_bot_shares(FakeHttp({"radar/http/summary/bot_class": answer}),
                                             {"CLOUDFLARE_RADAR_TOKEN": "t" * 40}, [64496, 64497, 64498])
    assert failed == 1
    assert sorted(rows) == [("bot_class", "12w", 64496, None, 11.5, "human"), ("bot_class", "12w", 64496, None, 88.5, "bot")]



def test_cloudflare_bot_shares_runs_calls_side_by_side_within_a_budget():
    import time as _t

    class Slow:
        def get(self, url, headers=None, params=None):
            _t.sleep(0.2)
            return Response(url, 200, json.dumps({"result": {"summary_0": {"bot": "50", "human": "50"}}}).encode(),
                            None, None, None)
    t0 = _t.monotonic()
    rows, failed = src.cloudflare_bot_shares(Slow(), {"CLOUDFLARE_RADAR_TOKEN": "t" * 40}, list(range(16)), workers=8)
    assert failed == 0 and len(rows) == 32
    assert _t.monotonic() - t0 < 1.0                       # 16 calls of 0.2 s on 8 workers, not 3.2 s in a row
    rows, failed = src.cloudflare_bot_shares(Slow(), {"CLOUDFLARE_RADAR_TOKEN": "t" * 40}, list(range(16)), budget=0)
    assert rows == [] and failed == 16                     # past the budget: counted as failed, never asked


def test_http_pace_holds_across_threads():
    import time as _t

    import httpx
    from concurrent.futures import ThreadPoolExecutor
    from zdc_netthreat.client import Http
    seen = []
    def handler(req):
        seen.append(_t.monotonic())
        return httpx.Response(200, content=b"{}")
    h = Http(pause=0.05, transport=httpx.MockTransport(handler))
    with ThreadPoolExecutor(6) as pool:
        list(pool.map(lambda _: h.get("https://example.test/"), range(12)))
    gaps = [b - a for a, b in zip(sorted(seen), sorted(seen)[1:])]
    assert min(gaps) >= 0.045

def test_network_name_prefers_curated_names_and_refuses_registry_prose():
    from zdc_netthreat.reference import network_name, parse_bgptools
    # an address and a description line are never a name
    assert network_name(132203, None, "Tencent Global", "Tencent", "Tencent Building, Kejizhongyi Avenue", "TENCENT-NET-AP-CN") == "Tencent Global"
    assert network_name(132203, None, None, None, "Tencent Building, Kejizhongyi Avenue", "TENCENT-NET-AP-CN") == "TENCENT-NET-AP-CN"
    assert network_name(18002, None, None, None, "AS Number for Interdomain Routing", "WORLDPHONE-IN") == "WORLDPHONE-IN"
    assert network_name(8452, None, None, "IDDQD-AS", "TE-AS", "TE-AS") == "TE-AS"
    # order: PeeringDB, bgp.tools, Cloudflare, registrant
    assert network_name(1, "CF", "PDB", "BT", "ORG", "H") == "PDB"
    assert network_name(1, "CF", None, "BT", "ORG", "H") == "BT"
    assert network_name(1, "CF", None, None, "ORG", "H") == "CF"
    assert network_name(28548, "Cablevisión, S.A. de C.V.", "izzi telecom (AS28548)", "izzi (Cablevision Mexico)", None, None) == "izzi telecom"
    assert network_name(1, None, None, None, None, None) == "AS1"
    assert parse_bgptools(b"asn,name,class,cc\nAS132203,Tencent,Eyeball,CN\nAS7,,x,GB\nbad,Row,x,x\n") == {132203: "Tencent"}


def test_org_belongs_drops_only_an_unrelated_apnic_organisation():
    from zdc_netthreat.reference import org_belongs
    assert not org_belongs("TRUE INTERNET", "TRUEINTERNET-AS-AP", "KGI Securities (Thailand) Public Company Limited", "apnic")
    assert org_belongs("Tencent Global", "TENCENT-NET-AP-CN", "Shenzhen Tencent Computer Systems Company Limited", "apnic")
    assert org_belongs("Lumen", "LVLT-3549", "Level 3 Parent, LLC", "arin")      # a real parent elsewhere is kept
    assert not org_belongs("X", "X-AS", None, "ripencc")
    assert org_belongs("M.A.T Co., Ltd.", "MATCORP-AS-AP", "M.A.T Co., Ltd.", "apnic")
    assert org_belongs("LG Uplus", "LGDACOM", "LG DACOM Corporation", "apnic")
    assert not org_belongs("AIS Fibre", "AIS-Fibre-AS-AP", "MAYBANK KIM ENG SECURITIES PTE. LTD", "apnic")
    assert not org_belongs("China Telecom Hangzhou IDC Network", "CT-HangZhou-IDC", "No.288,Fu-chun Road", "apnic")


def test_traffic_share_beyond_the_global_top_comes_from_country_lists():
    from zdc_netthreat.run import cf_ratios
    rows = [("traffic", "12w", 64496, 2.0, ""),                          # globally ranked
            ("traffic", "12w", 0, 10.0, "loc:AA"), ("traffic", "12w", 0, 5.0, "loc:BB"),
            ("traffic", "12w", 64496, 50.0, "cc:AA"),                    # ignored: global value wins
            ("traffic", "12w", 64497, 20.0, "cc:AA"), ("traffic", "12w", 64497, 40.0, "cc:BB")]
    out = cf_ratios(rows)
    assert out.get(64496, {}).get("traffic_est") is None
    assert abs(out[64497]["traffic_est"] - (10 * 0.2 + 5 * 0.4)) < 1e-9
    assert "traffic" not in out[64497]                                   # never joins the universe by ranking


def test_dshield_falls_back_to_topips_when_the_attacks_table_is_empty():
    top = json.dumps([{"rank": 1, "source": "198.51.100.7", "reports": 900, "targets": 40},
                      {"rank": 2, "source": "2001:db8::1", "reports": 800, "targets": 9},
                      {"rank": 3, "source": "198.51.100.8", "reports": 700, "targets": 3}]).encode()
    res = src.dshield(FakeHttp({"sources/attacks/10000": b"[]", "topips/records/10000": top}), CTX)
    assert [h.ip for h in res.hits] == ["198.51.100.7", "198.51.100.8"]
    assert res.extra["scale"]["endpoint"] == "topips/records" and res.extra["scale"]["min_attacks"] == 3
    full = json.dumps([{"ip": "198.51.100.9", "attacks": 5}]).encode()
    http = FakeHttp({"sources/attacks/10000": full, "topips/records/10000": top})
    res = src.dshield(http, CTX)
    assert [h.ip for h in res.hits] == ["198.51.100.9"] and len(http.calls) == 1   # no fallback when it answers


def test_volume_floor_counts_a_source_that_recorded_nothing():
    from zdc_netthreat import evals as ev
    ok = {s: f * 2 for s, f in ev.FLOORS.items()}
    assert ev.check_volume_floors(ok, list(ok)).passed
    without = {s: v for s, v in ok.items() if s != "dshield"}
    r = ev.check_volume_floors(without, list(ok))
    assert not r.passed and "dshield 0" in r.summary


def test_bot_shares_counts_only_the_global_list_as_ranked(monkeypatch):
    seen = {}

    class Cur:
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def execute(self, sql, args=()): seen.setdefault("sql", []).append(sql)
        def fetchone(self): return ("fid",)
        def fetchall(self): return [(64496,)]

    class Conn:
        def cursor(self): return Cur()
        def commit(self): pass
    monkeypatch.setattr(nrun.sources, "cloudflare_bot_shares", lambda h, s, want: (seen.setdefault("want", want), ([], 0))[1])
    monkeypatch.setattr(nrun.db, "insert_cloudflare", lambda *a: None)
    nrun.bot_shares(Conn(), "run", None, {}, [64496, 64497], {})
    assert "key = ''" in seen["sql"][-1] and seen["want"] == [64497]


def test_network_name_drops_an_appended_as_number():
    from zdc_netthreat.reference import network_name
    assert network_name(28548, "Cablevision", "izzi telecom (AS28548)", None, None, None) == "izzi telecom"
    assert network_name(28548, None, "  (AS28548) ", "izzi", None, None) == "izzi"


# ---- collection timing (audit 2026-10-26) ----------------------------------------------------
def test_last_complete_week_across_the_year_boundary():
    assert nrun.last_complete_week(dt.date(2027, 1, 4)) == dt.date(2026, 12, 28)     # ISO week 53
    assert nrun.last_complete_week(dt.date(2027, 1, 5)) == dt.date(2026, 12, 28)     # the Tuesday retry
    assert nrun.last_complete_week(dt.date(2027, 1, 10)) == dt.date(2026, 12, 28)


def test_collection_lag_gate():
    from zdc_netthreat import evals as ev
    on_time = ev.check_collection_lag({"crowdsec": 6.5, "blocklist_de": 7.0, "vulncheck": 200})
    assert on_time.passed and not on_time.blocking                    # vulncheck is week-bounded
    tuesday = ev.check_collection_lag({"crowdsec": 30, "blocklist_de": 31})
    assert not tuesday.passed and not tuesday.blocking
    wednesday = ev.check_collection_lag({"crowdsec": 57.7, "blocklist_de": 57.7})
    assert not wednesday.passed and wednesday.blocking
    assert not ev.check_collection_lag({}).passed


def test_feeds_changed_gate():
    from zdc_netthreat import evals as ev
    assert ev.check_feeds_changed([]).passed
    r = ev.check_feeds_changed(["phishing_db"])
    assert not r.passed and not r.blocking and "phishing_db" in r.summary


def test_a_week_not_yet_over_is_refused_before_any_connection(monkeypatch):
    monkeypatch.setattr(nrun, "utc_today", lambda: dt.date(2026, 10, 26))
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert nrun.main(["--week", "2026-10-26"]) == 2


# ---- daily credential probe (audit 2026-10-26) ---------------------------------------------
class _ProbeHttp:
    def __init__(self, status=None, cf=None):
        self.status, self.cf, self.calls = status or {}, cf or {"status": "active", "expires_on": "2027-10-21T00:00:00Z"}, []

    def get(self, url, headers=None, params=None):
        self.calls.append((url, headers, params))
        now = dt.datetime(2026, 10, 26, tzinfo=dt.timezone.utc)
        code = next((c for k, c in self.status.items() if k in url), 200)
        body = json.dumps({"success": True, "result": self.cf}).encode() if "tokens/verify" in url else b"{}"
        return Response(url, code, body if code == 200 else None, None if code == 200 else f"HTTP {code}", now, now)


ENV = {"CLOUDFLARE_RADAR_TOKEN": "t" * 40, "CROWDSEC_CTI_API_KEY": "c" * 40, "VULNCHECK_API_TOKEN": "v" * 40, "SHODAN_API_KEY": "s" * 32}


def test_probe_all_keys_answer():
    from zdc_netthreat import probe
    rows = probe.probe(_ProbeHttp(), ENV, dt.date(2026, 10, 26))
    assert [r["source"] for r in rows] == ["cloudflare", "cloudflare_radar", "crowdsec_fire", "vulncheck_backup", "shodan"]
    assert all(r["ok"] for r in rows) and "2027-10-21" in rows[0]["note"]


def test_probe_flags_a_refused_key_a_missing_key_and_a_near_expiry():
    from zdc_netthreat import probe
    env = dict(ENV); del env["SHODAN_API_KEY"]
    rows = {r["source"]: r for r in probe.probe(_ProbeHttp(status={"crowdsec": 403}), env, dt.date(2026, 10, 26))}
    assert not rows["crowdsec_fire"]["ok"] and rows["crowdsec_fire"]["status"] == 403
    assert not rows["shodan"]["ok"] and rows["shodan"]["note"] == "key not set"
    soon = probe.probe(_ProbeHttp(cf={"status": "active", "expires_on": "2026-11-10T00:00:00Z"}), ENV, dt.date(2026, 10, 26))
    assert not soon[0]["ok"] and "15 days" in soon[0]["note"]


def test_probe_never_prints_a_key(capsys, monkeypatch):
    from zdc_netthreat import probe
    monkeypatch.setattr(probe, "Http", lambda *a, **k: _ProbeHttp())
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    assert probe.main() == 0
    out = capsys.readouterr().out
    assert not any(v in out for v in ENV.values())


def test_http_keeps_api_key_off_a_redirect_to_another_host():
    # Security review 2026-10-26: httpx forwarded x-api-key on a cross-host redirect.
    import httpx
    from zdc_netthreat.client import Http
    seen = {}
    def handler(req):
        seen[req.url.host] = req.headers.get("x-api-key")
        if req.url.host == "api.example.test" and req.url.path == "/a":
            return httpx.Response(302, headers={"location": "/b"})
        if req.url.host == "api.example.test":
            return httpx.Response(302, headers={"location": "https://cdn.other.test/file"})
        return httpx.Response(200, content=b"ok")
    h = Http(pause=0, transport=httpx.MockTransport(handler))
    r = h.get("https://api.example.test/a", headers={"x-api-key": "k-secret"})
    assert r.ok and r.body == b"ok"
    assert seen["api.example.test"] == "k-secret"     # same host: the key still travels
    assert seen["cdn.other.test"] is None             # other host: it does not


def test_http_refuses_a_downgrade_and_caps_the_body(monkeypatch):
    import httpx
    import zdc_netthreat.client as c
    def handler(req):
        if req.url.host == "api.example.test":
            return httpx.Response(302, headers={"location": "http://evil.test/x"})
        return httpx.Response(200, content=b"x")
    h = c.Http(pause=0, retries=0, transport=httpx.MockTransport(handler))
    r = h.get("https://api.example.test/a", headers={"x-api-key": "k"})
    assert not r.ok and "refused redirect" in r.error

    monkeypatch.setattr(c, "MAX_BODY", 10)
    h2 = c.Http(pause=0, retries=0, transport=httpx.MockTransport(lambda req: httpx.Response(200, content=b"y" * 100)))
    r2 = h2.get("https://feed.example.test/")
    assert not r2.ok and "larger than" in r2.error


def test_http_downgrade_on_the_same_host_and_a_port_change():
    # Red-team round 2026-10-26: the key survived https->http on the same host and a hop to another port.
    import httpx
    from zdc_netthreat.client import Http
    seen = {}
    def handler(req):
        seen[(req.url.scheme, req.url.port)] = req.headers.get("x-api-key")
        if req.url.path == "/down":
            return httpx.Response(302, headers={"location": "http://feed.example/plain"})
        if req.url.path == "/port":
            return httpx.Response(302, headers={"location": "https://feed.example:8443/x"})
        return httpx.Response(200, content=b"ok")
    h = Http(pause=0, retries=0, transport=httpx.MockTransport(handler))
    r = h.get("https://feed.example/down", headers={"x-api-key": "k"})
    assert not r.ok and "https to http" in r.error and ("http", None) not in seen
    r = h.get("https://feed.example/port", headers={"x-api-key": "k"})
    assert r.ok and seen[("https", 8443)] is None


def test_http_non_200_from_a_real_socket_is_a_response_not_a_crash():
    # Red-team round 2026-10-26: a streamed response has no .text; every 404/429/5xx raised ResponseNotRead.
    # MockTransport pre-loads content and cannot show it, so this one uses a real server.
    import http.server, threading
    from zdc_netthreat.client import Http
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(s):
            s.send_response(404); s.send_header("Content-Type", "text/plain"); s.end_headers(); s.wfile.write(b"no such feed")
        def log_message(*a): pass
    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        r = Http(pause=0, retries=0).get(f"http://127.0.0.1:{srv.server_port}/x")
    finally:
        srv.shutdown()
    assert r.status == 404 and not r.ok and "no such feed" in r.error


def test_http_refusals_are_not_retried(monkeypatch):
    import httpx
    import zdc_netthreat.client as c
    calls = []
    def handler(req):
        calls.append(1)
        return httpx.Response(200, content=b"y" * 100)
    monkeypatch.setattr(c, "MAX_BODY", 10)
    monkeypatch.setattr(c.time, "sleep", lambda s: None)
    r = c.Http(pause=0, retries=3, transport=httpx.MockTransport(handler)).get("https://feed.example/")
    assert not r.ok and len(calls) == 1
