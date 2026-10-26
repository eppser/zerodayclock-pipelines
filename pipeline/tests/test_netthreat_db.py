"""zdc_netthreat end-to-end against a migrated database, with fake HTTP.

Runs only when NET_TEST_DATABASE_URL points at a THROWAWAY database with every migration
applied (CI's service container; never a Supabase project - the cleanup disables triggers
to empty the insert-only tables). All networks are private-use ASNs and all addresses
come from the documentation ranges.

What it proves that the unit tests cannot: the SQL matches the schema, collect writes no
address anywhere, score replaces its week instead of appending, the logical fetch rows
carry every sub-request, and the derived rows reproduce what the pure functions compute.
"""

from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import io
import json
import zipfile

import psycopg
import pytest

from zdc_netthreat import run as nrun
from zdc_netthreat.client import Response

import os
DSN = os.environ.get("NET_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DSN, reason="needs NET_TEST_DATABASE_URL")

WEEK = dt.date(2030, 1, 7)
BAD, CLEAN, BIG = 64496, 64497, 64498


def gz(text: str) -> bytes:
    b = io.BytesIO()
    with gzip.GzipFile(fileobj=b, mode="wb") as g:
        g.write(text.encode())
    return b.getvalue()


# 192.0.2.0/24 + 198.18.0.0/20 (RFC 2544 benchmarking) -> BAD (17 /24s), 198.51.100.0/24 -> CLEAN, 203.0.113.0/24 + 100.64.0.0/16 -> BIG.
# All of that is special-purpose space, so the address map (0112/0114) leaves it off as bogons; 20.1.0.0/23
# (AS64499, no evidence) is the one ordinary announcement the map shows.
OTHER = 64499
PFX = gz("192.0.2.0\t24\t64496\n198.18.0.0\t20\t64496\n198.51.100.0\t24\t64497\n203.0.113.0\t24\t64498\n100.64.0.0\t16\t64498\n20.1.0.0\t23\t64499\n")
ORG = gz("# format:org_id|changed|name|country|source\nORG-B|20300101|Bad Hosting Ltd|GB|RIPE\nORG-C|20300101|Clean Telecom|DE|RIPE\nORG-G|20300101|Big Cloud Inc|US|ARIN\n"
         "# format:aut|changed|aut_name|org_id|opaque_id|source\n64496|20300101|BADHOST|ORG-B||RIPE\n64497|20300101|CLEAN-TEL|ORG-C||RIPE\n64498|20300101|BIGCLOUD|ORG-G||ARIN\n")
RIR = "ripencc|GB|asn|64496|1|20200101|allocated|x|e\nripencc|DE|asn|64497|2|19990101|allocated|x|e\n"


def ips(prefix, n):
    return [f"{prefix}.{i}" for i in range(1, n + 1)]


BAD_IPS = [f"198.18.{i % 10}.{i + 1}" for i in range(30)]   # dense: 30 IPs over 10 of its 17 /24s
BIG_IPS = ips("203.0.113", 4) + [f"100.64.{i}.1" for i in range(10)]   # 14 IPs over 11 /24s
SCANNER = "198.51.100.200"


def crowdsec_page(p):
    items = [{"ip": ip, "behaviors": [{"name": "ssh:bruteforce"}],
              "classifications": {"classifications": [{"name": "connection-type:data-center"}]},
              "cves": ["CVE-2030-0001"], "history": {"first_seen": "2029-01-01"}} for ip in BAD_IPS + BIG_IPS]
    items.append({"ip": SCANNER})
    return json.dumps({"items": items, "_links": {}}).encode()


def vc_zip():
    z = io.BytesIO()
    with zipfile.ZipFile(z, "w") as f:
        f.writestr("out.json", "\n".join(json.dumps({"ip": ip, "classifications": ["c2:x"], "last_seen": "2030-01-08T00:00:00Z"})
                                          for ip in BAD_IPS[:12]))
    return z.getvalue()


VC = vc_zip()


def cf_top(p):
    if "mitigationProduct" in (p or {}):
        return json.dumps({"result": {"top_0": [{"originAsn": str(BAD), "originAsnName": "Bad Hosting Ltd", "value": "5.0"},
                                                {"originAsn": str(BIG), "originAsnName": "Big Cloud Inc", "value": "1.0"}]}}).encode()
    return json.dumps({"result": {"top_0": [{"clientASN": BIG, "clientASName": "Big Cloud Inc", "value": "10.0"},
                                            {"clientASN": BAD, "clientASName": "Bad Hosting Ltd", "value": "0.5"},
                                            {"clientASN": CLEAN, "clientASName": "Clean Telecom", "value": "8.0"}]}}).encode()


ROUTES = {
    "pfx2as-creation.log": b"1\t1\t2030/01/routeviews-rv2-20300106-1200.pfx2as.gz\n",
    "routeviews-rv2-20300106": PFX,
    "as-organizations/20300101.as-org2info.txt.gz": ORG,
    "as-organizations/": b'<a href="20300101.as-org2info.txt.gz">x</a>',
    "delegated-ripencc": RIR.encode(), "delegated-arin": b"", "delegated-apnic": b"", "delegated-lacnic": b"", "delegated-afrinic": b"",
    "peeringdb": json.dumps({"data": [{"asn": CLEAN, "name": "Clean Telecom", "info_type": "Cable/DSL/ISP"}]}).encode(),
    "threatcategory/research": json.dumps([{"ipv4": SCANNER, "type": "censys"}]).encode(),
    "cti.api.crowdsec.net": crowdsec_page,
    "isc.sans.edu/api/sources": json.dumps([{"ip": ip, "attacks": 300} for ip in BAD_IPS[:10]]).encode(),
    "lists.blocklist.de/lists/ssh.txt": "\n".join(BAD_IPS[:8]).encode(),
    "lists.blocklist.de/lists/all.txt": "\n".join(BAD_IPS[:8] + BIG_IPS[:2]).encode(),
    "lists.blocklist.de": b"",
    "cinsscore": "\n".join(BAD_IPS[:9]).encode(),
    "api.vulncheck.com": json.dumps({"data": [{"url": "https://serve.test/vc.zip?Signature=S", "sha256": hashlib.sha256(VC).hexdigest()}]}).encode(),
    "serve.test": VC,
    "threatfox": ("\n".join(f'"2030-01-08", "1", "{ip}:443", "ip:port", "botnet_cc", "x", "X", "XRat", "", "100"' for ip in BAD_IPS[:5])).encode(),
    "urlhaus": b"# none\n",
    "Phishing.Database": "\n".join(BAD_IPS[:7]).encode(),
    "api.shodan.io": json.dumps({"facets": {"asn": [{"value": f"as{BAD}", "count": 40}, {"value": f"as{BIG}", "count": 2}]}}).encode(),
    "asndrop.json": b'{"asn":64496,"rir":"ripencc","domain":"x.test","cc":"GB","asname":"BADHOST"}\n',
    "drop_v4.json": b'{"cidr":"192.0.2.0/24","sblid":"SBL1"}\n',
    "uceprotect": gz("x/AS64496 is UCEPROTECT-Level3 listed because of a spamscore of 12.5. See\n"),
    "torbulkexitlist": b"203.0.113.9\n",
    "radar/http/summary/bot_class": json.dumps({"result": {"summary_0": {"human": "64.0", "bot": "36.0"}}}).encode(),
    "radar/attacks/layer7/summary": json.dumps({"result": {"summary_0": {"WAF": "60", "DDOS": "40"}}}).encode(),
    "radar/": cf_top,
    "dashboard.shadowserver.org": lambda p: json.dumps({"geo_data": {"GB": {"count": 10 if p["data_set"] == "count" else 5.0},
                                                                     "DE": {"count": 20 if p["data_set"] == "count" else 1.0}}}).encode(),
    "stat.ripe.net": json.dumps({"data": {"abuse_contacts": ["abuse@example.test"]}}).encode(),
}


class FakeHttp:
    def __init__(self):
        self.calls = []

    def get(self, url, headers=None, params=None):
        self.calls.append(url)
        now = dt.datetime(2030, 1, 14, tzinfo=dt.timezone.utc)
        for k, v in ROUTES.items():
            if k in url:
                body = v(params) if callable(v) else v
                return Response(url, 200, body, None, now, now)
        return Response(url, 404, None, "HTTP 404", now, now)


def cleanup(cx):
    cx.execute("set session_replication_role = replica")     # bypass the insert-only triggers
    for t in ("net_derived.source_scores", "net_derived.network_scores", "net_derived.model_fits", "net_derived.country_week",
              "net_derived.network_scores_v2", "net_derived.fits_v2", "net_derived.netblock_v2",
              "net_core.routed_runs", "net_core.routing_files",
              "net_raw.asn_counts", "net_raw.asn_union", "net_raw.asn_union_side", "net_raw.routed_sizes",
              "net_raw.cloudflare_lists", "net_raw.country_counts",
              "net_raw.reference_snapshots", "net_core.networks", "net_raw.fetches"):
        cx.execute(f"delete from {t}")
    cx.execute("delete from raw.pipeline_runs where pipeline = 'netthreat'")
    cx.execute("set session_replication_role = origin")
    cx.commit()


@pytest.fixture()
def db(monkeypatch):
    cx = psycopg.connect(DSN)
    cleanup(cx)
    monkeypatch.setattr(nrun, "Http", lambda *a, **k: FakeHttp())
    monkeypatch.setattr(nrun, "utc_today", lambda: dt.date(2030, 1, 14))     # the fake fetch day
    monkeypatch.setenv("DATABASE_URL", DSN)
    for k, v in {"CROWDSEC_CTI_API_KEY": "c" * 40, "VULNCHECK_API_TOKEN": "v" * 40, "SHODAN_API_KEY": "s" * 32,
                 "CLOUDFLARE_RADAR_TOKEN": "t" * 40}.items():
        monkeypatch.setenv(k, v)
    yield cx
    cleanup(cx)
    cx.close()


def q(cx, sql, *a):
    return cx.execute(sql, a).fetchall()


def _tiny_week(monkeypatch):
    """Volume floors and v2's absent-feed floors are sized for the real internet; the synthetic week is tiny."""
    from zdc_netthreat import evals, score_v2
    monkeypatch.setattr(evals, "FLOORS", {})
    monkeypatch.setattr(score_v2, "ABSENT_FLOOR", {f: 0 for f in score_v2.ABSENT_FLOOR})


def test_collect_and_score_a_week(db, tmp_path, monkeypatch):
    _tiny_week(monkeypatch)
    rep = tmp_path / "r.json"
    rc = nrun.main(["--week", WEEK.isoformat(), "--report", str(rep)])
    report = json.loads(rep.read_text())
    assert rc == 0, report.get("checks") or report.get("error")

    # every source has one logical fetch row, with its sub-requests listed
    rows = dict(q(db, "select source_id, count(*) from net_raw.fetches where source_id <> 'reference' group by 1"))
    assert set(rows) == set(nrun.sources.ALL) and set(rows.values()) == {1}
    bl = q(db, "select jsonb_array_length(notes->'requests') from net_raw.fetches where source_id = 'blocklist_de'")[0][0]
    assert bl == 9                                           # 8 service lists + all.txt

    # no address anywhere; no credential in any URL
    for t, c in (("net_raw.asn_counts", "categories::text"), ("net_raw.fetches", "url || coalesce(error,'') || notes::text")):
        assert q(db, f"select count(*) from {t} where {c} ~ '\\d+\\.\\d+\\.\\d+\\.\\d+'")[0][0] == 0, t
    assert q(db, "select count(*) from net_raw.fetches where url ~ '(cccccccc|vvvvvvvv|ssssssss|Signature)'")[0][0] == 0

    # research scanners are removed before counting
    assert q(db, "select excluded from net_raw.fetches where source_id = 'crowdsec'")[0][0] == 1

    # the union counts an IP once across feeds
    u = dict((a, (i, n)) for a, i, n in q(db, "select asn, ips, slash24s from net_raw.asn_union"))
    assert u[BAD] == (30, 10) and u[BIG] == (14, 11)

    # BAD is dense and seen by every group; BIG is large and diffuse; CLEAN has nothing
    s = {a: (sc, g) for a, sc, g in q(db, "select asn, score, groups from net_derived.network_scores where week_start = %s", WEEK)}
    assert s[BAD][0] > 0.9 and "sensors" in s[BAD][1] and "vulncheck" in s[BAD][1]
    assert s[BAD][0] > s.get(BIG, (0,))[0]
    assert s.get(CLEAN, (0, []))[1] == []

    # profiles: type from measured data-centre share; only role abuse addresses
    n = dict((a, (t, ab)) for a, t, ab in q(db, "select asn, network_type, abuse_contact from net_core.networks"))
    assert n[BAD] == ("Hosting & VPS", "abuse@example.test")

    # Shadowserver per internet user, relative to the world
    c = dict(((d, cc), r) for d, cc, r in q(db, "select dataset, cc, ratio_to_world from net_derived.country_week where week_start = %s", WEEK))
    assert c[("sinkhole", "GB")] > 1 > c[("sinkhole", "DE")]

    # v2: every routed network's size was stored, both sides were fitted, BAD is far above average on
    # the attack side, rows carry both sides for every atlas network, and no row is NaN
    assert q(db, "select count(*) from net_raw.routed_sizes")[0][0] >= 3
    fits = {s: (c_, l) for s, c_, l in q(db, "select side, converged, listed from net_derived.fits_v2 where week_start = %s", WEEK)}
    assert set(fits) == {"attack", "host"} and all(c_ for c_, _ in fits.values())
    v2 = {(a, sd): (lo, best, mass) for a, sd, lo, best, mass in
          q(db, "select asn, side, lo_x, best_x, mass from net_derived.network_scores_v2 where week_start = %s", WEEK)}
    assert v2[(BAD, "attack")][0] > 1 and v2[(BAD, "attack")][0] <= v2[(BAD, "attack")][1]
    assert all(lo > 0 and best > 0 and mass >= 0 for lo, best, mass in v2.values())
    assert {sd for a, sd in v2 if a == BAD} == {"attack", "host"}
    assert report["score_v2"]["attack"]["feeds"]
    # per-side unions exist and the attack side's union is at most the all-feed union
    us = dict((sd, n) for sd, n in q(db, "select side, sum(slash24s) from net_raw.asn_union_side group by 1"))
    assert us["attack"] <= sum(n for _, n in u.values())
    # the atlas document carries v2 per node and the per-side fits
    doc = q(db, "select public.netthreat_atlas(%s)", WEEK)[0][0]
    node = next(n for n in doc["nodes"] if n["a"] == BAD)
    assert node["v2"]["attack"]["lo"] > 1 and node["v2"]["band"] in (0, 1, 2) and len(node["h2"]) == 1
    assert set(doc["v2"]["sides"]) == {"attack", "host"} and doc["v2"]["weeks"][0]["week"] == WEEK.isoformat()

    # 0112/0114: the routing table at /24 grain, the week's per-/16 map, and the map adds up. The
    # synthetic file's special-purpose announcements (198.18/15, 100.64/10, the RFC 5737 /24s) are
    # bogons and stay off the map, though the scores count them; only 20.1.0.0/23 is mapped.
    assert q(db, "select runs, routed24 from net_core.routing_files")[0] == (1, 2)
    cells = {b: (r, d, s) for b, r, d, s in q(db, "select b16, routed24, dom_asn, scored24 from net_derived.netblock_v2 where week_start = %s", WEEK)}
    assert cells == {(20 << 8) | 1: (2, OTHER, 0)}                  # no source reported OTHER
    assert report["netblock"]["cells"] == 1
    assert next(c for c in report["checks"] if c["name"] == "netblock")["passed"]
    s16 = q(db, "select public.netthreat_slash16(%s)", (20 << 8) | 1)[0][0]
    assert s16["runs"] == [[(20 << 16) | (1 << 8), (20 << 16) | (1 << 8) | 1, OTHER, None, False, False, 23, []]]
    assert q(db, "select jsonb_array_length(public.netthreat_slash16(%s)->'runs')", (192 << 8) | 0)[0][0] == 0


def test_rescoring_replaces_the_week(db, tmp_path, monkeypatch):
    _tiny_week(monkeypatch)
    assert nrun.main(["--week", WEEK.isoformat()]) == 0
    before = q(db, "select count(*) from net_derived.network_scores where week_start = %s", WEEK)[0][0]
    before2 = q(db, "select count(*) from net_derived.network_scores_v2 where week_start = %s", WEEK)[0][0]
    assert nrun.main(["--week", WEEK.isoformat(), "--score-only"]) == 0
    assert nrun.main(["--week", WEEK.isoformat(), "--score-only"]) == 0
    after = q(db, "select count(*) from net_derived.network_scores where week_start = %s", WEEK)[0][0]
    after2 = q(db, "select count(*) from net_derived.network_scores_v2 where week_start = %s", WEEK)[0][0]
    assert before == after > 0 and before2 == after2 > 0
    # a score-only run never refetches routing: the sizes stored at collect are reused
    assert q(db, "select count(distinct fetch_id) from net_raw.routed_sizes")[0][0] == 1


def test_no_write_fits_and_gates_but_stores_nothing(db, tmp_path, monkeypatch):
    _tiny_week(monkeypatch)
    assert nrun.main(["--week", WEEK.isoformat()]) == 0
    db.execute("set session_replication_role = replica")
    db.execute("delete from net_derived.network_scores_v2"); db.execute("delete from net_derived.fits_v2")
    db.execute("set session_replication_role = origin"); db.commit()
    rep = tmp_path / "r.json"
    assert nrun.main(["--week", WEEK.isoformat(), "--no-write", "--report", str(rep)]) == 0
    report = json.loads(rep.read_text())
    assert report["score_v2"]["attack"]["feeds"] and {c["name"] for c in report["checks"]} >= {"v2_converged", "volume_floors", "sources_answered"}
    assert q(db, "select count(*) from net_derived.fits_v2")[0][0] == 0
    assert q(db, "select notes->>'no_write' from raw.pipeline_runs where pipeline = 'netthreat' order by started_at desc limit 1")[0][0] == "true"


def test_the_fit_records_its_provenance(db, tmp_path, monkeypatch):
    _tiny_week(monkeypatch)
    assert nrun.main(["--week", WEEK.isoformat()]) == 0
    notes = dict(q(db, "select side, notes from net_derived.fits_v2 where week_start = %s", WEEK))
    # (the synthetic host side is always provisional: the fake URLhaus answers nothing, so that
    #  feed is absent; the attack side is complete)
    assert notes["attack"]["routed_sizes"] == "stored" and notes["attack"]["union_run_id"] and notes["attack"]["prev_week"] is None
    # the week after reads this week as its hysteresis base, because it was not provisional
    nxt = WEEK + dt.timedelta(days=7)
    from zdc_netthreat import db as ndb
    prev, base = ndb.previously_listed(db, nxt, "v2")
    assert base["attack"] == WEEK.isoformat()


def test_a_pre_0102_week_refetches_its_routing_file_once(db, tmp_path, monkeypatch):
    """A week collected before routed sizes were stored: the first score-only run refetches the
    week's routing file by its stored name, records it (notes.kind pfx2as_refetch) and stores the
    sizes; the second run finds them and fetches nothing."""
    _tiny_week(monkeypatch)
    assert nrun.main(["--week", WEEK.isoformat()]) == 0
    db.execute("set session_replication_role = replica")
    db.execute("delete from net_raw.routed_sizes")
    db.execute("set session_replication_role = origin"); db.commit()
    assert nrun.main(["--week", WEEK.isoformat(), "--score-only"]) == 0
    assert q(db, "select count(*) from net_raw.fetches where notes->>'kind' = 'pfx2as_refetch'")[0][0] == 1
    assert q(db, "select count(distinct fetch_id) from net_raw.routed_sizes")[0][0] == 1
    assert q(db, "select notes->>'routed_sizes' from net_derived.fits_v2 where side = 'attack'")[0][0].startswith("refetched:")
    assert nrun.main(["--week", WEEK.isoformat(), "--score-only"]) == 0
    assert q(db, "select count(*) from net_raw.fetches where notes->>'kind' = 'pfx2as_refetch'")[0][0] == 1
    assert q(db, "select notes->>'routed_sizes' from net_derived.fits_v2 where side = 'attack'")[0][0] == "stored"


def test_a_pre_0112_week_refetches_its_routing_runs_once(db, tmp_path, monkeypatch):
    """A week collected before 0112 has no runs: the first score-only run refetches the routing file
    once and writes the map; the next finds the runs stored."""
    _tiny_week(monkeypatch)
    assert nrun.main(["--week", WEEK.isoformat()]) == 0
    db.execute("delete from net_core.routed_runs"); db.execute("delete from net_core.routing_files")
    db.execute("delete from net_derived.netblock_v2"); db.commit()
    assert nrun.main(["--week", WEEK.isoformat(), "--score-only"]) == 0
    assert q(db, "select count(*) from net_core.routing_files")[0][0] == 1
    assert q(db, "select sum(routed24) from net_derived.netblock_v2 where week_start = %s", WEEK)[0][0] == 2
    stored = q(db, "select stored_at from net_core.routing_files")[0][0]
    assert nrun.main(["--week", WEEK.isoformat(), "--score-only"]) == 0
    assert q(db, "select stored_at from net_core.routing_files")[0][0] == stored        # not refetched


def test_a_missing_key_blocks_the_run(db, tmp_path, monkeypatch):
    _tiny_week(monkeypatch)
    monkeypatch.delenv("CROWDSEC_CTI_API_KEY")
    rep = tmp_path / "r.json"
    assert nrun.main(["--week", WEEK.isoformat(), "--report", str(rep)]) == 1
    checks = {c["name"]: c["passed"] for c in json.loads(rep.read_text())["checks"]}
    assert checks["sources_answered"] is False


def test_a_tuesday_is_refused(db):
    assert nrun.main(["--week", "2030-01-08"]) == 2


# ---- collection timing and retries (audit 2026-10-26) ---------------------------------------
def test_the_tuesday_retry_skips_a_collected_week(db, monkeypatch):
    _tiny_week(monkeypatch)
    assert nrun.main(["--week", WEEK.isoformat()]) == 0
    runs = q(db, "select count(*) from raw.pipeline_runs where pipeline = 'netthreat'")[0][0]
    assert nrun.main(["--week", WEEK.isoformat(), "--skip-if-collected"]) == 0
    assert q(db, "select count(*) from raw.pipeline_runs where pipeline = 'netthreat'")[0][0] == runs


def test_a_failed_collection_is_retried(db, monkeypatch):
    _tiny_week(monkeypatch)
    monkeypatch.delenv("CROWDSEC_CTI_API_KEY")
    assert nrun.main(["--week", WEEK.isoformat()]) == 1
    monkeypatch.setenv("CROWDSEC_CTI_API_KEY", "c" * 40)
    assert nrun.main(["--week", WEEK.isoformat(), "--skip-if-collected"]) == 0
    assert q(db, "select count(*) from raw.pipeline_runs where pipeline = 'netthreat' and mode = 'full' and ok")[0][0] == 1


def test_a_late_collection_is_served_provisional(db, tmp_path, monkeypatch):
    _tiny_week(monkeypatch)
    assert nrun.main(["--week", WEEK.isoformat()]) == 0
    db.execute("set session_replication_role = replica")
    db.execute("update net_raw.fetches set requested_at = requested_at + interval '3 days'")
    db.execute("set session_replication_role = origin")
    db.commit()
    rep = tmp_path / "r.json"
    assert nrun.main(["--week", WEEK.isoformat(), "--score-only", "--report", str(rep)]) == 1
    lag = next(c for c in json.loads(rep.read_text())["checks"] if c["name"] == "collection_lag")
    assert not lag["passed"] and "after the week ended" in lag["summary"]
    assert q(db, "select bool_and(provisional) from net_derived.fits_v2 where week_start = %s", WEEK)[0][0] is True


def test_an_unchanged_feed_is_flagged(db, tmp_path, monkeypatch):
    _tiny_week(monkeypatch)
    assert nrun.main(["--week", WEEK.isoformat()]) == 0
    db.execute("set session_replication_role = replica")
    db.execute("update net_raw.fetches set week_start = %s", (WEEK - dt.timedelta(days=7),))
    db.execute("set session_replication_role = origin")
    db.commit()
    rep = tmp_path / "r.json"
    nrun.main(["--week", WEEK.isoformat(), "--report", str(rep)])
    feeds = next(c for c in json.loads(rep.read_text())["checks"] if c["name"] == "feeds_changed")
    assert not feeds["passed"] and "crowdsec" in feeds["summary"]


def test_an_abandoned_run_row_is_closed(db, monkeypatch):
    _tiny_week(monkeypatch)
    db.execute("""insert into raw.pipeline_runs (run_id, pipeline, mode, trigger, started_at)
                  values (gen_random_uuid(), 'netthreat', 'full', 'test', now() - interval '5 hours')""")
    db.commit()
    nrun.main(["--week", WEEK.isoformat()])
    assert q(db, "select count(*) from raw.pipeline_runs where pipeline = 'netthreat' and finished_at is null")[0][0] == 0


def test_a_week_not_yet_over_is_refused(db):
    assert nrun.main(["--week", "2030-01-14"]) == 2          # utc_today() is that Monday
