"""zdc_aof end to end against a migrated database, with fake HTTP.

Runs only when AOF_TEST_DATABASE_URL points at a THROWAWAY database that has every migration
applied (CI's service container; never a Supabase project: the cleanup truncates the
insert-only tables). All data is synthetic; the only address used is the placeholder 1.2.3.4.
"""

from __future__ import annotations

import gzip
import json
import os
from datetime import date, datetime, timedelta, timezone

import psycopg
import pytest

from zdc_aof import client as c
from zdc_aof import db, models
from zdc_aof import run as aof_run

DSN = os.environ.get("AOF_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DSN, reason="needs AOF_TEST_DATABASE_URL")

KEY = "k3yk3yk3yk3yk3yk3yk3yk3yk3yk3y00"
D = date(2030, 1, 10)                    # the day the fake offensive.agency says its data runs to
TODAY = D + timedelta(days=1)
CFG = models.parse_config(b"""
window_days = 7
min_interval_seconds = 1.1
[[framework]]
slug = "artex"
name = "ARTEX"
rules = [ { match = 'product:ARTEX', anchor = true }, { match = 'http.title:"ARTEX console"' } ]
[[framework]]
slug = "pentagi"
name = "PentAGI"
rules = [ { match = 'product:PentAGI' } ]
""")


def resp(body, status=200, error=None, url="https://api.test/x") -> c.Response:
    now = datetime.now(timezone.utc)
    raw = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
    return c.Response(url, status, raw, error, now, now)


def host(asn, cc, *agents, org="Synthetic Hosting") -> dict:
    return {"ip": "1.2.3.4", "active": True, "first_seen": str(D), "last_seen": str(D),
            "agents": [{"slug": s, "level": lvl, "ports": [8787]} for s, lvl in agents],
            "network": {"asn": f"AS{asn}" if asn else None, "country": cc, "kind": "hosting", "org": org}}


HOSTS = [host(64500, "US", ("artex", "confirmed")), host(64500, "US", ("artex", "confirmed"), ("pentagi", "confirmed")),
         host(64500, "HK", ("artex", "probable")), host(64501, "DE", ("pentagi", "confirmed"), org="Second Net"),
         host(0, "", ("artex", "confirmed"))]


class FakeOA:
    """offensive.agency as measured on 2026-11-25, shrunk. `over` replaces any path's answer."""

    def __init__(self, hosts=None, day=D, over=None, page=3, rules=None, idle=()):
        self.hosts = HOSTS if hosts is None else hosts
        self.day, self.over, self.page, self.idle = day, over or {}, page, tuple(idle)
        self.rules = rules or {"artex": [("title", 'html.title.text:"ARTEX"'), ("favicon", "favicon.data.md5:aa11")],
                               "pentagi": [("cert", 'cert.issuer.cn:"PentAGI CA"')], "nebula": []}
        self.asked: list[str] = []

    def get(self, path, **params):
        self.asked.append(path)
        key = path.split("?")[0].rsplit("/api/v1/", 1)[-1]
        if key in self.over:
            v = self.over[key]
            return v if isinstance(v, c.Response) else resp(v)
        active = {s: sum(1 for h in self.hosts for a in h["agents"] if a["slug"] == s) for s in ("artex", "pentagi")}
        if key == "status":
            return resp({"meta": {}, "data": {"ref_day": str(self.day), "first_day": "2029-12-01", "hosts_active": len(self.hosts),
                                              "hosts_total": 9, "active_window_days": 7, "last_collection": f"{self.day}T17:40:00+00:00"}})
        if key == "agents":
            return resp({"meta": {"total": 3}, "data": [
                {"slug": "artex", "name": "ARTEX", "tracked": True, "hosts_active": active["artex"], "default_port": 8787,
                 "repository": "https://example.org/artex", "summary": "synthetic"},
                {"slug": "pentagi", "name": "PentAGI", "tracked": True, "hosts_active": active["pentagi"], "default_port": 8443},
                {"slug": "nebula", "name": "Nebula", "tracked": False, "hosts_active": 0, "default_port": None},
                *({"slug": s, "name": s.title(), "tracked": True, "hosts_active": 0} for s in self.idle)]})
        if key.startswith("agents/"):
            slug = key.split("/")[1]
            return resp({"meta": {}, "data": {"slug": slug, "detection": {"fingerprints": [
                {"family": f, "query": q} for f, q in self.rules.get(slug, [])]}}})
        if key == "timeline":
            return resp({"meta": {}, "data": {"days": [str(self.day - timedelta(days=1)), str(self.day)],
                                              "agents": {"artex": [3, 4], "pentagi": [1, 2]}, "total": [4, 6]}})
        if key == "hosts":
            off = int(params.get("offset", 0))
            chunk = self.hosts[off:off + self.page]
            nxt = f"/api/v1/hosts?scope=active&limit={self.page}&offset={off + self.page}" if off + self.page < len(self.hosts) else None
            return resp({"meta": {"total": len(self.hosts), "next": nxt, "count": len(chunk)}, "data": chunk})
        return resp({"meta": {}, "data": {"synthetic": key}})


class FakeHttp:
    requests = 0


class FakeShodan:
    def __init__(self, totals=None, info=None, errors=()):
        self.totals = totals or {"product:ARTEX": (30, {64500: 20, 64502: 10}), 'http.title:"ARTEX console"': (5, {64500: 5}),
                                 "product:PentAGI": (8, {64501: 8})}
        self._info, self.errors, self.http, self.queries = info, set(errors), FakeHttp(), []

    def info(self):
        self.http.requests += 1
        return self._info or resp({"plan": "oss", "query_credits": 0}, url="https://api.shodan.io/api-info")

    def count(self, query, facets=""):
        self.http.requests += 1
        self.queries.append(query)
        url = "https://api.shodan.io/shodan/host/count?query=" + query.split(" ")[0]
        match = next(m for m in self.totals if query.startswith(m))
        if match in self.errors:
            return resp(None, 503, "HTTP 503: unavailable", url=url)
        total, asn = self.totals[match]
        return resp({"matches": [], "total": total, "facets": {"asn": [{"value": f"as{a}", "count": n} for a, n in asn.items()]}}, url=url)


AOF_TABLES = ("aof_derived.network_day", "aof_derived.framework_day", "aof_core.detection_rules",
              "aof_core.network_names", "aof_core.frameworks", "aof_raw.fetches", "aof_raw.bodies")


@pytest.fixture()
def conn():
    def clean(k):
        k.execute("truncate " + ", ".join(AOF_TABLES) + " cascade")
        k.execute("delete from raw.pipeline_runs where pipeline = 'aof'")
        k.execute("delete from net_core.networks where asn in (64500)")
        k.commit()
    with psycopg.connect(DSN) as k:
        clean(k)
        k.execute("""insert into net_core.networks (asn, name, cc, network_type, type_basis, routed_24s,
                                                    announced_ipv4, prefixes, updated_week)
                     values (64500, 'Named Network Ltd', 'US', 'Hosting & VPS', 'test', 10, 2560, 2, '2030-01-07')""")
        k.commit()
        yield k
        k.rollback()
        clean(k)


def go(oa=None, shodan=None, today=TODAY, both=True):
    oa = oa if oa is not None or not both else FakeOA()
    shodan = shodan if shodan is not None or not both else FakeShodan()
    return aof_run.run(oa, shodan, CFG, psycopg.connect(DSN), trigger="test", today=today, secrets=(KEY,))


def q(conn, sql, *a):
    return conn.execute(sql, a).fetchall()


def fw(conn, source, metric):
    return {(str(d), f): v for d, f, v in q(conn, """select day, framework, value from aof_derived.framework_day
                                                   where source_id = %s and metric = %s""", source, metric)}


# ---- a healthy run ---------------------------------------------------------------

def test_a_run_stores_both_sources_each_under_its_own_day(conn):
    assert go() == 0
    assert fw(conn, "offensive_agency", "active_7d_addresses") == {
        (str(D), "artex"): 4, (str(D), "pentagi"): 2, (str(D), "*"): 5}          # 5 addresses, one runs two frameworks
    assert fw(conn, "shodan", "services_7d") == {(str(TODAY), "artex"): 35, (str(TODAY), "pentagi"): 8}
    nets = {(s, f, a, cc): v for s, f, a, cc, v in q(conn, "select source_id, framework, asn, cc, value from aof_derived.network_day")}
    assert nets[("offensive_agency", "artex", 64500, "US")] == 2 and nets[("offensive_agency", "artex", 64500, "HK")] == 1
    assert nets[("offensive_agency", "*", 64500, "US")] == 2                       # not 3: distinct addresses
    assert nets[("offensive_agency", "artex", 0, "")] == 1                         # no network given: kept, as asn 0
    assert nets[("shodan", "artex", 64500, "")] == 25 and nets[("shodan", "artex", 64502, "")] == 10
    ok, err, notes = q(conn, "select ok, error, notes from raw.pipeline_runs where pipeline = 'aof'")[0]
    assert ok and err is None and notes["config_sha256"] == CFG.sha256 and notes["days"] == {"offensive_agency": str(D), "shodan": str(TODAY)}


def test_frameworks_and_detection_rules_are_stored(conn):
    go()
    assert q(conn, "select slug, tracked, default_port from aof_core.frameworks order by slug") == [
        ("artex", True, 8787), ("nebula", False, None), ("pentagi", True, 8443)]
    assert q(conn, "select framework, family, query, retired_day from aof_core.detection_rules order by 1, 3") == [
        ("artex", "favicon", "favicon.data.md5:aa11", None), ("artex", "title", 'html.title.text:"ARTEX"', None),
        ("pentagi", "cert", 'cert.issuer.cn:"PentAGI CA"', None)]


def test_every_request_is_recorded_and_no_address_is_stored_anywhere(conn):
    go()
    rows = q(conn, "select endpoint, body_withheld, stored_hash is not null, record_count from aof_raw.fetches where source_id = 'offensive_agency'")
    by = {e: (w, s, n) for e, w, s, n in rows}
    assert by["hosts:0"] == ("carries_addresses", False, 3) and by["hosts:1"] == ("carries_addresses", False, 2)
    for kept in ("status", "agents", "agent:artex", "timeline", "stats", "clusters", "c2", "map", "facets"):
        assert by[kept][:2] == (None, True), kept
    # Every text column and every stored body in the three schemas, searched for the address
    # the fake host list carries. This is the test of "no address is stored".
    for table in AOF_TABLES:
        for (row,) in q(conn, f"select to_jsonb(t) - 'body_gz' from {table} t"):   # noqa: S608 - fixed list
            assert "1.2.3.4" not in json.dumps(row), table
    bodies = q(conn, "select content_hash from aof_raw.bodies")
    assert bodies
    for (h,) in bodies:
        assert b"1.2.3.4" not in db.body_of(conn, h)


def test_a_kept_body_is_replayable_and_stored_once(conn):
    go()
    (h,) = q(conn, "select stored_hash from aof_raw.fetches where endpoint = 'timeline'")[0]
    rows, days = models.parse_timeline(models.envelope(db.body_of(conn, h))[1])
    assert days == [D - timedelta(days=1), D] and (D, "artex", 4) in rows
    n = q(conn, "select count(*) from aof_raw.bodies")[0][0]
    go()                                                    # the same answers again
    assert q(conn, "select count(*) from aof_raw.bodies")[0][0] == n       # identical answers: no new body row
    assert q(conn, "select count(*) from aof_raw.fetches where endpoint = 'timeline'")[0][0] == 2


def test_shodan_queries_are_windowed_and_exclusive(conn):
    sh = FakeShodan()
    go(shodan=sh)
    since = (TODAY - timedelta(days=6)).strftime("%d/%m/%Y")
    assert sh.queries == [f"product:ARTEX after:{since}", f'http.title:"ARTEX console" -product:ARTEX after:{since}',
                          f"product:PentAGI after:{since}"]
    assert q(conn, "select count(*) from aof_raw.fetches where url ~* '[?&]key='")[0][0] == 0


# ---- idempotency and days ---------------------------------------------------------

def test_a_second_run_for_the_same_day_replaces_it(conn):
    go()
    before = (q(conn, "select count(*) from aof_derived.framework_day")[0][0], q(conn, "select count(*) from aof_derived.network_day")[0][0])
    assert go(oa=FakeOA(hosts=HOSTS[:4]), shodan=FakeShodan()) == 0          # the source revised its day: one address fewer
    assert fw(conn, "offensive_agency", "active_7d_addresses")[(str(D), "*")] == 4
    assert q(conn, "select count(*) from aof_derived.network_day where asn = 0")[0][0] == 0   # the dropped row is gone, not left behind
    assert q(conn, "select count(*) from aof_derived.framework_day")[0][0] == before[0]


def test_a_stale_source_rewrites_its_own_day_and_never_mints_a_new_one(conn):
    go()
    # Two days later the source still says its data runs to D: a warning, and still filed under D.
    assert go(today=TODAY + timedelta(days=1)) == 0
    assert {d for d, _ in fw(conn, "offensive_agency", "active_7d_addresses")} == {str(D)}
    assert {d for d, _ in fw(conn, "shodan", "services_7d")} == {str(TODAY), str(TODAY + timedelta(days=1))}


def test_a_source_four_days_stale_fails_the_run_and_stores_nothing_for_it(conn):
    assert go(today=D + timedelta(days=4)) == 1
    assert fw(conn, "offensive_agency", "active_7d_addresses") == {}
    assert fw(conn, "shodan", "services_7d")                                  # the other source is unaffected
    assert q(conn, "select ok, error from raw.pipeline_runs where pipeline = 'aof'") == [(False, "oa_fresh")]


def test_the_timeline_is_only_rewritten_where_it_changed(conn):
    go()
    assert fw(conn, "offensive_agency", "seen_day_addresses")[(str(D), "artex")] == 4
    first = q(conn, "select run_id from aof_derived.framework_day where metric = 'seen_day_addresses' and framework = 'artex' and day = %s", D)[0][0]
    go()
    assert q(conn, "select run_id from aof_derived.framework_day where metric = 'seen_day_addresses' and framework = 'artex' and day = %s", D)[0][0] == first
    # a re-run for the day must not delete the timeline's rows either
    assert len(fw(conn, "offensive_agency", "seen_day_addresses")) == 4


# ---- failures: stored short is worse than not stored --------------------------------

def test_a_short_host_list_stores_nothing_for_that_source_and_fails_the_run(conn):
    short = {"meta": {"total": 5, "next": None, "count": 2}, "data": HOSTS[:2]}
    assert go(oa=FakeOA(over={"hosts": short})) == 1
    assert fw(conn, "offensive_agency", "active_7d_addresses") == {}
    assert q(conn, "select count(*) from aof_derived.network_day where source_id = 'offensive_agency'")[0][0] == 0
    assert fw(conn, "shodan", "services_7d")
    (err,) = q(conn, "select error from raw.pipeline_runs where pipeline = 'aof'")[0]
    assert "oa_hosts_complete" in err


def test_a_source_that_updates_mid_run_is_not_stored(conn):
    class Moving(FakeOA):
        def get(self, path, **params):
            if path == "status" and self.asked.count("status") >= 1:
                self.day = D + timedelta(days=1)
            return super().get(path, **params)
    assert go(oa=Moving()) == 1
    assert fw(conn, "offensive_agency", "active_7d_addresses") == {}


def test_an_unanswered_shodan_rule_leaves_its_framework_out_not_short(conn):
    assert go(shodan=FakeShodan(errors={'http.title:"ARTEX console"'})) == 1    # 1 of 3 rules is over the 10% bar here
    assert fw(conn, "shodan", "services_7d") == {}                               # blocked: nothing stored for Shodan
    assert fw(conn, "offensive_agency", "active_7d_addresses")                   # offensive.agency committed on its own
    (ok, err, n) = q(conn, "select ok, error, sources_ok from raw.pipeline_runs where pipeline = 'aof'")[0]
    assert (ok, err, n) == (False, "shodan_rules_answered", 1)


def test_a_refused_key_sends_no_rule_requests_and_names_the_key(conn):
    sh = FakeShodan(info=resp(None, 401, "HTTP 401: Unauthorized", url="https://api.shodan.io/api-info"))
    assert go(shodan=sh) == 1
    assert sh.queries == []
    assert fw(conn, "offensive_agency", "active_7d_addresses")
    assert q(conn, "select error from raw.pipeline_runs where pipeline = 'aof'")[0][0].startswith("shodan_reachable")


def test_a_crash_in_one_source_keeps_the_other_and_records_a_failed_run(conn):
    class Broken(FakeOA):
        def get(self, path, **params):
            if path.startswith("agents/"):
                raise RuntimeError(f"boom https://api.test/?key={KEY}")
            return super().get(path, **params)
    assert go(oa=Broken()) == 1
    assert fw(conn, "shodan", "services_7d")
    ok, err = q(conn, "select ok, error from raw.pipeline_runs where pipeline = 'aof'")[0]
    assert ok is False and err and KEY not in err


# ---- detection rules over time ------------------------------------------------------

def test_a_rule_the_source_stops_publishing_is_retired_not_deleted(conn):
    go()
    later = D + timedelta(days=1)
    go(oa=FakeOA(day=later, rules={"artex": [("title", 'html.title.text:"ARTEX"')], "pentagi": [("cert", 'cert.issuer.cn:"PentAGI CA"')]}),
       today=later + timedelta(days=1))
    assert q(conn, "select query, retired_day from aof_core.detection_rules where framework = 'artex' order by 1") == [
        ("favicon.data.md5:aa11", later), ('html.title.text:"ARTEX"', None)]
    # and it comes back if the source publishes it again
    go(oa=FakeOA(day=later + timedelta(days=1)), today=later + timedelta(days=2))
    assert q(conn, "select retired_day from aof_core.detection_rules where query = 'favicon.data.md5:aa11'") == [(None,)]


def test_a_failed_profile_request_retires_nothing(conn):
    go()
    later = D + timedelta(days=1)
    go(oa=FakeOA(day=later, over={"agents/artex": resp(None, 502, "HTTP 502: bad gateway")}), today=later + timedelta(days=1))
    assert q(conn, "select count(*) from aof_core.detection_rules where retired_day is not null")[0][0] == 0


# ---- retention ----------------------------------------------------------------------

def test_per_network_rows_are_pruned_after_the_retention_window_and_totals_are_kept(conn):
    go()
    far = D + timedelta(days=db.NETWORK_DAY_RETENTION_DAYS + 5)
    assert go(oa=FakeOA(day=far), today=far + timedelta(days=1)) == 0
    assert {r[0] for r in q(conn, "select distinct day from aof_derived.network_day where source_id = 'offensive_agency'")} == {far}
    assert (str(D), "*") in fw(conn, "offensive_agency", "active_7d_addresses")


# ---- the database's own defences ------------------------------------------------------

def test_raw_is_insert_only_gzip_only_and_refuses_a_key_in_a_url(conn):
    go()
    for sql in ("update aof_raw.fetches set ok = false", "delete from aof_raw.fetches", "delete from aof_raw.bodies"):
        with pytest.raises(psycopg.errors.RaiseException):
            conn.execute(sql)
        conn.rollback()
    with pytest.raises(psycopg.errors.RaiseException, match="not gzip"):
        conn.execute("insert into aof_raw.bodies values (%s, 9, %s)", ("a" * 64, b'{"ip": "1.2.3.4"}   '))
    conn.rollback()
    run_id = q(conn, "select run_id from raw.pipeline_runs where pipeline = 'aof'")[0][0]
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute("""insert into aof_raw.fetches (run_id, source_id, endpoint, url, day, requested_at, finished_at, http_status, ok, body_withheld)
                        values (%s, 'shodan', 'x', 'https://api.test/count?query=a&key=abc', %s, now(), now(), 200, true, 'no_body')""", (run_id, D))
    conn.rollback()
    # a search rule may contain the word: only a credential-shaped PARAMETER is refused
    conn.execute("""insert into aof_raw.fetches (run_id, source_id, endpoint, url, day, requested_at, finished_at, http_status, ok, body_withheld)
                    values (%s, 'shodan', 'x', 'https://api.test/count?query=http.html%%3A%%22artex_token%%22', %s, now(), now(), 200, true, 'no_body')""", (run_id, D))
    conn.rollback()


def test_the_store_refuses_an_address_even_when_asked_to_keep_the_body(conn):
    run_id = conn.execute("insert into raw.pipeline_runs (pipeline, mode, trigger) values ('aof', 'full', 'test') returning run_id").fetchone()[0]
    db.store_fetch(conn, run_id, db.OA, "clusters", D, resp({"meta": {}, "data": [{"note": "seen at 1.2.3.4"}]}), keep_body=True)
    assert q(conn, "select body_withheld, stored_hash from aof_raw.fetches where endpoint = 'clusters'") == [("carries_addresses", None)]
    assert q(conn, "select count(*) from aof_raw.bodies")[0][0] == 0
    db.store_fetch(conn, run_id, db.OA, "stats", D, resp({"meta": {}, "data": {"n": 1}}))
    (gz,) = q(conn, "select body_gz from aof_raw.bodies")[0]
    assert gzip.decompress(bytes(gz)) == b'{"meta": {}, "data": {"n": 1}}'


def test_nothing_is_reachable_by_the_public_roles(conn):
    for role in ("anon", "authenticated"):
        for target in (*AOF_TABLES, "aof_core.source_manifest"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(f"set local role {role}")
                conn.execute(f"select 1 from {target} limit 1")           # noqa: S608 - fixed list
            conn.rollback()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(f"set local role {role}")
            conn.execute("select public.agentic_c2_atlas()")
        conn.rollback()
    assert q(conn, "select count(*) from pg_tables where schemaname in ('aof_raw','aof_core','aof_derived') and not (rowsecurity)")[0][0] == 0


def test_the_pipeline_is_registered_with_the_watchdog_and_the_method_registry(conn):
    assert q(conn, "select workflow, cron, max_silence_hours, enabled, runs_table from core.pipeline_expectations where pipeline = 'aof'") == [
        ("aof-pipeline.yml", "10 3 * * *", 48, True, "raw.pipeline_runs")]
    (params,) = q(conn, "select parameters from core.method_registry where metric_id = 'agentic_c2' and method_version = %s", db.METHOD_VERSION)[0]
    assert params["window_days"] == CFG.window_days and params["network_day_retention_days"] == db.NETWORK_DAY_RETENTION_DAYS


# ---- the document the page reads --------------------------------------------------------

def doc(conn):
    return q(conn, "select public.agentic_c2_atlas()")[0][0]


def test_the_document_is_null_before_any_run(conn):
    assert doc(conn) is None


def test_the_document_carries_per_network_aggregates_from_both_sources(conn):
    go()
    d = doc(conn)
    assert (d["day"], d["shodan_day"], d["total"], d["unplaced"]) == (str(D), str(TODAY), 5, 1)
    assert d["method"]["version"] == db.METHOD_VERSION and d["censored_at"] == str(D)
    assert [(f["slug"], f["oa"], f["shodan"], f["rules"]) for f in d["frameworks"]] == [("artex", 4, 35, 2), ("pentagi", 2, 8, 1)]
    assert {s["id"]: (s["unit"], s["attribution"]) for s in d["sources"]} == {
        "offensive_agency": ("addresses", "offensive.agency, data by ONYPHE"), "shodan": ("services", "Shodan")}
    nodes = {n["a"]: n for n in d["nodes"]}
    assert set(nodes) == {64500, 64501, 64502}                                   # asn 0 is counted in `unplaced`, not drawn
    a = nodes[64500]
    assert (a["n"], a["t"], a["cc"]) == ("Named Network Ltd", "Hosting & VPS", "US")   # the atlas reference data names it
    assert (a["all"], a["f"], a["sh"]) == (3, {"artex": 3, "pentagi": 1}, {"artex": 25})   # US + HK summed; `all` is distinct
    b = nodes[64501]
    assert (b["n"], b["t"], b["cc"], b["f"], b["sh"]) == ("Second Net", "Other", "DE", {"pentagi": 1}, {"pentagi": 8})
    assert nodes[64502]["all"] is None and nodes[64502]["f"] == {} and nodes[64502]["sh"] == {"artex": 10}   # Shodan only
    assert "1.2.3.4" not in json.dumps(d)
    assert "series" not in d                                                     # one day is drawn; no history is shipped


def test_shodan_is_absent_from_the_document_when_its_day_is_too_far_from_the_drawn_one(conn):
    go()
    far = D + timedelta(days=5)
    go(oa=FakeOA(day=far), shodan=None, today=far + timedelta(days=1), both=False)       # only offensive.agency ran
    d = doc(conn)
    assert d["day"] == str(far) and d["shodan_day"] is None
    assert all(f["shodan"] is None for f in d["frameworks"]) and all(n["sh"] is None for n in d["nodes"])


# ---- added after the code review (each closes a gap its mutation run found) ---------------

BIG = models.parse_config(b"""
window_days = 7
min_interval_seconds = 1.1
[[framework]]
slug = "artex"
name = "ARTEX"
rules = [ { match = 'product:ARTEX', anchor = true }, { match = 'http.title:"r2"' }, { match = 'http.title:"r3"' },
          { match = 'http.title:"r4"' }, { match = 'http.title:"r5"' }, { match = 'http.title:"r6"' },
          { match = 'http.title:"r7"' }, { match = 'http.title:"r8"' }, { match = 'http.title:"r9"' }, { match = 'http.title:"r10"' } ]
[[framework]]
slug = "pentagi"
name = "PentAGI"
rules = [ { match = 'product:PentAGI' } ]
""")


def big_shodan(**kw):
    totals = {"product:ARTEX": (30, {64500: 30}), "product:PentAGI": (8, {64501: 8}),
              **{f'http.title:"r{i}"': (1, {64500: 1}) for i in range(2, 11)}}
    return FakeShodan(totals=totals, **kw)


def test_one_unanswered_rule_under_the_bar_leaves_only_its_framework_out(conn):
    """1 of 11 rules fails: under the 10% bar, so the run passes. The framework whose rule
    failed gets NO row for the day (not a short one); the other is stored in full."""
    rc = aof_run.run(FakeOA(), big_shodan(errors={"product:PentAGI"}), BIG, psycopg.connect(DSN), trigger="test", today=TODAY, secrets=(KEY,))
    assert rc == 0
    assert fw(conn, "shodan", "services_7d") == {(str(TODAY), "artex"): 39}
    assert q(conn, "select count(*) from aof_derived.network_day where source_id = 'shodan' and framework = 'pentagi'")[0][0] == 0
    d = doc(conn)
    assert {f["slug"]: f["shodan"] for f in d["frameworks"]} == {"artex": 39, "pentagi": None}   # null: not collected, not zero


def test_a_host_page_is_withheld_even_when_no_address_is_detectable_in_it(conn):
    """The host list is withheld because of what it IS, not because a pattern matched: these
    records carry only a loopback address, which the detector deliberately ignores."""
    hosts = [dict(h, ip="127.0.0.1") for h in HOSTS]
    assert go(oa=FakeOA(hosts=hosts)) == 0
    assert set(q(conn, "select body_withheld, stored_hash from aof_raw.fetches where endpoint like 'hosts:%%'")) == {("carries_addresses", None)}


def test_a_run_whose_profiles_list_no_rules_fails_and_retires_nothing(conn):
    go()
    later = D + timedelta(days=1)
    rc = go(oa=FakeOA(day=later, rules={"artex": [], "pentagi": [], "nebula": []}), today=later + timedelta(days=1))
    assert rc == 1
    assert q(conn, "select count(*), count(retired_day) from aof_core.detection_rules") == [(3, 0)]
    # nothing else of that failed source was written either: the framework rows still say day D
    assert q(conn, "select distinct last_seen_day from aof_core.frameworks") == [(D,)]
    assert {d for d, _ in fw(conn, "offensive_agency", "active_7d_addresses")} == {str(D)}


def test_one_profile_that_suddenly_lists_no_rules_retires_nothing(conn):
    go()
    later = D + timedelta(days=1)
    assert go(oa=FakeOA(day=later, rules={"artex": [], "pentagi": [("cert", 'cert.issuer.cn:"PentAGI CA"')]}), today=later + timedelta(days=1)) == 0
    assert q(conn, "select count(*) from aof_core.detection_rules where retired_day is not null")[0][0] == 0


def test_a_crash_leaves_the_request_log_and_no_half_written_source(conn, caplog):
    """The requests made before the crash stay recorded; frameworks, rules and counts of the
    crashed source are not written at all; and the message carries neither the key nor an address."""
    class Broken(FakeOA):
        def get(self, path, **params):
            if path == "timeline":
                raise RuntimeError(f"boom at 1.2.3.4 https://api.test/?key={KEY}")
            return super().get(path, **params)
    with caplog.at_level("INFO"):
        assert go(oa=Broken()) == 1
    assert q(conn, "select count(*) from aof_raw.fetches where source_id = 'offensive_agency'")[0][0] >= 5
    assert q(conn, "select count(*) from aof_core.frameworks")[0][0] == 0
    assert q(conn, "select count(*) from aof_core.detection_rules")[0][0] == 0
    ok, err, finished = q(conn, "select ok, error, finished_at from raw.pipeline_runs where pipeline = 'aof'")[0]
    assert ok is False and finished is not None
    for text in (caplog.text, err):
        assert KEY not in text and "1.2.3.4" not in text


def test_a_failure_after_both_sources_still_finishes_the_run_row(conn, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("gate crashed")
    monkeypatch.setattr(aof_run.evals, "evaluate", boom)
    assert go() == 1
    ok, err, finished = q(conn, "select ok, error, finished_at from raw.pipeline_runs where pipeline = 'aof'")[0]
    assert (ok, finished is not None) == (False, True) and "gate crashed" in err


def test_a_next_link_that_is_not_a_later_page_of_the_same_list_is_not_followed(conn):
    for bad in ("https://elsewhere.example/api/v1/hosts?offset=3", "/api/v1/hosts?scope=active&limit=3&offset=0",
                "/api/v1/domains?offset=3", "/api/v1/hosts?offset=x"):
        oa = FakeOA(over={"hosts": {"meta": {"total": 5, "next": bad, "count": 3}, "data": HOSTS[:3]}})
        assert go(oa=oa, shodan=FakeShodan()) == 1                       # the list is short, so the source is not stored
        assert oa.asked.count("hosts") == 1, bad
    assert q(conn, "select count(*) from aof_raw.fetches where url ~* 'elsewhere'")[0][0] == 0


def test_a_followed_next_link_contributes_its_offset_and_nothing_else_to_the_stored_url(conn):
    """The next page is requested with a URL we build. Whatever else the source put in its link
    (here a credential-shaped parameter) is neither sent on nor stored."""
    class Tokened(FakeOA):
        def get(self, path, **params):
            r = super().get(path, **params)
            if path == "hosts" and params.get("offset", 0) == 0:
                body = json.loads(r.body)
                body["meta"]["next"] = "/api/v1/hosts?token=abc&offset=3"
                return resp(body)
            return r
    oa = Tokened()
    assert go(oa=oa) == 0
    assert oa.asked.count("hosts") == 2
    assert q(conn, "select count(*) from aof_raw.fetches where url ~* 'token'")[0][0] == 0


def test_a_tracked_framework_with_no_address_is_a_stored_zero(conn):
    assert go(oa=FakeOA(idle=("cairn",))) == 0
    assert fw(conn, "offensive_agency", "active_7d_addresses")[(str(D), "cairn")] == 0
    assert "cairn" not in {f["slug"] for f in doc(conn)["frameworks"]}        # zero in both sources: not offered


def test_a_day_the_source_withdraws_from_its_timeline_is_removed(conn):
    go()
    assert (str(D - timedelta(days=1)), "pentagi") in fw(conn, "offensive_agency", "seen_day_addresses")
    tl = {"meta": {}, "data": {"days": [str(D - timedelta(days=1)), str(D)], "agents": {"artex": [3, 4]}, "total": [3, 4]}}
    go(oa=FakeOA(over={"timeline": tl}))
    assert {f for _, f in fw(conn, "offensive_agency", "seen_day_addresses")} == {"artex"}


def test_the_document_tells_found_nothing_from_not_collected_per_network(conn):
    go()
    nodes = {n["a"]: n for n in doc(conn)["nodes"]}
    # 64501: Shodan reports pentagi there. Give offensive.agency a network Shodan says nothing about.
    assert go(oa=FakeOA(hosts=[*HOSTS, host(64510, "FR", ("artex", "confirmed"), org="Only Listed Here")])) == 0
    nodes = {n["a"]: n for n in doc(conn)["nodes"]}
    assert nodes[64510]["sh"] == {} and nodes[64510]["all"] == 1               # attached, found nothing: an empty object, not null


def test_the_document_counts_live_rules_and_takes_the_country_from_the_source(conn):
    go()
    later = D + timedelta(days=1)
    hosts = [host(64500, "HK", ("artex", "confirmed")), host(64500, "HK", ("artex", "confirmed")), host(64500, "US", ("artex", "confirmed")),
             host(64500, "", ("artex", "confirmed")), host(64500, "", ("artex", "confirmed")), host(64500, "", ("artex", "confirmed")),
             host(64501, "DE", ("pentagi", "confirmed"))]
    go(oa=FakeOA(day=later, hosts=hosts, rules={"artex": [("title", 'html.title.text:"ARTEX"')], "pentagi": [("cert", 'cert.issuer.cn:"PentAGI CA"')]}),
       today=later + timedelta(days=1))
    d = doc(conn)
    assert {f["slug"]: f["rules"] for f in d["frameworks"]}["artex"] == 1       # the retired rule is not counted
    a = {n["a"]: n for n in d["nodes"]}[64500]
    assert a["cc"] == "HK"          # the source's majority stated country: not the reference's US, not the blank group
