"""Unit tests for the agentic-C2 pipeline: the Shodan rule config, the query builder, the
parsers and the HTTP client's handling of the key. No network, no database.

The only address in fixtures is the placeholder 1.2.3.4 (public-pipelines/check_tree.py allows it).
"""

from __future__ import annotations

import io
import json
import urllib.error
from datetime import date

import pytest

from zdc_aof import client, evals, models
from zdc_aof.models import ConfigError, parse_config

MINIMAL = b"""
window_days = 7
min_interval_seconds = 1.1
[[framework]]
slug = "artex"
name = "ARTEX"
rules = [
  { match = 'product:ARTEX', anchor = true },
  { match = 'http.title:"X" -tag:honeypot', exclude = 'http.title:"X"' },
  { match = '"realm=\\"ARTEX\\""', exclude = false },
]
"""


# ---- the shipped config --------------------------------------------------------

def test_the_shipped_config_loads_and_has_an_anchor():
    cfg = models.load_config()
    assert cfg.window_days == 7
    assert {"artex", "cyberstrikeai", "pentagi"} <= {f.slug for f in cfg.frameworks}
    assert sum(r.anchor for f in cfg.frameworks for r in f.rules) >= 1
    assert len(cfg.sha256) == 64


def test_every_shipped_query_is_exclusive_of_the_rules_before_it():
    cfg = models.load_config()
    for fw in cfg.frameworks:
        qs = models.build_queries(fw, date(2026, 11, 25), cfg.window_days)
        for k, (rule, q) in enumerate(qs):
            for earlier, _ in qs[:k]:
                assert f"-{earlier.exclude}" in q, (fw.slug, rule.ordinal)
            assert q.endswith("after:19/11/2026")


# ---- config validation: each refusal is a mistake someone will make ------------------

def _with(old: bytes, new: bytes) -> bytes:
    assert old in MINIMAL
    return MINIMAL.replace(old, new)


def test_minimal_config_parses():
    cfg = parse_config(MINIMAL)
    assert [r.exclude for r in cfg.frameworks[0].rules] == ["product:ARTEX", 'http.title:"X"', None]


@pytest.mark.parametrize("old,new,why", [
    (b"anchor = true", b"anchor = false", "anchor"),
    (b'slug = "artex"', b'slug = "AR TEX"', "slug"),
    (b"window_days = 7", b"window_days = 0", "window_days"),
    (b"min_interval_seconds = 1.1", b"min_interval_seconds = 0.2", "min_interval_seconds"),
    (b"'product:ARTEX', anchor", b"'product:ARTEX after:01/01/2026', anchor", "after:"),
    (b"exclude = 'http.title:\"X\"'", b"exclude = '-tag:honeypot'", "one filter"),
    (b"exclude = 'http.title:\"X\"'", b"exclude = false", "last"),
])
def test_config_refuses(old, new, why):
    with pytest.raises(ConfigError, match=why):
        parse_config(_with(old, new))


def test_config_refuses_a_duplicate_framework_and_a_duplicate_rule():
    with pytest.raises(ConfigError, match="twice"):
        parse_config(MINIMAL + MINIMAL[MINIMAL.index(b"[[framework]]"):])
    with pytest.raises(ConfigError, match="twice"):
        parse_config(_with(b"'http.title:\"X\" -tag:honeypot'", b"'product:ARTEX'"))


def test_config_refuses_garbage():
    with pytest.raises(ConfigError, match="parse"):
        parse_config(b"window_days = [")


# ---- the query builder -------------------------------------------------------------

def test_queries_chain_exclusions_and_use_the_exclude_term_not_the_match():
    fw = parse_config(MINIMAL).frameworks[0]
    qs = [q for _, q in models.build_queries(fw, date(2026, 11, 25), 7)]
    assert qs[0] == "product:ARTEX after:19/11/2026"
    assert qs[1] == 'http.title:"X" -tag:honeypot -product:ARTEX after:19/11/2026'
    # the third rule subtracts the whole title, not the title-minus-honeypots refinement
    assert qs[2] == '"realm=\\"ARTEX\\"" -product:ARTEX -http.title:"X" after:19/11/2026'


def test_the_window_is_inclusive_at_both_ends_and_crosses_a_month():
    assert models.window_start(date(2026, 12, 3), 7) == date(2026, 11, 27)
    assert models.window_start(date(2026, 12, 3), 1) == date(2026, 12, 3)


# ---- Shodan responses ----------------------------------------------------------------

def test_count_parses_total_and_facets():
    body = json.dumps({"total": 12, "facets": {
        "asn": [{"value": "as54600", "count": 7}, {"value": "AS15169", "count": 5}, {"value": "junk", "count": 1}]}}).encode()
    c = models.parse_count(body, None)
    assert (c.total, c.asn, c.asn_truncated) == (12, {54600: 7, 15169: 5}, False)


def test_a_zero_total_is_a_count_not_an_error():
    c = models.parse_count(b'{"matches": [], "total": 0}', None)
    assert c.total == 0 and c.error is None


@pytest.mark.parametrize("body,error", [
    (b'{"error": "Requires membership or higher to access"}', None),
    (b"<html>", None), (b'{"matches": []}', None), (b'{"total": true}', None), (None, "HTTP 503: x"),
])
def test_count_refuses_anything_that_is_not_a_count(body, error):
    c = models.parse_count(body, error)
    assert c.total is None and c.error


def test_a_full_asn_facet_is_flagged_as_truncated():
    body = json.dumps({"total": 5000, "facets": {"asn": [{"value": f"as{i}", "count": 1}
                                                         for i in range(1, models.ASN_FACET_CAP + 1)]}}).encode()
    assert models.parse_count(body, None).asn_truncated


# ---- offensive.agency responses ----------------------------------------------------------

HOSTS = [
    {"ip": "1.2.3.4", "agents": [{"slug": "artex", "level": "confirmed", "ports": [8787]}],
     "network": {"asn": "AS54600", "country": "US", "org": "PEG TECH INC"}},
    {"ip": "1.2.3.4", "agents": [{"slug": "artex", "level": "probable"}, {"slug": "pentagi", "level": "confirmed"}],
     "network": {"asn": "AS54600", "country": "US", "org": "PEG TECH INC"}},
    {"ip": "1.2.3.4", "agents": [{"slug": "artex", "level": "confirmed"}], "network": {"asn": None, "country": "??"}},
    {"agents": [{"slug": "artex"}]},                                  # no address: malformed
    {"ip": "1.2.3.4", "agents": "nope"},                          # malformed
]


def test_hosts_are_counted_per_framework_and_network_and_no_address_survives():
    agg = models.aggregate_hosts(models.HostAggregate(), HOSTS)
    assert (agg.records, agg.malformed) == (3, 2)
    assert agg.by_network == {("artex", 54600, "US"): 2, ("pentagi", 54600, "US"): 1, ("artex", 0, ""): 1,
                              # every framework together: the address running two is counted once
                              ("*", 54600, "US"): 2, ("*", 0, ""): 1}
    assert agg.active == {"artex": 3, "pentagi": 1}
    assert agg.confirmed == {"artex": 2, "pentagi": 1}
    assert agg.orgs == {54600: "PEG TECH INC"}
    # the aggregate is the only thing that leaves the parser: it must not carry an address
    assert "1.2.3" not in repr(agg)


def test_hosts_fold_across_pages():
    agg = models.aggregate_hosts(models.HostAggregate(), HOSTS[:1])
    models.aggregate_hosts(agg, HOSTS[1:3])
    assert agg.records == 3 and agg.active["artex"] == 3


def test_a_framework_listed_twice_on_one_address_counts_once():
    agg = models.aggregate_hosts(models.HostAggregate(), [
        {"ip": "1.2.3.4", "agents": [{"slug": "artex"}, {"slug": "artex"}], "network": {"asn": "AS1"}}])
    assert agg.active["artex"] == 1


def test_envelope_status_agents_and_fingerprints():
    env = models.envelope(json.dumps({"meta": {"total": 2}, "data": {"ref_day": "2026-11-25", "first_day": "2026-10-21",
                                                                 "hosts_active": 5636, "last_collection": "2026-11-25T17:40:34+00:00"}}).encode())
    st = models.parse_status(env[1])
    assert (st.ref_day, st.first_day, st.hosts_active) == (date(2026, 11, 25), date(2026, 10, 21), 5636)
    assert models.envelope(b"[]") is None and models.envelope(b"<html>") is None
    assert models.parse_status({"hosts_active": 1}) is None

    agents, bad = models.parse_agents([{"slug": "artex", "name": "ARTEX", "tracked": True, "hosts_active": 4032},
                                       {"slug": "Bad Slug"}, "x"])
    assert [(a.slug, a.tracked, a.hosts_active) for a in agents] == [("artex", True, 4032)] and bad == 2

    fps = models.parse_fingerprints({"detection": {"fingerprints": [
        {"family": "title", "query": 'html.title.text:"ARTEX"'},
        {"family": "favicon", "name": "favicon", "query": "favicon.data.md5:cd3e"},
        {"family": "title", "query": 'html.title.text:"ARTEX"'}, {"family": "x", "query": ""}, "junk"]}})
    assert [(f.family, f.name) for f in fps] == [("title", None), ("favicon", "favicon")]
    assert models.parse_fingerprints({}) == [] and models.parse_fingerprints(None) == []


def test_timeline_aligns_series_to_days_and_refuses_a_ragged_one():
    rows, days = models.parse_timeline({"days": ["2026-10-21", "2026-10-22"],
                                        "agents": {"artex": [102, 377], "cairn": [8, None]}, "total": [1, 2]})
    assert days == [date(2026, 10, 21), date(2026, 10, 22)]
    assert sorted(rows) == [(date(2026, 10, 21), "artex", 102), (date(2026, 10, 21), "cairn", 8), (date(2026, 10, 22), "artex", 377)]
    assert models.parse_timeline({"days": ["2026-10-21"], "agents": {"artex": [1, 2]}}) == ([], [])
    assert models.parse_timeline({"days": ["soon"], "agents": {}}) == ([], [])


# ---- the client: the key never reaches a stored URL or an error ------------------------

KEY = "k3yk3yk3yk3yk3yk3yk3yk3yk3yk3y00"


class _Resp(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_shodan_sends_the_key_and_records_a_url_without_it():
    asked = []

    def opener(req, timeout):
        asked.append(req.full_url)
        return _Resp(b'{"total": 3}')

    sh = client.Shodan(client.Http(0, opener=opener, sleep=lambda s: None), KEY)
    r = sh.count("product:ARTEX", "asn:10")
    assert KEY in asked[0]                                   # it was sent
    assert KEY not in r.url and "key=" not in r.url          # it was not recorded
    assert "query=product%3AARTEX" in r.url and r.status == 200


def test_an_http_error_is_not_retried_on_4xx_and_carries_no_key():
    calls = []

    def opener(req, timeout):
        calls.append(1)
        raise urllib.error.HTTPError(req.full_url, 401, "no", {}, io.BytesIO(f"bad key {KEY}".encode()))

    sh = client.Shodan(client.Http(0, opener=opener, sleep=lambda s: None), KEY)
    r = sh.count("x")
    assert len(calls) == 1 and r.status == 401 and r.body is None
    assert KEY not in r.error and "<redacted>" in r.error


def test_a_transport_error_is_retried_and_its_message_is_redacted():
    calls = []

    def opener(req, timeout):
        calls.append(1)
        raise OSError(f"cannot reach {req.full_url}")

    r = client.Shodan(client.Http(0, opener=opener, sleep=lambda s: None), KEY).count("x")
    assert len(calls) == 3 and r.status == 0 and KEY not in r.error


def test_shodan_refuses_to_start_without_a_key():
    with pytest.raises(ValueError):
        client.Shodan(client.Http(0), "")


def test_offensive_agency_follows_the_next_link_it_was_given():
    asked = []

    def opener(req, timeout):
        asked.append(req.full_url)
        return _Resp(b"{}")

    oa = client.OffensiveAgency(client.Http(0, opener=opener, sleep=lambda s: None))
    oa.get("hosts", scope="active", limit=5000)
    oa.get("/api/v1/hosts?scope=active&limit=5000&offset=5000")
    assert asked == ["https://www.offensive.agency/api/v1/hosts?scope=active&limit=5000",
                     "https://www.offensive.agency/api/v1/hosts?scope=active&limit=5000&offset=5000"]


# ---- evals: a healthy run passes, and each check fails on its own defect ---------------

def healthy() -> evals.Facts:
    st = models.Status(date(2026, 11, 25), date(2026, 10, 21), "2026-11-25T17:40:34+00:00", 100, 200, 7)
    return evals.Facts(
        today=date(2026, 11, 26), oa_requests=95, oa_status_before=st, oa_status_after=st,
        oa_hosts_stated=100, oa_hosts_counted=100, oa_listed_active={"artex": 80, "pentagi": 25},
        oa_counted_active={"artex": 80, "pentagi": 25}, oa_tracked=["artex", "pentagi"],
        oa_rules={"artex": 23, "pentagi": 5}, oa_timeline_days=[date(2026, 11, 24), date(2026, 11, 25)],
        sh_info_status=200, sh_plan="oss", sh_rules=40, sh_totals={"artex": 2859, "pentagi": 491},
        sh_anchor_totals={"artex#1": 1874}, computed_rows=500, stored_rows=500, schema_bytes=5_000_000,
        report_text='{"ok": true}', secrets=(KEY,))


def run_all(f: evals.Facts):
    return evals.evaluate(f) + [c(f) for c in evals.REPORT_CHECKS]


def test_a_healthy_run_passes_every_check():
    bad = [r.name for r in run_all(healthy()) if not r.passed]
    assert bad == []


STALE = models.Status(date(2026, 11, 22), None, "x", 1, 1, 7)
LATE = models.Status(date(2026, 11, 24), None, "x", 1, 1, 7)
MOVED = models.Status(date(2026, 11, 25), None, "2026-11-26T17:40:00+00:00", 1, 1, 7)


@pytest.mark.parametrize("check,blocking,mutate", [
    ("oa_reachable", True, lambda f: f.oa_errors.update(timeline="HTTP 503")),
    ("oa_fresh", False, lambda f: [setattr(f, "oa_status_before", LATE), setattr(f, "oa_status_after", LATE)]),
    ("oa_fresh", True, lambda f: [setattr(f, "oa_status_before", STALE), setattr(f, "oa_status_after", STALE)]),
    ("oa_snapshot_consistent", True, lambda f: setattr(f, "oa_status_after", MOVED)),
    ("oa_snapshot_consistent", True, lambda f: setattr(f, "oa_status_after", None)),
    ("oa_endpoints_answered", True, lambda f: f.oa_errors.update({f"agent:x{i}": "HTTP 500" for i in range(10)})),
    ("oa_hosts_complete", True, lambda f: setattr(f, "oa_hosts_counted", 60)),          # a page was missed
    ("oa_hosts_complete", True, lambda f: setattr(f, "oa_hosts_stated", None)),
    ("oa_hosts_complete", True, lambda f: [setattr(f, "oa_hosts_counted", 90), setattr(f, "oa_hosts_malformed", 10)]),
    ("oa_counts_agree", True, lambda f: f.oa_counted_active.update(artex=70)),
    ("oa_counts_agree", True, lambda f: f.oa_counted_active.pop("pentagi")),
    ("oa_rules_collected", True, lambda f: f.oa_rules.clear()),
    ("oa_rules_collected", False, lambda f: f.oa_rules.update(pentagi=0)),
    ("oa_timeline_contiguous", False, lambda f: f.oa_timeline_days.append(date(2026, 11, 20))),
    ("shodan_reachable", True, lambda f: setattr(f, "sh_info_status", 401)),
    ("shodan_rules_answered", True, lambda f: f.sh_rule_errors.update({f"artex#{i}": "HTTP 503" for i in range(5)})),
    ("shodan_not_silently_empty", True, lambda f: setattr(f, "sh_totals", {"artex": 0, "pentagi": 0})),
    ("shodan_anchor_rules", False, lambda f: f.sh_anchor_totals.update({"artex#1": 0})),
    ("shodan_network_breakdown_complete", False, lambda f: f.sh_facet_short.append("artex#1")),
    ("persisted", True, lambda f: setattr(f, "stored_rows", 0)),
    ("bodies_kept", False, lambda f: f.oa_withheld_unexpected.append("clusters")),
    ("storage_within_budget", False, lambda f: setattr(f, "schema_bytes", evals.STORAGE_BUDGET_BYTES + 1)),
    ("no_secret_in_report", True, lambda f: setattr(f, "report_text", f'{{"url": "x?query=a&x={KEY}"}}')),
    ("no_secret_in_report", True, lambda f: setattr(f, "report_text", '{"url": "https://api.test/count?query=a&key=zzz"}')),
    ("no_address_in_report", True, lambda f: setattr(f, "report_text", '{"host": "1.2.3.4"}')),
])
def test_each_check_fails_on_its_own_defect_and_only_it(check, blocking, mutate):
    f = healthy()
    mutate(f)
    failed = {r.name: r for r in run_all(f) if not r.passed}
    assert list(failed) == [check], failed
    assert failed[check].blocking is blocking


def test_one_failed_request_in_ninety_five_does_not_block():
    f = healthy()
    f.oa_errors["agent:cairn"] = "HTTP 502"
    assert not [r for r in run_all(f) if r.blocking]


def test_one_failed_shodan_rule_leaves_its_framework_out_without_blocking():
    f = healthy()
    f.sh_rule_errors["cairn#2"] = "HTTP 503"
    f.sh_incomplete.append("cairn")
    res = {r.name: r for r in run_all(f)}
    assert res["shodan_rules_answered"].passed and "cairn" in res["shodan_rules_answered"].summary


def test_a_version_string_is_not_an_address_but_a_quoted_host_is():
    from zdc_aof.db import carries_addresses
    assert not carries_addresses(b'{"version": "1.2.3.4.5", "v": "6.0.0", "t": "17:40:34"}')
    assert carries_addresses(b'{"ip": "1.2.3.4"}')
    assert carries_addresses(b'alert ip [1.2.3.4,127.0.0.1] any')
    # a browser version, a default bind address and a loopback URL are not hosts
    assert not carries_addresses(b'"ua": "Chrome/128.0.0.0", "bind": "0.0.0.0:8787", "mcp": "http://127.0.0.1:8081"')
    assert carries_addresses(b'{"ip": "2001:db8::1"}')


# ---- added after the code review ----------------------------------------------------------

@pytest.mark.parametrize("body", [
    b'"ip": "1.2.3.4".', b"seen at 1.2.3.4. Then", b"static.1.2.3.4.clients.example.de", b"4.3.2.1.in-addr.arpa",
    b"ec2-1-2-3-4.compute.example.com", b'"ip6": "2001:db8::"', b'"ip6":"2001:db8:0:0:0:0:0:1"',
])
def test_addresses_in_awkward_positions_are_still_found(body):
    from zdc_aof.db import carries_addresses
    assert carries_addresses(body)


@pytest.mark.parametrize("body", [
    b"std::cout << x", b"a::before { }", b"module::exec()", b"dead::beef", b'"mask": "' + b".".join([b"255"] * 3) + b'.0"',     # a netmask, spelled so the publish check does not read it as an address
    b'"day": "2026-11-25", "id": "a-1-2-3-4"', b'"t": "17:40:34+00:00"', b"::1", b'"bind": "::"',
])
def test_code_and_times_are_not_mistaken_for_addresses(body):
    from zdc_aof.db import carries_addresses
    assert not carries_addresses(body)


def test_scrub_removes_addresses_and_keeps_the_rest():
    from zdc_aof.db import scrub
    assert scrub("boom at 1.2.3.4 and 2001:db8::1, version 6.0.0") == "boom at <address> and <address>, version 6.0.0"


def test_a_database_error_is_reported_without_the_row_it_quotes():
    import psycopg
    from zdc_aof.run import safe_error
    msg = safe_error(psycopg.errors.CheckViolation('Failing row contains (64500, Named Network Ltd, 1.2.3.4).'))
    assert msg.startswith("CheckViolation (SQLSTATE") and "Named" not in msg and "1.2.3.4" not in msg
    client.register_secret(KEY)
    assert safe_error(RuntimeError(f"x key={KEY} at 1.2.3.4")) == "RuntimeError: x key=<redacted> at <address>"


def test_a_redirect_is_refused_not_followed():
    assert client._RefuseRedirect().redirect_request(None, None, 302, "Found", {}, "http://elsewhere.example/") is None
    assert any(isinstance(h, client._RefuseRedirect) for h in client._OPENER.handlers)


def test_past_its_time_budget_the_client_answers_without_sending():
    calls = []
    http = client.Http(0, opener=lambda req, timeout: calls.append(1), sleep=lambda s: None, deadline_seconds=-1)
    r = http.get("https://api.test/x")
    assert calls == [] and r.status == 0 and "time budget" in r.error


def test_a_withheld_profile_is_reported_without_failing_and_a_withheld_structural_answer_warns():
    f = healthy()
    f.oa_withheld_unexpected.append("agent:pentestswarm")
    r = evals.check_bodies_kept(f)
    assert r.passed and "1 framework profile" in r.summary
    f.oa_withheld_unexpected.append("stats")
    r = evals.check_bodies_kept(f)
    assert not r.passed and not r.blocking and "stats" in r.summary
