"""The site probe's judgements, without the network.

Each check is a pure function over fetched facts; these pin what counts as a closed door, a complete header set,
a real redirect, and an exposure. Every test has a case that FAILS on purpose, so the probe cannot go vacuous.
"""
from __future__ import annotations

import json

import pytest

from tools import site_probe as P

GOOD_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}


# ---- HTTP -> HTTPS ----------------------------------------------------------------------------------
def test_redirect_to_https_on_the_same_host_passes():
    r = P.eval_https_redirect("zerodayclock.com", 301, "https://zerodayclock.com/")
    assert r.passed and r.severity == P.FAIL


@pytest.mark.parametrize("status,location", [
    (200, None),                                   # served over plain HTTP
    (301, "http://zerodayclock.com/"),             # redirect, but not to HTTPS
    (301, "https://evil.example/"),                # redirect off-site
    (0, None),                                     # unreachable
])
def test_anything_but_a_permanent_https_redirect_fails(status, location):
    r = P.eval_https_redirect("zerodayclock.com", status, location)
    assert not r.passed and r.severity == P.FAIL


def test_a_temporary_redirect_is_only_a_warning():
    r = P.eval_https_redirect("www.zerodayclock.com", 302, "https://www.zerodayclock.com/")
    assert not r.passed and r.severity == P.WARN


# ---- headers ---------------------------------------------------------------------------------------
def test_the_full_header_set_passes_and_is_case_insensitive():
    assert P.eval_security_headers("/", GOOD_HEADERS, production=True).passed
    assert P.eval_security_headers("/", {k.lower(): v for k, v in GOOD_HEADERS.items()}, production=True).passed


@pytest.mark.parametrize("drop,expect", [
    ("Strict-Transport-Security", "no Strict-Transport-Security"),
    ("Content-Security-Policy", "no Content-Security-Policy"),
    ("X-Frame-Options", "X-Frame-Options is not DENY"),
    ("X-Content-Type-Options", "nosniff"),
    ("Cross-Origin-Opener-Policy", "COOP"),
])
def test_each_missing_header_is_named(drop, expect):
    h = dict(GOOD_HEADERS)
    del h[drop]
    r = P.eval_security_headers("/", h, production=True)
    assert not r.passed and expect in r.summary


def test_a_short_hsts_or_a_csp_without_frame_ancestors_fails():
    h = dict(GOOD_HEADERS, **{"Strict-Transport-Security": "max-age=3600"})
    assert "HSTS max-age 3600" in P.eval_security_headers("/", h, production=True).summary
    h = dict(GOOD_HEADERS, **{"Content-Security-Policy": "default-src 'self'"})
    assert "frame-ancestors" in P.eval_security_headers("/", h, production=True).summary


def test_production_must_not_carry_a_staging_noindex_but_staging_may():
    h = dict(GOOD_HEADERS, **{"X-Robots-Tag": "noindex, nofollow, noarchive"})
    assert not P.eval_security_headers("/", h, production=True).passed
    assert P.eval_security_headers("/", h, production=False).passed


def test_x_powered_by_is_an_exposure():
    assert "X-Powered-By" in P.eval_security_headers("/", dict(GOOD_HEADERS, **{"X-Powered-By": "Next.js"}),
                                                     production=True).summary


# ---- admin paths -----------------------------------------------------------------------------------
def test_a_basic_challenge_or_an_access_redirect_is_a_closed_door():
    assert P.eval_admin_path("/admin", 401, {"WWW-Authenticate": 'Basic realm="x"'}).passed
    assert P.eval_admin_path("/admin", 302, {"Location": "https://team.cloudflareaccess.com/cdn-cgi/access/login/x"}).passed


@pytest.mark.parametrize("status,headers", [
    (200, {}),                                           # the page served
    (401, {}),                                           # 401 without a challenge is not Basic auth
    (302, {"Location": "https://zerodayclock.com/"}),    # redirected somewhere that is not Access
    (403, {}),                                           # a WAF block is not the password
])
def test_anything_else_on_an_admin_path_fails(status, headers):
    r = P.eval_admin_path("/admin", status, headers)
    assert not r.passed and r.severity == P.FAIL


def test_an_unreachable_admin_path_is_a_warning_not_an_exposure():
    r = P.eval_admin_path("/admin", 0, {})
    assert not r.passed and r.severity == P.WARN


# ---- CSRF, TLS, pages, health ----------------------------------------------------------------------
def test_the_roadmap_must_refuse_the_probe_itself():
    assert P.eval_roadmap_bot(403).passed
    assert not P.eval_roadmap_bot(200).passed


def test_csrf_needs_exactly_403():
    assert P.eval_csrf("x", 403).passed
    for s in (200, 204, 400, 401, 500):
        assert not P.eval_csrf("x", s).passed


def test_tls_expiry_bands():
    now = 1_700_000_000.0
    assert P.eval_tls("h", now + 90 * 86400, now).severity == P.INFO
    r = P.eval_tls("h", now + 10 * 86400, now)
    assert r.severity == P.WARN and not r.passed
    r = P.eval_tls("h", now + 3 * 86400, now)
    assert r.severity == P.FAIL and not r.passed
    assert P.eval_tls("h", None, now).severity == P.FAIL


def test_pages_all_200_passes_and_names_the_slowest():
    r = P.eval_pages("h", [("/", 200, 7.2), ("/about", 200, 0.3)])
    assert r.passed and "slowest / 7.2s" in r.summary
    r = P.eval_pages("h", [("/", 200, 1.0), ("/explorer", 500, 0.2), ("/ai", 404, 0.1)])
    assert not r.passed and "/explorer (500)" in r.summary and "/ai (404)" in r.summary


def test_health_is_reachability_not_freshness():
    body = json.dumps({"ok": False, "stalePipelines": ["netthreat"]}).encode()
    r = P.eval_health(503, body)
    assert r.passed and r.severity == P.INFO and "netthreat" in r.summary
    assert not P.eval_health(200, b"<html>").passed
    assert not P.eval_health(502, b"{}").passed


# ---- deployments -----------------------------------------------------------------------------------
def test_deployments_count_warns_and_an_open_hostname_fails():
    deps = [{"url": f"https://{i:08x}.p.pages.dev", "created_on": f"2026-10-{i + 1:02d}"} for i in range(31)]
    closed = {d["url"]: P.eval_admin_path(d["url"], 401, {"WWW-Authenticate": "Basic"}) for d in deps}
    count, doors = P.eval_deployments("p", deps, closed)
    assert count.severity == P.WARN and not count.passed and count.detail["count"] == 31
    assert doors.passed
    closed[deps[3]["url"]] = P.eval_admin_path(deps[3]["url"], 200, {})
    _, doors = P.eval_deployments("p", deps, closed)
    assert not doors.passed and doors.severity == P.FAIL and deps[3]["url"] in doors.detail["open"]


def test_list_deployments_paginates():
    pages = {1: [{"url": f"u{i}"} for i in range(25)], 2: [{"url": "u25"}]}

    def get(url, headers=None, **_):
        page = int(url.rsplit("page=", 1)[1])
        return P.Response(200, {}, json.dumps({"result": pages[page]}).encode(), url, 0.0)

    assert len(P.list_deployments(get, "t", "acct", "proj")) == 26


# ---- exposure --------------------------------------------------------------------------------------
def test_exposure_allowlist_judgement():
    allow = {"cves", "kev_entries", "rpc:lookup"}
    res = {r.name: r for r in P.eval_exposure({"cves", "kev_entries"}, set(), {"lookup"}, allow)}
    assert res["anon_readable"].passed and res["anon_writable"].passed and res["anon_executable"].passed
    res = {r.name: r for r in P.eval_exposure({"cves", "kev_entries", "secrets"}, {"cves"}, {"submit_signatory"}, allow)}
    assert not res["anon_readable"].passed and "secrets" in res["anon_readable"].summary
    assert not res["anon_writable"].passed and "cves" in res["anon_writable"].summary
    assert not res["anon_executable"].passed and "submit_signatory" in res["anon_executable"].summary


def test_a_relation_gone_from_the_database_is_information_only():
    res = {r.name: r for r in P.eval_exposure({"cves"}, set(), set(), {"cves", "old_view"})}
    assert res["anon_readable"].passed
    assert res["anon_allowlist_stale"].severity == P.INFO and "old_view" in res["anon_allowlist_stale"].summary


def test_the_shipped_allowlist_parses_and_allows_no_function():
    allow = P.read_allowlist()
    assert "cve_detail" in allow and "explorer_rows" in allow
    assert not any(a.startswith("rpc:") for a in allow)
    assert "signatory_submissions" not in allow and "admin_config" not in allow


# ---- orchestration with a fake network --------------------------------------------------------------
def test_http_checks_fail_when_the_site_regresses_and_pass_when_it_does_not():
    def site(hardened: bool):
        def get(url, method="GET", headers=None, body=None, **_):
            u = P.urllib.parse.urlsplit(url)
            if u.scheme == "http":
                return P.Response(301, {"location": f"https://{u.hostname}/"}, b"", url, 0.1)
            h = {k.lower(): v for k, v in GOOD_HEADERS.items()} if hardened else {}
            if u.path.lower().startswith(("/admin", "/api/admin")):
                return P.Response(401, dict(h, **{"www-authenticate": "Basic realm=x"}), b"", url, 0.1) if hardened \
                    else P.Response(200, h, b"admin", url, 0.1)
            if method == "POST":
                return P.Response(403 if hardened else 200, h, b"", url, 0.1)
            if u.path == "/api/health":
                return P.Response(503, h, json.dumps({"ok": False, "stalePipelines": []}).encode(), url, 0.1)
            if u.path == "/roadmap":
                return P.Response(403 if hardened else 200, h, b"", url, 0.1)
            return P.Response(200, h, b"<html>", url, 0.2)
        return get

    now = 1_700_000_000.0
    good = P.http_checks(get=site(True), tls=lambda h: now + 60 * 86400, now=now)
    assert not [r for r in good if not r.passed and r.severity == P.FAIL], P.render(good)
    bad = P.http_checks(get=site(False), tls=lambda h: now + 60 * 86400, now=now)
    failed = {r.name.split(":")[0] for r in bad if not r.passed and r.severity == P.FAIL}
    assert {"headers", "admin", "csrf"} <= failed
    assert "RESULT: FAILED" in P.render(bad)


def test_step_summary_is_a_markdown_table():
    s = P.step_summary([P.Result("x", P.FAIL, True, "a | b")], "T")
    assert s.startswith("### T") and "| x | pass | a / b |" in s
