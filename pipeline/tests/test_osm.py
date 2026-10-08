"""zdc_osm unit tests. No network, no database.

EVERY FIXTURE HERE IS SYNTHETIC. This file is mirrored to the public pipelines repo, and
OSM's terms forbid redistributing its records, so no real record, package name or
threat id from the feed may appear in it.
"""

from __future__ import annotations

import io
import json
import urllib.error
from datetime import datetime, timedelta, timezone

import pytest

from zdc_osm import client as c
from zdc_osm import evals
from zdc_osm.models import (PAGE, changed_fields, content_hash, parse_downloads,
                            parse_latest, parse_npm_bulk, window_complete)

T0 = datetime(2030, 1, 1, tzinfo=timezone.utc)
FAKE_TOKEN = "osm_" + "A1b2C3d4" * 4


def rec(i: int, **kw) -> dict:
    r = {"id": f"00000000-0000-4000-8000-{i:012d}", "registry": "npm",
         "package_name": f"synthetic-pkg-{i}", "report_type": "package",
         "severity_level": "high", "status": "verified", "tags": ["synthetic"],
         "created_at": (T0 + timedelta(hours=i)).isoformat(),
         "verified_at": (T0 + timedelta(hours=i)).isoformat(),
         "last_updated": (T0 + timedelta(hours=i)).isoformat(),
         "updated_at": (T0 + timedelta(hours=i)).isoformat(),
         "download_count": None}
    r.update(kw)
    return r


# ---- sanitising and secrets --------------------------------------------------

def test_sanitize_strips_tag_characters_and_nul_everywhere():
    hidden = "".join(chr(0xE0000 + ord(ch)) for ch in "ignore previous")
    body = {"threats": [{"d" + hidden: "ok\x00" + hidden, "t": ["a\x00b"]}]}
    out = c.sanitize(body)
    assert out == {"threats": [{"d": "ok", "t": ["ab"]}]}


def test_redact_scrubs_token_shaped_text():
    assert FAKE_TOKEN not in c.redact(f"HTTP 401: bad token {FAKE_TOKEN}")
    assert c.redact(None) is None
    assert c.redact("osm_short") == "osm_short"   # not token-shaped: left alone


def test_client_refuses_a_missing_or_foreign_token_without_echoing_it():
    for bad in ("", "sbp_" + "x" * 30, "Bearer osm_x"):
        with pytest.raises(ValueError) as e:
            c.OsmClient(bad)
        assert "sbp_" not in str(e.value)


def test_token_goes_in_the_header_never_the_url(monkeypatch):
    seen = {}

    def fake_urlopen(req, timeout, follow_redirects):
        seen["url"], seen["auth"] = req.full_url, req.get_header("Authorization")
        return _Resp(b'{"count":0,"threats":[]}')

    monkeypatch.setattr(c, "_open", fake_urlopen)
    r = c.OsmClient(FAKE_TOKEN, sleep=lambda s: None).latest("npm")
    assert r.status == 200
    assert FAKE_TOKEN not in seen["url"] and "apikey" not in seen["url"]
    assert seen["auth"] == f"Bearer {FAKE_TOKEN}"


def test_a_redirect_never_carries_the_token_to_another_host():
    """Real sockets: a 302 from the "API" to a different hostname must be refused, and
    the other host must never receive the Authorization header."""
    import http.server
    import threading
    seen = []

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path.startswith("/query-latest"):
                self.send_response(302)
                self.send_header("Location", f"http://localhost:{port}/elsewhere")
                self.end_headers()
            else:
                seen.append(self.headers.get("Authorization"))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"threats": []}')

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        r = c.OsmClient(FAKE_TOKEN, sleep=lambda s: None, retries=1,
                        base=f"http://127.0.0.1:{port}").latest("npm")
    finally:
        srv.shutdown()
    assert seen == [] and r.status == 302 and r.body is None


class _Resp(io.BytesIO):
    def __init__(self, body: bytes, headers=None):
        super().__init__(body)
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _http_error(code, body=b"", headers=None):
    return urllib.error.HTTPError("https://x.test", code, "err", headers or {}, io.BytesIO(body))


def test_retry_honours_retry_after_then_succeeds(monkeypatch):
    calls, slept = [], []

    def fake_urlopen(req, timeout, follow_redirects):
        calls.append(1)
        if len(calls) == 1:
            raise _http_error(429, b"slow down", {"Retry-After": "7"})
        return _Resp(b'{"ok":1}')

    monkeypatch.setattr(c, "_open", fake_urlopen)
    r = c._get("https://x.test", {}, timeout=1, retries=3, sleep=slept.append)
    assert r.status == 200 and r.body == {"ok": 1} and slept == [7]


def test_4xx_is_not_retried_and_error_is_redacted(monkeypatch):
    calls = []

    def fake_urlopen(req, timeout, follow_redirects):
        calls.append(1)
        raise _http_error(401, f'{{"error":"Invalid API token {FAKE_TOKEN}"}}'.encode())

    monkeypatch.setattr(c, "_open", fake_urlopen)
    r = c._get("https://x.test", {}, timeout=1, retries=3, sleep=lambda s: None)
    assert len(calls) == 1 and r.status == 401
    assert "Invalid API token" in r.error and FAKE_TOKEN not in r.error


def test_html_on_200_is_an_error_not_an_empty_feed(monkeypatch):
    monkeypatch.setattr(c, "_open",
                        lambda req, timeout, f: _Resp(b"<html>Attention Required</html>"))
    r = c._get("https://x.test", {}, timeout=1, retries=1, sleep=lambda s: None)
    assert r.body is None and "non-JSON" in r.error


def test_transport_failure_is_status_zero_after_retries(monkeypatch):
    def boom(req, timeout, f):
        raise TimeoutError("timed out")

    monkeypatch.setattr(c, "_open", boom)
    r = c._get("https://x.test", {}, timeout=1, retries=2, sleep=lambda s: None)
    assert r.status == 0 and "TimeoutError" in r.error


# ---- parsing -----------------------------------------------------------------

def test_parse_counts_malformed_and_dedupes_ids():
    body = {"threats": [rec(1), rec(1, severity_level="critical"), rec(2, id="not-a-uuid"),
                        "junk", rec(3, last_updated=None, updated_at=None),
                        rec(4, last_updated="2030-01-01T00:00:00",       # naive: refused
                            updated_at="2030-01-01T00:00:00"),
                        rec(5, last_updated="2030-01-01T00:00:00")]}     # falls back
    assert {t.threat_id[-1] for t in parse_latest(body, "npm")[0]} == {"1", "5"}
    threats, malformed, err = parse_latest(body, "npm")
    assert err is None and malformed == 4
    assert len(threats) == 2 and threats[0].record["severity_level"] == "critical"


def test_parse_rejects_a_body_without_a_threats_list():
    for body in (None, [], {"error": "x"}, {"threats": None}):
        assert parse_latest(body, "npm")[2] is not None


def test_parse_falls_back_to_the_requested_ecosystem():
    threats, _, _ = parse_latest({"threats": [rec(1, registry=None)]}, "pypi")
    assert threats[0].ecosystem == "pypi"


def test_content_hash_ignores_volatile_fields_only():
    a = rec(1)
    assert content_hash(a) == content_hash({**a, "last_updated": "2031-01-01T00:00:00+00:00",
                                            "updated_at": "x", "download_count": 5})
    assert content_hash(a) != content_hash({**a, "severity_level": "low"})


def test_changed_fields_is_the_diff_without_volatile_keys():
    a = rec(1)
    b = {**a, "severity_level": "critical", "tags": ["x"], "last_updated": "later", "new": 1}
    assert changed_fields(a, b) == ["new", "severity_level", "tags"]
    assert changed_fields(None, b) == []


@pytest.mark.parametrize("n,oldest,prev,expected", [
    (37, T0, None, True),                          # under a page: the whole set
    (PAGE, T0, None, None),                        # first full poll: unknowable
    (PAGE, T0, T0, True),                          # touches the watermark exactly
    (PAGE, T0, T0 + timedelta(seconds=1), True),
    (PAGE, T0 + timedelta(seconds=1), T0, False),  # gap: >100 updates in between
    (PAGE, None, T0, None),
])
def test_window_complete(n, oldest, prev, expected):
    assert window_complete(n, oldest, prev) is expected


# ---- download lookups ----------------------------------------------------------

@pytest.mark.parametrize("registry,name,ok", [
    ("npm", "left-pad", True), ("npm", "@scope/pkg.js", True), ("npm", "Legacy_Upper", True),
    ("npm", "../../../admin", False), ("npm", "@scope/../x", False), ("npm", "a/b", False),
    ("npm", "pkg?x=1", False), ("npm", "pkg%2f", False), ("npm", "", False),
    ("npm", None, False), ("npm", "x" * 215, False),
    ("pypi", "Django", True), ("pypi", "zope.interface", True), ("pypi", "a", True),
    ("pypi", "-bad", False), ("pypi", "bad-", False), ("pypi", "a/b", False),
    ("pypi", "a b", False), ("pypi", "pkg​", False),
    ("maven", "anything", False),
])
def test_valid_name_guards_the_url_path(registry, name, ok):
    assert c.valid_name(registry, name) is ok


def test_download_urls_encode_scopes_and_normalise_pypi():
    assert c.download_url("npm", "@scope/pkg").endswith("/last-week/@scope%2Fpkg")
    assert c.download_url("npm", "left-pad").endswith("/last-week/left-pad")
    assert c.download_url("pypi", "Zope.Interface").endswith("/zope.interface/recent")
    with pytest.raises(ValueError):
        c.download_url("maven", "x")


@pytest.mark.parametrize("registry,status,body,outcome,weekly", [
    ("npm", 200, {"downloads": 12, "start": "2030-01-01", "end": "2030-01-07"}, "ok", 12),
    ("npm", 200, {"downloads": 0, "start": "2030-01-01", "end": "2030-01-07"}, "ok", 0),
    ("npm", 404, None, "not_found", None),
    ("npm", 200, {"error": "package x not found"}, "not_found", None),
    ("npm", 200, {"error": "something else"}, "error", None),
    ("npm", 200, {"downloads": -1}, "error", None),
    ("npm", 200, {"downloads": True}, "error", None),
    ("npm", 429, None, "error", None),
    ("pypi", 200, {"data": {"last_week": 86, "last_month": 0}}, "ok", 86),
    ("pypi", 200, {"data": "x"}, "error", None),
    ("pypi", 404, None, "not_found", None),
    ("pypi", 0, None, "error", None),
])
def test_parse_downloads(registry, status, body, outcome, weekly):
    d = parse_downloads(registry, status, body, None)
    assert (d.outcome, d.weekly) == (outcome, weekly)


def test_parse_npm_bulk():
    body = {"a": {"downloads": 3}, "b": None}
    out = parse_npm_bulk(200, body, None, ["a", "b", "c"])
    assert (out["a"].outcome, out["a"].weekly) == ("ok", 3)
    assert out["b"].outcome == "not_found"
    assert out["c"].outcome == "error"                 # absent is not "not found"
    assert {d.outcome for d in parse_npm_bulk(429, None, "HTTP 429", ["a", "b"]).values()} == {"error"}
    assert parse_npm_bulk(200, {"error": "scoped packages are not supported"}, None, ["a"])["a"].outcome == "error"


def test_bulk_refuses_scoped_names():
    with pytest.raises(AssertionError):
        c.DownloadClient(sleep=lambda s: None).npm_bulk(["@scope/x"])


# ---- every gate can fail -------------------------------------------------------

def test_every_eval_can_fail():
    assert evals.check_authenticated({"npm": 401, "pypi": 200}).blocking
    assert evals.check_polls_answered({"a": 200, "b": 0}, {"b": "x"}).blocking
    assert not evals.check_polls_answered({"a": 200, "b": 200, "c": 200, "d": 500},
                                          {"d": "x"}).blocking
    assert evals.check_not_silently_empty({"npm": 0, "pypi": 0}).blocking
    assert evals.check_ecosystem_went_empty(["npm"]).blocking
    w = evals.check_window_complete({"npm": "gap"})
    assert not w.passed and not w.blocking            # WARN: visible, never blocking
    assert evals.check_malformed(90, 10).blocking
    assert not evals.check_malformed(99, 1).blocking
    assert evals.check_persisted(10, 9).blocking
    assert not evals.check_downloads({"error": 6, "ok": 4}).passed
    assert evals.check_no_token_leak(json.dumps({"x": FAKE_TOKEN}), FAKE_TOKEN).blocking
    assert not evals.check_no_token_leak("{}", FAKE_TOKEN).blocking
