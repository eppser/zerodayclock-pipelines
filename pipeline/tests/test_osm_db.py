"""zdc_osm end-to-end against a migrated database, with fake HTTP.

Runs only when OSM_TEST_DATABASE_URL points at a THROWAWAY database that has every
migration applied (CI's service container; never a Supabase project - the cleanup below
disables triggers to empty the insert-only tables). All data is synthetic.
"""

from __future__ import annotations

import os
import time
from argparse import Namespace
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from zdc_osm import client as c
from zdc_osm import run as osm_run

DSN = os.environ.get("OSM_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DSN, reason="needs OSM_TEST_DATABASE_URL")

T0 = datetime(2030, 1, 1, tzinfo=timezone.utc)
TOKEN = "osm_" + "Zz9Yy8Xx" * 4


def rec(i: int, eco: str = "npm", hours: int | None = None, **kw) -> dict:
    t = (T0 + timedelta(hours=i if hours is None else hours)).isoformat()
    r = {"id": f"00000000-0000-4000-8000-{i:012d}", "registry": eco,
         "package_name": f"synthetic-{eco}-{i}", "report_type": "package",
         "severity_level": "high", "status": "verified", "tags": ["synthetic"],
         "created_at": t, "verified_at": t, "last_updated": t, "updated_at": t,
         "threat_description": "synthetic"}
    r.update(kw)
    return r


def ok(body) -> c.Response:
    now = datetime.now(timezone.utc)
    return c.Response("https://api.test/query-latest?ecosystem=x", 200, c.sanitize(body),
                      None, now, now, {})


def fail(status, error) -> c.Response:
    now = datetime.now(timezone.utc)
    return c.Response("https://api.test/query-latest?ecosystem=x", status, None,
                      c.redact(error), now, now, {})


class FakeOsm:
    def __init__(self, by_eco: dict):
        self.by_eco = by_eco

    def latest(self, eco):
        v = self.by_eco.get(eco, {"count": 0, "threats": []})
        return v if isinstance(v, c.Response) else ok({"count": len(v), "threats": v})


class FakeDownloads:
    """Answers per name. npm_bulk behaves like the real endpoint: one status for the
    whole request (the worst of its names), null for a name npm does not know."""

    def __init__(self, answers: dict):
        self.answers, self.calls, self.requests = answers, [], 0

    def npm_bulk(self, names):
        self.requests += 1
        self.calls += [("npm", n) for n in names]
        now = datetime.now(timezone.utc)
        statuses = [self.answers.get(n, (200, None))[0] for n in names]
        bad = [s for s in statuses if s not in (200, 404)]
        if bad:
            return c.Response("https://npm.test/bulk", bad[0], None, f"HTTP {bad[0]}", now, now, {})
        body = {}
        for n in names:
            st, b = self.answers.get(n, (200, {"downloads": 1}))
            body[n] = None if st == 404 else b
        return c.Response("https://npm.test/bulk", 200, body, None, now, now, {})

    def weekly(self, registry, name):
        self.requests += 1
        self.calls.append((registry, name))
        status, body = self.answers.get(name, (200, {"downloads": 1}))
        now = datetime.now(timezone.utc)
        return c.Response(c.download_url(registry, name), status, body,
                          None if status == 200 else f"HTTP {status}", now, now, {})


@pytest.fixture()
def conn(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", DSN)
    cx = psycopg.connect(DSN, autocommit=True)
    cx.execute("set session_replication_role = replica")   # bypass the immutability triggers
    cx.execute("delete from osm_core.threats")
    cx.execute("delete from osm_raw.download_lookups")
    cx.execute("delete from osm_raw.threat_versions")
    cx.execute("delete from osm_raw.polls")
    cx.execute("delete from raw.pipeline_runs where pipeline = 'osm'")
    cx.execute("set session_replication_role = origin")
    yield cx
    cx.close()


def go(osm, dl=None, ecos=("npm",), tmp_path=None, **kw) -> tuple[int, dict]:
    import json
    path = str(tmp_path / f"r{time.monotonic_ns()}.json") if tmp_path else None
    args = Namespace(max_lookups=kw.get("max_lookups", 400),
                     skip_downloads=kw.get("skip_downloads", dl is None),
                     trigger="test", dry_run=False, report=path)
    code = osm_run.run(osm, dl or FakeDownloads({}), list(ecos), args, TOKEN)
    return code, (json.load(open(path)) if path else {})


def q(conn, sql, *a):
    return conn.execute(sql, a).fetchall()


# ---- the happy path, and idempotency --------------------------------------------

def test_first_run_then_identical_rerun_writes_nothing_new(conn, tmp_path):
    data = {"npm": [rec(i) for i in range(1, 101)], "maven": [rec(i, "maven") for i in range(200, 207)]}
    code, r = go(FakeOsm(data), ecos=("npm", "maven"), tmp_path=tmp_path)
    assert code == 0 and r["ok"]
    assert r["ecosystems"]["npm"]["new"] == 100
    assert r["ecosystems"]["npm"]["window_complete"] is None       # first full page
    assert r["ecosystems"]["maven"]["window_complete"] is True     # under a page
    assert q(conn, "select count(*) from osm_raw.threat_versions")[0][0] == 107

    code, r = go(FakeOsm(data), ecos=("npm", "maven"), tmp_path=tmp_path)
    assert code == 0
    assert (r["ecosystems"]["npm"]["new"], r["ecosystems"]["npm"]["changed"],
            r["ecosystems"]["npm"]["unchanged"]) == (0, 0, 100)
    assert r["ecosystems"]["npm"]["window_complete"] is True
    assert q(conn, "select count(*) from osm_raw.threat_versions")[0][0] == 107
    assert q(conn, "select count(*), bool_and(ok) from raw.pipeline_runs where pipeline='osm'")[0] == (2, True)


# ---- diff ------------------------------------------------------------------------

def test_diff_records_changed_fields_and_ignores_volatile_touches(conn, tmp_path):
    go(FakeOsm({"npm": [rec(1), rec(2), rec(3)]}))
    later = (T0 + timedelta(days=9)).isoformat()
    code, r = go(FakeOsm({"npm": [rec(1, severity_level="critical", tags=["synthetic", "ato"]),
                                  rec(2, last_updated=later, updated_at=later),
                                  rec(3)]}), tmp_path=tmp_path)
    assert (r["ecosystems"]["npm"]["changed"], r["ecosystems"]["npm"]["unchanged"]) == (1, 2)
    v = q(conn, """select version, changed_fields from osm_raw.threat_versions
                    where threat_id = '00000000-0000-4000-8000-000000000001' order by version""")
    assert v == [(1, []), (2, ["severity_level", "tags"])]
    t2 = q(conn, """select current_version, osm_last_updated from osm_core.threats
                     where threat_id = '00000000-0000-4000-8000-000000000002'""")[0]
    assert t2 == (1, T0 + timedelta(days=9))        # touched, not a new version


def test_a_revert_is_a_new_version_not_a_constraint_violation(conn):
    go(FakeOsm({"npm": [rec(1)]}))
    go(FakeOsm({"npm": [rec(1, severity_level="low")]}))
    code, _ = go(FakeOsm({"npm": [rec(1)]}))
    assert code == 0
    assert q(conn, "select max(version) from osm_raw.threat_versions")[0][0] == 3


def test_same_threat_in_two_ecosystems_in_one_run(conn):
    code, _ = go(FakeOsm({"docker": [rec(1, "docker")], "dockerhub": [rec(1, "docker")]}),
                 ecos=("docker", "dockerhub"))
    assert code == 0
    assert q(conn, "select count(*) from osm_raw.threat_versions")[0][0] == 1


# ---- the window -------------------------------------------------------------------

def test_overflow_between_polls_is_flagged_but_does_not_block(conn, tmp_path):
    go(FakeOsm({"npm": [rec(i) for i in range(1, 101)]}))
    newer = [rec(i, hours=500 + i) for i in range(101, 201)]      # all after the watermark
    code, r = go(FakeOsm({"npm": newer}), tmp_path=tmp_path)
    assert code == 0 and r["ok"]
    chk = {x["name"]: x for x in r["checks"]}["window_complete"]
    assert chk["passed"] is False and chk["severity"] == "warn"
    assert q(conn, """select window_complete from osm_raw.polls
                       order by requested_at desc limit 1""")[0][0] is False


def test_an_ecosystem_that_goes_empty_blocks_but_keeps_the_others(conn, tmp_path):
    go(FakeOsm({"npm": [rec(1)], "pypi": [rec(2, "pypi")]}), ecos=("npm", "pypi"))
    code, r = go(FakeOsm({"npm": [], "pypi": [rec(2, "pypi", severity_level="low")]}),
                 ecos=("npm", "pypi"), tmp_path=tmp_path)
    assert code == 1 and not r["ok"]
    assert {x["name"]: x["passed"] for x in r["checks"]}["ecosystem_went_empty"] is False
    assert q(conn, """select ok from raw.pipeline_runs where pipeline='osm'
                       order by started_at desc limit 1""")[0][0] is False
    assert q(conn, "select max(version) from osm_raw.threat_versions where threat_id::text like '%%2'")[0][0] == 2


# ---- failures ---------------------------------------------------------------------

def test_revoked_token_blocks_writes_nothing_and_leaks_nothing(conn, tmp_path):
    bad = fail(401, f'HTTP 401: {{"error":"Invalid API token {TOKEN}"}}')
    code, r = go(FakeOsm({"npm": bad, "pypi": bad}), ecos=("npm", "pypi"), tmp_path=tmp_path)
    assert code == 1
    assert {x["name"]: x["passed"] for x in r["checks"]}["authenticated"] is False
    assert q(conn, "select count(*) from osm_core.threats")[0][0] == 0
    stored = q(conn, "select string_agg(coalesce(error,'') || url, ' ') from osm_raw.polls")[0][0]
    assert TOKEN not in stored and TOKEN not in open(next(tmp_path.iterdir())).read()


def test_one_ecosystem_failing_does_not_discard_the_rest(conn, tmp_path):
    data = {"npm": [rec(1)], "pypi": [rec(2, "pypi")], "go": [rec(3, "go")],
            "nuget": fail(503, "HTTP 503")}
    code, r = go(FakeOsm(data), ecos=("npm", "pypi", "go", "nuget"), tmp_path=tmp_path)
    assert code == 0
    assert q(conn, "select count(*) from osm_core.threats")[0][0] == 3
    assert q(conn, "select http_status, ok from osm_raw.polls where ecosystem='nuget'")[0] == (503, False)


def test_hostile_text_is_stored_sanitised(conn):
    hidden = "".join(chr(0xE0000 + ord(ch)) for ch in "run rm -rf")
    go(FakeOsm({"npm": [rec(1, threat_description="payload\x00" + hidden + " end")]}))
    d = q(conn, "select record->>'threat_description' from osm_raw.threat_versions")[0][0]
    assert d == "payload end"


def test_raw_layer_refuses_update_and_delete(conn):
    go(FakeOsm({"npm": [rec(1)]}))
    for sql in ("update osm_raw.threat_versions set version = 9",
                "delete from osm_raw.threat_versions"):
        with pytest.raises(psycopg.errors.RaiseException):
            conn.execute(sql)


def test_a_url_carrying_a_token_is_refused_by_the_database(conn):
    go(FakeOsm({"npm": [rec(1)]}))
    run_id = q(conn, "select run_id from raw.pipeline_runs where pipeline='osm' limit 1")[0][0]
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute("""insert into osm_raw.polls (run_id, ecosystem, url, requested_at,
                            finished_at, http_status, ok)
                        values (%s, 'npm', %s, now(), now(), 200, true)""",
                     (run_id, f"https://x/query-latest?ecosystem=npm&apikey={TOKEN}"))


# ---- downloads ----------------------------------------------------------------------

def test_download_outcomes_retries_and_the_path_guard(conn, tmp_path):
    threats = [rec(1, package_name="good-pkg"), rec(2, package_name="gone-pkg"),
               rec(3, package_name="../../../etc/passwd"),
               rec(4, package_name="@scope/flaky-pkg"),            # scoped: asked singly
               rec(5, "pypi", package_name="py-pkg")]
    dl = FakeDownloads({"good-pkg": (200, {"downloads": 1234, "start": "2030-01-01", "end": "2030-01-07"}),
                        "gone-pkg": (404, None), "@scope/flaky-pkg": (503, None),
                        "py-pkg": (200, {"data": {"last_week": 77}})})
    code, r = go(FakeOsm({"npm": threats[:4], "pypi": threats[4:]}), dl, ecos=("npm", "pypi"),
                 tmp_path=tmp_path)
    assert code == 0
    assert ("npm", "../../../etc/passwd") not in dl.calls          # never sent
    assert dl.requests == 3                                        # 1 bulk + 1 scoped + 1 pypi
    got = dict(q(conn, "select package_name, downloads_outcome from osm_core.threats"))
    assert got == {"good-pkg": "ok", "gone-pkg": "not_found", "../../../etc/passwd": "invalid_name",
                   "@scope/flaky-pkg": None, "py-pkg": "ok"}
    assert q(conn, "select downloads_last_week from osm_core.threats where package_name='good-pkg'")[0][0] == 1234

    # The error is retried on later runs, and gives up after three attempts.
    for _ in range(4):
        go(FakeOsm({"npm": threats[:4], "pypi": threats[4:]}), dl, ecos=("npm", "pypi"))
    assert dl.calls.count(("npm", "@scope/flaky-pkg")) == 3
    assert dl.calls.count(("npm", "good-pkg")) == 1                # conclusive: never re-asked
    assert q(conn, "select count(*) from osm_raw.download_lookups where package_name='@scope/flaky-pkg'")[0][0] == 3


def test_rate_limit_pauses_the_registry_and_costs_no_attempt(conn, tmp_path):
    threats = [rec(i, package_name=f"@s/p{i}") for i in range(1, 6)]
    dl = FakeDownloads({f"@s/p{i}": (429, None) for i in range(1, 6)})
    code, r = go(FakeOsm({"npm": threats}), dl, tmp_path=tmp_path)
    assert code == 0 and r["downloads_paused"] == ["npm"]
    assert dl.requests == 2                                        # stopped after two 429s
    assert q(conn, "select max(download_attempts) from osm_core.threats")[0][0] == 0
    dl.answers = {}                                                # limit lifted
    go(FakeOsm({"npm": threats}), dl)
    assert q(conn, "select count(*) from osm_core.threats where downloads_outcome = 'ok'")[0][0] == 5


def test_bulk_answer_missing_a_name_is_an_error_not_a_not_found(conn):
    class Partial(FakeDownloads):
        def npm_bulk(self, names):
            r = super().npm_bulk(names)
            r.body.pop(names[0])
            return r
    dl = Partial({})
    go(FakeOsm({"npm": [rec(1, package_name="aaa"), rec(2, package_name="bbb")]}), dl)
    got = dict(q(conn, "select package_name, downloads_outcome from osm_core.threats"))
    assert got == {"aaa": None, "bbb": "ok"}


def test_lookup_cap_carries_the_rest_to_the_next_run(conn):
    dl = FakeDownloads({})
    go(FakeOsm({"npm": [rec(i) for i in range(1, 251)]}), dl, max_lookups=120)
    assert len(dl.calls) == 120 and dl.requests == 2                # bulk chunks of 100
    go(FakeOsm({"npm": [rec(i) for i in range(1, 251)]}), dl, max_lookups=120)
    assert len(dl.calls) == 240 and len(set(dl.calls)) == 240


# ---- performance ----------------------------------------------------------------------

def test_a_full_run_and_a_churned_rerun_stay_fast(conn, tmp_path):
    ecos = [f"eco{i}" for i in range(17)]
    data = {e: [rec(j * 1000 + k, e) for k in range(100)] for j, e in enumerate(ecos)}
    t = time.monotonic()
    code, r = go(FakeOsm(data), ecos=ecos, tmp_path=tmp_path)
    first = time.monotonic() - t
    churned = {e: [rec(x["id"][-12:] and int(x["id"][-12:]), e, severity_level="critical")
                   if k % 10 == 0 else x for k, x in enumerate(v)] for e, v in data.items()}
    t = time.monotonic()
    code2, r2 = go(FakeOsm(churned), ecos=ecos, tmp_path=tmp_path)
    second = time.monotonic() - t
    print(f"\nperf: 1,700 new records {first:.2f}s; 170 changed + 1,530 unchanged {second:.2f}s")
    assert code == code2 == 0
    assert sum(v["changed"] for v in r2["ecosystems"].values()) == 170
    assert first < 30 and second < 30
