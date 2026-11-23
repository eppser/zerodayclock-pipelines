"""Two enrichment checks that failed scheduled runs on correct data, against a migrated database.

Runs only when SCAN_TEST_DATABASE_URL points at a THROWAWAY database with every migration
applied (CI's service container). Each test works inside one transaction and rolls it
back, so nothing it writes survives. All data is synthetic, dated 2033.

The list is built by the real derived.rebuild_explorer_list, so the completeness check is
held against the function it describes and cannot drift from it unnoticed again.
"""

from __future__ import annotations

import os

import psycopg
import pytest

from zdc_enrich import evals

DSN = os.environ.get("SCAN_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DSN, reason="needs SCAN_TEST_DATABASE_URL")

CENSORED = "2033-06-30"

KEV_LISTED = "CVE-2033-2001"      # in a catalogue, never seen by a sensor
COUNTED = "CVE-2033-2002"         # seen by Shadowserver's API feed: carries a count
CANARY_ONLY = "CVE-2033-2003"     # seen by the canary alone, not catalogued: count is 0
UNSEEN = "CVE-2033-2004"          # nothing at all
VENDOR_ONLY = "CVE-2033-2005"     # a vendor statement and nothing else
SEEN_LATER = "CVE-2033-2006"      # the canary saw it after the censoring date

SEED = f"""
insert into obs_raw.pipeline_runs (pipeline, mode, trigger) values ('explorerchk', 'full', 'test');
insert into obs_raw.source_fetches (run_id, source_id, url, request_mode, ok, http_status)
select run_id, s, 'https://example.invalid/' || s, 'full', true, 200
  from obs_raw.pipeline_runs, unnest(array['shadowserver_api', 'vulncheck_canary', 'msrc']) s
 where pipeline = 'explorerchk';
insert into derived.cve_detail (cve_id, method_version, censored_at, kev_status, observation_count_total)
values ('{KEV_LISTED}',  'v3', date '{CENSORED}', 'in_kev',     0),
       ('{COUNTED}',     'v3', date '{CENSORED}', 'not_in_kev', 7),
       ('{CANARY_ONLY}', 'v3', date '{CENSORED}', 'not_in_kev', 0),
       ('{UNSEEN}',      'v3', date '{CENSORED}', 'not_in_kev', 0),
       ('{VENDOR_ONLY}', 'v3', date '{CENSORED}', 'not_in_kev', 0),
       ('{SEEN_LATER}',  'v3', date '{CENSORED}', 'not_in_kev', 0);
insert into obs_core.exploitation_observations (
    source_id, source_entry_id, observation_type, vuln_id, vuln_id_type, cve_id,
    observed_at, observation_count, raw, content_hash, first_fetch_id, last_fetch_id)
select x.src, x.vid || '@' || coalesce(x.d::text, 'undated'), x.typ, x.vid, 'cve', x.vid,
       x.d, x.n, '{{}}'::jsonb, md5(x.src || x.vid), f.fetch_id, f.fetch_id
  from (values
        ('shadowserver_api', 'attempt_observed',            '{COUNTED}',     date '2033-06-01', 7),
        ('vulncheck_canary', 'attempt_observed',            '{CANARY_ONLY}', date '2033-06-29', 1),
        ('msrc',             'vendor_reports_exploitation', '{VENDOR_ONLY}', null::date,        null::int),
        ('vulncheck_canary', 'attempt_observed',            '{SEEN_LATER}',  date '2033-07-02', 1))
       as x(src, typ, vid, d, n)
 cross join lateral (select fetch_id from obs_raw.source_fetches
                      where source_id = x.src order by fetch_id desc limit 1) f;
"""


@pytest.fixture()
def conn():
    cx = psycopg.connect(DSN)
    cx.execute("set timezone = 'UTC'")
    cx.execute(SEED)
    cx.execute("select derived.rebuild_explorer_list('v3', %s::date, null)", (CENSORED,))
    yield cx
    cx.rollback()
    cx.close()


def listed(cx) -> set[str]:
    return {r[0] for r in cx.execute("select cve_id from derived.explorer_list").fetchall()}


def test_the_rebuild_lists_a_vulnerability_only_the_canary_has_seen(conn):
    """The premise: the list has a third arm the count does not cover."""
    assert listed(conn) == {KEV_LISTED, COUNTED, CANARY_ONLY}


def test_complete_passes_on_the_list_the_rebuild_produced(conn):
    """21 November 2026: CVE-2023-6019, seen by the canary at 17:34 and catalogued the next morning,
    failed two enrichment runs as 'holds 6,260 rows but the predicate selects 6,259'."""
    r = evals.check_explorer_list_complete(conn)
    assert r.passed, r.summary
    assert r.detail["in_list"] == r.detail["expected"] == 3


def test_complete_FAILS_and_names_a_missing_row(conn):
    conn.execute("delete from derived.explorer_list where cve_id = %s", (CANARY_ONLY,))
    r = evals.check_explorer_list_complete(conn)
    assert not r.passed and r.blocking
    assert r.detail["missing"] == [CANARY_ONLY] and r.detail["not_selected"] == []
    assert CANARY_ONLY in r.summary


def test_complete_FAILS_and_names_a_row_the_predicate_does_not_select(conn):
    conn.execute("""insert into derived.explorer_list (cve_id, method_version, censored_at, computed_at)
                    values (%s, 'v3', %s::date, now())""", (UNSEEN, CENSORED))
    r = evals.check_explorer_list_complete(conn)
    assert not r.passed and r.blocking
    assert r.detail["not_selected"] == [UNSEEN] and r.detail["missing"] == []


def test_complete_FAILS_when_equal_counts_hide_a_swap(conn):
    """One row missing and one row extra: the two counts agree and the old check passed."""
    conn.execute("delete from derived.explorer_list where cve_id = %s", (COUNTED,))
    conn.execute("""insert into derived.explorer_list (cve_id, method_version, censored_at, computed_at)
                    values (%s, 'v3', %s::date, now())""", (UNSEEN, CENSORED))
    r = evals.check_explorer_list_complete(conn)
    assert r.detail["in_list"] == r.detail["expected"]
    assert not r.passed


OLD_VENDOR_ONLY_SQL = """
    select distinct source_id from obs_core.exploitation_observations
     where observation_type = 'vendor_reports_exploitation'
       and source_id not in (select source_id from obs_core.exploitation_observations
                              where observation_type = 'attempt_observed')
"""


def vendor_only(cx, sql) -> set[str]:
    return {r[0] for r in cx.execute(sql).fetchall()}


def test_vendor_only_sources_match_the_query_they_replace(conn):
    assert vendor_only(conn, evals.VENDOR_ONLY_SOURCES_SQL) == vendor_only(conn, OLD_VENDOR_ONLY_SQL) == {"msrc"}


def test_a_source_that_reports_both_types_is_not_vendor_only(conn):
    conn.execute("""insert into obs_core.exploitation_observations (
                        source_id, source_entry_id, observation_type, vuln_id, vuln_id_type, cve_id,
                        observed_at, raw, content_hash, first_fetch_id, last_fetch_id)
                    select 'msrc', 'sensor-row', 'attempt_observed', %s, 'cve', %s, date '2033-06-02',
                           '{}'::jsonb, 'x', fetch_id, fetch_id
                      from obs_raw.source_fetches where source_id = 'msrc' order by fetch_id desc limit 1""",
                 (UNSEEN, UNSEEN))
    assert vendor_only(conn, evals.VENDOR_ONLY_SOURCES_SQL) == vendor_only(conn, OLD_VENDOR_ONLY_SQL) == set()


def test_sensor_check_passes_and_FAILS_on_a_leak(conn):
    assert evals.check_sensors_are_not_vendor_reports(conn).passed
    conn.execute("update derived.explorer_list set sensor_sources = array['msrc'] where cve_id = %s",
                 (KEV_LISTED,))
    r = evals.check_sensors_are_not_vendor_reports(conn)
    assert not r.passed and r.detail["leaked"] == 1 and r.detail["vendor_only_sources"] == ["msrc"]
