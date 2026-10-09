"""The CrowdSec IDS charts' eval against a migrated database, both directions.

Runs only when SCAN_TEST_DATABASE_URL points at a THROWAWAY database with every migration
applied (CI's service container). Each test works inside one transaction and rolls it
back, so nothing it writes survives. All data is synthetic, dated 2033.
"""

from __future__ import annotations

import os

import psycopg
import pytest

from zdc_enrich import evals

DSN = os.environ.get("SCAN_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DSN, reason="needs SCAN_TEST_DATABASE_URL")

CENSORED = "2034-02-15"

SEED = """
insert into obs_raw.pipeline_runs (pipeline, mode, trigger) values ('scancomb', 'full', 'test');
insert into obs_raw.source_fetches (run_id, source_id, url, request_mode, ok, http_status)
select run_id, s, 'https://example.invalid/' || s, 'full', true, 200
  from obs_raw.pipeline_runs, unnest(array['shadowserver_api', 'crowdsec']) s
 where pipeline = 'scancomb';
insert into core.cves (cve_id, cve_year, date_published) values
  ('CVE-2033-1001', 2033, timestamptz '2027-01-01'),
  ('CVE-2033-1002', 2033, timestamptz '2032-06-01'),
  ('CVE-2033-1003', 2033, timestamptz '2033-09-01')
on conflict (cve_id) do nothing;
insert into obs_core.exploitation_observations (
    source_id, source_entry_id, observation_type, vuln_id, vuln_id_type, cve_id,
    observed_at, observation_count, product_key, product, vendor, device_class,
    raw, content_hash, first_fetch_id, last_fetch_id)
select x.src, x.vid || '@' || d::date, 'attempt_observed', x.vid, 'cve', x.vid,
       d::date, x.n, 'P', 'P', 'Vend', 'router', '{}'::jsonb,
       md5(x.src || x.vid || d::date), f.fetch_id, f.fetch_id
  from (values ('shadowserver_api', 'CVE-2033-1001', 10, date '2033-01-01', date '{end}'),
               ('shadowserver_api', 'CVE-2033-1002',  8, date '2033-01-01', date '{end}'),
               ('crowdsec',         'CVE-2033-1003', 20, date '2033-10-20', date '{end}'))
       as x(src, vid, n, d0, d1)
 cross join lateral generate_series(x.d0, x.d1, interval '1 day') d
 cross join lateral (select fetch_id from obs_raw.source_fetches
                      where source_id = x.src order by fetch_id desc limit 1) f;
"""


@pytest.fixture()
def conn():
    cx = psycopg.connect(DSN)
    cx.execute("set timezone = 'UTC'")
    yield cx
    cx.rollback()
    cx.close()


def seed_and_rebuild(cx, end="2034-02-14"):
    cx.execute(SEED.replace("{end}", end))
    for fn in ("rebuild_scan_age_mix", "rebuild_scan_pressure",
               "rebuild_scan_pressure_combined", "rebuild_scan_age_mix_combined"):
        cx.execute(f"select derived.{fn}('v1', %s, null)", (CENSORED,))


def test_passes_on_a_healthy_rebuild(conn):
    seed_and_rebuild(conn)
    r = evals.check_scan_combined_charts(conn)
    assert r.passed, r.summary
    assert r.detail["age_drift"] == 0 and r.detail["weekly_offsets"] == 8


def test_fails_when_the_combined_charts_stop_moving(conn):
    """Shadowserver moves on a month; the combined tables were not rebuilt."""
    seed_and_rebuild(conn)
    conn.execute("""insert into obs_core.exploitation_observations (
        source_id, source_entry_id, observation_type, vuln_id, vuln_id_type, cve_id,
        observed_at, observation_count, product_key, product, vendor, device_class,
        raw, content_hash, first_fetch_id, last_fetch_id)
      select 'shadowserver_api', 'late@' || d::date, 'attempt_observed', 'CVE-2033-1001',
             'cve', 'CVE-2033-1001', d::date, 10, 'P', 'P', 'Vend', 'router', '{}'::jsonb,
             md5('late' || d::date), f.fetch_id, f.fetch_id
        from generate_series(date '2034-02-15', date '2034-03-15', interval '1 day') d
       cross join (select fetch_id from obs_raw.source_fetches
                    where source_id = 'shadowserver_api' limit 1) f""")
    r = evals.check_scan_combined_charts(conn)
    assert not r.passed
    assert "weekly" in r.summary and "age" in r.summary and "stopped moving" in r.summary


def test_fails_when_the_copied_rebuild_drifts_from_production(conn):
    seed_and_rebuild(conn)
    conn.execute("""update derived.scan_age_mix_combined set attempts = attempts + 1
                     where networks = array['shadowserver'] and age_band = 'over_5y'""")
    r = evals.check_scan_combined_charts(conn)
    assert not r.passed and "differ from production" in r.summary


def test_fails_when_a_bubble_carries_crowdsec_where_it_did_not_count(conn):
    seed_and_rebuild(conn)
    # Every week of the fixture counts CrowdSec; mark one as not counting it, leaving the
    # CrowdSec bubbles in place.
    conn.execute("""update derived.scan_pressure_combined set networks = array['shadowserver']
                     where offset_weeks = 7""")
    r = evals.check_scan_combined_charts(conn)
    assert not r.passed and "did not count for" in r.summary


def test_fails_when_a_rung_goes_missing(conn):
    seed_and_rebuild(conn)
    conn.execute("delete from derived.scan_pressure_combined where offset_weeks = 7")
    r = evals.check_scan_combined_charts(conn)
    assert not r.passed and "against 8" in r.summary


def test_fails_when_a_month_loses_a_band(conn):
    seed_and_rebuild(conn)
    conn.execute("""delete from derived.scan_age_mix_combined
                     where month = (select max(month) from derived.scan_age_mix_combined)
                       and age_band = 'y3_5'""")
    r = evals.check_scan_combined_charts(conn)
    assert not r.passed and "four bands" in r.summary


def test_a_stalled_crowdsec_feed_passes_once_the_chart_moves_on(conn):
    """CrowdSec stops a month early: the rebuild must move on with Shadowserver, and the
    eval must accept that rather than demand CrowdSec."""
    seed_and_rebuild(conn)
    conn.execute("""delete from obs_core.exploitation_observations
                     where source_id = 'crowdsec' and observed_at > '2034-01-10'""")
    for fn in ("rebuild_scan_pressure_combined", "rebuild_scan_age_mix_combined"):
        conn.execute(f"select derived.{fn}('v1', %s, null)", (CENSORED,))
    r = evals.check_scan_combined_charts(conn)
    assert r.passed, r.summary
    assert r.detail["weekly_lag_days"] == 0


# ---- the Explorer's scanning series and EPSS-high record (0090) ------------------------

def rebuild_series(cx):
    cx.execute("select derived.rebuild_cve_scanning_daily('v1', %s, null)", (CENSORED,))


def test_scanning_series_passes_when_current(conn):
    seed_and_rebuild(conn)
    rebuild_series(conn)
    r = evals.check_scanning_series_fresh(conn)
    assert r.passed, r.summary
    assert r.detail["lag_days"] == 0   # the series ends on the latest counting day


def test_scanning_series_fails_when_the_sensor_moves_on_without_it(conn):
    seed_and_rebuild(conn)
    rebuild_series(conn)
    conn.execute("""insert into obs_core.exploitation_observations (
        source_id, source_entry_id, observation_type, vuln_id, vuln_id_type, cve_id,
        observed_at, observation_count, product_key, product, vendor, device_class,
        raw, content_hash, first_fetch_id, last_fetch_id)
      select 'shadowserver_api', 'late@' || d::date, 'attempt_observed', 'CVE-2033-1001',
             'cve', 'CVE-2033-1001', d::date, 10, 'P', 'P', 'Vend', 'router', '{}'::jsonb,
             md5('late' || d::date), f.fetch_id, f.fetch_id
        from generate_series(date '2034-02-15', date '2034-03-15', interval '1 day') d
       cross join (select fetch_id from obs_raw.source_fetches
                    where source_id = 'shadowserver_api' limit 1) f""")
    r = evals.check_scanning_series_fresh(conn)
    assert not r.passed and "stopped moving" in r.summary


def test_scanning_series_cannot_store_a_zero_or_an_out_of_window_day(conn):
    """Both are refused by the table itself, which is why the eval only watches the clock."""
    seed_and_rebuild(conn)
    rebuild_series(conn)
    for bad in ("select cve_id, observed_on - 400, 1, window_start, window_end, method_version, "
                "censored_at, computed_at, computed_by_run, provisional from derived.cve_scanning_daily limit 1",
                "select 'CVE-2033-9999', observed_on, 0, window_start, window_end, method_version, "
                "censored_at, computed_at, computed_by_run, provisional from derived.cve_scanning_daily limit 1"):
        conn.execute("savepoint s")
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(f"insert into derived.cve_scanning_daily {bad}")
        conn.execute("rollback to savepoint s")


EPSS = """insert into core.cves (cve_id, cve_year, date_published) values ('CVE-2033-1001', 2033, now())
          on conflict do nothing;
          insert into core.cve_epss (cve_id, epss_score, epss_percentile, model_version, score_date)
          values ('CVE-2033-1001', 0.4, 0.9, 'v2026.06.15', '2034-02-14')
          on conflict (cve_id) do update set epss_score = 0.4, score_date = '2034-02-14'"""


def test_epss_lifecycle_passes_once_recorded(conn):
    conn.execute(EPSS)
    conn.execute("select derived.record_epss_history(%s)", (CENSORED,))
    r = evals.check_epss_lifecycle_recorded(conn)
    assert r.passed, r.summary


def test_epss_lifecycle_fails_when_recording_stopped(conn):
    conn.execute(EPSS)
    conn.execute("select derived.record_epss_history(%s)", (CENSORED,))
    conn.execute("update core.cve_epss set score_date = '2034-02-15' where cve_id = 'CVE-2033-1001'")
    r = evals.check_epss_lifecycle_recorded(conn)
    assert not r.passed and r.detail["behind"] == 1


def test_epss_lifecycle_fails_on_a_state_contradicting_its_last_move(conn):
    conn.execute(EPSS)
    conn.execute("select derived.record_epss_history(%s)", (CENSORED,))
    conn.execute("update core.epss_summary set confirmed_high = false where cve_id = 'CVE-2033-1001'")
    r = evals.check_epss_lifecycle_recorded(conn)
    assert not r.passed and r.detail["contradicted"] == 1


def test_epss_lifecycle_fails_on_a_move_after_its_proof(conn):
    conn.execute(EPSS)
    conn.execute("select derived.record_epss_history(%s)", (CENSORED,))
    conn.execute("""insert into core.epss_transitions (cve_id, changed_on, direction, score, cause, basis)
                    values ('CVE-2033-1001', '2034-03-01', 'down', 0.01, 'organic', 'daily')""")
    r = evals.check_epss_lifecycle_recorded(conn)
    assert not r.passed and r.detail["ahead"] == 1


def test_epss_lifecycle_fails_when_nothing_is_tracked(conn):
    """An empty record must not vacuously pass."""
    conn.execute("delete from core.epss_transitions")
    conn.execute("delete from core.epss_summary")
    r = evals.check_epss_lifecycle_recorded(conn)
    assert not r.passed
