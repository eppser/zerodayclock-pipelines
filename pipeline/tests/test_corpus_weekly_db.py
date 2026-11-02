"""The weekly corpus chart (migration 0198) through the PIPELINE's own code, against a migrated database.

What has to keep working for years without anyone touching it: the enrich run calls the rebuild (with the guard),
the rebuild follows the censoring date into the next year, and the freshness eval goes RED when the table is stale
or has drifted from the monthly chart, and green when it is current. Both directions are tested.

Runs only when WEEKLY_TEST_DATABASE_URL points at a THROWAWAY database with every migration applied (CI's service
container). db.run_rebuilds COMMITS each rebuild by design (that isolation is what it exists for), so these tests
are not rolled back: every test empties the five tables and reseeds them. Never point this at a real database.
"""

from __future__ import annotations

import logging
import os
from datetime import date

import psycopg
import pytest

from zdc_enrich import db, evals, run

DSN = os.environ.get("WEEKLY_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DSN, reason="needs WEEKLY_TEST_DATABASE_URL")

LOG = logging.getLogger("test")


@pytest.fixture()
def conn():
    with psycopg.connect(DSN) as c:
        c.autocommit = False
        with c.cursor() as cur:
            cur.execute("set local timezone = 'America/Los_Angeles'")   # a non-UTC session must not move a week
            for t in ("derived.corpus_weekly", "derived.corpus_cohorts", "derived.kev_bulk_loads",
                      "derived.kev_consolidated", "derived.cve_detail"):
                cur.execute(f"delete from {t}")
            cur.execute("""
                insert into derived.cve_detail (cve_id, date_published, state, kev_catalogues, kev_feeds, method_version, censored_at)
                select format('CVE-%s-%s', extract(year from d)::int, 9500000 + row_number() over ()), d::date, 'PUBLISHED',
                       '{}', '{}', 't', date '2031-12-31'
                  from generate_series(date '2022-06-01', date '2028-06-01', interval '3 days') d""")
            cur.execute("""
                insert into derived.kev_consolidated (vuln_id, vuln_id_type, cve_id, first_kev_date, first_kev_source,
                       entry_count, source_count, independent_source_count, all_withdrawn, method_version, censored_at)
                select v, 'cve', v, d::date, 'cisa', 1, 1, 1, false, 't', date '2031-12-31'
                  from (select format('CVE-%s-%s', extract(year from d)::int, 9600000 + row_number() over ()) v, d
                          from generate_series(date '2022-06-01', date '2028-06-01', interval '10 days') d) x""")
        yield c
        c.rollback()


def _pipeline_rebuild(conn, censored: date) -> dict:
    """Exactly what run.py does for these two tables: the REBUILDS entries, through db.run_rebuilds."""
    wanted = {"derived.corpus_cohorts", "derived.corpus_weekly"}
    picked = [r for r in run.REBUILDS if r[1] in wanted] if hasattr(run, "REBUILDS") else [
        ("corpus_rows", "derived.corpus_cohorts", db.rebuild_corpus_cohorts),
        ("corpus_weekly_rows", "derived.corpus_weekly", db.rebuild_corpus_weekly)]
    rows, errors, _ = db.run_rebuilds(conn, picked, method_version="test", censored_at=censored, run_id=None, log=LOG)
    assert not errors, errors
    return rows


def test_run_py_rebuilds_the_weekly_table_after_the_monthly_one():
    src = open(run.__file__).read()
    i, j = src.index('"derived.corpus_cohorts"'), src.index('"derived.corpus_weekly"')
    assert i < j, "the weekly rebuild must run after (and with the censoring date of) the corpus cohorts"
    assert "db.rebuild_corpus_weekly" in src


def test_rebuild_and_eval_green_now_and_next_years(conn):
    for censored in (date(2026, 11, 2), date(2027, 1, 4), date(2028, 3, 1)):
        rows = _pipeline_rebuild(conn, censored)
        assert rows["corpus_weekly_rows"] > 0
        r = evals.check_corpus_weekly_fresh(conn)
        assert r.passed, (censored, r.summary)
        with conn.cursor() as cur:
            cur.execute("select min(week_start), max(week_start) from derived.corpus_weekly")
            lo, hi = cur.fetchone()
        assert lo.isoweekday() == 1 and hi.isoweekday() == 1
        assert (censored - hi).days in range(7, 14), "ends on the last complete week before the censor date"
        assert lo == max(date(2023, 1, 2), date.fromisocalendar(censored.year - 4, 1, 1))


def test_eval_goes_red_when_the_weekly_table_is_stale(conn):
    _pipeline_rebuild(conn, date(2026, 11, 2))
    # the monthly chart moves on a week, the weekly rebuild does not run
    db.rebuild_corpus_cohorts(conn, method_version="test", censored_at=date(2026, 11, 9))
    r = evals.check_corpus_weekly_fresh(conn)
    assert not r.passed and "stale" in r.summary


def test_eval_goes_red_when_a_week_is_missing(conn):
    _pipeline_rebuild(conn, date(2026, 11, 2))
    with conn.cursor() as cur:
        cur.execute("delete from derived.corpus_weekly where metric = 'kev_entered' and week_start = date '2024-06-03'")
    assert not evals.check_corpus_weekly_fresh(conn).passed


def test_weekly_sums_match_the_monthly_definitions(conn):
    """Same definitions as the chart above: over whole weeks inside one month, the totals agree with a direct count."""
    _pipeline_rebuild(conn, date(2026, 11, 2))
    with conn.cursor() as cur:
        cur.execute("""select (select sum(weekly_count) from derived.corpus_weekly where metric = 'cves_published'),
                              (select count(*) from derived.cve_detail where date_published between date '2023-01-02' and date '2026-11-01'),
                              (select sum(weekly_count) from derived.corpus_weekly where metric = 'kev_entered'),
                              (select count(*) from derived.kev_consolidated where first_kev_date between date '2023-01-02' and date '2026-11-01')""")
        cw, cd, kw, kd = cur.fetchone()
    assert (cw, kw) == (cd, kd)


def test_guard_returns_zero_when_the_migration_is_absent(conn):
    with conn.cursor() as cur:
        cur.execute("drop function derived.rebuild_corpus_weekly(text, date)")
    assert db.rebuild_corpus_weekly(conn, method_version="test", censored_at=date(2026, 11, 2)) == 0
