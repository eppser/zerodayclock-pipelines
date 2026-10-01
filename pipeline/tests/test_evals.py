"""Eval-suite tests.

Every check here is tested in both directions. A check that has only ever been seen to
pass is not evidence of anything — v1's lesson was that a green signal which cannot go
red is worse than no signal, because it trains the reader to stop looking.
"""

from __future__ import annotations

from datetime import date

from zdc_enrich import evals as enrich_evals
from zdc_kev import evals
from zdc_kev.models import CollectResult, KevObservation

from conftest import requires_repo_files


def obs(**overrides) -> KevObservation:
    kwargs = dict(
        source_id="cisa", upstream_source="cisa", source_entry_id="CVE-2024-0001",
        vuln_id="CVE-2024-0001", vuln_id_type="cve", cve_id="CVE-2024-0001", raw={},
    )
    kwargs.update(overrides)
    return KevObservation(**kwargs)


class TestNoSilentEmpty:
    """The v1 bug: a WAF block recorded as a successful run with no data."""

    def test_passes_when_sources_return_data(self):
        results = [CollectResult(source_id="cisa", observations=[obs()])]
        assert evals.check_no_silent_empty(results).passed

    def test_passes_when_source_is_legitimately_unchanged(self):
        results = [CollectResult(source_id="cisa", unchanged=True)]
        assert evals.check_no_silent_empty(results).passed

    def test_passes_when_emptiness_has_a_stated_reason(self):
        results = [CollectResult(source_id="cisa", error="HTTP 403: blocked")]
        assert evals.check_no_silent_empty(results).passed

    def test_FAILS_on_empty_with_no_reason(self):
        results = [CollectResult(source_id="cisa")]
        result = evals.check_no_silent_empty(results)
        assert not result.passed and result.blocking
        assert "cisa" in result.detail["offenders"]


class TestSourceYield:
    def test_passes_at_the_floor(self):
        results = [CollectResult(source_id="cisa", observations=[obs()] * 10)]
        assert evals.check_source_yield(results, {"cisa": 10}).passed

    def test_FAILS_below_the_floor(self):
        results = [CollectResult(source_id="cisa", observations=[obs()] * 9)]
        result = evals.check_source_yield(results, {"cisa": 10})
        assert not result.passed and result.blocking
        assert result.detail["cisa"] == {"got": 9, "expected_min": 10}

    def test_unchanged_source_is_exempt(self):
        results = [CollectResult(source_id="cisa", unchanged=True)]
        assert evals.check_source_yield(results, {"cisa": 1000}).passed


class TestCveShape:
    def test_passes_on_well_formed_ids(self):
        assert evals.check_cve_shape([obs(), obs(cve_id="CVE-2019-12345")]).passed

    def test_FAILS_on_malformed_id(self):
        # Constructed by bypassing validation, as a corrupt DB row would appear.
        bad = object.__new__(KevObservation)
        object.__setattr__(bad, "cve_id", "CVE-20-1")
        result = evals.check_cve_shape([bad])
        assert not result.passed and result.blocking

    def test_entries_without_a_cve_are_not_failures(self):
        assert evals.check_cve_shape([obs(cve_id=None, vuln_id="EUVD-1", vuln_id_type="euvd")]).passed


class TestNoFutureDates:
    def test_passes_on_dates_within_the_window(self):
        assert evals.check_no_future_dates([obs(date_added=date(2026, 1, 1))], date(2026, 8, 27)).passed

    def test_FAILS_on_a_date_after_the_censoring_date(self):
        result = evals.check_no_future_dates([obs(date_added=date(2027, 1, 1))], date(2026, 8, 27))
        assert not result.passed
        assert result.severity == evals.WARN     # visible, but not a promotion blocker


class TestSignalNotInflated:
    def test_passes_on_genuine_exploitation_language(self):
        entries = [obs(signal="successful_exploitation", short_description="Actively exploited in the wild.")]
        assert evals.check_signal_not_inflated(entries).passed

    def test_FAILS_when_an_exploitation_claim_reads_like_poc_only(self):
        entries = [
            obs(
                signal="successful_exploitation",
                short_description="A proof of concept exists; no evidence of exploitation was found.",
            )
        ]
        assert not evals.check_signal_not_inflated(entries).passed


class TestReport:
    def test_blocking_error_makes_the_report_not_ok(self):
        report = evals.EvalReport()
        report.add(evals.check_no_silent_empty([CollectResult(source_id="x")]))
        assert not report.ok
        assert "BLOCKED" in report.render()

    def test_warnings_alone_do_not_block_promotion(self):
        report = evals.EvalReport()
        report.add(evals.check_no_future_dates([obs(date_added=date(2027, 1, 1))], date(2026, 1, 1)))
        assert report.ok
        assert "OK" in report.render()

    def test_info_results_never_block(self):
        report = evals.EvalReport()
        report.add(evals.EvalResult("m", evals.INFO, True, "diagnostic"))
        assert report.ok


class TestSuspectedNonIndependence:
    """Two observers whose catalogues are near-identical are not two observers.

    Tested with a fake cursor so the logic is verified without a database; the live
    behaviour is exercised by the integration run.
    """

    class _Cur:
        def __init__(self, rows):
            self.rows = rows

        def execute(self, *a, **k):
            pass

        def fetchall(self):
            return self.rows

        def __enter__(self):
            return self

        def __exit__(self, *e):
            return False

    class _Conn:
        def __init__(self, rows):
            self.rows = rows

        def cursor(self):
            return TestSuspectedNonIndependence._Cur(self.rows)

    def test_passes_when_no_pair_is_near_identical(self):
        assert evals.check_suspected_non_independence(self._Conn([])).passed

    def test_FAILS_on_a_near_identical_pair(self):
        # The real measurement: cisa x enisa scored 0.996.
        rows = [("cisa", "enisa", 0.99645, 1683, 0, 6)]
        result = evals.check_suspected_non_independence(self._Conn(rows))
        assert not result.passed
        assert result.severity == evals.WARN
        assert result.detail["cisa x enisa"]["jaccard"] == 0.99645


class TestPublicViewsReadonly:
    """anon must never hold more than SELECT on a published view.

    Supabase grants ALL on new public objects by default; the views are auto-updatable
    and definer-owned, so a write through one bypasses RLS on the tables beneath.
    """

    def conn(self, rows):
        return TestSuspectedNonIndependence._Conn(rows)

    def test_passes_when_only_select_is_granted(self):
        assert evals.check_public_views_readonly(self.conn([])).passed

    def test_FAILS_when_anon_can_write(self):
        rows = [("kev_consolidated", "anon", "DELETE,INSERT,TRUNCATE,UPDATE")]
        result = evals.check_public_views_readonly(self.conn(rows))
        assert not result.passed and result.blocking      # must block promotion
        assert "kev_consolidated/anon" in result.detail


class _FakeCursor:
    """Returns one canned row; enough for the single-query freshness check."""

    def __init__(self, row):
        self._row = row

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, *a, **kw):
        return None

    def fetchone(self):
        return self._row


class _FakeConn:
    def __init__(self, row):
        self._row = row

    def cursor(self):
        return _FakeCursor(self._row)


class TestObservationWindowFresh:
    """The check that is supposed to make v1's six-month silent death impossible.

    It returned WARN on BOTH branches, so it could never block a promotion — the
    failure it documents would have been reported and shipped anyway. Driven here
    across every tier, because a threshold that is never crossed in a test is a
    threshold nobody has checked.
    """

    @staticmethod
    def _run(lag_days):
        from datetime import date as _d
        return enrich_evals.check_observation_window_fresh(
            _FakeConn((_d(2026, 9, 1), lag_days, _d(2026, 9, 1))))

    def test_fresh_window_is_INFO_and_passes(self):
        r = self._run(0)
        assert r.passed and not r.blocking and r.severity == evals.INFO

    def test_at_the_warn_threshold_still_passes(self):
        # Boundary: 7 is "within a week", 8 is not.
        assert self._run(enrich_evals.OBS_LAG_WARN_DAYS).passed

    def test_past_a_week_WARNS_but_does_not_block(self):
        r = self._run(enrich_evals.OBS_LAG_WARN_DAYS + 1)
        assert not r.passed
        assert r.severity == evals.WARN
        assert not r.blocking, "a week of lag should be visible, not fatal"

    def test_at_the_error_threshold_does_not_block_yet(self):
        r = self._run(enrich_evals.OBS_LAG_ERROR_DAYS)
        assert not r.blocking

    def test_BLOCKS_past_three_weeks(self):
        # This is the assertion the original could not make.
        r = self._run(enrich_evals.OBS_LAG_ERROR_DAYS + 1)
        assert not r.passed
        assert r.severity == evals.ERROR
        assert r.blocking, "a dead collector must stop the promotion"

    def test_BLOCKS_when_there_are_no_observations_at_all(self):
        r = enrich_evals.check_observation_window_fresh(_FakeConn((None, None, None)))
        assert r.blocking

    def test_v1_scenario_six_months_of_silence_blocks(self):
        # The concrete failure: v1 published "current" numbers for ~180 days.
        r = self._run(180)
        assert r.blocking
        assert "do not promote" in r.summary


class TestCollectorsHaveAdapters:
    """The obs pipeline exited 1 on every run for four days (migration 0062).

    obs_core.observation_sources is shared with zdc_honeypot, and zdc_obs tried to
    collect every enabled row. The filter that fixes it could itself hide a source
    silently dropping out, so the eval asserts both directions and both are tested.
    """

    class FakeConn:
        """Stands in for a psycopg connection returning one (source_id, collector) set."""

        def __init__(self, rows):
            self._rows = rows

        def cursor(self):
            rows = self._rows
            class Cur:
                def __enter__(self): return self
                def __exit__(self, *a): return False
                def execute(self, *a, **k): pass
                def fetchall(self): return rows
            return Cur()

    def _check(self, rows, adapters, monkeypatch):
        from zdc_obs import evals as obs_evals
        from zdc_obs import sources as obs_sources
        monkeypatch.setattr(obs_sources, "registered_ids", lambda: sorted(adapters))
        return obs_evals.check_collectors_have_adapters(self.FakeConn(rows))

    def test_passes_when_every_owned_source_has_an_adapter(self, monkeypatch):
        rows = [("msrc", "zdc_obs"), ("shadowserver", "zdc_obs"),
                ("vulncheck_canary", "zdc_obs"), ("shadowserver_api", "zdc_honeypot")]
        r = self._check(rows, {"msrc", "shadowserver", "vulncheck_canary"}, monkeypatch)
        assert r.passed, r.summary

    def test_fails_on_the_real_2026_09_regression(self, monkeypatch):
        """shadowserver_api assigned to us, but only zdc_honeypot implements it."""
        rows = [("msrc", "zdc_obs"), ("shadowserver", "zdc_obs"),
                ("vulncheck_canary", "zdc_obs"), ("shadowserver_api", "zdc_obs")]
        r = self._check(rows, {"msrc", "shadowserver", "vulncheck_canary"}, monkeypatch)
        assert not r.passed
        assert "shadowserver_api" in r.summary

    def test_fails_when_an_adapter_exists_but_no_source_asks_for_it(self, monkeypatch):
        """The silent-death direction: a source quietly reassigned away from us."""
        rows = [("msrc", "zdc_obs"), ("shadowserver", "zdc_honeypot"),
                ("vulncheck_canary", "zdc_obs")]
        r = self._check(rows, {"msrc", "shadowserver", "vulncheck_canary"}, monkeypatch)
        assert not r.passed
        assert "shadowserver" in r.summary

    def test_fails_when_an_adapter_is_deleted(self, monkeypatch):
        """A source we are told to collect whose adapter has been removed."""
        rows = [("msrc", "zdc_obs"), ("shadowserver", "zdc_obs")]
        r = self._check(rows, {"msrc"}, monkeypatch)
        assert not r.passed
        assert "shadowserver" in r.summary


class TestSourceFreshness:
    """The v1 failure: exploitation data ended 2026-02-28, the site said 'current'.

    Thresholds come from the registry per source, so the tests fix them explicitly
    rather than depending on what the live database happens to hold.
    """

    CENSORED = date(2026, 9, 7)

    class FakeConn:
        def __init__(self, rows): self._rows = rows
        def cursor(self):
            rows = self._rows
            class Cur:
                def __enter__(self): return self
                def __exit__(self, *a): return False
                def execute(self, *a, **k): pass
                def fetchall(self): return rows
            return Cur()

    def _check(self, rows):
        from zdc_obs import evals as obs_evals
        return obs_evals.check_source_freshness(self.FakeConn(rows), self.CENSORED)

    # (source_id, max_silence_days, max_reread_days, last_observed, last_seen)
    def test_passes_on_the_real_current_state(self):
        r = self._check([
            ("msrc", None, 3, None, date(2026, 9, 7)),
            ("shadowserver", 3, 3, date(2026, 9, 6), date(2026, 9, 7)),
            ("vulncheck_canary", 30, 3, date(2026, 8, 29), date(2026, 9, 7)),
        ])
        assert r.passed, r.summary

    def test_fails_when_a_daily_source_goes_quiet(self):
        """Shadowserver 9 days stale against a 3-day threshold — the v1 shape."""
        r = self._check([("shadowserver", 3, 3, date(2026, 8, 29), date(2026, 9, 7))])
        assert not r.passed
        assert "newest observation 9d old" in r.summary

    def test_sparse_canary_does_not_page_at_nine_days(self):
        """Its measured max gap is 13d; a shared 3-day threshold would page weekly."""
        r = self._check([("vulncheck_canary", 30, 3, date(2026, 8, 29), date(2026, 9, 7))])
        assert r.passed, r.summary

    def test_fails_when_the_source_stops_being_reachable(self):
        """Undated source, so only the re-read clock can catch it — msrc's only guard."""
        r = self._check([("msrc", None, 3, None, date(2026, 8, 30))])
        assert not r.passed
        assert "not re-read for 8d" in r.summary

    def test_undated_source_is_not_silently_exempt(self):
        """A silence threshold set on a source with no dates must fail, not pass."""
        r = self._check([("msrc", 3, 3, None, date(2026, 9, 7))])
        assert not r.passed
        assert "no dated observations" in r.summary

    def test_a_source_with_no_declared_expectation_fails(self):
        """Self-defending: registering a source must not leave it unmonitored."""
        r = self._check([("newsource", None, None, date(2026, 9, 7), date(2026, 9, 7))])
        assert not r.passed
        assert "no freshness expectation declared" in r.summary

    def test_no_sources_at_all_is_a_failure_not_a_pass(self):
        """An empty result set must not vacuously satisfy the gate."""
        r = self._check([])
        assert not r.passed


class TestScanPressureWindowRolls:
    """scan_pressure is the only sensor-anchored window and had no gate.

    Every parameter comes from core.method_registry, so the fake conn returns the
    registry row first and the table shape second, in call order.
    """

    class FakeConn:
        def __init__(self, registry, shape, sensor_max):
            self._q = [registry, shape, (sensor_max,)]
        def cursor(self):
            q = self._q
            class Cur:
                def __enter__(self): return self
                def __exit__(self, *a): return False
                def execute(self, *a, **k): pass
                def fetchone(self): return q.pop(0)
            return Cur()

    REG = (8, 7, 63, "shadowserver_api", "attempt_observed")

    def _check(self, shape, sensor_max, registry=None):
        from zdc_enrich import evals
        return evals.check_scan_pressure_window_rolls(
            self.FakeConn(registry or self.REG, shape, sensor_max))

    # shape = (n_offsets, k_lo, k_hi, oldest_window_start, newest_obs_window_end)
    def test_passes_on_the_real_current_state(self):
        r = self._check((8, 0, 7, date(2026, 7, 12), date(2026, 9, 5)), date(2026, 9, 5))
        assert r.passed, r.summary

    def test_fails_when_the_rebuild_accumulates(self):
        """The defect the gate exists for: a year of appending instead of replacing."""
        r = self._check((60, 0, 59, date(2025, 9, 5), date(2026, 9, 5)), date(2026, 9, 5))
        assert not r.passed
        assert "accumulating instead of replacing" in r.summary

    def test_fails_when_the_window_runs_ahead_of_the_sensor(self):
        """Anchored to the censoring date while the sensor stalled 10 days ago. This is
        what draws a collection failure as a collapse in attempts."""
        r = self._check((8, 0, 7, date(2026, 7, 12), date(2026, 9, 5)), date(2026, 8, 26))
        assert not r.passed
        assert "AHEAD of the sensor" in r.summary

    def test_tolerates_the_normal_lag_between_rebuilds(self):
        """The honeypot feed lands between enrich runs, so trailing by a day is
        correct, not a defect. Measured live on 2026-09-07."""
        r = self._check((8, 0, 7, date(2026, 7, 12), date(2026, 9, 5)), date(2026, 9, 6))
        assert r.passed, r.summary

    def test_fails_when_the_rebuild_has_stopped_moving(self):
        r = self._check((8, 0, 7, date(2026, 7, 12), date(2026, 9, 5)), date(2026, 9, 20))
        assert not r.passed
        assert "stopped moving" in r.summary

    def test_fails_when_a_rung_goes_missing(self):
        r = self._check((7, 0, 6, date(2026, 7, 19), date(2026, 9, 5)), date(2026, 9, 5))
        assert not r.passed
        assert "against 8 declared" in r.summary

    def test_fails_when_the_registry_declares_nothing(self):
        """0052's defect: a registry row that does not describe this metric."""
        r = self._check((8, 0, 7, date(2026, 7, 12), date(2026, 9, 5)), date(2026, 9, 5),
                        registry=(None, None, None, "shadowserver_api", "attempt_observed"))
        assert not r.passed
        assert "method_registry" in r.summary

    def test_registry_change_without_a_function_change_fails(self):
        """The cross-check: declaring 12 offsets while the function emits 8."""
        r = self._check((8, 0, 7, date(2026, 7, 12), date(2026, 9, 5)), date(2026, 9, 5),
                        registry=(12, 7, 91, "shadowserver_api", "attempt_observed"))
        assert not r.passed
        assert "against 12 declared" in r.summary


@requires_repo_files("supabase/migrations")
class TestSchemaMatchesMigrations:
    """Objects must be declared in supabase/migrations — the only committed set.

    game/ has never been committed, so widening the corpus to read
    game/server/migrations passed locally and failed in CI. The scoreboard is adopted
    into supabase/migrations by 0067 instead.
    """

    class FakeConn:
        def __init__(self, live): self._live = live
        def cursor(self):
            live = self._live
            class Cur:
                def __enter__(self): return self
                def __exit__(self, *a): return False
                def execute(self, *a, **k): pass
                def fetchall(self): return live
            return Cur()

    def test_adopted_game_scoreboard_is_not_an_orphan(self):
        from zdc_enrich import evals
        r = evals.check_schema_matches_migrations(
            self.FakeConn([("public", "ciso_game_scores")]))
        assert r.passed, r.summary

    def test_site_object_is_not_an_orphan(self):
        from zdc_enrich import evals
        r = evals.check_schema_matches_migrations(
            self.FakeConn([("obs_core", "observation_sources")]))
        assert r.passed, r.summary

    def test_a_genuinely_hand_created_object_still_fails(self):
        """The check must not have been widened into uselessness."""
        from zdc_enrich import evals
        r = evals.check_schema_matches_migrations(
            self.FakeConn([("derived", "dashboard_halfyear_scratch_xyz")]))
        assert not r.passed
        assert "dashboard_halfyear_scratch_xyz" in r.summary


class TestFreshnessThresholdCalibration:
    """0063 calibrated max_silence_days from the wrong quantity; 0068 corrects it.

    The eval measures the LEADING EDGE lag (censored_at - max(observed_at)), not gaps
    between consecutive observation days. shadowserver has no gaps at all and still ran
    a leading-edge lag of 2-3, so a threshold of 3 false-alarmed after one missed run.
    """

    CENSORED = date(2026, 9, 8)

    class FakeConn:
        def __init__(self, rows): self._rows = rows
        def cursor(self):
            rows = self._rows
            class Cur:
                def __enter__(self): return self
                def __exit__(self, *a): return False
                def execute(self, *a, **k): pass
                def fetchall(self): return rows
            return Cur()

    def _check(self, rows):
        from zdc_obs import evals as obs_evals
        return obs_evals.check_source_freshness(self.FakeConn(rows), self.CENSORED)

    def test_the_real_2026_09_08_state_passes(self):
        """Measured live: no gaps in the series, leading edge 2 days back."""
        r = self._check([
            ("msrc", None, 3, None, date(2026, 9, 8)),
            ("shadowserver", 5, 3, date(2026, 9, 6), date(2026, 9, 8)),
            ("vulncheck_canary", 30, 3, date(2026, 9, 7), date(2026, 9, 8)),
        ])
        assert r.passed, r.summary

    def test_old_threshold_would_have_false_alarmed_on_one_missed_run(self):
        """A lag-3 day plus one missed daily run is lag 4 — healthy, but 3 fails it."""
        old = self._check([("shadowserver", 3, 3, date(2026, 9, 4), date(2026, 9, 8))])
        assert not old.passed, "the defect this migration fixes did not reproduce"
        new = self._check([("shadowserver", 5, 3, date(2026, 9, 4), date(2026, 9, 8))])
        assert new.passed, new.summary

    def test_widening_did_not_blind_it_to_a_real_stall(self):
        """Six days behind is a stopped collector, and 5 must still catch it."""
        r = self._check([("shadowserver", 5, 3, date(2026, 9, 2), date(2026, 9, 8))])
        assert not r.passed
        assert "newest observation 6d old" in r.summary

    def test_reread_clock_still_fires_while_silence_passes(self):
        """The two thresholds are independent: reachable-but-stale vs unreachable."""
        r = self._check([("shadowserver", 5, 3, date(2026, 9, 6), date(2026, 9, 3))])
        assert not r.passed
        assert "not re-read for 5d" in r.summary


class TestIndependenceCountsAgree:
    """The two tables that count independent observers must agree — and when they do
    not, the message must say WHICH CVEs.

    This fired on both scheduled enrichment runs of 2026-09-17 reading "1 of 5,316
    CVEs" and naming nothing, and the next rebuild cleared it before anyone could look.
    A bare count cannot separate the systemic defect 0045 exists to catch — the
    discount reaching neither table, which is every CVE carrying a dependent observer —
    from one row that is briefly stale. The third test is the one that would have
    failed before this change.
    """

    class FakeConn:
        """Serves the eval's three queries in call order: sample, differ, total."""

        def __init__(self, sample, differ, total):
            self._all = [sample]
            self._one = [(differ,), (total,)]

        def cursor(self):
            allq, oneq = self._all, self._one

            class Cur:
                def __enter__(self): return self
                def __exit__(self, *a): return False
                def execute(self, *a, **k): pass
                def fetchall(self): return allq.pop(0)
                def fetchone(self): return oneq.pop(0)
            return Cur()

    def _check(self, sample, differ, total):
        return enrich_evals.check_independence_counts_agree(
            self.FakeConn(sample, differ, total))

    def test_passes_when_the_two_tables_agree(self):
        r = self._check([], 0, 5316)
        assert r.passed
        assert "5,316" in r.summary

    def test_fails_when_one_row_disagrees(self):
        r = self._check([("CVE-2026-1234", 4, 3)], 1, 5316)
        assert not r.passed

    def test_names_the_disagreeing_cves(self):
        r = self._check([("CVE-2026-1234", 4, 3)], 1, 5316)
        assert "CVE-2026-1234" in r.summary
        assert "detail 4" in r.summary and "consolidation 3" in r.summary
        assert r.detail["sample"][0]["cve_id"] == "CVE-2026-1234"

    def test_caps_the_sample_and_marks_that_it_is_truncated(self):
        rows = [(f"CVE-2026-100{i}", 4, 3) for i in range(6)]
        r = self._check(rows, 42, 5316)
        assert r.summary.endswith("...")
        assert len(r.detail["sample"]) == 5
        assert "42 of 5,316" in r.summary
