"""Tests for the cross-pipeline watchdog.

The interesting cases are the distinctions: a pipeline failing on schedule is NOT
running, a pipeline registered minutes ago is not yet overdue, and a pipeline nobody
registered must not be silently skipped.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from tools import watchdog

NOW = datetime(2026, 9, 8, 18, 0, tzinfo=timezone.utc)


def ago(hours: float) -> datetime:
    return NOW - timedelta(hours=hours)


class FakeConn:
    """Answers by which query was asked, never by call order."""

    def __init__(self, expectations, runs):
        self.expectations, self.runs = expectations, runs

    def cursor(self):
        outer = self
        class Cur:
            _last = ""
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def execute(self, sql, params=None): self._last = sql
            def fetchone(self): return (NOW,)
            def fetchall(self):
                if "pipeline_expectations" in self._last:
                    return outer.expectations
                for table, rows in outer.runs.items():
                    if table in self._last:
                        return rows
                return []
        return Cur()


def exp(pipeline, max_hours=30, table="raw.pipeline_runs", monitor_from=None, enabled=True):
    return (pipeline, pipeline.title(), table, f"{pipeline}.yml", "0 * * * *",
            max_hours, monitor_from or ago(500), enabled)


def state_of(rows, pipeline):
    return next(r["state"] for r in rows if r["pipeline"] == pipeline)


class TestStates:
    def test_recent_success_is_ok(self):
        rows = watchdog.collect(FakeConn(
            [exp("kev", 30)], {"raw.pipeline_runs": [("kev", ago(4), ago(4))]}))
        assert state_of(rows, "kev") == "OK"

    def test_silent_past_its_limit_is_overdue(self):
        rows = watchdog.collect(FakeConn(
            [exp("kev", 30)], {"raw.pipeline_runs": [("kev", ago(31), ago(31))]}))
        assert state_of(rows, "kev") == "OVERDUE"

    def test_failing_on_schedule_still_counts_as_silent(self):
        """The obs/enrich case: attempts every 12h, no success for two days.

        A watchdog satisfied by an ATTEMPT would have reported these healthy through
        the entire outage.
        """
        rows = watchdog.collect(FakeConn(
            [exp("observations", 30, table="obs_raw.pipeline_runs")],
            {"obs_raw.pipeline_runs": [("observations", ago(50), ago(2))]}))
        assert state_of(rows, "observations") == "OVERDUE"
        assert next(r for r in rows if r["pipeline"] == "observations")["failing_since_last_ok"]

    def test_just_registered_is_pending_not_overdue(self):
        """patch and export begin recording at 0069 and have no history.

        An alarm that is wrong the first time it speaks is not believed the second time.
        """
        rows = watchdog.collect(FakeConn(
            [exp("patch", 48, monitor_from=ago(1))], {"raw.pipeline_runs": []}))
        assert state_of(rows, "patch") == "PENDING"

    def test_registered_long_ago_and_never_ran_is_a_failure(self):
        """Grace expires. A pipeline that has never once succeeded is not healthy."""
        rows = watchdog.collect(FakeConn(
            [exp("patch", 48, monitor_from=ago(500))], {"raw.pipeline_runs": []}))
        assert state_of(rows, "patch") == "NEVER RAN"

    def test_a_pipeline_nobody_registered_is_reported(self):
        """An unwatched pipeline is the failure this exists to prevent."""
        rows = watchdog.collect(FakeConn(
            [exp("kev", 30)],
            {"raw.pipeline_runs": [("kev", ago(1), ago(1)), ("mystery", ago(1), ago(1))]}))
        assert state_of(rows, "mystery") == "UNREGISTERED"

    def test_disabled_is_not_an_alarm(self):
        rows = watchdog.collect(FakeConn(
            [exp("cve", 48, enabled=False)], {"raw.pipeline_runs": []}))
        assert state_of(rows, "cve") == "DISABLED"


class TestExitBehaviour:
    def _rows(self, states):
        return [{"pipeline": p, "display_name": p, "workflow": "w.yml", "cron": "*",
                 "state": s, "max_silence_hours": 30, "hours_since_ok": 1.0,
                 "last_ok": None, "last_attempt": None, "failing_since_last_ok": False}
                for p, s in states.items()]

    def test_render_lists_problems_first(self):
        out = watchdog.render(self._rows({"aaa_ok": "OK", "zzz_bad": "OVERDUE"}))
        assert out.index("zzz_bad") < out.index("aaa_ok")

    def test_pending_and_disabled_do_not_fail_the_run(self):
        rows = self._rows({"a": "PENDING", "b": "DISABLED", "c": "OK"})
        assert not [r for r in rows
                    if r["state"] in ("OVERDUE", "NEVER RAN", "UNREGISTERED")]
