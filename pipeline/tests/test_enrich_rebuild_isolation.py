"""One failing rebuild must not discard the others, and every one is timed."""
from __future__ import annotations

import logging

import pytest

from zdc_enrich import db


class _FakeCursor:
    """Serves core.method_registry rows to db.current_method_versions."""

    def __init__(self, registry):
        self._registry = registry

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, *a, **kw):
        return None

    def fetchall(self):
        return list(self._registry.items())


class FakeConn:
    """Records commits and rollbacks so the test can assert what survived.

    Also answers the registry lookup: run_rebuilds resolves each metric's
    method_version from core.method_registry, so a conn with no cursor() would
    fail before reaching the isolation behaviour these tests are about.
    """

    def __init__(self, registry=None):
        self.events: list[str] = []
        self.registry = registry or {}

    def cursor(self):
        return _FakeCursor(self.registry)

    def commit(self):
        self.events.append("commit")

    def rollback(self):
        self.events.append("rollback")


def _ok(n):
    def fn(conn, *, method_version, censored_at, run_id):
        return n
    return fn


def _boom(exc=RuntimeError("deadlock detected")):
    def fn(conn, *, method_version, censored_at, run_id):
        raise exc
    return fn


KW = dict(method_version="test", censored_at="2026-09-02", run_id=None,
          log=logging.getLogger("test"))


def test_a_failure_in_the_middle_does_not_stop_the_rest():
    # THE BUG THIS EXISTS FOR: all ten rebuilds shared one transaction and one try block, so a
    # deadlock in the first discarded every table, including three that had already succeeded.
    conn = FakeConn()
    rows, errors, seconds = db.run_rebuilds(
        conn,
        [("a", "derived.a", _ok(1)),
         ("b", "derived.b", _boom()),
         ("c", "derived.c", _ok(3))],
        **KW,
    )
    assert rows == {"a": 1, "b": 0, "c": 3}
    assert list(errors) == ["derived.b"]
    # a committed, b rolled back, c committed
    assert conn.events == ["commit", "rollback", "commit"]


def test_the_error_names_the_table_that_failed():
    conn = FakeConn()
    _, errors, _seconds = db.run_rebuilds(conn, [("b", "derived.b", _boom())], **KW)
    assert "derived.b" in errors
    assert "RuntimeError" in errors["derived.b"]
    assert "deadlock" in errors["derived.b"]


def test_every_rebuild_failing_still_reports_each_one():
    conn = FakeConn()
    rows, errors, seconds = db.run_rebuilds(
        conn,
        [("a", "derived.a", _boom()), ("b", "derived.b", _boom())],
        **KW,
    )
    assert rows == {"a": 0, "b": 0}
    assert set(errors) == {"derived.a", "derived.b"}
    assert conn.events == ["rollback", "rollback"]
    # A rebuild that FAILED is still timed. How long a rebuild ran before it died is the
    # first thing anyone asks when one starts failing, and it is exactly the case where
    # a timing that only covers the happy path tells you nothing.
    assert set(seconds) == {"derived.a", "derived.b"}


def test_a_clean_run_commits_once_per_rebuild():
    conn = FakeConn()
    rows, errors, seconds = db.run_rebuilds(
        conn, [("a", "derived.a", _ok(5)), ("b", "derived.b", _ok(6))], **KW)
    assert errors == {}
    assert rows == {"a": 5, "b": 6}
    # One commit per rebuild, not one at the end: that is what makes them independent.
    assert conn.events == ["commit", "commit"]


@pytest.mark.parametrize("exc", [RuntimeError("x"), ValueError("y"), KeyError("z")])
def test_any_exception_type_is_isolated(exc):
    conn = FakeConn()
    _, errors, _seconds = db.run_rebuilds(conn, [("a", "derived.a", _boom(exc))], **KW)
    assert list(errors) == ["derived.a"]


def test_every_rebuild_is_timed():
    """The durations exist because the rebuilds approach the statement timeout.

    derived.rebuild_technology measures 90 to 102 seconds against six years of data and
    grows with the corpus. The session raises the timeout, which buys room and hides the
    trend, so the durations go into the run notes. A rebuild that is not timed is a
    rebuild whose growth nobody sees until a run goes red.
    """
    conn = FakeConn()
    rows, errors, seconds = db.run_rebuilds(
        conn, [("a", "derived.a", _ok(5)), ("b", "derived.b", _ok(6))], **KW)
    assert errors == {}
    assert set(seconds) == {"derived.a", "derived.b"}
    assert all(isinstance(v, float) and v >= 0 for v in seconds.values())
    # Keyed on the TABLE, matching rebuild_errors, so a reader comparing the two dicts
    # in a run report is comparing like with like.
    assert set(seconds) == set(rows and {"derived.a", "derived.b"})


# --- the version a rebuild is actually given -------------------------------
#
# One global --method-version was applied to ten metrics with ten independent
# version histories. Measured 2026-09-03: pressure_index and patch_window_cohorts
# were correctly on v5 while the pipeline default was v3, so a scheduled run would
# have re-stamped them and pointed readers at the wrong method description.


def _capture():
    """A rebuild that records the method_version it was handed."""
    seen = {}

    def fn(conn, *, method_version, censored_at, run_id):
        seen["version"] = method_version
        return 1

    return fn, seen


def test_registered_metric_gets_its_own_version_not_the_global_one():
    conn = FakeConn(registry={"pressure_index": "v5"})
    fn, seen = _capture()
    db.run_rebuilds(conn, [("p", "derived.pressure_index", fn)], **KW)
    assert seen["version"] == "v5", "the registry, not --method-version, owns the version"


def test_unregistered_metric_falls_back_to_the_global_version():
    conn = FakeConn(registry={})            # nothing registered
    fn, seen = _capture()
    db.run_rebuilds(conn, [("p", "derived.brand_new", fn)], **KW)
    assert seen["version"] == "test"        # KW's method_version


def test_two_metrics_get_two_different_versions_in_one_run():
    # The precise failure: one string for every table.
    conn = FakeConn(registry={"pressure_index": "v5", "cve_detail": "v3"})
    f1, s1 = _capture()
    f2, s2 = _capture()
    db.run_rebuilds(conn, [("a", "derived.pressure_index", f1),
                           ("b", "derived.cve_detail", f2)], **KW)
    assert (s1["version"], s2["version"]) == ("v5", "v3")
