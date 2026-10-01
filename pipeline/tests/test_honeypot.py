"""Parsing tests for the Shadowserver honeypot API.

The fixture is synthetic data in the exact shape of the live endpoint, and deliberately
contains every quirk measured on 2026-08-30: a string "1d" beside integer averages, unscored rows, rows with
no euvd cross-reference, a cisa_kev=yes row, and two non-CVE identifiers. If the fixture
stops covering one of those, `test_fixture_still_covers_every_quirk` fails — otherwise
these tests could quietly stop exercising the code they exist for.
"""

from __future__ import annotations

import json
from datetime import date, datetime
from pathlib import Path

import pytest

from zdc_honeypot.models import (
    HoneypotParseError,
    id_type,
    parse_response,
    parse_row,
)

FIXTURE = Path(__file__).parent / "fixtures" / "shadowserver_honeypot_api.ndjson"
DAY = date(2026, 8, 30)


@pytest.fixture()
def raw_objects() -> list[dict]:
    return [json.loads(l) for l in FIXTURE.read_text().splitlines() if l.strip()]


@pytest.fixture()
def rows(raw_objects):
    return [parse_row(o, DAY) for o in raw_objects]


# ---------------------------------------------------------------------------
# The fixture must keep earning its place.
# ---------------------------------------------------------------------------
def test_fixture_still_covers_every_quirk(raw_objects):
    assert any(isinstance(o.get("1d"), str) for o in raw_objects), "no string '1d'"
    assert any(o.get("vulnerability_score") is None for o in raw_objects), "no unscored row"
    assert any(not o.get("euvd") for o in raw_objects), "no row missing euvd"
    assert any(o.get("cisa_kev") == "yes" for o in raw_objects), "no cisa_kev=yes row"
    assert any(not o["vulnerability"].startswith("CVE-") for o in raw_objects), "no non-CVE id"


# ---------------------------------------------------------------------------
# Type coercion — the reason this module exists.
# ---------------------------------------------------------------------------
def test_string_1d_and_integer_averages_both_become_ints(rows):
    for r in rows:
        assert isinstance(r.avg_1d, int)
        for v in (r.avg_7d, r.avg_30d, r.avg_90d):
            assert v is None or isinstance(v, int)


def test_connections_is_required():
    with pytest.raises(HoneypotParseError):
        parse_row({"vulnerability": "CVE-2020-0001"}, DAY)


def test_missing_identifier_is_an_error():
    with pytest.raises(HoneypotParseError):
        parse_row({"connections": 5}, DAY)


def test_a_bool_is_not_a_count():
    # bool is an int subclass in Python; accepting it would store True as 1 silently.
    with pytest.raises(HoneypotParseError):
        parse_row({"vulnerability": "CVE-2020-0001", "connections": True}, DAY)


def test_unparseable_count_raises_rather_than_defaulting_to_zero():
    with pytest.raises(HoneypotParseError):
        parse_row({"vulnerability": "CVE-2020-0001", "connections": "many"}, DAY)


# ---------------------------------------------------------------------------
# Identifier typing — non-CVE ids are the ones no catalogue can list.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "vid,kind",
    [("CVE-2020-99901", "cve"), ("EDB-41471", "edb"), ("CNVD-2018-24942", "cnvd"),
     ("GCVE-1-2026-0020", "gcve"), ("something-else", "other")],
)
def test_identifier_typing(vid, kind):
    assert id_type(vid) == kind


def test_non_cve_identifiers_survive_with_no_cve_id(rows):
    non_cve = [r for r in rows if r.vuln_id_type != "cve"]
    assert non_cve, "fixture lost its non-CVE rows"
    for r in non_cve:
        assert r.cve_id is None


def test_cve_rows_carry_a_cve_id(rows):
    for r in (r for r in rows if r.vuln_id_type == "cve"):
        assert r.cve_id == r.vuln_id.upper()


def test_malformed_cve_is_not_typed_as_cve():
    # The 0028 CHECK constraint requires (type='cve') == (cve_id is not null); a
    # malformed 'CVE-...' typed as cve would violate it at insert.
    r = parse_row({"vulnerability": "CVE-BOGUS", "connections": 1}, DAY)
    assert r.vuln_id_type == "other" and r.cve_id is None


# ---------------------------------------------------------------------------
# Nullable attributes must stay null, not become defaults.
# ---------------------------------------------------------------------------
def test_unscored_rows_keep_a_null_score(rows):
    unscored = [r for r in rows if r.cvss_score is None]
    assert unscored, "fixture lost its unscored row"
    for r in unscored:
        assert r.severity is None or isinstance(r.severity, str)


def test_out_of_range_score_is_rejected_not_stored():
    r = parse_row({"vulnerability": "CVE-2020-0001", "connections": 1,
                   "vulnerability_score": 99.0}, DAY)
    assert r.cvss_score is None


def test_yes_no_becomes_boolean_and_unknown_becomes_null(rows):
    assert any(r.cisa_kev is True for r in rows)
    assert all(r.is_iot in (True, False, None) for r in rows)
    r = parse_row({"vulnerability": "CVE-2020-0001", "connections": 1, "iot": "maybe"}, DAY)
    assert r.is_iot is None


def test_first_seen_parses_to_a_datetime(rows):
    seen = [r.sensor_first_seen for r in rows if r.sensor_first_seen]
    assert seen, "fixture lost first_seen"
    for d in seen:
        assert isinstance(d, datetime)
        assert d.year >= 2000


# ---------------------------------------------------------------------------
# Response-level behaviour.
# ---------------------------------------------------------------------------
def test_parse_response_reads_every_fixture_line(raw_objects):
    rows, errors = parse_response(FIXTURE.read_text(), DAY)
    assert len(rows) == len(raw_objects)
    assert errors == []


def test_malformed_lines_are_reported_not_silently_dropped():
    body = '{"vulnerability":"CVE-2020-0001","connections":5}\nnot json\n{"connections":1}\n'
    rows, errors = parse_response(body, DAY)
    assert len(rows) == 1
    assert len(errors) == 2, "a harvester that drops what it cannot parse reports a smaller world"


def test_blank_lines_are_not_errors():
    rows, errors = parse_response('\n\n{"vulnerability":"CVE-2020-0001","connections":5}\n\n', DAY)
    assert len(rows) == 1 and errors == []


# ---------------------------------------------------------------------------
# The grain: (vulnerability, product, day), not (vulnerability, day).
# ---------------------------------------------------------------------------
def test_product_key_normalises_a_missing_product():
    r = parse_row({"vulnerability": "CVE-2030-0001", "connections": 1}, DAY)
    assert r.product_key == "" and r.product is None


def test_product_key_matches_product_when_present(rows):
    for r in rows:
        assert r.product_key == (r.product or "")


def test_same_cve_against_two_products_yields_two_distinct_keys():
    # Seen on the live API (values here are synthetic): one CVE is reported against two
    # different products on the same day, with different vendors, classes and counts.
    # Keying on the CVE alone silently discards one.
    body = (
        '{"vulnerability":"CVE-2020-99904","connections":512,"product":"Example Storefront Server",'
        '"vendor":"Example Vendor F","class":"other-software"}\n'
        '{"vulnerability":"CVE-2020-99904","connections":3,"product":"Example CMS/XP",'
        '"vendor":"Example Vendor G","class":"cms"}\n'
    )
    parsed, errors = parse_response(body, DAY)
    assert errors == []
    assert len(parsed) == 2, "both product rows must survive"
    keys = {(r.vuln_id, r.product_key, r.observed_on) for r in parsed}
    assert len(keys) == 2, "the two rows must not collide on the natural key"
    assert {r.connections for r in parsed} == {512, 3}
    assert {r.vendor for r in parsed} == {"Example Vendor F", "Example Vendor G"}


def test_observed_on_is_the_requested_day_not_todays_date(rows):
    # The API takes a date parameter; the row carries no date of its own, so the caller's
    # requested day is authoritative. Using now() here would make backfill wrong.
    for r in rows:
        assert r.observed_on == DAY


class TestFreshnessReadsTheRegistry:
    """0068: the threshold lives in obs_core.observation_sources, not in the signature.

    A constant here meant the declared max_silence_days was documentation the pipeline
    ignored — tuning the data changed nothing, and the two could disagree silently.
    """

    class FakeConn:
        """Answers by WHICH query was asked, not by call order.

        A positional fake breaks the moment a code path skips a query — which is
        exactly the branch under test here — and then reports a fault in the code
        rather than in itself.
        """

        def __init__(self, declared, last_observed):
            self.declared, self.last_observed = declared, last_observed
            self.queries = []

        def cursor(self):
            outer = self
            class Cur:
                _last = ""
                def __enter__(self): return self
                def __exit__(self, *a): return False
                def execute(self, sql, params=None):
                    self._last = sql; outer.queries.append(sql)
                def fetchone(self):
                    if "max_silence_days" in self._last:
                        return (outer.declared,)
                    return (outer.last_observed,)
            return Cur()

    def _check(self, declared, last_observed, censored=date(2026, 9, 8), **kw):
        from zdc_honeypot import evals
        conn = self.FakeConn(declared, last_observed)
        return evals.check_freshness(conn, censored, **kw), conn

    def test_uses_the_declared_threshold_not_the_old_constant(self):
        """Declared 5, lag 4: passes. Under the hardcoded 3 it would have failed."""
        r, conn = self._check(5, date(2026, 9, 4))
        assert r.passed, r.summary
        assert any("max_silence_days" in q for q in conn.queries), \
            "the eval never read the registry"

    def test_a_tighter_declared_threshold_is_honoured_too(self):
        """Not just 'looser wins' — the registry decides in both directions."""
        r, _ = self._check(1, date(2026, 9, 6))
        assert not r.passed

    def test_falls_back_to_three_when_nothing_is_declared(self):
        """A source with no threshold must not pass vacuously."""
        r, _ = self._check(None, date(2026, 9, 1))
        assert not r.passed

    def test_an_explicit_argument_still_wins_and_skips_the_lookup(self):
        r, conn = self._check(1, date(2026, 9, 6), max_lag_days=30)
        assert r.passed
        assert not any("max_silence_days" in q for q in conn.queries)
