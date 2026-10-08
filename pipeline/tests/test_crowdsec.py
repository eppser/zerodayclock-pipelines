"""CrowdSec harvester tests.

Every check is exercised in both directions. A check that has only ever been seen to
pass is not evidence of anything — v1's lesson was that a green signal which cannot go
red trains the reader to stop looking.
"""

from __future__ import annotations

import io
from datetime import date

import pytest

from zdc_crowdsec import db, evals
from zdc_crowdsec.client import strip_tags
from zdc_crowdsec.models import CveState, DayCount, parse_cves, parse_timeline

# Synthetic replica of the string /v1/info returned on 2026-09-22 (same tag-character
# sequence and position; the visible name is invented): an invisible, unfilled
# prompt-injection template spliced into the middle of a human-looking name.
POISONED = ("Example Access - J\U000e0000\U000e0065\U000e006e\U000e0074\U000e0065\U000e0072"
            "\U000e0020\U000e0067\U000e006f\U000e0061\U000e006c\U000e0020\U000e0068"
            "\U000e0065\U000e0072\U000e0065\U000e0020\U000e005f\U000e005f\U000e002e"
            "\U000e007fane Doe - Test key (xyz) 30d")


class TestStripTags:
    """The injection vector must not survive the transport boundary."""

    def test_removes_the_tag_block_from_the_real_payload(self):
        assert strip_tags(POISONED) == "Example Access - Jane Doe - Test key (xyz) 30d"

    def test_leaves_ordinary_text_untouched(self):
        assert strip_tags("Example Product — Admin Panel Probing") == \
            "Example Product — Admin Panel Probing"

    def test_reaches_inside_nested_structures(self):
        out = strip_tags({"a": [{"b": "x\U000e0041y"}], "n": 3, "z": None})
        assert out == {"a": [{"b": "xy"}], "n": 3, "z": None}

    def test_is_applied_to_parsed_cve_text(self):
        """Parsing poisoned input must not be the way it gets in."""
        s = parse_cves([{"id": "CVE-2026-0001", "title": strip_tags(POISONED),
                         "affected_components": [{"vendor": "V", "product": "P"}]}])[0]
        assert not any(0xE0000 <= ord(c) <= 0xE007F for c in s.title)


class TestParseTimeline:
    PTS = [{"timestamp": "2026-09-20T00:00:00Z", "count": 5},
           {"timestamp": "2026-09-21T00:00:00Z", "count": 0},
           {"timestamp": "2026-09-22T00:00:00Z", "count": 3}]

    def test_drops_the_partial_current_day(self):
        out = parse_timeline("CVE-1", self.PTS, upto=date(2026, 9, 22))
        assert [c.day for c in out] == [date(2026, 9, 20), date(2026, 9, 21)]

    def test_keeps_a_measured_zero(self):
        """A zero is 'we watched and saw nothing' — a typed absence, not a gap."""
        out = parse_timeline("CVE-1", self.PTS, upto=date(2026, 9, 22))
        assert [c.count for c in out] == [5, 0]

    def test_keeps_the_last_day_when_no_cutoff_is_given(self):
        assert len(parse_timeline("CVE-1", self.PTS)) == 3

    def test_points_on_the_same_utc_day_are_summed_not_overwritten(self):
        pts = [{"timestamp": "2026-09-20T00:00:00Z", "count": 5},
               {"timestamp": "2026-09-20T12:00:00Z", "count": 7},
               # 01:00 at +02:00 is 23:00 UTC the day before.
               {"timestamp": "2026-09-21T01:00:00+02:00", "count": 4}]
        out = parse_timeline("CVE-1", pts)
        assert [(c.day, c.count) for c in out] == [(date(2026, 9, 20), 16)]

    @pytest.mark.parametrize("bad", [None, {}, "nope", [{"count": 1}],
                                     [{"timestamp": "x", "count": 1}],
                                     [{"timestamp": "2026-09-20T00:00:00Z", "count": -1}]])
    def test_rejects_malformed_points_without_raising(self, bad):
        assert parse_timeline("CVE-1", bad) == []


class TestParseCves:
    def test_extracts_the_fields_the_observation_needs(self):
        s = parse_cves([{
            "id": "CVE-2025-99901", "title": "Example Product - Auth Bypass",
            "affected_components": [{"vendor": "Example Vendor", "product": "Example Product"}],
            "nb_ips": 123457, "first_seen": "2025-04-16T00:00:00Z",
            "rule_release_date": "2025-04-15T10:00:00", "cvss_score": 8.4,
            "exploitation_phase": {"name": "active_exploitation"},
        }])[0]
        assert (s.cve_id, s.vendor, s.product) == ("CVE-2025-99901", "Example Vendor", "Example Product")
        assert s.phase == "active_exploitation" and s.nb_ips == 123457
        assert s.rule_release_date == date(2025, 4, 15)

    def test_skips_identifiers_that_are_not_cves(self):
        """The tracker is CVE-only today. A GHSA appearing later must not be silently
        mis-typed as a CVE — it is dropped and the count moves, which is visible."""
        assert parse_cves([{"id": "GHSA-xxxx"}, {"id": "CVE-2026-0001"}]) == \
            parse_cves([{"id": "CVE-2026-0001"}])

    def test_upper_cases_and_requires_the_database_check_pattern(self):
        """A prefix test let these through to the obs_cve_shape CHECK, where one row
        failed the whole batch. Each is now rejected and counted, never dropped silently."""
        rejected: list[str] = []
        out = parse_cves([{"id": "cve-2026-0003"}, {"id": "CVE-2026-XXXX"},
                          {"id": "CVE-2026-123"}, {"id": "GHSA-xxxx"}, {"id": None}],
                         rejected)
        assert [s.cve_id for s in out] == ["CVE-2026-0003"]
        assert len(rejected) == 4

    def test_rejected_ids_eval_warns_with_the_count(self):
        ok = evals.check_rejected_ids([])
        bad = evals.check_rejected_ids(["'CVE-2026-XXXX'"])
        assert ok.passed and not bad.passed
        assert bad.severity == evals.WARN and not bad.blocking
        assert bad.detail["rejected"] == 1

    def test_survives_a_missing_components_block(self):
        s = parse_cves([{"id": "CVE-2026-0001"}])[0]
        assert s.vendor is None and s.product is None

    def test_active_is_what_decides_a_timeline_fetch(self):
        never = parse_cves([{"id": "CVE-2026-0001", "nb_ips": 0}])[0]
        seen = parse_cves([{"id": "CVE-2026-0002", "first_seen": "2026-01-01T00:00:00Z"}])[0]
        assert not never.active and seen.active


class TestEntryId:
    def test_matches_the_shadowserver_convention(self):
        """Same grain, same spelling, so the two sensors compare without translation."""
        assert db.entry_id("CVE-2025-1", date(2026, 9, 20)) == "CVE-2025-1@2026-09-20"

    def test_is_unique_per_day(self):
        a = db.entry_id("CVE-1", date(2026, 9, 20))
        assert a != db.entry_id("CVE-1", date(2026, 9, 21))


def _state(**kw):
    base = dict(cve_id="CVE-1", title="t", vendor="v", product="p", nb_ips=1,
                first_seen=date(2026, 1, 1), last_seen=date(2026, 9, 1),
                rule_release_date=date(2025, 1, 1), published_date=date(2024, 1, 1),
                phase="limited_exploitation", cvss_score=7.0, has_public_exploit=True,
                crowdsec_score=1.0, opportunity_score=1.0, momentum_score=1.0)
    base.update(kw)
    return CveState(**base)


class TestRawRow:
    def test_carries_the_phase_so_the_series_is_recoverable(self):
        """0029's lesson: one sensor must not be split across two stores. Phase history
        lives in the daily row rather than in a second table."""
        raw = db._raw(_state(), DayCount("CVE-1", date(2026, 9, 20), 42))
        assert raw["exploitation_phase"] == "limited_exploitation"
        assert raw["occurrences"] == 42

    def test_carries_no_per_ip_field(self):
        raw = db._raw(_state(), DayCount("CVE-1", date(2026, 9, 20), 1))
        assert not {"ip", "ips", "ip_range", "source_ip"} & set(raw)

    def test_drops_nulls_rather_than_storing_them(self):
        raw = db._raw(_state(phase=None, cwes=[]), DayCount("CVE-1", date(2026, 9, 20), 1))
        assert "exploitation_phase" not in raw and "cwes" not in raw


class TestEvals:
    def test_catalogue_fetched_both_ways(self):
        assert evals.check_catalogue_fetched(500, None).passed
        assert not evals.check_catalogue_fetched(0, None).passed
        assert not evals.check_catalogue_fetched(500, "HTTP 403").passed

    def test_timelines_tolerates_a_transient_but_not_an_outage(self):
        """One failure in 500 must not discard 499 good rows; a tenth failing is a rate
        limit wearing a success badge."""
        assert evals.check_timelines_fetched(500, [("CVE-1", "HTTP 500")]).passed
        assert not evals.check_timelines_fetched(500, [("C", "e")] * 51).passed   # 10.2%
        assert not evals.check_timelines_fetched(0, []).passed

    def test_persisted_catches_fetching_cleanly_and_storing_nothing(self):
        assert evals.check_persisted(10, 5, 15).passed
        assert not evals.check_persisted(0, 0, 900).passed
        assert evals.check_persisted(0, 0, 0).passed      # nothing to store is not a fault

    def test_window_complete_warns_when_the_re_read_shrinks(self):
        assert evals.check_window_complete(30, 28).passed
        assert not evals.check_window_complete(3, 28).passed

    def test_no_per_ip_data_both_ways(self):
        assert evals.check_no_per_ip_data([{"occurrences": 1}]).passed
        assert not evals.check_no_per_ip_data([{"occurrences": 1, "ip": "1.2.3.4"}]).passed

    def test_tag_characters_stripped_both_ways(self):
        assert evals.check_tag_characters_stripped([{"title": "clean"}]).passed
        assert not evals.check_tag_characters_stripped([{"title": POISONED}]).passed

    def test_not_in_kev_layer_both_ways(self):
        class Conn:
            def __init__(self, n): self.n = n
            def cursor(self):
                n = self.n
                class C:
                    def __enter__(self): return self
                    def __exit__(self, *a): return False
                    def execute(self, *a): pass
                    def fetchone(self): return (n,)
                return C()
        assert evals.check_not_in_kev_layer(Conn(0)).passed
        assert not evals.check_not_in_kev_layer(Conn(150)).passed


class TestFreshness:
    """Nothing else watches this source: zdc_obs scopes its freshness check to its own
    collector, so without this the thresholds 0081 declares would go unread."""

    class Conn:
        def __init__(self, last, threshold=3):
            self._q = [(threshold,), (last,)]
        def cursor(self):
            q = self._q
            class C:
                def __enter__(self): return self
                def __exit__(self, *a): return False
                def execute(self, *a): pass
                def fetchone(self): return q.pop(0)
            return C()

    def test_passes_when_the_feed_is_current(self):
        r = evals.check_freshness(self.Conn(date(2026, 9, 21)), date(2026, 9, 22))
        assert r.passed and r.detail["lag_days"] == 1

    def test_fails_once_the_feed_stops(self):
        r = evals.check_freshness(self.Conn(date(2026, 9, 1)), date(2026, 9, 22))
        assert not r.passed and r.severity == evals.ERROR

    def test_reads_the_threshold_from_the_registry(self):
        """A constant here would make the declared value documentation nobody reads."""
        assert evals.check_freshness(self.Conn(date(2026, 9, 12), threshold=30),
                                     date(2026, 9, 22)).passed

    def test_an_empty_store_is_a_failure_not_a_pass(self):
        assert not evals.check_freshness(self.Conn(None), date(2026, 9, 22)).passed


class TestChunking:
    """Postgres refuses more than 65,535 bind parameters in one statement.

    A daily harvest is ~21,000 (CVE, day) rows at 17 columns = ~356,000 parameters.
    The honeypot stores ~700 rows a day and never meets the ceiling; copying its
    single-statement shape is exactly what broke the first live run here.
    """

    class Conn:
        def __init__(self): self.batches = []
        def cursor(self):
            outer = self
            class C:
                def __enter__(self): return self
                def __exit__(self, *a): return False
                def execute(self, sql, params): outer.batches.append(len(params))
                def fetchall(self): return [(True,)] * (outer.batches[-1] // db.COLS)
            return C()

    def _counts(self, n):
        return [DayCount(f"CVE-2026-{i}", date(2026, 9, 1), i) for i in range(n)]

    def _states(self, n):
        return {f"CVE-2026-{i}": _state(cve_id=f"CVE-2026-{i}") for i in range(n)}

    def test_no_statement_exceeds_the_parameter_ceiling(self):
        conn = self.Conn()
        db.upsert_observations(conn, self._states(21000), self._counts(21000), "f")
        assert conn.batches, "nothing was written"
        assert max(conn.batches) <= 65535, f"largest batch was {max(conn.batches)}"

    def test_every_row_is_written_exactly_once(self):
        conn = self.Conn()
        ins, upd = db.upsert_observations(conn, self._states(4500), self._counts(4500), "f")
        assert sum(conn.batches) // db.COLS == 4500
        assert ins + upd == 4500

    def test_a_small_harvest_still_takes_one_statement(self):
        conn = self.Conn()
        db.upsert_observations(conn, self._states(10), self._counts(10), "f")
        assert len(conn.batches) == 1


class TestErrorDetail:
    """A bare "HTTP 403" cost a round trip to find out whose 403 it was — the API's or
    the CDN in front of it. Only the body distinguishes them."""

    def _client(self, code, body):
        import urllib.error
        from zdc_crowdsec import client as cl
        c = cl.CrowdSecClient("k", retries=1)
        def boom(*a, **k):
            raise urllib.error.HTTPError("u", code, "x", {}, io.BytesIO(body))
        cl.urllib.request.urlopen = boom
        return c

    def test_error_carries_the_response_body(self):
        r = self._client(403, b"error code: 1010").get("/cves")
        assert "1010" in r.error and r.status == 403

    def test_error_survives_an_unreadable_body(self):
        r = self._client(403, b"").get("/cves")
        assert r.error == "HTTP 403"

    def test_body_is_bounded(self):
        r = self._client(403, b"x" * 5000).get("/cves")
        assert len(r.error) < 260


class TestNotSilentlyEmpty:
    """Every timeline answers 200 and every one is empty — the run would otherwise
    go green, because the catalogue is fine, nothing errored, and storing nothing
    when there is nothing to store is not a fault."""

    def test_fails_when_every_timeline_came_back_empty(self):
        r = evals.check_not_silently_empty(600, 0)
        assert not r.passed and r.severity == evals.ERROR

    def test_passes_on_a_normal_harvest(self):
        assert evals.check_not_silently_empty(600, 15000).passed

    def test_asking_for_nothing_is_not_a_fault(self):
        assert evals.check_not_silently_empty(0, 0).passed

    def test_the_run_is_blocked_not_merely_warned(self):
        """window_complete already WARNed on this and a warning does not stop a run."""
        assert evals.check_not_silently_empty(600, 0).blocking
