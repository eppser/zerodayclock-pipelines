"""CVE registry adapter tests. Fixtures cut from the live bundles on 2026-08-28."""

from __future__ import annotations

import json
from datetime import date, datetime, timedelta, timezone

import pytest

from conftest import FIXTURES, StubClient, load_bytes, load_json, make_fetch
from zdc_cve.models import CveRecord, NormalisationError, clamp, cve_year
from zdc_cve.sources.base import CveSourceState
from zdc_cve.sources.cve_project import CveProject, _read_bundle
from zdc_cve.sources.nvd import Nvd, _chunk


def releases(*specs) -> bytes:
    """Build a GitHub releases index response."""
    return json.dumps([
        {"tag_name": tag, "assets": [{"name": name,
                                      "browser_download_url": f"https://x.test/{name}"}]}
        for tag, name in specs
    ]).encode()


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class TestCveModel:
    def test_year_comes_from_the_identifier(self):
        assert cve_year("CVE-2019-0001") == 2019
        assert cve_year("cve-2003-5002") == 2003

    def test_year_rejects_a_non_cve(self):
        with pytest.raises(NormalisationError):
            cve_year("EDB-41471")

    @pytest.mark.parametrize("over", [
        {"cve_id": "CVE-BAD"}, {"source": "somewhere"},
        {"state": "DRAFT"}, {"cna_cvss_score": 11.0}, {"nvd_cvss_score": -1.0},
    ])
    def test_rejects_invalid(self, over):
        kw = dict(cve_id="CVE-2024-0001", source="cve_project")
        kw.update(over)
        with pytest.raises(NormalisationError):
            CveRecord(**kw)

    def test_clamp_bounds_the_row_and_drops_placeholders(self):
        # A few CVEs list thousands of products; unbounded arrays would bloat the table.
        assert clamp([f"p{i}" for i in range(100)], limit=5) == tuple(f"p{i}" for i in range(5))
        assert clamp(["n/a", "Cisco", "Cisco", ""]) == ("Cisco",)


# ---------------------------------------------------------------------------
# CVE Project
# ---------------------------------------------------------------------------


class TestCveProjectBundles:
    def test_reads_a_delta(self):
        records, bad = _read_bundle(load_bytes("cve_delta.zip"), require_records=False)
        assert len(records) == 3 and bad == 0
        assert {r.source for r in records} == {"cve_project"}

    def test_rejected_cves_are_kept(self):
        """A REJECTED CVE is a real outcome and must not vanish from the denominator."""
        records, _ = _read_bundle(load_bytes("cve_delta.zip"), require_records=False)
        assert any(r.state == "REJECTED" for r in records)

    def test_empty_delta_is_not_an_error(self):
        """A quiet window produces a legitimate 22-byte zip with zero entries."""
        records, bad = _read_bundle(load_bytes("cve_delta_empty.zip"), require_records=False)
        assert records == [] and bad == 0

    def test_empty_baseline_IS_an_error(self):
        # Same bytes, different expectation: an empty baseline means a broken download.
        with pytest.raises(ValueError):
            _read_bundle(load_bytes("cve_delta_empty.zip"), require_records=True)

    def test_unwraps_the_nested_baseline(self):
        """The baseline really is .zip.zip -> cves.zip -> per-CVE json."""
        records, bad = _read_bundle(load_bytes("cve_baseline_nested.zip"))
        assert len(records) == 2 and bad == 0

    def test_extracts_the_cna_fields(self):
        records, _ = _read_bundle(load_bytes("cve_delta.zip"), require_records=False)
        r = next(r for r in records if r.state == "PUBLISHED")
        assert r.assigner_short_name
        assert r.date_reserved is not None and r.date_published is not None
        # CNA score lands in the cna_* columns, never the nvd_* ones.
        assert r.nvd_cvss_score is None and r.nvd_published is None


class TestCveProjectCollect:
    #: A cursor that IS present in the index — the ordinary case. Absence of a cursor
    #: now escalates to the baseline (see TestCveProjectGapRecovery), so these tests
    #: must anchor the walk explicitly.
    ANCHOR = "cve_2026-08-25_2200Z"

    def collect(self, state=None, mode="incremental", index=None, assets=None):
        index = index or releases(("cve_2026-08-27_at_end_of_day", "delta_end_of_day.zip"),
                                  ("cve_2026-08-26_2300Z", "delta_2300Z.zip"),
                                  (self.ANCHOR, "delta_anchor.zip"))
        fetches = [make_fetch("cve_project", index)]
        for body in (assets if assets is not None else [load_bytes("cve_delta.zip")] * 2):
            fetches.append(make_fetch("cve_project", body))
        client = StubClient(fetches)
        return CveProject().collect(client, state or CveSourceState(cursor=self.ANCHOR), mode,
                                    today=date(2026, 8, 28)), client

    def test_walks_deltas_since_the_cursor(self):
        result, client = self.collect()
        assert result.error is None
        assert result.records
        # The anchor itself is already consumed, so only the two newer releases.
        assert len(result.covered) == 2

    def test_cursor_stops_the_walk(self):
        """Resumption is by release tag, so already-consumed releases are not refetched."""
        state = CveSourceState(cursor="cve_2026-08-26_2300Z")
        result, client = self.collect(state=state, assets=[load_bytes("cve_delta.zip")])
        assert len(result.covered) == 1
        assert "cve_2026-08-27_at_end_of_day" in result.covered[0]

    def test_nothing_new_is_unchanged_not_empty(self):
        state = CveSourceState(cursor="cve_2026-08-27_at_end_of_day")
        client = StubClient([make_fetch("cve_project",
                                        releases(("cve_2026-08-27_at_end_of_day", "d1.zip")))])
        result = CveProject().collect(client, state, "incremental")
        assert result.unchanged is True and result.error is None

    def test_deltas_are_applied_oldest_first(self):
        """A later release must win, so the walk is reversed before processing."""
        _, client = self.collect()
        # index, then d2 (older) before d1 (newer)
        assert [c["url"].rsplit("/", 1)[-1] for c in client.calls[1:]] == ["delta_2300Z.zip", "delta_end_of_day.zip"]

    def test_a_failed_delta_stops_the_run_so_the_cursor_cannot_advance(self):
        index = releases(("t1", "delta_a.zip"), ("t2", "delta_b.zip"), ("anchor", "delta_c.zip"))
        client = StubClient([
            make_fetch("cve_project", index),
            make_fetch("cve_project", None, ok=False, status=500, error="HTTP 500"),
            make_fetch("cve_project", load_bytes("cve_delta.zip")),
        ])
        result = CveProject().collect(client, CveSourceState(cursor="anchor"), "incremental")
        assert "500" in result.error
        assert result.complete_snapshot is False

    def test_too_far_behind_escalates_to_the_baseline(self):
        """Catching up is the pipeline's job, not the operator's."""
        from zdc_cve.sources.cve_project import MAX_DELTAS
        many = releases(*[(f"t{i}", f"delta_{i}.zip") for i in range(MAX_DELTAS + 5)]
                        + [("cursor-tag", "delta_old.zip")])
        base = json.dumps([{"tag_name": "newest", "assets": [
            {"name": "2026-08-28_all_CVEs_at_midnight.zip.zip",
             "browser_download_url": "https://x.test/base.zip"}]}]).encode()
        client = StubClient([make_fetch("cve_project", many),
                             make_fetch("cve_project", base),
                             make_fetch("cve_project", load_bytes("cve_baseline_nested.zip"))])
        result = CveProject().collect(client, CveSourceState(cursor="cursor-tag"), "incremental")
        assert result.error is None
        assert result.complete_snapshot is True
        assert any("ESCALATED" in c for c in result.covered)

    def test_full_mode_takes_the_baseline_and_discards_the_body(self):
        index = json.dumps([{"tag_name": "cve_2026-08-28_0700Z", "assets": [
            {"name": "2026-08-28_all_CVEs_at_midnight.zip.zip",
             "browser_download_url": "https://x.test/base.zip"}]}]).encode()
        client = StubClient([make_fetch("cve_project", index),
                             make_fetch("cve_project", load_bytes("cve_baseline_nested.zip"))])
        result = CveProject().collect(client, CveSourceState(), "full")
        assert result.complete_snapshot is True and result.records
        # 589MB must not be held for the raw store — the release asset is immutable,
        # so the tag plus hash is what makes the run reproducible (migration 0009).
        assert result.fetches[-1].body is None
        assert result.fetches[-1].content_hash is not None


# ---------------------------------------------------------------------------
# NVD
# ---------------------------------------------------------------------------


class TestNvdWindows:
    def test_splits_a_long_gap_into_windows_nvd_accepts(self):
        """NVD rejects a lastMod span wider than 120 days."""
        start = datetime(2025, 1, 1, tzinfo=timezone.utc)
        end = start + timedelta(days=400)
        windows = _chunk(start, end)
        assert len(windows) == 4
        assert all((b - a).days <= 120 for a, b in windows)
        assert windows[0][0] == start and windows[-1][1] == end

    def test_short_gap_is_one_window(self):
        start = datetime(2026, 8, 20, tzinfo=timezone.utc)
        assert len(_chunk(start, start + timedelta(days=2))) == 1


class TestNvd:
    def page(self, records, total=None):
        return json.dumps({"resultsPerPage": len(records),
                           "totalResults": total if total is not None else len(records),
                           "vulnerabilities": records}).encode()

    def test_parses_records_into_nvd_columns_only(self):
        body = json.dumps(load_json("nvd_page.json")).encode()
        client = StubClient([make_fetch("nvd", body)])
        result = Nvd(api_key="k").collect(client, CveSourceState(), "full")
        assert result.error is None and result.records
        r = result.records[0]
        assert r.source == "nvd"
        assert r.nvd_published is not None
        # NVD must never write the CNA's columns.
        assert r.state is None and r.date_reserved is None and r.cna_cvss_score is None

    def test_full_mode_is_a_complete_snapshot(self):
        body = json.dumps(load_json("nvd_page.json")).encode()
        result = Nvd(api_key="k").collect(StubClient([make_fetch("nvd", body)]),
                                          CveSourceState(), "full")
        assert result.complete_snapshot is True

    def test_an_incomplete_sweep_is_an_error_not_a_smaller_corpus(self):
        """A truncated sweep looks exactly like a world with fewer CVEs in it."""
        recs = load_json("nvd_page.json")["vulnerabilities"]
        client = StubClient([make_fetch("nvd", self.page(recs, total=999_999)),
                             make_fetch("nvd", self.page([], total=999_999))])
        result = Nvd(api_key="k").collect(client, CveSourceState(), "full")
        assert "incomplete" in result.error

    def test_missing_api_key_is_visible_but_not_fatal(self):
        body = json.dumps(load_json("nvd_page.json")).encode()
        src = Nvd(api_key="")
        result = src.collect(StubClient([make_fetch("nvd", body)]), CveSourceState(), "full")
        assert result.error is None
        assert any("NVD_API_KEY" in c for c in result.covered)
        assert src.rate_per_minute < 10        # falls back to the unauthenticated rate

    def test_api_key_raises_the_rate(self):
        assert Nvd(api_key="k").rate_per_minute > 50

    def test_http_failure_is_reported(self):
        client = StubClient([make_fetch("nvd", None, ok=False, status=403, error="HTTP 403")])
        result = Nvd(api_key="k").collect(client, CveSourceState(), "full")
        assert result.records == [] and "403" in result.error


class TestNvdCursor:
    """The incremental cursor must never advance past a page that failed."""

    def page(self, records, total):
        return make_fetch("nvd", json.dumps({"resultsPerPage": len(records),
                                             "totalResults": total,
                                             "vulnerabilities": records}).encode())

    def failed(self):
        return make_fetch("nvd", None, ok=False, status=503, error="HTTP 503")

    def test_resumes_from_the_cursor_not_the_last_ok_fetch(self):
        # A failed run leaves ok fetches whose timestamps are AFTER the gap; the
        # recorded cursor is the end of the last window actually ingested.
        cursor = datetime(2026, 9, 1, tzinfo=timezone.utc)
        state = CveSourceState(last_success_at=datetime(2026, 9, 5, tzinfo=timezone.utc),
                               cursor=cursor.isoformat())
        client = StubClient([self.page([], 0)])
        Nvd(api_key="k").collect(client, state, "incremental")
        sent = client.calls[0]["params"]["lastModStartDate"]
        assert sent == (cursor - timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    def test_page_two_failing_does_not_advance_the_cursor(self):
        recs = load_json("nvd_page.json")["vulnerabilities"]
        state = CveSourceState(cursor=(datetime.now(timezone.utc)
                                       - timedelta(days=2)).isoformat())
        client = StubClient([self.page(recs, total=len(recs) + 5), self.failed()])
        result = Nvd(api_key="k").collect(client, state, "incremental")
        assert result.error and result.cursor is None
        assert result.records == []     # a half-read window is not persisted either

    def test_a_later_window_failing_keeps_the_earlier_windows_cursor(self):
        recs = load_json("nvd_page.json")["vulnerabilities"]
        start = datetime.now(timezone.utc) - timedelta(days=150)   # two windows
        state = CveSourceState(cursor=start.isoformat())
        client = StubClient([self.page(recs, total=len(recs)),               # window 1
                             self.page(recs, total=len(recs) + 5), self.failed()])  # window 2
        result = Nvd(api_key="k").collect(client, state, "incremental")
        assert result.error
        window_1_end = _chunk(start - timedelta(hours=6), datetime.now(timezone.utc))[0][1]
        assert datetime.fromisoformat(result.cursor) == window_1_end
        sent_2 = client.calls[1]["params"]["lastModStartDate"]
        assert sent_2 == window_1_end.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    def test_a_clean_incremental_advances_to_the_last_window_end(self):
        state = CveSourceState(cursor=(datetime.now(timezone.utc)
                                       - timedelta(days=1)).isoformat())
        before = datetime.now(timezone.utc)
        result = Nvd(api_key="k").collect(StubClient([self.page([], 0)]), state, "incremental")
        assert result.error is None and datetime.fromisoformat(result.cursor) >= before


class TestPublicationLagEval:
    """Each median can be absent independently — before NVD loads, every
    nvd_published is NULL and only the reservation lag exists."""

    class _Cur:
        def __init__(self, row): self.row = row
        def execute(self, *a, **k): pass
        def fetchone(self): return self.row
        def __enter__(self): return self
        def __exit__(self, *e): return False

    class _Conn:
        def __init__(self, row): self.row = row
        def cursor(self): return TestPublicationLagEval._Cur(self.row)

    def test_reports_only_the_reservation_lag_when_nvd_is_absent(self):
        from zdc_cve import evals
        r = evals.measure_publication_lag(self._Conn((61.0, None, 384020)))
        assert r.passed
        assert "reservation->publication 61d" in r.summary
        assert "NVD" not in r.summary

    def test_reports_both_when_available(self):
        from zdc_cve import evals
        r = evals.measure_publication_lag(self._Conn((61.0, 1.5, 384020)))
        assert "reservation->publication" in r.summary and "NVD 1.5d" in r.summary

    def test_says_so_when_neither_is_computable(self):
        from zdc_cve import evals
        r = evals.measure_publication_lag(self._Conn((None, None, 0)))
        assert "not enough dated records" in r.summary


class TestCveProjectGapRecovery:
    """The failure this class exists to prevent.

    One page of releases spans only ~3 days (measured 2026-08-28: 40 releases covered
    2026-08-25..28). If the pipeline is down longer than that, the cursor tag is not on
    the page. The original walk never matched it, consumed every delta it could see,
    and advanced the cursor to newest — silently discarding every CVE changed inside
    the gap. No error, no short count, nothing to notice.
    """

    BASE_INDEX = json.dumps([{"tag_name": "newest", "assets": [
        {"name": "2026-08-28_all_CVEs_at_midnight.zip.zip",
         "browser_download_url": "https://x.test/base.zip"}]}]).encode()

    def test_gap_escalates_to_baseline_instead_of_skipping(self):
        # Five pages of releases, none containing the cursor: a real gap.
        pages = [make_fetch("cve_project", releases(*[(f"p{p}t{i}", f"delta_{p}_{i}.zip")
                                                      for i in range(3)]))
                 for p in range(5)]
        client = StubClient(pages + [make_fetch("cve_project", self.BASE_INDEX),
                                     make_fetch("cve_project", load_bytes("cve_baseline_nested.zip"))])
        result = CveProject().collect(client, CveSourceState(cursor="long-gone-tag"), "incremental")

        assert result.error is None                      # self-healed, not failed
        assert result.complete_snapshot is True          # baseline, so nothing is missing
        assert result.records
        assert any("ESCALATED" in c for c in result.covered)
        assert any("gap exists" in c for c in result.covered)

    def test_it_paginates_before_giving_up(self):
        """A long weekend is recoverable from deltas; only a real gap needs the baseline."""
        page1 = releases(("newA", "delta_a.zip"), ("newB", "delta_b.zip"))
        page2 = releases(("newC", "delta_c.zip"), ("cursor-tag", "delta_old.zip"))
        client = StubClient([
            make_fetch("cve_project", page1),
            make_fetch("cve_project", page2),
        ] + [make_fetch("cve_project", load_bytes("cve_delta.zip")) for _ in range(3)])
        result = CveProject().collect(client, CveSourceState(cursor="cursor-tag"), "incremental")

        assert result.error is None
        assert result.complete_snapshot is False         # deltas were sufficient
        assert not any("ESCALATED" in c for c in result.covered)
        assert len(result.covered) == 3                  # newA, newB, newC — not the cursor itself

    def test_first_run_without_a_cursor_takes_the_baseline(self):
        """Otherwise an incremental first run yields a silently partial corpus."""
        client = StubClient([make_fetch("cve_project", self.BASE_INDEX),
                             make_fetch("cve_project", load_bytes("cve_baseline_nested.zip"))])
        result = CveProject().collect(client, CveSourceState(cursor=None), "incremental")
        assert result.complete_snapshot is True
        assert any("ESCALATED" in c and "no cursor" in c for c in result.covered)

    def test_escalation_is_visible_in_the_run_record(self):
        """It must be legible afterwards, not just correct in the moment."""
        client = StubClient([make_fetch("cve_project", self.BASE_INDEX),
                             make_fetch("cve_project", load_bytes("cve_baseline_nested.zip"))])
        result = CveProject().collect(client, CveSourceState(cursor=None), "incremental")
        # `covered` is persisted into raw.pipeline_runs.notes and the Actions summary.
        assert result.covered[0].startswith("ESCALATED")


class TestNvdDateFormat:
    """NVD 404s on an offset without a colon, with an empty body.

    strftime's %z renders '+0000'. Measured 2026-08-28 against the live API:
    '...000Z' -> 200, '...000+00:00' -> 200, '...000+0000' -> 404. The 404 carries no
    message, so it reads as "endpoint not found" rather than "bad parameter".
    """

    def test_renders_a_z_suffix_not_a_bare_offset(self):
        from zdc_cve.sources.nvd import _fmt
        got = _fmt(datetime(2026, 8, 27, 0, 0, 0, tzinfo=timezone.utc))
        assert got == "2026-08-27T00:00:00.000Z"
        assert "+0000" not in got

    def test_converts_to_utc_first(self):
        from zdc_cve.sources.nvd import _fmt
        berlin = timezone(timedelta(hours=2))
        assert _fmt(datetime(2026, 8, 27, 2, 0, 0, tzinfo=berlin)) == "2026-08-27T00:00:00.000Z"
