"""Tests for the enrichment pipeline.

The EPSS parser is the only place in this pipeline where external text becomes
numbers, so it carries most of the tests. Each one is written so that removing the
logic it covers turns it red — a suite that would stay green with the check deleted is
worse than no suite (CLAUDE.md, "Tests are part of the contract").
"""

from __future__ import annotations

import gzip
from datetime import date
from decimal import Decimal

import pytest

from zdc_enrich import epss, evals
from zdc_enrich.models import EpssCollectResult, parse_epss, parse_header

HEADER = "#model_version:v2026.06.15,score_date:2026-08-30T12:03:42Z"
CSV_HEADER = "cve,epss,percentile"


def payload(*rows: str, header: str = HEADER) -> str:
    return "\n".join([header, CSV_HEADER, *rows])


# --------------------------------------------------------------------------
# Header parsing — provenance is mandatory, not best-effort
# --------------------------------------------------------------------------

def test_parse_header_extracts_model_and_date():
    model, score_date = parse_header(HEADER)
    assert model == "v2026.06.15"
    assert score_date == date(2026, 8, 30)


def test_parse_header_rejects_missing_provenance():
    """A score without its model version is not reproducible across EPSS generations.

    Defaulting here would quietly mix model generations into one percentile column,
    and nothing downstream could detect it.
    """
    with pytest.raises(ValueError, match="no model_version"):
        parse_header("cve,epss,percentile")


def test_parse_epss_rejects_headerless_payload():
    with pytest.raises(ValueError):
        parse_epss("cve,epss,percentile\nCVE-2024-0001,0.5,0.9")


# --------------------------------------------------------------------------
# Row parsing
# --------------------------------------------------------------------------

def test_parses_well_formed_rows():
    records, model, score_date, skipped = parse_epss(
        payload("CVE-1999-0001,0.03351,0.87825", "CVE-2024-12345,0.97,0.99987"))
    assert skipped == 0
    assert model == "v2026.06.15" and score_date == date(2026, 8, 30)
    assert [r.cve_id for r in records] == ["CVE-1999-0001", "CVE-2024-12345"]
    assert records[0].epss_score == Decimal("0.03351")
    assert records[0].epss_percentile == Decimal("0.87825")


@pytest.mark.parametrize("bad_row", [
    "NOT-A-CVE,0.5,0.5",            # malformed identifier
    "CVE-2024-0001,0.5",            # wrong column count
    "CVE-2024-0001,abc,0.5",        # non-numeric score
    "CVE-2024-0001,1.5,0.5",        # probability above 1
    "CVE-2024-0001,-0.1,0.5",       # probability below 0
    "CVE-2024-0001,0.5,2.0",        # percentile above 1
])
def test_bad_rows_are_counted_not_silently_dropped(bad_row):
    """A source that starts emitting garbage must show up as a rising skip count.

    Silently discarding them would look identical to the feed shrinking.
    """
    records, _, _, skipped = parse_epss(payload("CVE-2024-9999,0.1,0.2", bad_row))
    assert len(records) == 1
    assert skipped == 1


def test_duplicate_cve_is_counted_not_last_write_wins():
    records, _, _, skipped = parse_epss(
        payload("CVE-2024-0001,0.1,0.2", "CVE-2024-0001,0.9,0.9"))
    assert len(records) == 1
    assert records[0].epss_score == Decimal("0.1")
    assert skipped == 1


def test_blank_and_comment_lines_are_ignored_without_counting():
    records, _, _, skipped = parse_epss(
        payload("CVE-2024-0001,0.1,0.2", "", "# trailing note"))
    assert len(records) == 1
    assert skipped == 0


# --------------------------------------------------------------------------
# Decompression — the file is gzip, but a CDN may also apply Content-Encoding
# --------------------------------------------------------------------------

def test_decompress_handles_gzip_and_plain_bytes():
    text = payload("CVE-2024-0001,0.1,0.2")
    assert epss._decompress(gzip.compress(text.encode())) == text
    assert epss._decompress(text.encode()) == text


# --------------------------------------------------------------------------
# Collection guards
# --------------------------------------------------------------------------

class _FakeFetch:
    def __init__(self, *, ok=True, body=b"", status=200, error=None):
        self.ok, self.body, self.http_status, self.error = ok, body, status, error
        self.not_modified = False
        self.record_count = None


class _FakeClient:
    def __init__(self, fetch):
        self._fetch = fetch
        self.calls = 0

    def get(self, url, **kw):
        self.calls += 1
        return self._fetch


def test_skips_when_already_fetched_today():
    """EPSS scores once a day. A second fetch downloads 2.5 MB to learn nothing."""
    client = _FakeClient(_FakeFetch())
    result = epss.collect(client, last_fetch_date=date(2026, 8, 31),
                          today=date(2026, 8, 31))
    assert client.calls == 0
    assert result.skipped_reason is not None
    assert result.ok is True          # a deliberate skip is not a failure
    assert result.error is None       # ...and is not an error either


def test_force_overrides_the_daily_limit():
    body = gzip.compress(payload(*[f"CVE-2024-{i:05d},0.1,0.2"
                                   for i in range(200_000)]).encode())
    client = _FakeClient(_FakeFetch(body=body))
    result = epss.collect(client, last_fetch_date=date(2026, 8, 31),
                          today=date(2026, 8, 31), force=True)
    assert client.calls == 1
    assert len(result.records) == 200_000


def test_empty_body_with_http_200_is_an_error_not_absence():
    """v1 recorded a WAF block as 220 successful rows. A 200 with no body is a block."""
    client = _FakeClient(_FakeFetch(body=b""))
    result = epss.collect(client, last_fetch_date=None, today=date(2026, 8, 31))
    assert result.error is not None
    assert result.ok is False
    assert not result.records


def test_truncated_file_is_refused_rather_than_persisted():
    """Overwriting 366k good scores with 500 would look like a successful run."""
    body = gzip.compress(payload("CVE-2024-0001,0.1,0.2").encode())
    client = _FakeClient(_FakeFetch(body=body))
    result = epss.collect(client, last_fetch_date=None, today=date(2026, 8, 31))
    assert result.error is not None and "floor" in result.error
    assert not result.records


def test_failed_fetch_reports_the_reason():
    client = _FakeClient(_FakeFetch(ok=False, status=503, error="ReadTimeout"))
    result = epss.collect(client, last_fetch_date=None, today=date(2026, 8, 31))
    assert result.error == "ReadTimeout"
    assert result.ok is False


# --------------------------------------------------------------------------
# Evals on in-memory results
# --------------------------------------------------------------------------

def test_eval_flags_a_source_that_returned_nothing_without_a_reason():
    empty = EpssCollectResult()
    check = evals.check_epss_collected(empty)
    assert check.passed is False
    assert check.blocking is True


def test_eval_treats_a_deliberate_skip_as_informational():
    skipped = EpssCollectResult(skipped_reason="already fetched today (2026-08-31)")
    check = evals.check_epss_collected(skipped)
    assert check.passed is True
    assert check.blocking is False


def test_eval_warns_once_skipped_rows_pass_the_limit():
    noisy = EpssCollectResult(skipped_rows=500)
    assert evals.check_epss_rows_not_skipped(noisy, limit=100).passed is False
    quiet = EpssCollectResult(skipped_rows=3)
    assert evals.check_epss_rows_not_skipped(quiet, limit=100).passed is True
