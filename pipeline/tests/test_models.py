from __future__ import annotations

from datetime import date, datetime, timezone

import pytest

from zdc_kev.models import (
    KevObservation,
    NormalisationError,
    classify_vuln_id,
    extract_cve,
    parse_date,
    parse_timestamp,
)


class TestParseDate:
    @pytest.mark.parametrize(
        "value,expected",
        [
            ("2026-08-26", date(2026, 8, 26)),                      # CISA
            ("2026-07-14T00:00:00Z", date(2026, 7, 14)),            # VulnCheck
            ("2026-02-05T00:00:00+00:00", date(2026, 2, 5)),        # CIRCL
            ("Jul 29, 2025, 11:29:31 PM", date(2025, 7, 29)),       # EUVD
            ("Mar 20, 2026, 12:00:00 AM", date(2026, 3, 20)),       # EUVD midnight
        ],
    )
    def test_parses_every_format_these_sources_emit(self, value, expected):
        assert parse_date(value) == expected

    @pytest.mark.parametrize("value", [None, "", "not a date", "13/45/2026", []])
    def test_returns_none_rather_than_guessing(self, value):
        # A wrong date silently corrupts every downstream statistic; a missing one
        # is visible. None is the safe failure.
        assert parse_date(value) is None

    def test_euvd_midnight_is_not_off_by_one(self):
        # "12:00:00 AM" is midnight, not noon. Getting this wrong shifts a whole
        # source's exploitation dates by a day.
        assert parse_date("Mar 20, 2026, 12:00:00 AM") == date(2026, 3, 20)


class TestParseTimestamp:
    def test_naive_input_is_assumed_utc(self):
        assert parse_timestamp("2026-08-26T17:00:09") == datetime(
            2026, 8, 26, 17, 0, 9, tzinfo=timezone.utc
        )

    def test_falls_back_to_date_only_input(self):
        assert parse_timestamp("Jul 29, 2025, 11:29:31 PM").date() == date(2025, 7, 29)


class TestExtractCve:
    def test_finds_cve_inside_euvd_newline_aliases(self):
        aliases = ("GHSA-vrfh-8v52-6452", "CVE-2025-31277")
        assert extract_cve(aliases) == "CVE-2025-31277"

    def test_uppercases_circl_lowercase_ids(self):
        assert extract_cve("cve-2024-9164") == "CVE-2024-9164"

    def test_returns_none_when_no_cve_exists(self):
        assert extract_cve("EUVD-2026-40307", ["GHSA-abcd-efgh-ijkl"]) is None


def test_classify_vuln_id():
    assert classify_vuln_id("CVE-2024-0001") == "cve"
    assert classify_vuln_id("EUVD-2026-40307") == "euvd"
    assert classify_vuln_id("GHSA-a-b-c") == "ghsa"
    assert classify_vuln_id("something-else") == "other"


class TestObservationValidation:
    def base(self, **overrides):
        kwargs = dict(
            source_id="cisa", upstream_source="cisa", source_entry_id="CVE-2024-0001",
            vuln_id="CVE-2024-0001", vuln_id_type="cve", raw={},
        )
        kwargs.update(overrides)
        return KevObservation(**kwargs)

    def test_valid_observation_constructs(self):
        assert self.base().cve_id is None

    @pytest.mark.parametrize(
        "overrides",
        [
            {"signal": "poc_available"},          # PoC is not exploitation
            {"vuln_id_type": "nonsense"},
            {"confidence": 1.5},
            {"confidence": -0.1},
            {"status_reason": "maybe"},
            {"cve_id": "CVE-BAD"},
            {"vuln_id": ""},
            {"source_entry_id": ""},
        ],
    )
    def test_rejects_invalid_records(self, overrides):
        with pytest.raises(NormalisationError):
            self.base(**overrides)

    def test_poc_signal_is_not_representable(self):
        # The type system enforces Iron Rule: exploit-code availability can never be
        # written into the exploitation signal, which is exactly what v1 got wrong.
        with pytest.raises(NormalisationError):
            self.base(signal="poc")


class TestContentHash:
    def test_is_stable_across_identical_records(self):
        assert self.obs().content_hash() == self.obs().content_hash()

    def test_ignores_raw_payload_churn(self):
        # Cosmetic upstream reformatting must not register as a change, or
        # last_changed_at becomes a run timestamp and stops meaning anything.
        a = self.obs(raw={"a": 1})
        b = self.obs(raw={"a": 1, "cosmetic": "reordered"})
        assert a.content_hash() == b.content_hash()

    def test_detects_a_real_field_change(self):
        a = self.obs(date_added=date(2026, 1, 1))
        b = self.obs(date_added=date(2026, 1, 2))
        assert a.content_hash() != b.content_hash()

    def obs(self, **overrides):
        kwargs = dict(
            source_id="cisa", upstream_source="cisa", source_entry_id="CVE-2024-0001",
            vuln_id="CVE-2024-0001", vuln_id_type="cve", cve_id="CVE-2024-0001",
            date_added=date(2026, 1, 1), raw={},
        )
        kwargs.update(overrides)
        return KevObservation(**kwargs)


class TestClassifyVulnIdEdgeCases:
    """A 'CVE-' prefix does not make something a CVE."""

    def test_unassigned_placeholder_is_not_a_cve(self):
        # Shadowserver-style placeholder (synthetic). Typing it 'cve' would pollute
        # CVE-keyed joins.
        assert classify_vuln_id("CVE-UNASSIGNED-2020-Example-Vendor-Command-Injection-01") == "other"

    def test_exploitdb_and_cnvd_are_other(self):
        assert classify_vuln_id("EDB-41471") == "other"
        assert classify_vuln_id("CNVD-2018-24942") == "other"

    def test_real_cve_still_classifies(self):
        assert classify_vuln_id("CVE-2022-40684") == "cve"
        assert classify_vuln_id("cve-2022-40684") == "cve"
