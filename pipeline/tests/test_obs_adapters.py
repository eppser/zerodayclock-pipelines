"""Observation adapter tests, against fixtures shaped like the live APIs 2026-08-27.

The VulnCheck and Shadowserver fixtures are synthetic: same structure as the licensed
feeds, invented content and counts.
"""

from __future__ import annotations

import json
from datetime import date

import pytest

from conftest import StubClient, load_json, make_fetch
from zdc_obs.models import ExploitationObservation, NormalisationError
from zdc_obs.sources.base import ObsSourceState
from zdc_obs.sources.msrc import MsrcObservations, parse_status
from zdc_obs.sources.shadowserver import ShadowserverObservations
from zdc_obs.sources.vulncheck_canary import VulnCheckCanaries


# ---------------------------------------------------------------------------
# The model's own guarantees
# ---------------------------------------------------------------------------


class TestObservationModel:
    def base(self, **over):
        kw = dict(source_id="msrc", source_entry_id="e1",
                  observation_type="vendor_reports_exploitation",
                  vuln_id="CVE-2024-0001", vuln_id_type="cve",
                  asserted_at=date(2026, 1, 1), raw={})
        kw.update(over)
        return ExploitationObservation(**kw)

    def test_valid_observation(self):
        assert self.base().effective_date == date(2026, 1, 1)

    @pytest.mark.parametrize("over", [
        {"observation_type": "known_exploited"},   # a KEV listing is not an observation
        {"observation_type": "poc_available"},     # PoC is never an observation
        {"observation_type": "exploited"},
        {"vuln_id_type": "nope"},
        {"cve_id": "CVE-BAD"},
        {"observation_count": -1},
    ])
    def test_rejects_invalid(self, over):
        with pytest.raises(NormalisationError):
            self.base(**over)

    def test_an_undated_observation_is_rejected(self):
        # Undated rows inflate counts while contributing nothing to any timeline.
        with pytest.raises(NormalisationError):
            self.base(asserted_at=None, observed_at=None, first_observed_at=None)

    def test_observation_count_none_means_unknown_not_one(self):
        assert self.base().observation_count is None


# ---------------------------------------------------------------------------
# MSRC
# ---------------------------------------------------------------------------


class TestMsrcStatusParsing:
    def test_splits_the_three_fields(self):
        got = parse_status("Publicly Disclosed:No;Exploited:Yes;Latest Software Release:Exploitation Detected")
        assert got == {"Publicly Disclosed": "No", "Exploited": "Yes",
                       "Latest Software Release": "Exploitation Detected"}

    def test_handles_the_two_field_variant(self):
        assert parse_status("Publicly Disclosed:No;Exploited:No") == {
            "Publicly Disclosed": "No", "Exploited": "No"}

    def test_empty_input(self):
        assert parse_status("") == {}


class TestMsrc:
    def collect(self, mode="incremental"):
        updates = json.dumps(load_json("msrc_updates.json")).encode()
        cvrf = json.dumps(load_json("msrc_cvrf.json")).encode()
        # Distinct objects per response: the adapter clears fetch.body after parsing
        # (to keep 7MB documents out of memory), so a shared object would read empty
        # on its second use.
        client = StubClient([make_fetch("msrc", updates)] +
                            [make_fetch("msrc", cvrf) for _ in range(8)])
        return MsrcObservations().collect(client, ObsSourceState(), mode,
                                          today=date(2026, 8, 27)), client

    def test_only_exploited_yes_becomes_an_observation(self):
        """The fixture has 1 Exploited:Yes and 2 Exploited:No."""
        result, _ = self.collect()
        assert result.error is None
        cves = {o.cve_id for o in result.observations}
        assert cves == {"CVE-2026-68820"}

    def test_exploited_no_is_not_recorded_as_evidence_of_absence(self):
        result, _ = self.collect()
        assert all(o.observation_type == "vendor_reports_exploitation"
                   for o in result.observations)
        assert len(result.observations) < 3   # the two No rows produced nothing

    def test_forecast_is_captured_separately_from_the_observation(self):
        result, _ = self.collect()
        obs = result.observations[0]
        # The forecast is stored, but it is not what made this an observation.
        assert obs.vendor_forecast == "Exploitation Detected"
        assert obs.publicly_disclosed is False

    def test_revision_dates_are_kept(self):
        # "flagged at patch time" vs "flagged six months later" are different claims.
        result, _ = self.collect()
        assert result.observations[0].revision_dates

    def test_skips_documents_before_the_flag_existed(self):
        """Pre-2016 CVRF documents carry no Type-1 threats; fetching them is waste."""
        from zdc_obs.sources.msrc import _select_documents
        docs = [{"ID": "1999-Sep", "InitialReleaseDate": "1999-09-02T00:00:00"},
                {"ID": "2015-Jan", "InitialReleaseDate": "2015-01-13T00:00:00"},
                {"ID": "2016-Jan", "InitialReleaseDate": "2016-01-12T00:00:00"},
                {"ID": "2026-Aug", "InitialReleaseDate": "2026-08-11T00:00:00"}]
        assert _select_documents(docs, "full", date(2026, 8, 27)) == ["2016-Jan", "2026-Aug"]

    def test_incremental_only_fetches_recent_months(self):
        from zdc_obs.sources.msrc import _select_documents
        docs = [{"ID": "2016-Jan", "InitialReleaseDate": "2016-01-12T00:00:00"},
                {"ID": "2026-Jul", "InitialReleaseDate": "2026-07-14T00:00:00"},
                {"ID": "2026-Aug", "InitialReleaseDate": "2026-08-11T00:00:00"}]
        got = _select_documents(docs, "incremental", date(2026, 8, 27))
        assert "2016-Jan" not in got and "2026-Aug" in got

    def test_full_mode_is_a_complete_snapshot_only_when_clean(self):
        result, _ = self.collect(mode="full")
        assert result.complete_snapshot is True

    def test_one_bad_month_does_not_discard_the_others(self):
        # Full mode selects three documents from the fixture; fail the first.
        updates = json.dumps(load_json("msrc_updates.json")).encode()
        cvrf = json.dumps(load_json("msrc_cvrf.json")).encode()
        client = StubClient([make_fetch("msrc", updates),
                             make_fetch("msrc", None, ok=False, status=500, error="HTTP 500")]
                            + [make_fetch("msrc", cvrf) for _ in range(2)])
        result = MsrcObservations().collect(client, ObsSourceState(), "full",
                                            today=date(2026, 8, 27))
        assert result.observations           # kept what we could
        assert "1 of 3 CVRF documents failed" in result.error
        assert result.complete_snapshot is False

    def test_index_failure_is_reported(self):
        client = StubClient([make_fetch("msrc", None, ok=False, status=403, error="HTTP 403")])
        result = MsrcObservations().collect(client, ObsSourceState(), "incremental")
        assert result.observations == []
        assert "403" in result.error


# ---------------------------------------------------------------------------
# VulnCheck canaries
# ---------------------------------------------------------------------------


class TestVulnCheckCanaries:
    """The index API caps at 6 pages against a 26-page corpus, so a complete canary
    set can only come from the bulk snapshot. Both paths are exercised."""

    @staticmethod
    def _state():
        import datetime as dt
        return ObsSourceState(last_success_at=dt.datetime(2026, 8, 26, tzinfo=dt.timezone.utc))

    @staticmethod
    def _zip(records):
        import io, zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("kev.json", json.dumps(records))
        return buf.getvalue()

    def collect_index(self, payload=None):
        """Incremental path: reads the paged index."""
        body = json.dumps(payload or load_json("vulncheck_canary.json")).encode()
        client = StubClient([make_fetch("vulncheck_canary", body)])
        return VulnCheckCanaries(token="t").collect(client, self._state(), "incremental",
                                                    today=date(2026, 8, 27)), client

    def collect_full(self, records):
        """Full path: pointer fetch, then the presigned archive."""
        client = StubClient([
            make_fetch("vulncheck_canary",
                       json.dumps({"data": [{"url": "https://signed.test/kev.zip"}]}).encode()),
            make_fetch("vulncheck_canary", self._zip(records)),
        ])
        return VulnCheckCanaries(token="t").collect(client, ObsSourceState(), "full",
                                                    today=date(2026, 8, 27)), client

    def test_parses_canary_records_from_the_index(self):
        result, _ = self.collect_index()
        assert result.error is None
        assert result.observations
        assert all(o.observation_type == "attempt_observed" for o in result.observations)

    def test_only_canary_flagged_records_are_included(self):
        payload = {"_meta": {"total_pages": 1}, "data": [
            {"cve": ["CVE-2024-0001"], "date_added": "2026-01-01T00:00:00Z",
             "reported_exploited_by_vulncheck_canaries": True},
            {"cve": ["CVE-2024-0002"], "date_added": "2026-01-01T00:00:00Z"},
            {"cve": ["CVE-2024-0003"], "date_added": "2026-01-01T00:00:00Z",
             "reported_exploited_by_vulncheck_canaries": False},
        ]}
        result, _ = self.collect_index(payload)
        # A KEV listing without a canary hit is not an observed attempt.
        assert {o.cve_id for o in result.observations} == {"CVE-2024-0001"}

    def test_uses_earliest_report_date_not_catalogue_date(self):
        payload = {"_meta": {"total_pages": 1}, "data": [{
            "cve": ["CVE-2024-0004"], "date_added": "2026-07-14T00:00:00Z",
            "reported_exploited_by_vulncheck_canaries": True,
            "vulncheck_reported_exploitation": [
                {"url": "https://a.test", "date_added": "2026-07-14T00:00:00Z"},
                {"url": "https://b.test", "date_added": "2025-11-02T00:00:00Z"}]}]}
        result, _ = self.collect_index(payload)
        assert result.observations[0].observed_at == date(2025, 11, 2)

    def test_count_is_unknown_not_invented(self):
        result, _ = self.collect_index()
        assert all(o.observation_count is None for o in result.observations)

    def test_missing_token_is_explicit(self):
        result = VulnCheckCanaries(token="").collect(StubClient([]), ObsSourceState(), "full")
        assert "VULNCHECK_API_TOKEN" in result.error

    def test_full_mode_uses_the_bulk_snapshot(self):
        result, client = self.collect_full([
            {"cve": ["CVE-2024-0005"], "date_added": "2026-01-01T00:00:00Z",
             "reported_exploited_by_vulncheck_canaries": True},
            {"cve": ["CVE-2024-0006"], "date_added": "2026-01-01T00:00:00Z"},
        ])
        assert result.complete_snapshot is True
        assert [o.cve_id for o in result.observations] == ["CVE-2024-0005"]
        # The presigned URL must not carry our bearer token: S3 returns 400 for two
        # auth mechanisms on one request.
        assert client.calls[1]["no_auth"] is True
        assert result.fetches[-1].body is None      # archive kept out of the raw store

    def test_index_page_cap_escalates_to_the_snapshot(self):
        """A delta wider than 6 pages would silently lose records past the cap."""
        import io, zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("kev.json", json.dumps(
                [{"cve": ["CVE-2024-0007"], "date_added": "2026-01-01T00:00:00Z",
                  "reported_exploited_by_vulncheck_canaries": True}]))
        wide = json.dumps({"_meta": {"total_pages": 26}, "data": []}).encode()
        client = StubClient(
            [make_fetch("vulncheck_canary", wide) for _ in range(6)]
            + [make_fetch("vulncheck_canary",
                          json.dumps({"data": [{"url": "https://signed.test/kev.zip"}]}).encode()),
               make_fetch("vulncheck_canary", buf.getvalue())])
        result = VulnCheckCanaries(token="t").collect(client, self._state(), "incremental",
                                                      today=date(2026, 8, 27))
        assert result.complete_snapshot is True
        assert [o.cve_id for o in result.observations] == ["CVE-2024-0007"]

    def test_backup_pointer_without_url_is_an_error(self):
        client = StubClient([make_fetch("vulncheck_canary", json.dumps({"data": []}).encode())])
        result = VulnCheckCanaries(token="t").collect(client, ObsSourceState(), "full")
        assert "no download URL" in result.error


# ---------------------------------------------------------------------------
# Shadowserver — registered but not enabled
# ---------------------------------------------------------------------------


class TestShadowserver:
    """Public dashboard endpoint. Synthetic fixtures in the shape captured live 2026-08-27."""

    def collect(self, mode="incremental", conn_fx="shadowserver_connections.json",
                uip_fx="shadowserver_unique_ips.json"):
        import json as _json
        client = StubClient([
            make_fetch("shadowserver", _json.dumps(load_json(conn_fx)).encode()),
            make_fetch("shadowserver", _json.dumps(load_json(uip_fx)).encode()),
        ])
        return ShadowserverObservations().collect(client, ObsSourceState(), mode,
                                                  today=date(2026, 8, 27)), client

    def test_produces_one_observation_per_vulnerability_per_day(self):
        result, _ = self.collect()
        assert result.error is None
        assert all(o.observation_type == "attempt_observed" for o in result.observations)
        # a daily time series, not a single "first seen" row
        ids = [o.source_entry_id for o in result.observations]
        assert len(ids) == len(set(ids))
        assert any(o.source_entry_id.startswith("CVE-2022-40684@") for o in result.observations)

    def test_carries_attempt_volume(self):
        """The whole point: no catalogue publishes counts."""
        result, _ = self.collect()
        counted = [o for o in result.observations if o.observation_count]
        assert counted
        assert all(o.observation_count > 0 for o in counted)

    def test_keeps_unique_ips_alongside_connections(self):
        result, _ = self.collect()
        o = next(o for o in result.observations if o.cve_id == "CVE-2023-20198")
        assert o.raw["connections"] is not None
        assert o.raw["unique_ips"] is not None

    def test_non_cve_identifiers_survive(self):
        """EDB/CNVD entries are the only exploitation no KEV catalogue can list."""
        result, _ = self.collect()
        ids = {o.vuln_id for o in result.observations}
        assert "CNVD-2018-24942" in ids
        assert "EDB-41471" in ids
        for o in result.observations:
            if o.vuln_id.startswith(("EDB-", "CNVD-")):
                assert o.vuln_id_type == "other"
                assert o.cve_id is None

    def test_cve_unassigned_placeholder_is_not_typed_as_a_cve(self):
        result, _ = self.collect()
        o = next(o for o in result.observations if o.vuln_id.startswith("CVE-UNASSIGNED"))
        assert o.vuln_id_type == "other"
        assert o.cve_id is None

    def test_sends_the_xhr_headers_the_dashboard_requires(self):
        # Without these the endpoint serves HTML instead of JSON.
        h = ShadowserverObservations().headers()
        assert h["X-Requested-With"] == "XMLHttpRequest"
        assert "json" in h["Accept"]

    def test_requests_json_and_groups_by_vulnerability(self):
        _, client = self.collect()
        p = client.calls[0]["params"]
        assert p["json"] == 1 and p["group_by"] == "vulnerability"
        assert [c["params"]["dataset"] for c in client.calls] == ["connections", "unique_ips"]

    def test_full_mode_requests_a_year_and_is_a_complete_snapshot(self):
        result, client = self.collect(mode="full")
        assert client.calls[0]["params"]["date_range"] == 365
        assert result.complete_snapshot is True

    def test_incremental_requests_a_short_window(self):
        _, client = self.collect(mode="incremental")
        assert client.calls[0]["params"]["date_range"] == 7

    def test_validation_error_body_is_not_mistaken_for_data(self):
        """The endpoint answers 200 with an errors object rather than a 4xx."""
        import json as _json
        client = StubClient([make_fetch("shadowserver",
                    _json.dumps({"errors": {"dataset": ["This field is required."]}}).encode())])
        result = ShadowserverObservations().collect(client, ObsSourceState(), "incremental")
        assert result.observations == []
        assert "rejected" in result.error

    def test_truncation_at_the_limit_is_an_error(self):
        """A full result set would understate the uncatalogued long tail."""
        import json as _json
        from zdc_obs.sources.shadowserver import LIMIT
        cols = [["x", "2026-08-27"]] + [[f"CVE-2020-{i:05d}", 1] for i in range(LIMIT)]
        body = _json.dumps({"data": {"columns": cols}}).encode()
        client = StubClient([make_fetch("shadowserver", body)])
        result = ShadowserverObservations().collect(client, ObsSourceState(), "incremental")
        assert "truncated" in result.error

    def test_http_failure_is_reported(self):
        client = StubClient([make_fetch("shadowserver", None, ok=False, status=403,
                                        error="HTTP 403: blocked")])
        result = ShadowserverObservations().collect(client, ObsSourceState(), "incremental")
        assert result.observations == []
        assert "403" in result.error


class TestForecastEval:
    """Microsoft rates exploitability per software release, so Exploited:Yes does NOT
    imply a 'Detected' forecast on the latest build. The check must test provenance."""

    def obs(self, statuses, forecast):
        return ExploitationObservation(
            source_id="msrc", source_entry_id="e", observation_type="vendor_reports_exploitation",
            vuln_id="CVE-2016-0167", vuln_id_type="cve", asserted_at=date(2016, 4, 12),
            vendor_forecast=forecast, raw={"statuses": statuses})

    def test_real_world_case_passes(self):
        """CVE-2016-0167: exploited in the wild, but 'More Likely' on the latest build."""
        from zdc_obs import evals
        o = self.obs([{"Exploited": "Yes", "Latest Software Release": "Exploitation More Likely",
                       "Older Software Release": "Exploitation Detected"}],
                     "Exploitation More Likely")
        assert evals.check_forecast_not_used_as_evidence([o]).passed

    def test_FAILS_when_no_exploited_flag_backs_the_row(self):
        from zdc_obs import evals
        o = self.obs([{"Exploited": "No", "Latest Software Release": "Exploitation More Likely"}],
                     "Exploitation More Likely")
        result = evals.check_forecast_not_used_as_evidence([o])
        assert not result.passed and result.blocking

    def test_attempt_observations_are_out_of_scope(self):
        from zdc_obs import evals
        o = ExploitationObservation(
            source_id="vulncheck_canary", source_entry_id="e", observation_type="attempt_observed",
            vuln_id="CVE-2024-0001", vuln_id_type="cve", observed_at=date(2026, 1, 1), raw={})
        assert evals.check_forecast_not_used_as_evidence([o]).passed


class TestShadowserverDailyLimit:
    """We told Shadowserver we would fetch once a day. The pipeline runs twice, so the
    limit is enforced in the adapter — it holds however the pipeline is invoked."""

    def test_second_run_on_the_same_day_is_skipped(self):
        import datetime as dt
        state = ObsSourceState(last_success_at=dt.datetime(2026, 8, 28, 6, 30, tzinfo=dt.timezone.utc))
        # Empty stub: any HTTP call would raise "StubClient exhausted".
        result = ShadowserverObservations().collect(StubClient([]), state, "incremental",
                                                    today=date(2026, 8, 28))
        assert result.unchanged is True
        assert result.observations == []
        assert result.error is None          # skipping is not a failure

    def test_next_day_runs_again(self):
        import datetime as dt, json as _json
        state = ObsSourceState(last_success_at=dt.datetime(2026, 8, 27, 6, 30, tzinfo=dt.timezone.utc))
        client = StubClient([
            make_fetch("shadowserver", _json.dumps(load_json("shadowserver_connections.json")).encode()),
            make_fetch("shadowserver", _json.dumps(load_json("shadowserver_unique_ips.json")).encode()),
        ])
        result = ShadowserverObservations().collect(client, state, "incremental",
                                                    today=date(2026, 8, 28))
        assert result.unchanged is False
        assert result.observations

    def test_full_backfill_is_never_skipped(self):
        import datetime as dt, json as _json
        state = ObsSourceState(last_success_at=dt.datetime(2026, 8, 28, 6, 30, tzinfo=dt.timezone.utc))
        client = StubClient([
            make_fetch("shadowserver", _json.dumps(load_json("shadowserver_connections.json")).encode()),
            make_fetch("shadowserver", _json.dumps(load_json("shadowserver_unique_ips.json")).encode()),
        ])
        result = ShadowserverObservations().collect(client, state, "full", today=date(2026, 8, 28))
        assert result.unchanged is False
        assert result.complete_snapshot is True
