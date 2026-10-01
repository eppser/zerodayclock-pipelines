"""Adapter tests, run against fixtures shaped like the live APIs (2026-08-27).

The VulnCheck fixture is synthetic: same structure as the licensed feed, invented content.
"""

from __future__ import annotations

import json
from datetime import date

import pytest

from conftest import StubClient, make_fetch, requires_repo_files
from zdc_kev.sources.base import SourceState
from zdc_kev.sources.circl import CirclKev
from zdc_kev.sources.cisa import CisaKev
from zdc_kev.sources.euvd import EuvdKev
from zdc_kev.sources.vulncheck import VulnCheckKev


# ---------------------------------------------------------------------------
# CISA
# ---------------------------------------------------------------------------


class TestCisa:
    def collect(self, body, state=None):
        client = StubClient([make_fetch("cisa", body)])
        return CisaKev().collect(client, state or SourceState(), "incremental"), client

    def test_parses_catalogue(self, cisa_body):
        result, _ = self.collect(cisa_body)
        assert result.error is None
        assert result.observations
        assert result.complete_snapshot is True

        first = result.observations[0]
        assert first.source_id == "cisa"
        assert first.upstream_source == "cisa"
        assert first.cve_id.startswith("CVE-")
        assert first.signal == "successful_exploitation"
        assert first.date_added is not None

    def test_sends_conditional_headers_when_state_exists(self, cisa_body):
        state = SourceState(last_etag='"abc"', last_modified="Wed, 26 Aug 2026 17:00:09 GMT")
        _, client = self.collect(cisa_body, state)
        assert client.calls[0]["etag"] == '"abc"'
        assert client.calls[0]["last_modified"] == "Wed, 26 Aug 2026 17:00:09 GMT"

    def test_unchanged_content_hash_short_circuits(self, cisa_body):
        import hashlib

        state = SourceState(last_content_hash=hashlib.sha256(cisa_body).hexdigest())
        result, _ = self.collect(cisa_body, state)
        assert result.unchanged is True
        assert result.observations == []
        # Not a complete snapshot: there is nothing new to reconcile against, and
        # claiming otherwise would risk spurious withdrawals.
        assert result.complete_snapshot is False

    def test_304_is_treated_as_unchanged(self, cisa_body):
        fetch = make_fetch("cisa", b"", status=304, not_modified=True)
        result = CisaKev().collect(StubClient([fetch]), SourceState(), "incremental")
        assert result.unchanged is True
        assert result.error is None

    def test_http_failure_is_reported_not_swallowed(self):
        fetch = make_fetch("cisa", None, ok=False, status=403, error="HTTP 403: blocked")
        result = CisaKev().collect(StubClient([fetch]), SourceState(), "incremental")
        assert result.observations == []
        assert "403" in result.error          # a block must never look like "no data"
        assert result.complete_snapshot is False

    def test_envelope_count_mismatch_is_flagged(self, cisa_body):
        document = json.loads(cisa_body)
        document["count"] = 999                # claims more than the body carries
        result, _ = self.collect(json.dumps(document).encode())
        assert "count mismatch" in result.error

    def test_unparseable_body_is_reported(self):
        result = CisaKev().collect(
            StubClient([make_fetch("cisa", b"{not json")]), SourceState(), "incremental"
        )
        assert "unparseable" in result.error


# ---------------------------------------------------------------------------
# EUVD
# ---------------------------------------------------------------------------


class TestEuvd:
    def page(self, items, total):
        return json.dumps({"items": items, "total": total}).encode()

    def test_parses_and_resolves_cve_from_aliases(self, euvd_page):
        items = euvd_page["items"]
        client = StubClient([make_fetch("euvd", self.page(items, len(items)))])
        result = EuvdKev().collect(client, SourceState(), "incremental")

        assert result.error is None
        assert result.complete_snapshot is True
        assert len(result.observations) == len(items)

        cve_backed = [o for o in result.observations if o.cve_id]
        assert cve_backed, "fixture should contain at least one CVE-bearing entry"
        for obs in cve_backed:
            # Grouping id must be the CVE, or nothing joins across sources.
            assert obs.vuln_id == obs.cve_id
            assert obs.vuln_id_type == "cve"
            assert obs.source_entry_id.startswith("EUVD-")

    def test_keeps_exploited_since(self, euvd_page):
        items = euvd_page["items"]
        client = StubClient([make_fetch("euvd", self.page(items, len(items)))])
        result = EuvdKev().collect(client, SourceState(), "incremental")
        assert any(o.exploited_since is not None for o in result.observations)

    def test_entry_without_cve_falls_back_to_native_id(self):
        items = [{"id": "EUVD-2026-99999", "aliases": "GHSA-xxxx-yyyy-zzzz\n"}]
        client = StubClient([make_fetch("euvd", self.page(items, 1))])
        result = EuvdKev().collect(client, SourceState(), "incremental")
        obs = result.observations[0]
        assert obs.cve_id is None
        assert obs.vuln_id == "EUVD-2026-99999"
        assert obs.vuln_id_type == "euvd"

    def test_pages_until_total_reached(self):
        pages = [
            make_fetch("euvd", self.page([{"id": f"EUVD-2026-{i}"}], 3)) for i in range(3)
        ]
        client = StubClient(pages)
        result = EuvdKev().collect(client, SourceState(), "incremental")
        assert len(result.observations) == 3
        assert [c["params"]["page"] for c in client.calls] == [0, 1, 2]

    def test_short_pagination_is_an_error_not_a_short_catalogue(self):
        # The failure mode that matters: the source advertises 1,689 entries but
        # pagination dries up after one. Publishing 1 of 1,689 as if it were the whole
        # catalogue would look like a collapse in exploitation, not a broken fetch.
        client = StubClient(
            [
                make_fetch("euvd", self.page([{"id": "EUVD-2026-1"}], 1689)),
                make_fetch("euvd", self.page([], 1689)),
            ]
        )
        result = EuvdKev().collect(client, SourceState(), "incremental")
        assert result.complete_snapshot is False
        assert "incomplete pagination" in result.error
        assert "1689" in result.error

    def test_mid_pagination_failure_aborts_reconciliation(self):
        client = StubClient(
            [
                make_fetch("euvd", self.page([{"id": "EUVD-1"}], 3)),
                make_fetch("euvd", None, ok=False, status=500, error="HTTP 500"),
            ]
        )
        result = EuvdKev().collect(client, SourceState(), "incremental")
        assert result.complete_snapshot is False
        assert "500" in result.error


# ---------------------------------------------------------------------------
# CIRCL
# ---------------------------------------------------------------------------


class TestCircl:
    def collect(self, body, state=None):
        return CirclKev().collect(StubClient([make_fetch("circl", body)]), state or SourceState(), "incremental")

    def test_explodes_one_entry_per_evidence_source(self, circl_body):
        result = self.collect(circl_body)
        assert result.error is None
        upstreams = {o.upstream_source for o in result.observations}
        # The fixture deliberately spans several upstream feeds.
        assert {"cisa-kev", "kevintel", "enisa-cnw-kev"} <= upstreams

    def test_sensor_telemetry_is_dropped_not_ingested(self, circl_body):
        """A honeypot hit is not a catalogue listing, and Shadowserver publishes no KEV.

        CIRCL republishes Shadowserver telemetry in the same JSON shape as a real
        catalogue entry. Ingesting it set first_kev_date for 506 CVEs (243 of them too
        early, median 43 days) and counted a sensor as an independent observer for
        1,231. It belongs in obs_core, which already holds it.
        """
        result = self.collect(circl_body)
        assert result.error is None
        # The fixture's second line IS a Shadowserver honeypot entry — if this stops
        # being true the test goes vacuous, so assert the input as well as the output.
        assert any(
            ev.get("type") == "honeypot"
            for line in circl_body.decode().splitlines() if line.strip()
            for ev in json.loads(line).get("evidence", [])
        ), "fixture no longer contains a honeypot entry — this test is vacuous"
        assert not [o for o in result.observations if o.upstream_source == "shadowserver"]
        assert not [o for o in result.observations if o.evidence_type in ("honeypot", "sinkhole")]

    def test_reviewed_evidence_types_still_pass_through(self, circl_body):
        """The filter must drop telemetry only — not every entry that carries evidence."""
        result = self.collect(circl_body)
        kept = {o.evidence_type for o in result.observations if o.evidence_type}
        assert kept, "the filter removed every evidence-bearing entry"
        assert not (kept & {"honeypot", "sinkhole"})

    def test_upstream_is_never_collapsed_to_the_aggregator(self, circl_body):
        result = self.collect(circl_body)
        for obs in result.observations:
            assert obs.source_id == "circl"
            # Losing the upstream identity would make CIRCL's copy of CISA look like
            # independent corroboration and inflate every agreement statistic.
            if obs.upstream_source == "circl":
                continue
            assert obs.upstream_source != obs.source_id

    def test_entry_without_evidence_is_kept_not_dropped(self, circl_body):
        result = self.collect(circl_body)
        attributed_to_circl = [o for o in result.observations if o.upstream_source == "circl"]
        assert attributed_to_circl, "the zero-evidence fixture line must survive"
        assert attributed_to_circl[0].signal == "unspecified"

    def test_source_entry_ids_are_unique_and_stable(self, circl_body):
        result = self.collect(circl_body)
        ids = [o.identity for o in result.observations]
        assert len(ids) == len(set(ids))
        assert self.collect(circl_body).observations[0].identity == ids[0]

    def test_unknown_signal_degrades_to_unspecified(self):
        line = json.dumps(
            {
                "uuid": "u1",
                "vulnerability": {"vulnId": "CVE-2024-0001"},
                "status": {"exploited": True, "status_reason": "confirmed"},
                "timestamps": {},
                "evidence": [{"source": "newfeed", "signal": "something_new", "confidence": 0.9}],
            }
        ).encode()
        result = self.collect(line)
        # Never guess upward: over-stating a claim is the error that inflates headlines.
        assert result.observations[0].signal == "unspecified"

    def test_corrupt_line_is_counted_and_surfaced(self, circl_body):
        result = self.collect(circl_body + b"\n{broken json\n")
        assert result.observations
        assert "unparseable" in result.error

    def test_unchanged_dump_is_not_redownloaded_into_observations(self, circl_body):
        import hashlib

        state = SourceState(last_content_hash=hashlib.sha256(circl_body).hexdigest())
        result = self.collect(circl_body, state)
        assert result.unchanged and not result.observations


# ---------------------------------------------------------------------------
# VulnCheck
# ---------------------------------------------------------------------------


class TestVulnCheck:
    def source(self):
        return VulnCheckKev(token="test-token")

    def index_page(self, data, total_pages=1):
        return json.dumps({"data": data, "_meta": {"total_pages": total_pages}}).encode()

    def test_missing_credential_is_an_explicit_error(self):
        result = VulnCheckKev(token="").collect(StubClient([]), SourceState(), "incremental")
        assert "VULNCHECK_API_TOKEN" in result.error
        assert result.observations == []

    def test_parses_index_records(self, vulncheck_body):
        data = json.loads(vulncheck_body)["data"]
        state = SourceState(
            last_success_at=__import__("datetime").datetime(2026, 8, 20, tzinfo=__import__("datetime").timezone.utc),
            last_full_sync_at=__import__("datetime").datetime(2026, 8, 26, tzinfo=__import__("datetime").timezone.utc),
        )
        client = StubClient([make_fetch("vulncheck", self.index_page(data))])
        result = self.source().collect(client, state, "incremental", today=date(2026, 8, 27))
        assert result.error is None
        assert result.observations
        assert result.observations[0].source_id == "vulncheck"

    def test_multi_cve_record_becomes_one_observation_per_cve(self):
        record = {"cve": ["CVE-2024-0001", "CVE-2024-0002"], "date_added": "2026-01-01T00:00:00Z"}
        state = self._recent_state()
        client = StubClient([make_fetch("vulncheck", self.index_page([record]))])
        result = self.source().collect(client, state, "incremental", today=date(2026, 8, 27))
        assert {o.cve_id for o in result.observations} == {"CVE-2024-0001", "CVE-2024-0002"}
        assert len({o.identity for o in result.observations}) == 2

    def test_exploited_since_uses_earliest_report_not_catalogue_date(self):
        record = {
            "cve": ["CVE-2024-0003"],
            "date_added": "2026-07-14T00:00:00Z",
            "vulncheck_reported_exploitation": [
                {"url": "https://a.test/x", "date_added": "2026-07-14T00:00:00Z"},
                {"url": "https://b.test/y", "date_added": "2025-11-02T00:00:00Z"},
            ],
        }
        client = StubClient([make_fetch("vulncheck", self.index_page([record]))])
        result = self.source().collect(client, self._recent_state(), "incremental", today=date(2026, 8, 27))
        obs = result.observations[0]
        assert obs.date_added == date(2026, 7, 14)
        # The earliest third-party report is a tighter bound on when exploitation was
        # known than when VulnCheck got round to cataloguing it.
        assert obs.exploited_since == date(2025, 11, 2)

    def test_paging_cap_escalates_to_full_snapshot(self):
        """The silent-truncation trap: total_pages beyond the API's max_pages."""
        import io
        import zipfile

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("kev.json", json.dumps([{"cve": ["CVE-2024-0009"], "date_added": "2026-01-01T00:00:00Z"}]))

        client = StubClient(
            [make_fetch("vulncheck", self.index_page([], total_pages=99))]
            + [make_fetch("vulncheck", self.index_page([], total_pages=99)) for _ in range(5)]
            + [
                make_fetch("vulncheck", json.dumps({"data": [{"url": "https://signed.test/kev.zip"}]}).encode()),
                make_fetch("vulncheck", buffer.getvalue()),
            ]
        )
        result = self.source().collect(client, self._recent_state(), "incremental", today=date(2026, 8, 27))
        assert result.complete_snapshot is True
        assert [o.cve_id for o in result.observations] == ["CVE-2024-0009"]

    def test_full_mode_uses_backup_snapshot(self):
        import io
        import zipfile

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("kev.json", json.dumps({"data": [{"cve": ["CVE-2024-0005"], "date_added": "2026-01-01T00:00:00Z"}]}))

        client = StubClient(
            [
                make_fetch("vulncheck", json.dumps({"data": [{"url": "https://signed.test/kev.zip"}]}).encode()),
                make_fetch("vulncheck", buffer.getvalue()),
            ]
        )
        result = self.source().collect(client, SourceState(), "full", today=date(2026, 8, 27))
        assert result.complete_snapshot is True
        assert result.observations[0].cve_id == "CVE-2024-0005"
        # The multi-MB signed archive must not be retained as a raw payload under a
        # single-use URL that can never be re-fetched.
        assert result.fetches[-1].body is None

    def test_backup_pointer_without_url_is_an_error(self):
        client = StubClient([make_fetch("vulncheck", json.dumps({"data": []}).encode())])
        result = self.source().collect(client, SourceState(), "full", today=date(2026, 8, 27))
        assert "no download URL" in result.error

    @staticmethod
    def _recent_state():
        import datetime as dt

        return SourceState(
            last_success_at=dt.datetime(2026, 8, 26, tzinfo=dt.timezone.utc),
            last_full_sync_at=dt.datetime(2026, 8, 26, tzinfo=dt.timezone.utc),
        )


# ---------------------------------------------------------------------------
# Issuer vs. evidence — CIRCL is an aggregator AND a KEV issuer
# ---------------------------------------------------------------------------


class TestCirclOrigins:
    CIRCL_UUID = "1a89b78e-f703-45f3-bb86-59eb712668bd"

    def explode(self, entry):
        from zdc_kev.sources.circl import _explode

        return _explode(entry)

    def entry(self, origin, evidence, vuln="CVE-2024-0001"):
        return {
            "uuid": "u1",
            "vulnerability": {"vulnId": vuln},
            "status": {"exploited": True, "status_reason": "confirmed"},
            "gcve": {"origin_uuid": origin},
            "timestamps": {},
            "evidence": evidence,
        }

    def test_issuer_comes_from_origin_not_from_the_citation(self):
        """A CIRCL-authored entry citing Check Point is ONE observation, by CIRCL.

        Reading the issuer off the citation would invent 'checkpoint' as an
        independent observer and hide that CIRCL issues KEV entries of its own.
        """
        obs = self.explode(
            self.entry(self.CIRCL_UUID, [{"source": "Checkpoint", "signal": "successful_exploitation"}])
        )
        assert len(obs) == 1
        assert obs[0].upstream_source == "circl"
        assert obs[0].evidence_source == "Checkpoint"
        assert obs[0].origin_uuid == self.CIRCL_UUID

    def test_republished_feeds_keep_their_own_issuer(self):
        obs = self.explode(
            self.entry("c8fb6bf1-f81f-4cb8-95b1-eadbb3b54ee8", [{"source": "shadowserver"}])
        )
        assert obs[0].upstream_source == "shadowserver"

    def test_circl_authored_entry_without_evidence_is_attributed_to_circl(self):
        obs = self.explode(self.entry(self.CIRCL_UUID, []))
        assert len(obs) == 1
        assert obs[0].upstream_source == "circl"
        assert obs[0].evidence_source is None
        assert obs[0].signal == "unspecified"

    def test_gcve_only_vulnerability_is_kept(self):
        """Three CIRCL-issued entries appear in no other source, two with no CVE at all.
        Dropping non-CVE ids would silently lose them."""
        obs = self.explode(self.entry(self.CIRCL_UUID, [], vuln="GCVE-1-2026-0020"))
        assert obs[0].vuln_id == "GCVE-1-2026-0020"
        assert obs[0].vuln_id_type == "gcve"
        assert obs[0].cve_id is None

    def test_unknown_origin_falls_back_to_citation_without_losing_data(self):
        obs = self.explode(self.entry("00000000-0000-0000-0000-000000000000", [{"source": "NewFeed"}]))
        assert len(obs) == 1                      # nothing dropped
        assert obs[0].upstream_source == "newfeed"
        assert obs[0].evidence_source == "NewFeed"

    @requires_repo_files("supabase/migrations/0005_kev_origins_and_agreement.sql")
    def test_adapter_origin_map_matches_the_migration(self):
        """The adapter map and core.kev_origins must not drift apart.

        Asserted by parsing the migration, not by trusting a comment: a mismatch would
        silently mis-attribute observations to the wrong issuing authority.
        """
        import pathlib
        import re

        from zdc_kev.sources.circl import ORIGIN_ISSUERS

        sql = (
            pathlib.Path(__file__).parents[2]
            / "supabase/migrations/0005_kev_origins_and_agreement.sql"
        ).read_text()
        seeded = dict(
            re.findall(r"\('([0-9a-f-]{36})',\s*'([a-z-]+)',", sql)
        )
        assert seeded, "could not parse core.kev_origins seed from the migration"
        assert ORIGIN_ISSUERS == seeded
