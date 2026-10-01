"""Tests for the MSRC vendor fix extraction, including ones that can fail."""
from __future__ import annotations

import pytest

from zdc_patch import parse

DOC = {
    "DocumentTracking": {"InitialReleaseDate": "2026-01-13T08:00:00",
                         "CurrentReleaseDate": "2026-08-23T14:43:58"},
    "Vulnerability": [
        {"CVE": "CVE-2026-0001",
         "ReleaseDate": "0001-01-01T00:00:00", "ReleaseDateSpecified": False,
         "Remediations": [
             {"Type": 2, "Date": "0001-01-01T00:00:00", "DateSpecified": False,
              "Description": {"Value": "5074109"},
              "URL": "https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB5074109"},
             {"Type": 3, "Description": {"Value": "workaround"}},
         ]},
        # A vulnerability with no vendor fix must not acquire a patch date from the document.
        {"CVE": "CVE-2026-0002",
         "Remediations": [{"Type": 3, "Description": {"Value": "mitigation only"}}]},
        {"CVE": "CVE-2026-0003", "Remediations": []},
        {"CVE": "not-a-cve", "Remediations": [{"Type": 2}]},
    ],
}


def test_reads_the_document_release_date_not_the_remediation_date():
    # MSRC sets DateSpecified false on every remediation and every ReleaseDate, measured on
    # the live API. The only usable date is the document's.
    assert parse.document_release_date(DOC) == "2026-01-13"


def test_unspecified_document_date_is_not_a_date():
    # CVRF writes 0001-01-01 for "unspecified". Treating it as a date would file the fix in
    # the year 1, and cve_detail takes min(patch_date), so one such row would poison the CVE.
    assert parse.document_release_date(
        {"DocumentTracking": {"InitialReleaseDate": "0001-01-01T00:00:00"}}) is None
    assert parse.document_release_date({"DocumentTracking": {}}) is None
    assert parse.document_release_date({}) is None


def test_only_vendor_fix_remediations_produce_a_patch_date():
    recs = {r.cve_id: r for r in parse.parse(DOC)}
    assert set(recs) == {"CVE-2026-0001"}
    assert recs["CVE-2026-0001"].patch_date == "2026-01-13"
    assert "KB5074109" in recs["CVE-2026-0001"].evidence_url


def test_a_mitigation_is_not_a_fix():
    # THE CHECK THAT CAN FAIL: drop the Type filter and CVE-2026-0002, which has only a
    # workaround, acquires a patch date it does not have.
    only_mitigation = {"DocumentTracking": DOC["DocumentTracking"],
                       "Vulnerability": [DOC["Vulnerability"][1]]}
    assert parse.parse(only_mitigation) == []


def test_malformed_identifiers_are_dropped():
    assert all(r.cve_id.startswith("CVE-") for r in parse.parse(DOC))


def test_a_document_with_no_release_date_yields_nothing():
    assert parse.parse({"DocumentTracking": {"InitialReleaseDate": "0001-01-01T00:00:00"},
                        "Vulnerability": DOC["Vulnerability"]}) == []


def test_one_record_per_cve_per_document():
    # A document lists the same fix against many product ids. Storing each would multiply the
    # corpus by product count for no extra information: they share one release date.
    many = {"DocumentTracking": DOC["DocumentTracking"],
            "Vulnerability": [{"CVE": "CVE-2026-0009",
                               "Remediations": [{"Type": 2, "ProductID": [str(i)]}
                                                for i in range(40)]}]}
    assert len(parse.parse(many)) == 1


@pytest.mark.parametrize("month,expected", [((2016, 1), "2016-Jan"), ((2026, 12), "2026-Dec")])
def test_month_ids_match_the_msrc_document_naming(month, expected):
    from datetime import date

    from zdc_patch import client

    assert client.months(month, date(month[0], month[1], 1)) == [expected]


BACKADDED = {
    # CVE-2022-41082 as MSRC actually publishes it: the September document, the CVE added to
    # it on 30 September, and the KB for the November update. Reading the document date here
    # gives 2022-09-13, seven weeks before the fix shipped and on the wrong side of the KEV
    # listing, which flips "exploited before a patch existed" from true to false.
    "DocumentTracking": {"InitialReleaseDate": "2022-09-13T08:00:00"},
    "Vulnerability": [
        {"CVE": "CVE-2022-41082",
         "RevisionHistory": [{"Number": "1.0", "Date": "2022-09-30T07:00:00"},
                             {"Number": "2.0", "Date": "2022-11-08T08:00:00"}],
         "Remediations": [{"Type": 2, "Description": {"Value": "5019758"},
                           "FixedBuild": "15.00.1497.044"}]},
        # A CVE that shipped with the document keeps its date.
        {"CVE": "CVE-2022-30000",
         "RevisionHistory": [{"Number": "1.0", "Date": "2022-09-13T08:00:00"}],
         "Remediations": [{"Type": 2, "Description": {"Value": "5017308"}}]},
    ],
}


def test_a_back_added_cve_gets_no_date_rather_than_a_wrong_one():
    got = {r.cve_id for r in parse.parse(BACKADDED)}
    assert got == {"CVE-2022-30000"}


def test_a_cve_that_shipped_with_the_document_keeps_its_date():
    recs = {r.cve_id: r for r in parse.parse(BACKADDED)}
    assert recs["CVE-2022-30000"].patch_date == "2022-09-13"


def test_the_tolerance_is_a_few_days_not_a_month():
    # THE CHECK THAT CAN FAIL: widen the tolerance to a month and ProxyNotShell comes back
    # with a date seven weeks before its fix existed.
    assert parse.BACKADD_TOLERANCE_DAYS <= 7


def test_first_documented_reads_the_earliest_revision():
    assert parse.first_documented(BACKADDED["Vulnerability"][0]) == "2022-09-30"
    assert parse.first_documented({"RevisionHistory": []}) is None
    assert parse.first_documented({"RevisionHistory": [{"Date": "0001-01-01T00:00:00"}]}) is None
