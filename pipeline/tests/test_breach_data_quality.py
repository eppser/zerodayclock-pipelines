"""0181 breach data quality: the adapter half (HIBP compilations, implausible event dates) and its parity with SQL.

Unit tests need nothing. The parity tests are gated on BREACH_TEST_DATABASE_URL (a database migrated through 0181):
breach_core.hibp_not_a_victim must agree with sources_reg.hibp_not_a_victim, and breach_core.is_person_name must
know every given name of zdc_breach.reality.GIVEN (the person-shape guard's list). Synthetic names only.
"""

from __future__ import annotations

import json
import os
from datetime import date

import pytest

from zdc_breach import reality as R
from zdc_breach import sources_reg as S

NOT_A_VICTIM = [
    {"Title": "June 2026 Stealer Logs", "IsStealerLog": True},
    {"Title": "Zzquorvex Malware Corpus", "IsMalware": True},
    {"Title": "Zzquorvex Spam List", "IsSpamList": True},
    {"Title": "Zzquorvex", "IsFabricated": True},
    {"Title": "Operation Endgame 4.0"},
    {"Title": "Anti Public Combo List"},
    {"Title": "Combolists Posted to Telegram"},
    {"Title": "Collection #1"},
    {"Title": "Zzquorvex Credential Stuffing List"},
    {"Title": "mail.ru Dump"},
    {"Title": "You've Been Scraped"},
    {"Title": "2,844 Separate Data Breaches"},
    {"Title": "Not Zzquorvex"},
    {"Title": "Misattributed Zzquorvex Data"},
    {"Title": "Exploit.In"},
    {"Title": "Naz.API"},
]
VICTIM = [
    {"Title": "Adobe", "Domain": "adobe.com", "IsVerified": True},
    {"Title": "AT&T", "Domain": ""},
    {"Title": "Leaked Reality", "Domain": "leakedreality.com"},
    {"Title": "Zzquorvex Operations Ltd"},              # 'operation' only at the start, as a word
    {"Title": "Zzdumpster Rentals"},                    # 'dump' only as a word
    {"Title": "Zzquorvex", "IsStealerLog": False, "IsMalware": False},
]


@pytest.mark.parametrize("r", NOT_A_VICTIM, ids=lambda r: r["Title"])
def test_hibp_not_a_victim(r):                          # mutant: hibp_not_a_victim always False
    assert S.hibp_not_a_victim(r)


@pytest.mark.parametrize("r", VICTIM, ids=lambda r: r["Title"])
def test_hibp_victim_kept(r):                           # mutant: hibp_not_a_victim always True
    assert not S.hibp_not_a_victim(r)


def test_parse_hibp_skips_compilations():               # mutant: parse_hibp no longer calls hibp_not_a_victim
    rows = [{"Name": "ZzA", "Title": "June 2026 Stealer Logs", "Domain": "", "AddedDate": "2026-06-15T19:30:15Z",
             "IsStealerLog": True, "PwnCount": 5},
            {"Name": "ZzB", "Title": "Operation Endgame 4.0", "Domain": "", "AddedDate": "2026-06-18T20:08:06Z",
             "IsMalware": True, "PwnCount": 5},
            {"Name": "ZzC", "Title": "Zzquorvex", "Domain": "zzquorvex.example", "AddedDate": "2026-06-18T20:08:06Z",
             "PwnCount": 5}]
    ds, bad = S.parse_hibp(rows)
    assert [d.organization for d in ds] == ["Zzquorvex"] and bad == 0


def test_ca_event_date_skips_a_future_typo():           # mutant: parse_ca takes the first listed date again
    body = ('Organization Name,Date(s) of Breach  (if known),Reported Date\n'
            'Zzquorvex Inc.,"11/20/2027, 12/14/2023",07/03/2024\n')
    (d,), _ = S.parse_ca(body)
    assert d.as_of == date(2024, 7, 3) and d.event_date == date(2023, 12, 14)


def test_de_event_date_after_the_notice_is_none():      # mutant: _event_d ignores as_of
    rows = [{"company_name": "Zzquorvex", "date_of_notice": "2024-07-03T00:00:00.000",
             "date_of_breach": "2027-11-20T00:00:00.000"},
            {"company_name": "Zzquorvex Two", "date_of_notice": "2024-07-03T00:00:00.000",
             "date_of_breach": "2024-01-02T00:00:00.000"}]
    ds, _ = S.parse_de(rows)
    assert [d.event_date for d in ds] == [None, date(2024, 1, 2)]


def test_de_placeholder_notice_is_skipped():            # the 1971 placeholder never becomes a first-public date
    ds, bad = S.parse_de([{"company_name": "Zzquorvex", "date_of_notice": "1971-01-01T00:00:00.000",
                           "date_of_breach": "1971-01-01T00:00:00.000"}])
    assert ds == [] and bad == 1


# ---- parity with the SQL rules (0181) ---------------------------------------------------------------------------
DSN = os.environ.get("BREACH_TEST_DATABASE_URL")
db = pytest.mark.skipif(not DSN, reason="BREACH_TEST_DATABASE_URL not set")


@db
def test_sql_hibp_rule_matches_python():
    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(DSN) as conn, conn.cursor() as cur:
        for r in NOT_A_VICTIM + VICTIM:
            cur.execute("select breach_core.hibp_not_a_victim(%s::jsonb)", (json.dumps(r),))
            assert cur.fetchone()[0] == S.hibp_not_a_victim(r), r["Title"]


@db
def test_sql_person_rule_knows_every_given_name():     # the SQL copy of reality.GIVEN cannot drift silently
    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(DSN) as conn, conn.cursor() as cur:
        cur.execute("""select g from unnest(%s::text[]) g
                        where not breach_core.is_person_name(initcap(g) || ' Zzquorvexson')""", (sorted(R.GIVEN),))
        assert [r[0] for r in cur.fetchall()] == []
        cur.execute("select breach_core.is_person_name('Zzquorvex Zzquorvexson')")
        assert cur.fetchone()[0] is False                # not a given name: not a person
