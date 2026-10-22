"""Press fixes, 2026-10-21: (1) data types from an ACTIVE extractor field reach the list without a reconcile run;
(2) follow-up articles are attach-only and coarse breach years match the breach they name (dates audit fixes
1, 2 and 4). Unit tests run anywhere; the database tests need BREACH_TEST_DATABASE_URL (the migrated schema)."""

from __future__ import annotations

import os
from argparse import Namespace
from datetime import date, datetime, timezone

import pytest

from zdc_breach import doc_kind, extract, press_repair, resolve

OUT = {"is_incident_report": True}

# The ten rows the dates audit (2026-10-21) found wrong in its 40-row sample, by title.
AUDIT_WRONG_TITLES = [
    "Asheville Eye Associates Settles Lawsuit Stemming from DragonForce Ransomware Attack",
    "Physicians Primary Care of Southwest Florida Agrees to Data Breach Settlement",
    "American Vision Partners Settles Data Breach Litigation for $1.75M",
    "Bradford Health Services; Bradford Health Partners Settle Data Breach Lawsuit",
    "Georgia hospital notifies 160,000+ people of year-old data breach that leaked SSNs, credit cards, and medical records",
    "Gandara Mental Health Center Settles Class Action Data Breach Lawsuit",
    "Coastal Orthopedics Agrees to Pay $1.4 Million to Settle Data Breach Litigation",
    "OrthopedicsNY Settles Class Action Data Breach Lawsuit for $1.45M",
    "Dakota Eye Institute Settles Class Action Data Breach Lawsuit for $1 Million",
    "OCR Phishing Investigation Uncovers HIPAA Training Failure; Children’s Hospital Colorado Fined $548,265",
]
# First reports, among them the sample's correct rows and organisations a loose vocabulary would catch.
FIRST_REPORTS = [
    "UMMC Shuts Clinics While it Grapples with Ransomware Attack",
    "Qantas cuts executive bonuses by 15% after a July data breach",
    "Cumberland County Hospital Data Breach Affects Almost 37,000 Individuals",
    "Harrods alerts customers to new data breach linked to third-party provider",
    "Telecom SaaS firm Communications Data Group notifies 42K people of data breach on behalf of Duo Broadband",
    "Premier Health Partners Announces July 2023 Data Breach",          # a late FIRST notice is not a follow-up
    "Los Angeles Superior Court hit by ransomware attack",             # a court can be the victim
    "State prison system confirms cyberattack on inmate records",       # so can a prison
    "Ransomware gang claims it breached Canada’s Park’N Fly airport shuttle service, 1 million records compromised",
    "Auction house Sotheby’s disclosed a July data breach",
    "Judge.me app exposes merchant data",                                # "judge" alone is not a ruling
]


# ---- (1) document kind ----------------------------------------------------------------------------------
@pytest.mark.parametrize("title", AUDIT_WRONG_TITLES)
def test_every_wrong_row_of_the_audit_sample_is_a_follow_up(title):
    assert doc_kind.classify(title, OUT).follow_up, title


@pytest.mark.parametrize("title", FIRST_REPORTS)
def test_first_reports_are_not_follow_ups(title):
    assert doc_kind.classify(title, OUT).kind == "incident_report", title


@pytest.mark.parametrize("title,reason", [
    ("Capital One hacker Paige Thompson got too light a sentence, appeals court rules", "criminal"),
    ("Court reimposes original sentence for Capital One hacker", "litigation"),
    ("British teen arrested over cyberattack on London transportation agency", "criminal"),
    ("Five years after the breach, Equifax looks back", "retrospective"),
    ("Acme re-notifies patients after review finds more victims", "renotice"),
    ("OCR Resolves Guam Hospital HIPAA Investigation with a $25,000 Settlement", "penalty"),
])
def test_follow_up_reasons(title, reason):
    k = doc_kind.classify(title, OUT)
    assert k.follow_up and k.reason == reason, (title, k)


def test_a_document_that_is_not_an_incident_report_is_neither():
    assert doc_kind.classify("Acme settles lawsuit", {"is_incident_report": False}).kind == "not_incident"
    assert doc_kind.classify("Acme settles lawsuit", None).kind == "not_incident"


# ---- (2) coarse breach dates ------------------------------------------------------------------------------
CAPITAL_ONE_DOC = (
    "A federal judge has reimposed a sentence on Paige Thompson, the former Amazon Web Services engineer convicted "
    "in the 2019 Capital One data breach that compromised the personal information of more than 100 million people. "
    "The resentencing follows a Ninth Circuit Court of Appeals decision that vacated Thompson's original 2022 "
    "sentence after prosecutors appealed.")


@pytest.mark.parametrize("sentence,want", [
    ("convicted in the 2019 Capital One data breach that compromised", {(2019, None)}),
    ("Acme said a June 2024 attack exposed records.", {(2024, 6)}),
    ("Acme disclosed the breach in December 2023.", {(2023, 12)}),
    ("Acme was hit by a ransomware attack in May 2021.", {(2021, 5)}),
    ("vacated Thompson's original 2022 sentence", set()),
    ("Acme reported 2019 revenue of $5 billion after a breach.", set()),
    ("The 2024 Data Breach Investigations Report names Acme.", set()),
    ("On June 2, 2025, Acme notified 2,375 people of a breach.", set()),
])
def test_a_year_dates_a_breach_only_next_to_a_breach_noun(sentence, want):
    assert extract.coarse_mentions(sentence) == want


def test_validate_files_the_grounded_year_and_not_the_sentence_year():
    out = {"is_incident_report": True, "incidents": [{"organization": "Capital One", "source_of_account": "news",
                                                       "facts": []}]}
    [ei] = extract.validate(out, CAPITAL_ONE_DOC)
    got = {(c.field, c.value, c.accepted) for c in ei.candidates}
    assert got == {("event_year", "2019", True)}, got


def test_a_model_year_is_a_coarse_date_judged_on_its_quote():
    doc = "Acme Corp said a June 2024 attack exposed records. Acme Corp opened in 2019 in Ohio."
    out = {"is_incident_report": True, "incidents": [{"organization": "Acme Corp", "source_of_account": "news", "facts": [
        {"field": "event_date", "value": "2024-06", "unit": "none", "qualifier": "exact",
         "quote": "Acme Corp said a June 2024 attack exposed records."},
        {"field": "event_date", "value": "2019", "unit": "none", "qualifier": "exact",
         "quote": "Acme Corp opened in 2019 in Ohio."}]}]}
    [ei] = extract.validate(out, doc)
    by = {(c.field, c.value): (c.accepted, c.reject_reason) for c in ei.candidates}
    assert by[("event_month", "2024-06")] == (True, None)
    assert by[("event_year", "2019")] == (False, "year_not_next_to_breach_noun")
    # the deterministic reading adds nothing the model already gave
    assert sum(1 for c in ei.candidates if c.field == "event_month") == 1


def test_coarse_window_reaches_across_new_year_only():
    y2019 = [(2019, None)]
    assert resolve.in_coarse(date(2018, 12, 15), y2019) and resolve.in_coarse(date(2020, 1, 20), y2019)
    assert not resolve.in_coarse(date(2018, 11, 30), y2019) and not resolve.in_coarse(date(2020, 2, 1), y2019)
    dec = [(2023, 12)]
    assert resolve.in_coarse(date(2024, 1, 15), dec) and resolve.in_coarse(date(2023, 11, 2), dec)
    assert not resolve.in_coarse(date(2024, 2, 1), dec) and not resolve.in_coarse(date(2023, 10, 31), dec)
    # an incident known only by its filing date: filed within the filing lag after the breach year
    assert resolve.matches_coarse(None, date(2020, 6, 30), y2019)
    assert not resolve.matches_coarse(date(2021, 1, 5), date(2020, 6, 30), y2019)   # its own event date decides


# ---- (4) the repair plan, pure ------------------------------------------------------------------------------
def _other(iid, fpd, ev=None, structured=True, dup_of=None, listed=True, name="Capital One"):
    return {"incident_id": iid, "name": name, "fpd": fpd, "ev": ev, "structured": structured, "dup_of": dup_of,
            "listed": listed}


CAP_OTHERS = [_other("i2017", "2017-02-06"), _other("i2017b", "2018-08-09", "2017-01-27"),
              _other("i2019", "2019-08-08", "2019-03-22"), _other("i2023", "2023-05-26", "2023-02-01")]


def _row(vid, title, text, fpd, others, ev=None, name="Capital One"):
    return {"victim_id": "incident:" + vid, "incident_id": vid, "org_id": "o", "name": name, "norm_name": name.lower(),
            "fpd": fpd, "ev": ev, "dup_of": None, "docs": [{"sha": "s", "title": title, "pub": fpd, "text": text}],
            "others": others}


def test_repair_puts_the_resentencing_behind_the_2019_breach_and_holds_the_undated_ruling():
    resent = press_repair.decide(_row("c5", "Court reimposes original sentence for Capital One hacker",
                                      CAPITAL_ONE_DOC, "2025-11-05", CAP_OTHERS))
    assert (resent["action"], resent["target"], resent["how"]) == ("possible_duplicate_of", "i2019", "coarse_year")
    ruling = press_repair.decide(_row("53", "Capital One hacker Paige Thompson got too light a sentence, appeals court rules",
                                      "Two of three judges said the sentence was too light.", "2025-03-19", CAP_OTHERS))
    assert (ruling["action"], ruling["how"]) == ("review", "no_older_incident_named")


def test_repair_keeps_a_late_first_notice_and_a_new_breach_of_an_old_victim():
    late = press_repair.decide(_row("p1", "Premier Health Partners Announces July 2023 Data Breach",
                                    "Premier Health Partners said the July 2023 breach exposed patient data.",
                                    "2025-07-20", [], name="Premier Health Partners"))
    assert "old_year" in late["flags"] and late["action"] == "keep"
    new = press_repair.decide(_row("h1", "Hasbro hit by cyberattack, investigates possible data breach",
                                   "Hasbro said it detected unauthorized access.", "2026-04-02",
                                   [_other("h2017", "2018-06-25", "2017-09-15", name="Hasbro")], name="Hasbro"))
    assert new["flags"] == ["older_same_org"] and new["action"] == "keep"


def test_repair_follow_up_with_one_older_incident_goes_behind_it():
    e = press_repair.decide(_row("z1", "Zeta Clinic Settles Data Breach Lawsuit", "Zeta Clinic agreed to pay.",
                                 "2026-01-10", [_other("z0", "2024-03-01", name="Zeta Clinic")], name="Zeta Clinic"))
    assert (e["action"], e["target"], e["how"]) == ("possible_duplicate_of", "z0", "only_older_incident")


# ---- database ---------------------------------------------------------------------------------------------
DSN = os.environ.get("BREACH_TEST_DATABASE_URL")
db = pytest.mark.skipif(not DSN, reason="BREACH_TEST_DATABASE_URL not set")
EXT = "agent:test-press@0000000000000000"


@pytest.fixture()
def conn():
    psycopg = pytest.importorskip("psycopg")
    c = psycopg.connect(DSN, autocommit=False)
    with c.cursor() as cur:
        cur.execute("""truncate breach_core.press_review, breach_core.claims, breach_core.incident_cves, breach_core.incident_facts,
                       breach_core.cve_links, breach_core.source_pii_hashes,
                       breach_core.incident_sources, breach_core.match_overrides, breach_core.takedown_requests,
                       breach_core.leak_claims, breach_core.extractions, breach_core.llm_calls,
                       breach_core.incidents, breach_core.organizations, breach_core.source_state,
                       breach_raw.documents, breach_raw.source_records, breach_raw.fetches cascade""")
        cur.execute("delete from breach_core.extractor_versions where kind = 'llm'")
        cur.execute("""insert into breach_core.extractor_versions (extractor_id, kind, model_id, prompt_hash, gold, active, active_fields)
                       values (%s, 'llm', 'm', 'h', '{}', true, '{people_affected,event_date,data_types}')""", (EXT,))
    c.commit()
    yield c
    c.rollback()
    c.close()


def _ctx(conn):
    from zdc_breach import run as brun
    return brun.Ctx(conn, None, Namespace(max_docs=0))


def _doc(cur, sha, title, text, published="2025-11-05"):
    cur.execute("""insert into breach_raw.documents (doc_sha256, source_id, url, title, published_at, text)
                   values (%s, 'news_cyberscoop', %s, %s, %s, %s)""", (sha, "https://example.org/" + sha[:8], title, published, text))


def _file(conn, cur, sha, title, text, output, published):
    from zdc_breach import run as brun
    _doc(cur, sha, title, text, published)
    brun.file_output(_ctx(conn), cur, sha, text, output, EXT,
                     published=datetime.fromisoformat(published).replace(tzinfo=timezone.utc), source_id="news_cyberscoop")


def _capital_one(cur):
    """The live shape: four regulator incidents of Capital One, the 2019 one with its event date."""
    org, _ = resolve.find_or_create_org(cur, name="Capital One", country="US")
    ids = {}
    for key, ev, pub in (("2017", None, date(2017, 2, 6)), ("2017b", date(2017, 1, 27), date(2018, 8, 9)),
                         ("2019", date(2019, 3, 22), date(2019, 8, 8)), ("2023", date(2023, 2, 1), date(2023, 5, 26))):
        cur.execute("""insert into breach_core.incidents (org_id, event_date, first_public_date, regulator_filed)
                       values (%s, %s, %s, true) returning incident_id""", (org, ev, pub))
        ids[key] = cur.fetchone()[0]
        cur.execute("""insert into breach_core.incident_sources (incident_id, source_id, source_record_id, doc_sha256, match_method)
                       values (%s, 'ca_ag', %s, '', 'new')""", (ids[key], "co-" + key))
    return org, ids


def _q(cur, sql, *p):
    cur.execute(sql, p)
    return cur.fetchall()


CO_OUT = {"is_incident_report": True, "incidents": [{"organization": "Capital One", "source_of_account": "news", "facts": [
    {"field": "people_affected", "value": 100000000, "unit": "persons", "qualifier": "at_least",
     "quote": CAPITAL_ONE_DOC.split(". ")[0] + "."}]}]}


@db
def test_follow_up_attaches_to_the_2019_breach_and_moves_no_date(conn):
    with conn.cursor() as cur:
        org, ids = _capital_one(cur)
        _file(conn, cur, "c" * 64, "Court reimposes original sentence for Capital One hacker", CAPITAL_ONE_DOC, CO_OUT, "2025-11-05")
        assert _q(cur, "select count(*) from breach_core.incidents") == [(4,)], "a follow-up never creates an incident"
        assert _q(cur, """select incident_id, match_method::text from breach_core.incident_sources
                           where source_id = 'news_cyberscoop'""") == [(ids["2019"], "follow_up")]
        assert _q(cur, "select event_date, first_public_date from breach_core.incidents where incident_id = %s",
                  ids["2019"]) == [(date(2019, 3, 22), date(2019, 8, 8))]
        assert _q(cur, """select field, value_text, accepted from breach_core.claims where field = 'event_year'""") == \
            [("event_year", "2019", True)]
        assert _q(cur, "select count(*) from breach_core.press_review") == [(0,)]


@db
def test_follow_up_stating_the_breach_date_attaches_to_a_filing_without_one(conn):
    """HHS lists no breach date: a settlement article stating it attaches to the filing made within the filing
    lag after it, and the filing keeps its own (absent) event date and its first public date."""
    with conn.cursor() as cur:
        org, _ = resolve.find_or_create_org(cur, name="Zeta Clinic", country="US")
        cur.execute("""insert into breach_core.incidents (org_id, first_public_date, regulator_filed)
                       values (%s, '2024-06-20', true) returning incident_id""", (org,))
        hhs = cur.fetchone()[0]
        cur.execute("""insert into breach_core.incident_sources (incident_id, source_id, source_record_id, doc_sha256, match_method)
                       values (%s, 'hhs_ocr', 'zz-hhs', '', 'new')""", (hhs,))
        text = "Zeta Clinic said the breach occurred on March 3, 2024."
        out = {"is_incident_report": True, "incidents": [{"organization": "Zeta Clinic", "source_of_account": "news", "facts": [
            {"field": "event_date", "value": "2024-03-03", "unit": "none", "qualifier": "exact", "quote": text}]}]}
        _file(conn, cur, "b" * 64, "Zeta Clinic Settles Data Breach Lawsuit", text, out, "2026-02-01")
        assert _q(cur, "select count(*) from breach_core.incidents") == [(1,)]
        assert _q(cur, "select incident_id, match_method::text from breach_core.incident_sources where source_id = 'news_cyberscoop'") == \
            [(hhs, "follow_up")]
        assert _q(cur, "select event_date, first_public_date from breach_core.incidents") == [(None, date(2024, 6, 20))]


@db
def test_follow_up_with_no_date_and_several_incidents_is_held_privately(conn):
    with conn.cursor() as cur:
        _capital_one(cur)
        text = "Two of three judges said the sentence for the Capital One hacker was too light."
        _file(conn, cur, "d" * 64, "Capital One hacker Paige Thompson got too light a sentence, appeals court rules", text,
              {"is_incident_report": True, "incidents": [{"organization": "Capital One", "source_of_account": "news", "facts": []}]},
              "2025-03-19")
        assert _q(cur, "select count(*) from breach_core.incidents") == [(4,)]
        assert _q(cur, "select reason, doc_kind, kind_reason, incident_id from breach_core.press_review") == \
            [("ambiguous", "follow_up", "criminal", None)]
        assert _q(cur, "select count(*) from breach_core.incident_sources where source_id = 'news_cyberscoop'") == [(0,)]
        cur.execute("set local role anon")
        with pytest.raises(Exception):
            cur.execute("select * from breach_core.press_review")


@db
def test_follow_up_about_an_unknown_organisation_creates_nothing(conn):
    with conn.cursor() as cur:
        out = {"is_incident_report": True, "incidents": [{"organization": "Nowhere Clinic", "source_of_account": "news", "facts": [
            {"field": "people_affected", "value": 5000, "unit": "persons", "qualifier": "exact",
             "quote": "Nowhere Clinic said 5,000 patients were affected."}]}]}
        _file(conn, cur, "e" * 64, "Nowhere Clinic Settles Data Breach Lawsuit", "Nowhere Clinic said 5,000 patients were affected.",
              out, "2026-01-10")
        assert _q(cur, "select count(*) from breach_core.organizations") == [(0,)]
        assert _q(cur, "select count(*) from breach_core.incidents") == [(0,)]
        assert _q(cur, "select count(*) from breach_core.claims") == [(0,)]
        assert _q(cur, "select organization, reason from breach_core.press_review") == [("Nowhere Clinic", "no_matching_incident")]


@db
def test_first_report_naming_an_old_breach_year_links_to_that_breach(conn):
    """Not a follow-up (a late notice), no full date: the coarse year finds the 2019 incident before the 90-day
    window; a name match links (possible_duplicate_of) rather than standing alone dated 2025."""
    with conn.cursor() as cur:
        org, ids = _capital_one(cur)
        text = "Capital One is notifying more customers about the 2019 Capital One data breach."
        _file(conn, cur, "f" * 64, "Capital One notifies more customers", text,
              {"is_incident_report": True, "incidents": [{"organization": "Capital One", "country": "United States",
                                                          "source_of_account": "news", "facts": []}]},
              "2025-06-01")
        [(new, dup)] = _q(cur, "select incident_id, possible_duplicate_of from breach_core.incidents where first_public_date = '2025-06-01'")
        assert dup == ids["2019"]


@db
def test_press_data_types_reach_the_list_on_a_rebuild_without_a_run(conn):
    """The 2026-10-21 shape: an agent load files accepted data_types claims after the last run's reconcile.
    The list shows them on the next rebuild_victims_list(), split exactly as reconcile.split_data_types splits."""
    from zdc_breach import reconcile
    with conn.cursor() as cur:
        text = "Zeta Retail said names, addresses and Social Security numbers were stolen in the attack."
        value = "names, addresses and Social Security numbers"
        out = {"is_incident_report": True, "incidents": [{"organization": "Zeta Retail", "source_of_account": "news_citing_victim",
               "facts": [{"field": "data_types", "value": value, "unit": "none", "qualifier": "not_applicable", "quote": text}]}]}
        _file(conn, cur, "a" * 64, "Zeta Retail confirms cyberattack", text, out, "2026-10-20")
        want = sorted(set(reconcile.split_data_types(value)))
        assert want == ["Social Security numbers", "addresses", "names"]       # 'and' before a label splits
        cur.execute("select breach_core.rebuild_victims_list()")
        assert _q(cur, "select name, data_types from breach_core.victims_list where name = 'Zeta Retail'") == [("Zeta Retail", want)]
        # the run's reconcile writes the same thing into incident_facts
        reconcile.build(cur)
        assert _q(cur, "select data_types from breach_core.incident_facts") == [(want,)]
        # an inactive field publishes nothing (and, the claim being the only one, no name either)
        cur.execute("update breach_core.extractor_versions set active_fields = '{people_affected}' where extractor_id = %s", (EXT,))
        cur.execute("select breach_core.rebuild_victims_list()")
        assert _q(cur, "select count(*) from breach_core.victims_list where name = 'Zeta Retail'") == [(0,)]


@db
def test_refresh_brings_every_claim_to_the_current_split(conn):
    """A claim written without items (an older writer) is split by the next run's reconcile, before the list."""
    from zdc_breach import reconcile
    de = ("Social Security number, Account number, credit card account number, or debit card number, in combination "
          "with any required security code, access code, or password that would permit access to a financial account")
    with conn.cursor() as cur:
        org, _ = resolve.find_or_create_org(cur, name="Zz Delaware Clinic", country="US")
        cur.execute("""insert into breach_core.incidents (org_id, first_public_date, regulator_filed) values (%s, '2026-09-01', true)
                       returning incident_id""", (org,))
        inc = cur.fetchone()[0]
        cur.execute("""insert into breach_core.incident_sources (incident_id, source_id, source_record_id, doc_sha256, match_method)
                       values (%s, 'de_ag', 'zz-de', '', 'new')""", (inc,))
        cur.execute("""insert into breach_core.claims (incident_id, field, value_text, unit, qualifier, as_of, basis, source_id,
                                                       source_record_id, accepted)
                       values (%s, 'data_types', %s, 'none', 'not_applicable', '2026-09-01', 'regulator_filing', 'de_ag', 'zz-de', true)""",
                    (inc, de))
        naive = _q(cur, "select breach_core.incident_data_types(%s)", inc)[0][0]
        assert len(naive) == 7, naive                    # the comma fallback breaks the statutory element apart
        assert reconcile.refresh_value_items(cur) == 1
        want = sorted(set(reconcile.split_data_types(de)))
        assert len(want) == 2
        assert _q(cur, "select breach_core.incident_data_types(%s)", inc) == [(want,)]
        assert reconcile.refresh_value_items(cur) == 0   # idempotent


@db
def test_repair_apply_hides_a_held_row_and_links_a_duplicate(conn):
    with conn.cursor() as cur:
        org, ids = _capital_one(cur)
        cur.execute("""insert into breach_core.incidents (org_id, first_public_date, media_reported) values (%s, '2025-11-05', true),
                       (%s, '2025-03-19', true) returning incident_id""", (org, org))
        resent, ruling = [r[0] for r in cur.fetchall()]
        # make both press rows public the way the live ones are: an accepted claim in an active field
        for inc in (resent, ruling):
            _doc(cur, str(inc).replace("-", "").ljust(64, "0"), "t", "Capital One said 100 million people were affected.", "2025-03-19")
            cur.execute("""insert into breach_core.extractions (extraction_id, doc_sha256, extractor_id, output, ok)
                           values (gen_random_uuid(), %s, %s, '{}', true) returning extraction_id""",
                        (str(inc).replace("-", "").ljust(64, "0"), EXT))
            ex = cur.fetchone()[0]
            cur.execute("""insert into breach_core.claims (incident_id, field, value_num, unit, qualifier, as_of, basis, source_id,
                                                           doc_sha256, extraction_id, accepted, quote)
                           values (%s, 'people_affected', 100000000, 'persons', 'exact', '2025-03-19', 'news', 'news_cyberscoop',
                                   %s, %s, true, 'q')""", (inc, str(inc).replace("-", "").ljust(64, "0"), ex))
        public = lambda i: _q(cur, "select count(*) from public.breach_incidents where incident_id = %s", i)[0][0]  # noqa: E731
        assert public(resent) == 1 and public(ruling) == 1
        plan = {"method": press_repair.METHOD, "rows": [
            {"action": "possible_duplicate_of", "incident_id": str(resent), "target": str(ids["2019"])},
            {"action": "review", "incident_id": str(ruling), "name": "Capital One", "flags": ["follow_up"],
             "kind_reasons": ["criminal"], "coarse": [], "titles": ["appeals court rules"], "fpd": "2025-03-19"}]}
        conn.commit()
    press_repair.apply(conn, plan, "test")
    with conn.cursor() as cur:
        assert _q(cur, "select possible_duplicate_of from breach_core.incidents where incident_id = %s", resent) == [(ids["2019"],)]
        assert public(ruling) == 0, "a row held for review is not public"
        cur.execute("update breach_core.press_review set status = 'released', resolved_at = now(), resolved_by = 't'")
        assert public(ruling) == 1, "releasing it publishes it again"
    conn.rollback()
