"""Unit tests for the breach pipeline. Synthetic data only; no network, no database."""

from __future__ import annotations

import json
from datetime import date, datetime, timezone
from decimal import Decimal

import pytest

from zdc_breach import extract, grounding, llm, normalize, reconcile, sources_leak, sources_news, sources_reg

DOC = ("Acme Health said in a statement that the personal information of 4.2 million patients "
       "was stolen in the attack. The attackers demanded a $5 million ransom, which Acme did not pay. "
       "The intruders exploited CVE-2026-12345 in the company's VPN appliance. "
       "Investigators found 1.5 TB of data had been exfiltrated. Separately, Globex reported revenue "
       "of $10 million last quarter. There is no evidence that customer payment data was taken.")


# ---- grounding ---------------------------------------------------------------------------------
def test_numbers_in_reads_every_spelling():
    assert Decimal(4200000) in grounding.numbers_in("4.2 million patients")
    assert Decimal(4200000) in grounding.numbers_in("4,200,000 patients")
    assert Decimal(4200000) in grounding.numbers_in("4.2M patients")
    assert Decimal(5000000) in grounding.numbers_in("a $5 million ransom")


def test_sizes_in():
    assert 1_500_000_000_000 in grounding.sizes_in("1.5 TB of data")
    assert 2 * 10**9 in grounding.sizes_in("2GB archive")
    assert 3 * 10**12 in grounding.sizes_in("3 terabytes")


def test_quote_must_be_in_document():
    assert grounding.check("people_affected", 4200000,
                           "the personal information of 4.2 million patients was stolen in the attack", DOC) is None
    assert grounding.check("people_affected", 4200000,
                           "the personal information of 4.2 million patients was copied", DOC) == "quote_not_in_document"


def test_short_quote_proves_nothing():
    assert grounding.check("people_affected", 4200000, "4.2 million", DOC) == "quote_not_in_document"


def test_number_must_be_in_quote():
    q = "the personal information of 4.2 million patients was stolen in the attack"
    assert grounding.check("people_affected", 4300000, q, DOC) == "number_not_in_quote"


def test_negated_quote_rejected():
    assert grounding.check("data_types", "payment data",
                           "There is no evidence that customer payment data was taken.", DOC) == "negated"


def test_quote_normalisation_is_whitespace_and_punctuation_only():
    doc = "Acme said “the data of 10,000 people” was taken."
    assert grounding.quote_in_document('Acme said "the data of 10,000 people" was taken.', doc)
    assert not grounding.quote_in_document('acme said "the data of 10,000 people" was taken.', doc)


def test_cve_must_be_in_quote():
    q = "The intruders exploited CVE-2026-12345 in the company's VPN appliance."
    assert grounding.check("cve_id", "CVE-2026-12345", q, DOC) is None
    assert grounding.check("cve_id", "CVE-2026-99999", q, DOC) == "cve_not_in_quote"


# ---- extraction validation ----------------------------------------------------------------------
def _out(*facts, org="Acme Health", basis="victim_statement", more=None):
    incs = [{"organization": org, "domain": "acmehealth.example", "country": "US", "sector": "health",
             "source_of_account": basis, "facts": list(facts)}]
    return {"is_incident_report": True, "incidents": incs + (more or [])}


def _f(field, value, quote, unit="none", qualifier="exact", **kw):
    return {"field": field, "value": value, "unit": unit, "qualifier": qualifier, "quote": quote, **kw}


Q_PEOPLE = "Acme Health said in a statement that the personal information of 4.2 million patients was stolen in the attack."
Q_RANSOM = "The attackers demanded a $5 million ransom, which Acme did not pay."


def test_valid_people_count_accepted():
    [inc] = extract.validate(_out(_f("people_affected", 4200000, Q_PEOPLE, "persons")), DOC)
    c = inc.candidates[0]
    assert c.accepted and c.quote_start is not None


def test_unit_mismatch_rejected():
    [inc] = extract.validate(_out(_f("people_affected", 4200000, Q_PEOPLE, "records")), DOC)
    assert inc.candidates[0].reject_reason == "unit_records_for_people_affected"


def test_ransom_needs_currency_and_kind():
    [inc] = extract.validate(_out(_f("ransom_demand_amount", 5000000, Q_RANSOM, "money")), DOC)
    assert inc.candidates[0].reject_reason == "money_without_currency_or_kind"
    [inc] = extract.validate(_out(_f("ransom_demand_amount", 5000000, Q_RANSOM, "money",
                                     currency="USD", money_kind="demand_initial")), DOC)
    assert inc.candidates[0].accepted


def test_revenue_is_not_a_ransom():
    q = "Separately, Globex reported revenue of $10 million last quarter."
    [inc] = extract.validate(_out(_f("ransom_demand_amount", 10000000, q, "money", currency="USD",
                                     money_kind="demand_initial"), org="Globex"), DOC)
    assert inc.candidates[0].reject_reason == "field_cue_missing"


def test_threat_actor_cannot_supply_a_count():
    [inc] = extract.validate(_out(_f("people_affected", 4200000, Q_PEOPLE, "persons"),
                                  basis="threat_actor_claim"), DOC)
    assert inc.candidates[0].reject_reason == "actor_claim_cannot_supply_count"


def test_subject_must_be_named_when_article_has_two_organisations():
    other = {"organization": "Globex", "source_of_account": "news", "facts": []}
    q = "The intruders exploited CVE-2026-12345 in the company's VPN appliance."
    incs = extract.validate(_out(_f("cve_id", "CVE-2026-12345", q, cve_role="initial_access"), more=[other]), DOC)
    assert incs[0].candidates[0].reject_reason == "subject_not_named"


def test_single_organisation_article_does_not_need_the_name_in_every_sentence():
    q = "The intruders exploited CVE-2026-12345 in the company's VPN appliance."
    [inc] = extract.validate(_out(_f("cve_id", "CVE-2026-12345", q, cve_role="initial_access")), DOC)
    assert inc.candidates[0].accepted


def test_vector_needs_its_cue():
    q = "The intruders exploited CVE-2026-12345 in the company's VPN appliance."
    [inc] = extract.validate(_out(_f("vector", "phishing", q)), DOC)
    assert inc.candidates[0].reject_reason == "vector_cue_missing"
    [inc] = extract.validate(_out(_f("vector", "vulnerability_exploitation", q)), DOC)
    assert inc.candidates[0].accepted


def test_false_boolean_from_a_negating_sentence_is_a_fact():
    q = "There is no evidence that customer payment data was taken."
    [inc] = extract.validate(_out(_f("data_exfiltrated", False, q)), DOC)
    assert inc.candidates[0].accepted and inc.candidates[0].value is False


def test_hypothetical_count_rejected():
    doc = "Acme Health warned the incident could affect up to 2 million customers in total."
    [inc] = extract.validate(_out(_f("people_affected", 2000000, doc, "persons", "at_most")), doc)
    assert inc.candidates[0].reject_reason == "hypothetical"


def test_not_an_incident_report_yields_nothing():
    assert extract.validate({"is_incident_report": False, "incidents": []}, DOC) == []
    assert extract.validate("garbage", DOC) == []


def test_prompt_hash_changes_with_model():
    assert extract.prompt_hash("a/b") != extract.prompt_hash("a/c")


# ---- normalisation ---------------------------------------------------------------------------
def test_norm_name_strips_legal_form_only():
    assert normalize.norm_name("Acme, Inc.") == normalize.norm_name("ACME INC") == "acme"
    assert normalize.norm_name("Acme Health LLC") != normalize.norm_name("Acme")


def test_domain_kept_whole():
    assert normalize.norm_domain("https://www.Sub.Example.co.uk/path") == "sub.example.co.uk"
    assert normalize.norm_domain("not a domain") is None
    assert normalize.domain_from_title("acme.com") == "acme.com"
    assert normalize.domain_from_title("Acme.com Ltd") is None


def test_country():
    assert normalize.norm_country("United States") == "US"
    assert normalize.norm_country("de") == "DE"
    assert normalize.norm_country("Atlantis") is None


# ---- source parsers --------------------------------------------------------------------------
def test_ransomfeed_parse():
    rows = [{"id": 1, "date": "2026-10-13 10:58:42", "victim": "Valode", "gang": "Panzer", "hash": "h1",
             "country": "France", "website": "v-p.com", "work_sector": "Construction"},
            {"id": 2, "victim": "", "gang": "x"}]
    posts, bad = sources_leak.parse_ransomfeed(rows)
    assert bad == 1 and posts[0].victim_domain == "v-p.com" and posts[0].country == "FR"
    assert posts[0].seen_at.tzinfo is not None


def test_ransomlook_parse_domain_title():
    rows = [{"post_title": "acme.com", "discovered": "2026-10-13 23:18:33.059", "group_name": "Qilin",
             "misp_uuid": "u1"}]
    [p], bad = sources_leak.parse_ransomlook(rows)
    assert p.actor_group == "qilin" and p.victim_domain == "acme.com" and bad == 0


def test_wa_parse_vector_and_floor():
    rows = [{"name": "Acme", "id": "9", "datesubmitted": "2026-09-11T00:00:00.000",
             "datestart": "2026-08-01T00:00:00.000", "washingtoniansaffected": "681",
             "databreachcause": "Cyberattack", "cyberattacktype": "Phishing"},
            {"name": "Beta", "id": "10", "datesubmitted": "2026-09-12T00:00:00.000",
             "databreachcause": "Cyberattack", "cyberattacktype": "Ransomware"}]
    ds, bad = sources_reg.parse_wa(rows)
    a = {f.field: f for f in ds[0].facts}
    assert a["people_affected"].qualifier == "at_least" and a["vector"].value_text == "phishing"
    b = {f.field: f for f in ds[1].facts}
    assert "vector" not in b and b["ransomware_family"].value_text == "unspecified"


def test_hhs_placeholder():
    body = ('"Name","State","Type","Individuals Affected","Breach Submission Date","Type of Breach","Location","BA","Desc"\n'
            '"A Clinic","NC","Healthcare Provider","500","09/01/2026","Hacking/IT Incident","Network Server","No",""\n'
            '"B Plan","IA","Health Plan","1693","09/21/2026","Theft","Laptop","Yes",""\n')
    ds, bad = sources_reg.parse_hhs(body)
    assert ds[0].facts[0].qualifier == "placeholder"
    assert not any(f.field == "vector" for f in ds[0].facts)      # Hacking/IT is not a vector
    assert any(f.field == "vector" and f.value_text == "physical_loss" for f in ds[1].facts)


def test_hibp_counts_accounts_not_persons():
    ds, _ = sources_reg.parse_hibp([{"Name": "X", "Title": "X", "Domain": "x.com", "AddedDate": "2026-10-12T00:00:00Z",
                                     "BreachDate": "2026-08-01", "PwnCount": 318185, "DataClasses": ["Emails"]}])
    assert ds[0].facts[0].unit == "accounts" and ds[0].basis == "breach_index"


def test_efts_only_item_105_filings():
    payload = {"hits": {"hits": [
        {"_id": "0001-26-1:doc.htm", "_source": {"display_names": ["Acme Corp  (ACME)  (CIK 0000123456)"],
         "file_date": "2026-09-23", "period_ending": "2026-09-22", "adsh": "0001-26-1", "items": ["1.05"]}},
        {"_id": "0001-26-2:doc.htm", "_source": {"display_names": ["Other Co  (CIK 0000000001)"],
         "file_date": "2026-09-23", "adsh": "0001-26-2", "items": ["8.01"]}}]}}
    ds, bad = sources_reg.parse_efts(payload)
    assert len(ds) == 1 and ds[0].sec_cik == "123456" and ds[0].organization == "Acme Corp"
    assert ds[0].url.endswith("/123456/0001261/doc.htm")


def test_feed_relevance_filter():
    xml = b"""<rss><channel>
      <item><title>Acme hit by ransomware</title><link>https://n.example/a</link><description>x</description></item>
      <item><title>New laptop review</title><link>https://n.example/b</link><description>fast</description></item>
      <item><title>Old</title><link>http://insecure.example/c</link><description>breach</description></item>
    </channel></rss>"""
    items = sources_news.parse_feed("news_x", xml)
    assert [i.relevant for i in items] == [True, False]   # the http:// link is dropped


# ---- reconciliation ----------------------------------------------------------------------------
def _c(basis, value, qualifier="exact", as_of=date(2026, 9, 1), cid="1", source="s"):
    return {"basis": basis, "value_num": value, "qualifier": qualifier, "as_of": as_of, "claim_id": cid,
            "source_id": source}


def test_regulator_beats_news_and_placeholder_loses():
    claims = [_c("news", 5000, cid="1"), _c("regulator_filing", 500, "placeholder", cid="2"),
              _c("regulator_filing", 4200, cid="3")]
    assert reconcile.choose(claims, reconcile.COUNT_ORDER)["claim_id"] == "3"


def test_later_as_of_wins_within_basis():
    claims = [_c("regulator_filing", 100, as_of=date(2026, 1, 1), cid="1"),
              _c("regulator_filing", 120, as_of=date(2026, 3, 1), cid="2")]
    assert reconcile.choose(claims, reconcile.COUNT_ORDER)["claim_id"] == "2"


def test_disagreement_kept_as_range():
    best, lo, hi, dis, n = reconcile._count([_c("regulator_filing", 100, cid="1", source="a"),
                                              _c("news", 200, cid="2", source="b")])
    assert best["value_num"] == 100 and (lo, hi) == (100, 200) and dis and n == 2


def test_threat_actor_never_in_count_order():
    assert "threat_actor_claim" not in reconcile.COUNT_ORDER


# ---- LLM client ------------------------------------------------------------------------------
FAKE_KEY = "sk-or-" + "v1-" + "abcdef0123456789" * 3


def test_budget_guard_refuses_before_calling():
    called = []

    class Opener:
        def open(self, req, timeout):
            called.append(1)
            raise AssertionError("must not be called")

    c = llm.OpenRouter(FAKE_KEY, spent_month_usd=llm.MONTHLY_CAP_USD, spent_today_usd=0, opener=Opener())
    with pytest.raises(llm.BudgetExceeded):
        c.json("s", "u")
    assert not called


def test_key_redacted_and_validated():
    assert FAKE_KEY not in llm.redact(f"error near {FAKE_KEY}")
    with pytest.raises(ValueError):
        llm.OpenRouter("not-a-key", 0, 0)


def test_llm_parses_usage_and_cost():
    class Resp:
        def __init__(self, payload):
            self._b = json.dumps(payload).encode()

        def read(self):
            return self._b

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class Opener:
        def open(self, req, timeout):
            body = json.loads(req.data)
            assert body["temperature"] == 0 and body["provider"]["data_collection"] == "deny"
            assert body["provider"]["allow_fallbacks"] is False
            return Resp({"model": "m", "provider": "p", "usage": {"prompt_tokens": 10, "completion_tokens": 5, "cost": 0.0001},
                         "choices": [{"message": {"content": '{"is_incident_report": false}'}}]})

    c = llm.OpenRouter(FAKE_KEY, 0, 0, opener=Opener())
    r = c.json("s", "u")
    assert r.ok and r.cost_usd == 0.0001 and c.spent_today == 0.0001


def test_negation_is_clause_local_for_amounts():
    q = "The attackers demanded a $5 million ransom, which Acme did not pay."
    assert grounding.check("ransom_demand_amount", 5000000, q, DOC) is None
    doc = "Acme said there is no evidence that 2 million records were taken from the server."
    assert grounding.check("records_affected", 2000000, doc, doc) == "negated"


def test_jsf_button_found_by_label():
    html = ("""<a href="#" onclick="mojarra.jsfcljs(document.getElementById('ocrForm'),{'ocrForm:j_idt37':'ocrForm:j_idt37'},'');return false">File a HIPAA Breach</a>"""
            """<a href="#" onclick="mojarra.jsfcljs(document.getElementById('ocrForm'),{'ocrForm:j_idt39':'ocrForm:j_idt39'},'');return false">View HIPAA Breach Reports</a>"""
            """<a href="#" onclick="mojarra.jsfcljs(document.getElementById('ocrForm'),{'ocrForm:j_idt388':'ocrForm:j_idt388'},'');return false"><img src="/ocr/resources/images/csv.png" /></a>""")
    assert sources_reg.jsf_button(html, "View HIPAA Breach Reports") == "ocrForm:j_idt39"
    assert sources_reg.jsf_button(html, r"[^>]*csv") == "ocrForm:j_idt388"


def test_attacker_claim_in_news_cannot_supply_a_count():
    doc = "Criminals called BYOD claim to have broken into Acme Mobile and leaked data belonging to 3,615 customers."
    [inc] = extract.validate(_out(_f("people_affected", 3615, doc, "persons"), org="Acme Mobile", basis="news"), doc)
    c = inc.candidates[0]
    assert c.basis == "threat_actor_claim" and c.reject_reason == "actor_claim_cannot_supply_count"


def test_actor_filed_as_victim_is_dropped():
    doc = "In April, we published research on a campaign we tie to the North Korean group Famous Chollima."
    out = _out(_f("actor", "Famous Chollima", doc), org="Famous Chollima", basis="news")
    assert extract.validate(out, doc) == []


def test_disruption_needs_its_cue():
    doc = "RubyGems removed more than 500 of the packages as malicious, the maintainers said."
    [inc] = extract.validate(_out(_f("operations_disrupted", True, doc), org="RubyGems"), doc)
    assert inc.candidates[0].reject_reason == "disruption_cue_missing"


def test_loose_misconfiguration_cue_rejected():
    doc = "Anthropic disclosed three incidents in which models with open tool access compromised external organisations."
    [inc] = extract.validate(_out(_f("vector", "misconfiguration", doc), org="Anthropic"), doc)
    assert inc.candidates[0].reject_reason == "vector_cue_missing"


def test_count_must_be_of_people():
    doc = "Intermarche owner Les Mousquetaires said around 150 of its supermarkets were affected by the attack."
    [inc] = extract.validate(_out(_f("people_affected", 150, doc, "persons", "approx"), org="Les Mousquetaires"), doc)
    assert inc.candidates[0].reject_reason == "count_not_of_people"


def test_attacker_claim_cannot_supply_exfiltration():
    doc = "In late September, ShinyHunters hacked the portal and claimed it stole sensitive details about employees."
    [inc] = extract.validate(_out(_f("data_exfiltrated", True, doc), org="Portal", basis="news"), doc)
    assert inc.candidates[0].reject_reason == "actor_claim_cannot_supply_impact"


def test_exfiltration_needs_theft_and_discovery_needs_discovery():
    doc = ("The FBI investigation gained urgency with the group's attempted extortion of Acme Health. "
           "The affected individuals were notified on or around March 22, 2024.")
    [inc] = extract.validate(_out(
        _f("data_exfiltrated", True, "The FBI investigation gained urgency with the group's attempted extortion of Acme Health."),
        _f("discovery_date", "2024-03-22", "The affected individuals were notified on or around March 22, 2024.")), doc)
    assert [c.reject_reason for c in inc.candidates] == ["theft_cue_missing", "discovery_cue_missing"]


def test_hedged_false_is_not_a_fact():
    doc = "The SEC filing does not state whether payment was made to the attacker by Acme Health."
    [inc] = extract.validate(_out(_f("ransom_paid", False, doc)), doc)
    assert inc.candidates[0].reject_reason == "hedged"


def test_two_values_from_one_source_are_not_a_disagreement():
    best, lo, hi, dis, n = reconcile._count([_c("regulator_filing", 6083, cid="1", source="de_ag"),
                                              _c("regulator_filing", 1185755, cid="2", source="de_ag")])
    assert (lo, hi) == (6083, 1185755) and n == 1 and not dis


def test_placeholder_dates_rejected():
    ds, _ = sources_reg.parse_de([{"company_name": "Acme", "date_of_notice": "2026-09-25T00:00:00.000",
                                    "date_of_breach": "1971-01-01T00:00:00.000", "total_affected": "10"}])
    assert ds[0].event_date is None and ds[0].as_of.year == 2026


def test_wikidata_size_latest_dated_value_wins():
    from zdc_breach import sources_size
    p = {"results": {"bindings": [
        {"item": {"value": "http://www.wikidata.org/entity/Q1"}, "url": {"value": "https://www.acme.com/"},
         "emp": {"value": "1000"}, "t": {"value": "2018-01-01T00:00:00Z"}},
        {"item": {"value": "http://www.wikidata.org/entity/Q1"}, "url": {"value": "https://www.acme.com/"},
         "emp": {"value": "1500"}, "t": {"value": "2024-01-01T00:00:00Z"}},
        {"item": {"value": "http://www.wikidata.org/entity/Q1"}, "url": {"value": "https://www.acme.com/"},
         "emp": {"value": "9999"}},
        {"item": {"value": "http://www.wikidata.org/entity/Q2"}, "url": {"value": "https://other.org"},
         "emp": {"value": "5"}}]}}
    got = sources_size.parse(p, ["acme.com"])
    assert got == {"acme.com": (1500, date(2024, 1, 1), "Q1")}
    assert "https://www.acme.com/" in sources_size.variants("acme.com") and len(sources_size.variants("acme.com")) == 8


def test_headcount_from_leak_post():
    f = sources_leak.employees_stated
    assert f("Around 630 employees work at Placer.ai after 150 layoffs") == 630
    assert f("operating in 25+ countries with 250–400 employees.") == 250
    assert f("around 2,000 employees in 36 countries") == 2000
    assert f("We stole the data of 5,000 employees and customers") is None
    assert f("Files: 746,108 Data volume: 106.8 GB") is None


def test_demand_from_leak_post():
    d = sources_leak.demand_stated
    t = "Dear Acme. If you would rather not have us contact your partners, we suggest you pay the following: $500,000 in BTC or XMR. Email: crook@example.com"
    text, amount, cur = d(t)
    assert amount == 500000 and cur == "USD" and "crook@" not in text
    assert d("The ransom is 12 BTC, send to session 05651c7323273b723588d47455471ee9e27feb5187a30f2933554a705aacb38358")[1:] == (12.0, "BTC")
    assert d("We stole 1.2M contact records and 920 MB of data.") is None


def test_header_thumb_keeps_only_the_top_and_shrinks():
    import io
    from PIL import Image
    from zdc_breach import thumbs
    im = Image.new("RGB", (1280, 3000), "white")
    buf = io.BytesIO(); im.save(buf, "PNG")
    webp, w, h = thumbs.header_thumb(buf.getvalue())
    assert w == 400 and h == round(520 * 400 / 1280)          # header only, capped at 520 px of 3000
    assert thumbs.screenshot_url("screenshots/x/Acme Ltd.png").endswith("screenshots/x/Acme%20Ltd.png")
    assert thumbs.screenshot_url("../etc/passwd") is None and thumbs.screenshot_url("http://evil/x.png") is None


def test_wilson_interval():
    from zdc_breach import confidence
    r, lo, hi = confidence.wilson(5, 100)
    assert r == 0.05 and 0.01 < lo < 0.05 < hi < 0.12
    assert confidence.wilson(0, 0) == (None, None, None)


# ---- 0119: actors, media, leak-stated facts ----------------------------------------------------
def test_actor_registry_merges_aliases_and_drops_shared_ones():
    from zdc_breach import sources_actors as sa
    misp = {"values": [
        {"value": "APT28", "meta": {"synonyms": ["Fancy Bear", "Sednit"], "cfr-suspected-state-sponsor": "Russian Federation",
                                    "cfr-type-of-incident": ["Espionage"], "refs": ["https://example.org/apt28"]}},
        {"value": "Storm-1567", "meta": {"synonyms": ["Akira"]}},
        {"value": "Alpha", "meta": {"synonyms": ["Shared Name"]}},
        {"value": "Beta", "meta": {"synonyms": ["Shared Name"]}},
        {"value": "Defacers", "meta": {"motive": "Hacktivists-Nationalists"}},
    ]}
    rw = {"values": [{"value": "Akira Ransomware", "meta": {}}, {"value": "LockBit", "meta": {"synonyms": ["LockBit 3.0"]}}]}
    actors, aliases = sa.build(misp, rw, ["akira", "lockbit", "qilin"])
    by = {a.actor_id: a for a in actors}
    assert aliases["fancybear"][0] == aliases["sednit"][0] == "apt28"
    assert by["apt28"].kind == "state_sponsored" and by["apt28"].sponsor_country == "RU" and by["apt28"].motive == "espionage"
    assert aliases["akira"][0] == "storm-1567" and by["storm-1567"].display_name == "Akira"   # not the tracking code
    assert by["storm-1567"].kind == "extortion" and by["storm-1567"].listed_ransomware
    assert by["rl-lockbit"].listed_ransomware and not by["rl-qilin"].listed_ransomware
    assert "sharedname" not in aliases                     # two actors claim it: dropped, not guessed
    assert by["defacers"].kind == "hacktivist"


def test_actor_norm_keeps_short_names_whole():
    from zdc_breach.sources_actors import norm
    assert norm("LockBit Ransomware") == "lockbit" and norm("Akira Team") == "akira"
    assert norm("INC Ransom") == "incransom" and norm("Ransom House") == "ransomhouse"
    assert norm("The Gentlemen") == norm("thegentlemen")


def test_media_match_needs_the_name_in_the_title_and_a_breach_term():
    from zdc_breach import sources_media as sm
    assert sm.matches("Change Healthcare", "Change Healthcare confirms ransomware attack", "https://x.org/a")
    assert not sm.matches("Change Healthcare", "UnitedHealth earnings beat", "https://x.org/ransomware-news")
    assert not sm.matches("Acme", "Acmeville council meets on ransomware", "https://x.org/a")   # whole words only
    assert sm.matches("Acme Corp", "Acme Corp quarterly results", "https://x.org/acme-corp-data-breach")
    assert not sm.searchable("acme.com") and not sm.searchable("ABC") and sm.searchable("Acme Corp")
    payload = {"articles": [
        {"url": "https://news.example/a", "title": "Acme Corp hit by cyberattack", "seendate": "20250102T030405Z",
         "domain": "news.example", "language": "English"},
        {"url": "http://abc.onion/x", "title": "Acme Corp hit by cyberattack"},
        {"url": "https://news.example/b", "title": "Acme Corp opens plant"}]}
    got = sm.parse(payload, "Acme Corp")
    assert [g["url"] for g in got] == ["https://news.example/a"] and got[0]["published_at"].year == 2025
    from datetime import date
    assert sm.query_url("Acme Corp", date(2016, 1, 1), date(2016, 6, 1)) is None    # before GDELT's index
    assert "startdatetime=2024" in sm.query_url("Acme Corp", date(2024, 3, 1), date(2026, 10, 14))


def test_leak_stated_size_and_revenue():
    from zdc_breach import sources_leak as sl
    assert sl.data_size_stated("We will upload 104gb corporate data soon.") == 104e9
    assert sl.data_size_stated("Total size: 1,84Gb Revenue: $5,000,000") == 1.84e9
    assert sl.data_size_stated("Stolen: 1.82 TB. 1,719,610 Files") == 1.82e12
    assert sl.data_size_stated("The company makes 4K TVs with 2 TB drives") is None
    assert sl.revenue_stated("Revenue: $17.4 Billion Website: amcor.com") == 17.4e9
    assert sl.revenue_stated("estimated annual revenue of $19.1M with ~23-50 employees") == 19.1e6
    assert sl.revenue_stated("Total size: 1,84Gb Revenue: <$5,000,000") is None      # a bound, not a value
    assert sl.revenue_stated("Revenue: $5 Million | Views: 87") == 5e6


def test_category_fact_is_gated_on_quote_cue_and_hedge():
    from zdc_breach import extract
    doc = ("Acme Corp said its servers were encrypted in a ransomware attack on 3 May. "
           "Officials believe the intrusion may have been espionage. "
           "The breach was carried out by APT28, investigators said.")
    out = {"is_incident_report": True, "incidents": [{"organization": "Acme Corp", "source_of_account": "news", "facts": [
        {"field": "category", "value": "ransomware", "unit": "none", "qualifier": "not_applicable",
         "quote": "Acme Corp said its servers were encrypted in a ransomware attack on 3 May."},
        {"field": "category", "value": "espionage", "unit": "none", "qualifier": "not_applicable",
         "quote": "Officials believe the intrusion may have been espionage."},
        {"field": "category", "value": "skimming", "unit": "none", "qualifier": "not_applicable",
         "quote": "Acme Corp said its servers were encrypted in a ransomware attack on 3 May."},
        {"field": "category", "value": "ransomware", "unit": "none", "qualifier": "not_applicable",
         "quote": "Acme Corp was hit by ransomware."},
        {"field": "actor", "value": "APT28", "unit": "none", "qualifier": "not_applicable",
         "quote": "The breach was carried out by APT28, investigators said."}]}]}
    got = {(c.field, str(c.value)): c.reject_reason for c in extract.validate(out, doc)[0].candidates}
    cands = extract.validate(out, doc)[0].candidates
    assert cands[0].accepted                                   # stated, cued, in the document
    assert cands[1].reject_reason == "hedged"                  # "believe ... may have been"
    assert cands[2].reject_reason == "category_cue_missing"    # nothing about skimming in it
    assert cands[3].reject_reason == "quote_not_in_document"   # paraphrase
    assert cands[4].accepted and cands[4].value == "APT28"     # a named state group is an actor
