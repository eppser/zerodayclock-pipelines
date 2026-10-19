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


def test_feed_title_matching_is_whole_phrase_and_distinctive():
    from zdc_breach import sources_media as sm
    idx = sm.index_names([("v1", "Target"), ("v2", "Change Healthcare"), ("v3", "PowerSchool"),
                          ("v4", "Hospital Sisters Health System"), ("v5", "acme.com"), ("v6", "Ascension")])
    assert "target" not in idx and "acme com" not in idx           # an ordinary word; a bare domain
    assert sm.find_in_title("Hackers target hospitals with ransomware", idx) == []
    assert sm.find_in_title("Change Healthcare ransomware attack cost $2.9bn", idx) == ["v2"]
    assert sm.find_in_title("PowerSchool breach: hacker extorted districts", idx) == ["v3"]
    assert sm.find_in_title("Ascension restores systems after ransomware", idx) == []        # one plain word: never
    assert not sm.distinctive("Affiliate") and not sm.distinctive("Notification") and sm.distinctive("McKesson")
    assert not sm.TITLE_EVENT.search("Microsoft catches hackers exploiting Zimbra bug before disclosure")
    assert sm.TITLE_EVENT.search("Manchester Airports Group Hit by Cyber Incident")
    assert sm.TITLE_EVENT.search("Nutex Health Says Patient Data Stolen, Hackers Threaten Leak")
    assert sm.find_in_title("Changes to healthcare law", idx) == []
    assert "dutch" not in sm.index_names([("v7", "Dutch ???")])
    from datetime import date
    assert sm.in_window(date(2026, 3, 1), date(2026, 2, 15)) and not sm.in_window(date(2026, 3, 1), date(2024, 1, 1))
    assert not sm.in_window(None, date(2026, 1, 1))


# ---- Japanese coverage (0130, docs/decisions/0007) ---------------------------------------------
# Synthetic sentences written for these tests, in the shape Japanese incident notices and press
# use. No publisher text.
import glob as _glob
import re as _re
import unicodedata as _ud
from pathlib import Path as _Path

_LEGAL_0129 = _re.compile(
    r"\b(incorporated|inc|corp|corporation|co|company|llc|l\.l\.c|ltd|limited|plc|gmbh|ag|sa|"
    r"s\.a|sas|sarl|srl|spa|s\.p\.a|bv|b\.v|nv|n\.v|oy|ab|as|a/s|pty|pvt|kg|kgaa|se|lp|llp|pc|"
    r"pllc|the)\b\.?", _re.I)


def _norm_name_0129(name: str) -> str:
    """normalize.norm_name exactly as it stood before 0130, frozen here as the reference."""
    s = _ud.normalize("NFKD", name or "").encode("ascii", "ignore").decode().lower()
    s = s.replace("&", " and ")
    s = _LEGAL_0129.sub(" ", s)
    return _re.sub(r"[^a-z0-9]+", " ", s).strip()


def _fixture_names() -> set[str]:
    names: set[str] = set()

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if isinstance(v, str) and _re.search(r"vendor|product|organi|victim|name$", k, _re.I):
                    names.add(v)
                else:
                    walk(v)
        elif isinstance(o, list):
            for x in o:
                walk(x)
    fx = _Path(__file__).parent / "fixtures"
    for f in _glob.glob(str(fx / "*.json")):
        walk(json.load(open(f)))
    for f in _glob.glob(str(fx / "*.ndjson")):
        for line in open(f):
            if line.strip():
                walk(json.loads(line))
    return names


# Real organisation names in Latin script, several with diacritics, ligatures and legal forms -
# the cases the ASCII path's NFKD + drop exists for.
LATIN_NAMES = [
    "Change Healthcare", "Acme, Inc.", "ACME INC", "Hospital Sisters Health System", "PowerSchool",
    "Société Générale S.A.", "Nestlé S.A.", "Ørsted A/S", "Müller GmbH & Co. KG", "Banco Santander, S.A.",
    "Telefónica, S.A.", "Ascension", "McKesson", "Keio Corporation", "Asahi Group Holdings, Ltd.",
    "Æon Credit", "Straße AG", "Çelik Holding A.Ş.", "Kraków Airport sp. z o.o.", "The Co-operative Bank p.l.c.",
    "L'Oréal", "Dansk Supermarked A/S", "  spaced   out  LLC ", "", "Иванов и партнёры", "삼성전자",
    "Ελληνικά Πετρέλαια", "شركة", "N.V. Nederlandse Spoorwegen", "Imagine the Possibilities",
]


def test_norm_name_unchanged_for_every_name_without_han_or_kana():
    """The no-change property: 0130 adds a path for names with Han or kana and must not move one
    byte of any other name. Fixture names (real vendors and products) plus real organisation
    names with diacritics, and the non-Latin scripts that still normalise to "" (Korean,
    Cyrillic, Greek, Arabic - a known limit, ADR 0007)."""
    names = _fixture_names() | set(LATIN_NAMES)
    assert len(names) > 100
    for n in names:
        assert not normalize.has_cjk(n), n
        assert normalize.norm_name(n) == _norm_name_0129(n), n


def test_norm_name_keeps_japanese_and_strips_legal_forms():
    nn = normalize.norm_name
    # every spelling of one company: prefix or suffix legal form, bracketed abbreviations,
    # half-width katakana
    assert {nn(x) for x in ("アスクル株式会社", "株式会社アスクル", "㈱アスクル", "（株）アスクル", "(株)アスクル",
                            "ｱｽｸﾙ株式会社", "アスクル")} == {"アスクル"}
    assert nn("ＮＴＴデータ") == nn("NTT データ") == nn("NTTデータ株式会社") == "ntt データ"
    assert nn("ソフトバンク・テクノロジー株式会社") == nn("ソフトバンクテクノロジー")
    # Holdings and Group are part of the name in Japanese as in English
    assert nn("アサヒグループホールディングス株式会社") == "アサヒグループホールディングス"
    assert nn("アサヒグループホールディングス") != nn("アサヒグループ")
    # corporation-type prefixes of non-profits and hospitals go; what the organisation is stays
    assert nn("医療法人社団 健康会 さくら病院") == "健康会さくら病院"
    assert nn("一般社団法人日本音楽著作権協会") == "日本音楽著作権協会"
    # voicing marks survive (NFKC recomposes them), hiragana and the iteration mark are kept
    assert nn("ガンホー") == "ガンホー" and nn("みずほ銀行") == "みずほ銀行" and nn("佐々木病院") == "佐々木病院"
    # two Japanese organisations no longer share a normalised name
    assert nn("株式会社ニフティ") != nn("ソースネクスト株式会社") and nn("株式会社ニフティ") != ""
    # English legal words in a mixed name still go, even run into Han characters
    assert nn("ABC Co株式会社") == "abc" and nn("トヨタ Toyota Motor Corp") == "トヨタ toyota motor"
    assert normalize.has_cjk("ｱｽｸﾙ") and normalize.has_cjk("ＮＴＴデータ") and not normalize.has_cjk("NTT Data")


def test_japanese_numbers():
    n = grounding.numbers_in
    assert Decimal(1260000) in n("顧客情報約126万件が流出した")
    assert Decimal(120000000) in n("1億2000万人分")
    assert Decimal(542513) in n("最大54万2513件の情報")
    assert Decimal(22519960) in n("会員情報2,251万9,960件が流出")
    assert Decimal(5310000) in n("5,310,000件") and Decimal(5310000) in n("５３１万件")
    assert Decimal(50000000) in n("身代金5千万円を要求")
    assert Decimal(3000) in n("顧客3千人")
    # English is read exactly as before: no new numbers appear in an English sentence
    assert n("4.2 million patients") == {Decimal("4200000.0")}
    assert n("the 1.5 TB archive of 2,000 files") == {Decimal("1.5"), Decimal(2000)}
    assert 1_500_000_000_000 in grounding.sizes_in("約1.5TB分のデータ")
    assert 2 * 10**12 in grounding.sizes_in("2テラバイトのファイル")


def test_japanese_qualifier_is_read_from_the_sentence():
    q = grounding.ja_qualifier
    assert q("約126万件が漏えいした", 1260000) == "approx"
    assert q("最大54万2513件の情報", 542513) == "at_most"
    assert q("1万人以上の顧客情報", 10000) == "at_least"
    assert q("3万件を超える個人情報", 30000) == "at_least"
    assert q("126万件の個人情報が流出した", 1260000) == "exact"
    assert q("4.2 million patients", 4200000) is None             # English: the model's qualifier stands


def test_japanese_negation_is_clause_local_and_not_fooled_by_nai_words():
    assert grounding.negated("流出は確認されていません。")
    assert grounding.negated("情報の流出はなかった")
    assert grounding.negated("流出していないことを確認した")
    assert grounding.negated("同社は不正アクセスを否定した")
    assert not grounding.negated("個人情報が流出した")
    assert not grounding.negated("被害は少ないとみられる")          # 少ない "few" is not a negation
    assert not grounding.negated("発覚して間もない時期だった")       # 間もない "soon after"
    doc = "顧客約126万人の個人情報が流出し、クレジットカード情報の流出は確認されていない。"
    assert grounding.check("people_affected", 1260000, doc, doc) is None      # negation is in the other clause
    doc2 = "顧客約126万人の個人情報の流出は確認されていない。"
    assert grounding.check("people_affected", 1260000, doc2, doc2) == "negated"


JA_DOC = ("株式会社サンプル物流は2026年10月15日、同社のサーバーがランサムウェアに感染し、ファイルが暗号化されたと発表した。"
          "顧客約126万人の氏名、住所、電話番号が外部に流出した。"
          "クレジットカード情報の流出は確認されていません。"
          "攻撃者は委託先のVPN機器の脆弱性を悪用して侵入したとみられる。"
          "同社によると、社員を装ったフィッシングメールが侵入の起点だった。"
          "コールセンターには問い合わせが1200件寄せられた。"
          "ランサムウェアグループ「Qilin」はリークサイトで、従業員3万人分のデータを盗んだと主張している。"
          "同社は2026年10月13日に不審な通信を検知した。")


def _ja(*facts, org="株式会社サンプル物流", org_en="Sample Butsuryu", more=None):
    incs = [{"organization": org, "organization_en": org_en, "country": "JP",
             "source_of_account": "news", "facts": list(facts)}]
    return {"is_incident_report": True, "incidents": incs + (more or [])}


def test_japanese_facts_pass_the_gate():
    out = _ja(_f("people_affected", 1260000, "顧客約126万人の氏名、住所、電話番号が外部に流出した。", "persons", "exact"),
              _f("data_exfiltrated", True, "顧客約126万人の氏名、住所、電話番号が外部に流出した。"),
              _f("data_types", "氏名、住所、電話番号", "顧客約126万人の氏名、住所、電話番号が外部に流出した。"),
              _f("category", "ransomware", "株式会社サンプル物流は2026年10月15日、同社のサーバーがランサムウェアに感染し、ファイルが暗号化されたと発表した。"),
              _f("vector", "phishing", "同社によると、社員を装ったフィッシングメールが侵入の起点だった。"),
              _f("discovery_date", "2026-10-13", "同社は2026年10月13日に不審な通信を検知した。"),
              _f("data_exfiltrated", False, "クレジットカード情報の流出は確認されていません。"))
    [inc] = extract.validate(out, JA_DOC)
    got = [(c.field, c.reject_reason) for c in inc.candidates]
    assert all(r is None for _, r in got), got
    assert inc.candidates[0].qualifier == "approx"           # 約: the sentence's qualifier, not the model's
    assert inc.organization_en == "Sample Butsuryu"


def test_japanese_negatives_are_rejected():
    out = _ja(
        # the inquiry count is not people and not records
        _f("people_affected", 1200, "コールセンターには問い合わせが1200件寄せられた。", "persons"),
        _f("records_affected", 1200, "コールセンターには問い合わせが1200件寄せられた。", "records"),
        # "not confirmed" negates a leak
        _f("data_exfiltrated", True, "クレジットカード情報の流出は確認されていません。"),
        # "believed to" is not a stated cause
        _f("vector", "vulnerability_exploitation", "攻撃者は委託先のVPN機器の脆弱性を悪用して侵入したとみられる。"),
        # what the gang claims on its leak site is the gang's claim: never a count
        _f("people_affected", 30000, "ランサムウェアグループ「Qilin」はリークサイトで、従業員3万人分のデータを盗んだと主張している。", "persons"))
    reasons = [c.reject_reason for c in extract.validate(out, JA_DOC)[0].candidates]
    assert reasons == ["count_not_of_people", "count_not_of_records", "negated", "hedged",
                       "actor_claim_cannot_supply_count"], reasons


def test_japanese_possibility_and_ceiling_and_part():
    doc = ("サンプル電機は、最大54万2513件の個人情報が漏えいした可能性があると発表した。"
           "サンプル電機によると、情報漏えいの可能性がある。"
           "サンプル百貨店は、会員情報約126万件の一部が漏えいしたと発表した。"
           "このうち、カード情報は3万件だった。")
    out = {"is_incident_report": True, "incidents": [
        {"organization": "サンプル電機", "source_of_account": "news", "facts": [
            _f("records_affected", 542513, "サンプル電機は、最大54万2513件の個人情報が漏えいした可能性があると発表した。", "records"),
            _f("data_exfiltrated", True, "サンプル電機によると、情報漏えいの可能性がある。")]},
        {"organization": "サンプル百貨店", "source_of_account": "news", "facts": [
            _f("records_affected", 1260000, "サンプル百貨店は、会員情報約126万件の一部が漏えいしたと発表した。", "records"),
            _f("records_affected", 30000, "このうち、カード情報は3万件だった。", "records")]}]}
    a, b = extract.validate(out, doc)
    assert [c.reject_reason for c in a.candidates] == ["hypothetical", "hedged"]
    # 126万 is what the store holds, not what leaked; 3万 is a sub-group (and names nobody)
    assert [c.reject_reason for c in b.candidates] == ["partial_count", "partial_count"]


def test_japanese_subject_naming_uses_the_written_name_never_organization_en():
    doc = ("株式会社サンプル物流と株式会社テスト商事は、共同で利用するシステムに不正アクセスがあったと発表した。"
           "サンプル物流では顧客約126万人の個人情報が流出した。"
           "Sample Butsuryu の顧客約2万人の個人情報も流出した。")
    other = {"organization": "株式会社テスト商事", "organization_en": "Test Shoji", "source_of_account": "news", "facts": []}
    out = _ja(_f("people_affected", 1260000, "サンプル物流では顧客約126万人の個人情報が流出した。", "persons"),
              # the sentence names the company only by the model's English name: not evidence
              _f("people_affected", 20000, "Sample Butsuryu の顧客約2万人の個人情報も流出した。", "persons"),
              more=[other])
    a = extract.validate(out, doc)[0]
    assert a.candidates[0].accepted and a.candidates[0].subject_match
    assert a.candidates[1].reject_reason == "subject_not_named"
    assert not extract._names_org("株式会社テスト商事は発表した。", "サンプル物流")


def test_japanese_number_values_and_actor():
    doc = "サンプル製薬は、患者1億2000万人分の診療記録が窃取されたと発表した。ランサムウェアグループ「Qilin」が犯行声明を出した。"
    out = {"is_incident_report": True, "incidents": [{"organization": "サンプル製薬", "source_of_account": "news", "facts": [
        _f("people_affected", 120000000, "サンプル製薬は、患者1億2000万人分の診療記録が窃取されたと発表した。", "persons"),
        _f("actor", "Qilin", "ランサムウェアグループ「Qilin」が犯行声明を出した。"),
        _f("actor", "攻撃者", "ランサムウェアグループ「Qilin」が犯行声明を出した。")]}]}
    c = extract.validate(out, doc)[0].candidates
    assert c[0].accepted and c[0].qualifier == "exact"
    assert c[1].accepted and c[1].basis == "threat_actor_claim"     # 犯行声明 is the gang's own claim
    assert c[2].reject_reason == "value_not_in_quote"


def test_organization_en_is_latin_or_nothing():
    assert extract._english_name("ASKUL Corporation") == "ASKUL Corporation"
    assert extract._english_name("アスクル") is None and extract._english_name("") is None
    assert extract._english_name(None) is None and extract._english_name(42) is None


def test_language_detection():
    assert extract.language(JA_DOC) == "ja"
    assert extract.language(DOC) == "en"
    # any Han or kana sends a document to the Japanese version, which has no active fields (review)
    assert extract.language("某公司遭受勒索软件攻击，导致数据泄露。") == "ja"
    assert extract.language("Acme (アクメ) was breached; the attackers took 2 TB of data from its servers.") == "ja"


def test_prompt_v4_carries_organization_en_and_the_no_translation_rule():
    assert extract.SCHEMA_VERSION == "breach-extract-v4"
    assert '"organization_en"' in extract.SYSTEM and "Never translate" in extract.SYSTEM
    assert "126万" in extract.SYSTEM and "最大" in extract.SYSTEM


def test_japanese_extractor_version_is_separate():
    from zdc_breach import agent_load, run
    assert run.extractor_id("m/x") != run.extractor_id("m/x", "ja") == run.extractor_id("m/x") + ":ja"
    assert agent_load.extractor_id("m", "ja").endswith(":ja")
    # an English gold set cannot switch on the Japanese version (checked before any database call)
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump({"languages": ["en"], "prompt_hash": extract.prompt_hash("m"),
                   "fields": {"people_affected": {"accepted": 9, "correct": 9}}}, fh)
    with pytest.raises(SystemExit, match="documents, not"):
        agent_load.activate(None, "m", ["people_affected"], [fh.name], lang="ja")
    with open(fh.name, "w") as f2:
        json.dump({"prompt_hash": extract.prompt_hash("m"),
                   "fields": {"people_affected": {"accepted": 9, "correct": 9}}}, f2)    # no language: English
    with pytest.raises(SystemExit, match="documents, not"):
        agent_load.activate(None, "m", ["people_affected"], [fh.name], lang="ja")


def test_gold_records_the_language_it_scored():
    from zdc_breach import gold
    out = _ja(_f("people_affected", 1260000, "顧客約126万人の氏名、住所、電話番号が外部に流出した。", "persons"))
    res = gold.score({"d": {"incidents": []}}, {"d": JA_DOC}, {"d": out})
    assert res["languages"] == ["ja"]


RDF = """<?xml version="1.0" encoding="UTF-8" ?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns:dc="http://purl.org/dc/elements/1.1/"
         xmlns="http://purl.org/rss/1.0/">
  <channel rdf:about="https://jp.example/"><title>Example</title><link>https://jp.example/</link></channel>
  <item rdf:about="https://jp.example/article/1.html">
    <title>サンプル物流に不正アクセス、約126万件の会員情報が漏えい</title>
    <link>https://jp.example/article/1.html</link>
    <dc:date>2026-10-19T08:05:25+09:00</dc:date>
  </item>
  <item rdf:about="https://jp.example/article/2.html">
    <title>新製品セミナーのお知らせ</title>
    <link>https://jp.example/article/2.html</link>
    <description>来月開催</description>
    <dc:date>2026-10-19T09:00:00+09:00</dc:date>
  </item>
</rdf:RDF>""".encode()


def test_rss1_rdf_feed_parses():
    items = sources_news.parse_feed("news_jp_x", RDF)
    assert [i.url for i in items] == ["https://jp.example/article/1.html", "https://jp.example/article/2.html"]
    assert items[0].guid == "https://jp.example/article/1.html"
    assert items[0].published_at == datetime(2026, 10, 18, 23, 5, 25, tzinfo=timezone.utc)
    assert [i.relevant for i in items] == [True, False]      # the Japanese prefilter


def test_japanese_feeds_registered_feed_text_only():
    jp = [f for f in sources_news.FEEDS if f.source_id.startswith("news_jp_")]
    assert {f.source_id for f in jp} == {"news_jp_securitynext", "news_jp_scannetsecurity",
                                          "news_jp_cybersecurityjp", "news_jp_itmedia"}
    assert not any(f.fetch_page for f in jp)
    banned = ("news.google.", "bing.com", "news.yahoo.co.jp", "westeria.jp", "legalagent.co.jp", "satimo.org",
              "piyolog", "elkentaro", "jpx.co.jp", "tdnet")
    assert not any(b in f.url for f in sources_news.FEEDS for b in banned)


def test_japanese_title_links_need_a_long_name_and_an_event():
    from zdc_breach import sources_media as sm
    idx = sm.index_names([("v1", "株式会社ニフティ"), ("v2", "トヨタ"), ("v3", "ソースネクスト株式会社"),
                          ("v4", "Change Healthcare"), ("v5", "アスクル")])
    assert sm.JA_KEY + "トヨタ" not in idx                          # three characters: too short to trust
    assert sm.find_in_title("ソースネクストに不正アクセス、会員情報2,251万件が流出した可能性", idx) == ["v3"]
    assert sm.find_in_title("ニフティ、54万件超漏えいの可能性", idx) == ["v1"]
    assert sm.find_in_title("Change Healthcare ransomware attack", idx) == ["v4"]
    assert sm.TITLE_EVENT.search("ニフティ、54万件超漏えいの可能性")
    assert sm.TITLE_EVENT.search("サンプル社でデータ流出")
    assert not sm.TITLE_EVENT.search("人材流出が止まらないアスクル")        # staff leaving is not a breach
    assert not sm.TITLE_EVENT.search("「Fortinet」の脆弱性悪用に注意喚起")    # an advisory, no victim event
    assert sm.matches("ソースネクスト株式会社", "ソースネクストに不正アクセス", "https://x.example/a")
    assert not sm.matches("ソースネクスト株式会社", "ソースネクストが新製品", "https://x.example/a")


# ---- review fixes, 2026-10-19 (each written to fail first) --------------------------------------
def test_english_id_is_not_a_credential_or_account_cue():
    doc = "Hackers used stolen employee ID numbers to get in. The attackers stole ID scans of 5,000 customers."
    out = _out(_f("vector", "stolen_credentials", "Hackers used stolen employee ID numbers to get in."),
               _f("accounts_affected", 5000, "The attackers stole ID scans of 5,000 customers.", "accounts"))
    c = extract.validate(out, doc)[0].candidates
    assert c[0].reject_reason == "vector_cue_missing"
    # accounts_affected never reaches its cue (the gate rejects the field as unknown, as at HEAD),
    # so its cue is checked directly: "ID" must not be an English accounts cue
    assert c[1].reject_reason == "unknown_field"
    assert extract._cued(extract.CUES, extract.CUES_JA, "accounts_affected", "The attackers stole ID scans of 5,000 customers.") is False
    assert extract._cued(extract.CUES, extract.CUES_JA, "accounts_affected", "ID 3万件が流出した") is True


def test_japanese_negations_reviewer_set():
    for q in ("被害は確認されておりません", "不審なファイルは見つかっておりません", "情報の流出は確認されず",
              "同社は流出は無いとした", "流出は確認できていません"):
        assert grounding.negated(q), q


@pytest.mark.parametrize("quote", [
    "顧客約126万人の個人情報が漏えいした恐れがある。",
    "顧客約126万人の個人情報が流出したおそれがある。",
    "顧客約126万人の個人情報が流出したとみられる。",
    "顧客約126万人の個人情報が流出したと思われる。",
    "顧客約126万人の個人情報が流出したとされる。",
    "流出した個人情報は推定126万人分にのぼる。",
    "同社は顧客約126万人の個人情報が流出したとみている。",
    "顧客約126万人について情報流出の有無について調査している。",
])
def test_japanese_hedged_counts_are_rejected(quote):
    [inc] = extract.validate(_ja(_f("people_affected", 1260000, quote, "persons")), quote)
    assert inc.candidates[0].reject_reason == "hedged", inc.candidates[0].reject_reason


@pytest.mark.parametrize("field,value,unit,quote", [
    ("people_affected", 30, "persons", "同社は30人体制で調査を進め、流出の範囲を確認している。"),
    ("people_affected", 5, "persons", "外部専門家5名を交えて流出の経緯を調べている。"),
    ("people_affected", 100, "persons", "従業員100人が在宅勤務中で、流出の影響を調べている。"),
    ("people_affected", 1260000, "persons", "会員数は126万人にのぼり、一部の情報が流出した。"),
    ("people_affected", 1260000, "persons", "同社は会員126万人にメールで通知し、注意を呼びかけた。"),
    ("records_affected", 3, "records", "サーバ3件が不正アクセスを受けた。"),
    ("records_affected", 300, "records", "300件の不審なメールが送信された。"),
    ("records_affected", 1260000, "records", "126万件中20万件の個人情報が流出した。"),
])
def test_japanese_counts_that_are_not_the_victims(field, value, unit, quote):
    [inc] = extract.validate(_ja(_f(field, value, quote, unit)), quote)
    assert not inc.candidates[0].accepted, (quote, inc.candidates[0].reject_reason)


def test_japanese_attacker_statements_are_claims_but_a_company_statement_is_not():
    a = "犯行グループは、従業員3万人分のデータを盗んだとしている。"
    b = "ハッカー集団は3万人分の情報を入手したと声明を出した。"
    c = "同社は、顧客約126万人の個人情報が流出したとしている。"
    for q in (a, b):
        [inc] = extract.validate(_ja(_f("people_affected", 30000, q, "persons")), q)
        assert inc.candidates[0].basis == "threat_actor_claim", q
        assert inc.candidates[0].reject_reason == "actor_claim_cannot_supply_count"
    assert not extract.actor_claim(c)


def test_japanese_category_negation():
    q = "同社によると、今回の障害はランサムウェアの被害ではない。"
    [inc] = extract.validate(_ja(_f("category", "ransomware", q)), q)
    assert inc.candidates[0].reject_reason == "negated"


def test_japanese_names_must_end_at_a_word_boundary():
    from zdc_breach import sources_media as sm
    idx = sm.index_names([("v1", "日本航空"), ("v2", "アスクル")])
    assert sm.find_in_title("日本航空電子工業に不正アクセス", idx) == []
    assert sm.find_in_title("全日本航空に不正アクセス", idx) == []
    assert sm.find_in_title("日本航空に不正アクセス、情報流出", idx) == ["v1"]       # a particle may follow
    assert sm.find_in_title("アスクルロジストでランサムウェア被害", idx) == []
    assert not extract._names_org("日本航空電子工業は不正アクセスを受けた。", "日本航空")
    assert extract._names_org("日本航空は不正アクセスを受けた。", "日本航空")


def test_language_is_japanese_for_any_han_or_kana_or_a_japanese_feed():
    assert extract.language("Acme (アクメ) was breached; the attackers took 2 TB of data.") == "ja"
    assert extract.language("某公司遭受勒索软件攻击。") == "ja"
    assert extract.language("Plain English text about a breach.", "news_jp_itmedia") == "ja"
    assert extract.language("Plain English text about a breach.", "news_therecord") == "en"


def test_bare_thousand_counts():
    assert Decimal(1000) in grounding.numbers_in("顧客千人分の情報が流出した")
    assert Decimal(1000) in grounding.numbers_in("千件の個人情報")
    assert Decimal(1000) not in grounding.numbers_in("数千件の個人情報")
    assert Decimal(1000) not in grounding.numbers_in("五千人の情報")


def test_organization_en_is_a_match_key_only_when_the_document_writes_it():
    doc = "トヨタ紡織株式会社は、サーバーがランサムウェアに感染したと発表した。顧客約2万人の個人情報が流出した。"
    out = {"is_incident_report": True, "incidents": [{"organization": "トヨタ紡織株式会社", "organization_en": "Toyota",
                                                      "source_of_account": "news", "facts": []}]}
    [inc] = extract.validate(out, doc)
    assert inc.organization_en == "Toyota" and not inc.organization_en_in_text
    doc2 = doc + "Toyota Boshoku (トヨタ紡織) said the attack began on Monday."
    out["incidents"][0]["organization_en"] = "TOYOTA BOSHOKU"
    [inc] = extract.validate(out, doc2)
    assert inc.organization_en_in_text                       # case-insensitive for Latin


def test_titles_only_feed_is_never_extracted():
    scan = next(f for f in sources_news.FEEDS if f.source_id == "news_jp_scannetsecurity")
    assert scan.extract is False and all(f.extract for f in sources_news.FEEDS if f is not scan)


def test_gold_activation_refuses_another_prompt():
    from zdc_breach import agent_load, gold
    import tempfile
    res = gold.score({}, {}, {}, prompt_hash=extract.prompt_hash("m"))
    assert res["prompt_hash"] == extract.prompt_hash("m")
    for sc in ({"languages": ["en"], "prompt_hash": "deadbeef", "fields": {"x": {"accepted": 9, "correct": 9}}},
               {"languages": ["en"], "fields": {"x": {"accepted": 9, "correct": 9}}}):          # legacy: no hash
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(sc, fh)
        with pytest.raises(SystemExit, match="scored prompt"):
            agent_load.activate(None, "m", ["x"], [fh.name])
