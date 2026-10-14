"""Integration tests: the breach pipeline end to end against the migrated schema.

Gated on BREACH_TEST_DATABASE_URL (CI points it at the throwaway Postgres every migration was
applied to). Network and model are faked; everything else - SQL, constraints, views - is real.
"""

from __future__ import annotations

import json
import os
from argparse import Namespace
from datetime import datetime, timedelta, timezone

import pytest

psycopg = pytest.importorskip("psycopg")
DSN = os.environ.get("BREACH_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DSN, reason="BREACH_TEST_DATABASE_URL not set")

from zdc_breach import llm as llm_mod  # noqa: E402
from zdc_breach import run as brun  # noqa: E402
from zdc_breach.http import Fetched  # noqa: E402

NOW = datetime.now(timezone.utc)
D = lambda days: (NOW - timedelta(days=days))  # noqa: E731

RANSOMLOOK = [{"post_title": "acmewidgets.example", "discovered": D(1).strftime("%Y-%m-%d %H:%M:%S.%f"),
               "group_name": "Qilin", "misp_uuid": "rl-1"}]
RANSOMFEED = [
    {"id": 1, "date": D(1).strftime("%Y-%m-%d %H:%M:%S"), "victim": "Acme Widgets", "gang": "Qilin",
     "hash": "rf-1", "country": "United States", "website": "acmewidgets.example", "work_sector": "Manufacturing"},
    {"id": 2, "date": D(2).strftime("%Y-%m-%d %H:%M:%S"), "victim": "Acme Widgets", "gang": "Akira",
     "hash": "rf-2", "country": "United States", "website": "acmewidgets.example"},
    {"id": 3, "date": D(1).strftime("%Y-%m-%d %H:%M:%S"), "victim": "Only Claimed GmbH", "gang": "Akira",
     "hash": "rf-3", "country": "Germany", "website": "onlyclaimed.example"},
]
WA = [
    {"name": "Twin Filing Corp", "id": "w1", "datesubmitted": D(20).strftime("%Y-%m-%dT00:00:00.000"),
     "datestart": "2026-08-01T00:00:00.000", "washingtoniansaffected": "900",
     "databreachcause": "Cyberattack", "cyberattacktype": "Phishing"},
    {"name": "Near Date Inc", "id": "w2", "datesubmitted": D(20).strftime("%Y-%m-%dT00:00:00.000"),
     "datestart": "2026-08-01T00:00:00.000", "washingtoniansaffected": "700",
     "databreachcause": "Cyberattack", "cyberattacktype": "Ransomware"},
]
CA = ("﻿Organization Name,Date(s) of Breach  (if known),Reported Date\n"
      f"Twin Filing Corp.,08/01/2026,{D(18).strftime('%m/%d/%Y')}\n"
      f"Near Date Inc,08/09/2026,{D(18).strftime('%m/%d/%Y')}\n")
HIBP = [{"Name": "AcmeWidgets", "Title": "Acme Widgets", "Domain": "acmewidgets.example",
         "BreachDate": D(3).date().isoformat(), "AddedDate": D(1).strftime("%Y-%m-%dT%H:%M:%SZ"),
         "PwnCount": 120000, "DataClasses": ["Email addresses", "Passwords"]}]
EFTS = {"hits": {"hits": [
    {"_id": "0009-26-1:a8k.htm", "_source": {"display_names": ["Widget Holdings Inc  (WDGT)  (CIK 0000999999)"],
     "file_date": D(2).date().isoformat(), "period_ending": D(4).date().isoformat(), "adsh": "0009-26-1",
     "items": ["1.05", "9.01"], "biz_states": ["DE"]}}]}}
FILING = ("<html><body><p>On September 30, 2026, Widget Holdings Inc identified unauthorized access to its "
          "network. The threat actor exploited CVE-2026-40404 in a remote access appliance to gain initial access. "
          "The company has notified approximately 52,000 individuals whose information was involved.</p></body></html>")
FEED = f"""<rss><channel>
<item><title>Acme Widgets confirms ransomware attack</title><link>https://news.example/acme</link>
<guid>g-acme</guid><pubDate>{NOW.strftime('%a, %d %b %Y %H:%M:%S +0000')}</pubDate>
<description>Acme Widgets said in a statement that attackers demanded a $2 million ransom, which the company refused to pay. The attackers gained access through a phishing email sent to an employee in the finance team last month.</description></item>
<item><title>A new laptop review</title><link>https://news.example/laptop</link><guid>g-lap</guid>
<description>Fast.</description></item>
</channel></rss>"""


def payload_for(url: str):
    if "ransomlook" in url:
        return json.dumps(RANSOMLOOK).encode()
    if "ransomfeed" in url:
        return json.dumps(RANSOMFEED).encode()
    if "data.wa.gov" in url:
        return json.dumps(WA).encode()
    if "oag.ca.gov" in url:
        return CA.encode()
    if "haveibeenpwned" in url:
        return json.dumps(HIBP).encode()
    if "efts.sec.gov" in url:
        return json.dumps(EFTS if "forms=8-K&" in url else {"hits": {"hits": []}}).encode()
    if "sec.gov/Archives" in url:
        return FILING.encode()
    if "hipaajournal" in url:
        return FEED.encode()
    return None


def fake_get(url, **kw):
    body = payload_for(url)
    return Fetched(url, 200 if body is not None else 404, body or b"", None if body is not None else "HTTP 404",
                   NOW, NOW, {})


class FakeLLM:
    """Answers like the model would for the two documents in the fixtures."""

    def __init__(self, spent=0.0):
        self.calls = 0
        self.spent_month = spent
        self.spent_today = spent

    def json(self, system, user, **kw):
        if self.spent_month >= llm_mod.MONTHLY_CAP_USD:
            raise llm_mod.BudgetExceeded("monthly cap")
        self.calls += 1
        if "Widget Holdings" in user:
            data = {"is_incident_report": True, "incidents": [{"organization": "Widget Holdings Inc",
                    "source_of_account": "regulator_filing", "facts": [
                        {"field": "cve_id", "value": "CVE-2026-40404", "unit": "none", "qualifier": "exact",
                         "cve_role": "initial_access",
                         "quote": "The threat actor exploited CVE-2026-40404 in a remote access appliance to gain initial access."},
                        {"field": "people_affected", "value": 52000, "unit": "persons", "qualifier": "approx",
                         "quote": "The company has notified approximately 52,000 individuals whose information was involved."},
                        {"field": "people_affected", "value": 99000, "unit": "persons", "qualifier": "exact",
                         "quote": "The company has notified approximately 99,000 individuals."}]}]}
        else:
            data = {"is_incident_report": True, "incidents": [{"organization": "Acme Widgets",
                    "domain": "acmewidgets.example", "source_of_account": "victim_statement", "facts": [
                        {"field": "ransom_demand_amount", "value": 2000000, "unit": "money", "qualifier": "exact",
                         "currency": "USD", "money_kind": "demand_initial",
                         "quote": "Acme Widgets said in a statement that attackers demanded a $2 million ransom, which the company refused to pay."},
                        {"field": "vector", "value": "phishing", "unit": "none", "qualifier": "not_applicable",
                         "quote": "The attackers gained access through a phishing email sent to an employee in the finance team last month."}]}]}
        return llm_mod.LlmResult(True, data, "fake/model", "fake", 100, 50, 0.0001, 5, None)


class NoFx:
    def usd_rate(self, currency, on):
        return (1, on, "identity") if currency == "USD" else None


SOURCES = "ransomlook,ransomfeed,wa_ag,ca_ag,hibp,sec_8k,news_hipaajournal,extract"


def args(**kw):
    a = dict(sources=SOURCES, force=True, max_docs=10, sec_days=3, trigger="test", dry_run=False, report=None,
             max_apply=2000)
    a.update(kw)
    return Namespace(**a)


@pytest.fixture()
def conn():
    c = psycopg.connect(DSN, autocommit=False)
    with c.cursor() as cur:
        cur.execute("""truncate breach_core.claims, breach_core.incident_cves, breach_core.incident_facts,
                       breach_core.incident_sources, breach_core.match_overrides, breach_core.takedown_requests,
                       breach_core.leak_claims, breach_core.extractions, breach_core.llm_calls,
                       breach_core.incidents, breach_core.organizations, breach_core.source_state,
                       breach_raw.documents, breach_raw.source_records, breach_raw.fetches cascade""")
        cur.execute("delete from breach_core.extractor_versions where kind = 'llm'")
    c.commit()
    yield c
    c.close()


def q(conn, sql, *p):
    with conn.cursor() as cur:
        cur.execute(sql, p)
        return cur.fetchall()


def activate(conn):
    with conn.cursor() as cur:
        cur.execute("""update breach_core.extractor_versions set gold = '{"test": true}', active = true,
                               active_fields = '{people_affected,cve_id,vector,ransom_demand_amount}'
                        where kind = 'llm'""")
    conn.commit()


def test_end_to_end(conn):
    rep = brun.run(conn, args(), getter=fake_get, llm=FakeLLM(), fx=NoFx())
    assert rep["ok"], [e for e in rep["evals"] if not e["passed"]]
    # leak posts: RansomLook and RansomFeed saw the same Qilin post -> one claim, two trackers;
    # Akira naming the same victim is a second claim, never merged into the first.
    claims = q(conn, "select actor_group, trackers from breach_core.leak_claims order by actor_group, first_seen_at")
    assert ("qilin", ["ransomfeed", "ransomlook"]) in claims
    assert sum(1 for g, _ in claims if g == "akira") == 2
    # only filed or confirmed incidents are public; a claimed-only victim never is
    public = {r[0] for r in q(conn, "select organization from public.breach_incidents")}
    assert "Only Claimed GmbH" not in public and "Twin Filing Corp" in public
    assert not q(conn, "select 1 from public.breach_leak_claims_monthly where actor_group = 'only claimed gmbh'")


def test_same_event_date_merges_near_date_links(conn):
    brun.run(conn, args(sources="wa_ag,ca_ag"), getter=fake_get, llm=None, fx=NoFx())
    twin = q(conn, """select count(distinct i.incident_id), count(distinct s.source_id)
                        from breach_core.incidents i join breach_core.organizations o using (org_id)
                        join breach_core.incident_sources s using (incident_id) where o.norm_name = 'twin filing'""")
    assert twin == [(1, 2)]
    near = q(conn, """select count(*), count(possible_duplicate_of) from breach_core.incidents i
                        join breach_core.organizations o using (org_id) where o.norm_name = 'near date'""")
    assert near == [(2, 1)]


def test_llm_facts_hidden_until_extractor_active(conn):
    brun.run(conn, args(), getter=fake_get, llm=FakeLLM(), fx=NoFx())
    sec = q(conn, """select f.people_affected, f.cve_ids from breach_core.incident_facts f
                       join breach_core.incidents i using (incident_id) join breach_core.organizations o using (org_id)
                      where o.sec_cik = '999999'""")
    assert sec == [(None, None)]
    activate(conn)
    with conn.cursor() as cur:
        from zdc_breach import reconcile
        reconcile.build(cur)
    conn.commit()
    sec = q(conn, """select f.people_affected, f.people_qualifier::text from breach_core.incident_facts f
                       join breach_core.incidents i using (incident_id) join breach_core.organizations o using (org_id)
                      where o.sec_cik = '999999'""")
    assert sec == [(52000, "approx")]           # the invented 99,000 failed the evidence gate
    assert q(conn, "select cve_id, role::text from breach_core.incident_cves") == [("CVE-2026-40404", "initial_access")]
    rejected = q(conn, "select reject_reason from breach_core.claims where not accepted")
    assert ("quote_not_in_document",) in rejected


def test_news_alone_does_not_publish_but_attaches_by_domain(conn):
    brun.run(conn, args(), getter=fake_get, llm=FakeLLM(), fx=NoFx())
    activate(conn)
    acme = q(conn, """select i.media_reported, i.victim_confirmed, i.actor_claimed
                        from breach_core.incidents i join breach_core.organizations o using (org_id)
                       where o.domain = 'acmewidgets.example' order by i.first_public_date""")
    assert acme and all(r[0] or r[2] for r in acme)
    # the article's 'said in a statement' is not trusted while the extractor is inactive
    assert not any(r[1] for r in acme)
    assert not q(conn, "select 1 from public.breach_incidents where domain = 'acmewidgets.example'")


def test_second_run_changes_nothing_and_facts_are_deterministic(conn):
    brun.run(conn, args(), getter=fake_get, llm=FakeLLM(), fx=NoFx())
    activate(conn)
    snap = lambda: q(conn, """select incident_id::text, coalesce(people_affected::text,''), coalesce(vector,''),
                                     coalesce(ransom_demand_usd::text,''), n_sources from breach_core.incident_facts order by 1""")
    counts = lambda: q(conn, """select (select count(*) from breach_core.incidents), (select count(*) from breach_core.claims),
                                       (select count(*) from breach_core.leak_claims), (select count(*) from breach_raw.source_records)""")
    fake = FakeLLM()
    brun.run(conn, args(), getter=fake_get, llm=fake, fx=NoFx())
    first_facts, first_counts = snap(), counts()
    brun.run(conn, args(), getter=fake_get, llm=fake, fx=NoFx())
    assert snap() == first_facts and counts() == first_counts
    assert fake.calls == 0      # every document already extracted by this version


def test_budget_stops_extraction(conn):
    fake = FakeLLM(spent=llm_mod.MONTHLY_CAP_USD)
    rep = brun.run(conn, args(), getter=fake_get, llm=fake, fx=NoFx())
    assert fake.calls == 0 and rep["llm"]["budget_stopped"]
    assert any(e["name"] == "llm_budget" and not e["passed"] for e in rep["evals"])
    assert rep["ok"]            # a WARN, not a failed run: the structured sources still landed


def test_suppression_removes_everywhere(conn):
    brun.run(conn, args(sources="wa_ag,ca_ag"), getter=fake_get, llm=None, fx=NoFx())
    with conn.cursor() as cur:
        cur.execute("""update breach_core.incidents set suppressed = true, suppression_reason = 'test'
                        where org_id in (select org_id from breach_core.organizations where norm_name = 'twin filing')""")
    conn.commit()
    brun.run(conn, args(sources="wa_ag"), getter=fake_get, llm=None, fx=NoFx())
    assert not q(conn, "select 1 from public.breach_incidents where organization like 'Twin Filing%%'")
    assert not q(conn, """select 1 from breach_core.incident_facts f join breach_core.incidents i using (incident_id)
                           where i.suppressed""")


def test_report_carries_no_victim_names(conn):
    rep = brun.run(conn, args(), getter=fake_get, llm=FakeLLM(), fx=NoFx())
    text = json.dumps(rep, default=str)
    for name in ("Acme", "Twin Filing", "Only Claimed", "Widget Holdings", "Near Date"):
        assert name not in text


def test_dry_run_writes_nothing(conn):
    brun.run(conn, args(dry_run=True), getter=fake_get, llm=FakeLLM(), fx=NoFx())
    assert q(conn, "select count(*) from breach_core.incidents") == [(0,)]
    assert q(conn, "select count(*) from breach_raw.fetches") == [(0,)]


def test_actor_attaches_only_by_domain(conn):
    brun.run(conn, args(), getter=fake_get, llm=FakeLLM(), fx=NoFx())
    # HIBP indexed acmewidgets.example; the Qilin and Akira claims share that domain
    actors = q(conn, """select distinct c.value_text from breach_core.claims c
                          join breach_core.incidents i using (incident_id) join breach_core.organizations o using (org_id)
                         where c.field = 'actor' and c.basis = 'threat_actor_claim' and o.domain = 'acmewidgets.example'""")
    assert {a for (a,) in actors} == {"qilin", "akira"}
    # the name-only German victim has no organisation to attach to
    assert q(conn, "select incident_id from breach_core.leak_claims where victim_domain = 'onlyclaimed.example'") == [(None,)]


def test_first_fill_is_spread_over_runs(conn):
    brun.run(conn, args(sources="ca_ag", max_apply=1), getter=fake_get, llm=None, fx=NoFx())
    assert q(conn, "select count(*) from breach_raw.source_records where source_id = 'ca_ag'") == [(1,)]
    brun.run(conn, args(sources="ca_ag", max_apply=1), getter=fake_get, llm=None, fx=NoFx())
    assert q(conn, "select count(*) from breach_raw.source_records where source_id = 'ca_ag'") == [(2,)]
    brun.run(conn, args(sources="ca_ag", max_apply=1), getter=fake_get, llm=None, fx=NoFx())
    assert q(conn, "select count(*) from breach_raw.source_records where source_id = 'ca_ag'") == [(2,)]
