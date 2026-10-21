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
# atg.wa.gov's list (R4): the data types for "Twin Filing Corp", and a notice no dataset row carries.
from test_wa_site import page as wa_page, row as wa_row  # noqa: E402

WA_SITE = [wa_page([wa_row("Twin Filing Corp", D(20).strftime("%m/%d/%Y"), "08/01/2026", "900",
                           "Name; Social Security Number; Unknown", pdf="A9001"),
                    wa_row("Zz Unfiled Clinic", D(25).strftime("%m/%d/%Y"), "", "650", "Medical Information",
                           pdf="A9000")])]
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
    if "atg.wa.gov" in url:
        return WA_SITE[0].encode()
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
             max_apply=2000, deadline_minutes=15)
    a.update(kw)
    return Namespace(**a)


@pytest.fixture()
def conn():
    c = psycopg.connect(DSN, autocommit=False)
    with c.cursor() as cur:
        cur.execute("""truncate breach_core.claims, breach_core.incident_cves, breach_core.incident_facts, breach_core.cve_links,
                       breach_core.source_pii_hashes,
                       breach_core.incident_sources, breach_core.match_overrides, breach_core.takedown_requests,
                       breach_core.leak_claims, breach_core.extractions, breach_core.llm_calls,
                       breach_core.incidents, breach_core.organizations, breach_core.source_state,
                       breach_raw.documents, breach_raw.source_records, breach_raw.fetches cascade""")
        cur.execute("delete from breach_core.extractor_versions where kind = 'llm'")
        cur.execute("update breach_core.sources set publication = 'private' where source_id = 'cra_export'")
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
    # 0105: every victim is named with its status; a leak-only victim appears as a claim
    public = dict(q(conn, "select organization, status from public.breach_incidents"))
    assert public["Twin Filing Corp"] == "filed_with_regulator"
    leak = dict(q(conn, "select victim_name, status from public.breach_leak_victims"))
    assert leak["Only Claimed GmbH"] == "claimed_by_attackers"


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


def test_news_alone_never_confirms(conn):
    brun.run(conn, args(), getter=fake_get, llm=FakeLLM(), fx=NoFx())
    activate(conn)
    acme = q(conn, """select i.media_reported, i.victim_confirmed, i.actor_claimed
                        from breach_core.incidents i join breach_core.organizations o using (org_id)
                       where o.domain = 'acmewidgets.example' order by i.first_public_date""")
    assert acme and all(r[0] or r[2] for r in acme)
    # an article never sets victim_confirmed (advisor review 2); the incident is public with the
    # status the evidence supports (0105), never "confirmed"
    assert not any(r[1] for r in acme)
    statuses = {r[0] for r in q(conn, "select status from public.breach_incidents where domain = 'acmewidgets.example'")}
    assert statuses and "confirmed_by_victim" not in statuses


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


def test_deadline_skips_remaining_work_but_finishes(conn):
    rep = brun.run(conn, args(deadline_minutes=-1), getter=fake_get, llm=FakeLLM(), fx=NoFx())
    assert all(v.get("skipped") == "run deadline" for v in rep["sources"].values())
    assert "ok" in rep and rep["evals"]


def test_human_review_publishes_one_fact(conn):
    brun.run(conn, args(), getter=fake_get, llm=FakeLLM(), fx=NoFx())
    cve = q(conn, """select c.claim_id from breach_core.claims c join breach_core.incidents i using (incident_id)
                      join breach_core.organizations o using (org_id)
                     where o.sec_cik = '999999' and c.field = 'cve_id' and c.accepted""")[0][0]
    in_registry(conn, "CVE-2026-40404")
    with conn.cursor() as cur:
        cur.execute("""update breach_core.claims set review_verdict = 'confirmed', reviewer = 'test', reviewed_at = now()
                        where claim_id = %s""", (cve,))
        from zdc_breach import reconcile
        reconcile.build(cur)
        cur.execute("select breach_core.rebuild_victims_list()")
    conn.commit()
    facts = q(conn, """select f.people_affected from breach_core.incident_facts f
                         join breach_core.incidents i using (incident_id) join breach_core.organizations o using (org_id)
                        where o.sec_cik = '999999'""")
    assert facts == [(None,)]                        # the unreviewed count stays private
    # the reviewed CVE is public through the one gate (0137), on the row and in the Explorer's view alike
    assert q(conn, "select cve_ids from public.breach_victims where name like 'Widget Holdings%%'") == [(["CVE-2026-40404"],)]
    assert q(conn, """select l.cve_id, l.role::text, l.name from public.breach_cve_links l""") == [
        ("CVE-2026-40404", "initial_access", "Widget Holdings Inc")]


# ---- Japanese coverage (0130) ------------------------------------------------------------------
JA_FEED = f"""<rss version="2.0"><channel>
<item><title>サンプル物流にランサムウェア攻撃、顧客約126万人の情報が流出</title>
<link>https://jp.example/news/1</link><guid>jp-1</guid><pubDate>{NOW.strftime('%a, %d %b %Y %H:%M:%S +0000')}</pubDate>
<description>株式会社サンプル物流は、同社のサーバーがランサムウェアに感染したと発表した。顧客約126万人の氏名、住所、電話番号が外部に流出した。</description></item>
</channel></rss>"""
JA_QUOTE = "顧客約126万人の氏名、住所、電話番号が外部に流出した。"


def fake_get_ja(url, **kw):
    if "itmedia" in url:
        return Fetched(url, 200, JA_FEED.encode(), None, NOW, NOW, {})
    return fake_get(url, **kw)


class FakeLLMJa(FakeLLM):
    def json(self, system, user, **kw):
        if "サンプル物流" not in user:
            return super().json(system, user, **kw)
        self.calls += 1
        data = {"is_incident_report": True, "incidents": [{
            "organization": "株式会社サンプル物流", "organization_en": "Sample Butsuryu Holdings", "country": "Japan",
            "source_of_account": "news", "facts": [
                {"field": "people_affected", "value": 1260000, "unit": "persons", "qualifier": "exact", "quote": JA_QUOTE}]}]}
        return llm_mod.LlmResult(True, data, "fake/model", "fake", 100, 50, 0.0001, 5, None)


def in_registry(conn, *cves):
    """The link gate requires the CVE in the registry (0137 rule 4); fixture CVEs are added once."""
    with conn.cursor() as cur:
        for c in cves:
            cur.execute("insert into core.cves (cve_id, cve_year) values (%s, %s) on conflict do nothing", (c, int(c[4:8])))
    conn.commit()


def test_incident_cves_name_their_claim(conn):
    """0138: run.py writes claim_id. Without it the link has no quote, document or verdict behind it and is
    never built at all (0137 T4)."""
    brun.run(conn, args(), getter=fake_get, llm=FakeLLM(), fx=NoFx())
    rows = q(conn, """select ic.cve_id, c.field, upper(c.value_text), c.quote is not null from breach_core.incident_cves ic
                        join breach_core.claims c on c.claim_id = ic.claim_id""")
    assert rows == [("CVE-2026-40404", "cve_id", "CVE-2026-40404", True)]
    assert q(conn, "select count(*) from breach_core.cve_links") == [(1,)]


def test_mentioned_cve_never_reaches_the_list(conn):
    """A CVE the extractor files as merely mentioned stays held (mentioned_only) even when its claim is
    confirmed by a person and the extractor is active for cve_id."""
    in_registry(conn, "CVE-2026-40404")
    brun.run(conn, args(), getter=fake_get, llm=FakeLLM(), fx=NoFx())
    activate(conn)
    with conn.cursor() as cur:
        cur.execute("update breach_core.incident_cves set role = 'mentioned'")
        cur.execute("""update breach_core.claims set review_verdict = 'confirmed', reviewer = 'test', reviewed_at = now()
                        where field = 'cve_id'""")
        cur.execute("select breach_core.rebuild_victims_list()")
    conn.commit()
    assert q(conn, "select public, hold_reason from breach_core.cve_links") == [(False, "mentioned_only")]
    assert q(conn, "select count(*) from breach_core.victims_list where cve_ids is not null") == [(0,)]
    assert q(conn, "select count(*) from public.breach_cve_links") == [(0,)]


def test_hourly_run_evals_cover_the_links(conn):
    """The hourly run carries the link evals and they pass on a consistent build."""
    in_registry(conn, "CVE-2026-40404")
    rep = brun.run(conn, args(), getter=fake_get, llm=FakeLLM(), fx=NoFx())
    names = {e["name"]: e for e in rep["evals"]}
    for n in ("cve_links_current", "cve_links_one_view", "cve_links_have_evidence", "no_machine_link_public_ungated",
              "cve_links_no_pii", "cve_links_held", "cve_extraction_recall_vs_export"):
        assert names[n]["passed"], names[n]
    assert names["cve_links_held"]["detail"]["by_reason"] == {"extractor_inactive": {"links": 1, "cves": 1}}


def test_norm_name_sql_twin_matches_python(conn):
    """breach_core.norm_name_cjk() re-normalised the stored rows in 0130; it must agree with the
    Python normaliser on every name with Han or kana, and leave every other name alone (NULL)."""
    from zdc_breach.normalize import has_cjk, norm_name
    names = ["アスクル株式会社", "株式会社アスクル", "㈱アスクル", "（株）アスクル", "ｱｽｸﾙ", "ＮＴＴデータ", "NTT データ",
             "ソフトバンク・テクノロジー株式会社", "アサヒグループホールディングス株式会社", "一般社団法人 日本音楽著作権協会",
             "医療法人社団 健康会 さくら病院", "ABC Co株式会社", "トヨタ Toyota Motor Corp", "Søren株式会社", "Café株式会社",
             "Ｈ２Ｏ　リテイリング", "エイチ・ツー・オー リテイリング株式会社", "みずほ銀行", "佐々木病院", "ガンホー",
             "AT&T ジャパン合同会社", "S.p.A. イタリア支社", "the サンプル L.L.C.", "サンプル(有)", "東京大学", "𠮷野家",
             "Acme, Inc.", "Société Générale", "삼성전자", ""]
    with conn.cursor() as cur:
        for n in names:
            cur.execute("select breach_core.norm_name_cjk(%s)", (n,))
            got = cur.fetchone()[0]
            assert got == (norm_name(n) if has_cjk(n) else None), (n, got, norm_name(n))


def test_japanese_document_extracts_under_its_own_version_and_stays_private(conn):
    rep = brun.run(conn, args(sources="news_jp_itmedia,extract"), getter=fake_get_ja, llm=FakeLLMJa(), fx=NoFx())
    assert rep["sources"]["news_jp_itmedia"].get("documents") == 1, rep["sources"]
    [(ext,)] = q(conn, "select extractor_id from breach_core.extractions")
    assert ext.endswith(":ja")
    # the organisation keeps its Japanese name; the English name the model gave is stored, but the
    # article never writes it, so it is not a match key
    [(nn, aliases, alias_norms, ctry)] = q(conn, "select norm_name, aliases, alias_norms, country from breach_core.organizations")
    assert nn == "サンプル物流" and aliases == ["Sample Butsuryu Holdings"] and alias_norms == []
    assert q(conn, "select accepted, qualifier::text from breach_core.claims where field = 'people_affected'") == [(True, "approx")]
    # every English version activated: the Japanese fact stays private
    with conn.cursor() as cur:
        cur.execute("""update breach_core.extractor_versions set gold = '{"test": true}', active = true,
                               active_fields = '{people_affected}' where kind = 'llm' and extractor_id not like '%%:ja'""")
        from zdc_breach import reconcile
        reconcile.build(cur)
    conn.commit()
    assert q(conn, "select people_affected from breach_core.incident_facts") == [(None,)]
    # ... until the Japanese version itself is activated
    with conn.cursor() as cur:
        cur.execute("""update breach_core.extractor_versions set gold = '{"test": true}', active = true,
                               active_fields = '{people_affected}' where extractor_id like '%%:ja'""")
        reconcile.build(cur)
    conn.commit()
    assert q(conn, "select people_affected from breach_core.incident_facts") == [(1260000,)]


def test_alias_finds_the_same_organisation_across_languages(conn):
    from zdc_breach import resolve
    with conn.cursor() as cur:
        ja, how = resolve.find_or_create_org(cur, name="株式会社サンプル物流", country="JP", name_en="Sample Butsuryu",
                                             name_en_in_text=True)
        assert how == "new"
        # a later English report finds it through the alias, as a NAME match (same country rule)
        assert resolve.find_or_create_org(cur, name="Sample Butsuryu Co., Ltd.", country="JP") == (ja, "name")
        assert resolve.find_or_create_org(cur, name="Sample Butsuryu", country="US")[1] == "new"
        # a Japanese report naming it differently in Japanese still finds it by the English name
        assert resolve.find_or_create_org(cur, name="サンプル・ブツリュウ", country="JP", name_en="Sample Butsuryu",
                                          name_en_in_text=True) == (ja, "name_en")
        # the same alias, not written in that article, finds nothing
        assert resolve.find_or_create_org(cur, name="サンプル・ブツリュウ二", country="JP",
                                          name_en="Sample Butsuryu")[1] == "new"
        # an English-named organisation never takes an alias: "Change Healthcare" is not "UnitedHealth"
        en, _ = resolve.find_or_create_org(cur, name="Change Healthcare", country="US", name_en="UnitedHealth Group")
        cur.execute("select aliases from breach_core.organizations where org_id = %s", (en,))
        assert cur.fetchone()[0] == []
        assert resolve.find_or_create_org(cur, name="UnitedHealth Group", country="US")[1] == "new"
        # the batched resolver makes the same decision
        r = resolve.Resolver(cur)
        assert r.org(name="Sample Butsuryu", country="JP") == (ja, "name")
    conn.rollback()


# ---- review fixes, 2026-10-19 ------------------------------------------------------------------
def test_leak_claims_with_an_empty_normalised_name_never_merge(conn):
    """Korean, Cyrillic, Greek and Arabic names still normalise to "": two different victims of
    one group must stay two claims (an empty name matched every other empty name)."""
    from zdc_breach import db as bdb
    from zdc_breach.sources_leak import LeakPost
    posts = [LeakPost("ransomfeed", "k-1", "qilin", "가나다 병원", None, "KR", None, D(2), {}),
             LeakPost("ransomfeed", "k-2", "qilin", "라마바 은행", None, "KR", None, D(2), {}),
             LeakPost("ransomfeed", "k-3", "qilin", "가나다 병원", None, "KR", None, D(1), {})]
    with conn.cursor() as cur:
        bdb.upsert_leak_posts(cur, posts)
    conn.commit()
    got = q(conn, "select victim_name, jsonb_array_length(tracker_refs) from breach_core.leak_claims order by 1")
    assert got == [("가나다 병원", 2), ("라마바 은행", 1)], got


def test_organization_en_not_written_in_the_document_is_never_a_key(conn):
    from zdc_breach import resolve
    with conn.cursor() as cur:
        # the model's "Toyota" for トヨタ紡織, a name the article never writes: stored, not a key
        sub, _ = resolve.find_or_create_org(cur, name="トヨタ紡織株式会社", country="JP", name_en="Toyota")
        cur.execute("select aliases, alias_norms from breach_core.organizations where org_id = %s", (sub,))
        assert cur.fetchone() == (["Toyota"], [])
        assert resolve.find_or_create_org(cur, name="Toyota", country="JP")[1] == "new"
        assert resolve.Resolver(cur).org(name="Toyota Motor", country="JP")[1] == "new"
        # an alias written in the article is a key
        ja, _ = resolve.find_or_create_org(cur, name="アスクル株式会社", country="JP", name_en="ASKUL Corporation",
                                           name_en_in_text=True)
        assert resolve.find_or_create_org(cur, name="ASKUL", country="JP") == (ja, "name")
        # a Latin-named organisation found by domain takes no alias at all
        en, _ = resolve.find_or_create_org(cur, name="Example Logistics", domain="example-logi.example", country="JP")
        resolve.find_or_create_org(cur, name="サンプル物流", domain="example-logi.example", country="JP",
                                   name_en="Example Logistics Holdings", name_en_in_text=True)
        cur.execute("select aliases, alias_norms from breach_core.organizations where org_id = %s", (en,))
        assert cur.fetchone() == ([], [])
    conn.rollback()


def test_one_group_spelled_two_ways_across_trackers_is_one_claim(conn):
    """RansomFeed writes "thegentlemen" and "incransom" where RansomLook writes "the gentlemen" and
    "inc ransom": measured 2026-10-19, ~110 October victims were counted twice. Groups compare by
    actor_norm, the same key the actor table uses."""
    from zdc_breach import db as bdb
    from zdc_breach.sources_leak import LeakPost
    posts = [LeakPost("ransomlook", "g-1", "the gentlemen", "Aquatech Ltd", None, None, None, D(3), {}),
             LeakPost("ransomfeed", "g-2", "thegentlemen", "Aquatech Ltd", None, None, None, D(2), {}),
             LeakPost("ransomlook", "v-1", "vexy", "Small Bakery GmbH", None, None, None, D(3), {}),
             LeakPost("ransomfeed", "v-2", "vexy ransomware", "Small Bakery GmbH", None, None, None, D(3), {}),
             # a different group naming the same victim is still a second claim
             LeakPost("ransomlook", "q-1", "qilin", "Aquatech Ltd", None, None, None, D(3), {})]
    with conn.cursor() as cur:
        bdb.upsert_leak_posts(cur, posts)
    conn.commit()
    got = q(conn, """select victim_name, array_to_string(trackers, ','), jsonb_array_length(tracker_refs)
                       from breach_core.leak_claims order by 1, 2""")
    assert got == [("Aquatech Ltd", "ransomfeed,ransomlook", 2), ("Aquatech Ltd", "ransomlook", 1),
                   ("Small Bakery GmbH", "ransomfeed,ransomlook", 2)], got
    # a new claim keeps the group as the post that opened it wrote it
    assert q(conn, "select distinct actor_group from breach_core.leak_claims order by 1") == \
        [("qilin",), ("the gentlemen",), ("vexy",)]


def test_news_backfill_stores_short_japanese_summaries_and_repairs_earlier_runs(conn):
    """The archive backfill used a fixed 200-character minimum, so every Japanese feed summary
    (50-180 characters) was stored as a record and never as a document: 945 items, 0 documents
    on 2026-10-19. It now uses the per-language minimum, and re-running it gives an already-stored
    item the document it should have had."""
    import types
    from datetime import datetime as _dt, timezone as _tz
    from zdc_breach import run, http
    summary = ("株式会社サンプル物流は、外部からの不正アクセスにより顧客の個人情報約1万2000件が流出したと発表した。"
               "同社は警察に相談し、対象となる顧客に個別に連絡している。")
    rss = (f"""<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel><title>t</title>
<item><title>サンプル物流に不正アクセス</title><link>https://www.security-next.com/999999</link>
<guid>https://www.security-next.com/999999</guid><pubDate>Mon, 12 Oct 2026 01:00:00 +0000</pubDate>
<description>{summary}</description></item></channel></rss>""").encode()
    now = _dt.now(_tz.utc)

    def getter(url, **kw):
        body = rss if url.endswith("paged=2") else b'<?xml version="1.0"?><rss version="2.0"><channel></channel></rss>'
        return http.Fetched(url, 200, body, None, now, now, {})
    args = types.SimpleNamespace(backfill_news_since="2024-01-01", sources="news_jp_securitynext",
                                 deadline_minutes=5, backfill_news_start_page=2, backfill_news_pages=2)
    assert 60 <= len(summary) < 200
    # the broken run stored the record and no document (documents are insert-only, so the test
    # recreates that state rather than deleting a document)
    from zdc_breach import sources_news, db as bdb
    item = sources_news.parse_feed("news_jp_securitynext", rss)[0]
    with conn.cursor() as cur:
        bdb.store_records(cur, "news_jp_securitynext", [(item.guid, {"url": item.url, "title": item.title,
                          "published_at": item.published_at.isoformat(), "summary": item.summary})], None)
    conn.commit()
    assert q(conn, "select count(*) from breach_raw.documents where source_id = 'news_jp_securitynext'") == [(0,)]
    again = run.backfill_news(conn, args, getter=getter)
    assert q(conn, "select count(*) from breach_raw.documents where source_id = 'news_jp_securitynext'") == [(1,)], again
    assert again["news_jp_securitynext"]["documents"] == 1


# ---- owner decision 2026-10-20: card issuers file one notice per merchant breach -----------------
def test_card_issuer_notices_are_never_linked_as_duplicates(conn):
    """Two American Express notices a month apart are two merchant breaches; a non-issuer pair with
    the same dates is still linked (so the test fails if the duplicate rule itself is removed)."""
    from datetime import date
    from zdc_breach import resolve
    with conn.cursor() as cur:
        for name in ("American Express Travel Related Services", "Near Date Holdings Corp"):
            oid, _ = resolve.find_or_create_org(cur, name=name, country="US")
            resolve.resolve_incident(cur, org_id=oid, org_how="name", source_id="ca_ag", record_id=name + "1",
                                     event_date=date(2026, 3, 1), public_date=date(2026, 4, 1))
            resolve.resolve_incident(cur, org_id=oid, org_how="name", source_id="ca_ag", record_id=name + "2",
                                     event_date=date(2026, 3, 20), public_date=date(2026, 4, 20))
        r = resolve.Resolver(cur)
        for name, want in (("American Express Travel Related Services", 0), ("Near Date Holdings Corp", 1)):
            oid, _ = r.org(name=name, country="US")
            r.incident(org_id=oid, org_how="name", source_id="wa_ag", record_id=name + "3",
                       event_date=date(2026, 3, 10), public_date=date(2026, 4, 10))
            assert sum(1 for sql, p in r.writes if "possible_duplicate_of" in sql and p[0] and p[4]) == want
            r.writes.clear()
        cur.execute("""select o.norm_name, count(i.possible_duplicate_of) from breach_core.incidents i
                         join breach_core.organizations o using (org_id) where o.country = 'US'
                          and (o.norm_name like 'american express%%' or o.norm_name like 'near date%%') group by 1""")
        got = dict(cur.fetchall())
    conn.rollback()
    assert got["american express travel related services"] == 0
    assert sum(v for k, v in got.items() if k.startswith("near date")) == 1


def test_card_issuer_list_matches_the_linkage_model():
    from zdc_breach import linkage, resolve
    assert resolve.CARD_ISSUERS == linkage.CARD_ISSUERS


# ---- record linkage, active classes (0134, ADR 0008) ------------------------------------------------
LK_A, LK_B = "00000000-0000-4000-8000-000000000a01", "00000000-0000-4000-8000-000000000a02"


def _linkage_fixture(conn):
    """A CA filing and a press report of one breach under two spellings (link_key match, same event
    date, same exact count): the frozen model auto-links them as a reg_press pair."""
    with conn.cursor() as cur:
        cur.execute("""insert into breach_core.organizations (org_id, display_name, norm_name, country, sector) values
                       ('00000000-0000-4000-8000-0000000000a1', 'Zzlink Orbital Health Services', 'zzlink orbital health services', 'US', 'Health'),
                       ('00000000-0000-4000-8000-0000000000a2', 'Zzlink Orbital Health', 'zzlink orbital health', 'US', 'Health')""")
        cur.execute("""insert into breach_core.incidents (incident_id, org_id, event_date, first_public_date, regulator_filed, media_reported)
                       values (%s, '00000000-0000-4000-8000-0000000000a1', '2026-03-01', '2026-04-01', true, false),
                              (%s, '00000000-0000-4000-8000-0000000000a2', '2026-03-01', '2026-04-05', false, true)""", (LK_A, LK_B))
        cur.execute("""insert into breach_core.incident_sources (incident_id, source_id, source_record_id, match_method)
                       values (%s, 'ca_ag', 'lk-a', 'new'), (%s, 'news_hipaajournal', 'lk-b', 'new')""", (LK_A, LK_B))
        cur.execute("""insert into breach_core.claims (incident_id, field, value_num, unit, qualifier, basis, source_id, as_of, accepted)
                       values (%s, 'people_affected', 48211, 'persons', 'exact', 'regulator_filing', 'ca_ag', '2026-04-01', true),
                              (%s, 'people_affected', 48211, 'persons', 'exact', 'victim_statement', 'news_hipaajournal', '2026-04-05', true)""",
                    (LK_A, LK_B))
    conn.commit()


def _set_linkage(conn, *, active: bool, classes=("press_press", "reg_press"), code_sha=None):
    # The method row pins the scorer (0134: the frozen v1 sha); these tests exercise the wiring with the
    # code under test, so they pin its sha unless a test passes a different one on purpose.
    code_sha = code_sha or linkage_code_sha()
    with conn.cursor() as cur:
        cur.execute("""update breach_core.link_methods
                          set active = %s, activated_at = case when %s then now() end, active_classes = %s,
                              code_sha = coalesce(%s, code_sha)
                        where method_version = 'breach-linkage-v1'""", (active, active, list(classes), code_sha))
    conn.commit()


def _rebuild_and_evals(conn):
    from zdc_breach import evals
    with conn.cursor() as cur:
        cur.execute("select breach_core.rebuild_victims_list()")
        res = {r.name: r for r in (evals.victims_list_current(cur), evals.linkage_clusters_valid(cur))}
        cur.execute("select victim_id from breach_core.victims_list where victim_id like 'incident:%%' order by 1")
        listed = [x[0] for x in cur.fetchall()]
    conn.commit()
    return listed, res


def test_linkage_inactive_writes_nothing_and_the_list_is_legacy(conn):
    from zdc_breach import linkage_db
    _linkage_fixture(conn)
    with conn.cursor() as cur:
        assert linkage_db.refresh(cur) == {"active": False}
    conn.commit()
    listed, res = _rebuild_and_evals(conn)
    assert f"incident:{LK_A}" in listed and f"incident:{LK_B}" in listed
    assert res["victims_list_current"].passed and res["linkage_clusters_valid"].passed
    assert q(conn, "select count(*) from breach_core.incident_clusters") == [(0,)]


def test_linkage_active_hides_the_member_deterministically(conn):
    from zdc_breach import linkage_db
    _linkage_fixture(conn)
    try:
        _set_linkage(conn, active=True)
        outs = []
        for _ in range(2):
            with conn.cursor() as cur:
                rep = linkage_db.refresh(cur)
            conn.commit()
            outs.append((q(conn, """select incident_a::text, incident_b::text, decision, probability, band
                                      from breach_core.incident_links order by 1, 2"""),
                         q(conn, "select incident_id::text, cluster_id::text from breach_core.incident_clusters order by 1")))
        assert outs[0] == outs[1], "a second run must write the same rows"
        assert rep["active"] and rep["auto_links"] == 1 and rep["max_cluster"] == 2
        assert (LK_A, LK_B, "auto_link") == outs[0][0][0][:3]
        listed, res = _rebuild_and_evals(conn)
        # 0135 (option (a)): the PUBLIC list is the legacy build; the private linked list carries the linkage
        assert f"incident:{LK_A}" in listed and f"incident:{LK_B}" in listed
        assert res["victims_list_current"].passed, res["victims_list_current"].summary
        assert res["linkage_clusters_valid"].passed, res["linkage_clusters_valid"].summary
        with conn.cursor() as cur:
            cur.execute("select breach_core.rebuild_victims_list_linked()")
            from zdc_breach import evals
            linked_eval = evals.linked_list_current(cur)
        conn.commit()
        linked = [x[0] for x in q(conn, "select victim_id from breach_core.victims_list_linked where victim_id like 'incident:%%'")]
        assert f"incident:{LK_A}" in linked and f"incident:{LK_B}" not in linked      # the press row joins the filing
        assert linked_eval.passed, linked_eval.summary
        assert q(conn, """select sources from breach_core.victims_list_linked where victim_id = %s""", f"incident:{LK_A}")[0][0] \
            == ["ca_ag", "news_hipaajournal"]
        # rollback by the flag: the press row is listed again, nothing deleted
        _set_linkage(conn, active=True, classes=())
        listed, res = _rebuild_and_evals(conn)
        assert f"incident:{LK_B}" in listed and res["victims_list_current"].passed
        with conn.cursor() as cur:
            cur.execute("select breach_core.rebuild_victims_list_linked()")
        conn.commit()
        assert f"incident:{LK_B}" in [x[0] for x in q(conn, "select victim_id from breach_core.victims_list_linked")]
        assert q(conn, "select count(*) from breach_core.incident_clusters") == [(2,)]
    finally:
        _set_linkage(conn, active=False)


def test_linkage_auto_link_in_an_inactive_class_takes_no_part(conn):
    from zdc_breach import linkage_db
    _linkage_fixture(conn)
    try:
        _set_linkage(conn, active=True, classes=("press_press",))
        with conn.cursor() as cur:
            rep = linkage_db.refresh(cur)
        conn.commit()
        assert rep["inactive_class_auto"] == 1 and rep["clusters_multi"] == 0
        assert q(conn, "select decision, reason from breach_core.incident_links") == [("review_pending", "class_not_active")]
    finally:
        _set_linkage(conn, active=False)


def test_linkage_refuses_a_changed_scorer(conn):
    from zdc_breach import linkage_db
    _linkage_fixture(conn)
    try:
        _set_linkage(conn, active=True, code_sha="deadbeef0")
        with conn.cursor() as cur, pytest.raises(RuntimeError):
            linkage_db.refresh(cur)
        conn.rollback()
    finally:
        _set_linkage(conn, active=False, code_sha=linkage_code_sha())


def linkage_code_sha():
    from zdc_breach import linkage_db
    return linkage_db.code_sha256()[:40]


# ---- the CVE link layer (0137, ADR 0009): every ERROR eval can fail -----------------------------------------
def _confirmed_link(conn):
    """One public link through a person's confirmation (Widget Holdings, CVE-2026-40404)."""
    in_registry(conn, "CVE-2026-40404")
    brun.run(conn, args(), getter=fake_get, llm=FakeLLM(), fx=NoFx())
    with conn.cursor() as cur:
        cur.execute("""update breach_core.claims set review_verdict = 'confirmed', reviewer = 'test', reviewed_at = now()
                        where field = 'cve_id'""")
        cur.execute("select breach_core.rebuild_victims_list()")
    conn.commit()
    assert q(conn, "select gate from breach_core.cve_links where public") == [("human_confirmed",)]


def _eval(conn, fn, mutate=None):
    from zdc_breach import evals
    with conn.cursor() as cur:
        if mutate:
            cur.execute(mutate)
        res = getattr(evals, fn)(cur)
    conn.rollback()
    return res


@pytest.mark.parametrize("fn, mutate", [
    ("cve_links_current", "update breach_core.cve_links set built_at = now() - interval '1 hour'"),
    ("cve_links_one_view", "update breach_core.victims_list set cve_ids = null"),
    ("cve_links_one_view", "update breach_core.victims_list set cve_ids = array['CVE-2026-40404'] where cve_ids is null"),
    ("cve_links_have_evidence", "update breach_core.claims set accepted = false, reject_reason = 'test' where field = 'cve_id'"),
    ("no_machine_link_public_ungated", "update breach_core.cve_links set gate = 'extractor_active' where public"),
    ("cve_links_no_pii", """insert into breach_core.source_pii_hashes (source_id, sha256)
                            select 'cra_export', encode(sha256(convert_to(lower(btrim(name)), 'UTF8')), 'hex')
                              from public.breach_cve_links"""),
])
def test_each_link_eval_can_fail(conn, fn, mutate):
    _confirmed_link(conn)
    with conn.cursor() as cur:
        cur.execute("select breach_core.rebuild_victims_list()")    # the evals read this transaction's build
        from zdc_breach import evals
        assert getattr(evals, fn)(cur).passed, fn
    conn.rollback()
    with conn.cursor() as cur:
        cur.execute("select breach_core.rebuild_victims_list()")
    res = _eval(conn, fn, mutate)
    from zdc_crowdsec.evals import ERROR
    assert not res.passed and res.severity == ERROR, (fn, res)


def test_publication_has_no_open_tier(conn):
    """Addendum s5.1: 'facts_only' or 'private', nothing that would surface the export's expressive fields."""
    with pytest.raises(psycopg.errors.CheckViolation):
        with conn.cursor() as cur:
            cur.execute("update breach_core.sources set publication = 'open' where source_id = 'cra_export'")
    conn.rollback()


def test_enrich_breach_count_eval_can_fail(conn):
    """zdc_enrich: breach_count equals the link view and the list rebuild reads no breach data. Mutant:
    restore 0091's core.breach_cves join."""
    from zdc_enrich import evals as eevals
    _confirmed_link(conn)
    with conn.cursor() as cur:
        cur.execute("""insert into derived.explorer_list (cve_id, method_version, censored_at, computed_at)
                       values ('CVE-2026-40404', 't', current_date, now()) on conflict do nothing""")
    conn.commit()
    try:
        ok = eevals.check_explorer_breach_count_from_links(conn)
        assert ok.passed and ok.detail["sampled"] == 1, ok
        with conn.cursor() as cur:
            body = q(conn, "select pg_get_functiondef('derived.rebuild_explorer_list(text,date,uuid)'::regprocedure)")[0][0]
            cur.execute(body.replace("left join core.epss_summary es",
                                     "left join (select cve_id, count(*)::int as n from core.breach_cves group by cve_id) b\n"
                                     "        on b.cve_id = d.cve_id\n      left join core.epss_summary es"))
        bad = eevals.check_explorer_breach_count_from_links(conn)
        assert not bad.passed and bad.detail["rebuild_reads"] == ["breach_cves"], bad
        conn.rollback()
    finally:
        with conn.cursor() as cur:
            cur.execute("delete from derived.explorer_list where cve_id = 'CVE-2026-40404' and method_version = 't'")
        conn.commit()


def test_incident_cve_never_files_against_a_rejected_twin(conn):
    """Review s7: when the dedupe index kept an older REJECTED claim with the same key, the accepted
    candidate is not inserted and the CVE must not be filed against the rejected one. Mutant: drop
    `c.accepted` from run.py's claim lookup."""
    from types import SimpleNamespace

    from zdc_breach import extract
    from zdc_breach import run as brun_
    with conn.cursor() as cur:
        cur.execute("""insert into breach_core.organizations (org_id, display_name, norm_name)
                       values ('00000000-0000-4000-8fff-000000000001', 'Twin Rejected Co', 'twin rejected') returning org_id""")
        cur.execute("""insert into breach_core.incidents (incident_id, org_id, first_public_date)
                       values ('00000000-0000-4000-9fff-000000000001', '00000000-0000-4000-8fff-000000000001', '2026-01-01')""")
        cur.execute("""insert into breach_raw.documents (doc_sha256, source_id, url, text)
                       values (repeat('a', 64), 'news_bleepingcomputer', 'https://news.example/t', 'Twin Rejected Co hit via CVE-2026-1111.')""")
        cur.execute("""insert into breach_core.claims (incident_id, field, value_text, unit, qualifier, as_of, basis, source_id,
                                                       doc_sha256, quote, accepted, reject_reason)
                       values ('00000000-0000-4000-9fff-000000000001', 'cve_id', 'CVE-2026-1111', 'none', 'exact', '2026-01-01',
                               'news', 'news_bleepingcomputer', repeat('a', 64), 'x', false, 'earlier_rejection')""")
        c = extract.Candidate(field="cve_id", value="CVE-2026-1111", unit="none", qualifier="exact",
                              quote="Twin Rejected Co hit via CVE-2026-1111.",
                              accepted=True, cve_role="initial_access")
        ctx = SimpleNamespace(report={"claims": {"accepted": 0, "rejected": 0, "reject_reasons": {}}}, new_quotes=[],
                              fx=NoFx())
        brun_.file_candidate(ctx, cur, '00000000-0000-4000-9fff-000000000001', c, "news", "news_bleepingcomputer",
                             "a" * 64, None, NOW.date(), "Twin Rejected Co hit via CVE-2026-1111.")
    conn.commit()
    assert q(conn, """select count(*) from breach_core.incident_cves ic join breach_core.claims c on c.claim_id = ic.claim_id
                       where not c.accepted""") == [(0,)]


# ---- atg.wa.gov list (R4) ------------------------------------------------------------------------
def _wa_dt(conn):
    return q(conn, """select o.display_name, c.value_text, c.source_record_id, c.superseded_by is null
                        from breach_core.claims c join breach_core.incidents i using (incident_id)
                        join breach_core.organizations o using (org_id)
                       where c.field = 'data_types' and c.source_id = 'wa_ag' order by c.created_at, c.value_text""")


def test_wa_site_types_join_the_dataset_incident_and_nothing_else(conn):
    rep = brun.run(conn, args(sources="wa_ag"), getter=fake_get, llm=None, fx=NoFx())
    assert rep["ok"], [e for e in rep["evals"] if not e["passed"]]
    site = rep["sources"]["wa_ag"]["site"]
    assert site["ok"] and site["notices"] == 2 and site["claims_written"] == 1
    assert site["join"] == {"name_date": 1, "no_match": 1}
    assert _wa_dt(conn) == [("Twin Filing Corp", "Name, Social Security Number", "site:A9001", True)]
    # raw first: both notices stored, the page fetch recorded with its URL, status and hash
    assert q(conn, """select count(*) from breach_raw.source_records
                       where source_id = 'wa_ag' and source_record_id like 'site:%%'""") == [(2,)]
    assert q(conn, """select http_status, sha256 is not null from breach_raw.fetches
                       where url like 'https://www.atg.wa.gov/%%'""") == [(200, True)]
    # no second link, no new organisation or incident from the list
    assert q(conn, "select count(*) from breach_core.incident_sources where source_record_id like 'site:%%'") == [(0,)]
    assert q(conn, "select count(*) from breach_core.organizations where display_name like 'Zz%%'") == [(0,)]
    brun.run(conn, args(sources="extract"), getter=fake_get, llm=None, fx=NoFx())
    facts = q(conn, """select f.data_types from breach_core.incident_facts f join breach_core.incidents i using (incident_id)
                         join breach_core.organizations o using (org_id) where o.display_name = 'Twin Filing Corp'""")
    assert facts == [(["Name", "Social Security Number"],)]


def test_wa_site_second_run_writes_nothing_and_a_revision_supersedes(conn):
    brun.run(conn, args(sources="wa_ag"), getter=fake_get, llm=None, fx=NoFx())
    rep = brun.run(conn, args(sources="wa_ag"), getter=fake_get, llm=None, fx=NoFx())
    site = rep["sources"]["wa_ag"]["site"]
    assert site["pages"] == 1 and site["unchanged"] == 2 and site["claims_written"] == 0
    old = WA_SITE[0]
    try:
        WA_SITE[0] = old.replace("Name; Social Security Number; Unknown", "Name; Passport Number")
        rep = brun.run(conn, args(sources="wa_ag"), getter=fake_get, llm=None, fx=NoFx())
    finally:
        WA_SITE[0] = old
    assert rep["sources"]["wa_ag"]["site"]["changed"] == 1
    assert _wa_dt(conn) == [("Twin Filing Corp", "Name, Social Security Number", "site:A9001", False),
                            ("Twin Filing Corp", "Name, Passport Number", "site:A9001", True)]


def test_wa_site_blocked_keeps_the_dataset_rows_and_warns(conn):
    def blocked(url, **kw):
        if "atg.wa.gov" in url:
            return Fetched(url, 403, b"", "HTTP 403", NOW, NOW, {})
        return fake_get(url, **kw)
    rep = brun.run(conn, args(sources="wa_ag"), getter=blocked, llm=None, fx=NoFx())
    assert rep["ok"] and rep["sources"]["wa_ag"]["ok"]
    assert rep["sources"]["wa_ag"]["site"]["error"] == "blocked"
    assert q(conn, "select count(*) from breach_core.incident_sources where source_id = 'wa_ag'") == [(2,)]
    assert q(conn, "select http_status from breach_raw.fetches where url like 'https://www.atg.wa.gov/%%'") == [(403,)]
    ev = {e["name"]: e for e in rep["evals"]}["wa_site_harvested"]
    assert not ev["passed"] and ev["severity"] == "warn"


def test_wa_site_eval_fails_when_the_list_changes_shape(conn):
    old = WA_SITE[0]
    try:
        WA_SITE[0] = "<html><body>new design</body></html>"
        rep = brun.run(conn, args(sources="wa_ag"), getter=fake_get, llm=None, fx=NoFx())
    finally:
        WA_SITE[0] = old
    ev = {e["name"]: e for e in rep["evals"]}["wa_site_harvested"]
    assert not ev["passed"] and ev["severity"] == "error"


def test_wa_site_reads_every_page_once_then_stops_at_the_first_unchanged_page(conn):
    p0 = wa_page([wa_row("Zz Page Zero", D(5).strftime("%m/%d/%Y"), "", "600", "Name", pdf="A9100")], last=1)
    p1 = wa_page([wa_row("Zz Page One", D(40).strftime("%m/%d/%Y"), "", "700", "Name", pdf="A9101")], last=1)
    asked = []

    def two_pages(url, **kw):
        if "atg.wa.gov" in url:
            asked.append(url)
            return Fetched(url, 200, (p1 if url.endswith("page=1") else p0).encode(), None, NOW, NOW, {})
        return fake_get(url, **kw)
    rep = brun.run(conn, args(sources="wa_ag"), getter=two_pages, llm=None, fx=NoFx())
    assert rep["sources"]["wa_ag"]["site"]["pages"] == 2 and len(asked) == 2
    rep = brun.run(conn, args(sources="wa_ag"), getter=two_pages, llm=None, fx=NoFx())
    assert rep["sources"]["wa_ag"]["site"]["pages"] == 1 and len(asked) == 3
