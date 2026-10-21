"""CVE pass, attach-only filing, against the migrated schema (RULING verify-B1/B3, 2026-10-21).

Gated on BREACH_TEST_DATABASE_URL like test_breach_db.py. The main news extraction (run.file_output, the path
that may create organisations under the naming rules) builds each document's incidents; the CVE output is then
filed by cve_agent_load.file_cve_output, the only CVE filer, which must never create anything.
Every test names the mutant it kills.
"""

from __future__ import annotations

import os
from argparse import Namespace
from datetime import datetime, timezone

import pytest

psycopg = pytest.importorskip("psycopg")
DSN = os.environ.get("BREACH_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DSN, reason="BREACH_TEST_DATABASE_URL not set")

from zdc_breach import cve_agent_load, cve_extract  # noqa: E402
from zdc_breach import run as brun  # noqa: E402

SRC = "news_bleepingcomputer"
MAIN = "llm:test-model@main0000000000"
CVE_EXT = "agent:test-model@cve00000000000"
NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)


@pytest.fixture()
def conn():
    c = psycopg.connect(DSN, autocommit=False)
    with c.cursor() as cur:
        cur.execute("""truncate breach_core.claims, breach_core.incident_cves, breach_core.incident_facts, breach_core.cve_links,
                       breach_core.incident_sources, breach_core.match_overrides, breach_core.takedown_requests,
                       breach_core.leak_claims, breach_core.extractions, breach_core.llm_calls,
                       breach_core.incidents, breach_core.organizations, breach_raw.documents cascade""")
        cur.execute("delete from breach_core.extractor_versions where kind = 'llm'")
        cur.execute("""insert into breach_core.extractor_versions (extractor_id, kind, model_id, prompt_hash, schema_hash, active)
                       values (%s, 'llm', 'test-model', 'main', 'breach-extract-v4', false),
                              (%s, 'llm', 'test-model', 'cve', %s, false)""", (MAIN, CVE_EXT, cve_extract.SCHEMA_VERSION))
    c.commit()
    yield c
    c.rollback()
    c.close()


def _ctx(conn):
    return brun.Ctx(conn, None, Namespace(max_docs=0, dry_run=False))


def _fact(sentence):
    return {"field": "people_affected", "value": 1000, "unit": "persons", "qualifier": "exact", "quote": sentence}


def main_pass(conn, text, incidents):
    """Store the document and run the NEWS extraction's filer on it (this may create organisations)."""
    with conn.cursor() as cur:
        sha = brun.store_doc(cur, SRC, "https://news.example/" + str(abs(hash(text))), "t", NOW, text)
        brun.file_output(_ctx(conn), cur, sha, text, {"is_incident_report": True, "incidents": incidents}, MAIN,
                         published=NOW, source_id=SRC)
    return sha


def cve_pass(conn, sha, text, links):
    with conn.cursor() as cur:
        return cve_agent_load.file_cve_output(_ctx(conn), cur, sha, text, {"cves_on_page": [], "links": links},
                                              CVE_EXT, published=NOW, source_id=SRC)


def L(cve, org, quote, **kw):
    d = {"cve_id": cve, "organization": org, "role": "exploited", "named_in_sentence": True, "vendor_self": False,
         "basis": "news", "quote": quote}
    d.update(kw)
    return d


def counts(conn):
    with conn.cursor() as cur:
        cur.execute("""select (select count(*) from breach_core.organizations), (select count(*) from breach_core.incidents),
                              (select count(*) from breach_core.incident_cves)""")
        return cur.fetchone()


ACME = "Acme Corp said 1,000 customers were affected. Acme Corp, Inc. was breached through CVE-2031-20001 in July."
ACME_INC = [{"organization": "Acme Corp", "country": "US", "source_of_account": "news",
             "facts": [_fact("Acme Corp said 1,000 customers were affected.")]}]


def test_no_organisation_and_no_incident_is_ever_created(conn):
    """B3-1. Mutant: CVE output routed through run.file_output (the pre-fix code), which creates the org."""
    text = ACME + " Brand New Co was also hit through CVE-2031-20001, the report said."
    sha = main_pass(conn, text, ACME_INC)
    before = counts(conn)
    res = cve_pass(conn, sha, text, [L("CVE-2031-20001", "Brand New Co",
                                       "Brand New Co was also hit through CVE-2031-20001, the report said.")])
    assert res == {"attached": 0, "unattached": {"name_not_in_doc_incidents": 1}}
    assert counts(conn) == before


def test_country_blind_attach_to_the_documents_incident(conn):
    """B3-2. Mutant: a country filter on the targets (misses the US org and holds the link)."""
    sha = main_pass(conn, ACME, ACME_INC)
    res = cve_pass(conn, sha, ACME, [L("CVE-2031-20001", "Acme Corp, Inc.",
                                       "Acme Corp, Inc. was breached through CVE-2031-20001 in July.")])
    assert res["attached"] == 1
    with conn.cursor() as cur:
        cur.execute("""select o.display_name, ic.cve_id, ic.role::text from breach_core.incident_cves ic
                         join breach_core.incidents i using (incident_id) join breach_core.organizations o using (org_id)""")
        assert cur.fetchall() == [("Acme Corp", "CVE-2031-20001", "exploited")]


def test_never_another_documents_incident(conn):
    """B3-3. Mutant: targets looked up globally by name instead of from this document."""
    main_pass(conn, ACME, ACME_INC)                                         # Acme exists, from document E
    other = ("Globex Ltd said 1,000 customers were affected. Separately, Acme Corp was breached through "
             "CVE-2031-20001, researchers said.")
    sha_d = main_pass(conn, other, [{"organization": "Globex Ltd", "country": "GB", "source_of_account": "news",
                                     "facts": [_fact("Globex Ltd said 1,000 customers were affected.")]}])
    res = cve_pass(conn, sha_d, other, [L("CVE-2031-20001", "Acme Corp",
                                          "Separately, Acme Corp was breached through CVE-2031-20001, researchers said.")])
    assert res["unattached"] == {"name_not_in_doc_incidents": 1} and counts(conn)[2] == 0


def test_two_targets_that_normalise_alike_hold_the_link(conn):
    """B3-4. Mutant: the first of several matching targets is taken. The second target reaches the document
    the way a structured source does: an incident_sources row naming the document."""
    sha = main_pass(conn, ACME, ACME_INC)
    with conn.cursor() as cur:
        cur.execute("""insert into breach_core.organizations (display_name, norm_name, country)
                       values ('ACME Corporation', 'acme', 'GB') returning org_id""")
        org2 = cur.fetchone()[0]
        cur.execute("""insert into breach_core.incidents (org_id, first_public_date) values (%s, '2026-09-30')
                       returning incident_id""", (org2,))
        inc2 = cur.fetchone()[0]
        cur.execute("""insert into breach_core.incident_sources (incident_id, source_id, source_record_id, doc_sha256, match_method)
                       values (%s, %s, 'r2', %s, 'domain')""", (inc2, SRC, sha))
        assert len({t["incident_id"] for t in cve_agent_load._doc_targets(cur, sha)}) == 2
    res = cve_pass(conn, sha, ACME, [L("CVE-2031-20001", "Acme Corp", "Acme Corp, Inc. was breached through CVE-2031-20001 in July.")])
    assert res["unattached"] == {"ambiguous_target": 1} and counts(conn)[2] == 0


def test_the_loader_creates_nothing_either(conn):
    """B3-6. Mutant: cve_agent_load.load files through run.file_output."""
    text = ACME + " Brand New Co was also hit through CVE-2031-20001, the report said."
    sha = main_pass(conn, text, ACME_INC)
    conn.commit()
    before = counts(conn)
    out = {"cves_on_page": ["CVE-2031-20001"], "links": [
        L("CVE-2031-20001", "Brand New Co", "Brand New Co was also hit through CVE-2031-20001, the report said."),
        L("CVE-2031-20001", "Acme Corp, Inc.", "Acme Corp, Inc. was breached through CVE-2031-20001 in July.")]}
    res = cve_agent_load.load(conn, "test-model", [{"doc": sha, "output": out}])
    assert res["organisations_created"] == res["incidents_created"] == 0
    assert res["attached"] == 1 and res["unattached"] == {"name_not_in_doc_incidents": 1}
    o, i, ic = counts(conn)
    assert (o, i) == before[:2] and ic == 1


def test_hard_key_only_through_an_exact_domain(conn):
    """B3-7. Mutant: norm_name treated as a hard key (or the domain ignored)."""
    text = ("Globex Ltd said 1,000 customers were affected. Globex Europe was breached through CVE-2031-20002. "
            "Initech was also breached through CVE-2031-20002.")
    sha = main_pass(conn, text, [{"organization": "Globex Ltd", "domain": "globex.example", "country": "GB",
                                  "source_of_account": "news",
                                  "facts": [_fact("Globex Ltd said 1,000 customers were affected.")]}])
    res = cve_pass(conn, sha, text, [
        L("CVE-2031-20002", "Globex Europe", "Globex Europe was breached through CVE-2031-20002.", domain="globex.example"),
        L("CVE-2031-20002", "Initech", "Initech was also breached through CVE-2031-20002.")])
    assert res == {"attached": 1, "unattached": {"name_not_in_doc_incidents": 1}}
    text2 = text + " Update."
    sha2 = main_pass(conn, text2, [{"organization": "Globex Ltd", "domain": "globex.example", "country": "GB",
                                    "source_of_account": "news",
                                    "facts": [_fact("Globex Ltd said 1,000 customers were affected.")]}])
    res2 = cve_pass(conn, sha2, text2, [L("CVE-2031-20002", "Globex Europe",
                                          "Globex Europe was breached through CVE-2031-20002.")])
    assert res2["unattached"] == {"name_not_in_doc_incidents": 1}          # same name, no domain: not a key


def test_every_incident_cve_names_an_accepted_claim(conn):
    """B3-8. Mutant: incident_cves written without claim_id."""
    sha = main_pass(conn, ACME, ACME_INC)
    cve_pass(conn, sha, ACME, [L("CVE-2031-20001", "Acme Corp", "Acme Corp, Inc. was breached through CVE-2031-20001 in July.")])
    with conn.cursor() as cur:
        cur.execute("""select count(*), count(ic.claim_id), count(*) filter (where c.accepted and c.field = 'cve_id'
                                                                           and c.extraction_id is not null)
                         from breach_core.incident_cves ic left join breach_core.claims c on c.claim_id = ic.claim_id""")
        n, with_claim, accepted = cur.fetchone()
    assert n == 1 and with_claim == 1 and accepted == 1


def test_cve_pass_claims_do_not_make_a_document_a_target(conn):
    """A CVE-pass claim on a document never counts as that document's incident (schema filter in _doc_targets).
    Mutant: the CVE extractor version not excluded from the target query."""
    sha = main_pass(conn, ACME, ACME_INC)
    cve_pass(conn, sha, ACME, [L("CVE-2031-20001", "Acme Corp", "Acme Corp, Inc. was breached through CVE-2031-20001 in July.")])
    with conn.cursor() as cur:
        cur.execute("delete from breach_core.claims c using breach_core.extractions e, breach_core.extractor_versions x "
                    "where e.extraction_id = c.extraction_id and x.extractor_id = e.extractor_id and x.extractor_id = %s",
                    (MAIN,))
        cur.execute("delete from breach_core.incident_sources")
        assert cve_agent_load._doc_targets(cur, sha) == []
