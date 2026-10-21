"""The CVE pass in run.py (patch 0001) and its eval (patch 0004), against the migrated schema.
RULING verify-B3 tests 5 (scope) and 10 (eval). Gated on BREACH_TEST_DATABASE_URL."""
from __future__ import annotations

import os
from argparse import Namespace
from datetime import datetime, timezone

import pytest

psycopg = pytest.importorskip("psycopg")
DSN = os.environ.get("BREACH_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DSN, reason="BREACH_TEST_DATABASE_URL not set")

from zdc_breach import cve_extract, evals  # noqa: E402
from zdc_breach import llm as llm_mod  # noqa: E402
from zdc_breach import run as brun  # noqa: E402

SRC = "news_bleepingcomputer"
MAIN = "llm:test-model@main0000000000"
NOW = datetime.now(timezone.utc)


@pytest.fixture()
def conn():
    c = psycopg.connect(DSN, autocommit=False)
    with c.cursor() as cur:
        cur.execute("""truncate breach_core.claims, breach_core.incident_cves, breach_core.incident_facts, breach_core.cve_links,
                       breach_core.incident_sources, breach_core.extractions, breach_core.llm_calls,
                       breach_core.incidents, breach_core.organizations, breach_raw.documents cascade""")
        cur.execute("delete from breach_core.extractor_versions where kind = 'llm'")
        cur.execute("""insert into breach_core.extractor_versions (extractor_id, kind, model_id, prompt_hash, schema_hash, active)
                       values (%s, 'llm', 'test-model', 'main', 'breach-extract-v4', false)""", (MAIN,))
    c.commit()
    yield c
    c.rollback()
    c.close()


class RecLLM:
    def __init__(self):
        self.users = []
        self.spent_month = self.spent_today = 0.0
    def json(self, system, user, **kw):
        assert system == cve_extract.prompt_text()
        self.users.append(user)
        return llm_mod.LlmResult(True, {"cves_on_page": [], "links": []}, "test-model", None, 1, 1, 0.0, 1, None)


def _ctx(conn, llm=None):
    return brun.Ctx(conn, None, Namespace(max_docs=10, dry_run=False), llm=llm)


def _main(conn, text, org):
    with conn.cursor() as cur:
        sha = brun.store_doc(cur, SRC, "https://news.example/" + org.replace(" ", ""), "t", NOW, text)
        brun.file_output(_ctx(conn), cur, sha, text, {"is_incident_report": True, "incidents": [
            {"organization": org, "source_of_account": "news", "facts": [
                {"field": "people_affected", "value": 1000, "unit": "persons", "qualifier": "exact",
                 "quote": f"{org} said 1,000 customers were affected."}]}]}, MAIN, published=NOW, source_id=SRC)
    return sha


def test_scope_only_cve_documents_with_a_main_incident(conn):
    """B3-5. Mutants: drop the exists clause; drop the CVE regex."""
    a = _main(conn, "Acme Corp said 1,000 customers were affected. It was breached through CVE-2031-30001.", "Acme Corp")
    c = _main(conn, "Globex Ltd said 1,000 customers were affected. No identifier was given.", "Globex Ltd")
    with conn.cursor() as cur:
        b = brun.store_doc(cur, SRC, "https://news.example/b", "t", NOW, "A flaw, CVE-2031-30002, is under attack.")
    conn.commit()
    llm = RecLLM()
    rep = brun.run_cve_extraction(_ctx(conn, llm), conn)
    assert rep["in_scope"] == 1 and rep["calls"] == 1 and len(llm.users) == 1 and "CVE-2031-30001" in llm.users[0]
    assert not rep["did_not_run"]
    rep2 = brun.run_cve_extraction(_ctx(conn, RecLLM()), conn)
    assert rep2["in_scope"] == 0                                          # one CVE extraction per version


def test_no_llm_key_means_skipped(conn):
    assert brun.run_cve_extraction(_ctx(conn, None), conn) == {"skipped": "no LLM key"}


def test_eval_no_incident_from_cve_pass_can_fail(conn):
    """B3-10. Mutant: the eval counts nothing (or looks at the wrong schema)."""
    _main(conn, "Acme Corp said 1,000 customers were affected. CVE-2031-30001.", "Acme Corp")
    with conn.cursor() as cur:
        assert evals.no_incident_from_cve_pass(cur).passed
        cur.execute("""insert into breach_core.extractor_versions (extractor_id, kind, model_id, prompt_hash, schema_hash, active)
                       values ('agent:x@cve', 'llm', 'x', 'cve', %s, false)""", (cve_extract.SCHEMA_VERSION,))
        cur.execute("insert into breach_core.organizations (display_name, norm_name) values ('Rogue', 'rogue') returning org_id")
        org = cur.fetchone()[0]
        cur.execute("insert into breach_core.incidents (org_id, first_public_date) values (%s, current_date) returning incident_id", (org,))
        inc = cur.fetchone()[0]
        sha = brun.store_doc(cur, SRC, "https://news.example/r", "t", NOW, "Rogue was breached via CVE-2031-30009.")
        cur.execute("""insert into breach_core.extractions (doc_sha256, extractor_id, output, ok) values (%s, 'agent:x@cve', '{}', true)
                       returning extraction_id""", (sha,))
        ex = cur.fetchone()[0]
        cur.execute("""insert into breach_core.claims (incident_id, field, value_text, unit, qualifier, as_of, basis, source_id,
                                                      doc_sha256, quote, extraction_id, accepted)
                       values (%s, 'cve_id', 'CVE-2031-30009', 'none', 'exact', current_date, 'news', %s, %s,
                               'Rogue was breached via CVE-2031-30009.', %s, true)""", (inc, SRC, sha, ex))
        r = evals.no_incident_from_cve_pass(cur)
        assert not r.passed and r.detail["bad"] == 1
