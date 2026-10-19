"""AI cyber capability tracker: registry rules, the vals board parser, every gate, discovery, and an
end-to-end run against a migrated database. All fixtures are synthetic (no vals.ai data is committed:
its board is all rights reserved)."""

from __future__ import annotations

import copy
import datetime as dt
import json
import os
import types

import httpx
import pytest

from zdc_aicap import checks, discover, registry, source_vals
from zdc_crowdsec.evals import EvalResult as EvalResultT

TODAY = dt.date(2026, 10, 19)


# ---------------------------------------------------------------- the real registry
def test_the_shipped_registry_is_valid():
    assert registry.validate(registry.load(), TODAY) == []


def test_every_vals_model_on_the_shipped_name_map_has_a_developer():
    names = registry.load()["model_names"]
    assert names and all(len(v) == 2 and v[1] for v in names.values())


# ---------------------------------------------------------------- registry rules
def reg_fixture():
    return {
        "evaluators": [{"id": "gov", "name": "Gov", "kind": "government", "url": "https://gov.example", "develops_models": []},
                       {"id": "lab", "name": "Lab", "kind": "vendor_research", "url": "https://lab.example", "develops_models": ["LabCo"]}],
        "benchmarks": [{"id": "b1", "name": "B1", "side": "offence", "skill": "exploit things", "unit": "percent", "scale_max": 100,
                        "tasks": 10, "evaluator": "gov", "source": "curated", "url": "https://b1.example", "licence": "x",
                        "republish": "allowed", "status": "active"},
                       {"id": "b2", "name": "B2", "side": "defence", "skill": "detect things", "unit": "reward", "scale_max": 1,
                        "tasks": None, "evaluator": "lab", "source": "curated", "url": "https://b2.example", "licence": "x",
                        "republish": "cite", "status": "active"}],
        "results": [{"benchmark": "b1", "version": "1", "model": "M", "developer": "OtherCo", "score": 44.4, "n": 502,
                     "published_on": "2026-09-17", "source_url": "https://b1.example/r", "evidence": "44.4% (223/502)", "verified_on": "2026-10-19"},
                    {"benchmark": "b2", "version": "1", "model": "N", "developer": "OtherCo", "score": 0.637,
                     "published_on": "2026-03-13", "source_url": "https://b2.example/r", "evidence": "reward (0.637)", "verified_on": "2026-10-19"}],
        "events": [{"id": "e1", "date": "2026-09-17", "precision": "day", "lane": "government", "evaluator": "gov", "title": "T",
                    "detail": "one sentence", "source_url": "https://gov.example/e", "evidence": "quote", "verified_on": "2026-10-19"}],
        "model_names": {"x/m": ["M", "OtherCo"]},
    }


def test_a_valid_registry_has_no_problems():
    assert registry.validate(reg_fixture(), TODAY) == []


@pytest.mark.parametrize("mutate, needle", [
    (lambda r: r["results"][0].update(developer="LabCo", benchmark="b2", score=0.5, evidence="0.5"), "self-evaluation"),
    (lambda r: r["results"][0].update(commissioned_by_developer=True), "commissioned"),
    (lambda r: r["results"][0].update(evidence="the best model scored highly"), "does not state 44.4"),
    (lambda r: r["results"][0].update(published_on="2027-01-01"), "future"),
    (lambda r: r["results"][0].update(score=144), "outside 0..100"),
    (lambda r: r["results"][0].update(ci=[50, 60]), "interval"),
    (lambda r: r["results"][1].update(score=63.7), "outside 0..1"),
    (lambda r: r["benchmarks"][0].update(side="both"), "offence or defence"),
    (lambda r: r["benchmarks"][0].update(unit="reward"), "scale_max"),
    (lambda r: r["benchmarks"][0].update(url="http://insecure.example"), "https"),
    (lambda r: r["results"].append(dict(r["results"][0])), "duplicate"),
    (lambda r: r["events"][0].update(lane="lab"), "government or benchmark"),
    (lambda r: r["events"][0].update(evidence=""), "without an evidence quote"),
    (lambda r: r["benchmarks"][0].update(skill="x" * 111), "one-line skill"),
])
def test_each_registry_rule_catches_its_mistake(mutate, needle):
    r = reg_fixture()
    mutate(r)
    assert any(needle in p for p in registry.validate(r, TODAY)), registry.validate(r, TODAY)


def test_evidence_may_state_the_count_instead_of_the_share():
    assert registry.evidence_states("exploited 157 of those 898 instances", 17.48, 898, 100)
    assert not registry.evidence_states("exploited 157 of those 898 instances", 19.0, 898, 100)


# ---------------------------------------------------------------- the vals board
def board_doc(n_models=4, version="1.1", poc_tasks=60, patch_tasks=56, skew=0.0):
    tasks = {"overall": {}, "poc": {}, "patch": {}}
    for i in range(n_models):
        mid = f"lab{i}/model-{i}"
        poc, patch = 80 - 7 * i, 85 - 3 * i

        def tr(n, prefix, passed):
            return {f"{prefix}:oss-fuzz:{k}": {"passed": k < passed, "measurable": True, "status": "passed" if k < passed else "failed"}
                    for k in range(n)}
        tasks["poc"][mid] = {"accuracy": poc, "stderr": 5.0, "cost_per_test": 1.0 + i, "latency": 600, "provider": f"Lab{i}",
                             "task_results": tr(poc_tasks, "poc", int(poc * poc_tasks / 100))}
        tasks["patch"][mid] = {"accuracy": patch, "stderr": 4.0, "cost_per_test": 0.5 + i, "latency": 400, "provider": f"Lab{i}",
                               "task_results": tr(patch_tasks, "patch", int(patch * patch_tasks / 100))}
        tasks["overall"][mid] = {"accuracy": (poc + patch) / 2 + skew, "stderr": 4.5, "cost_per_test": 0.75 + i, "latency": 500,
                                 "provider": f"Lab{i}", "task_results": {}}
    return {"metadata": {"benchmark": f"CyberBench v{version}", "version": version, "updated": "2026-10-12", "models": sorted(tasks["overall"])},
            "tasks": tasks}


NAMES = {f"lab{i}/model-{i}": [f"Model {i}", f"Lab{i}"] for i in range(6)}


def index_text(doc, version="1.1"):
    rows = sorted(doc["tasks"]["overall"].items(), key=lambda kv: -kv[1]["accuracy"])
    lines = "\n".join(f"{k + 1}. [{NAMES[m][0]}](https://www.vals.ai/models/x): {v['accuracy']:.2f}%" for k, (m, v) in enumerate(rows))
    return f"# Vals\n\n## CyberBench v{version}\n\n- Page: https://www.vals.ai/benchmarks/cyber\n- Category: Cyber\n\nTop:\n\n{lines}\n\n## Other\n"


def test_the_board_parses_into_rows_per_model_and_track():
    b = source_vals.parse(board_doc())
    assert b.version == "1.1" and len(b.models) == 4 and len(b.rows) == 12
    poc = next(r for r in b.rows if r.track == "poc" and r.model_id == "lab0/model-0")
    assert poc.n_tasks == 60 and poc.n_passed == 48 and poc.n_errors == 0


@pytest.mark.parametrize("breaks", [
    lambda d: d.pop("metadata"), lambda d: d["tasks"].pop("patch"), lambda d: d["metadata"].update(updated="12/10/2026"),
    lambda d: d["tasks"]["poc"]["lab0/model-0"].pop("accuracy"),
])
def test_a_changed_board_format_stops_the_run(breaks):
    d = board_doc()
    breaks(d)
    with pytest.raises(ValueError):
        source_vals.parse(d)


def test_the_page_must_name_exactly_one_board_file():
    assert source_vals.json_paths('<a href="/_astro/benchmark_view_cyberbench.Ab1.json">') == ["/_astro/benchmark_view_cyberbench.Ab1.json"]
    two = '"/_astro/benchmark_view_cyberbench.A.json" "/_astro/benchmark_view_cyberbench.B.json"'
    assert not checks.board_read(None, source_vals.json_paths(two)).passed


def test_board_checks_pass_on_a_consistent_board():
    d = board_doc()
    b = source_vals.parse(d)
    iv, top = source_vals.top10_from_index(index_text(d))
    for c in (checks.board_shape(b, {"poc": 60, "patch": 56}), checks.overall_is_mean(b), checks.matches_index(b, iv, top, NAMES),
              checks.names_known(b, NAMES), checks.no_silent_rescore(b, {}), checks.error_share(b)):
        assert c.passed, c.summary


def test_board_checks_each_catch_their_failure():
    d = board_doc()
    assert not checks.board_shape(source_vals.parse(board_doc(poc_tasks=59)), {"poc": 60, "patch": 56}).passed
    assert not checks.overall_is_mean(source_vals.parse(board_doc(skew=2.0))).passed
    b = source_vals.parse(d)
    iv, top = source_vals.top10_from_index(index_text(d))
    wrong = [(n, p + 1.0) for n, p in top]
    assert checks.matches_index(b, iv, wrong, NAMES).blocking
    assert checks.matches_index(b, "1.2", top, NAMES).blocking
    assert not checks.names_known(b, {}).passed and checks.names_known(b, {}).severity == checks.WARN
    prev = {("lab0/model-0", "poc"): (40.0, 5.0)}
    assert checks.no_silent_rescore(b, prev).blocking
    assert checks.model_count(b, 10).blocking and checks.model_count(b, 4).passed


def test_errored_tasks_are_flagged():
    d = board_doc()
    for k, v in list(d["tasks"]["poc"]["lab1/model-1"]["task_results"].items())[:20]:
        v.update(status="error", measurable=False, passed=False)
    c = checks.error_share(source_vals.parse(d))
    assert not c.passed and "lab1/model-1" in c.summary


def test_independence_refuses_a_self_evaluation_even_past_the_registry():
    ev = {"lab": {"develops_models": ["LabCo"]}, "gov": {"develops_models": []}}
    assert checks.independence([{"benchmark_id": "b", "model": "m", "developer": "OtherCo", "evaluator_id": "lab"}], ev).passed
    assert checks.independence([{"benchmark_id": "b", "model": "m", "developer": "LabCo", "evaluator_id": "lab"}], ev).blocking


def test_staleness_and_document_checks():
    assert not checks.staleness({"x:main": "2025-07-14"}, "2026-10-19").passed
    assert checks.staleness({"x:main": "2026-03-13"}, "2026-10-19").passed
    assert checks.document_sane(None).blocking
    assert checks.document_sane({"results": [1], "benchmarks": [{"side": "offence"}]}).blocking
    assert checks.document_sane({"results": [1], "benchmarks": [{"side": "offence"}, {"side": "defence"}]}).passed


def test_non_finite_numbers_are_refused_by_the_parser():
    d = board_doc()
    d["tasks"]["poc"]["lab0/model-0"]["accuracy"] = float("nan")
    with pytest.raises(ValueError):
        source_vals.parse(d)
    d = board_doc()
    d["tasks"]["poc"]["lab0/model-0"]["stderr"] = float("nan")
    assert next(r for r in source_vals.parse(d).rows if r.track == "poc" and r.model_id == "lab0/model-0").stderr is None


@pytest.mark.parametrize("doc", [[], "x", {"metadata": {}, "tasks": {"overall": {"m": []}, "poc": {"m": 1}, "patch": {"m": 1}}}])
def test_a_board_of_the_wrong_type_is_a_parse_error(doc):
    with pytest.raises(ValueError):
        source_vals.parse(doc)


def test_self_evaluation_ignores_case_and_spacing_and_refuses_undisclosed():
    from zdc_aicap.registry import is_self_evaluation
    assert is_self_evaluation(" microsoft ", ["Microsoft"])
    assert is_self_evaluation("undisclosed", ["Microsoft"])
    assert not is_self_evaluation("undisclosed", [])
    assert not is_self_evaluation("Anthropic", ["Microsoft"])


def test_public_summaries_carry_no_board_content():
    b = source_vals.parse(board_doc())
    r = checks.no_silent_rescore(b, {("lab0/model-0", "poc"): (10.0, 1.0)})
    assert "lab0" not in checks.public_summary(r) and "10.0" not in checks.public_summary(r)
    w = EvalResultT("discovery", "warn", False, "::error::x | y\nz", {})
    assert checks.public_summary(w) == "error::x \\| y z"


def test_the_index_check_is_exact_and_order_free_on_ties():
    d = board_doc()
    d["tasks"]["overall"]["lab1/model-1"]["accuracy"] = d["tasks"]["overall"]["lab0/model-0"]["accuracy"]
    b = source_vals.parse(d)
    iv, top = source_vals.top10_from_index(index_text(d))
    assert checks.matches_index(b, iv, top[::-1][-2:] + top[2:] if False else [top[1], top[0]] + top[2:], NAMES).passed
    names = {**NAMES, "lab0/model-0": ["Model 0 Mini", "Lab0"]}
    assert checks.matches_index(b, iv, top, names).blocking            # a prefix is not a match
    assert checks.matches_index(b, None, [], NAMES, index_read=True).blocking


def test_board_freshness():
    assert checks.board_fresh("2026-10-12", "2026-10-19").passed
    assert checks.board_fresh("2026-09-20", "2026-10-19").blocking
    assert checks.board_fresh(None, "2026-10-19").blocking


def _http(handler):
    from zdc_aicap.run import Http
    return Http(transport=httpx.MockTransport(handler))


def test_the_real_client_reads_gzip_bodies():
    import gzip
    body = json.dumps({"ok": 1}).encode()
    h = _http(lambda req: httpx.Response(200, content=gzip.compress(body), headers={"Content-Encoding": "gzip"}))
    r = h.get("https://example.test/x.json")
    assert r.json() == {"ok": 1} and r.text == body.decode()


def test_an_oversized_response_is_not_an_outage(monkeypatch):
    from zdc_aicap import run as arun
    monkeypatch.setattr(arun.Http, "MAX_BYTES", 10)
    page = '<a href="/_astro/benchmark_view_cyberbench.Ab1.json">'
    h = _http(lambda req: httpx.Response(200, content=page.encode() if req.url.path.endswith("cyber") else b"x" * 100))
    out = arun.read_vals(h)
    assert out["net_error"] is None and "TooLarge" in (out["parse_error"] or "")


def test_a_page_that_moved_is_not_an_outage():
    from zdc_aicap import run as arun
    out = arun.read_vals(_http(lambda req: httpx.Response(404, content=b"gone")))
    assert out["net_error"] is None and out["parse_error"] == "page HTTP 404"


def test_a_tie_at_tenth_place_may_list_either_model():
    d = board_doc(n_models=6)
    # models 4 and 5 tie at the bottom of a five-row index
    d["tasks"]["overall"]["lab5/model-5"]["accuracy"] = d["tasks"]["overall"]["lab4/model-4"]["accuracy"]
    b = source_vals.parse({**d, "tasks": {**d["tasks"]}}) if False else None
    for t in ("poc", "patch"):
        d["tasks"][t]["lab5/model-5"] = dict(d["tasks"][t]["lab4/model-4"])
    b = source_vals.parse(d)
    iv, top = source_vals.top10_from_index(index_text(d))
    top5 = [x for x in top if x[0] != "Model 4"][:5]          # the index happened to list model 5
    assert checks.matches_index(b, iv, top5, NAMES).passed


def test_an_index_with_odd_names_parses_or_says_its_format_changed():
    ok = "## CyberBench v1.1\n\n1. [GPT [beta]](https://x/a_(b)): 80.00%\n2. [M](https://x): 70.00%\n"
    assert source_vals.top10_from_index(ok)[1] == [("GPT [beta]", 80.0), ("M", 70.0)]
    with pytest.raises(ValueError):
        source_vals.top10_from_index("## CyberBench v1.1\n\n1. [A](https://x): 80%\n2. A changed line\n")


def test_an_index_that_answers_404_blocks_the_board():
    from zdc_aicap import run as arun
    page = '<a href="/_astro/benchmark_view_cyberbench.Ab1.json">'
    board = json.dumps(board_doc()).encode()
    def h(req):
        u = str(req.url)
        if u == source_vals.PAGE: return httpx.Response(200, content=page.encode())
        if "benchmark_view" in u: return httpx.Response(200, content=board)
        return httpx.Response(404)
    out = arun.read_vals(_http(h))
    assert out["board"] and out["index_refused"]
    c = checks.matches_index(out["board"], out["index_version"], out["top10"], NAMES, out["index_read"] or out["index_refused"])
    assert c.blocking


# ---------------------------------------------------------------- discovery
@pytest.mark.parametrize("title, ok", [
    ("CyberArena: Benchmarking AI Agents in Live Symmetric Attack-and-Defense Combat", True),
    ("ProtoArena: Can AI Agents Discover and Exploit Real-World Cross-Component Protocol Vulnerabilities?", True),
    ("VulnBump: A Benchmark for Fixing Vulnerable Dependencies in Real Projects", True),
    ("MobileJailBench: Red Queen Jailbreak Benchmarking for Mobile Agents", False),
    ("PVFH-Bench: Benchmarking Premise-Induced Visual Fixation Hallucinations in Vision-Language Models", False),
    ("Security in LLM-Assisted Coding: A Systematic Literature Review", False),
    ("An exact finite-state representation of viscoelastic memory", False),
])
def test_discovery_keeps_cyber_benchmarks_and_drops_the_rest(title, ok):
    assert discover.relevant(title, "We evaluate LLM agents.") is ok


def test_arxiv_parsing_keeps_recent_relevant_entries():
    atom = """<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom">
      <entry><id>http://arxiv.org/abs/2610.00001v2</id><published>2026-10-15T00:00:00Z</published>
        <title>ExploitArena: a Benchmark of Exploit Development for LLM Agents</title><summary>LLM agents write exploits.</summary></entry>
      <entry><id>http://arxiv.org/abs/2601.00002v1</id><published>2026-01-01T00:00:00Z</published>
        <title>OldBench: Vulnerability Benchmark for LLM Agents</title><summary>old</summary></entry>
      <entry><id>http://arxiv.org/abs/2610.00003v1</id><published>2026-10-16T00:00:00Z</published>
        <title>A Study of Protein Folding</title><summary>no</summary></entry></feed>"""
    c = discover.parse_arxiv(atom, dt.date(2026, 10, 5))
    assert [x.url for x in c] == ["https://arxiv.org/abs/2610.00001"]


def test_vals_index_reports_only_untracked_cyber_boards():
    txt = ("## CyberBench v1.1\n- Page: https://www.vals.ai/benchmarks/cyber\n- Category: Cyber\n\n"
           "## SOC Bench\n- Page: https://www.vals.ai/benchmarks/soc\n- Category: Security\n- Updated: 2026-10-01\n\n"
           "## Finance Agent\n- Page: https://www.vals.ai/benchmarks/fin\n- Category: Finance\n")
    c = discover.parse_vals_index(txt, {"CyberBench v1.1"})
    assert [x.url for x in c] == ["https://www.vals.ai/benchmarks/soc"]


# ---------------------------------------------------------------- end to end
DSN = os.environ.get("NET_TEST_DATABASE_URL")
e2e = pytest.mark.skipif(not DSN, reason="needs NET_TEST_DATABASE_URL (a migrated database)")


class FakeResp:
    def __init__(self, status, body):
        self.status_code = status
        self.content = body if isinstance(body, bytes) else body.encode()
        self.text = self.content.decode()

    def json(self):
        return json.loads(self.text)


class FakeHttp:
    def __init__(self, doc, index, fail_board=False):
        self.doc, self.index, self.fail_board = doc, index, fail_board

    def get(self, url, github=False):
        if url == source_vals.PAGE:
            return FakeResp(200, '<html><a href="/_astro/benchmark_view_cyberbench.T3st.json">')
        if url.endswith("benchmark_view_cyberbench.T3st.json"):
            return FakeResp(500, "x") if self.fail_board else FakeResp(200, json.dumps(self.doc))
        if url == source_vals.INDEX:
            return FakeResp(200, self.index)
        if "arxiv" in url:
            return FakeResp(200, '<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"></feed>')
        if "github" in url:
            return FakeResp(200, '{"items": []}')
        return FakeResp(200, "[]")


@pytest.fixture
def db(monkeypatch):
    import psycopg
    cx = psycopg.connect(DSN)
    def clean():
        cx.execute("set session_replication_role = replica")
        for t in ("observations", "fetches", "candidates", "events", "benchmarks", "evaluators"):
            cx.execute(f"delete from aicap.{t}")
        cx.execute("delete from raw.pipeline_runs where pipeline = 'aicap'")
        cx.execute("set session_replication_role = origin")
        cx.commit()
    clean()
    monkeypatch.setenv("DATABASE_URL", DSN)
    yield cx
    clean()
    cx.close()


def run_report(monkeypatch, doc, **kw):
    import tempfile
    with tempfile.NamedTemporaryFile("r", suffix=".json") as f:
        run_with(monkeypatch, doc, report=f.name, **kw)
        return json.load(open(f.name))


def run_with(monkeypatch, doc, *, fail_board=False, reg_patch=None, report=None):
    from zdc_aicap import run as arun
    real = registry.load()
    reg = copy.deepcopy(real)
    reg["model_names"].update(NAMES)
    for b in reg["benchmarks"]:
        if b["source"] == "vals":
            b["tasks"] = 60 if b["track"] == "poc" else 56
    if reg_patch:
        reg_patch(reg)
    monkeypatch.setattr(arun.registry, "load", lambda directory=None: reg)
    args = types.SimpleNamespace(no_write=False, skip_discovery=False, report=report, trigger="test")
    return arun.run(args, FakeHttp(doc, index_text(doc), fail_board), TODAY)


@e2e
def test_a_week_is_written_and_the_page_document_builds(db, monkeypatch):
    assert run_with(monkeypatch, board_doc()) == 0
    doc = db.execute("select public.aicap_document()").fetchone()[0]
    assert {b["side"] for b in doc["benchmarks"]} == {"offence", "defence"}
    assert doc["board"]["version"] == "1.1" and len(doc["board"]["rows"]) == 12
    assert any(r["b"] == "vals-cyberbench-find" for r in doc["results"]) and any(r["b"] == "caisi-exploitbench" for r in doc["results"])
    assert not any(r["t"] == "overall" for r in doc["results"])        # overall belongs to the board block only
    assert not any(r["model"].startswith("Best US model") and r["dev"] != "undisclosed" for r in doc["results"])
    # ExploitGym was co-written with Anthropic, OpenAI and Google researchers: none of its results may reach the page
    assert not any(r["ev"] == "berkeley-rdi" for r in doc["results"])
    assert {s for (s,) in db.execute("select source from aicap.fetches").fetchall()} == {"vals-page", "vals-board", "vals-index"}
    assert db.execute("select count(*) from raw.pipeline_runs where pipeline = 'aicap' and ok").fetchone()[0] == 1
    assert {e["id"] for e in doc["events"]} == {e["id"] for e in registry.load()["events"] if e.get("evidence")}


@e2e
def test_a_silent_rescore_blocks_the_week_and_writes_no_results(db, monkeypatch):
    assert run_with(monkeypatch, board_doc()) == 0
    n = db.execute("select count(*) from aicap.observations").fetchone()[0]
    d = board_doc()
    d["tasks"]["poc"]["lab0/model-0"]["accuracy"] = 30.0
    d["tasks"]["overall"]["lab0/model-0"]["accuracy"] = (30.0 + 85) / 2
    fetched = db.execute("select count(*) from aicap.observations where origin = 'fetched'").fetchone()[0]
    assert run_with(monkeypatch, d) == 1
    # the board is kept out; the curated results, which do not depend on vals, still go in
    assert db.execute("select count(*) from aicap.observations where origin = 'fetched'").fetchone()[0] == fetched
    assert db.execute("select count(*) from aicap.observations").fetchone()[0] > n
    assert db.execute("select count(*) from raw.pipeline_runs where pipeline = 'aicap' and not ok").fetchone()[0] == 1


@e2e
def test_vals_unreachable_keeps_last_week_and_still_writes_the_registry(db, monkeypatch):
    assert run_with(monkeypatch, board_doc(), fail_board=True) == 1      # never read: the run fails, so it is seen
    doc = db.execute("select public.aicap_document()").fetchone()[0]
    assert doc["board"]["rows"] is None                                    # nothing stored yet, nothing invented
    assert any(r["b"] == "cti-realm" for r in doc["results"])              # the curated results still went through
    assert run_with(monkeypatch, board_doc()) == 0
    assert run_with(monkeypatch, board_doc(), fail_board=True) == 0
    doc = db.execute("select public.aicap_document()").fetchone()[0]
    assert len(doc["board"]["rows"]) == 12                                 # last week's board is kept


def test_a_co_authored_benchmark_refuses_its_authors_models():
    r = registry.load()
    r["results"].append({"benchmark": "berkeley-exploitgym", "version": "2026-05", "model": "Claude Mythos Preview", "developer": "Anthropic",
                         "score": 17.48, "n": 898, "published_on": "2026-05-13", "source_url": "https://rdi.berkeley.edu/x",
                         "evidence": "157 of 898", "verified_on": "2026-10-19"})
    assert any("self-evaluation" in p for p in registry.validate(r, TODAY))


@e2e
def test_a_self_evaluation_is_stopped_by_the_independence_gate_itself(db, monkeypatch):
    """With the registry check switched off, the row-level gate must still block it."""
    def add_self(reg):
        reg["results"].append({"benchmark": "cti-realm", "version": "2026-03", "model": "MAI-1", "developer": " microsoft ",
                               "score": 0.9, "published_on": "2026-03-13", "source_url": "https://arxiv.org/abs/2603.13517",
                               "evidence": "0.9", "verified_on": "2026-10-19"})
    monkeypatch.setattr(registry, "validate", lambda reg, today: [])
    rep = run_report(monkeypatch, board_doc(), reg_patch=add_self)
    assert rep["ok"] is False
    assert [c["name"] for c in rep["checks"] if not c["passed"] and c["severity"] == "error"] == ["independent_only"]
    assert db.execute("select count(*) from aicap.observations").fetchone()[0] == 0


@e2e
def test_a_vals_result_keeps_the_date_it_first_appeared(db, monkeypatch):
    assert run_with(monkeypatch, board_doc()) == 0
    d = board_doc(n_models=5)
    d["metadata"]["updated"] = "2026-10-19"
    assert run_with(monkeypatch, d) == 0
    doc = db.execute("select public.aicap_document()").fetchone()[0]
    pub = {r["model"]: r["pub"] for r in doc["results"] if r["b"] == "vals-cyberbench-find"}
    assert pub["Model 0"] == "2026-10-12" and pub["Model 4"] == "2026-10-19"


@e2e
def test_a_rescore_is_blocked_by_the_rescore_gate_and_nothing_else(db, monkeypatch):
    assert run_with(monkeypatch, board_doc()) == 0
    d = board_doc()
    d["tasks"]["patch"]["lab1/model-1"]["accuracy"] = 50.0
    d["tasks"]["overall"]["lab1/model-1"]["accuracy"] = (73 + 50.0) / 2
    rep = run_report(monkeypatch, d)
    failed = [c["name"] for c in rep["checks"] if not c["passed"] and c["severity"] == "error"]
    assert failed == ["vals_no_silent_rescore"]


@e2e
def test_no_board_content_reaches_the_public_log_or_report(db, monkeypatch, caplog):
    assert run_with(monkeypatch, board_doc()) == 0
    d = board_doc()
    d["tasks"]["poc"]["lab2/model-2"]["accuracy"] = 12.345
    d["tasks"]["overall"]["lab2/model-2"]["accuracy"] = (12.345 + 79) / 2
    d["tasks"]["poc"]["lab3/model-3"]["task_results"] = {f"poc:x:{k}": {"passed": False, "status": "error"} for k in range(60)}
    caplog.set_level("INFO", logger="zdc_aicap")
    rep = run_report(monkeypatch, d)
    public = caplog.text + json.dumps(rep)
    assert rep["ok"] is False
    for secret in ("lab2/model-2", "lab3/model-3", "Model 2", "12.3", "45.67"):
        assert secret not in public, secret
    # the detail is kept, privately, on the run record
    notes = db.execute("select notes from raw.pipeline_runs where pipeline = 'aicap' order by started_at desc limit 1").fetchone()[0]
    assert "lab2/model-2" in json.dumps(notes)
    # the whole list, not the first four in a summary
    share = next(c for c in notes["checks"] if c["name"] == "vals_error_share")
    assert any("lab3/model-3" in m for m in share["detail"]["models"])
    # an exception whose text quotes a row (psycopg's DETAIL line) is not printed either
    from zdc_aicap import db as adb
    def boom(conn, rows):
        raise RuntimeError("violates check constraint\nDETAIL:  Failing row contains (-87.3, secret-model-x).")
    monkeypatch.setattr(adb, "insert_observations", boom)
    caplog.clear()
    rep2 = run_report(monkeypatch, board_doc())
    assert rep2["ok"] is False and "secret-model-x" not in caplog.text + json.dumps(rep2)
