"""CVE pass of the breach pipeline: one prompt file, its hash, the gate mirror, and cve_id scoring.

Synthetic data only; no network, no database. Every test names the mutant it exists to kill.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from conftest import REPO_ROOT, requires_repo_files
from zdc_breach import cve_extract, extract, gold

SKILL = REPO_ROOT / ".claude/skills/breach-cve-extraction/SKILL.md"
SQL_0137 = REPO_ROOT / "supabase/migrations/0137_breach_cve_links.sql"

DOC = ("Acme Health said attackers gained initial access by exploiting CVE-2031-10001 in its file-transfer "
       "server. Globex Corp may have been hit through CVE-2031-10002, the company is investigating whether "
       "it was. The flaw, CVE-2031-10003, was reported by Initech Labs and patched by Hooli. "
       "The gang claimed on its leak site that Umbrella was breached via CVE-2031-10004. "
       "Patients were told the breach exploited CVE-2031-10005.")


def link(cve, org, role, quote, basis="news", **kw):
    d = {"cve_id": cve, "organization": org, "role": role, "named_in_sentence": True,
         "vendor_self": False, "basis": basis, "quote": quote}
    d.update(kw)
    return d


S_ACME = ("Acme Health said attackers gained initial access by exploiting CVE-2031-10001 in its "
          "file-transfer server.")
S_GLOBEX = ("Globex Corp may have been hit through CVE-2031-10002, the company is investigating whether "
            "it was.")
S_HOOLI = "The flaw, CVE-2031-10003, was reported by Initech Labs and patched by Hooli."
S_UMB = "The gang claimed on its leak site that Umbrella was breached via CVE-2031-10004."
S_PAT = "Patients were told the breach exploited CVE-2031-10005."


# ---- one text ------------------------------------------------------------------------------------

def test_prompt_lint_no_ids_products_or_victims():
    """Mutant: a few-shot example with a real CVE ID, product nickname or victim in the prompt."""
    t = cve_extract.prompt_text()
    assert not re.search(r"CVE-\d{4}-", t)
    for word in ("moveit", "citrix", "eternalblue", "log4", "proxylogon", "proxyshell", "accellion",
                 "goanywhere", "fortinet", "ivanti", "pulse secure", "exchange", "solarwinds", "kaseya",
                 "confluence", "cleo", "zerologon", "printnightmare", "bleed"):
        assert word not in t.lower(), word


@requires_repo_files(".claude/skills/breach-cve-extraction/SKILL.md")
def test_skill_points_at_the_prompt_and_restates_none_of_it():
    """Mutant: rubric text pasted into SKILL.md (two texts that can drift)."""
    skill = SKILL.read_text()
    assert "pipeline/zdc_breach/prompts/cve_extraction.md" in skill
    rubric_lines = [l.strip() for l in cve_extract.prompt_text().splitlines() if len(l.strip()) >= 25]
    assert rubric_lines and not [l for l in rubric_lines if l in skill]


def test_prompt_hash_follows_the_file(tmp_path, monkeypatch):
    """Mutant: prompt_hash computed from a constant instead of the file."""
    h0 = cve_extract.prompt_hash("m")
    p = tmp_path / "cve_extraction.md"
    p.write_text(cve_extract.prompt_text() + "\nOne more rule.\n")
    monkeypatch.setattr(cve_extract, "PROMPT_PATH", p)
    assert cve_extract.prompt_hash("m") != h0
    assert cve_extract.prompt_hash("m") != cve_extract.prompt_hash("other-model")


def test_user_message_cuts_at_max_chars():
    """Mutant: the agent sees more text than the pipeline would send."""
    m = cve_extract.user_message("T", "https://x", "a" * 20000)
    assert m.count("a") == cve_extract.MAX_CHARS


def test_has_cve_scope():
    """Mutant: the CVE pass runs on every document."""
    assert cve_extract.has_cve("exploited CVE-2024-1234 today")
    assert not cve_extract.has_cve("a breach with no identifier")


# ---- validate ---------------------------------------------------------------------------------------

def _by(links):
    return {(l.cve_id, l.organization): l for l in links}


def test_validate_accepts_named_initial_access():
    out = {"links": [link("CVE-2031-10001", "Acme Health", "initial_access", S_ACME)]}
    (l,) = cve_extract.validate(out, DOC)
    assert l.accepted and l.public_candidate and l.role == "initial_access"


def test_quote_not_verbatim_is_rejected():
    """Mutant: grounding.check skipped."""
    out = {"links": [link("CVE-2031-10001", "Acme Health", "initial_access",
                          "Acme Health was breached via CVE-2031-10001.")]}
    (l,) = cve_extract.validate(out, DOC)
    assert not l.accepted and l.reject_reason == "quote_not_in_document" and not l.public_candidate


def test_cve_must_be_in_the_quote():
    """Mutant: a quote that does not carry the CVE ID proves it."""
    out = {"links": [link("CVE-2031-10009", "Acme Health", "initial_access", S_ACME)]}
    (l,) = cve_extract.validate(out, DOC)
    assert not l.accepted


def test_hedge_downgrades_to_mentioned():
    """Mutant: HEDGE not applied."""
    out = {"links": [link("CVE-2031-10002", "Globex Corp", "exploited", S_GLOBEX)]}
    (l,) = cve_extract.validate(out, DOC)
    assert l.accepted and l.role == "mentioned" and not l.public_candidate and l.hold_reason == "mentioned_only"


def test_attacker_claim_downgrades_to_mentioned():
    """Mutant: threat_actor_claim basis left public."""
    out = {"links": [link("CVE-2031-10004", "Umbrella", "initial_access", S_UMB, basis="threat_actor_claim")]}
    (l,) = cve_extract.validate(out, DOC)
    assert l.role == "mentioned" and not l.public_candidate


def test_vendor_or_reporter_is_held():
    """Mutant: rule 7 dropped (BeyondTrust / DIVD as a victim)."""
    out = {"links": [link("CVE-2031-10003", "Hooli", "exploited", S_HOOLI),
                     link("CVE-2031-10003", "Initech Labs", "exploited", S_HOOLI)]}
    meta = {"CVE-2031-10003": {"vendors": ["hooli"], "assigner": "Initech"}}
    got = _by(cve_extract.validate(out, DOC, meta))
    assert got[("CVE-2031-10003", "Hooli")].hold_reason == "victim_is_vendor_or_reporter"
    assert got[("CVE-2031-10003", "Initech Labs")].hold_reason == "victim_is_vendor_or_reporter"
    assert not any(l.public_candidate for l in got.values())


def test_quote_without_the_organisation_is_held():
    """Mutant: rule 6 dropped (HIQ: the document names the victim, the quote does not)."""
    out = {"links": [link("CVE-2031-10005", "Acme Health", "exploited", S_PAT, named_in_sentence=False)]}
    (l,) = cve_extract.validate(out, DOC)
    assert l.accepted and l.hold_reason == "quote_lacks_subject_or_cve" and not l.public_candidate


def test_generic_or_missing_organisation_is_never_a_victim():
    """Mutant: GENERIC_ORG check removed."""
    out = {"links": [link("CVE-2031-10005", "the hospital", "exploited", S_PAT),
                     link("CVE-2031-10001", None, "exploited", S_ACME)]}
    assert all(l.role == "mentioned" for l in cve_extract.validate(out, DOC))


def test_a_name_starting_with_the_is_not_generic():
    """Mutant: any name beginning with 'The' treated as generic (dropped The Washington Post on dev, round 1)."""
    q = "Attackers exploited CVE-2031-10001 to breach The Washington Post in July."
    doc = q + " Nothing else."
    out = {"links": [link("CVE-2031-10001", "The Washington Post", "exploited", q)]}
    (l,) = cve_extract.validate(out, doc)
    assert l.role == "exploited" and l.public_candidate
    for g in ("the company", "The hospital", "Company #3", "several universities", "Victims"):
        assert cve_extract.GENERIC_ORG.search(g), g


def test_researcher_basis_maps_to_claim_basis_enum():
    """Mutant: 'researcher' written to claims.basis, which the enum rejects."""
    out = {"links": [link("CVE-2031-10001", "Acme Health", "initial_access", S_ACME, basis="researcher")]}
    (l,) = cve_extract.validate(out, DOC)
    assert l.basis == "news"


# ---- attach, never create (RULING verify-B1, 2026-10-21) ----------------------------------------------

from datetime import date  # noqa: E402

T = [{"incident_id": "inc-acme", "org_id": "org-acme", "norm_name": "acme health", "alias_norms": ["acme hc"]}]


def test_attaches_to_the_documents_own_incident_country_blind():
    """Mutant: step 3 skipped (no target ever matches); B3 test 2's name half."""
    r = cve_extract.resolve_target("Acme Health, Inc.", T)
    assert (r.incident_id, r.how, r.unattached) == ("inc-acme", "document_incident", None)
    assert cve_extract.resolve_target("ACME HC", T).incident_id == "inc-acme"          # alias key


def test_two_targets_that_normalise_alike_are_ambiguous():
    """Mutant: the first of several matching targets is taken (B3 test 4)."""
    t2 = T + [{"incident_id": "inc-acme-2", "org_id": "org-acme-2", "norm_name": "acme health", "alias_norms": []}]
    r = cve_extract.resolve_target("Acme Health", t2)
    assert (r.incident_id, r.unattached) == (None, "ambiguous_target")


def test_a_name_is_never_a_hard_key():
    """Mutant: an organisation outside the document's targets found by name (B3 tests 3 and 7)."""
    key = [{"org_id": "org-globex", "domain": "globex.com", "sec_cik": None,
            "incidents": [{"incident_id": "inc-g", "first_public_date": date(2026, 9, 1)}]}]
    assert cve_extract.resolve_target("Globex", T, key_orgs=key).unattached == "name_not_in_doc_incidents"
    assert cve_extract.resolve_target("Globex", [], key_orgs=key, published=date(2026, 9, 5)).unattached == "no_target"


def test_hard_key_attaches_inside_the_document_or_by_date():
    """Mutants: domain ignored; date window ignored; several incidents -> first (B3 test 7)."""
    key = [{"org_id": "org-globex", "domain": "globex.com", "sec_cik": "0000123",
            "incidents": [{"incident_id": "inc-g", "first_public_date": date(2026, 9, 1)},
                          {"incident_id": "inc-g-old", "first_public_date": date(2024, 1, 1)}]}]
    tg = T + [{"incident_id": "inc-g", "org_id": "org-globex", "norm_name": "globex ltd", "alias_norms": []}]
    r = cve_extract.resolve_target("Globex Europe", tg, link_domain="GLOBEX.com", key_orgs=key)
    assert (r.incident_id, r.how) == ("inc-g", "hard_key_in_doc")
    tg2 = tg + [{"incident_id": "inc-g9", "org_id": "org-globex", "norm_name": "globex holdings", "alias_norms": []}]
    assert cve_extract.resolve_target("Globex Europe", tg2, link_domain="globex.com", key_orgs=key).unattached == "ambiguous_target"
    r = cve_extract.resolve_target("Globex Europe", [], link_cik="0000123", key_orgs=key, published=date(2026, 10, 1))
    assert (r.incident_id, r.how) == ("inc-g", "hard_key_by_date")
    r = cve_extract.resolve_target("Globex Europe", [], link_cik="0000123", key_orgs=key, published=date(2025, 6, 1))
    assert r.unattached == "no_target"                                                # outside +-90 days
    key[0]["incidents"].append({"incident_id": "inc-g2", "first_public_date": date(2026, 9, 20)})
    r = cve_extract.resolve_target("Globex Europe", [], link_cik="0000123", key_orgs=key, published=date(2026, 10, 1))
    assert r.unattached == "ambiguous_target"


def test_plan_attaches_only_to_targets_and_creates_nothing():
    """Mutant: an unattached link counted as attached (B3 test 9's invariant)."""
    from zdc_breach import cve_agent_load
    doc = DOC.replace("Patients were told", "Brand New Company said")
    q_new = "Brand New Company said the breach exploited CVE-2031-10005."
    out = {"links": [link("CVE-2031-10001", "Acme Health", "initial_access", S_ACME),
                     link("CVE-2031-10005", "Brand New Company", "exploited", q_new)]}
    res = cve_agent_load.plan([{"doc": "sha1", "output": out}], {"sha1": doc}, {"sha1": T})
    assert res["attached"] == 1 and res["attached_by"] == {"document_incident": 1}
    assert res["unattached"] == {"name_not_in_doc_incidents": 1}
    assert res["attached"] + sum(res["unattached"].values()) == res["accepted_non_mentioned"] == 2
    assert res["organisations_created"] == res["incidents_created"] == 0


def test_single_filer_never_calls_an_organisation_creating_path():
    """Mutant: the loader goes back through run.file_output / find_or_create_org (B3 test 6, static half)."""
    from zdc_breach import cve_agent_load
    src = Path(cve_agent_load.__file__).read_text()
    for banned in ("file_output(", "find_or_create_org", "resolve_incident(", "set_flag(", "Resolver(",
                   "insert into breach_core.organizations", "insert into breach_core.incidents"):
        assert banned not in src, banned
    assert src.count("run.file_candidate(") == 1 and "resolve_target(" in src


def test_main_extractor_keeps_the_exploited_role():
    """Mutant: extract._judge maps 'exploited' (0136) to 'mentioned'."""
    out = {"is_incident_report": True, "incidents": [{"organization": "Acme Health", "facts": [
        {"field": "cve_id", "value": "CVE-2031-10001", "unit": "none", "qualifier": "not_applicable",
         "cve_role": "exploited", "quote": S_ACME}]}]}
    (ei,) = extract.validate(out, DOC)
    (c,) = ei.candidates
    assert c.accepted and c.cve_role == "exploited"


def test_to_candidate_keeps_the_role_and_quote():
    """Mutant: the role is dropped (the claim path would file 'mentioned')."""
    out = {"links": [link("CVE-2031-10001", "Acme Health", "exploited", S_ACME)]}
    (lk,) = cve_extract.validate(out, DOC)
    c = cve_extract.to_candidate(lk, DOC)
    assert (c.field, c.value, c.cve_role, c.accepted, c.subject_match) == ("cve_id", "CVE-2031-10001", "exploited", True, True)
    assert c.quote_start is not None and c.quote_end > c.quote_start


@requires_repo_files("supabase/migrations/0137_breach_cve_links.sql")
def test_gate_mirror_pinned_to_sql():
    """The Python mirror copies 0137's predicates. Mutant: the SQL gate changes and the mirror does not."""
    sql = SQL_0137.read_text()
    for frag in ("length(regexp_replace(lower(vnd), '[^a-z0-9]', '', 'g')) >= 3",
                 "regexp_replace(lower(vnd), '[^a-z0-9]', '', 'g') = regexp_replace(o.norm_name, '[^a-z0-9]', '', 'g')",
                 "(' ' || o.norm_name || ' ') like ('% ' || lower(vnd) || ' %')",
                 "split_part(coalesce(o.domain, ''), '.', 1) = regexp_replace(lower(vnd), '[^a-z0-9]', '', 'g')",
                 "position(ic.cve_id in upper(c.quote)) > 0",
                 "position(lower(o.display_name) in lower(c.quote)) > 0",
                 "length(o.norm_name) >= 4 and position(o.norm_name in lower(c.quote)) > 0"):
        assert frag in sql, frag
    assert cve_extract.vendor_or_reporter("Hooli Inc", None, ["hooli"], None)
    assert cve_extract.vendor_or_reporter("Acme", "hooli.com", ["Hooli"], None)
    assert not cve_extract.vendor_or_reporter("Acme Health", None, ["ab"], None)  # < 3 chars ignored
    assert cve_extract.quote_ok("CVE-2031-10001", "Acme Health", S_ACME)
    assert not cve_extract.quote_ok("CVE-2031-10005", "Acme Health", S_PAT)


# ---- scoring -----------------------------------------------------------------------------------------

def test_wilson_matches_the_advisor_example():
    """Mutant: normal approximation instead of Wilson (97/100 would give LB 0.937)."""
    lb, ub = gold.wilson(97, 100)
    assert lb == pytest.approx(0.9155, abs=1e-3) and ub > 0.97
    assert gold.wilson(0, 0) == (None, None)


def _score(pred_links, gold_links):
    labels = {"s2:a": {"stratum": "s2", "links": gold_links}}
    return gold.score_cve(labels, {"s2:a": DOC}, {"s2:a": {"links": pred_links}})


def test_score_counts_a_mentioned_gold_pair_as_a_false_positive_and_a_leak():
    """Mutant: gold role ignored when matching (a mention counted correct)."""
    acme = link("CVE-2031-10001", "Acme Health", "initial_access", S_ACME)
    pat = link("CVE-2031-10005", "Acme Health", "exploited", S_ACME.replace("10001", "10005"))
    r = _score([acme], [dict(acme, role="mentioned")])
    assert r["correct_pairs"] == 0 and r["accepted_pairs"] == 1
    assert r["leaked_mentioned"] == 1 and r["leak_rate"] == 1.0
    r = _score([acme], [acme])
    assert r["correct_pairs"] == 1 and r["precision"] == 1.0 and r["recall_named"] == 1.0


def test_score_only_counts_what_the_gate_would_publish():
    """Mutant: precision scored on raw model output instead of public candidates."""
    glob = link("CVE-2031-10002", "Globex Corp", "exploited", S_GLOBEX)
    r = _score([glob], [])
    assert r["accepted_pairs"] == 0


def test_verdict_needs_support_bound_leak_recall_and_campaign_robustness():
    """Mutants: the 0.95 / support-5 rule reused for cve_id; the bound or campaign check dropped."""
    ok = {"accepted_pairs": 120, "precision": 0.983, "wilson_lb": 0.95, "cluster_bootstrap_lb": 0.93,
          "leak_rate": 0.0, "recall_named": 0.9, "largest_cve_group": {"precision_without": 0.97},
          "initial_access": {"predicted": 0, "correct": 0, "precision": None, "wilson_lb": None}}
    assert gold.cve_verdict(ok)["pass"]
    for bad in ({"accepted_pairs": 59}, {"precision": 0.94}, {"cluster_bootstrap_lb": 0.89},
                {"leak_rate": 0.03}, {"recall_named": 0.4}, {"largest_cve_group": {"precision_without": 0.94}}):
        assert not gold.cve_verdict(dict(ok, **bad))["pass"], bad
    # Wilson is reported, never the gate: a high Wilson cannot rescue a low cluster bound.
    assert not gold.cve_verdict(dict(ok, wilson_lb=0.99, cluster_bootstrap_lb=0.85))["pass"]
    assert not gold.cve_verdict(dict(ok, accepted_pairs=80), {**gold.CVE_THRESHOLDS, "min_support": 100})["pass"]


def test_cluster_bound_is_lower_than_wilson_when_errors_share_a_document():
    """Mutant: per-pair Wilson used as the bound (ADVISOR split ruling)."""
    per_doc = {f"d{i}": (3, 3) for i in range(29)}
    per_doc["bad"] = (0, 4)                      # 91 pairs, all 4 errors in one document
    k = sum(v[0] for v in per_doc.values()); n = sum(v[1] for v in per_doc.values())
    lb = gold.cluster_bootstrap_lb(per_doc)
    assert lb < gold.wilson(k, n)[0]
    assert gold.cluster_bootstrap_lb(per_doc) == lb          # fixed seed: reproducible
    assert gold.cluster_bootstrap_lb({}) is None


def test_campaign_removed_precision():
    """Mutant: the largest CVE group is not removed (a one-campaign prompt passes)."""
    s1 = "Acme Health said attackers gained initial access by exploiting CVE-2031-10001 in its file-transfer server."
    pred = [link("CVE-2031-10001", "Acme Health", "initial_access", s1)]
    labels = {"s1:a": {"links": [dict(pred[0])]}}
    r = gold.score_cve(labels, {"s1:a": DOC}, {"s1:a": {"links": pred}})
    g = r["largest_cve_group"]
    assert g["cve_id"] == "CVE-2031-10001" and g["accepted_without"] == 0 and g["precision_without"] is None
    assert not r["verdict"]["checks"]["campaign_removed"]
    # Two CVEs: the campaign (largest gold group) is right, the other is wrong -> 0/1 once it is removed.
    wrong = link("CVE-2031-10003", "Initech Labs", "exploited", S_HOOLI)
    r = gold.score_cve(labels, {"s1:a": DOC}, {"s1:a": {"links": pred + [wrong]}})
    assert r["precision"] == 0.5 and r["largest_cve_group"]["precision_without"] == 0.0


def test_sealed_holdout_opens_once(tmp_path):
    """Mutants: scoring a sealed hold-out without --final; a second --final."""
    lab = tmp_path / "h.jsonl"
    lab.write_text(json.dumps({"doc": "s2:a", "links": []}) + "\n")
    man = tmp_path / "m.json"
    man.write_text(json.dumps({"holdouts": {"H-agent": {"labels_sha256": gold._sha256_file(str(lab))}}}))
    with pytest.raises(gold.SealedHoldout):
        gold.check_seal(str(lab), str(man), final=False)
    assert gold.check_seal(str(lab), str(man), final=True) == "H-agent"
    gold.record_opening(str(man), "H-agent", "abc", {"verdict": {"pass": False}})
    with pytest.raises(gold.SealedHoldout):
        gold.check_seal(str(lab), str(man), final=True)
    other = tmp_path / "dev.jsonl"
    other.write_text("{}\n")
    assert gold.check_seal(str(other), str(man), final=False) is None
    with pytest.raises(gold.SealedHoldout):
        gold.check_seal(str(other), str(man), final=True)
