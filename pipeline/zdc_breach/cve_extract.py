"""CVE -> breached organisation links from one document: prompt, validator and the gate mirror.

ONE TEXT. The rubric and the prompt are the same file, `prompts/cve_extraction.md`. Gold labellers
read it as the rubric, the extractor (a Claude subagent via agent_load, or OpenRouter via run.py)
receives it as the system prompt, and `.claude/skills/breach-cve-extraction/SKILL.md` points at it
without restating it. `prompt_hash(model)` hashes the model id, the file and the user template, so an
edited rubric is a new extractor version and can never inherit an earlier gold result.

THE MODEL PROPOSES, THE GATE DISPOSES. `validate` turns the model's JSON into Link candidates and
judges every one deterministically:
  - grounding.check('cve_id', ...): the quote is verbatim in the document and contains the CVE ID,
    and the quote is not negated;
  - the role is one of the four; a hedged quote ("may have", "believed", "investigating whether")
    or an attacker's claim is downgraded to `mentioned`, never upgraded;
  - a generic organisation ("a hospital", "the company") is not a victim.
`public_candidate` mirrors the two machine-only rules of breach_core.cve_link_gate (0137, RULING s4):
rule 6 - the quote itself names the CVE and the organisation; rule 7 - the organisation is not the
CVE's vendor or its assigner. The SQL function stays the only gate that publishes; this mirror exists
so precision is scored on what the gate would let through (ADVISOR s5), and a test pins the two
predicates to the SQL text.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from . import grounding
from .normalize import norm_name

SCHEMA_VERSION = "breach-cve-v1"
PROMPT_PATH = Path(__file__).with_name("prompts") / "cve_extraction.md"
USER_TEMPLATE = "TITLE: {title}\nURL: {url}\n\nARTICLE:\n<<<\n{text}\n>>>"
MAX_CHARS = 14000          # the same cut run.extract_doc applies to the main extraction

ROLES = ("initial_access", "post_access", "exploited", "mentioned")
PUBLIC_ROLES = {"initial_access", "post_access", "exploited"}
# claim_basis has no 'researcher': a security firm's account of an attack is press-grade evidence.
BASIS = {"victim_statement": "victim_statement", "regulator_filing": "regulator_filing",
         "news": "news", "researcher": "news", "threat_actor_claim": "threat_actor_claim"}

# A hedge in the supporting sentence makes the link 'mentioned' whatever the model said.
HEDGE = re.compile(r"\b(may have|might have|could have|may be|possibly|potentially|believed|suspected|"
                   r"likely|unclear whether|not (?:yet )?known whether|investigat\w+ whether|"
                   r"whether or not|it is not clear|cannot confirm|could not confirm|unconfirmed)\b", re.I)
# English half of breach_core.is_generic_name (0108/0130), plus vague plurals and quantifiers that
# never name anyone. "The Washington Post" is a name; "the company" is not.
GENERIC_ORG = re.compile(r"^\s*(?:an?|some|several|many|multiple|unnamed|unknown|undisclosed|other)\s|"
                         r"^\s*the\s+(?:victim|company|organi[sz]ation|firm|business|hospital|school|agency|provider)\s*$|"
                         r"company\s*#\s*\d|\bvictim\s*#?\s*\d|^\s*(?:n/?a|tbd|redacted)\s*$|\*{2,}|"
                         r"^\s*(?:the\s+)?(?:victims?|organi[sz]ations?|companies|customers|users|businesses|"
                         r"government agencies|hospitals|universities)\s*$", re.I)


def prompt_text() -> str:
    return PROMPT_PATH.read_text(encoding="utf-8")


def prompt_hash(model: str) -> str:
    return hashlib.sha256(f"{model}\n{SCHEMA_VERSION}\n{prompt_text()}\n{USER_TEMPLATE}".encode()).hexdigest()[:16]


def file_hash() -> str:
    """sha256 of the prompt file alone: what SKILL.md and the extractor_versions note record."""
    return hashlib.sha256(PROMPT_PATH.read_bytes()).hexdigest()


def user_message(title: str | None, url: str | None, text: str) -> str:
    return USER_TEMPLATE.format(title=title or "", url=url or "", text=(text or "")[:MAX_CHARS])


def has_cve(text: str | None) -> bool:
    """The CVE pass runs only on documents whose text carries a CVE ID (ADVISOR s7)."""
    return bool(grounding.CVE.search(text or ""))


@dataclass
class Link:
    cve_id: str
    organization: str | None
    role: str                      # after the gate's downgrades
    model_role: str                # what the model said
    basis: str
    quote: str
    named_in_sentence: bool
    vendor_self: bool
    accepted: bool = False         # the claim passes the evidence gate (stored as accepted)
    reject_reason: str | None = None
    public_candidate: bool = False  # would pass cve_link_gate rules 1, 6, 7 if the extractor were active
    hold_reason: str | None = None
    domain: str | None = None       # reserved: only a hard key, never asked for by the current prompt
    cik: str | None = None


def _sql_norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def vendor_or_reporter(org: str, domain: str | None, vendors: list[str] | None, assigner: str | None) -> bool:
    """Mirror of 0137's p_vendor_or_reporter: the organisation is the CVE's vendor or assigner."""
    on = norm_name(org)
    for v in list(vendors or []) + ([assigner] if assigner else []):
        nv = _sql_norm(v)
        if len(nv) < 3:
            continue
        if nv == _sql_norm(on) or f" {(v or '').lower()} " in f" {on} " or \
                (domain or "").split(".")[0] == nv:
            return True
    return False


def quote_ok(cve_id: str, org: str, quote: str, aliases: list[str] | None = None) -> bool:
    """Mirror of 0137's p_quote_ok: the quote contains the CVE ID and the organisation's name,
    its normalised name (>= 4 chars) or an alias (>= 4 chars)."""
    q = quote or ""
    if cve_id.upper() not in q.upper():
        return False
    on = norm_name(org)
    return (org.lower() in q.lower() or (len(on) >= 4 and on in q.lower())
            or any(len(a) >= 4 and a.lower() in q.lower() for a in (aliases or [])))


def validate(output: dict, document: str, cve_meta: dict | None = None) -> list[Link]:
    """Every link the model proposed, judged. cve_meta: {CVE: {"vendors": [...], "assigner": str}}."""
    if not isinstance(output, dict):
        return []
    doc = (document or "")[:MAX_CHARS]
    seen, out = set(), []
    for raw in output.get("links") or []:
        if not isinstance(raw, dict):
            continue
        cve = str(raw.get("cve_id") or "").strip().upper()
        org = raw.get("organization")
        org = " ".join(str(org).split())[:200] if isinstance(org, str) and org.strip() else None
        model_role = raw.get("role") if raw.get("role") in ROLES else "mentioned"
        basis = BASIS.get(raw.get("basis"), "news")
        quote = str(raw.get("quote") or "")
        lk = Link(cve, org, model_role, model_role, basis, quote,
                  bool(raw.get("named_in_sentence")), bool(raw.get("vendor_self")),
                  domain=(str(raw["domain"]).strip().lower() or None) if raw.get("domain") else None,
                  cik=(str(raw["cik"]).strip() or None) if raw.get("cik") else None)
        key = (cve, norm_name(org or ""))
        if key in seen:
            lk.reject_reason = "duplicate_link"
            out.append(lk)
            continue
        seen.add(key)
        if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", cve):
            lk.reject_reason = "not_a_cve_id"
        else:
            lk.reject_reason = grounding.check("cve_id", cve, quote, doc)
        if lk.reject_reason is None and len(grounding.norm(quote)) > 400:
            lk.reject_reason = "quote_too_long"
        # Downgrades: the gate may weaken a role, never strengthen one.
        if lk.role != "mentioned":
            if org is None or GENERIC_ORG.search(org):
                lk.role = "mentioned"
            elif HEDGE.search(quote) or lk.basis == "threat_actor_claim" or lk.vendor_self:
                lk.role = "mentioned"
        lk.accepted = lk.reject_reason is None
        if not lk.accepted:
            lk.hold_reason = "rejected"
        elif lk.role == "mentioned":
            lk.hold_reason = "mentioned_only"
        else:
            meta = (cve_meta or {}).get(cve) or {}
            if vendor_or_reporter(org, None, meta.get("vendors"), meta.get("assigner")):
                lk.hold_reason = "victim_is_vendor_or_reporter"
            elif not quote_ok(cve, org, quote):
                lk.hold_reason = "quote_lacks_subject_or_cve"
        lk.public_candidate = lk.accepted and lk.hold_reason is None
        out.append(lk)
    return out


# ---- where a link may attach: never a new organisation or incident (RULING verify-B1, 2026-10-21) -------
# The news pass resolves a document to incidents (and creates organisations under its own naming rules). The
# CVE pass only ATTACHES. Targets T = the incidents this document already resolved to: incidents of accepted
# claims on the document from a non-CVE extractor version, incident_sources rows for the document, and for an
# SEC filing the incident of its source record. A link attaches to the ONE target whose organisation's
# norm_name or alias_norms equals norm_name(link.organization) - country-blind, because the CVE output carries
# no country. Otherwise, only if the link carries a domain or SEC CIK (reserved; the current prompt asks for
# neither): the organisation with exactly that cik/domain, and only to its single incident in T, or - with no T
# - its single incident first made public within 90 days of the document. Anything else is UNATTACHED
# (no_target / ambiguous_target / name_not_in_doc_incidents) and never filed. A name is never a hard key.

HARD_KEY_WINDOW_DAYS = 90


@dataclass
class Resolution:
    incident_id: str | None
    org_id: str | None
    how: str                        # document_incident | hard_key_in_doc | hard_key_by_date | unattached
    unattached: str | None = None   # no_target | ambiguous_target | name_not_in_doc_incidents


def _keys(o: dict) -> set:
    return {o.get("norm_name") or ""} | set(o.get("alias_norms") or [])


def resolve_target(org: str, targets: list[dict], *, link_domain: str | None = None, link_cik: str | None = None,
                   key_orgs: list[dict] | None = None, published=None) -> Resolution:
    """targets: [{incident_id, org_id, norm_name, alias_norms}] (the document's incidents).
    key_orgs: organisations found by the link's exact cik/domain: [{org_id, domain, sec_cik,
    incidents: [{incident_id, first_public_date}]}]."""
    nn = norm_name(org or "")
    hits = sorted({t["incident_id"] for t in targets if nn and nn in _keys(t)})
    if len(hits) == 1:
        t = next(t for t in targets if t["incident_id"] == hits[0])
        return Resolution(hits[0], t.get("org_id"), "document_incident")
    if len(hits) > 1:
        return Resolution(None, None, "unattached", "ambiguous_target")
    if link_domain or link_cik:
        ko = [o for o in (key_orgs or [])
              if (link_cik and o.get("sec_cik") == link_cik) or (link_domain and (o.get("domain") or "") == link_domain.lower())]
        if len({o["org_id"] for o in ko}) > 1:
            return Resolution(None, None, "unattached", "ambiguous_target")
        if ko:
            o = ko[0]
            in_t = sorted({t["incident_id"] for t in targets if t.get("org_id") == o["org_id"]})
            if len(in_t) == 1:
                return Resolution(in_t[0], o["org_id"], "hard_key_in_doc")
            if len(in_t) > 1:
                return Resolution(None, o["org_id"], "unattached", "ambiguous_target")
            if not targets and published is not None:
                near = sorted({i["incident_id"] for i in o.get("incidents", [])
                               if i.get("first_public_date") is not None
                               and abs((i["first_public_date"] - published).days) <= HARD_KEY_WINDOW_DAYS})
                if len(near) == 1:
                    return Resolution(near[0], o["org_id"], "hard_key_by_date")
                if len(near) > 1:
                    return Resolution(None, o["org_id"], "unattached", "ambiguous_target")
    return Resolution(None, None, "unattached", "no_target" if not targets else "name_not_in_doc_incidents")


def to_candidate(lk: "Link", document: str):
    """The accepted link as the claim path's Candidate (field cve_id), for run.file_candidate."""
    from .extract import Candidate
    c = Candidate("cve_id", lk.cve_id, "none", "not_applicable", lk.quote, cve_role=lk.role,
                  accepted=lk.accepted, reject_reason=lk.reject_reason, subject_match=quote_ok(lk.cve_id, lk.organization or "", lk.quote),
                  basis=lk.basis)
    loc = grounding.norm(document).find(grounding.norm(lk.quote)) if lk.quote else -1
    if loc >= 0:
        c.quote_start, c.quote_end = loc, loc + len(grounding.norm(lk.quote))
    return c
