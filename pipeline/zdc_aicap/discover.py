"""Discovery: candidate new cyber benchmarks, proposed for a person to review. Never added.

Four public sources, each read-only and cheap: arXiv (new papers), GitHub (new repositories),
Hugging Face (new datasets), and vals.ai's own index (a new cyber or security board there). A hit
must name a benchmark, a cyber task and an AI model or agent; the rest is noise. A candidate that is
accepted becomes an entry in registry/benchmarks.json through a reviewed change, with its evaluator
and licence, and only then is it fetched or curated.
"""

from __future__ import annotations

import datetime as dt
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass

ARXIV = "https://export.arxiv.org/api/query"
GITHUB = "https://api.github.com/search/repositories"
HF = "https://huggingface.co/api/datasets"

# A candidate must NAME a benchmark and a specific cyber task in its title (abstracts mention
# "benchmark" and "security" far too loosely: the first unfiltered week returned 66 hits, a handful
# real), and mention an AI model or agent somewhere. Model-safety work (jailbreaks, refusals, prompt
# injection) is not cyber capability unless it is also about exploits or vulnerabilities.
TITLE_BENCH = re.compile(r"bench|benchmark|arena|leaderboard|\beval(uation|uating)?s?\b|\bgym\b|\Bgym\b", re.I)
TITLE_CYBER = re.compile(r"cyber|exploit|vulnerab|penetration|pentest|\bctf\b|capture[- ]the[- ]flag|\bsoc\b|threat|malware|"
                         r"incident|detection rule|red[- ]team|attack|hardening|\bcve|\bcwe|zero[- ]day|0[- ]day|fuzz|"
                         r"intrusion|forensic|reverse[- ]engineer", re.I)
STRONG = re.compile(r"exploit|vulnerab|penetration|pentest|\bcve|\bcwe|zero[- ]day|fuzz", re.I)
SAFETY_ONLY = re.compile(r"jailbreak|refusal|prompt[- ]injection|hallucinat|guardrail", re.I)
AI = re.compile(r"\b(llms?|language models?|agents?|agentic|ai|foundation models?|gpt|claude|gemini)\b", re.I)


def relevant(title: str, body: str = "") -> bool:
    if not TITLE_BENCH.search(title) or not TITLE_CYBER.search(title):
        return False
    if SAFETY_ONLY.search(title) and not STRONG.search(title):
        return False
    return bool(AI.search(f"{title} {body}"))


@dataclass
class Candidate:
    url: str
    title: str
    source: str
    published: str | None
    summary: str = ""




def arxiv_query(days: int = 14) -> str:
    q = ('(abs:benchmark OR ti:benchmark OR ti:bench) AND (abs:cyber OR abs:exploit OR abs:vulnerability OR '
         'abs:penetration OR abs:"capture the flag" OR abs:"security operations") AND (abs:LLM OR abs:agent OR abs:"language model")')
    return f"{ARXIV}?search_query={_q(q)}&sortBy=submittedDate&sortOrder=descending&max_results=60"


def _q(s: str) -> str:
    from urllib.parse import quote
    return quote(s, safe="():")


def parse_arxiv(atom: str, since: dt.date) -> list[Candidate]:
    ns = {"a": "http://www.w3.org/2005/Atom"}
    out = []
    root = ET.fromstring(atom)
    for e in root.findall("a:entry", ns):
        title = re.sub(r"\s+", " ", (e.findtext("a:title", "", ns) or "")).strip()
        summ = re.sub(r"\s+", " ", (e.findtext("a:summary", "", ns) or "")).strip()
        pub = (e.findtext("a:published", "", ns) or "")[:10]
        url = (e.findtext("a:id", "", ns) or "").strip().replace("http://", "https://")
        url = re.sub(r"v\d+$", "", url)
        if not url or not pub or dt.date.fromisoformat(pub) < since:
            continue
        if relevant(title, summ):
            out.append(Candidate(url=url, title=title, source="arxiv", published=pub, summary=summ[:300]))
    return out


def github_query(since: dt.date) -> str:
    q = f"benchmark (cyber OR exploit OR vulnerability OR pentest OR ctf) (llm OR agent) created:>={since.isoformat()}"
    return f"{GITHUB}?q={_q(q)}&sort=stars&order=desc&per_page=40"


def parse_github(doc: dict) -> list[Candidate]:
    out = []
    for it in (doc or {}).get("items", []):
        title = f"{it.get('name', '')} {it.get('description') or ''}"
        if it.get("fork") or not relevant(title, " ".join(it.get("topics") or [])) or (it.get("stargazers_count") or 0) < 5:
            continue
        out.append(Candidate(url=it.get("html_url", ""), title=f"{it.get('full_name')}: {(it.get('description') or '')[:160]}",
                             source="github", published=(it.get("created_at") or "")[:10] or None))
    return out


def hf_query() -> str:
    return f"{HF}?search=cyber&sort=lastModified&direction=-1&limit=50"


def parse_hf(items: list, since: dt.date) -> list[Candidate]:
    out = []
    for it in items or []:
        mod = (it.get("lastModified") or it.get("createdAt") or "")[:10]
        rid = it.get("id", "")
        name = rid.split("/")[-1].replace("_", " ").replace("-", " ")
        # a dataset counts only when its own name says it is a benchmark or an eval: Hugging Face is full
        # of cyber training sets, and a training set is not a measurement
        if not re.search(r"bench|eval", rid.split("/")[-1], re.I):
            continue
        if not mod or dt.date.fromisoformat(mod) < since or not relevant(name, " ".join(it.get("tags") or []) + " llm"):
            continue
        out.append(Candidate(url=f"https://huggingface.co/datasets/{rid}", title=rid, source="huggingface", published=mod))
    return out


def parse_vals_index(text: str, known_titles: set[str]) -> list[Candidate]:
    """Any section in vals.ai's index whose category is Cyber or Security and that we do not track."""
    out = []
    for m in re.finditer(r"^## ([^\n]+)\n(.*?)(?=^## |\Z)", text or "", re.M | re.S):
        title, body = m.group(1).strip(), m.group(2)
        cat = re.search(r"^- Category:\s*(.+)$", body, re.M)
        page = re.search(r"^- Page:\s*(https://\S+)$", body, re.M)
        if not cat or not re.search(r"cyber|security", cat.group(1), re.I) or not page:
            continue
        if title in known_titles:
            continue
        upd = re.search(r"^- Updated:\s*(\d{4}-\d{2}-\d{2})\s*$", body, re.M)
        out.append(Candidate(url=page.group(1), title=f"vals.ai: {title}", source="vals-index", published=upd.group(1) if upd else None))
    return out
