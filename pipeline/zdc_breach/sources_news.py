"""Security-news feeds: the only place ransom amounts, vectors and CVEs are written down.

POLICY PER FEED, FROM ITS TERMS (checked 2026-10-14). RSS is a published interface, so every
feed may be read. Article PAGES are fetched only where the terms do not forbid automated
access and curl is answered without a challenge; elsewhere the feed text is all we read.
TechCrunch, Cybersecurity Dive and Infosecurity Magazine forbid scrapers in their terms;
DataBreaches.net and Dark Reading answer 403. Text is stored privately for audit and never
republished: the site shows a short quote and the link.

CHEAP FILTER FIRST. Only items whose title or summary mention an incident reach the model;
product news, opinion and vulnerability write-ups without a victim cost nothing.
"""

from __future__ import annotations

import hashlib
import html
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from .http import clean


@dataclass(frozen=True)
class Feed:
    source_id: str
    url: str
    fetch_page: bool           # may the article page be fetched?
    full_text_in_feed: bool


FEEDS = (
    Feed("news_hipaajournal", "https://www.hipaajournal.com/feed/", False, True),
    Feed("news_bleepingcomputer", "https://www.bleepingcomputer.com/feed/", True, False),
    Feed("news_therecord", "https://therecord.media/feed", True, False),
    Feed("news_securityweek", "https://www.securityweek.com/feed/", True, False),
    Feed("news_theregister", "https://www.theregister.com/security/headlines.atom", False, True),
    Feed("news_databreaches", "https://databreaches.net/feed/", False, False),
    Feed("news_krebs", "https://krebsonsecurity.com/feed/", False, True),
    Feed("news_cyberscoop", "https://cyberscoop.com/feed/", False, True),
    Feed("news_cybersecuritydive", "https://www.cybersecuritydive.com/feeds/news/", False, False),
)

INCIDENT = re.compile(
    r"\b(breach|breached|ransomware|ransom|extort|hack(?:ed|ers?)?|cyberattack|cyber[- ]attack|"
    r"cyber incident|security incident|data leak|leaked|stolen data|data theft|compromis|"
    r"exposed (?:data|records|database)|intrusion|notif(?:y|ies|ied|ication) (?:patients|customers|individuals))", re.I)


@dataclass
class Item:
    source_id: str
    guid: str
    url: str
    title: str
    published_at: datetime | None
    summary: str               # plain text from the feed

    @property
    def relevant(self) -> bool:
        return bool(INCIDENT.search(self.title) or INCIDENT.search(self.summary[:1500]))


_TAG = re.compile(r"<[^>]+>")
_WS = re.compile(r"\s+")


def strip_html(fragment: str) -> str:
    fragment = re.sub(r"(?is)<(script|style|noscript|figure|aside|nav|footer|header)\b.*?</\1>", " ", fragment or "")
    fragment = re.sub(r"(?i)<br\s*/?>|</p>|</li>|</h[1-6]>", "\n", fragment)
    text = html.unescape(_TAG.sub(" ", fragment))
    return clean(_WS.sub(" ", text).strip())


_NS = {"atom": "http://www.w3.org/2005/Atom", "content": "http://purl.org/rss/1.0/modules/content/"}


def _date(v: str | None) -> datetime | None:
    if not v:
        return None
    try:
        d = parsedate_to_datetime(v)
    except (TypeError, ValueError):
        try:
            d = datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def parse_feed(source_id: str, body: bytes) -> list[Item]:
    root = ET.fromstring(body)
    out = []
    for it in root.iter("item"):
        link = (it.findtext("link") or "").strip()
        body_html = it.findtext("content:encoded", namespaces=_NS) or it.findtext("description") or ""
        guid = (it.findtext("guid") or link).strip()
        out.append(Item(source_id, guid, link, clean((it.findtext("title") or "").strip()),
                        _date(it.findtext("pubDate")), strip_html(body_html)))
    for e in root.iter("{http://www.w3.org/2005/Atom}entry"):
        link_el = e.find("atom:link[@rel='alternate']", _NS) or e.find("atom:link", _NS)
        link = link_el.get("href") if link_el is not None else ""
        body_html = e.findtext("atom:content", namespaces=_NS) or e.findtext("atom:summary", namespaces=_NS) or ""
        out.append(Item(source_id, (e.findtext("atom:id", namespaces=_NS) or link).strip(), link,
                        clean((e.findtext("atom:title", namespaces=_NS) or "").strip()),
                        _date(e.findtext("atom:published", namespaces=_NS) or e.findtext("atom:updated", namespaces=_NS)),
                        strip_html(body_html)))
    return [i for i in out if i.url.startswith("https://")]


def article_text(page_html: str) -> str:
    """The article body: the <article> element if there is one, else all paragraphs. Crude on
    purpose; the evidence gate only needs the sentences, and a missed paragraph costs a fact,
    never invents one."""
    m = re.search(r"(?is)<article\b.*?</article>", page_html)
    scope = m.group(0) if m else page_html
    paras = re.findall(r"(?is)<p\b[^>]*>(.*?)</p>", scope)
    text = "\n".join(strip_html(p) for p in paras if len(strip_html(p)) > 40)
    return text if len(text) > 300 else strip_html(scope)


def doc_sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()
