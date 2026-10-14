"""News coverage of each victim: GDELT DOC 2.0 article search (migration 0119).

GDELT indexes worldwide online news since 2017 and asks for one request every five seconds;
its data is open for unrestricted use with attribution. The query is the victim's exact name
as a phrase plus breach terms. A hit is KEPT only if the article TITLE names the victim (the
same normalised phrase) and the title or URL carries a breach term - a full-text match on a
common name is not evidence that an article is about this organisation. Links only: we store
the URL, title, outlet, date and language, never the page.
"""

from __future__ import annotations

import re
import urllib.parse
from datetime import date, datetime, timedelta, timezone

API = "https://api.gdeltproject.org/api/v2/doc/doc"
INDEX_START = date(2017, 1, 1)
PACE_S = 8.0          # GDELT asks for one request per 5 s; shared runner IPs need more
RETRIES_429 = 3       # GDELT is often congested: a 429 that is retried 15 s later usually answers
RETRY_SLEEP_S = 15.0
GIVE_UP_AFTER = 3     # consecutive searches that never got an answer
_BREACH = re.compile(r"(ransom|breach|hack|cyber|attack|leak|stolen|extort|data theft|compromis|incident|"
                     r"datenleck|cyberangriff|piratage|fuite|ciberataque|violaci|attacco|lek|aanval)", re.I)


def norm(s: str | None) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[^\w]+", " ", (s or "").lower())).strip()


def searchable(name: str | None) -> bool:
    """A name worth a news query: not a bare domain, at least 5 characters and two letters."""
    n = (name or "").strip()
    if len(n) < 5 or re.fullmatch(r"[\w.-]+\.[a-z]{2,}", n.lower()) or len(re.findall(r"[^\W\d_]", n)) < 2:
        return False
    return True


def query_url(name: str, seen: date, today: date) -> str | None:
    start = max(INDEX_START, seen - timedelta(days=60))
    end = min(today, seen + timedelta(days=365))
    if end <= start:
        return None
    phrase = '"' + re.sub(r'["()]', " ", name).strip() + '"'
    q = f'{phrase} (ransomware OR breach OR hacked OR cyberattack OR "data leak" OR "cyber attack")'
    return API + "?" + urllib.parse.urlencode({
        "query": q, "mode": "artlist", "format": "json", "maxrecords": 75, "sort": "datedesc",
        "startdatetime": start.strftime("%Y%m%d000000"), "enddatetime": end.strftime("%Y%m%d235959")})


def matches(name: str, title: str, url: str) -> bool:
    n, t = norm(name), norm(title)
    if not n or not t or not re.search(r"(^|\s)" + re.escape(n) + r"(\s|$)", t):
        return False
    return bool(_BREACH.search(title) or _BREACH.search(url))


def parse(payload: dict, name: str) -> list[dict]:
    out, seen = [], set()
    for a in (payload or {}).get("articles") or []:
        url, title = (a.get("url") or "").strip(), (a.get("title") or "").strip()
        if not url.startswith(("http://", "https://")) or ".onion" in url or url in seen:
            continue
        if not matches(name, title, url):
            continue
        seen.add(url)
        when = None
        try:
            when = datetime.strptime(a.get("seendate", ""), "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
        except ValueError:
            pass
        out.append({"url": url[:2000], "title": title[:500], "outlet": (a.get("domain") or "")[:200] or None,
                    "published_at": when, "language": (a.get("language") or "")[:40] or None})
    return out


# ---- links from the news feeds we already read -----------------------------------------------
def distinctive(name: str | None) -> bool:
    """A victim name safe to look for in a headline: two or more words, or one word that cannot
    be an ordinary word ("Target" is a verb in "Hackers target hospitals"): CamelCase, a digit,
    or at least nine letters."""
    n = (name or "").strip()
    if not searchable(n) or "?" in n:
        return False
    words = norm(n).split()
    if len(words) >= 2:
        return len(norm(n)) >= 6
    w = n.strip()
    return bool(re.search(r"[a-z][A-Z]|\d", w)) or len(w) >= 9


def index_names(victims) -> dict[str, list]:
    """{normalised name: [victim ids, or (victim id, seen date)]} for distinctive names."""
    idx: dict[str, list] = {}
    for v in victims:
        vid, name = v[0], v[1]
        if distinctive(name):
            idx.setdefault(norm(name), []).append(vid if len(v) == 2 else (vid, v[2]))
    return idx


def in_window(published: date | None, seen: date | None) -> bool:
    """An article belongs to a breach only if it appeared from 30 days before the victim was first
    seen to a year after: the same big name in an unrelated story is usually from another time."""
    if published is None or seen is None:
        return False
    return seen - timedelta(days=30) <= published <= seen + timedelta(days=365)


def find_in_title(title: str, idx: dict[str, list[str]], max_words: int = 8) -> list[str]:
    """Victim ids whose normalised name occurs as a whole phrase in the title."""
    words = norm(title).split()
    hits = []
    for i in range(len(words)):
        for j in range(i + 1, min(len(words), i + max_words) + 1):
            hits += idx.get(" ".join(words[i:j]), [])
    return hits
