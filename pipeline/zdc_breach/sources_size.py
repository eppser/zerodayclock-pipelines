"""Organisation size from Wikidata: employees, matched on the exact website domain only.

WHY EXACT DOMAIN. A name match ("Acme") would size the wrong company as readily as the right
one. Wikidata's "official website" (P856) holds full URLs, so each domain is tried in the eight
spellings sites are recorded under (http/https, with/without www, with/without a trailing slash)
and matched exactly - an indexed lookup, not a scan. No match is 'not_found', shown as
'unknown', never a guess.

WHICH COUNT. P1128 (employees) often has several values with a point in time (P585). The latest
dated value wins; undated values are used only when no dated one exists, largest first.

Wikidata is CC0. The query service asks for a descriptive User-Agent and modest batches.
"""

from __future__ import annotations

import json
import urllib.parse
from datetime import date

ENDPOINT = "https://query.wikidata.org/sparql"


def variants(domain: str) -> list[str]:
    out = []
    for scheme in ("https", "http"):
        for host in (domain, "www." + domain):
            for tail in ("/", ""):
                out.append(f"{scheme}://{host}{tail}")
    return out


def query(domains: list[str]) -> str:
    values = " ".join(f"<{u}>" for d in domains for u in variants(d))
    return ("SELECT ?item ?url ?emp ?t WHERE { VALUES ?url { " + values + " } "
            "?item wdt:P856 ?url . ?item p:P1128 ?st . ?st ps:P1128 ?emp . "
            "OPTIONAL { ?st pq:P585 ?t } }")


def url(domains: list[str]) -> str:
    return ENDPOINT + "?" + urllib.parse.urlencode({"query": query(domains), "format": "json"})


def _host(u: str) -> str:
    h = urllib.parse.urlsplit(u).hostname or ""
    return h[4:] if h.startswith("www.") else h


def parse(payload: dict, domains: list[str]) -> dict[str, tuple[int, date | None, str]]:
    """{domain: (employees, as_of, qid)} for the domains Wikidata answered."""
    best: dict[str, tuple] = {}
    for b in (payload.get("results") or {}).get("bindings") or []:
        try:
            dom = _host(b["url"]["value"])
            emp = int(float(b["emp"]["value"]))
            qid = b["item"]["value"].rsplit("/", 1)[-1]
        except (KeyError, ValueError):
            continue
        if dom not in domains or emp <= 0:
            continue
        t = b.get("t", {}).get("value")
        as_of = date.fromisoformat(t[:10]) if t and t[:4].isdigit() and not t.startswith("-") else None
        # Rank: a dated value beats an undated one; among dated, the latest; among undated, the largest.
        key = (as_of is not None, as_of or date.min, emp)
        if dom not in best or key > best[dom][0]:
            best[dom] = (key, emp, as_of, qid)
    return {d: (v[1], v[2], v[3]) for d, v in best.items()}


def body_json(body: bytes) -> dict:
    return json.loads(body.decode("utf-8", "replace"))
