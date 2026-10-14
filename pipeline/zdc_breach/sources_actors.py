"""The actor registry (migration 0119): who is behind a breach, under every name they go by.

Two public lists, merged on exact normalised alias:
- MISP threat-actor galaxy (CC0): ~1,060 named actors with synonyms, suspected state sponsor,
  country and incident type ("Espionage", "Sabotage", "Financial Theft", ...).
- RansomLook's group list: the extortion groups whose leak sites it watches.
The MISP ransomware galaxy (also CC0) marks which group names are ransomware families. It also
lists extortion-only crews, so `listed_ransomware` means exactly that and nothing stronger.

AN ALIAS TWO ACTORS SHARE IS DROPPED, never assigned to one of them. Attribution is the
galaxy's, as published; we resolve names, we do not attribute.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

MISP_ACTORS = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"
MISP_RANSOMWARE = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/ransomware.json"
RANSOMLOOK_GROUPS = "https://www.ransomlook.io/api/groups"

_SUFFIX = re.compile(r"(ransomware|ransom|group|team|gang|leaks|leak|blog)$")


def norm(name: str | None) -> str | None:
    """Python twin of breach_core.actor_norm() - the two must agree (tested). Letters and digits
    only; ONE trailing word groups and trackers append ("LockBit Ransomware", "Akira Team") is
    dropped when at least four characters remain, so "INC Ransom" and "Ransom House" survive."""
    s = re.sub(r"[^a-z0-9]+", "", (name or "").lower())
    t = _SUFFIX.sub("", s)
    s = t if len(t) >= 4 else s
    return s or None


_TRACKING_CODE = re.compile(r"^(storm|dev|unc|ta|tag|uat|g|tg|ti)[- ]?\d+$", re.I)


def slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:60]


_COUNTRY = {"china": "CN", "russian federation": "RU", "russia": "RU", "iran (islamic republic of)": "IR", "iran": "IR",
            "korea (democratic people's republic of)": "KP", "north korea": "KP", "united states": "US",
            "israel": "IL", "india": "IN", "pakistan": "PK", "vietnam": "VN", "viet nam": "VN",
            "palestine": "PS", "turkey": "TR", "lebanon": "LB", "united arab emirates": "AE", "belarus": "BY"}


@dataclass
class Actor:
    actor_id: str
    display_name: str
    kind: str = "unknown"
    motive: str | None = None
    sponsor_country: str | None = None
    listed_ransomware: bool = False
    aliases: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)
    refs: list[str] = field(default_factory=list)


def _as_list(v) -> list[str]:
    if v is None:
        return []
    return [v] if isinstance(v, str) else [str(x) for x in v]


def classify(meta: dict) -> tuple[str, str | None, str | None]:
    """(kind, motive, sponsor ISO2) from a MISP threat-actor's meta, using only what it states."""
    incidents = {x.lower() for x in _as_list(meta.get("cfr-type-of-incident"))}
    motives = " ".join(_as_list(meta.get("motive"))).lower()
    sponsor = (_as_list(meta.get("cfr-suspected-state-sponsor")) or [None])[0]
    iso = _COUNTRY.get((sponsor or "").lower())
    c = meta.get("country")
    if not iso and isinstance(c, str) and re.fullmatch(r"[A-Z]{2}", c):
        iso = c
    if "hacktivis" in motives or incidents & {"defacement", "denial of service"}:
        return "hacktivist", "hacktivism", iso
    if (sponsor and sponsor.lower() != "unknown") or incidents & {"espionage", "sabotage"}:
        return "state_sponsored", "sabotage" if incidents == {"sabotage"} else "espionage", iso
    if "cybercrime" in motives or "financ" in motives or incidents & {"financial theft", "business email compromise"}:
        return "cybercrime", "financial", iso
    if "extortion" in incidents:
        return "extortion", "financial", iso
    return "unknown", None, iso


def build(misp_actors: dict, misp_ransomware: dict, ransomlook_groups: list) -> tuple[list[Actor], dict[str, tuple[str, str, str]]]:
    """Actors and the alias map {alias_norm: (actor_id, alias, source)}; shared aliases dropped."""
    actors: dict[str, Actor] = {}
    claims: dict[str, set[str]] = {}            # alias_norm -> actor ids claiming it
    first_spelling: dict[tuple[str, str], tuple[str, str]] = {}

    def claim(a: Actor, alias: str, source: str):
        n = norm(alias)
        if not n or len(n) < 3:
            return
        claims.setdefault(n, set()).add(a.actor_id)
        first_spelling.setdefault((n, a.actor_id), (alias, source))
        a.aliases.add(alias)

    for v in (misp_actors or {}).get("values") or []:
        name = (v.get("value") or "").strip()
        if not name:
            continue
        meta = v.get("meta") or {}
        kind, motive, iso = classify(meta)
        a = actors.setdefault(slug(name), Actor(slug(name), name))
        a.kind, a.motive, a.sponsor_country = kind, motive, iso
        a.sources.add("misp_galaxy")
        a.refs = [r for r in _as_list(meta.get("refs")) if r.startswith("https://")][:5]
        for alias in [name] + _as_list(meta.get("synonyms")):
            claim(a, alias, "misp_galaxy")

    ransomware_norms = set()
    for v in (misp_ransomware or {}).get("values") or []:
        for alias in [v.get("value") or ""] + _as_list((v.get("meta") or {}).get("synonyms")):
            n = norm(alias)
            if n and len(n) >= 3:
                ransomware_norms.add(n)

    alias_owner = {n: next(iter(ids)) for n, ids in claims.items() if len(ids) == 1}
    for g in ransomlook_groups or []:
        if not isinstance(g, str) or not g.strip():
            continue
        n = norm(g)
        if not n or len(n) < 3:
            continue
        owner = alias_owner.get(n)
        a = actors[owner] if owner else actors.setdefault("rl-" + slug(g), Actor("rl-" + slug(g), g.strip().title()))
        if owner and _TRACKING_CODE.match(a.display_name):
            a.display_name = g.strip().title()   # "Akira", not Microsoft's "Storm-1567"
        a.sources.add("ransomlook_groups")
        if a.kind == "unknown":
            a.kind, a.motive = "extortion", "financial"
        claim(a, g, "ransomlook_groups")
        if owner is None:
            alias_owner.setdefault(n, a.actor_id)

    for a in actors.values():
        a.listed_ransomware = any(norm(x) in ransomware_norms for x in a.aliases)
    alias_map = {n: (next(iter(ids)),) + first_spelling[(n, next(iter(ids)))]
                 for n, ids in claims.items() if len(ids) == 1}
    return list(actors.values()), alias_map


def body_json(b: bytes):
    return json.loads(b.decode("utf-8", "replace"))
