"""Ransomware leak-site trackers: what a criminal group says it did, and nothing more.

These rows never name a victim on the site (migration 0101, rule 1). They become
breach_core.leak_claims, published only as monthly counts by group, country and sector, and
they can attach an actor_claimed flag to an incident that a victim or regulator confirmed.

TWO TRACKERS, ONE UNDERLYING SOURCE. RansomLook and RansomFeed scrape the same leak sites, so
a post both of them saw is one claim seen twice, never two confirmations. Measured 2026-10-14:
- RansomLook /api/last/{days}: keyless; group, title, discovered, description; no domain,
  country or sector except when the title is the victim's domain.
- RansomFeed api.ransomfeed.it: keyless, 5 requests/minute; a stable sha256 `hash` per post,
  website on ~88%, country on all, sector on ~47%.
ransomware.live is richer but its terms bar commercial use without written approval, so it is
not polled until the owner decides (docs/decisions/0006).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from .normalize import domain_from_title, norm_country, norm_domain, norm_name


_EMPLOYEES = re.compile(
    r"(?:around|about|approximately|roughly|over|more than|nearly|with|has|employs|employing|"
    r"workforce of|team of|staff of)\s+(\d{1,3}(?:,\d{3})+|\d+)(?:\s*[\u2013-]\s*\d[\d,]*)?\+?\s+"
    r"(?:employees|staff|workers|people)\b", re.I)
_NOT_HEADCOUNT = re.compile(r"(data|records|information|files|details|documents|belonging|stolen|leaked|of)\W*$", re.I)


def employees_stated(text: str | None) -> int | None:
    """A company headcount stated in a leak post ("around 630 employees work at ...", "with
    250-400 employees"); the lower bound of a range. A number that counts whose data was taken
    ("data of 5,000 employees") is not a headcount and is refused."""
    for m in _EMPLOYEES.finditer(text or ""):
        if _NOT_HEADCOUNT.search((text or "")[max(0, m.start() - 25):m.start()]):
            continue
        n = int(m.group(1).replace(",", ""))
        if 0 < n < 5_000_000:
            return n
    return None


_AMOUNT = re.compile(
    r"(?:\$\s?(\d[\d,]*(?:\.\d+)?)\s*(k|m|mn|million|thousand)?|"
    r"(\d[\d,]*(?:\.\d+)?)\s*(k|m|million|thousand)?\s*(usd|us dollars|dollars|eur|euro|btc|bitcoin|xmr|monero|usdt)\b)", re.I)
_DEMAND_CUE = re.compile(r"\b(pay|payment|ransom|demand|price|fee|amount|transfer)\b", re.I)
_SCRUB = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+|\b[a-z2-7]{16,56}\.onion\S*|\b[0-9a-f]{24,}\b|https?://\S+|session\s*(id)?\s*:?\s*\S+", re.I)
_CUR = {"usd": "USD", "us dollars": "USD", "dollars": "USD", "eur": "EUR", "euro": "EUR", "btc": "BTC",
        "bitcoin": "BTC", "xmr": "XMR", "monero": "XMR", "usdt": "USDT"}
_MULT = {"k": 1_000, "thousand": 1_000, "m": 1_000_000, "mn": 1_000_000, "million": 1_000_000}


def demand_stated(text: str | None) -> tuple[str, float, str] | None:
    """The attackers' own demand, as their post words it: the first sentence that both asks for
    payment and names an amount. Email addresses, onion links, session ids and long hex are
    removed - the page quotes the demand, never how to pay it."""
    for sent in re.split(r"(?<=[.!?])\s+|\n+", text or ""):
        if not _DEMAND_CUE.search(sent):
            continue
        m = _AMOUNT.search(sent)
        if not m:
            continue
        num, mult = (m.group(1), m.group(2)) if m.group(1) else (m.group(3), m.group(4))
        cur = "USD" if m.group(1) else _CUR.get((m.group(5) or "").lower())
        try:
            amount = float(num.replace(",", "")) * _MULT.get((mult or "").lower(), 1)
        except ValueError:
            continue
        if not cur or amount <= 0 or amount > 5e9:
            continue
        clean = _SCRUB.sub("[removed]", sent).strip()
        return clean[:300], amount, cur
    return None


@dataclass(frozen=True)
class LeakPost:
    source_id: str
    source_record_id: str
    actor_group: str
    victim_name: str
    victim_domain: str | None
    country: str | None
    sector: str | None
    seen_at: datetime
    record: dict

    @property
    def demand(self) -> tuple[str, float, str] | None:
        return demand_stated(str(self.record.get("description") or ""))

    @property
    def employees(self) -> int | None:
        return employees_stated(str(self.record.get("description") or ""))

    @property
    def victim_norm(self) -> str:
        return norm_name(self.victim_name)


def _ts(value: str | None) -> datetime | None:
    if not value:
        return None
    v = value.strip().replace("Z", "+00:00")
    for fmt in (None, "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            d = datetime.fromisoformat(v) if fmt is None else datetime.strptime(v, fmt)
        except ValueError:
            continue
        # Both trackers publish naive timestamps that are UTC (measured against their
        # aware siblings: RansomLook /api/posts carries the same instants with a Z).
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    return None


def parse_ransomlook(rows: list) -> tuple[list[LeakPost], int]:
    out, bad = [], 0
    for r in rows if isinstance(rows, list) else []:
        if not isinstance(r, dict):
            bad += 1
            continue
        group, title, seen = (r.get("group_name") or "").strip(), (r.get("post_title") or "").strip(), _ts(r.get("discovered"))
        if not group or not title or not seen:
            bad += 1
            continue
        rid = r.get("misp_uuid") or hashlib.sha256(f"{group}|{title}|{r.get('discovered')}".encode()).hexdigest()
        out.append(LeakPost("ransomlook", str(rid), group.lower(), title, domain_from_title(title),
                            None, None, seen, r))
    return out, bad


def parse_ransomfeed(rows: list) -> tuple[list[LeakPost], int]:
    out, bad = [], 0
    for r in rows if isinstance(rows, list) else []:
        if not isinstance(r, dict):
            bad += 1
            continue
        group, victim, seen = (r.get("gang") or "").strip(), (r.get("victim") or "").strip(), _ts(r.get("date"))
        rid = r.get("hash") or r.get("id")
        if not group or not victim or not seen or not rid:
            bad += 1
            continue
        sector = (r.get("work_sector") or "").strip() or None
        out.append(LeakPost("ransomfeed", str(rid), group.lower(), victim,
                            norm_domain(r.get("website")) or domain_from_title(victim),
                            norm_country(r.get("country")), sector, seen, r))
    return out, bad


def claim_key(post: LeakPost) -> str:
    """One posting episode: the same group naming the same victim within the same 14-day
    bucket. Two trackers seeing one post land on one key; a group re-posting a victim weeks
    later is a second episode, and a second group naming the same victim is a second claim
    (linked through the incident, never merged)."""
    who = post.victim_domain or post.victim_norm
    bucket = int(post.seen_at.timestamp() // (14 * 86400))
    return f"{post.actor_group}|{who}|{bucket}"
