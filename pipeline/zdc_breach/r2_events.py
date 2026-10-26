"""R2 event matcher: is a record a NEW breach event or one we already have? (RUBRIC_R2 section 3, method r2-events-v1)

An EVENT is one organisation + one breach episode. Records (a leak-site post, a regulator filing, a breach-index row,
a press incident) are its members. Raw rows are never changed or deleted: membership is written to the private,
versioned tables breach_core.r2_events / r2_event_members, every Jev answer to r2_answers (insert-only).

  units       records joined by a STRUCTURED key first: a leak claim linked to an incident (leak_claims.incident_id),
              the posts names-v1 already groups into one list row (victims_list.posts). Then DETERMINISTIC: leak posts of
              the same actor about the same company (same core name or same domain) within 90 days (names-v1 episode).
  blocking    candidate pairs of units, deterministic: same org id / domain; the same CORE name after stripping
              scraping junk (outlet prefixes and suffixes, 'Exclusive:', possessives, legal forms, 'City/County of',
              '...' truncation, doubled titles, hostnames, the actor's own name); acronym <-> long form; token-set
              containment; trigram >= 0.6; a truncated name that is a prefix of the other; Wikidata parent/subsidiary;
              the legacy possible_duplicate_of link. Within a block: reported or breach dates within +-24 months
              (follow-ups: any older event), people affected within 10x (totals only - a state AG notice counts that
              state's residents), industry compatible unless the name link is strong.
  cannot-link two leak-only units by different actors (different episodes unless an article ties them); two campaigns;
              breach dates both known and > 24 months apart (follow-ups exempt).
  mapping     online, per connected component, oldest unit first: the unit's candidate EVENTS (cap K=8, strongest name
              link then nearest date) go to TypeSafe Jev as one Choice (K events + none) plus one yes/no per candidate
              (asked together; only the chosen one's is used). Merge iff the choice p >= TAU_C and the pair p >= TAU_P.
              A pick with both p >= 0.5 but under a tau -> a new event with possible_duplicate_of (private review).
              Anything else -> a new event. A candidate linked ONLY through a Wikidata parent (brand rule: Volkswagen
              vs Seat) never merges unless the record names the other organisation; at most possible_duplicate_of.
  follow-up   a press-only record whose every headline is a follow-up (doc_kind: lawsuit, settlement, sentencing, ...)
              attaches to an OLDER event of the same organisation with role follow_up (0171: never moves a date).
  campaign    a supplier campaign (MOVEit, Cleo, GoAnywhere, Accellion, Snowflake, Salesloft Drift, Oracle EBS) gets a
              campaign_id; each breached customer stays its own event; the vendor is an event only for its own records.

PUBLIC LOGS: counts only, never a name.

CLI (DATABASE_URL, TYPESAFE_API_KEY):
  python -m zdc_breach.r2_events run --extract extract.json [--limit-units N] --max-usd X [--write]   # full backfill
  python -m zdc_breach.r2_events run --new-only --max-usd X [--write]   # hourly: only records with no stored membership
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures as cf
import hashlib
import html
import json
import re
import sys
import threading
import time
import unicodedata
import uuid
from dataclasses import dataclass, field
from datetime import date

from zdc_breach import doc_kind
from zdc_breach.normalize import has_cjk, norm_domain, norm_name

METHOD_VERSION = 'r2-events-v2'
QV = 'r2-events-q4'
K = 8
WINDOW_DAYS = 730            # blocking: +-24 months (tolerates scraping and date bugs)
LEAK_EPISODE_DAYS = 90       # names-v1: posts of one actor about one company within 90 days = one episode
TAU_C = 0.8                  # frozen on dev (see TUNING in the run report); merge iff choice p >= TAU_C ...
TAU_P = 0.8                  # ... and pair p >= TAU_P
# Taus per agreement tier (deterministic evidence beside Jev): A = strong name link (org id / domain / exact core) AND
# dates agree (breach dates within 31 days, or reported within 60 days when a breach date is missing); B = the rest.
TAUS = {'A': (0.6, 0.6), 'B': (0.7, 0.7), 'C': (0.8, 0.8)}   # dev H1-H3: pairwise P 0.991, R 0.756
AGREE_BREACH_DAYS = 31
AGREE_REPORTED_DAYS = 60
BUSY_UNITS = 5
TAU_ORG = 0.85               # v2: a containment / acronym / spelling link merges only if Jev says same legal entity or brand
UNCERTAIN = 0.5              # [0.5, tau) -> possible_duplicate_of
TRIGRAM_MIN = 0.6
VOLUME_RATIO = 10.0
BLOCK_CAP = 400              # a non-identity key shared by more units than this is too generic to block on
PRICE_PER_MTOK = 0.042
STATEMENT_TIMEOUT = '60s'

CARD_ISSUERS = ('american express', 'discover financial')
STATE_AG = frozenset({'wa_ag', 'de_ag', 'ca_ag'})        # per-state resident counts: never compared as totals
REGULATOR = frozenset({'wa_ag', 'de_ag', 'ca_ag', 'hhs_ocr', 'sec_8k'})
LEAK = frozenset({'ransomlook', 'ransomfeed', 'cra_export'})
INDEX = frozenset({'hibp'})

# ---------------------------------------------------------------------------------------------------------------
# Names: scraping junk off, then a core key
# ---------------------------------------------------------------------------------------------------------------
OUTLETS = (r"reuters|bloomberg|techcrunch|the record|therecord|bleepingcomputer|bleeping computer|securityweek|security week|"
           r"the register|zdnet|cyberscoop|hackread|securityaffairs|security affairs|databreaches(?:\.net)?|hipaa journal|"
           r"hipaajournal|comparitech|helpnetsecurity|help net security|govinfosecurity|industrial cyber|cybernews|"
           r"dark reading|darkreading|the hacker news|infosecurity magazine|wired|cnn|bbc(?: news)?|ap news|associated press|"
           r"the verge|forbes|cnbc|nbc news|fox news|abc news|wsj|the guardian|new york times|nyt|axios|politico|"
           r"sc media|scmagazine|teiss|the daily swig|krebs on security|krebsonsecurity")
PREFIX = re.compile(r"^\s*(?:\[?(?:exclusive|breaking(?: news)?|update[d]?|updates?|report|alert|news|just in|watch|"
                    r"opinion|analysis|confirmed|developing|new|video|live|data breach(?: alert| notice)?|security incident|"
                    r"ransomware(?: attack)?|cyber ?attack|hacked|hack|leak(?:ed)?|breach(?:ed)?)\]?\s*[:|\-–—]\s*)+", re.I)
OUTLET_TAIL = re.compile(r"\s*(?:[|\-–—:]\s*|\bvia\s+)(?:" + OUTLETS + r")\s*$", re.I)
OUTLET_HEAD = re.compile(r"^\s*(?:" + OUTLETS + r")\s*[:|\-–—]\s*", re.I)
ELLIPSIS = re.compile(r"\s*(?:\.\.\.|…|\.\s\.\s\.)\s*$")
POSSESSIVE = re.compile(r"(?<=\w)['’`]s\b", re.I)
PAREN = re.compile(r"\s*[(\[]([^)\]]*)[)\]]")
HOST = re.compile(r"^(?:https?://)?(?:www\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,24})/?$", re.I)
MUNICIPAL = re.compile(r"^(?:the\s+)?(?:city|county|town|township|village|borough|municipality|parish)\s+of\s+", re.I)
FILING_TAIL = re.compile(r"(?:\s*,?\s+(?:on behalf of|obo|o/b/o|for and on behalf of)\b.*$)|(?:\s*,?\s+(?:and|&) (?:its|their) "
                         r"(?:subsidiaries|affiliates|affiliated entities|related entities)\b.*$)|(?:\s*,\s*an? (?:delaware|nevada|"
                         r"new york|california|texas|florida)\b.*$)|(?:\s+(?:supplement(?:al)?|amended|addendum|update|"
                         r"notice)(?:\s*(?:no\.?\s*)?\d+)?\s*$)", re.I)
DBA = re.compile(r"\s*,?\s+(?:d/?b/?a|doing business as)\s+.*$", re.I)
QUOTED_ALIAS = re.compile(r"\s*\(?\s*[\"“][^\"”]*[\"”]?\s*\)?\s*$")
MUNICIPAL_TAIL = re.compile(r"\s+(?:city|county|town|township|village|borough)\s+(?:government|council)$", re.I)
STOP = frozenset({'of', 'and', 'the', 'for', 'a', 'an', 'in', 'at', 'on', 'to', 'de', 'la', 'le', 'du', 'des', 'et', 'y', 'und'})
GENERIC = frozenset({'group', 'services', 'service', 'health', 'healthcare', 'medical', 'center', 'centre', 'hospital', 'system',
                     'systems', 'school', 'schools', 'district', 'university', 'college', 'bank', 'insurance', 'international',
                     'national', 'american', 'america', 'united', 'states', 'global', 'solutions', 'technologies', 'technology',
                     'associates', 'partners', 'care', 'clinic', 'county', 'city', 'department', 'state', 'community', 'family',
                     'first', 'new', 'north', 'south', 'east', 'west', 'general', 'capital', 'financial', 'management',
                     'consulting', 'industries', 'holdings', 'corporation', 'company', 'association', 'foundation', 'church',
                     'law', 'firm', 'office', 'public', 'credit', 'union', 'trust', 'energy', 'data', 'network', 'software',
                     'cloud', 'digital', 'media', 'enterprises', 'enterprise', 'pharmacy', 'dental', 'physicians', 'practice',
                     'government', 'council', 'police', 'court', 'museum', 'library', 'airlines', 'airport', 'motors', 'auto',
                     'construction', 'engineering', 'manufacturing', 'logistics', 'transport', 'realty', 'real', 'estate'})
ABBREV = {'st': 'saint', 'mt': 'mount', 'ctr': 'center', 'centre': 'center', 'hosp': 'hospital', 'med': 'medical',
          'intl': 'international', 'natl': 'national', 'assn': 'association', 'svcs': 'services', 'dept': 'department',
          'univ': 'university', 'ins': 'insurance', 'fed': 'federal', 'sch': 'school', 'dist': 'district', 'mgmt': 'management',
          'grp': 'group', 'sys': 'systems', 'hlth': 'health', 'fin': 'financial', 'svc': 'services', 'cntr': 'center'}
SECOND_LEVEL = ('co', 'com', 'org', 'net', 'ac', 'gov', 'edu', 'ne', 'or', 'go', 'gob', 'gv', 'nhs')


def unesc(s: str | None) -> str:
    s = s or ''
    for _ in range(8):
        t = html.unescape(s)
        if t == s:
            break
        s = t
    return s


OBO = re.compile(r"\s*[,;(\-–]?\s*\b(?:for and on behalf of|on behalf of|o/b/o|obo|acting for)\b\s*(?P<b>.*)$", re.I)
GENERIC_BENEFICIARY = re.compile(r"^(?:(?:the|a|an)\s+)?(?:(?:its|their|our|certain|various|multiple|several|relevant|affected|covered|"
                                 r"participating|listed|attached|identified|named)\b|(?:clients?|customers?|entities|members|"
                                 r"plans?|employers?|affiliat\w*|subsidiar\w*|companies|organi[sz]ations|insurers|brokers|"
                                 r"retailers|schools|districts|agencies|practices|providers|hospitals|facilities|"
                                 r"healthcare providers)\b)|exhibit|addend|appendix|schedule|see attached", re.I)
NO_VICTIM = re.compile(r"^\s*(?:(?:files?|archive|dump|leak(?:ed)?(?:\s+data)?|data)\b[\s\-:#]*(?:part\s*)?\d+\b|part\s*\d+\b|"
                       r"(?:files?|data)\s+part\b)", re.I)


def split_agent(raw: str | None) -> tuple[str, str | None, bool]:
    """'Legalinc o/b/o Stripe GEP' -> ('Stripe GEP', 'Legalinc', False): the subject of a filing made by an agent is the
    organisation named after 'on behalf of', never the agent. A generic beneficiary ('its clients', 'the entities in Exhibit
    A') leaves no subject: (agent, agent, True) and the record never anchors a merge."""
    s = unesc(raw)
    m = OBO.search(s)
    if not m or m.start() == 0:
        return s, None, False
    agent, bene = s[:m.start()].strip(' ,;-–('), re.sub(r'\s*\([^)]*$', '', m.group('b')).strip(' ,;-–)."“”')
    if not bene or GENERIC_BENEFICIARY.search(bene) or len(re.sub(r'[^A-Za-z0-9]', '', bene)) < 3:
        return agent, agent, True
    return bene, agent, False


def clean_name(raw: str | None, actor: str | None = None) -> tuple[str, bool, str | None]:
    """(cleaned display name, truncated?, host found in the name). Scraping junk off; the name itself kept."""
    s = unicodedata.normalize('NFKC', unesc(raw)).strip().strip('"“”\'‘’ ')
    truncated = bool(ELLIPSIS.search(s))
    s = ELLIPSIS.sub('', s)
    host = None
    for _ in range(3):
        before = s
        s = PREFIX.sub('', s)
        s = OUTLET_HEAD.sub('', s)
        s = OUTLET_TAIL.sub('', s)
        s = s.strip(' -–—|:,;"“”')
        if s == before:
            break
    for m in PAREN.finditer(s):
        h = HOST.match(m.group(1).strip().lower())
        if h:
            host = h.group(1)
    s = PAREN.sub('', s).strip() or s
    h = HOST.match(s.lower())
    if h:
        host = h.group(1)
    s = POSSESSIVE.sub('', s)
    if actor:
        a = re.escape(actor.strip())
        t = re.sub(r"(?i)^\s*" + a + r"\s*[:|\-–—]\s*|\s*[:|\-–—]\s*" + a + r"\s*$", '', s)
        s = t if t.strip() else s
    w = s.split()
    if len(w) >= 2 and len(w) % 2 == 0 and [x.lower() for x in w[:len(w) // 2]] == [x.lower() for x in w[len(w) // 2:]]:
        s = ' '.join(w[:len(w) // 2])                  # doubled title "Acme Corp Acme Corp"
    return s.strip(), truncated, host


def host_label(host: str | None) -> str | None:
    if not host:
        return None
    parts = host.lower().split('.')
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in SECOND_LEVEL:
        lab = parts[-3]
    else:
        lab = parts[-2] if len(parts) >= 2 else parts[0]
    return lab


def reg_domain(d: str | None) -> str | None:
    d = norm_domain(d) if d else None
    if not d:
        return None
    parts = d.split('.')
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in SECOND_LEVEL:
        return '.'.join(parts[-3:])
    return '.'.join(parts[-2:])


def core_tokens(clean: str, host: str | None = None) -> tuple:
    """Tokens of the organisation's core name: legal forms, 'City/County of', 'the' dropped. A bare hostname -> its label."""
    s = clean
    if host and HOST.match(clean.lower()):
        s = host_label(host) or clean
    for _ in range(2):
        t = FILING_TAIL.sub('', s)
        t = DBA.sub('', t)
        t = QUOTED_ALIAS.sub('', t)
        s = t.strip(' ,;') or s
    s = MUNICIPAL.sub('', s)
    s = MUNICIPAL_TAIL.sub('', s)
    nn = norm_name(s)
    return tuple(ABBREV.get(t, t) for t in nn.split() if t)


def squash(toks) -> str:
    return ''.join(toks)


def initials(toks) -> str:
    return ''.join(t[0] for t in toks if t not in STOP and t[0].isalnum())


def trigrams(s: str) -> set:
    s = f'  {s} '
    return {s[i:i + 3] for i in range(len(s) - 2)}


def trigram_sim(a: str, b: str) -> float:
    ta, tb = trigrams(a), trigrams(b)
    return len(ta & tb) / len(ta | tb) if ta and tb else 0.0


def is_acronym(short: tuple, long_: tuple) -> bool:
    """'HSHS' <-> 'Hospital Sisters Health System'; 'UCLA Health' <-> 'University of California Los Angeles Health'."""
    if not short or not long_ or len(long_) < 2:
        return False
    a = short[0]
    if not (2 <= len(a) <= 7) or not a.isascii():
        return False
    ini = initials(long_)
    if len(ini) < 2:
        return False
    if a == ini or a == ''.join(t[0] for t in long_):
        return len(short) == 1
    # acronym followed by shared tail words: 'ucla health' vs 'university of california los angeles health'
    tail = short[1:]
    if tail and tuple(long_[-len(tail):]) == tuple(tail):
        head = long_[:-len(tail)]
        return a in (initials(head), ''.join(t[0] for t in head))
    return False


# ---------------------------------------------------------------------------------------------------------------
# Campaigns (vendor-vs-customer: one event per breached customer, tied by campaign_id)
# ---------------------------------------------------------------------------------------------------------------
def _o(y, m, d=1):
    return date(y, m, d).toordinal()


CAMPAIGNS = (  # id, text pattern, window (reported date), clop-window (the actor's mass-exploitation wave)
    ('moveit-2023', re.compile(r'\bmove\s?it\b', re.I), (_o(2023, 5, 15), _o(2024, 12, 31)), (_o(2023, 6, 1), _o(2023, 10, 31))),
    ('goanywhere-2023', re.compile(r'\bgo\s?anywhere\b', re.I), (_o(2023, 1, 15), _o(2024, 6, 30)), (_o(2023, 3, 1), _o(2023, 4, 30))),
    ('cleo-2024', re.compile(r'\bcleo\b(?:\s+(?:harmony|vltrader|lexicom|file transfer|software))', re.I),
     (_o(2024, 10, 1), _o(2025, 12, 31)), (_o(2024, 12, 15), _o(2025, 4, 30))),
    ('accellion-2021', re.compile(r'\baccellion\b|\bkiteworks\b', re.I), (_o(2020, 12, 1), _o(2022, 6, 30)), None),
    ('snowflake-2024', re.compile(r'\bsnowflake\b', re.I), (_o(2024, 4, 1), _o(2025, 6, 30)), None),
    ('salesloft-drift-2025', re.compile(r'\bsalesloft\b|\bsales ?loft drift\b', re.I), (_o(2025, 8, 1), _o(2026, 6, 30)), None),
    ('oracle-ebs-2025', re.compile(r'\boracle e-?business\b|\boracle ebs\b|\bE-Business Suite\b', re.I),
     (_o(2025, 9, 15), _o(2026, 9, 30)), (_o(2025, 10, 1), _o(2026, 1, 31))),
)
CLOP = frozenset({'clop', 'cl0p'})


def campaign_of(text: str, actors, reported: int | None) -> str | None:
    if reported is None:
        return None
    for cid, pat, (lo, hi), wave in CAMPAIGNS:
        if lo <= reported <= hi and pat.search(text or ''):
            return cid
    if actors & CLOP:
        for cid, _, _, wave in CAMPAIGNS:
            if wave and wave[0] <= reported <= wave[1]:
                return cid
    return None


# ---------------------------------------------------------------------------------------------------------------
# Records and units
# ---------------------------------------------------------------------------------------------------------------
@dataclass
class Rec:
    vid: str                    # claim:<key> | incident:<uuid>
    kind: str                   # claim | incident
    mid: str                    # member id
    name: str                   # display
    toks: tuple                 # core tokens
    core: str                   # squashed core
    truncated: bool
    domain: str | None
    org_id: str | None
    country: str | None
    industry: str | None
    reported: int | None
    breach: int | None
    breach_prec: str | None
    actors: frozenset
    people: float | None
    people_total: bool          # people is a total (not a per-state notice count)
    gb: float | None
    stratum: str                # leak | regulator | press | index
    sources: frozenset
    titles: tuple = ()
    quotes: tuple = ()
    follow_up: bool = False
    campaign: str | None = None
    related: frozenset = frozenset()   # Wikidata parent/owner/subsidiary core keys
    legacy_dup: str | None = None      # vid of the legacy possible_duplicate_of
    link_to: str | None = None         # structured link: leak claim -> its incident's vid
    listed: bool = True
    text: str = ''                     # lower-case text for co-mention tests
    extra_members: tuple = ()          # (kind, id) structured members carried by this record (grouped posts)
    card_issuer: bool = False          # a regulator notice by a card issuer: about a merchant's breach (linkage s7 b1)
    agent: str | None = None           # v2: the filing agent when the record is filed 'on behalf of' its subject
    agent_only: bool = False           # v2: filed by an agent for unnamed customers: no subject, never anchors a merge
    no_victim: bool = False            # v2: a title with no victim ('FILES PART 2'): never seeds or joins an event


def _ord(v) -> int | None:
    if not v:
        return None
    if isinstance(v, date):
        return v.toordinal()
    return date.fromisoformat(str(v)[:10]).toordinal()


def stratum_of(sources) -> str:
    s = set(sources or ())
    if s & REGULATOR:
        return 'regulator'
    if s & INDEX:
        return 'index'
    if any(x.startswith('news_') for x in s):
        return 'press'
    return 'leak'


def actor_key(name: str | None) -> str | None:
    """One key per actor spelling: 'CL0P' = 'clop', 'LockBit 3.0' = 'lockbit3' = 'lockbit', 'INC Ransom' = 'inc'."""
    s = unicodedata.normalize('NFKD', name or '').encode('ascii', 'ignore').decode().lower()
    s = re.sub(r'[^a-z0-9]+', '', s)
    t = re.sub(r'(ransomware|ransom|group|team|gang|leaks|leak|blog)$', '', s)
    s = t if len(t) >= 3 else s
    t = re.sub(r'(?<=[a-z]{3})v?[0-9]+$', '', s)          # version suffix: lockbit3, lockbit30, babuk2
    s = (t if len(t) >= 3 else s).replace('0', 'o')        # cl0p = clop
    t = s
    return (t if len(t) >= 3 else s) or None


def make_rec(*, vid, name, domain=None, org_id=None, country=None, industry=None, reported=None, breach=None,
             breach_prec=None, actor=None, people=None, gb=None, sources=(), titles=(), quotes=(), related=(),
             legacy_dup=None, link_to=None, listed=True, extra_members=(), all_titles=None) -> Rec:
    kind, mid = vid.split(':', 1)
    raw_name = name
    name, agent, agent_only = split_agent(name)
    clean, trunc, host = clean_name(name, actor)
    dom = reg_domain(domain) or (reg_domain(host) if host else None)
    toks = core_tokens(clean, host)
    srcs = frozenset(sources or ())
    stratum = stratum_of(srcs)
    rep = _ord(reported)
    actors = frozenset(a for a in {actor_key(actor)} if a)
    ft = titles if all_titles is None else all_titles     # every headline behind the record, roundups included
    fu = bool(ft) and stratum == 'press' and all(doc_kind.FOLLOW_UP_TITLE.search(t or '') for t in ft)
    text = ' '.join([name or ''] + list(titles) + list(quotes)).lower()
    return Rec(vid, kind, mid, clean or (name or ''), toks, squash(toks), trunc, dom, org_id, country, industry, rep,
               _ord(breach), (breach_prec or 'day') if breach else None, actors,
               float(people) if people else None, not (srcs & STATE_AG), float(gb) if gb else None, stratum, srcs,
               tuple(titles), tuple(quotes), fu, campaign_of(text, actors, rep), frozenset(related), legacy_dup,
               link_to, listed, text, tuple(extra_members),
               bool(srcs & REGULATOR) and ' '.join(toks).startswith(CARD_ISSUERS), agent, agent_only,
               bool(NO_VICTIM.search(unesc(raw_name or ''))) or not re.search(r'[^\W_]', unesc(raw_name or '')))


class UF:
    def __init__(self):
        self.p = {}

    def find(self, x):
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            if rb < ra:
                ra, rb = rb, ra
            self.p[rb] = ra
        return ra


@dataclass
class Unit:
    uid: str                    # anchor vid (smallest)
    recs: list
    method: dict = field(default_factory=dict)   # vid -> seed | structured_key | deterministic
    busy: bool = False          # a frequent victim: >= BUSY_UNITS units of the same core name within the window

    @property
    def reported(self):
        r = [x.reported for x in self.recs if x.reported is not None and not x.follow_up]
        r = r or [x.reported for x in self.recs if x.reported is not None]
        return min(r) if r else None

    @property
    def leak_only(self):
        return all(r.stratum == 'leak' for r in self.recs)

    @property
    def actors(self):
        return frozenset().union(*(r.actors for r in self.recs))

    @property
    def campaigns(self):
        return frozenset(r.campaign for r in self.recs if r.campaign)

    @property
    def follow_up(self):
        return all(r.follow_up for r in self.recs)

    def breach(self):
        b = [(r.breach, r.breach_prec) for r in self.recs if r.breach is not None]
        return min(b) if b else (None, None)


def same_filing(a: Rec, b: Rec) -> bool:
    if a.breach and b.breach and a.breach_prec == 'day' and b.breach_prec == 'day':
        return a.breach == b.breach
    return (a.stratum == 'regulator' and b.stratum == 'regulator' and a.reported is not None and b.reported is not None
            and abs(a.reported - b.reported) <= 7 and not (a.breach and b.breach))


def build_units(recs: list) -> list:
    """Structured keys (leak claim -> incident) then deterministic leak episodes (same actor + same company, 90 days)."""
    uf, method = UF(), {r.vid: 'seed' for r in recs}
    by = {r.vid: r for r in recs}
    for r in recs:
        if r.link_to and r.link_to in by:
            uf.union(r.vid, r.link_to)
            method[r.vid] = 'structured_key'
    groups = collections.defaultdict(list)
    for r in recs:
        if r.stratum == 'leak' and r.actors and r.reported is not None and not r.no_victim:
            for a in r.actors:
                if r.core and len(r.core) >= 3:
                    groups[('n', a, r.core)].append(r)
                if r.domain:
                    groups[('d', a, r.domain)].append(r)
    for _, rs in sorted(groups.items()):
        rs.sort(key=lambda x: (x.reported, x.vid))
        anchor = rs[0]
        for x in rs[1:]:
            if x.reported - anchor.reported <= LEAK_EPISODE_DAYS:
                if uf.find(x.vid) != uf.find(anchor.vid):
                    uf.union(x.vid, anchor.vid)
                    if method[x.vid] == 'seed':
                        method[x.vid] = 'deterministic'
            else:
                anchor = x
    # deterministic, non-leak: the same organisation (org id / domain / exact core) with the same breach day, or two
    # regulator filings within 7 days with no breach-date conflict (one breach filed in several states). Dev H1-H3:
    # 50/50 and 83/83 same_breach. Card issuers never (their notices are about merchants' breaches).
    idx = collections.defaultdict(list)
    for r in recs:
        if r.stratum != 'leak' and not r.card_issuer and not r.agent_only and not r.no_victim and \
                (r.breach or r.stratum == 'regulator'):
            for k in ((('o', r.org_id) if r.org_id else None), (('d', r.domain) if r.domain else None),
                      (('c', r.core) if len(r.core) >= 3 else None)):
                if k:
                    idx[k].append(r)
    for k in sorted(idx):
        rs = sorted(idx[k], key=lambda x: x.vid)
        if len(rs) > 200:
            continue
        for i in range(len(rs)):
            for j in range(i + 1, len(rs)):
                a, b = rs[i], rs[j]
                if same_filing(a, b) and uf.find(a.vid) != uf.find(b.vid):
                    uf.union(a.vid, b.vid)
                    for x in (a, b):
                        if method[x.vid] == 'seed':
                            method[x.vid] = 'deterministic'
    members = collections.defaultdict(list)
    for r in recs:
        members[uf.find(r.vid)].append(r)
    units = []
    for root, rs in members.items():
        rs.sort(key=lambda x: (x.reported or 0, x.vid))
        uid = min(x.vid for x in rs)
        m = {x.vid: method[x.vid] for x in rs}
        # the unit's first record is its seed; the rest joined by the key that brought them
        first = rs[0].vid
        m[first] = 'seed'
        for x in rs[1:]:
            if m[x.vid] == 'seed':
                m[x.vid] = 'structured_key'
        units.append(Unit(uid, rs, m))
    units.sort(key=lambda u: u.uid)
    return units


# ---------------------------------------------------------------------------------------------------------------
# Blocking
# ---------------------------------------------------------------------------------------------------------------
STRENGTH = {'org': 3, 'domain': 3, 'exact': 3, 'legacy': 2, 'acronym': 2, 'prefix': 2, 'domain_name': 2, 'tokenset': 1,
            'trigram': 1, 'parent': 0}


def name_link(a: Rec, b: Rec, df=None) -> str | None:
    """The strongest name relation between two records, or None. df: token -> number of records (rarity)."""
    if a.org_id and a.org_id == b.org_id:
        return 'org'
    if a.domain and a.domain == b.domain:
        return 'domain'
    if a.core and a.core == b.core and len(a.core) >= 3:
        return 'exact'
    if (a.legacy_dup and a.legacy_dup == b.vid) or (b.legacy_dup and b.legacy_dup == a.vid):
        return 'legacy'
    if is_acronym(a.toks, b.toks) or is_acronym(b.toks, a.toks):
        return 'acronym'
    for x, y in ((a, b), (b, a)):
        if x.truncated and len(x.core) >= 6 and y.core.startswith(x.core):
            return 'prefix'
        if x.domain and y.core and len(y.core) >= 4 and host_label(x.domain).replace('-', '') == y.core:
            return 'domain_name'
    ta, tb = set(a.toks), set(b.toks)
    if ta and tb:
        small, large = (ta, tb) if len(ta) <= len(tb) else (tb, ta)
        distinct = [t for t in small if len(t) >= 4 and t not in GENERIC]
        if small <= large and distinct and (len(small) >= 2 or len(large) <= 3):
            return 'tokenset'
        if small <= large and len(small) >= 2 and not (large - small - GENERIC):
            return 'tokenset'           # 'LCS Financial' / 'LCS Financial Services'
        if small <= large and len(small) == 1 and distinct and len(distinct[0]) >= 6 and df is not None and \
                df.get(distinct[0], 0) <= 50:
            return 'tokenset'           # one rare distinctive word: 'AssuranceAmerica' / '... Managing General Agency'
        da, db = ta - GENERIC, tb - GENERIC
        if da and da == db and (len(da) >= 2 or any(len(t) >= 5 for t in da)):
            return 'tokenset'           # only generic words differ: 'Bradford Health Services' / '... Health Systems'
    if len(a.core) >= 5 and len(b.core) >= 5 and trigram_sim(a.core, b.core) >= TRIGRAM_MIN:
        return 'trigram'
    if (a.related and b.core in a.related) or (b.related and a.core in b.related):
        return 'parent'
    return None


WEAK_FOR_INDUSTRY = frozenset({'trigram', 'parent'})


def _near(x, y, days=WINDOW_DAYS):
    return x is not None and y is not None and abs(x - y) <= days


def pair_ok(a: Rec, b: Rec, link: str) -> bool:
    """Window, volume and industry rules inside a block."""
    fu = a.follow_up or b.follow_up
    if not fu:
        dates_a = [d for d in (a.reported, a.breach) if d is not None]
        dates_b = [d for d in (b.reported, b.breach) if d is not None]
        if dates_a and dates_b and not any(_near(x, y) for x in dates_a for y in dates_b):
            return False
    elif link in WEAK_FOR_INDUSTRY:
        return False                       # a follow-up attaches to the same organisation only (any age)
    if a.people and b.people and a.people_total and b.people_total:
        hi, lo = max(a.people, b.people), min(a.people, b.people)
        if lo > 0 and hi / lo > VOLUME_RATIO:
            return False
    if a.industry and b.industry and a.industry != b.industry and link in WEAK_FOR_INDUSTRY:
        return False                       # industry must be compatible when only the spelling links them
    return True


def block(recs: list, unit_of: dict) -> dict:
    """{(unit_a, unit_b): link} for unit pairs with at least one record pair passing the block rules. Deterministic."""
    keys = collections.defaultdict(set)
    df = collections.Counter()
    for r in recs:
        df.update(set(r.toks))
    ident = []
    for r in recs:
        ks = set()
        if r.org_id:
            ks.add(('o', r.org_id))
        if r.domain:
            ks.add(('d', r.domain))
            lab = host_label(r.domain).replace('-', '')
            if len(lab) >= 4:
                ks.add(('c', lab))
        if len(r.core) >= 3:
            ks.add(('c', r.core))
            ks.add(('p6', r.core[:6]))
        if r.legacy_dup:
            ks.add(('l', min(r.vid, r.legacy_dup) + '|' + max(r.vid, r.legacy_dup)))
        if len(r.toks) >= 2:
            ini = initials(r.toks)
            if len(ini) >= 2:
                ks.add(('c', ini))           # long form indexed under its initials; an acronym under its core
        for t in r.toks:
            if len(t) >= 4 and t not in GENERIC and df[t] <= BLOCK_CAP:
                ks.add(('t', t))
        for rel in r.related:
            ks.add(('c', rel))
        for k in ks:
            keys[k].add(r.vid)
        ident.append(r)
    by = {r.vid: r for r in recs}
    out: dict = {}
    for k in sorted(keys):
        vs = sorted(keys[k])
        if len(vs) < 2 or (k[0] in ('t', 'p6') and len(vs) > BLOCK_CAP):
            continue
        for i in range(len(vs)):
            for j in range(i + 1, len(vs)):
                ua, ub = unit_of[vs[i]], unit_of[vs[j]]
                if ua == ub:
                    continue
                pk = (ua, ub) if ua < ub else (ub, ua)
                a, b = by[vs[i]], by[vs[j]]
                link = name_link(a, b, df)
                if link is None or not pair_ok(a, b, link):
                    continue
                if pk not in out or STRENGTH[link] > STRENGTH[out[pk]]:
                    out[pk] = link
    return out


def unit_near(u: Unit, v: Unit) -> bool:
    """Some reported or breach date of u within the blocking window of one of v (or no dates to compare)."""
    du = [d for r in u.recs for d in (r.reported, r.breach) if d is not None]
    dv = [d for r in v.recs for d in (r.reported, r.breach) if d is not None]
    return not du or not dv or any(_near(x, y) for x in du for y in dv)


REG_BREACH_DAYS = 31        # v2: two regulator notices of one org with breach dates further apart are different events
EPISODE_BREACH_DAYS = 365   # both breach dates known: one episode within 12 months (rubric s3)
EPISODE_LEAD_DAYS = 60      # one breach date known: the other record may appear 60 days before ...
EPISODE_LAG_DAYS = 540      # ... to 18 months after it (late notices, press, leak posts after the intrusion)
EPISODE_REPORTED_DAYS = 120 # no breach dates: records within 120 days (rubric s3)
REPOST_TEXT = re.compile(r"\b(re-?post(?:ed)?|re-?upload(?:ed)?|again|previously (?:published|leaked|posted|reported)|same data|"
                         r"second part|part\s*[2-9])\b", re.I)


def dates_agree(a: Rec, b: Rec) -> bool:
    if a.breach and b.breach:
        lim = REG_BREACH_DAYS if a.stratum == 'regulator' and b.stratum == 'regulator' else EPISODE_BREACH_DAYS
        return abs(a.breach - b.breach) <= lim
    for x, y in ((a, b), (b, a)):
        if x.breach and not y.breach:
            return y.reported is not None and x.breach - EPISODE_LEAD_DAYS <= y.reported <= x.breach + EPISODE_LAG_DAYS
    if a.reported is None or b.reported is None:
        return False
    lim = LEAK_EPISODE_DAYS if a.stratum == 'leak' and b.stratum == 'leak' else EPISODE_REPORTED_DAYS
    return abs(a.reported - b.reported) <= lim


def episode_why(u: Unit, ev_units: list) -> str | None:
    """v2: the same organisation is a separate episode unless the dates agree (or a follow-up / an explicit repost)."""
    if u.follow_up:
        return None
    for v in ev_units:
        for a in u.recs:
            for b in v.recs:
                if a.stratum == 'regulator' and b.stratum == 'regulator' and a.breach and b.breach and \
                        abs(a.breach - b.breach) > REG_BREACH_DAYS:
                    return 'reg_breach_dates'
    core = [v for v in ev_units if not v.follow_up] or ev_units
    if any(dates_agree(a, b) for v in core for a in v.recs for b in u.recs):
        return None
    if u.leak_only and all(v.leak_only for v in core) and any(REPOST_TEXT.search(' '.join(r.quotes)) for r in u.recs):
        return None
    return 'leak_repost_far' if u.leak_only and all(v.leak_only for v in core) else 'episode_dates'


def cannot_link(u: Unit, ev_units: list) -> str | None:
    """Deterministic: never merge u into the event made of ev_units."""
    if any(r.card_issuer for r in u.recs):
        return 'card_issuer'
    if any(r.agent_only for r in u.recs) or any(r.agent_only for v in ev_units for r in v.recs):
        return 'filing_agent'
    if any(r.no_victim for r in u.recs) or any(r.no_victim for v in ev_units for r in v.recs):
        return 'no_victim'
    for v in ev_units:
        if u.leak_only and v.leak_only and u.actors and v.actors and not (u.actors & v.actors):
            return 'leak_actor_differs'
        if u.campaigns and v.campaigns and not (u.campaigns & v.campaigns):
            return 'campaign_differs'
        (bu, pu), (bv, pv) = u.breach(), v.breach()
        if bu and bv and not (u.follow_up or v.follow_up) and abs(bu - bv) > WINDOW_DAYS:
            return 'breach_dates_far'
    return episode_why(u, ev_units)


# ---------------------------------------------------------------------------------------------------------------
# Cards and the Jev request
# ---------------------------------------------------------------------------------------------------------------
SOURCE_WORD = {'leak': 'ransomware leak-site post', 'regulator': 'regulator breach filing', 'index': 'breach index entry',
               'press': 'press article'}


def _iso(o):
    return date.fromordinal(o).isoformat() if o else None


def card(units: list) -> dict:
    recs = sorted((r for u in units for r in u.recs), key=lambda r: (r.reported or 0, r.vid))
    names = list(dict.fromkeys(r.name for r in recs if r.name))[:3]
    c = {'names': names}
    doms = sorted({r.domain for r in recs if r.domain})[:2]
    if doms:
        c['website'] = doms
    for f in ('country', 'industry'):
        v = sorted({getattr(r, f) for r in recs if getattr(r, f)})
        if v:
            c[f] = v[:2]
    rep = [r.reported for r in recs if r.reported]
    if rep:
        c['first_reported'] = _iso(min(rep))
        if max(rep) - min(rep) > 30:
            c['last_reported'] = _iso(max(rep))
    br = sorted({_iso(r.breach) for r in recs if r.breach})
    if br:
        c['breach_date'] = br[:2]
    act = sorted({a for r in recs for a in r.actors})
    if act:
        c['attacker_group'] = act[:3]
    ppl = [r.people for r in recs if r.people]
    if ppl:
        c['people_affected'] = int(max(ppl))
    gb = [r.gb for r in recs if r.gb]
    if gb:
        c['data_stolen_gb'] = round(max(gb), 1)
    c['record_types'] = sorted({SOURCE_WORD[r.stratum] for r in recs})
    camp = sorted({r.campaign for r in recs if r.campaign})
    if camp:
        c['supplier_campaign'] = camp
    heads = list(dict.fromkeys(t[:160] for r in recs for t in r.titles if t))[:2]
    if heads:
        c['headlines'] = heads
    quotes = list(dict.fromkeys(q[:240] for r in recs for q in r.quotes if q))[:2]
    if quotes:
        c['quotes'] = quotes
    if any(r.follow_up for r in recs):
        c['note'] = 'headline is about a lawsuit, settlement or other follow-up'
    return c


RULES = ('A breach event is ONE organisation hit by ONE breach episode. The same event is usually recorded several times: '
         'a ransomware leak-site post (sometimes several posts), regulator filings in several states (each counting only that '
         'state\'s residents, filed days to months apart, sometimes supplemental notices years later), a breach-index entry, '
         'press articles (often a roundup naming several victims), and later lawsuit, settlement or court news about it. '
         'These are the SAME event: the same organisation with breach dates that agree or are close, or records that appear '
         'within a few months of each other with nothing indicating a second incident. Differing affected-people counts are '
         'normal. Names are messy and still mean the same organisation: truncated headlines, legal forms (Inc., LLC), an '
         'acronym versus the long name, a website instead of a name, possessives, a news-outlet or "Exclusive:" prefix, '
         '"City of X" versus "X". DIFFERENT organisations: separate brands or subsidiaries whose names differ substantively '
         '(Volkswagen versus Seat) unless one intrusion is stated to have hit both; a software vendor versus a customer '
         'breached through that vendor\'s product (MOVEit, Cleo, Snowflake): each customer is its own event. Same '
         'organisation but a DIFFERENT episode: breach dates clearly far apart (a year or more), a different attacker group, '
         'or a record that describes a new or second incident. The first_reported date is when a record appeared, not when '
         'the breach happened; a late notice about an old breach is still that old breach.')
CHOICE_Q = RULES + (' Which candidate event in `candidates` is the same breach event as `record` (the same organisation and '
                    'the same breach episode)? Choose none if no candidate is.')
PAIR_Q = RULES + ' Is `record` about the same breach event as `{c}`: the same organisation and the same breach episode?'
ORG_Q = RULES + (' Are `record` and `{c}` the SAME organisation: the same legal entity or the same brand? Answer no if they '
                 'are different organisations whose names merely overlap: a dealer, franchisee, agency or law firm named after '
                 'another company, a subsidiary or sister brand with its own name, a different company sharing a word.')
DIFF_Q = RULES + (' Is `record` about a DIFFERENT breach event than `{c}`: a different organisation, or the same organisation '
                  'hit in a separate incident?')
NONE_CRIT = 'none of the candidate events: a different organisation, or the same organisation in a different breach episode'


def prompt_sha256() -> str:
    return hashlib.sha256((QV + '\n' + CHOICE_Q + '\n' + PAIR_Q + '\n' + DIFF_Q + '\n' + ORG_Q + '\n' + NONE_CRIT).encode()).hexdigest()


def build_request(rec_card: dict, cand_cards: list) -> tuple[dict, dict]:
    state = {'record': rec_card, 'candidates': {f'e{k + 1}': c for k, c in enumerate(cand_cards)}}
    crit = {f'e{k + 1}': f'candidate `candidates.e{k + 1}`' for k in range(len(cand_cards))}
    crit['none'] = NONE_CRIT
    qs = {'pick': {'type': 'choice', 'instructions': CHOICE_Q, 'criteria': crit}}
    for k in range(len(cand_cards)):
        qs[f'same_e{k + 1}'] = {'type': 'noul', 'instructions': PAIR_Q.format(c=f'candidates.e{k + 1}')}
        qs[f'diff_e{k + 1}'] = {'type': 'noul', 'instructions': DIFF_Q.format(c=f'candidates.e{k + 1}')}
        qs[f'org_e{k + 1}'] = {'type': 'noul', 'instructions': ORG_Q.format(c=f'candidates.e{k + 1}')}
    return state, qs


def input_sha256(state, qs, model) -> str:
    return hashlib.sha256(json.dumps({'m': model, 's': state, 'q': qs}, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def read_answer(answers: dict, k: int) -> dict:
    """{'pick': 'e2'|'none', 'choice_p': p(pick), 'pair_p': noul of the pick, 'probs': {...}}."""
    pk = answers.get('pick') or {}
    probs = pk.get('probabilities') or {}
    pick = pk.get('choice')
    if pick not in probs:
        pick = max(probs, key=probs.get) if probs else 'none'
    out = {'pick': pick, 'choice_p': float(probs.get(pick, 0.0)), 'probs': probs, 'pair_p': None}
    out['pairs'] = {f'e{i + 1}': pair_p(answers, f'e{i + 1}') for i in range(k)}
    out['orgs'] = {f'e{i + 1}': (answers.get(f'org_e{i + 1}') or {}).get('noul') for i in range(k)}
    out['org_p'] = out['orgs'].get(pick) if pick != 'none' else None
    if pick != 'none':
        out['pair_p'] = out['pairs'].get(pick, 0.0)
    return out


def pair_p(answers: dict, key: str) -> float:
    """The pairwise yes/no, asked both ways: mean of p(same) and 1 - p(different). A missing 'diff' (a fake or an
    older answer) leaves p(same)."""
    same = float(((answers.get('same_' + key) or {}).get('noul')) or 0.0)
    d = (answers.get('diff_' + key) or {}).get('noul')
    return same if d is None else (same + 1.0 - float(d)) / 2.0


def decide(ans: dict, *, tau_c=TAU_C, tau_p=TAU_P, uncertain=UNCERTAIN, merge_allowed=True) -> str:
    """merge | possible | new."""
    if ans['pick'] == 'none' or ans['pair_p'] is None:
        return 'new'
    if ans['choice_p'] >= tau_c and ans['pair_p'] >= tau_p and merge_allowed:
        return 'merge'
    if ans['choice_p'] >= uncertain and ans['pair_p'] >= uncertain:
        return 'possible'
    return 'new'


# ---------------------------------------------------------------------------------------------------------------
# The matcher
# ---------------------------------------------------------------------------------------------------------------
class Asker:
    """Jev with a cache of stored answers (r2_answers): a re-run with the same inputs never re-asks."""

    def __init__(self, jev=None, cache=None, model='jev-1.13.0'):
        self.jev, self.cache, self.model = jev, dict(cache or {}), model
        self.new = []                     # answer rows to insert
        self.lock = threading.Lock()
        self.calls = self.cached = self.tokens = 0

    def ask(self, input_ref, state, qs):
        ish = input_sha256(state, qs, self.model)
        with self.lock:
            if ish in self.cache:
                self.cached += 1
                return self.cache[ish]
        from zdc_breach.profile import JevError
        for attempt in range(6):
            try:
                js = self.jev.ask(state, qs, model=self.model)
                break
            except JevError:                      # e.g. 529 overloaded: back off, then give up loudly
                if attempt == 5:
                    raise
                time.sleep(5 * (attempt + 1))
        ans = js.get('answers') or {}
        tok = int((js.get('usage') or {}).get('input_tokens') or 0)
        row = {'input_ref': input_ref, 'input_sha256': ish, 'answer': ans, 'model_id': js.get('model') or self.model,
               'cost_usd': round(tok * PRICE_PER_MTOK / 1e6, 6)}
        with self.lock:
            self.calls += 1
            self.tokens += tok
            self.cache[ish] = row
            self.new.append(row)
        return row


@dataclass
class Event:
    eid: str
    units: list
    method: dict                      # vid -> (match_method, choice_p, pair_p, input_sha256)
    role: dict                        # vid -> member | follow_up
    possible_dup: str | None = None
    possible_p: tuple | None = None


def event_id(anchor_vid: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f'zdc:{METHOD_VERSION}:{anchor_vid}'))


CONTAIN_LINKS = frozenset({'tokenset', 'trigram', 'prefix', 'acronym', 'parent'})


def needs_org_check(u: Unit, ev_units: list, link: str) -> bool:
    """v2: a name link short of identity (containment, spelling, acronym) merges only on a shared domain or Jev's
    same-legal-entity-or-brand answer."""
    if link not in CONTAIN_LINKS:
        return False
    doms = {r.domain for r in u.recs if r.domain}
    return not (doms & {r.domain for v in ev_units for r in v.recs if r.domain})


def text_names(u: Unit, other: list) -> bool:
    """The brand rule's exception: the record itself names the other organisation (one intrusion, several brands)."""
    txt = ' '.join(r.text for r in u.recs)
    for v in other:
        for r in v.recs:
            if len(r.name) >= 4 and r.name.lower() in txt:
                return True
    return False


def mark_busy(units: list) -> None:
    """Frequent victims (Microsoft, a state agency): many units of one core name within +-24 months. Their decisions
    take the strict tier (repeat victims are the main merge risk, RUBRIC_R2 D4)."""
    by = collections.defaultdict(list)
    for u in units:
        cores = {r.core for r in u.recs if len(r.core) >= 3}
        for c in cores:
            by[c].append(u)
    for c, us in by.items():
        if len(us) < BUSY_UNITS:
            continue
        reps = sorted((u.reported or 0, u.uid) for u in us)
        for u in us:
            n = sum(1 for d, _ in reps if abs(d - (u.reported or 0)) <= WINDOW_DAYS)
            if n >= BUSY_UNITS:
                u.busy = True


def components(units: list, edges: dict) -> list:
    uf = UF()
    for u in units:
        uf.find(u.uid)
    for a, b in edges:
        uf.union(a, b)
    comp = collections.defaultdict(list)
    for u in units:
        comp[uf.find(u.uid)].append(u)
    return sorted(comp.values(), key=lambda c: c[0].uid)


def _sortkey(u: Unit):
    return (u.reported if u.reported is not None else 10 ** 7, u.uid)


def thin(u: Unit) -> bool:
    """No evidence beyond a name and a date: no breach date, actor, count, headline or quote."""
    return not any(r.breach or r.actors or r.people or r.titles or r.quotes for r in u.recs)


def tier(u: Unit, link: str, ev_units: list) -> str:
    press_only = lambda w: all(r.stratum == 'press' for r in w.recs)
    if u.follow_up or u.busy or thin(u) or (press_only(u) and all(press_only(v) for v in ev_units)):
        return 'C'          # press vs press (repeat victims: press_press failed 96.2%), follow-ups, evidence-poor
    if STRENGTH.get(link, 0) < 3:
        return 'B'
    for v in ev_units:
        if v.follow_up:
            continue
        (bu, _), (bv, _) = u.breach(), v.breach()
        if bu and bv:
            if abs(bu - bv) <= AGREE_BREACH_DAYS:
                return 'A'
        elif u.reported is not None and v.reported is not None and abs(u.reported - v.reported) <= AGREE_REPORTED_DAYS:
            return 'A'
    return 'B'


def run_component(units: list, edges: dict, asker: Asker | None, *, taus=None, stats=None, log=None,
                  preplaced: dict | None = None) -> list:
    """Online assignment, oldest unit first. Returns the NEW events of this component.
    preplaced (incremental mode): unit id -> Event for units that already belong to a stored event; they are candidates
    for the units being placed, exactly as an event created earlier in the same pass is. `units` then holds only the
    units still to place."""
    stats = stats if stats is not None else collections.Counter()
    adj = collections.defaultdict(dict)
    for (a, b), link in edges.items():
        adj[a][b] = link
        adj[b][a] = link
    ev_of, events = dict(preplaced or {}), []
    for u in sorted(units, key=_sortkey):
        cands = {}
        for v, link in adj[u.uid].items():
            if v in ev_of:
                e = ev_of[v]
                if not u.follow_up and not any(unit_near(u, w) for w in e.units if not w.follow_up) and \
                        any(not w.follow_up for w in e.units):
                    continue                    # reached only through a follow-up: the event itself is out of window
                s = STRENGTH[link]
                if e.eid not in cands or s > cands[e.eid][0]:
                    cands[e.eid] = (s, link, e)
        ok = []
        for eid, (s, link, e) in cands.items():
            why = cannot_link(u, e.units)
            if why:
                stats['cannot_' + why] += 1
                continue
            dist = min((abs((u.reported or 0) - (v.reported or 0)) for v in e.units), default=10 ** 6)
            ok.append((-s, dist, eid, link, e))
        ok.sort(key=lambda x: x[:3])
        ok = ok[:K]
        placed = None
        if ok and asker is not None:
            rec_card = card([u])
            cand_cards = [card(e.units) for *_, e in ok]
            state, qs = build_request(rec_card, cand_cards)
            row = asker.ask(u.recs[0].vid, state, qs)
            ans = read_answer(row['answer'], len(ok))
            target = None
            if ans['pick'] != 'none':
                idx = int(ans['pick'][1:]) - 1
                target = ok[idx]
            merge_allowed = True
            if target is not None and target[3] == 'parent' and not text_names(u, target[4].units):
                merge_allowed = False           # brand rule: a parent-only link needs the record to name both
            if target is not None and needs_org_check(u, target[4].units, target[3]) and \
                    (ans.get('org_p') is None or ans['org_p'] < TAU_ORG):
                merge_allowed = False           # v2 containment rule: 'Comoli Ferrari' is not 'Ferrari S.p.A.'
                stats['org_check_failed'] += 1
            tr = tier(u, target[3], target[4].units) if target is not None else None
            tc, tp = (taus or TAUS)[tr] if tr else (TAU_C, TAU_P)
            verdict = decide(ans, tau_c=tc, tau_p=tp, merge_allowed=merge_allowed)
            stats['jev_' + verdict] += 1
            if tr:
                stats[f'tier_{tr}_{verdict}'] += 1
            if log is not None:
                log.append({'unit': u.uid, 'recs': [r.vid for r in u.recs], 'target': target[4].eid if target else None,
                            'target_recs': [r.vid for w in target[4].units for r in w.recs] if target else [],
                            'link': target[3] if target else None, 'tier': tr, 'choice_p': ans['choice_p'],
                            'pair_p': ans['pair_p'], 'org_p': ans.get('org_p'), 'verdict': verdict, 'ncand': len(ok)})
            if verdict == 'merge':
                e = target[4]
                e.units.append(u)
                role = 'follow_up' if u.follow_up else 'member'
                for r in u.recs:
                    m = u.method.get(r.vid, 'seed')
                    e.method[r.vid] = ('jev_choice_pair' if m == 'seed' else m, ans['choice_p'], ans['pair_p'],
                                       row['input_sha256'])
                    e.role[r.vid] = role
                ev_of[u.uid] = e
                placed = e
                stats['merge_' + target[3]] += 1
            elif verdict == 'possible':
                placed = 'possible', target[4], (ans['choice_p'], ans['pair_p'], row['input_sha256'])
        elif ok:
            stats['no_jev'] += 1
        if not isinstance(placed, Event):
            e = Event(event_id(u.uid), [u], {r.vid: (u.method.get(r.vid, 'seed'), None, None, None) for r in u.recs},
                      {r.vid: 'member' for r in u.recs})
            if isinstance(placed, tuple):
                e.possible_dup, e.possible_p = placed[1].eid, placed[2]
                stats['possible_duplicate'] += 1
            events.append(e)
            ev_of[u.uid] = e
    return events


def run(recs: list, asker: Asker | None, *, taus=None, workers=8, stats=None, only_units=None, log=None) -> list:
    stats = stats if stats is not None else collections.Counter()
    units = build_units(recs)
    unit_of = {r.vid: u.uid for u in units for r in u.recs}
    mark_busy(units)
    edges = block(recs, unit_of)
    comps = components(units, edges)
    if only_units is not None:
        comps = [c for c in comps if any(u.uid in only_units for u in c)]
    stats['units'] += len(units)
    stats['edges'] += len(edges)
    stats['components_multi'] += sum(1 for c in comps if len(c) > 1)
    out = []
    lock = threading.Lock()

    def one(c):
        ids = {u.uid for u in c}
        ed = {k: v for k, v in edges.items() if k[0] in ids}
        st = collections.Counter()
        lg = [] if log is not None else None
        evs = run_component(c, ed, asker, taus=taus, stats=st, log=lg)
        with lock:
            stats.update(st)
            if log is not None:
                log.extend(lg)
            out.extend(evs)

    singles = [c for c in comps if len(c) == 1]
    multi = [c for c in comps if len(c) > 1]
    for c in singles:
        one(c)
    if workers <= 1:
        for c in multi:
            one(c)
    else:
        with cf.ThreadPoolExecutor(workers) as ex:
            for f in [ex.submit(one, c) for c in multi]:
                f.result()
    out.sort(key=lambda e: e.eid)
    return out


# ---------------------------------------------------------------------------------------------------------------
# Event rows
# ---------------------------------------------------------------------------------------------------------------
PRECEDENCE = {'regulator': 0, 'index': 1, 'press': 2, 'leak': 3}


def event_row(e: Event) -> dict:
    recs = [r for u in e.units for r in u.recs]
    top = sorted(recs, key=lambda r: (PRECEDENCE[r.stratum], r.reported or 0, r.vid))[0]
    rep = [r.reported for r in recs if r.reported and e.role.get(r.vid) != 'follow_up'] or \
          [r.reported for r in recs if r.reported]
    br = sorted((r.breach, r.breach_prec) for r in recs if r.breach and e.role.get(r.vid) != 'follow_up')
    camp = collections.Counter(r.campaign for r in recs if r.campaign)
    org_id = next((r.org_id for r in sorted(recs, key=lambda r: (PRECEDENCE[r.stratum], r.vid)) if r.org_id), None)
    return {'event_id': e.eid, 'org_id': org_id, 'org_name': top.name or top.vid, 'campaign_id':
            (sorted(camp.items(), key=lambda kv: (-kv[1], kv[0]))[0][0] if camp else None),
            'breach_date': _iso(br[0][0]) if br else None, 'breach_date_precision': (br[0][1] or 'day') if br else None,
            'reported_date': _iso(min(rep)) if rep else None, 'possible_duplicate_of': e.possible_dup}


def member_rows(e: Event) -> list:
    out = []
    for u in e.units:
        for r in u.recs:
            m, cp, pp, ish = e.method[r.vid]
            out.append({'event_id': e.eid, 'member_kind': r.kind, 'member_id': r.mid, 'role': e.role[r.vid],
                        'match_method': m, 'jev_choice_p': cp, 'jev_pair_p': pp, 'input_sha256': ish})
            for kind, mid in r.extra_members:
                out.append({'event_id': e.eid, 'member_kind': kind, 'member_id': mid, 'role': 'member',
                            'match_method': 'structured_key', 'jev_choice_p': None, 'jev_pair_p': None, 'input_sha256': None})
    return out


# ---------------------------------------------------------------------------------------------------------------
# Loading the universe (a read-only extract: victims_list + duplicate-hidden incidents)
# ---------------------------------------------------------------------------------------------------------------
EXTRACT_SQL = {
    'victims': 'select victim_id,name,domain,country,sector,seen_date,event_date,actor,people_affected,data_bytes,'
               'data_bytes_stated,sources,kind,industry,post_title,posts from breach_core.victims_list',
    # v2: ALL records - private-only incidents and unlisted leak claims are in the event model too (never public from here)
    'incidents': 'select incident_id::text,org_id::text,event_date,first_public_date,possible_duplicate_of::text,suppressed '
                 'from breach_core.incidents',
    'orgs': 'select org_id::text,display_name,domain,country,sector,is_natural_person from breach_core.organizations',
    'isrc': 'select incident_id::text,source_id,doc_sha256 from breach_core.incident_sources',
    'docs': 'select doc_sha256,source_id,title,left(text,20000) text from breach_raw.documents',
    'claims': 'select claim_key,actor_group,victim_name,victim_domain,country,sector,first_seen_at::text first_seen_at,data_bytes_stated,'
              'incident_id::text from breach_core.leak_claims',
    'sents': 'select claim_key,sid,text from breach_core.victim_description_sentences where shown and not coalesce(boilerplate,false)',
    'qids': 'select domain,wikidata_qid from breach_core.org_sizes where wikidata_qid is not null',
    'media': 'select victim_id,title from breach_core.victim_media',
}


SENT = re.compile(r'(?<=[.!?])\s+(?=[A-Z"“])|(?<=[。！？])')


def press_evidence(name: str | None, docs, media_titles=()) -> tuple[tuple, tuple]:
    """(headlines, quotes) about THIS organisation: a headline or sentence counts only if it names the organisation (a
    distinctive core word); a roundup headline about other victims is left out. Quotes are verbatim sentences."""
    clean = clean_name(name)[0]
    toks = [t for t in core_tokens(clean) if len(t) >= 3 and t not in GENERIC] or list(core_tokens(clean))
    if not toks:
        return (), ()

    cjk = has_cjk(clean)

    def names_it(text):
        if cjk:
            return clean in (text or '')
        low = norm_name(text or '')
        words = set(low.split())
        return any(t in words for t in toks)

    heads, quotes = [], []
    for d in sorted(docs, key=lambda d: d.get('doc_sha256') or ''):
        t = d.get('title') or ''
        if t and names_it(t) and t not in heads:
            heads.append(t)
        for sent in SENT.split((d.get('text') or '')[:20000]):
            if len(quotes) >= 2:
                break
            if (12 if cjk else 30) <= len(sent) <= 400 and names_it(sent) and sent not in quotes:
                quotes.append(sent.strip())
    for t in media_titles:
        if names_it(t) and t not in heads:
            heads.append(t)
    return tuple(heads[:3]), tuple(quotes[:2])


def records_from_extract(X: dict, parents: list | None = None, extra_incidents=frozenset(), all_records=True) -> list:
    """X: rows per EXTRACT_SQL key (dicts). parents: Wikidata rows {qid, rel, label}. extra_incidents: incident ids
    that are neither listed nor duplicate-hidden but must be built anyway (dev pairs only)."""
    org = {o['org_id']: o for o in X['orgs']}
    inc = {i['incident_id']: i for i in X['incidents']}
    docs_of = collections.defaultdict(list)
    doc = {d['doc_sha256']: d for d in X['docs']}
    for s in X['isrc']:
        d = doc.get((s.get('doc_sha256') or '')[:64])
        if d and s['source_id'].startswith('news_'):
            docs_of[s['incident_id']].append(d)
    srcs = collections.defaultdict(set)
    for s in X['isrc']:
        srcs[s['incident_id']].add(s['source_id'])
    media = collections.defaultdict(list)
    for m in X.get('media') or ():
        if m.get('title'):
            media[m['victim_id']].append(m['title'])
    quotes = collections.defaultdict(list)
    for s in sorted(X.get('sents') or (), key=lambda s: (s['claim_key'], s['sid'])):
        if len(quotes[s['claim_key']]) < 2:
            quotes[s['claim_key']].append(s['text'])
    claim_inc = {c['claim_key']: c['incident_id'] for c in X['claims'] if c.get('incident_id')}
    rel = collections.defaultdict(set)
    for p in parents or ():
        toks = core_tokens(clean_name(p['label'])[0])
        if toks:
            rel[p['qid']].add(squash(toks))
    qid_of = {reg_domain(q['domain']): q['wikidata_qid'] for q in X.get('qids') or () if q.get('domain')}
    recs, seen = [], set()

    def related(dom):
        q = qid_of.get(dom) if dom else None
        return rel.get(q, ()) if q else ()

    for v in X['victims']:
        vid = v['victim_id']
        kind, mid = vid.split(':', 1)
        extra = []
        for p in v.get('posts') or ():
            pv = p.get('victim_id')
            if pv and pv != vid and pv.startswith('claim:'):
                extra.append(('claim', pv.split(':', 1)[1]))
        i = inc.get(mid) if kind == 'incident' else None
        dom = reg_domain(v.get('domain'))
        dd = docs_of.get(mid, ()) if kind == 'incident' else ()
        tt, qq = press_evidence(v['name'], dd, media.get(vid, ()))
        at = tuple(d['title'] for d in dd if d.get('title')) or None
        if kind == 'claim' and mid in claim_inc:
            link = 'incident:' + claim_inc[mid]
        else:
            link = None
        recs.append(make_rec(vid=vid, name=v['name'], domain=v.get('domain'), org_id=(i or {}).get('org_id'),
                             country=v.get('country'), industry=v.get('industry'), reported=v.get('seen_date'),
                             breach=v.get('event_date'), breach_prec='day' if v.get('event_date') else None,
                             actor=v.get('actor'), people=v.get('people_affected'),
                             gb=(v.get('data_bytes_stated') or v.get('data_bytes') or 0) / 1e9 or None,
                             sources=v.get('sources') or (), titles=tt,
                             quotes=quotes.get(mid, ()) if kind == 'claim' else qq, related=related(dom),
                             legacy_dup=('incident:' + i['possible_duplicate_of']) if i and i.get('possible_duplicate_of') else None,
                             link_to=link, listed=True, extra_members=tuple(extra), all_titles=at))
        seen.add(vid)
        seen.update('claim:' + m for _, m in extra)
    # incidents hidden as duplicates by v1 (0123/0144): re-resolved by v2, never deleted
    for i in X['incidents']:
        vid = 'incident:' + i['incident_id']
        if vid in seen or i.get('suppressed') or not (all_records or i.get('possible_duplicate_of')
                                                       or i['incident_id'] in extra_incidents):
            continue
        o = org.get(i['org_id']) or {}
        if o.get('is_natural_person'):
            continue
        dd = docs_of.get(i['incident_id'], ())
        tt, qq = press_evidence(o.get('display_name'), dd, media.get(vid, ()))
        at = tuple(d['title'] for d in dd if d.get('title')) or None
        recs.append(make_rec(vid=vid, name=o.get('display_name'), domain=o.get('domain'), org_id=i['org_id'],
                             country=o.get('country'), industry=None, reported=i.get('first_public_date'),
                             breach=i.get('event_date'), breach_prec='day' if i.get('event_date') else None,
                             sources=srcs.get(i['incident_id'], ()), titles=tt, quotes=qq,
                             related=related(reg_domain(o.get('domain'))),
                             legacy_dup=('incident:' + i['possible_duplicate_of']) if i.get('possible_duplicate_of') else None,
                             listed=False, all_titles=at))
        seen.add(vid)
    # v2: leak claims not on the list (hidden, linked or unresolved) are records too
    for c in X['claims'] if all_records else ():
        vid = 'claim:' + c['claim_key']
        if vid in seen:
            continue
        seen.add(vid)
        recs.append(make_rec(vid=vid, name=c.get('victim_name') or c['claim_key'].split('|')[1], domain=c.get('victim_domain'),
                             country=c.get('country'), reported=(c.get('first_seen_at') or '')[:10] or c['claim_key'].rsplit('|', 1)[-1],
                             actor=c.get('actor_group'), gb=(c.get('data_bytes_stated') or 0) / 1e9 or None,
                             sources=('ransomlook',), quotes=quotes.get(c['claim_key'], ()),
                             link_to=('incident:' + c['incident_id']) if c.get('incident_id') else None, listed=False))
    recs.sort(key=lambda r: r.vid)
    return recs


# ---------------------------------------------------------------------------------------------------------------
# Database writes (private tables only: r2_answers, r2_events, r2_event_members)
# ---------------------------------------------------------------------------------------------------------------
def load_cache(cur) -> dict:
    cur.execute('select answer_id, input_ref, input_sha256, answer, model_id, cost_usd from breach_core.r2_answers '
                'where engine = %s and engine_version = %s and prompt_sha256 = %s', ('jev', METHOD_VERSION, prompt_sha256()))
    return {ish: {'answer_id': aid, 'input_ref': ref, 'input_sha256': ish, 'answer': ans, 'model_id': mid, 'cost_usd': c}
            for aid, ref, ish, ans, mid, c in cur.fetchall()}


def _store_answers(cur, answers: list, run_id: str) -> tuple[int, dict]:
    """Insert-only answers (a duplicate input hash is skipped); returns (rows offered, input_sha256 -> answer_id)."""
    psh = prompt_sha256()
    rows = [('jev', METHOD_VERSION, a['model_id'], psh, a['input_ref'], a['input_sha256'], json.dumps(a['answer']),
             _p_of(a['answer']), a['cost_usd'], run_id) for a in answers]
    for i in range(0, len(rows), 500):
        cur.executemany('insert into breach_core.r2_answers (engine, engine_version, model_id, prompt_sha256, input_ref, '
                        'input_sha256, answer, p, cost_usd, run_id) values (%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s) '
                        'on conflict (engine_version, prompt_sha256, input_sha256) do nothing', rows[i:i + 500])
    cur.execute('select input_sha256, answer_id from breach_core.r2_answers where engine_version = %s and prompt_sha256 = %s',
                (METHOD_VERSION, psh))
    return len(rows), dict(cur.fetchall())


def write(conn, events: list, answers: list, run_id: str, method_version: str = METHOD_VERSION) -> dict:
    """One transaction: answers (insert-only), then this version's events and members replaced."""
    with conn.cursor() as cur:
        cur.execute(f"set local statement_timeout = '{STATEMENT_TIMEOUT}'")
        cur.execute("set local lock_timeout = '5s'")
        n_answers, aid = _store_answers(cur, answers, run_id)
        cur.execute('delete from breach_core.r2_event_members where method_version = %s', (method_version,))
        cur.execute('update breach_core.r2_events set possible_duplicate_of = null where method_version = %s', (method_version,))
        cur.execute('delete from breach_core.r2_events where method_version = %s', (method_version,))
        evrows = [event_row(e) for e in events]
        for i in range(0, len(evrows), 1000):
            cur.executemany('insert into breach_core.r2_events (event_id, method_version, org_id, org_name, campaign_id, '
                            'breach_date, breach_date_precision, reported_date) values (%s,%s,%s,%s,%s,%s,%s,%s)',
                            [(r['event_id'], method_version, r['org_id'], r['org_name'], r['campaign_id'], r['breach_date'],
                              r['breach_date_precision'], r['reported_date']) for r in evrows[i:i + 1000]])
        pd = [(r['possible_duplicate_of'], r['event_id']) for r in evrows if r['possible_duplicate_of']]
        for i in range(0, len(pd), 1000):
            cur.executemany('update breach_core.r2_events set possible_duplicate_of = %s where event_id = %s', pd[i:i + 1000])
        mrows = [m for e in events for m in member_rows(e)]
        seen, uniq = set(), []
        for m in mrows:
            k = (m['member_kind'], m['member_id'])
            if k not in seen:
                seen.add(k)
                uniq.append(m)
        for i in range(0, len(uniq), 1000):
            cur.executemany('insert into breach_core.r2_event_members (method_version, event_id, member_kind, member_id, role, '
                            'match_method, jev_choice_p, jev_pair_p, answer_id) values (%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                            [(method_version, m['event_id'], m['member_kind'], m['member_id'], m['role'], m['match_method'],
                              m['jev_choice_p'], m['jev_pair_p'], aid.get(m['input_sha256']) if m['input_sha256'] else None)
                             for m in uniq[i:i + 1000]])
    return {'events': len(evrows), 'members': len(uniq), 'answers_new': n_answers}


def _p_of(ans: dict):
    pk = (ans or {}).get('pick') or {}
    probs = pk.get('probabilities') or {}
    ch = pk.get('choice')
    return float(probs[ch]) if ch in probs else None


def report(events: list, stats, asker: Asker | None) -> dict:
    sizes = collections.Counter()
    methods = collections.Counter()
    for e in events:
        n = sum(len(u.recs) for u in e.units)
        sizes['1' if n == 1 else '2' if n == 2 else '3-5' if n <= 5 else '6-10' if n <= 10 else '11+'] += 1
        for vid, (m, *_rest) in e.method.items():
            methods[m] += 1
    return {'events': len(events), 'records': sum(len(u.recs) for e in events for u in e.units),
            'members_per_event': dict(sizes), 'members_by_method': dict(methods),
            'possible_duplicate': sum(1 for e in events if e.possible_dup),
            'follow_up': sum(1 for e in events for v in e.role.values() if v == 'follow_up'),
            'with_campaign': sum(1 for e in events if any(r.campaign for u in e.units for r in u.recs)),
            'stats': dict(sorted(stats.items())),
            'jev_calls': asker.calls if asker else 0, 'jev_cached': asker.cached if asker else 0,
            'jev_usd': round((asker.tokens if asker else 0) * PRICE_PER_MTOK / 1e6, 4)}


# ---------------------------------------------------------------------------------------------------------------
# Incremental mode (--new-only): place the records that have no membership yet, change nothing that is stored
# ---------------------------------------------------------------------------------------------------------------
# The full run (run / write) rebuilds a membership version from scratch and is a backfill. The hourly pipeline needs the
# opposite: every record ingested since gets an event, existing events and their members stay as they are. A unit
# (build_units) with no stored member is NEW; it is matched against the stored events exactly as the v2 method matches a
# unit against an event created earlier in the same pass (same blocking, cannot-link, tiers, Jev choice + pair + org
# questions, same taus), oldest first, then either merged or given an event of its own. A unit that already has a stored
# member keeps its event; its records that are not stored yet (a new post linked to an old incident, a new grouped post)
# are added to that event. Nothing is deleted, no event is rewritten; r2_events.breach_date / reported_date of an event
# that gained a member is refreshed from the same event_row() rule.

def _vids(u: Unit) -> set:
    return {r.vid for r in u.recs} | {f'{k}:{m}' for r in u.recs for k, m in r.extra_members}


def survivor(eid: str, meta: dict) -> str | None:
    """The event that carries eid's members: itself, its merge survivor (one level, 0185), or None when withdrawn."""
    e = meta.get(eid)
    if e is None or e['status'] == 'withdrawn':
        return None
    if e['status'] == 'merged':
        t = meta.get(e['merged_into'])
        return e['merged_into'] if t is not None and t['status'] == 'active' else None
    return eid


def place_units(units: list, members: dict, meta: dict, stats=None) -> tuple[dict, list]:
    """(placed: unit id -> stored event id, new: units with no stored member).
    members: vid -> {'event_id', ...} (stored, current membership version); meta: event id -> {'status', 'merged_into'}."""
    stats = stats if stats is not None else collections.Counter()
    placed, new = {}, []
    for u in units:
        found = [members[v]['event_id'] for v in sorted(_vids(u)) if v in members]
        if not found:
            new.append(u)
            continue
        eids = sorted({survivor(e, meta) for e in found} - {None})
        if not eids:
            stats['unit_event_withdrawn'] += 1          # its stored event is withdrawn: never re-placed here
            continue
        if len(eids) > 1:
            stats['unit_spans_events'] += 1             # stored membership disagrees with today's units: keep the first
        placed[u.uid] = eids[0]
    return placed, new


def stored_events(units: list, placed: dict, members: dict) -> dict:
    """Event objects for the stored events that have units, rebuilt from the stored membership (event id -> Event)."""
    out: dict = {}
    for u in units:
        eid = placed.get(u.uid)
        if eid is None:
            continue
        e = out.setdefault(eid, Event(eid, [], {}, {}))
        e.units.append(u)
        for r in u.recs:
            m = members.get(r.vid)
            if m is not None:
                e.method[r.vid] = (m['match_method'], m.get('jev_choice_p'), m.get('jev_pair_p'), None)
                e.role[r.vid] = m['role']
            else:                                   # a new record in a stored unit: joins by the key that links it
                e.method[r.vid] = (u.method.get(r.vid) if u.method.get(r.vid) in ('structured_key', 'deterministic')
                                   else 'structured_key', None, None, None)
                e.role[r.vid] = 'follow_up' if u.follow_up else 'member'
    return out


def run_new(recs: list, asker: Asker | None, members: dict, meta: dict, *, workers=8, stats=None, log=None) -> tuple[list, dict]:
    """(new events, stored events by id with the new units appended). A component whose Jev budget runs out is left
    unplaced (restored) and retried by the next run."""
    from zdc_breach.profile import BudgetExhausted
    stats = stats if stats is not None else collections.Counter()
    units = build_units(recs)
    unit_of = {r.vid: u.uid for u in units for r in u.recs}
    mark_busy(units)
    edges = block(recs, unit_of)
    placed, new = place_units(units, members, meta, stats)
    new_ids = {u.uid for u in new}
    stored = stored_events(units, placed, members)
    stats['units'] += len(units)
    stats['units_new'] += len(new)
    stats['records_new'] += sum(len(u.recs) for u in new)
    out, lock = [], threading.Lock()
    todo = [c for c in components(units, edges) if any(u.uid in new_ids for u in c)]
    stats['components_todo'] += len(todo)

    def one(c):
        ids = {u.uid for u in c}
        pre = {u.uid: stored[placed[u.uid]] for u in c if u.uid in placed}
        snap = {id(e): (e, len(e.units), dict(e.method), dict(e.role)) for e in pre.values()}
        st, lg = collections.Counter(), ([] if log is not None else None)
        try:
            evs = run_component([u for u in c if u.uid in new_ids], {k: v for k, v in edges.items() if k[0] in ids},
                                asker, stats=st, log=lg, preplaced=pre)
        except BudgetExhausted:
            for e, n, meth, role in snap.values():       # undo this component's merges: nothing of it is written
                del e.units[n:]
                e.method.clear()
                e.method.update(meth)
                e.role.clear()
                e.role.update(role)
            with lock:
                stats['components_skipped_budget'] += 1
            return
        with lock:
            stats.update(st)
            out.extend(evs)
            if log is not None:
                log.extend(lg)

    # components that touch a stored event run one after another (two components may share a stored event); the rest
    # are independent and may run in parallel
    seq = [c for c in todo if len(c) == 1 or any(u.uid in placed for u in c)]
    par = [c for c in todo if not (len(c) == 1 or any(u.uid in placed for u in c))]
    for c in seq:
        one(c)
    if workers <= 1:
        for c in par:
            one(c)
    else:
        with cf.ThreadPoolExecutor(workers) as ex:
            for f in [ex.submit(one, c) for c in par]:
                f.result()
    out.sort(key=lambda e: e.eid)
    return out, stored


def new_member_rows(events: list, members: dict) -> list:
    """Member rows (of `events`, new and stored) that are not stored yet; one row per (kind, id)."""
    seen, out = set(), []
    for e in events:
        for m in member_rows(e):
            k = (m['member_kind'], m['member_id'])
            if k in seen or f"{k[0]}:{k[1]}" in members:
                continue
            seen.add(k)
            out.append(m)
    return out


def _decimal_free(row: tuple, cols: list) -> dict:
    import decimal
    return {c: (float(v) if isinstance(v, decimal.Decimal) else v) for c, v in zip(cols, row)}


def fetch_extract(conn, page: int = 1000) -> dict:
    """Live read-only extract of the matcher's universe (EXTRACT_SQL keys). Each statement runs under 60 s."""
    X = {}
    with conn.transaction(), conn.cursor() as cur:
        cur.execute('set transaction read only')
        cur.execute(f"set local statement_timeout = '{STATEMENT_TIMEOUT}'")
        for k, q in EXTRACT_SQL.items():
            if k == 'docs':
                continue
            cur.execute(q)
            cols = [d.name for d in cur.description]
            X[k] = [_decimal_free(r, cols) for r in cur.fetchall()]
        docs, last = [], ''
        while True:                                     # keyset pages: the document table is the only large one
            cur.execute('select doc_sha256,source_id,title,left(text,20000) text from breach_raw.documents '
                        'where doc_sha256 > %s order by doc_sha256 limit %s', (last, page))
            rows = cur.fetchall()
            docs += [{'doc_sha256': a, 'source_id': b, 'title': c, 'text': d} for a, b, c, d in rows]
            if len(rows) < page:
                break
            last = rows[-1][0]
        X['docs'] = docs
    return X


def fetch_membership(conn) -> tuple[str, dict, dict]:
    """(membership version, members: vid -> row, meta: event id -> {status, merged_into}) of the current version."""
    with conn.transaction(), conn.cursor() as cur:
        cur.execute('set transaction read only')
        cur.execute(f"set local statement_timeout = '{STATEMENT_TIMEOUT}'")
        cur.execute("select value from breach_core.breach_settings where key = 'r2_membership_version'")
        ver = (cur.fetchone() or [None])[0]
        cur.execute('select event_id::text, status, merged_into::text from breach_core.r2_events where method_version = %s', (ver,))
        meta = {e: {'status': s, 'merged_into': mi} for e, s, mi in cur.fetchall()}
        cur.execute("select member_kind, member_id, event_id::text, role, match_method, jev_choice_p, jev_pair_p "
                    "from breach_core.r2_event_members where method_version = %s and member_kind in ('claim', 'incident')", (ver,))
        members = {f'{k}:{i}': {'event_id': e, 'role': r, 'match_method': mm, 'jev_choice_p': cp, 'jev_pair_p': pp}
                   for k, i, e, r, mm, cp, pp in cur.fetchall()}
    return ver, members, meta


def write_new(conn, new_events: list, stored: dict, members: dict, answers: list, run_id: str, ver: str) -> dict:
    """One transaction, additive only: answers (insert-only), the new events, the missing member rows; the dates of a
    stored event that gained a member are refreshed. Re-running it writes nothing."""
    mrows = new_member_rows(list(stored.values()) + new_events, members)
    gained = {m['event_id'] for m in mrows}
    new_ids = {e.eid for e in new_events}
    with conn.transaction(), conn.cursor() as cur:
        cur.execute(f"set local statement_timeout = '{STATEMENT_TIMEOUT}'")
        cur.execute("set local lock_timeout = '5s'")
        n_answers, aid = _store_answers(cur, answers, run_id)
        evrows = [event_row(e) for e in new_events]
        for i in range(0, len(evrows), 500):
            cur.executemany('insert into breach_core.r2_events (event_id, method_version, org_id, org_name, campaign_id, '
                            'breach_date, breach_date_precision, reported_date) values (%s,%s,%s,%s,%s,%s,%s,%s) '
                            'on conflict (event_id) do nothing',
                            [(r['event_id'], ver, r['org_id'], r['org_name'], r['campaign_id'], r['breach_date'],
                              r['breach_date_precision'], r['reported_date']) for r in evrows[i:i + 500]])
        pd = [(r['possible_duplicate_of'], r['event_id']) for r in evrows if r['possible_duplicate_of']]
        if pd:
            cur.executemany('update breach_core.r2_events set possible_duplicate_of = %s where event_id = %s', pd)
        for i in range(0, len(mrows), 500):
            cur.executemany('insert into breach_core.r2_event_members (method_version, event_id, member_kind, member_id, role, '
                            'match_method, jev_choice_p, jev_pair_p, answer_id) values (%s,%s,%s,%s,%s,%s,%s,%s,%s) '
                            'on conflict (method_version, member_kind, member_id) do nothing',
                            [(ver, m['event_id'], m['member_kind'], m['member_id'], m['role'], m['match_method'],
                              m['jev_choice_p'], m['jev_pair_p'], aid.get(m['input_sha256']) if m['input_sha256'] else None)
                             for m in mrows[i:i + 500]])
        refreshed = 0
        for e in stored.values():
            if e.eid in gained and e.eid not in new_ids:
                r = event_row(e)
                cur.execute('update breach_core.r2_events set breach_date = %s, breach_date_precision = %s, reported_date = %s, '
                            'updated_at = now() where event_id = %s and (breach_date, breach_date_precision, reported_date) '
                            'is distinct from (%s, %s, %s)',
                            (r['breach_date'], r['breach_date_precision'], r['reported_date'], r['event_id'],
                             r['breach_date'], r['breach_date_precision'], r['reported_date']))
                refreshed += cur.rowcount
    return {'events_new': len(evrows), 'members_new': len(mrows), 'events_refreshed': refreshed, 'answers_new': n_answers}


def run_new_only(conn, *, max_usd: float, workers: int = 8, write_db: bool = True, run_id: str = 'r2-events-new',
                 parents: list | None = None, jev=None) -> dict:
    """The whole incremental step against the live DB; returns a counts-only report."""
    from zdc_breach.profile import Budget, Jev
    ver, members, meta = fetch_membership(conn)
    if ver != METHOD_VERSION:
        raise SystemExit(f'membership version is {ver!r}, this matcher writes {METHOD_VERSION!r}: new-only refuses')
    recs = records_from_extract(fetch_extract(conn), parents)
    with conn.transaction(), conn.cursor() as cur:
        cur.execute(f"set local statement_timeout = '{STATEMENT_TIMEOUT}'")
        cache = load_cache(cur)
    jev = jev or Jev(Budget(max_usd))
    asker = Asker(jev, cache)
    stats = collections.Counter()
    new_events, stored = run_new(recs, asker, members, meta, workers=workers, stats=stats)
    rep = {'method_version': ver, 'records': len(recs), 'stored_members': len(members), 'stored_events': len(stored),
           'new_events': len(new_events), 'stats': dict(sorted(stats.items())), 'jev_calls': asker.calls,
           'jev_cached': asker.cached, 'jev_usd': round(asker.tokens * PRICE_PER_MTOK / 1e6, 4), 'written': False}
    rep['members_to_add'] = len(new_member_rows(list(stored.values()) + new_events, members))
    if write_db:
        rep['write'] = write_new(conn, new_events, stored, members, asker.new, run_id, ver)
        rep['written'] = True
    return rep


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog='zdc_breach.r2_events')
    sub = ap.add_subparsers(dest='cmd', required=True)
    r = sub.add_parser('run')
    r.add_argument('--extract', help='JSON extract (EXTRACT_SQL keys); required unless --new-only')
    r.add_argument('--new-only', action='store_true',
                   help='incremental: place only the records with no stored membership (live DB read), additive write; '
                        'with --write it writes, without it a dry run')
    r.add_argument('--parents', help='Wikidata parent rows JSON')
    r.add_argument('--max-usd', type=float, default=10.0)
    r.add_argument('--limit-components', type=int, default=0, help='pilot: only the first N multi-unit components')
    r.add_argument('--workers', type=int, default=8)
    r.add_argument('--write', action='store_true')
    r.add_argument('--run-id', default='r2-events')
    r.add_argument('--out', help='write the report JSON here')
    a = ap.parse_args(argv)
    import os
    import psycopg
    from zdc_breach.profile import Budget, Jev
    if a.new_only:
        parents = json.load(open(a.parents)) if a.parents else None
        conn = psycopg.connect(os.environ['DATABASE_URL'], connect_timeout=20)
        rep = run_new_only(conn, max_usd=a.max_usd, workers=a.workers, write_db=a.write, run_id=a.run_id, parents=parents)
        if a.out:
            json.dump(rep, open(a.out, 'w'), indent=1)
        print(json.dumps(rep))
        return 0
    if not a.extract:
        ap.error('--extract is required unless --new-only')
    X = json.load(open(a.extract))
    parents = json.load(open(a.parents)) if a.parents else None
    recs = records_from_extract(X, parents)
    conn = psycopg.connect(os.environ['DATABASE_URL'], connect_timeout=20)
    with conn.cursor() as cur:
        cur.execute(f"set statement_timeout = '{STATEMENT_TIMEOUT}'")
        cache = load_cache(cur)
    conn.rollback()
    asker = Asker(Jev(Budget(a.max_usd)), cache)
    only = None
    if a.limit_components:
        units = build_units(recs)
        unit_of = {r.vid: u.uid for u in units for r in u.recs}
        comps = [c for c in components(units, block(recs, unit_of)) if len(c) > 1][:a.limit_components]
        only = {u.uid for c in comps for u in c}
    stats = collections.Counter()
    events = run(recs, asker, workers=a.workers, stats=stats, only_units=only)
    rep = report(events, stats, asker)
    if a.write:
        rep['write'] = write(conn, events, asker.new, a.run_id)
        conn.commit()
    if a.out:
        json.dump(rep, open(a.out, 'w'), indent=1)
    print(json.dumps({k: v for k, v in rep.items() if k != 'stats'}, indent=1))
    return 0


if __name__ == '__main__':
    sys.exit(main())
