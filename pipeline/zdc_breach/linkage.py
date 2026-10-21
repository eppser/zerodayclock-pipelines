"""Record linkage for breach incidents: which rows of breach_core.incidents describe one breach.

DESIGN (advisor, 2026-10-19; ADR docs/decisions/0008-breach-record-linkage.md). NOT ACTIVE.

- Pairs of INCIDENTS are linked. Organisations are never merged and incidents never rewritten;
  linkage is a layer on top (incident_links, incident_clusters, migration 0133).
- Everything runs here, in memory, on one read of organisations, incidents, incident_sources and
  the date and count claims. NO SIMILARITY FUNCTION RUNS IN SQL - a pg_trgm join took the shared
  database (staging and production) down on 2026-10-19.
- Blocking is a union of passes B1-B5 (the pass that found each pair is kept). A block that would
  produce more than BLOCK_CAP pairs is dropped and logged ("county", "health").
- Each comparison level carries a Fellegi-Sunter log2 Bayes factor log2(m/u). u comes from
  ~1M random incident pairs; m comes from labelled pairs. Until labels exist, a HAND-SET m
  (PROVISIONAL_M) is used for one purpose only: to stratify the labelling sample. It never sets a
  threshold. EM is a diagnostic: its match class drifts to "same organisation", not "same breach".
- Clustering is constrained, never a transitive closure: auto edges in descending score; two
  components merge only if no cannot-link pair spans them and every cross pair scores at least the
  review threshold (complete linkage at review level); a row at review level against two clusters
  is ambiguous and goes to review; no auto cluster grows past MAX_AUTO_CLUSTER.

DATE SEMANTICS. An SEC 8-K's period_ending is the date of report, not the breach (design s6), so
an incident whose only source is sec_8k has NO event date here. Everything else uses
incidents.event_date as stored; its meaning differs by source, which is why the event-date levels
are learnt per source-pair class.

link_key (design s2) is for linkage only: norm_name minus geographic / structural qualifiers.
Organisation identity keeps ADR 0006's normaliser.
"""

from __future__ import annotations

import hashlib
import json
import math
import random
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import date
from functools import lru_cache
from pathlib import Path

from .normalize import has_cjk, norm_name

METHOD_VERSION = "breach-linkage-v2"

# ---- parameters ---------------------------------------------------------------------------------
BLOCK_CAP = 300            # a block producing more pairs than this is dropped and logged
RARE_DF = 50               # a token in at most this many organisations is rare (B3, "single" level)
DISTINCTIVE_SHARE = 0.01   # a token in at most 1% of organisations is distinctive (conflict level).
                           # Measured 2026-10-19: "life" is in 86 of 9,833 (distinctive, not rare);
                           # "hospital" 160, "medical" 302, "county" 234 are neither.
PUBLIC_WINDOW = 365        # days, B2 / B4 / B5
B3_EVENT_WINDOW = 7        # days, B3 (and B2's second clock)
LEGACY_EVENT_WINDOW = 30   # days, B6 = resolve.EVENT_WINDOW
LEGACY_PUBLIC_WINDOW = 90  # days, B6 = resolve.PUBLIC_WINDOW
CANNOT_LINK_EVENT_DAYS = 180
ANOMALY_FLOOR = date(1990, 1, 1).toordinal()
MAX_AUTO_CLUSTER = 10
# PROVISIONAL: decide nothing but the sampling strata. Fixed from dev labels in step 4.
PROVISIONAL_AUTO = 0.95
REVIEW = 0.5
STORE_MIN_P = 0.01
U_PAIRS = 1_000_000
U_SEED = 20261019
SOFT_TFIDF_MIN = 0.9
JW_MIN = 0.9
CONTAIN_MASS = 0.6
TF_ADJ_CLAMP = (-6.0, 4.0)
# Design s2: single-token names and dateless press rows are capped at review. Both are
# parameters because the design's expected Allianz outcome allows a dateless press row to auto.
CAP_SINGLE_TOKEN = True
CAP_DATELESS_PRESS = True
# Step-4 ruling (advisor, DESIGN s7 b1-b4, 2026-10-19). Measured on dev, derived there only.
# b2: a dateless-press pair may auto-link only when published within 45 days AND the name level is
#     one of these; otherwise it is capped at review (dev: every non-match at or above t was dateless,
#     almost all > 45 days apart - Red Hat, Zscaler, UPenn, MSG, OB-GYN).
DATELESS_PUBLIC = ("p14", "p45")
DATELESS_NAMES = ("exact", "linkkey", "contain", "soft")
# b3: a single-token pair may auto-link only with event delta <= 14 d, an equal/consistent domain, or
#     under the b2 rule for a dateless pair.
SINGLE_EVENT = ("d0", "d3", "d14")
SINGLE_DOMAIN = ("equal", "consistent")
# b1: incidents.possible_duplicate_of is an accepted edge source (dev 119/120 outside the card
#     issuers); the final edge set is legacy edges plus model auto edges, minus cannot-links.
LEGACY_EDGES = True
# s9: a legacy edge is accepted only at or above this model posterior (review level), never across a
#     cannot-link. Dev: 147/151 -> 142/144 (0.986), losing 5 of 147 true legacy links (3.4%). None = off.
LEGACY_MIN_P = 0.5
# s9 (Instructure, 2026-05-07: "the same threat actor gained additional access through a second Canvas
#     vulnerability"): a record whose headline states a repeat event never auto-links to a record
#     without one unless both event dates are stated and within REPEAT_EVENT_DAYS; the pair goes to
#     review. Which earlier/later event a dateless press row describes cannot be read from the record,
#     so the rule does not try to order them. Titles come from the source documents.
REPEAT_EVENT = True
REPEAT_EVENT_DAYS = 3
# v2 (advisor s15, R11): title evidence, data-derived; each rule is a switch, measured separately.
# ACTOR_CONFLICT: two rows naming different threat actors (titles, accepted actor claims, linked leak
#   claims), resolved through breach_core.actor_aliases, are capped at REVIEW (s16: a poor discriminator,
#   6 of 11 dev firings were true matches, so never a cannot-link) - Cisco 2025 ShinyHunters vs 2022
#   Yanluowang. An alias counts only if it is never a token of an organisation's name and
#   appears in at most ACTOR_TITLE_SHARE of titles ("data", "global", "trinity" are not actor evidence).
# YEAR_CONFLICT: a title stating a year Y more than a year before the other row's publication, and not
#   the other row's stated event year, blocks auto-linking ("in 2023 compromised Epstein files").
# REG_BRIDGE_GUARD: two regulator rows of different organisations may share a cluster only if their own
#   pair is not cannot-link and their names do not differ by a distinctive token on one side only
#   (Cedar Valley Services vs Cedar Valley Hospice: "services" is a link_key qualifier and generic, so the
#   conflict level - which needs a distinctive token on BOTH sides - cannot fire; the pair is containment).
ACTOR_CONFLICT = True
ACTOR_TITLE_SHARE = 0.01
YEAR_CONFLICT = True
YEAR_TITLE = re.compile(r"(?<![0-9])(199[0-9]|20[0-3][0-9])(?![0-9])")
REG_BRIDGE_GUARD = True
# QUALIFIER_CONFLICT (s16(2)): containment where the shorter name lost a generic qualifier and the longer
# name adds a distinctive token is the conflict level (a cannot-link), not contain.
QUALIFIER_CONFLICT = True
# TITLE_CAP_GUARD (s16(1) "never auto" at cluster level): a pair capped by ACTOR_CONFLICT or YEAR_CONFLICT
# stays a review item (not a cannot-link) and its two rows never share a cluster through other members.
TITLE_CAP_GUARD = True
# JA_PRESS_CAP (s17, R13): a press pair in which either row is Japanese-language (a Han/kana name, or a
# news_jp_* source) is held at review, never auto; the title-cap guard keeps its rows out of one cluster.
# Doctrine, not tuning: ADR 0007 keeps Japanese machine output private until its own gold set passes, and
# dev holds ~30 Japanese pairs (10 of the 19 wrong implied pairs on dev v3 were Japanese press pairs).
JA_PRESS_CAP = True
TITLE_CAPS = ("actor_conflict", "year_conflict", "ja_press")
# "both": the guard applies to two regulator rows (s15 as written); "either": to any pair with a regulator
# row (a press row naming the shorter organisation against the other organisation's filing) - measured
# separately in R11, not the default.
REG_GUARD_SCOPE = "both"
# Narrowed once (advisor s10 a): explicit re-compromise phrasing only. A hack/breach/attack/compromise
# verb followed within three words by "again" (no count, lawsuit or update word in between); "second" or
# "another" + breach/attack/intrusion/hack/compromise; re-breached / re-compromised / re-hacked; the
# Japanese "again / a second time" + attack/unauthorised access/intrusion/hacking.
REPEAT_TITLE = re.compile(
    r"\b(?:hack|breach|attack|compromis)\w*(?:\W+(?!count\b|counts\b|sued\b|suit\b|lawsuit\b|update\w*\b)\w+){0,3}?\W+again\b"
    r"|\b(?:second|another)\s+(?:(?:data|security)\s+)?(?:cyber\s*-?\s*)?(?:breach|attack|intrusion|hack|compromise)"
    r"|\bre-?(?:breach|compromis|hack)\w*"
    r"|(?:再び|再度|2度目|二度目)の?(?:サイバー)?(?:攻撃|不正アクセス|侵入|ハッキング)", re.I)
# b1: card-issuer notices concern merchant breaches they do not name; two of them never link (dev 0/4).
CARD_ISSUERS = ("american express", "discover financial")

# Removed from norm_name to form link_key, longest phrase first, as whole tokens. "u s" / "u s a"
# are what norm_name makes of "U.S." / "U.S.A." ("Allianz Global Risks U.S. Insurance").
QUALIFIERS = ("of north america", "of america", "north america", "u s a", "u s", "usa", "us",
              "holdings", "holding", "group", "services")

REG_SOURCES = frozenset({"wa_ag", "de_ag", "ca_ag", "hhs_ocr"})
CLASS_RANK = ("reg", "sec", "hibp", "press", "other")
DATE_CLASSES = ("reg_reg", "reg_hibp", "reg_press", "press_press", "sec_any", "other")

BAND_EDGES = (0.0, 0.01, 0.05, 0.2, 0.4, 0.5, 0.6, 0.8, 0.95, 0.99)

LEVELS = {
    "name": ("exact", "alias", "linkkey", "contain", "conflict", "soft", "single", "none"),
    "domain": ("equal", "consistent", "missing", "different"),
    "event": ("d0", "d3", "d14", "d45", "d120", "gt120", "md_match_year_off", "missing"),
    "public": ("p14", "p45", "p120", "p365", "gt365"),
    "impossible": ("impossible", "ok", "na"),
    "source": ("diff_reg", "same_reg", "other"),
    "country": ("agree", "missing", "conflict"),
    "sector": ("agree", "missing", "differ"),
    "count": ("same", "other"),
}
FEATURES = tuple(LEVELS)

# PROVISIONAL, HAND-SET (2026-10-19). Used ONLY to stratify the labelling sample. Replaced by m
# estimated from labelled dev pairs before any threshold is chosen.
PROVISIONAL_M = {
    "name": {"exact": .50, "alias": .02, "linkkey": .10, "contain": .14, "conflict": .005,
             "soft": .06, "single": .10, "none": .075},
    # "different" is a cannot-link; its m is set far below its u (0.008) so the BF is a strong negative.
    "domain": {"equal": .12, "consistent": .04, "missing": .8395, "different": .0005},
    "event:reg_reg": {"d0": .55, "d3": .10, "d14": .06, "d45": .05, "d120": .03, "gt120": .01, "md_match_year_off": .01, "missing": .19},
    "event:reg_hibp": {"d0": .25, "d3": .10, "d14": .10, "d45": .10, "d120": .10, "gt120": .10, "md_match_year_off": .01, "missing": .24},
    "event:reg_press": {"d0": .25, "d3": .10, "d14": .10, "d45": .10, "d120": .06, "gt120": .02, "md_match_year_off": .01, "missing": .36},
    "event:press_press": {"d0": .25, "d3": .10, "d14": .07, "d45": .05, "d120": .03, "gt120": .02, "md_match_year_off": .01, "missing": .47},
    "event:sec_any": {"d0": .05, "d3": .05, "d14": .05, "d45": .05, "d120": .05, "gt120": .02, "md_match_year_off": .01, "missing": .72},
    "event:other": {"d0": .20, "d3": .10, "d14": .10, "d45": .08, "d120": .06, "gt120": .04, "md_match_year_off": .01, "missing": .41},
    "public": {"p14": .45, "p45": .25, "p120": .17, "p365": .11, "gt365": .02},
    "impossible": {"impossible": .02, "ok": .58, "na": .40},
    "source": {"diff_reg": .20, "same_reg": .10, "other": .70},
    "country": {"agree": .55, "missing": .43, "conflict": .02},
    "sector": {"agree": .30, "missing": .55, "differ": .15},
    "count": {"same": .08, "other": .92},
}
# PROVISIONAL prior: expected true duplicate pairs among all C(N, 2) incident pairs.
PROVISIONAL_EXPECTED_MATCHES = 2500


# ---- classes ------------------------------------------------------------------------------------
def source_class(source_id: str) -> str:
    if source_id in REG_SOURCES:
        return "reg"
    if source_id == "sec_8k":
        return "sec"
    if source_id == "hibp":
        return "hibp"
    if source_id.startswith("news_") or source_id == "gdelt":
        return "press"
    return "other"


def incident_class(sources) -> str:
    return min((source_class(s) for s in sources), key=CLASS_RANK.index, default="other")


def pair_class(ca: str, cb: str) -> str:
    if "sec" in (ca, cb):
        return "sec_any"
    a, b = sorted((ca, cb), key=CLASS_RANK.index)
    return f"{a}_{b}"


def date_class(pc: str) -> str:
    return pc if pc in DATE_CLASSES else "other"


# ---- names --------------------------------------------------------------------------------------
def link_key(nn: str) -> str:
    """norm_name minus QUALIFIERS (whole tokens). Falls back to norm_name when nothing is left."""
    toks = nn.split()
    if not toks:
        return ""
    quals = [q.split() for q in QUALIFIERS]
    out, i = [], 0
    while i < len(toks):
        for q in quals:
            if toks[i:i + len(q)] == q:
                i += len(q)
                break
        else:
            out.append(toks[i])
            i += 1
    return " ".join(out) if out else nn


def domain_label(domain: str | None) -> str | None:
    """The registrant label of a domain: acme.com -> acme, acme.co.uk -> acme. Only for the B5
    consistency test; domains themselves are always compared whole (ADR 0006)."""
    if not domain:
        return None
    parts = domain.split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in ("co", "com", "org", "net", "ac", "gov", "edu", "ne", "or", "go"):
        lab = parts[-3]
    else:
        lab = parts[-2] if len(parts) >= 2 else parts[0]
    lab = lab.replace("-", "")
    return lab if len(lab) >= 4 else None


SECTOR_MAP = (("health", "health"), ("medical", "health"), ("hospital", "health"), ("clinic", "health"),
              ("pharm", "health"), ("dental", "health"), ("insur", "finance"), ("financ", "finance"),
              ("bank", "finance"), ("credit", "finance"), ("invest", "finance"), ("educ", "education"),
              ("school", "education"), ("universit", "education"), ("government", "government"),
              ("public", "government"), ("retail", "retail"), ("tech", "technology"),
              ("software", "technology"), ("manufactur", "manufacturing"), ("non-profit", "nonprofit"),
              ("nonprofit", "nonprofit"), ("legal", "legal"), ("law", "legal"))


def sector_norm(s: str | None) -> str | None:
    if not s:
        return None
    s = s.lower()
    for k, v in SECTOR_MAP:
        if k in s:
            return v
    return s.split(":")[0].split()[0] if s.split() else None


@lru_cache(maxsize=1 << 20)
def jaro_winkler(a: str, b: str) -> float:
    if a == b:
        return 1.0
    la, lb = len(a), len(b)
    if not la or not lb:
        return 0.0
    rng = max(la, lb) // 2 - 1
    am, bm = [False] * la, [False] * lb
    m = 0
    for i, ch in enumerate(a):
        for j in range(max(0, i - rng), min(lb, i + rng + 1)):
            if not bm[j] and b[j] == ch:
                am[i] = bm[j] = True
                m += 1
                break
    if not m:
        return 0.0
    t, k = 0, 0
    for i in range(la):
        if am[i]:
            while not bm[k]:
                k += 1
            if a[i] != b[k]:
                t += 1
            k += 1
    j = (m / la + m / lb + (m - t / 2) / m) / 3
    p = 0
    for x, y in zip(a[:4], b[:4]):
        if x != y:
            break
        p += 1
    return j + p * 0.1 * (1 - j)


def _fuzzy_ok(t: str) -> bool:
    # A Japanese name is one token: トヨタ and トヨタ紡織 are different names, never fuzzy kin.
    return len(t) >= 4 and t.isascii()


def token_sim(a: str, b: str) -> float:
    """1 for equal tokens; Jaro-Winkler >= JW_MIN for two ASCII tokens of >= 4 characters that
    share their first character; otherwise 0."""
    if a == b:
        return 1.0
    if not (_fuzzy_ok(a) and _fuzzy_ok(b)) or a[0] != b[0]:
        return 0.0
    la, lb = len(a), len(b)
    if (min(la, lb) / la + min(la, lb) / lb + 1) / 3 < 0.83:   # Jaro upper bound too low
        return 0.0
    s = jaro_winkler(a, b) if a < b else jaro_winkler(b, a)
    return s if s >= JW_MIN else 0.0


class Idf:
    """Document frequency of link_key tokens over ORGANISATIONS (an organisation with many
    filings counts once), plus incident-level token frequency for the exact-name TF adjustment."""

    def __init__(self, df: dict, n_orgs: int, tf: dict | None = None, n_incidents: int = 0):
        self.df, self.n = df, max(n_orgs, 1)
        self.tf, self.n_inc = tf or {}, max(n_incidents, 1)

    def idf(self, t: str) -> float:
        return math.log(self.n / self.df.get(t, 1)) + 1e-9

    def rare(self, t: str) -> bool:
        return self.df.get(t, 1) <= RARE_DF

    def distinctive(self, t: str) -> bool:
        return self.df.get(t, 1) <= max(1.0, DISTINCTIVE_SHARE * self.n)

    def rarest(self, toks) -> str | None:
        return min(toks, key=lambda t: (self.df.get(t, 1), t)) if toks else None

    def token_freq(self, t: str) -> float:
        return max(self.tf.get(t, 1), 1) / self.n_inc


def soft_tfidf(ta, tb, idf: Idf) -> float:
    wa = {t: idf.idf(t) for t in ta}
    wb = {t: idf.idf(t) for t in tb}
    na = math.sqrt(sum(w * w for w in wa.values()))
    nb = math.sqrt(sum(w * w for w in wb.values()))
    if not na or not nb:
        return 0.0
    s = 0.0
    for t, w in wa.items():
        best, bt = 0.0, None
        for u in tb:
            x = token_sim(t, u)
            if x > best:
                best, bt = x, u
        if bt is not None:
            s += (w / na) * (wb[bt] / nb) * best
    return s


# Abbreviations that name the same word (advisor ruling 2026-10-19). A token "lacked" by the other
# side through one of these is not distinctive evidence of a different organisation.
ABBREVIATIONS = {"st": "saint", "mt": "mount", "ctr": "center", "centre": "center", "hosp": "hospital",
                 "med": "medical", "intl": "international", "natl": "national", "assn": "association",
                 "svcs": "services", "dept": "department", "univ": "university"}


def _canon(t: str) -> str:
    return ABBREVIATIONS.get(t, t)


def _kin(t: str, u: str) -> bool:
    """Same word for the conflict test: equal, fuzzy (token_sim), the same abbreviation, or an
    ASCII prefix of at least 3 characters ("mass" / "massachusetts")."""
    if t == u or _canon(t) == _canon(u) or token_sim(t, u):
        return True
    short, long_ = (t, u) if len(t) <= len(u) else (u, t)
    return short.isascii() and long_.isascii() and len(short) >= 3 and long_.startswith(short)


def _acronym_spans(toks) -> dict:
    """{initials: tokens} for every run of >= 2 consecutive ASCII tokens: "hshs" -> the four
    tokens of "hospital sisters health system"."""
    out: dict = {}
    for i in range(len(toks)):
        for j in range(i + 2, len(toks) + 1):
            span = toks[i:j]
            if not all(x.isascii() and x for x in span):
                break
            out.setdefault("".join(x[0] for x in span), set()).update(span)
    return out


def _lacks(t: str, own, other, idf: "Idf") -> bool:
    """True when token t (of `own`) has no counterpart in `other`: no kin word, t is not an
    acronym of consecutive tokens of `other`, and t is not part of a run of `own` whose initials
    are a token of `other`. An acronym counts only if it is itself distinctive: "of florida" has
    the initials "of", which must not cover "florida". (Callers pass distinctive t only.)"""
    if any(_kin(t, u) for u in other):
        return False
    if t in _acronym_spans(tuple(other)):
        return False
    spans = _acronym_spans(tuple(own))
    return not any(t in spans.get(u, ()) and idf.distinctive(u) for u in other)


def name_level(a: "Rec", b: "Rec", idf: Idf) -> str:
    if a.nn and a.nn == b.nn:
        return "exact"
    if (a.aliases and (b.nn in a.aliases or b.lk in a.aliases or set(a.aliases) & set(b.aliases))) or \
       (b.aliases and (a.nn in b.aliases or a.lk in b.aliases)):
        return "alias"
    if a.lk and a.lk == b.lk:
        return "linkkey"
    ta, tb = set(a.toks), set(b.toks)
    if not ta or not tb:
        return "none"
    common = ta & tb
    small, large = (ta, tb) if len(ta) <= len(tb) else (tb, ta)
    if small <= large and len(small) >= 2:
        ms = sum(idf.idf(t) for t in small)
        ml = sum(idf.idf(t) for t in large)
        if ml and ms / ml >= CONTAIN_MASS:
            # s16(2): the shorter name reached its link_key only by losing a generic qualifier ("Cedar
            # Valley Services" -> "cedar valley") while the longer one adds a distinctive token
            # ("hospice"): an entity-type difference, not a containment.
            srec, lrec = (a, b) if small is ta else (b, a)
            if QUALIFIER_CONFLICT and srec.nn != srec.lk and any(
                    idf.distinctive(t) and _lacks(t, lrec.toks, srec.toks, idf) for t in large - small):
                return "conflict"
            return "contain"
    if common:
        a_only = [t for t in ta - tb if idf.distinctive(t) and _lacks(t, a.toks, b.toks, idf)]
        b_only = [t for t in tb - ta if idf.distinctive(t) and _lacks(t, b.toks, a.toks, idf)]
        if a_only and b_only:
            return "conflict"
    if soft_tfidf(ta, tb, idf) >= SOFT_TFIDF_MIN:
        return "soft"
    if (len(small) == 1 and small <= large) or any(idf.rare(t) for t in common):
        return "single"
    return "none"


# ---- records ------------------------------------------------------------------------------------
@dataclass(slots=True)
class Rec:
    iid: str
    org_id: str
    name: str
    nn: str
    lk: str
    toks: tuple
    domain: str | None
    dlabel: str | None
    cik: str | None
    country: str | None
    sector: str | None
    aliases: tuple
    sources: frozenset
    cls: str
    ev: int | None          # effective event date (ordinal); None for SEC-only incidents
    ev_raw: int | None
    pub: int
    persons: frozenset      # exact persons counts >= 1,000
    cjk: bool
    prefixes: frozenset     # concatenated token prefixes, for B5
    dup_of: str | None = None   # incidents.possible_duplicate_of (the legacy link), for B6
    ev_anomalous: bool = False  # R3: event after its own first_public_date, or before 1990
    evb: int | None = None      # the event date BLOCKING uses: SEC-masked, anomalies kept (recall)
    card_issuer: bool = False   # a regulator notice filed by a card issuer (CARD_ISSUERS), s7 b1
    repeat: bool = False        # a source headline states a repeat event (REPEAT_TITLE), s9
    actors: frozenset = frozenset()       # actor ids named for the incident (titles, claims), v2
    title_years: frozenset = frozenset()  # years a source headline states, v2

    @property
    def single_token(self) -> bool:
        return len(self.toks) <= 1

    @property
    def dateless_press(self) -> bool:
        return self.cls == "press" and self.ev is None


def _ord(v) -> int | None:
    if v is None or v == "":
        return None
    if isinstance(v, date):
        return v.toordinal()
    return date.fromisoformat(str(v)[:10]).toordinal()


def _prefixes(*tok_lists) -> frozenset:
    out = set()
    for toks in tok_lists:
        for k in range(1, len(toks) + 1):
            s = "".join(toks[:k])
            if len(s) >= 4:
                out.add(s)
    return frozenset(out)


def _actor_words(text: str) -> list[str]:
    return [w for w in (re.sub(r"[^a-z0-9]+", "", x) for x in (text or "").lower().split()) if w]


def actor_norm(n: str | None) -> str | None:
    """breach_core.actor_norm (0119) = sources_actors.norm: letters and digits, one trailing group word
    dropped when four characters remain."""
    s = re.sub(r"[^a-z0-9]+", "", (n or "").lower())
    t = re.sub(r"(ransomware|ransom|group|team|gang|leaks|leak|blog)$", "", s)
    return (t if len(t) >= 4 else s) or None


class ActorIndex:
    """actor_aliases (alias_norm -> actor_id) restricted to aliases that are evidence of an actor: never a
    token of an organisation name, and in at most ACTOR_TITLE_SHARE of titles. Data only, no name list."""

    MAX_WORDS = 4

    def __init__(self, aliases: dict, org_tokens: set, titles: list):
        def grams(t):
            w = _actor_words(t)
            return {actor_norm(" ".join(w[i:i + k])) for i in range(len(w)) for k in range(1, self.MAX_WORDS + 1)
                    if i + k <= len(w)}
        df = Counter()
        for t in titles:
            df.update(grams(t) & set(aliases))
        cap = max(ACTOR_TITLE_SHARE * len(titles), 1)   # a tiny corpus keeps an alias seen once
        self.aliases = {a: x for a, x in aliases.items() if a not in org_tokens and df[a] <= cap}
        self._grams = grams

    def in_title(self, title: str) -> set:
        return {self.aliases[g] for g in self._grams(title) if g in self.aliases}

    def resolve(self, name: str | None) -> set:
        n = actor_norm(name)
        return {self.aliases[n]} if n in self.aliases else set()


def build_actor_index(orgs, documents, actor_aliases) -> ActorIndex:
    tokens = set()
    for o in orgs:
        tokens.update((o.get("norm_name") or "").split())
        for a in o.get("alias_norms") or ():
            tokens.update(a.split())
    return ActorIndex({a["alias_norm"]: a["actor_id"] for a in actor_aliases}, tokens,
                      [d.get("title") or "" for d in documents or ()])


def build_records(orgs, incidents, sources, claims, documents=None, actors=None) -> list[Rec]:
    """Rows as dicts (the snapshot's or a cursor's). Suppressed incidents and natural persons are
    left out. Claims: accepted, not superseded, not rejected by a reviewer. documents (optional):
    the source documents, whose titles mark a repeat event (s9) and state actors and years (v2).
    actors (optional, v2): {"aliases": actor_aliases rows, "claims": accepted actor claims
    (incident_id, value_text), "leak_claims": (incident_id, actor_group)}."""
    org = {str(o["org_id"]): o for o in orgs}
    title = {d["doc_sha256"]: d.get("title") or "" for d in documents or ()}
    src = defaultdict(set)
    repeat = set()
    named, years = defaultdict(set), defaultdict(set)
    ax = build_actor_index(orgs, documents, actors["aliases"]) if actors else None
    for s in sources:
        src[str(s["incident_id"])].add(s["source_id"])
        t = title.get((s.get("doc_sha256") or "")[:64], "")
        if REPEAT_TITLE.search(t):
            repeat.add(str(s["incident_id"]))
        if t:
            years[str(s["incident_id"])].update(int(y) for y in YEAR_TITLE.findall(t))
            if ax:
                named[str(s["incident_id"])] |= ax.in_title(t)
    if ax:
        for c in actors.get("claims") or ():
            named[str(c["incident_id"])] |= ax.resolve(c.get("value_text"))
        for c in actors.get("leak_claims") or ():
            if c.get("incident_id"):
                named[str(c["incident_id"])] |= ax.resolve(c.get("actor_group"))
    persons = defaultdict(set)
    for c in claims:
        if (c["field"] == "people_affected" and c["accepted"] and not c.get("superseded_by")
                and (c.get("review_verdict") or "") != "rejected" and c["qualifier"] == "exact"
                and c["value_num"] is not None and float(c["value_num"]) >= 1000):
            persons[str(c["incident_id"])].add(int(float(c["value_num"])))
    recs = []
    for i in incidents:
        if i.get("suppressed"):
            continue
        o = org[str(i["org_id"])]
        if o.get("is_natural_person"):
            continue
        iid = str(i["incident_id"])
        ss = frozenset(src.get(iid, ()))
        nn = o["norm_name"] or ""
        lk = link_key(nn)
        toks = tuple(lk.split())
        ev_raw = _ord(i["event_date"])
        cls = incident_class(ss)
        pub = _ord(i["first_public_date"])
        evb = None if ss and all(source_class(s) == "sec" for s in ss) else ev_raw
        # R3 (advisor, 2026-10-19): a date after the record's own first publication, or before
        # 1990, is not a usable breach date. It is kept for blocking and dropped from Δevent,
        # the impossibility feature and the event cannot-link.
        anomalous = evb is not None and (evb > pub or evb < ANOMALY_FLOOR)
        ev = None if anomalous else evb
        recs.append(Rec(iid, str(i["org_id"]), o["display_name"], nn, lk, toks, o.get("domain"),
                        domain_label(o.get("domain")), o.get("sec_cik"), o.get("country") or None,
                        sector_norm(o.get("sector")), tuple(sorted(o.get("alias_norms") or ())), ss, cls,
                        ev, ev_raw, pub, frozenset(persons.get(iid, ())),
                        has_cjk(o["display_name"]), _prefixes(toks, tuple(nn.split())),
                        str(i["possible_duplicate_of"]) if i.get("possible_duplicate_of") else None,
                        anomalous, evb, bool(ss & REG_SOURCES) and nn.startswith(CARD_ISSUERS), iid in repeat,
                        frozenset(named.get(iid, ())), frozenset(years.get(iid, ()))))
    recs.sort(key=lambda r: r.iid)
    return recs


def build_idf(recs: list[Rec]) -> Idf:
    df, seen = Counter(), set()
    tf = Counter()
    for r in recs:
        tf.update(set(r.toks))
        if r.org_id in seen:
            continue
        seen.add(r.org_id)
        df.update(set(r.toks))
    return Idf(dict(df), len(seen), dict(tf), len(recs))


# ---- comparison ---------------------------------------------------------------------------------
def _md_year_off(x: int, y: int) -> bool:
    """Same month and day, years exactly one apart: a likely mistyped year. Exempt from the
    >180-day cannot-link; its Bayes factor is learnt like any other level."""
    dx, dy = date.fromordinal(x), date.fromordinal(y)
    return (dx.month, dx.day) == (dy.month, dy.day) and abs(dx.year - dy.year) == 1


def _dlevel(d: int) -> str:
    return "d0" if d == 0 else "d3" if d <= 3 else "d14" if d <= 14 else "d45" if d <= 45 else "d120" if d <= 120 else "gt120"


def _plevel(d: int) -> str:
    return "p14" if d <= 14 else "p45" if d <= 45 else "p120" if d <= 120 else "p365" if d <= 365 else "gt365"


def compare(a: Rec, b: Rec, idf: Idf) -> dict:
    """Levels per feature plus the raw values behind them (stored in incident_links.features)."""
    pc = pair_class(a.cls, b.cls)
    lv = {"name": name_level(a, b, idf)}
    if a.domain and b.domain:
        lv["domain"] = "equal" if a.domain == b.domain else "different"
    elif (a.dlabel and a.dlabel in b.prefixes) or (b.dlabel and b.dlabel in a.prefixes):
        lv["domain"] = "consistent"
    else:
        lv["domain"] = "missing"
    dev = abs(a.ev - b.ev) if a.ev is not None and b.ev is not None else None
    year_off = dev is not None and _md_year_off(a.ev, b.ev)
    lv["event"] = "missing" if dev is None else "md_match_year_off" if year_off else _dlevel(dev)
    dpub = abs(a.pub - b.pub)
    lv["public"] = _plevel(dpub)
    if a.ev is None and b.ev is None:
        lv["impossible"] = "na"
    else:
        lv["impossible"] = "impossible" if ((a.ev is not None and a.ev > b.pub) or (b.ev is not None and b.ev > a.pub)) else "ok"
    ra, rb = a.sources & REG_SOURCES, b.sources & REG_SOURCES
    lv["source"] = ("same_reg" if ra & rb else "diff_reg") if ra and rb else "other"
    lv["country"] = "missing" if not (a.country and b.country) else ("agree" if a.country == b.country else "conflict")
    lv["sector"] = "missing" if not (a.sector and b.sector) else ("agree" if a.sector == b.sector else "differ")
    lv["count"] = "same" if a.persons & b.persons else "other"
    cannot = []
    if a.domain and b.domain and a.domain != b.domain:
        cannot.append("domain_differs")
    if a.cik and b.cik and a.cik != b.cik:
        cannot.append("cik_differs")
    if lv["name"] == "conflict":
        cannot.append("distinctive_tokens_conflict")
    if dev is not None and dev > CANNOT_LINK_EVENT_DAYS and not year_off:
        cannot.append("event_dates_gt_180d")
    if a.country and b.country and a.country != b.country:
        cannot.append("country_differs")
    if a.card_issuer and b.card_issuer:
        cannot.append("card_issuer_notices")
    return {"levels": lv, "pair_class": pc, "date_class": date_class(pc), "cannot": cannot,
            "raw": {"event_delta_days": dev, "public_delta_days": dpub,
                    "year_conflict": _year_conflict(a, b) or _year_conflict(b, a),
                    "actor_conflict": bool(a.actors and b.actors and not (a.actors & b.actors)),
                    "one_sided_distinct": _one_sided_distinct(a, b, idf)}}


def _is_ja(r: "Rec") -> bool:
    return r.cjk or any(s.startswith("news_jp_") for s in r.sources)


def _year_conflict(a: "Rec", b: "Rec") -> bool:
    """a's headline states a year more than a year before b's publication that is not b's event year."""
    by = date.fromordinal(b.ev).year if b.ev is not None else None
    return any(date(y, 12, 31).toordinal() < b.pub - 365 and y != by for y in a.title_years)


def _one_sided_distinct(a: "Rec", b: "Rec", idf: "Idf") -> bool:
    """Different organisations whose names differ by a distinctive token on exactly one side."""
    if a.org_id == b.org_id:
        return False
    a_only = [t for t in set(a.toks) - set(b.toks) if idf.distinctive(t) and _lacks(t, a.toks, b.toks, idf)]
    b_only = [t for t in set(b.toks) - set(a.toks) if idf.distinctive(t) and _lacks(t, b.toks, a.toks, idf)]
    return bool(a_only) != bool(b_only)


def feature_key(feat: str, cmp: dict) -> str:
    return f"event:{cmp['date_class']}" if feat == "event" else feat


# ---- m / u and scoring --------------------------------------------------------------------------
def m_u_keys():
    keys = [f for f in FEATURES if f != "event"] + [f"event:{c}" for c in DATE_CLASSES]
    return {k: LEVELS[k.split(":")[0]] for k in keys}


def estimate_u(recs: list[Rec], idf: Idf, n_pairs: int = U_PAIRS, seed: int = U_SEED) -> dict:
    """u per level from n_pairs uniformly random incident pairs (Splink-style), Laplace +1.
    Event-date u is per date class. Also the exact-name u for the TF adjustment."""
    rnd = random.Random(seed)
    n = len(recs)
    counts = {k: Counter() for k in m_u_keys()}
    for _ in range(n_pairs):
        i = rnd.randrange(n)
        j = rnd.randrange(n - 1)
        j += j >= i
        c = compare(recs[i], recs[j], idf)
        for f, lvl in c["levels"].items():
            counts[feature_key(f, c)][lvl] += 1
    u = {}
    for k, cnt in counts.items():
        levels = LEVELS[k.split(":")[0]]
        tot = sum(cnt.values()) + len(levels)
        u[k] = {lvl: (cnt[lvl] + 1) / tot for lvl in levels}
    u["_meta"] = {"n_pairs": n_pairs, "seed": seed, "n_records": n,
                  "support": {k: dict(sorted(v.items())) for k, v in counts.items()}}
    return u


M_SMOOTH = 4.0      # pseudo-matches shrinking each m row towards u (step 4, 2026-10-19)
WILSON_Z = 1.959964
AUTO_TARGET_LB = 0.95


def estimate_m(labelled, u: dict, alpha: float = M_SMOOTH) -> dict:
    """m per level from labelled MATCHES (design s2). labelled: (levels, date_class, weight) per
    same_breach pair; weight is the Horvitz-Thompson weight N/n, so the shares describe the
    candidate population rather than the oversampled bands. Each row is smoothed towards u with
    alpha pseudo-matches in Kish effective-sample units:
        m = (n_eff * share + alpha * u) / (n_eff + alpha)
    so a level no labelled match reached keeps a finite negative BF (log2(alpha / (n_eff + alpha))),
    and a key with few matches (a rare date class) stays near BF 0 instead of taking a noisy value."""
    keys = m_u_keys()
    w_cnt = {k: Counter() for k in keys}
    raw = {k: Counter() for k in keys}
    w_sum = Counter()
    w_sq = Counter()
    for lv, dc, w in labelled:
        for f, lvl in lv.items():
            k = feature_key(f, {"date_class": dc})
            w_cnt[k][lvl] += w
            raw[k][lvl] += 1
            w_sum[k] += w
            w_sq[k] += w * w
    m, meta = {}, {}
    for k in keys:
        levels = LEVELS[k.split(":")[0]]
        n_eff = w_sum[k] ** 2 / w_sq[k] if w_sq[k] else 0.0
        share = {lvl: (w_cnt[k][lvl] / w_sum[k] if w_sum[k] else 0.0) for lvl in levels}
        m[k] = ({lvl: (n_eff * share[lvl] + alpha * u[k][lvl]) / (n_eff + alpha) for lvl in levels}
                if n_eff + alpha > 0 else {lvl: u[k][lvl] for lvl in levels})     # no data, no prior: m = u
        meta[k] = {"n": sum(raw[k].values()), "n_eff": round(n_eff, 3),
                   "support": dict(sorted(raw[k].items())),
                   "weighted_share": {lvl: round(share[lvl], 6) for lvl in levels}}
    m["_meta"] = {"alpha": alpha, "toward": "u", "weights": "horvitz_thompson", "per_key": meta}
    return m


def wilson_lower(p: float, n: float, z: float = WILSON_Z) -> float:
    """Wilson score lower bound for a proportion p observed on n trials (n may be an effective n)."""
    if n <= 0:
        return 0.0
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    r = z * math.sqrt(max(0.0, p * (1 - p) / n + z * z / (4 * n * n)))
    return (c - r) / d


def precision_at(rows, t: float) -> dict:
    """rows: (probability, is_match, weight, eligible). Precision of the eligible pairs with p >= t
    (step 4: eligible = no cannot-link), unweighted and Horvitz-Thompson weighted with a Kish
    effective n."""
    sel = [(y, w) for p, y, w, ok in rows if ok and p >= t]
    n = len(sel)
    tp = sum(y for y, _ in sel)
    sw = sum(w for _, w in sel)
    sw2 = sum(w * w for _, w in sel)
    pw = sum(w for y, w in sel if y) / sw if sw else 0.0
    n_eff = sw * sw / sw2 if sw2 else 0.0
    p = tp / n if n else 0.0
    return {"t": t, "n": n, "tp": tp, "precision": p, "wilson_lb": wilson_lower(p, n),
            "precision_ht": pw, "n_eff": n_eff, "wilson_lb_ht": wilson_lower(pw, n_eff)}


def auto_threshold(rows, floor: float = REVIEW, target: float = AUTO_TARGET_LB):
    """The auto threshold, chosen mechanically (design s2): the LOWEST posterior t >= floor at which
    dev precision of the eligible pairs with p >= t has a Wilson lower bound >= target, required of
    BOTH the unweighted and the Horvitz-Thompson (Kish n_eff) estimate. Candidates are the observed
    posteriors. Returns (None, None) when no t qualifies. The row caps (single token, dateless
    press) and the class caps are applied on top, as separate rules (design s2, s3)."""
    for t in sorted({p for p, _, _, ok in rows if ok and p >= floor}):
        r = precision_at(rows, t)
        if r["wilson_lb"] >= target and r["wilson_lb_ht"] >= target:
            return t, r
    return None, None


class Model:
    """Fellegi-Sunter with a pluggable m table. bf = log2(m/u) per (feature key, level).
    auto / review are the band thresholds; auto_classes, when set, is the list of source-pair
    classes allowed to auto-link (every other class is capped at review, design s3)."""

    def __init__(self, m: dict, u: dict, idf: Idf, prior: float, name: str = "provisional",
                 auto: float = PROVISIONAL_AUTO, review: float = REVIEW, auto_classes=None):
        self.m, self.u, self.idf, self.prior, self.name = m, u, idf, prior, name
        self.auto, self.review = auto, review
        self.auto_classes = frozenset(auto_classes) if auto_classes is not None else None
        self.prior_w = math.log2(prior / (1 - prior))
        self.bf = {k: {lvl: math.log2(m[k][lvl] / u[k][lvl]) for lvl in LEVELS[k.split(":")[0]]}
                   for k in m_u_keys()}

    def tf_adjust(self, a: Rec) -> float:
        t = self.idf.rarest(a.toks)
        if not t:
            return 0.0
        adj = math.log2(self.u["name"]["exact"] / self.idf.token_freq(t))
        return max(TF_ADJ_CLAMP[0], min(TF_ADJ_CLAMP[1], adj))

    def score(self, a: Rec, b: Rec, cmp: dict | None = None) -> dict:
        cmp = cmp or compare(a, b, self.idf)
        w = {}
        for f, lvl in cmp["levels"].items():
            w[f] = self.bf[feature_key(f, cmp)][lvl]
        if cmp["levels"]["name"] == "exact":
            w["name_tf"] = self.tf_adjust(a)
        mw = self.prior_w + sum(w.values())
        p = 1 / (1 + 2 ** (-mw)) if mw > -60 else 0.0
        lv = cmp["levels"]
        dateless = a.dateless_press or b.dateless_press
        dateless_ok = lv["public"] in DATELESS_PUBLIC and lv["name"] in DATELESS_NAMES
        single_ok = lv["event"] in SINGLE_EVENT or lv["domain"] in SINGLE_DOMAIN or (dateless and dateless_ok)
        caps = []
        if CAP_SINGLE_TOKEN and (a.single_token or b.single_token) and not single_ok:
            caps.append("single_token")
        if CAP_DATELESS_PRESS and dateless and not dateless_ok:
            caps.append("dateless_press")
        if self.auto_classes is not None and cmp["pair_class"] not in self.auto_classes:
            caps.append("class")
        repeat = REPEAT_EVENT and a.repeat != b.repeat and not (
            a.ev is not None and b.ev is not None and abs(a.ev - b.ev) <= REPEAT_EVENT_DAYS)
        if repeat:
            caps.append("repeat_event")
        year = YEAR_CONFLICT and cmp["raw"].get("year_conflict", False)
        if year:
            caps.append("year_conflict")
        actor = ACTOR_CONFLICT and cmp["raw"].get("actor_conflict", False)
        if actor:
            caps.append("actor_conflict")
        ja = JA_PRESS_CAP and a.cls == "press" and b.cls == "press" and (_is_ja(a) or _is_ja(b))
        if ja:
            caps.append("ja_press")
        actor = actor or ja
        year = year or actor
        legacy = LEGACY_EDGES and (a.dup_of == b.iid or b.dup_of == a.iid) and not repeat and not year and \
            (LEGACY_MIN_P is None or p >= LEGACY_MIN_P)
        band = "auto" if (p >= self.auto and not caps) or legacy else "review" if p >= self.review else "none"
        return {**cmp, "weights": w, "match_weight": mw, "probability": p, "band": band, "capped": bool(caps),
                "cap_reasons": caps, "legacy": legacy}


def provisional_model(u: dict, idf: Idf, n_records: int, m: dict | None = None) -> Model:
    total = n_records * (n_records - 1) / 2
    return Model(m or PROVISIONAL_M, u, idf, min(0.5, PROVISIONAL_EXPECTED_MATCHES / total))


FROZEN_KEYS = ("method_version", "code_sha256", "m", "u", "prior", "auto", "review", "auto_classes")


def load_frozen(path: str | Path, idf: Idf) -> tuple[Model, dict]:
    """The frozen model of step 4 (m from dev labels, u, prior, thresholds, allowed classes). Refuses
    a file written for another METHOD_VERSION."""
    f = json.loads(Path(path).read_text())
    missing = [k for k in FROZEN_KEYS if k not in f]
    if missing:
        raise ValueError(f"frozen model lacks {missing}")
    if f["method_version"] != METHOD_VERSION:
        raise ValueError(f"frozen model is {f['method_version']}, code is {METHOD_VERSION}")
    m = {k: v for k, v in f["m"].items() if not k.startswith("_")}
    u = {k: v for k, v in f["u"].items() if not k.startswith("_")}
    return Model(m, u, idf, f["prior"], name="frozen", auto=f["auto"], review=f["review"],
                 auto_classes=f["auto_classes"]), f


def band_index(p: float) -> int:
    k = 0
    for i, e in enumerate(BAND_EDGES):
        if p >= e:
            k = i
    return k


# ---- blocking -----------------------------------------------------------------------------------
def _pairs_in_window(members: list[Rec], attr: str, window: int):
    ms = sorted((m for m in members if getattr(m, attr) is not None), key=lambda r: (getattr(r, attr), r.iid))
    out = []
    for i, a in enumerate(ms):
        va = getattr(a, attr)
        for b in ms[i + 1:]:
            if getattr(b, attr) - va > window:
                break
            if a.iid != b.iid:
                out.append((a.iid, b.iid) if a.iid < b.iid else (b.iid, a.iid))
    return out


def _legacy_window_pairs(members: list[Rec]):
    """resolve.py's window: event dates within 30 d when both are stated, else public within 90 d.
    Uses the RAW event date, as the resolver did (SEC period_ending included)."""
    ms = sorted(members, key=lambda r: r.iid)
    out = []
    for i, a in enumerate(ms):
        for b in ms[i + 1:]:
            if a.ev_raw is not None and b.ev_raw is not None:
                close = abs(a.ev_raw - b.ev_raw) <= LEGACY_EVENT_WINDOW
            else:
                close = abs(a.pub - b.pub) <= LEGACY_PUBLIC_WINDOW
            if close:
                out.append((a.iid, b.iid))
    return out


def _all_pairs(members: list[Rec]):
    ids = sorted({m.iid for m in members})
    return [(ids[i], ids[j]) for i in range(len(ids)) for j in range(i + 1, len(ids))]


def _cross_pairs(left: list[Rec], right: list[Rec], window: int | None):
    out = set()
    for a in left:
        for b in right:
            if a.iid == b.iid or (window is not None and abs(a.pub - b.pub) > window):
                continue
            out.add((a.iid, b.iid) if a.iid < b.iid else (b.iid, a.iid))
    return sorted(out)


def block(recs: list[Rec], idf: Idf, cap: int = BLOCK_CAP):
    """Candidate pairs -> sorted list of block keys; and the dropped blocks.

    B1  same CIK or same domain, any date
    B2  same first two tokens of link_key (one token if that is all there is), public within 365 d
        OR both event dates within 7 d (added: one vendor breach filed by customers 600 days later,
        "Illuminate Education on behalf of ...", is otherwise never a candidate)
    B2p a ONE-token link_key against the first token of longer link_keys, public within 365 d
        (added: without it a bare "Allianz" press row blocks with nothing)
    B3  same rarest token (df <= 50 organisations), both event dates within 7 d
    B4  an alias key (alias_norms) equal to the other's norm_name / link_key / alias, 365 d
    B5  domain label equal to the other's concatenated name tokens (allianzlife = allianz+life), 365 d
    B6  every pair the current system links: the stored possible_duplicate_of edges, plus the same
        organisation inside the legacy resolver's window (both event dates within 30 d, else
        first_public within 90 d). Added so the legacy links can be labelled and scored (design s3
        gate). NOT capped: it is bounded by what resolve.py already compares, and the cap exists
        for generic name tokens. Measured: American Express's 86 CA notices give one 310-pair block.
    """
    cand: dict[tuple, set] = defaultdict(set)
    dropped: list[dict] = []
    stats = Counter()

    def emit(key: str, pairs, capped: bool = True):
        if capped and len(pairs) > cap:
            dropped.append({"block": key, "pairs": len(pairs)})
            stats[key.split(":")[0] + "_dropped_pairs"] += len(pairs)
            return
        for p in pairs:
            cand[p].add(key)

    def groups(keyfn):
        g = defaultdict(list)
        for r in recs:
            for k in keyfn(r):
                g[k].append(r)
        return g

    for k, ms in sorted(groups(lambda r: [r.cik] if r.cik else []).items()):
        emit(f"B1:cik:{k}", _all_pairs(ms))
    for k, ms in sorted(groups(lambda r: [r.domain] if r.domain else []).items()):
        emit(f"B1:domain:{k}", _all_pairs(ms))
    for k, ms in sorted(groups(lambda r: [" ".join(r.toks[:2])] if r.toks else []).items()):
        if len(ms) > 1:
            emit(f"B2:{k}", sorted(set(_pairs_in_window(ms, "pub", PUBLIC_WINDOW))
                                   | set(_pairs_in_window(ms, "evb", B3_EVENT_WINDOW))))
    first = groups(lambda r: [r.toks[0]] if len(r.toks) >= 2 else [])
    for k, ms in sorted(groups(lambda r: [r.toks[0]] if len(r.toks) == 1 else []).items()):
        if k in first:
            emit(f"B2p:{k}", _cross_pairs(ms, first[k], PUBLIC_WINDOW))
    def rarest(r):
        t = idf.rarest(r.toks)
        return [t] if t and idf.rare(t) and r.evb is not None else []
    for k, ms in sorted(groups(rarest).items()):
        if len(ms) > 1:
            emit(f"B3:{k}", _pairs_in_window(ms, "evb", B3_EVENT_WINDOW))
    by_name = groups(lambda r: {x for x in (r.nn, r.lk) if x} | set(r.aliases))
    for k, ms in sorted(groups(lambda r: list(r.aliases)).items()):
        emit(f"B4:{k}", _cross_pairs(ms, by_name.get(k, []), PUBLIC_WINDOW))
    by_prefix = groups(lambda r: sorted(r.prefixes))
    for k, ms in sorted(groups(lambda r: [r.dlabel] if r.dlabel else []).items()):
        if k in by_prefix:
            emit(f"B5:{k}", _cross_pairs(ms, by_prefix[k], PUBLIC_WINDOW))
    for k, ms in sorted(groups(lambda r: [r.org_id]).items()):
        if len(ms) > 1:
            emit(f"B6:{k}", _legacy_window_pairs(ms), capped=False)
    ids = {r.iid for r in recs}
    emit("B6:possible_duplicate_of", sorted({(min(r.iid, r.dup_of), max(r.iid, r.dup_of)) for r in recs
                                             if r.dup_of and r.dup_of in ids and r.dup_of != r.iid}),
         capped=False)
    out = {p: sorted(v) for p, v in sorted(cand.items())}
    per_pass = Counter()
    for keys in out.values():
        for ps in {k.split(":")[0] for k in keys}:
            per_pass[ps] += 1
    return out, sorted(dropped, key=lambda d: (-d["pairs"], d["block"])), dict(per_pass)


# ---- EM (diagnostic only) -----------------------------------------------------------------------
def em_m(scored_levels: list[tuple[dict, str]], u: dict, m_init: dict, lam: float = 0.3,
         iters: int = 200, tol: float = 1e-7, fix_u: bool = True) -> tuple[dict, float, int, dict]:
    """EM on the candidate pairs. Diagnostic only (design s2): its match class converges towards
    "same organisation" (or, with u fixed from random pairs, towards "a blocked pair"), not
    "same breach". fix_u=False re-estimates u on the candidates as well."""
    keys = m_u_keys()
    rows = [[(feature_key(f, {"date_class": dc}), lvl) for f, lvl in lv.items()] for lv, dc in scored_levels]
    m = {k: dict(v) for k, v in m_init.items()}
    u = {k: dict(u[k]) for k in keys}
    it = 0
    for it in range(1, iters + 1):
        acc = {k: Counter() for k in keys}
        tot = {k: 0.0 for k in keys}
        uacc = {k: Counter() for k in keys}
        utot = {k: 0.0 for k in keys}
        s = 0.0
        for row in rows:
            lm, lu = math.log(lam), math.log(1 - lam)
            for k, lvl in row:
                lm += math.log(m[k][lvl])
                lu += math.log(u[k][lvl])
            g = 1 / (1 + math.exp(min(700, lu - lm)))
            s += g
            for k, lvl in row:
                acc[k][lvl] += g
                tot[k] += g
                uacc[k][lvl] += 1 - g
                utot[k] += 1 - g
        new_lam = s / len(rows)
        delta = abs(new_lam - lam)
        for k in keys:
            levels = LEVELS[k.split(":")[0]]
            denom = tot[k] + 1e-3 * len(levels)
            nm = {lvl: (acc[k][lvl] + 1e-3) / denom for lvl in levels}
            delta = max(delta, max(abs(nm[lvl] - m[k][lvl]) for lvl in levels))
            m[k] = nm
            if not fix_u:
                ud = utot[k] + 1e-3 * len(levels)
                u[k] = {lvl: (uacc[k][lvl] + 1e-3) / ud for lvl in levels}
        lam = new_lam
        if delta < tol:
            break
    return m, lam, it, u


# ---- clustering ---------------------------------------------------------------------------------
def cluster(recs: list[Rec], scored: dict, model: Model, decisions: dict | None = None,
            review: float = REVIEW, max_size: int = MAX_AUTO_CLUSTER):
    """Constrained clustering (design s2). scored: {(a, b): score dict}. decisions: human verdicts
    {(a, b): 'must_link' | 'cannot_link'}, which beat the model. Returns (cluster_of, notes) where
    notes[(a, b)] says why an auto edge was not taken."""
    decisions = decisions or {}
    by_id = {r.iid: r for r in recs}
    cache: dict = {}

    def pair(x, y):
        k = (x, y) if x < y else (y, x)
        if k in scored:
            return scored[k]
        if k not in cache:
            cache[k] = model.score(by_id[k[0]], by_id[k[1]])
        return cache[k]

    def cannot(x, y):
        k = (x, y) if x < y else (y, x)
        d = decisions.get(k)
        if d == "cannot_link":
            return True
        if d == "must_link":
            return False
        return bool(pair(x, y)["cannot"])

    members = {r.iid: [r.iid] for r in recs}
    root = {r.iid: r.iid for r in recs}
    edges = [(k, s["probability"]) for k, s in scored.items()
             if (s["band"] == "auto" and not s["cannot"] and decisions.get(k) != "cannot_link")]
    edges += [(k, 1.0) for k, d in decisions.items() if d == "must_link" and k[0] in by_id and k[1] in by_id]
    edges.sort(key=lambda e: (-e[1], e[0]))
    notes: dict = {}
    forced = {k for k, d in decisions.items() if d == "must_link"}
    def reg_guard(k):
        """s15: two regulator rows share a cluster only if their own pair is not a one-sided distinct-token
        difference between two organisations (a cannot-link is refused below already)."""
        a, b = by_id[k[0]], by_id[k[1]]
        regs = (a.cls == "reg") + (b.cls == "reg")
        scoped = regs == 2 if REG_GUARD_SCOPE == "both" else regs >= 1
        return REG_BRIDGE_GUARD and scoped and pair(*k).get("raw", {}).get("one_sided_distinct")

    def title_capped(k):
        return TITLE_CAP_GUARD and any(c in TITLE_CAPS for c in (pair(*k).get("cap_reasons") or ()))

    def incompatible(A, B):
        cross = [((x, y) if x < y else (y, x)) for x in A for y in B]
        cross = [k for k in cross if k not in forced]
        if any(cannot(*k) for k in cross):
            return "cannot_link_spans"
        # a legacy edge is accepted on its own measured precision (s7 b1): it is exempt from the
        # review-level test, never from a cannot-link
        if any(reg_guard(k) for k in cross):
            return "reg_bridge_guard"
        if any(title_capped(k) for k in cross):
            return "title_conflict"
        if any(pair(*k)["probability"] < review and not pair(*k).get("legacy") for k in cross):
            return "complete_linkage"
        return None

    overflow: set = set()
    for (a, b), _p in edges:
        ra, rb = root[a], root[b]
        if ra == rb:
            continue
        A, B = members[ra], members[rb]
        if len(A) + len(B) > max_size:
            notes[(a, b)] = "cluster_size_cap"
            # the smaller side is the overflow: it goes to review, never out as a second, truncated
            # cluster of the same breach (advisor s8 d)
            small = A if (len(A), ra) < (len(B), rb) else B
            overflow.update(small)
            continue
        why = incompatible(A, B)
        if why:
            notes[(a, b)] = why
            continue
        keep, gone = (ra, rb) if len(A) >= len(B) else (rb, ra)
        for x in members[gone]:
            root[x] = keep
        members[keep] = sorted(members[keep] + members.pop(gone))
    # Rows refused by the size cap stand alone; their auto edges become review items (s8 d).
    for x in sorted(overflow):
        rx = root[x]
        if len(members[rx]) < 2 or any((min(x, y), max(x, y)) in forced for y in members[rx] if y != x):
            continue
        for y in members[rx]:
            k = (min(x, y), max(x, y))
            if y != x and scored.get(k, {}).get("band") == "auto":
                notes[k] = "cluster_size_cap"
        members[rx] = [y for y in members[rx] if y != x]
        if rx == x:
            nr = members[rx][0]
            members[nr] = members.pop(rx)
            for y in members[nr]:
                root[y] = nr
        root[x] = x
        members[x] = [x]
    # Ambiguity (design s2 rule 4): a member that reaches review level (not cannot-link) against a
    # RIVAL cluster - one that a cannot-link pair separates from its own ("Allianz" against Allianz
    # Life and Allianz Global Risks) - is ambiguous: it leaves its cluster and its auto edges go to
    # review. A cluster kept apart only by a weak score is not a rival but a pending review item
    # (a dateless press row beside a dated cluster); treating it as one dissolved the dated
    # Allianz Life cluster that the design expects at auto. INTERPRETATION, for the advisor.
    review_nb = defaultdict(set)
    for (a, b), s in scored.items():
        if s["probability"] >= review and not s["cannot"] and decisions.get((a, b)) != "cannot_link":
            review_nb[a].add(b)
            review_nb[b].add(a)
    for _ in range(10):
        moved = False
        for x in sorted(root):
            rx = root[x]
            if len(members[rx]) < 2:
                continue
            others = sorted({root[y] for y in review_nb[x]} - {rx})
            rivals = [o for o in others if incompatible(members[rx], members[o]) == "cannot_link_spans"]
            if rivals and not any((min(x, y), max(x, y)) in forced for y in members[rx] if y != x):
                members[rx] = [y for y in members[rx] if y != x]
                if len(members[rx]) and rx == x:     # re-root the remaining members
                    nr = members[rx][0]
                    members[nr] = members.pop(rx)
                    for y in members[nr]:
                        root[y] = nr
                root[x] = x
                members[x] = [x]
                for y in review_nb[x]:
                    k = (min(x, y), max(x, y))
                    if scored.get(k, {}).get("band") == "auto":
                        notes[k] = "ambiguous"
                moved = True
        if not moved:
            break
    # The listed id: earliest first_public, then incident_id (design s4).
    cluster_of = {}
    for rt, ms in members.items():
        cid = min(ms, key=lambda i: (by_id[i].pub, i))
        for i in ms:
            cluster_of[i] = cid
    return cluster_of, notes


def decision_of(s: dict, note: str | None) -> str:
    if s["cannot"]:
        return "cannot_link"
    if s["band"] == "auto":
        return "review_pending" if note else "auto_link"
    if s["band"] == "review":
        return "review_pending"
    return "none"


# ---- snapshot I/O and the run -------------------------------------------------------------------
def load_snapshot(d: str | Path) -> dict:
    d = Path(d)
    optional = ("documents", "actor_aliases", "actor_claims", "leak_claims")
    return {n: [json.loads(x) for x in (d / f"{n}.jsonl").open()]
            for n in ("organizations", "incidents", "incident_sources", "claims") + optional
            if n not in optional or (d / f"{n}.jsonl").exists()}


def snapshot_actors(snap: dict) -> dict | None:
    """The actor tables of a snapshot (v2 title evidence), or None when the snapshot has none."""
    if "actor_aliases" not in snap:
        return None
    return {"aliases": snap["actor_aliases"], "claims": snap.get("actor_claims") or [],
            "leak_claims": snap.get("leak_claims") or []}


def _round(x):
    return round(x, 6) if isinstance(x, float) else x


def run(snapshot: str | Path, out: str | Path, n_u: int = U_PAIRS, seed: int = U_SEED, em: bool = True,
        frozen: str | Path | None = None) -> dict:
    """One linkage run on a snapshot. With `frozen` (step 4's model_frozen.json) u, m, prior,
    thresholds and allowed classes come from that file: no u is estimated and no EM runs."""
    import resource
    import time
    t0 = time.time()
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    snap = load_snapshot(snapshot)
    recs = build_records(snap["organizations"], snap["incidents"], snap["incident_sources"], snap["claims"],
                         snap.get("documents"), snapshot_actors(snap))
    idf = build_idf(recs)
    by_id = {r.iid: r for r in recs}
    t_load = time.time()
    cand, dropped, per_pass = block(recs, idf)
    t_block = time.time()
    if frozen:
        model, fz = load_frozen(frozen, idf)
        u = fz["u"]
    else:
        u = estimate_u(recs, idf, n_u, seed)
        model = provisional_model(u, idf, len(recs))
    t_u = time.time()
    scored = {}
    for (a, b), keys in cand.items():
        s = model.score(by_id[a], by_id[b])
        s["block_keys"] = keys
        scored[(a, b)] = s
    t_score = time.time()
    em_out = None
    if em and not frozen:
        lv = [(s["levels"], s["date_class"]) for s in scored.values()]
        m_em, lam_em, iters, _ = em_m(lv, u, PROVISIONAL_M)
        m_em2, lam_em2, iters2, u_em2 = em_m(lv, u, PROVISIONAL_M, fix_u=False)
        em_out = {"m": m_em, "lambda_candidates": lam_em, "iterations": iters,
                  "free_u": {"m": m_em2, "u_candidates": u_em2, "lambda_candidates": lam_em2,
                             "iterations": iters2}}
    t_em = time.time()
    cluster_of, notes = cluster(recs, scored, model, review=model.review)
    t_cl = time.time()
    with (out / "pairs.jsonl").open("w") as f:
        for (a, b), s in scored.items():
            f.write(json.dumps({"a": a, "b": b, "block_keys": s["block_keys"], "levels": s["levels"],
                                "pair_class": s["pair_class"], "cannot": s["cannot"], "raw": s["raw"],
                                "weights": {k: _round(v) for k, v in s["weights"].items()},
                                "match_weight": _round(s["match_weight"]), "p": _round(s["probability"]),
                                "band": s["band"], "capped": s["capped"], "cap_reasons": s["cap_reasons"],
                                "legacy": s["legacy"],
                                "decision": decision_of(s, notes.get((a, b))), "note": notes.get((a, b))},
                               sort_keys=True) + "\n")
    with (out / "clusters.jsonl").open("w") as f:
        for i in sorted(cluster_of):
            f.write(json.dumps({"incident_id": i, "cluster_id": cluster_of[i]}) + "\n")
    json.dump({k: v for k, v in u.items()}, (out / "u.json").open("w"), indent=1, sort_keys=True)
    if frozen:
        (out / "model.sha256").write_text(f"{hashlib.sha256(Path(frozen).read_bytes()).hexdigest()}  {Path(frozen).name}\n")
    else:
        json.dump({"provisional": True, "hand_m": PROVISIONAL_M, "prior": model.prior, "em": em_out},
                  (out / "m_provisional.json").open("w"), indent=1, sort_keys=True)
    json.dump({"dropped": dropped}, (out / "blocking.json").open("w"), indent=1)
    sizes = Counter(Counter(cluster_of.values()).values())
    summary = {
        "method_version": METHOD_VERSION, "model": model.name, "records": len(recs), "candidate_pairs": len(cand),
        "per_pass": per_pass, "dropped_blocks": len(dropped),
        "bands": dict(Counter(s["band"] for s in scored.values())),
        "decisions": dict(Counter(decision_of(s, notes.get(k)) for k, s in scored.items())),
        "cluster_sizes": dict(sorted(sizes.items())),
        "seconds": {"load": round(t_load - t0, 1), "block": round(t_block - t_load, 1), "u": round(t_u - t_block, 1),
                    "score": round(t_score - t_u, 1), "em": round(t_em - t_score, 1), "cluster": round(t_cl - t_em, 1)},
        # ru_maxrss is bytes on macOS, kilobytes on Linux
        "peak_rss_mb": round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                             / ((1 << 20) if sys.platform == "darwin" else (1 << 10)), 1),
    }
    json.dump(summary, (out / "summary.json").open("w"), indent=1, sort_keys=True)
    summary["sha256"] = {n: hashlib.sha256((out / n).read_bytes()).hexdigest()
                         for n in ("pairs.jsonl", "clusters.jsonl", "u.json", "blocking.json",
                                   "model.sha256" if frozen else "m_provisional.json")}
    return summary


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="Breach record linkage on a snapshot (no database access).")
    ap.add_argument("--snapshot", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--u-pairs", type=int, default=U_PAIRS)
    ap.add_argument("--seed", type=int, default=U_SEED)
    ap.add_argument("--no-em", action="store_true")
    ap.add_argument("--model", help="frozen model (step 4 model_frozen.json); skips u estimation and EM")
    a = ap.parse_args(argv)
    print(json.dumps(run(a.snapshot, a.out, a.u_pairs, a.seed, not a.no_em, a.model), indent=1))


if __name__ == "__main__":
    main()
