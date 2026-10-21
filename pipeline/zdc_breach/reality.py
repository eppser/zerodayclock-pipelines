"""Is a ransomware leak-site victim name a real organisation? (method breach-reality-v1)

A port of the frozen C2 research cascade (production configuration ``cfg_prod_f6``: rules A1-A7, the
identity, institution, weak-name and truncation guards and the F6 fixes; no LLM judge, no back-linking,
no Common Crawl, no certificate logs). Behaviour is identical to the frozen code on the same evidence
pack; configuration branches the production config never takes were removed.

Labels: ``real_org`` | ``not_org`` (placeholder, test, gibberish, actor infrastructure - deterministic
name rules only; a person is never not_org) | ``ambiguous`` | ``redacted_unresolved`` (masked names).
``natural_person_risk`` routes person-like names to review. Nothing here publishes anything: the
decision table has no public view (publication is an owner decision).

Evidence pack per claim (``breach_raw.victim_evidence``, insert-only):
  pool     candidate hosts + Wikidata hits (reality_harvest.harvest_pool)
  extras   TLS subject, up to four extra pages, GLEIF, EDGAR (reality_harvest.harvest_extras)
  leakmeta domains a leak post's text names, extracted by regex INSIDE the query (LEAKMETA_SQL):
           the post text itself never leaves the database
  corrob   organisations the breach tables already hold under the same name or domain (CORROB_SQL)

Lexicon (computed from the database each run; never committed as a file, being name-derived):
  token_df_distinct  per token, the number of distinct leak-claim names (victim_norm) whose
                     core tokens contain it. The frozen file was built the same way over the
                     research population (sealed evaluation keys excluded); production uses all.
  actor_norms        breach_core.actor_aliases.alias_norm, plus every leak_claims.actor_group
                     lower-cased with everything but [a-z0-9] removed.
The frozen token_df.json (per-claim counts) is not used: its only reader, generic_name(), is
unreachable under the production identity guard ('all_slug').

CLI (counts-only JSON report; never a name):
  python -m zdc_breach.reality run --limit N --deadline-min M
  python -m zdc_breach.reality load-packs --pool F --extras F --groups F
  python -m zdc_breach.reality decide
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import re
import sys
import time
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

METHOD = "breach-reality-v1"
RECHECK_AFTER = timedelta(days=90)
BATCH = 500
STATEMENT_TIMEOUT = "120s"
LOCK_TIMEOUT = "5s"

# =====================================================================================================
# Name rules (frozen detpass.py, RUBRIC v2.1)
# =====================================================================================================
GLYPHS = '•●■▪█◼◾⬛∗'
MASK_RUN = r'\*+|\?{2,}|_{2,}|#{2,}|\.\.\.+|…|[' + GLYPHS + ']+'
XRUN = re.compile(r'(?<=[A-Za-z])[xX]{3,}|[xX]{3,}(?=[A-Za-wyzA-WYZ])')   # x-runs only next to other visible letters
MASK = re.compile(MASK_RUN)
PREFIX = re.compile(r'^\s*(\[[A-Za-z ]{2,20}\]\s*|audit entity\s*:\s*)', re.I)
DOMAIN = re.compile(r'^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$', re.I)
PLACEHOLDER = re.compile(r'^\s*(company|victim|client|target)\s*#\s*\d+\s*$|^\s*\[?\s*(redacted|negotiated|unknown|private|n/?a|tba|tbd|null|none|coming soon)\s*\]?\s*$|'
                         r'^\s*(an?|some|one)\s+(large|small|big|major|leading|certain|independent|unnamed|undisclosed)\b|^\s*[\d\s.,$€%+-]+\s*$', re.I)
ANNOUNCE = re.compile(r'\b(gift|surprise|who is next|false claims?|rules for|communicating with|private keys|exclusive data|for everyone|hey everyone|'
                      r'fake actor|a buyer|stay tuned|identification number|important announcement|announcement)\b|'
                      r'^\s*(an?|some|one)\s+(top[- ]tier|little|big|huge|well[- ]known|famous|major|large|leading|certain|independent)\b', re.I)
REPEAT = re.compile(r'^\s*(\w)\1{2,}\s*$')
TEST = re.compile(r'^\s*\[?\s*(test|testing|demo|sample|asdf|qwerty|lorem ipsum)\s*\d*\s*\]?\s*$', re.I)
# RFC 2606/6761. Not .local: victims' AD domains are real organisations. Frozen in v2.1.
RESERVED_TLD = ('.test', '.invalid', '.localhost', '.example')
RESERVED_EXACT = frozenset(['example.com', 'example.net', 'example.org', 'test.com', 'domain.com', 'company.com', 'yourdomain.com',
                            'yourcompany.com', 'mydomain.com', 'mycompany.com', 'sample.com', 'website.com', 'yoursite.com', 'site.com',
                            'email.com', 'localhost'])


def clean(n):
    """Strip tracker prefixes ('[Ransom] ', 'audit entity:') and markdown bold around the whole name."""
    n = PREFIX.sub('', n or '')
    n = re.sub(r'^\*\*(.+)\*\*$', r'\1', n.strip())
    return n.strip()


def is_masked(n):
    n = clean(n)
    return bool(MASK.search(n) or XRUN.search(n))


def domain_shaped(n):
    return bool(DOMAIN.match(clean(n).strip().lower()))


def n_letters(n):
    return len(re.findall(r'[^\W\d_]', n or ''))


def name_rule(raw):
    """'masked' | ('not_org', subtype) | None. The lexicon never fires on a domain-shaped name."""
    n = clean(raw)
    if not domain_shaped(n) and ANNOUNCE.search(n):
        return ('not_org', 'placeholder')          # announcements before the mask test ("WHO IS NEXT??")
    if is_masked(n):
        return 'masked'
    if domain_shaped(n):
        return None                                 # a hostname is never a placeholder/test/gibberish verdict
    if n_letters(n) < 2 or REPEAT.match(n):
        return ('not_org', 'gibberish')
    if PLACEHOLDER.search(n):
        return ('not_org', 'placeholder')
    if TEST.search(n):
        return ('not_org', 'test')
    return None


def _norm_alnum(s):
    return re.sub(r'[^a-z0-9]', '', (s or '').lower())


def reserved_domain(n):
    h = re.sub(r'^www\.', '', clean(n).strip().lower().rstrip('.'))
    return h in RESERVED_EXACT or h.endswith(RESERVED_TLD) or re.match(r'^example\.', h) is not None


def registrable_label(h):
    parts = re.sub(r'^www\.', '', h.lower()).split('.')
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in ('co', 'com', 'org', 'net', 'ac', 'gov', 'edu'):
        return parts[-3]
    return parts[-2] if len(parts) >= 2 else parts[0]


def actor_infra(n, actor, actor_norms):
    """Domain-shaped name whose registrable label is the claiming actor, or another known actor's name when
    decorated with digits or a leaks/leak/blog/news/team suffix and >= 5 characters (lockbit4.com, akiraleaks.net;
    hive360.com and core-1.com are firms)."""
    if not domain_shaped(n):
        return False
    lab = _norm_alnum(registrable_label(clean(n).strip()))
    base = re.sub(r'\d+$', '', re.sub(r'(leaks?|blog|news|team)$', '', re.sub(r'\d+$', '', lab)) or lab)
    if len(base) < 3:
        return False
    own = re.sub(r'\d+$', '', _norm_alnum(actor)) if actor else ''
    if own and base == own:
        return True
    decorated = base != lab
    return decorated and len(base) >= 5 and base in set(actor_norms or ())


def name_rule_v21(raw, actor=None, actor_norms=()):
    """Actor infrastructure and reserved domains first (never fetched), then name_rule."""
    if actor_infra(raw, actor, actor_norms):
        return ('not_org', 'actor_infrastructure')
    if domain_shaped(raw) and reserved_domain(raw):
        return ('not_org', 'placeholder')
    return name_rule(raw)


def never_fetch(name, actor, actor_norms):
    """The harvester sends no request at all for these names (RUBRIC v2.1)."""
    return actor_infra(name, actor, actor_norms) or (domain_shaped(name) and reserved_domain(name))


def norm_host(h):
    h = (h or '').strip().lower()
    h = re.sub(r'^https?://', '', h).split('/')[0].split(':')[0]
    return re.sub(r'^www\.', '', h)


# =====================================================================================================
# Person guard (frozen person.py): personal-name structure. Never decides alone; it routes to review.
# =====================================================================================================
GIVEN = set('''james john robert michael william david richard joseph thomas charles christopher daniel matthew anthony mark donald steven paul andrew joshua kenneth kevin brian george timothy ronald edward jason jeffrey ryan jacob gary nicholas eric jonathan stephen larry justin scott brandon benjamin samuel gregory alexander frank patrick raymond jack dennis jerry tyler aaron jose adam nathan henry douglas zachary peter kyle noah ethan jeremy walter christian keith roger terry austin sean gerald carl harold dylan arthur lawrence jordan jesse bryan billy bruce gabriel joe logan albert willie alan eugene russell vincent philip bobby johnny bradley roy ralph randy wayne howard louis
mary patricia jennifer linda elizabeth barbara susan jessica sarah karen lisa nancy betty margaret sandra ashley kimberly emily donna michelle carol amanda dorothy melissa deborah stephanie rebecca sharon laura cynthia kathleen amy angela shirley anna brenda pamela emma nicole helen samantha katherine christine debra rachel carolyn janet catherine maria heather diane ruth julie olivia joyce virginia victoria kelly lauren christina joan evelyn judith megan andrea cheryl hannah jacqueline martha gloria teresa ann sara madison frances kathryn janice jean abigail alice judy sophia grace denise amber doris marilyn danielle beverly isabella theresa diana natalie brittany charlotte marie kayla alexis lori
hans peter klaus jurgen jürgen wolfgang dieter uwe stefan andreas thomas michael frank markus martin matthias sabine petra monika ursula karin brigitte renate gabriele andrea claudia susanne birgit
jean pierre michel philippe alain nicolas francois françois patrick christophe laurent sophie isabelle nathalie sylvie catherine valerie valérie
giuseppe giovanni antonio mario luigi francesco marco paolo andrea roberto stefano alessandro luca maria anna giulia francesca chiara
jose josé juan carlos luis miguel javier manuel francisco pedro antonio jorge alejandro diego fernando ricardo sergio pablo carmen ana lucia lucía laura marta elena isabel rosa teresa
joao joão paulo ana fernanda
ivan sergei sergey dmitry dmitri alexei alexey andrei andrey vladimir nikolai mikhail olga tatiana natalia elena irina svetlana anastasia
mohammed muhammad ahmed ali omar hassan hussein mahmoud fatima aisha ali
wei li zhang wang chen liu yang huang zhao hiroshi takashi yuki kenji akira haruto sakura
raj rahul amit sanjay vijay anil sunil ravi priya anita sunita deepak arjun
jan piotr krzysztof tomasz pawel paweł marta katarzyna agnieszka anna
lars erik anders johan nils karl olof ingrid astrid kristin'''.split())
PERSON_ORGWORDS = re.compile(r'\b(inc|llc|ltd|gmbh|corp|co|company|group|bank|school|college|university|hospital|clinic|law|legal|associates|partners|'
                             r'dental|medical|services?|solutions|systems|technologies|tech|consulting|holdings?|industries|international|global|'
                             r'construction|insurance|realty|properties|foundation|church|city|county|council|district|centre|center|farm|farms|'
                             r'motors|logistics|foods?|hotel|restaurant|store|shop|studio|design|media|capital|financial|energy|club|academy|sa|srl|spa|bv|ag|kg|plc|pc|pa|pllc|cpa|md|dds)\b', re.I)


def fold(s):
    return unicodedata.normalize('NFKD', s).encode('ascii', 'ignore').decode().lower()


def person_like(name):
    n = (name or '').strip()
    if not n or PERSON_ORGWORDS.search(n) or re.search(r'[\d@/\\.]', n):
        return False
    if re.fullmatch(r"(the\s+)?[A-Z][\w'-]+\s+family", n, re.I):
        return True
    toks = re.findall(r"[^\W\d_][\w'-]*", n)
    if not 2 <= len(toks) <= 3:
        return False
    if not all(t[0].isupper() for t in toks):
        return False
    if fold(toks[0]) in GIVEN:
        return True
    if len(toks) == 3 and re.search(r'(ovich|evich|ovna|evna|ich)$', fold(toks[1])):
        return True                                  # patronymic
    return False


# =====================================================================================================
# Lexicon
# =====================================================================================================
@dataclass(frozen=True)
class Lexicon:
    token_df_distinct: dict = field(default_factory=dict)
    actor_norms: frozenset = frozenset()

    def sha256(self) -> str:
        blob = json.dumps({'token_df_distinct': sorted(self.token_df_distinct.items()),
                           'actor_norms': sorted(self.actor_norms)}, ensure_ascii=False, separators=(',', ':'))
        return hashlib.sha256(blob.encode()).hexdigest()


# One read each; the counting is in Python because the tokeniser (NFKD fold, stop and legal words) is.
LEXICON_SQL = {
    'victim_norms': "select distinct victim_norm from breach_core.leak_claims",
    'alias_norms': "select distinct alias_norm from breach_core.actor_aliases",
    'actor_groups': "select distinct actor_group from breach_core.leak_claims",
}


def build_lexicon(victim_norms, alias_norms, actor_groups) -> Lexicon:
    df = collections.Counter()
    for nn in set(victim_norms):
        df.update(set(core(nn or '')))
    norms = {a for a in alias_norms if a} | {_norm_alnum(g) for g in actor_groups if g}
    norms.discard('')
    return Lexicon(dict(df), frozenset(norms))


def read_lexicon(cur) -> Lexicon:
    cols = {}
    for k, sql in LEXICON_SQL.items():
        cur.execute(sql)
        cols[k] = [r[0] for r in cur.fetchall()]
    return build_lexicon(**cols)


# =====================================================================================================
# Signals and decision (frozen methods.py under cfg_prod_f6)
# =====================================================================================================
STOP = {'the', 'and', 'of', 'for', 'de', 'la', 'le', 'del', 'des', 'du', 'di', 'da', 'und', 'et', 'y', 'e', 'a', 'an', 'in', 'at', 'on', 'by'}
LEGALW = set('inc incorporated llc ltd limited plc gmbh mbh ag kg sa sas srl spa bv nv corp corporation co company pty pvt private bhd sdn oy ab as aps sl ltda lda sarl saic saicei group grupo gruppe holding holdings'.split())
TR = frozenset({'tracker_domain', 'name_is_domain', 'embedded_in_name'})
MARKET = re.compile(r'aftermarket|domainmarkt|domainmarket|sedo\.|dan\.com|afternic|hugedomains|seohulp|mooiedomeinnaam|undeveloped|domain(s)? (is )?for sale|buy this domain|parkingcrew|bodis|godaddy|namecheap|spaceship', re.I)
COMMON = set('city county town village state district metro transit court lines construction services service group holdings company industries technologies technology solutions systems '
             'healthcare health medical care injury law legal projects project management consulting capital partners associates international global national american united '
             'general first new north south east west central pacific atlantic royal premier quality best'.split())
INST = re.compile(r'\b(st|ste|saint|san|santa|sao|são|sankt|holy|sacred|our lady|christ|church|parish|diocese|cathedral|chapel|temple|mosque|synagogue|'
                  r'anglican|catholic|baptist|methodist|lutheran|presbyterian|evangelical|islamic|jewish|primary school|elementary school|high school|'
                  r'secondary school|grammar school|school district|public schools?|kindergarten|academy|college|unified)\b', re.I)
ORGWORD = re.compile(r'\b(inc|incorporated|llc|ltd|limited|plc|gmbh|ag|sa|srl|spa|bv|nv|corp|corporation|co|company|group|holdings?|bank|school|college|university|'
                     r'hospital|clinic|association|foundation|society|council|city|county|municipality|ministry|department|authority|agency|church|institute|'
                     r'academy|club|partners|associates|lab|labs|laboratories|industries|services|solutions|systems|technologies|board|commission|bureau|office|trust|fund|union|kk|oy|ab|as|aps|ltda|sarl|pty)\b', re.I)
CCTLD = {'uk': 'GB', 'de': 'DE', 'fr': 'FR', 'it': 'IT', 'es': 'ES', 'nl': 'NL', 'br': 'BR', 'au': 'AU', 'ca': 'CA', 'ch': 'CH', 'at': 'AT', 'be': 'BE', 'dk': 'DK',
         'se': 'SE', 'no': 'NO', 'cz': 'CZ', 'pl': 'PL', 'mx': 'MX', 'za': 'ZA', 'in': 'IN', 'jp': 'JP', 'ar': 'AR', 'co': 'CO', 'cl': 'CL', 'pe': 'PE', 'tw': 'TW',
         'th': 'TH', 'sg': 'SG', 'my': 'MY', 'tr': 'TR', 'il': 'IL', 'kr': 'KR', 'pt': 'PT', 'fi': 'FI', 'ie': 'IE', 'gr': 'GR', 'hu': 'HU', 'ro': 'RO', 'nz': 'NZ', 'us': 'US'}
# F6 (advisor, 2026-10-21): hidden-name words and masking characters; Wikidata hits that describe a person.
HIDDEN = re.compile(r'^\W*(removed|classified|confidential|redacted|hidden|undisclosed|anonymous|unknown|private|secret|deleted|censored|withheld)\W*$', re.I)
MASKCH = re.compile(r'[?*•●■▇█▒░…_#]')
WD_PERSON = re.compile(r'\b(born \d|\(\d{4}\s*[-–]|\bpolitician\b|\bactor\b|\bactress\b|\bsinger\b|\bfootballer\b|\bplayer\b|\bwriter\b|\bauthor\b|'
                       r'\bjournalist\b|\bbusiness(man|woman|person)\b|\bentrepreneur\b|\blawyer\b|\bphysician\b|\bscientist\b|\bresearcher\b|'
                       r'\bartist\b|\bmusician\b|\bpainter\b|\bathlete\b|\bcoach\b|\bprofessor\b|\bpriest\b|\bbishop\b|\bnurse\b|\bdentist\b|'
                       r'\bfamily name\b|\bgiven name\b|\bsurname\b|\bmale given\b|\bfemale given\b)')


def ntoks(s):
    s = unicodedata.normalize('NFKD', re.sub(r'<[^>]+>', ' ', s or '')).encode('ascii', 'ignore').decode().lower().replace('&', ' and ')
    return [w for w in re.findall(r'[a-z0-9]+', s) if w not in STOP]


def core(s):
    return [w for w in ntoks(s) if w not in LEGALW]


def name_match(name, text, host=None):
    """1.0 = every significant name token appears in the text (or the slugged host); 0 = none."""
    nt = [w for w in core(name) if len(w) >= 2]
    if not nt:
        return 0.0
    tt = set(ntoks(text))
    slug = (host or '').split('.')[0].replace('-', '')
    hit = sum(1 for w in nt if w in tt or (len(w) >= 3 and w in slug))
    s = hit / len(nt)
    if host and ''.join(nt) == slug:
        s = max(s, 1.0)
    return s


def seg(name):
    """The name before ' - ', ' | ', '(' or '|' (trackers append descriptions)."""
    n = re.sub(r'<[^>]+>', ' ', clean(name))
    return re.split(r'\s[-|–]\s|\s?\(|\|', n)[0].strip() or n


def squash(s):
    return re.sub(r'[^a-z0-9]', '', unicodedata.normalize('NFKD', s or '').encode('ascii', 'ignore').decode().lower())


def span_equal(label, text):
    """The squashed label equals a contiguous span of whole tokens of the text (no prefix/substring matches)."""
    lab = squash(label)
    toks = [squash(t) for t in re.findall(r'[\w]+', unicodedata.normalize('NFKD', text or '').encode('ascii', 'ignore').decode().lower())]
    for i in range(len(toks)):
        acc = ''
        for j in range(i, min(len(toks), i + 6)):
            acc += toks[j]
            if acc == lab:
                return True
            if len(acc) >= len(lab):
                break
    return False


def truncated(name, lex: Lexicon):
    """A tracker-truncated name: unbalanced brackets, or >= 40 characters ending in a token no other name uses."""
    n = clean(name)
    if n.count('(') + n.count('（') != n.count(')') + n.count('）') or n.count('[') != n.count(']'):
        return True
    t = re.findall(r'[A-Za-z]+', n)
    return len(n) >= 40 and bool(t) and lex.token_df_distinct.get(t[-1].lower(), 0) <= 1


def inst_name(name):
    """Saint, religious and school-style names collide (many same-named bodies)."""
    return bool(INST.search(clean(name)))


def weak_name(name, lex: Lexicon):
    """Placeholder/announcement wording, or every token generic with no organisation-type word: the registry
    rule (E2) may not decide it."""
    n = clean(name)
    if ANNOUNCE.search(n) or PLACEHOLDER.search(n) or TEST.search(n):
        return True
    if domain_shaped(n):
        return False                                 # a hostname is judged on its own host, not as a phrase
    t = [w for w in core(seg(n)) if len(w) >= 2]
    return bool(t) and all((lex.token_df_distinct.get(w, 0) >= 10 or w in COMMON) for w in t) and not ORGWORD.search(n)


def distinctive(name, lex: Lexicon):
    """At least one name token that is neither common across leak names nor a generic word."""
    t = [w for w in core(seg(clean(name))) if len(w) >= 3]
    return any(lex.token_df_distinct.get(w, 0) < 10 and w not in COMMON for w in t)


def wd_is_person(hit):
    return bool(WD_PERSON.search((hit.get('description') or '').lower()))


def person_shape(name):
    """F6-4b: two or three capitalised alphabetic words with no organisation word: it could be a natural person,
    whatever the given name (the given-name list alone missed most real names in the person test)."""
    n = clean(name).strip()
    if PERSON_ORGWORDS.search(n) or ORGWORD.search(n) or re.search(r'[\d@/\\.&,]', n) or domain_shaped(n):
        return False
    toks = re.findall(r"[^\W\d_][\w'-]*", n)
    return 2 <= len(toks) <= 3 and all(t[0].isupper() for t in toks) and len(n.split()) == len(toks)


def edgar_individual(name, entity):
    """EDGAR lists individual filers as 'LAST FIRST [MIDDLE]': the same tokens and no organisation word."""
    e = re.sub(r'\(.*?\)', '', entity or '')
    if PERSON_ORGWORDS.search(e) or ORGWORD.search(e):
        return False
    return set(core(e)) >= set(core(name)) and len(core(e)) <= len(core(name)) + 1


def f6_rule(name, rule):
    """F6-3: hidden-name words are masked; gibberish with masking characters is masked; other gibberish abstains."""
    n = clean(name)
    if HIDDEN.match(n):
        return 'masked'
    if rule == ('not_org', 'gibberish'):
        if MASKCH.search(n):
            return 'masked'
        return ('ambiguous', 'gibberish_abstain')
    return rule


def second_signal(item, S, host, exclude_p856=False):
    """An independent signal that the host belongs to this victim: tracker-country ccTLD, a leak-post domain,
    a corroborating organisation's domain, or a Wikidata official website."""
    tld = host.rsplit('.', 1)[-1]
    if item.get('country') and CCTLD.get(tld) == (item.get('country') or '').upper():
        return 'country'
    if host in {norm_host(x) for x in S['leakmeta_domains']}:
        return 'A2'
    if any((c.get('domain') or '').lower().endswith(host) for c in S.get('corrob_all', [])):
        return 'A7'
    if not exclude_p856 and any(norm_host(p) == host for h in S.get('wd_all', []) for p in h.get('p856', [])):
        return 'A6'
    return None


def signals(item, ev, lex: Lexicon):
    """item: {claim_key, name_raw, actor, domain, country}; ev: evidence pack {pool, extras, leakmeta, corrob}."""
    name = item['name_raw']
    S = {'rule': name_rule_v21(name, item.get('actor'), lex.actor_norms),
         'person_like': person_like(clean(name)), 'domain_shaped': domain_shaped(name)}
    nm = seg(name)
    if S['domain_shaped']:
        nm = registrable_label(clean(name).strip()).replace('-', ' ')
    cands = ev['pool'].get('candidates', [])
    extras = ev['extras'] or {}
    tls = extras.get('tls', {}) or {}
    pages = extras.get('pages', []) or []
    ph = extras.get('pages_host')
    best = []
    for c in cands:
        if not c.get('live'):
            continue
        src = set(x.split(':')[0] for x in c['sources'])
        texts = {'title': c.get('title') or '', 'og': c.get('og_site_name') or '', 'certO': (tls.get(c['host']) or {}).get('O') or ''}
        if ph == c['host']:
            texts['page'] = ' '.join((p.get('title') or '') + ' ' + (p.get('h1') or '') for p in pages if p.get('status') == 200)
        m = {k: max(name_match(nm, v), 1.0 if (S['domain_shaped'] and len(squash(nm)) >= 4 and span_equal(nm, v)) else 0.0)
             for k, v in texts.items() if v}
        if MARKET.search(c['host']) or MARKET.search(texts['title']):
            continue
        best.append({'host': c['host'], 'src': src, 'origin': [x.split(':', 1)[1] for x in c['sources'] if x.startswith('redirect_of:')],
                     'm_title': max([m.get('title', 0), m.get('og', 0)]), 'm_cert': m.get('certO', 0), 'm_page': m.get('page', 0),
                     'title': texts['title'][:80]})
    S['cands'] = best
    S['raw_cands'] = cands
    S['tracker_live'] = [b for b in best if b['src'] & TR]
    wd = ev['pool'].get('wikidata', []) or []
    S['wd_all'] = wd
    S['wd_match'] = [h for h in wd if name_match(nm, h.get('label') or '') >= 1.0 and name_match(h.get('label') or '', nm) >= 0.99]
    gl = [g for g in (extras.get('gleif') or []) if isinstance(g, dict) and g.get('name')]
    S['gleif_match'] = [g for g in gl if name_match(nm, g['name']) >= 1.0 and name_match(g['name'], nm) >= 0.99]
    ed = [g for g in (extras.get('edgar') or []) if isinstance(g, dict) and g.get('entity')]
    S['edgar_match'] = [g for g in ed if name_match(nm, re.sub(r'\(.*?\)', '', g['entity'])) >= 1.0
                        and name_match(re.sub(r'\(.*?\)', '', g['entity']), nm) >= 0.99]
    lm = ev.get('leakmeta') or {}
    lmd = set(lm.get('desc_domains') or []) | ({norm_host(lm['rf_website'])} if lm.get('rf_website') else set())
    S['leakmeta_domains'] = sorted(lmd)
    S['leakmeta_live'] = [b for b in best if b['host'] in {norm_host(x) for x in lmd}]
    S['corrob_all'] = ev.get('corrob', []) or []
    S['corrob'] = [c for c in S['corrob_all'] if len(core(c.get('display_name') or ''))
                   and (c.get('other_sources') or c.get('regulator_filed') or c.get('victim_confirmed'))
                   and name_match(nm, c.get('display_name') or '') >= 1.0]
    return S


def _origin_sources(b, cmap):
    out = set()
    for o in b['origin']:
        oc = cmap.get(o)
        if oc:
            out |= set(x.split(':')[0] for x in oc['sources'])
    return out


def decide(item, S, lex: Lexicon):
    """The production cascade. Returns {label, subtype?, via, used (set), domain?, natural_person_risk?}."""
    name = item['name_raw']
    # A1 name rules, with the F6 fixes: masked -> redacted; gibberish without mask characters abstains
    rule = f6_rule(name, S['rule'])
    if isinstance(rule, tuple) and rule[0] == 'ambiguous':
        return {'label': 'ambiguous', 'subtype': rule[1], 'via': 'F6', 'used': {'A1'}}
    if rule == 'masked':
        return {'label': 'redacted_unresolved', 'via': 'mask', 'used': {'A1'}}
    if rule:
        return {'label': rule[0], 'subtype': rule[1], 'via': 'A1', 'used': {'A1'}}
    # E1: a live site whose title, og:site_name, certificate O= or about page names the entity
    hits = []
    cmap = {c['host']: c for c in S.get('raw_cands', [])}
    ct = core(seg(name))
    short_name = len(ct) == 1 and len(ct[0]) <= 4
    for b in S['cands']:
        srcs = b['src']
        origin_src = _origin_sources(b, cmap)
        tracker = bool(srcs & TR or origin_src & TR)
        allowed = (tracker or 'slug_guess' in srcs or 'slug_guess' in origin_src
                   or any(x.startswith('wikidata_p856') for x in srcs) or any(x.startswith('wikidata_p856') for x in origin_src))
        if allowed and not tracker and short_name:
            allowed = False                          # short/acronym names: guessed hosts never decide
        if allowed and S['domain_shaped'] and not tracker:
            allowed = False                          # a domain name is judged on its own host only
        if b in S['leakmeta_live']:
            allowed = True                           # A2: the leak post names this host
        if not allowed:
            continue
        if max(b['m_title'], b['m_cert'], b['m_page']) >= 1.0:
            hits.append(b)
    if S['tracker_live'] and not hits:
        tl = S['tracker_live'][0]
        if tl['m_title'] > 0 or tl['m_cert'] > 0 or tl['m_page'] > 0:
            hits.append(tl)
    # F6-4b: a person-shaped name is decided by a site only through the leak tracker's own domain; a guessed site
    # titled with the name is as often the person's own page
    if hits and person_shape(name):
        hits = [h for h in hits if h['src'] & {'tracker_domain'}]
        if not hits:
            return {'label': 'ambiguous', 'subtype': 'no_evidence', 'via': 'person_guard', 'used': {'A1'},
                    'natural_person_risk': True}
    if hits:
        if len({h['host'] for h in hits}) > 1:
            pri = [h for h in hits if h['src'] & TR or any(x.startswith('wikidata_p856') for x in h['src'])]
            if len({h['host'] for h in pri}) == 1:
                hits = pri
            else:
                titles = {re.sub(r'\W', '', h['title'].lower())[:30] for h in hits}
                if len(titles) > 1 and not S['domain_shaped']:
                    # F6-1: several entities carry the name -> real, no domain; never for a person, a weak,
                    # an undistinctive or a truncated name
                    f6_block = S['person_like'] or weak_name(name, lex) or not distinctive(name, lex)
                    if not f6_block and not truncated(name, lex):
                        return {'label': 'real_org', 'domain': None, 'via': 'multi_host_real', 'used': {'A3', 'A5'}}
                    return {'label': 'ambiguous', 'subtype': 'multi_candidate', 'via': 'multi_host', 'used': {'A3', 'A5'},
                            'natural_person_risk': bool(S['person_like'])}
        h = hits[0]
        u = {'A3'} | ({'A5'} if 'slug_guess' in h['src'] else set()) | ({'A2'} if h in S['leakmeta_live'] else set())
        dom = h['host']
        # Identity guard (all_slug, p856 guard): a host nobody named needs a second independent signal for its domain
        from_p856 = any(x.startswith('wikidata_p856') for x in h['src'])
        if not (h['src'] & TR) and h not in S['leakmeta_live']:
            second = second_signal(item, S, dom, exclude_p856=from_p856)
            if not second:
                dom = None
            else:
                u.add(second)
        # Institution guard: saint/religious/school names need a country or registry signal
        if dom and inst_name(name):
            sec = second_signal(item, S, dom)
            if sec not in ('country', 'A6') and not (S['wd_match'] or S['gleif_match']):
                dom = None
        return {'label': 'real_org', 'domain': dom, 'via': 'E1', 'used': u}
    # E2: an exact registry match (Wikidata non-person, GLEIF, EDGAR), never for a person-like or weak name
    wd_ok = [h for h in S['wd_match'] if not wd_is_person(h)] if not S['person_like'] else []
    gl_ok, ed_ok = S['gleif_match'], S['edgar_match']
    if person_shape(name):
        # F6-4b: Wikidata items named like a person are usually named after one (school, ship, prize); GLEIF holds
        # 'c/o <person>' records and owner-named firms; EDGAR lists individual filers. None separates a person.
        wd_ok, gl_ok = [], []
        ed_ok = [g for g in ed_ok if not edgar_individual(name, g.get('entity'))]
    if (wd_ok or gl_ok or ed_ok) and not weak_name(name, lex):
        return {'label': 'real_org', 'domain': None, 'via': 'E2', 'used': {'A6'}}
    # E3: an organisation the breach tables already corroborate under the same name
    if S['corrob']:
        return {'label': 'real_org', 'domain': None, 'via': 'E3', 'used': {'A7'}}
    return {'label': 'ambiguous', 'subtype': 'no_evidence', 'via': 'none', 'used': set(),
            'natural_person_risk': bool(S['person_like'])}


def check(item, pack, lex: Lexicon) -> dict:
    """signals + decide, normalised to the stored row shape."""
    d = decide(item, signals(item, pack, lex), lex)
    return {'label': d['label'], 'subtype': d.get('subtype'), 'via': d['via'], 'used': sorted(d.get('used') or []),
            'natural_person_risk': bool(d.get('natural_person_risk', False)), 'domain_candidate': d.get('domain')}


# =====================================================================================================
# Evidence packs
# =====================================================================================================
def _scrub(x):
    """Postgres jsonb refuses NUL in strings; web titles occasionally carry one."""
    if isinstance(x, str):
        return x.replace('\x00', '')
    if isinstance(x, list):
        return [_scrub(v) for v in x]
    if isinstance(x, dict):
        return {k: _scrub(v) for k, v in x.items()}
    return x


def make_pack(pool, extras, leakmeta, corrob) -> dict:
    """One claim-independent pack: the claim_key fields are dropped so every claim in a name group shares it."""
    strip = lambda d: {k: v for k, v in (d or {}).items() if k != 'claim_key'}  # noqa: E731
    return _scrub({'pool': strip(pool) if pool else {'candidates': [], 'wikidata': []},
                   'extras': strip(extras),
                   'leakmeta': strip(leakmeta) if leakmeta else None,
                   'corrob': sorted((strip(c) for c in (corrob or [])), key=lambda c: json.dumps(c, sort_keys=True))})


def pack_sha256(pack) -> str:
    return hashlib.sha256(json.dumps(pack, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()


# Domains a leak post names. The regex runs here, in SQL: the post text never leaves the database.
LEAKMETA_SQL = r"""
with lc as (select l.claim_key, r->>'source_id' sid, r->>'id' rid
              from breach_core.leak_claims l, jsonb_array_elements(l.tracker_refs) r
             where l.claim_key = any(%(keys)s)),
sr as (select lc.claim_key, lc.sid, s.record
         from lc join breach_raw.source_records s on s.source_id = lc.sid and s.source_record_id = lc.rid)
select claim_key,
  array(select distinct lower(m[1]) from sr s2,
               regexp_matches(coalesce(s2.record->>'description',''), '(?:https?://)?(?:www\.)?((?:[a-z0-9][a-z0-9-]{0,61}\.)+(?:com|net|org|edu|gov|co|io|biz|info|de|fr|it|es|uk|ca|au|br|mx|jp|nl|ch|at|be|pl|in|us|cz|dk|se|no|fi|pt|ar|cl|co\.uk|com\.au|com\.br))\M', 'gi') m
         where s2.claim_key = sr.claim_key and s2.sid = 'ransomlook' and m[1] !~* '\.onion' order by 1) desc_domains,
  max(case when sid = 'ransomfeed' then nullif(trim(record->>'website'),'') end) rf_website,
  max(case when sid = 'ransomfeed' then nullif(trim(record->>'work_sector'),'') end) rf_sector,
  bool_or(sid = 'ransomlook' and coalesce(record->>'description','') <> '') has_desc
from sr group by claim_key
"""

# Organisations the breach tables hold under the claim's normalised name, alias or exact domain, with
# their incidents' evidence flags and non-leak sources.
CORROB_SQL = """
with lc as (select l.claim_key, l.victim_norm, nullif(lower(l.victim_domain),'') d
              from breach_core.leak_claims l where l.claim_key = any(%(keys)s)),
o as (select lc.claim_key, og.org_id, og.display_name, og.domain, og.country, og.sec_cik,
             case when og.norm_name = lc.victim_norm then 'norm_name' else 'domain' end how
        from lc join breach_core.organizations og
          on og.norm_name = lc.victim_norm or (lc.d is not null and lower(og.domain) = lc.d) or lc.victim_norm = any(og.alias_norms))
select o.claim_key, o.display_name, o.domain, o.country, o.sec_cik is not null has_cik, o.how,
  bool_or(i.regulator_filed) regulator_filed, bool_or(i.victim_confirmed) victim_confirmed, bool_or(i.media_reported) media_reported,
  array_agg(distinct s.source_id) filter (where s.source_id not in ('ransomlook','ransomfeed')) other_sources
from o join breach_core.incidents i on i.org_id = o.org_id
       left join breach_core.incident_sources s on s.incident_id = i.incident_id
group by 1,2,3,4,5,6
"""

CLAIM_COLS = "claim_key, victim_name, actor_group, victim_domain, country"


def _item(row):
    k, name, actor, domain, country = row
    return {'claim_key': k, 'name_raw': name, 'actor': actor, 'domain': domain, 'country': country}


def _group_key(it):
    return (it['name_raw'], it['domain'], it['country'], it['actor'])


def _rows_as_dicts(cur):
    cols = [d.name for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def read_leakmeta(cur, keys) -> dict:
    cur.execute(LEAKMETA_SQL, {'keys': list(keys)})
    return {r['claim_key']: r for r in _rows_as_dicts(cur)}


def read_corrob(cur, keys) -> dict:
    cur.execute(CORROB_SQL, {'keys': list(keys)})
    out = collections.defaultdict(list)
    for r in _rows_as_dicts(cur):
        if r.get('other_sources') is not None:
            r['other_sources'] = sorted(r['other_sources'])
        out[r['claim_key']].append(r)
    return out


def _timeouts(cur):
    cur.execute(f"set local statement_timeout = '{STATEMENT_TIMEOUT}'")
    cur.execute(f"set local lock_timeout = '{LOCK_TIMEOUT}'")


def write(conn, evidence_rows, check_rows) -> int:
    """evidence_rows: (claim_key, harvested_at, pack, sha); check_rows: (claim_key, check dict, sha, lexicon_sha).
    One transaction, pipelined batches (the runner->database round trip is ~100 ms). Returns new raw rows."""
    from psycopg.types.json import Jsonb
    new = 0
    with conn.transaction(), conn.cursor() as cur:
        _timeouts(cur)
        for i in range(0, len(evidence_rows), BATCH):
            part = evidence_rows[i:i + BATCH]
            cur.execute("""insert into breach_raw.victim_evidence (claim_key, method_version, harvested_at, pack, pack_sha256)
                           select x.k, %s, x.h, x.p, x.s
                             from unnest(%s::text[], %s::timestamptz[], %s::jsonb[], %s::text[]) as x(k, h, p, s)
                           on conflict (claim_key, pack_sha256) do nothing""",
                        (METHOD, [r[0] for r in part], [r[1] for r in part], [Jsonb(r[2]) for r in part], [r[3] for r in part]))
            new += cur.rowcount
        for i in range(0, len(check_rows), BATCH):
            part = check_rows[i:i + BATCH]
            cur.execute("""insert into breach_core.victim_checks
                               (claim_key, label, subtype, via, used, natural_person_risk, domain_candidate,
                                method_version, evidence_sha256, lexicon_sha256, checked_at)
                           select x.k, x.l, x.st, x.v, string_to_array(x.u, ','), x.npr, x.d, %s, x.s, x.ls, now()
                             from unnest(%s::text[], %s::text[], %s::text[], %s::text[], %s::text[], %s::boolean[],
                                         %s::text[], %s::text[], %s::text[]) as x(k, l, st, v, u, npr, d, s, ls)
                           on conflict (claim_key) do update set
                               label = excluded.label, subtype = excluded.subtype, via = excluded.via, used = excluded.used,
                               natural_person_risk = excluded.natural_person_risk, domain_candidate = excluded.domain_candidate,
                               method_version = excluded.method_version, evidence_sha256 = excluded.evidence_sha256,
                               lexicon_sha256 = excluded.lexicon_sha256, checked_at = excluded.checked_at""",
                        (METHOD, [r[0] for r in part], [r[1]['label'] for r in part], [r[1]['subtype'] for r in part],
                         [r[1]['via'] for r in part], [','.join(r[1]['used']) for r in part],
                         [r[1]['natural_person_risk'] for r in part], [r[1]['domain_candidate'] for r in part],
                         [r[2] for r in part], [r[3] for r in part]))
    return new


def _fan_out(rep_item, members, pack, harvested_at, lex, lex_sha, report):
    """The representative's pack and decision, applied to every claim of its name group."""
    sha = pack_sha256(pack)
    d = check(rep_item, pack, lex)
    report['labels'][d['label']] += len(members)
    report['via'][d['via']] += len(members)
    if d['natural_person_risk']:
        report['natural_person_risk'] += len(members)
    if d['domain_candidate']:
        report['with_domain'] += len(members)
    ev = [(k, harvested_at, pack, sha) for k in members]
    ck = [(k, d, sha, lex_sha) for k in members]
    return ev, ck


def _new_report(mode):
    return {'mode': mode, 'method_version': METHOD, 'claims': 0, 'groups': 0, 'raw_new': 0, 'checks_written': 0,
            'labels': collections.Counter(), 'via': collections.Counter(), 'natural_person_risk': 0, 'with_domain': 0}


def _finish(report, t0):
    report['labels'] = dict(sorted(report['labels'].items()))
    report['via'] = dict(sorted(report['via'].items()))
    report['seconds'] = round(time.time() - t0, 1)
    return report


# =====================================================================================================
# Commands
# =====================================================================================================
def select_claims(cur, limit, now=None):
    """Unchecked claims first (newest first), then undecided checks (ambiguous on evidence, not on the name
    alone) older than 90 days, oldest check first."""
    now = now or datetime.now(timezone.utc)
    cur.execute(f"""select {CLAIM_COLS} from breach_core.leak_claims l
                     where not exists (select 1 from breach_core.victim_checks c where c.claim_key = l.claim_key)
                     order by first_seen_at desc, claim_key limit %s""", (limit,))
    rows = [_item(r) for r in cur.fetchall()]
    if len(rows) < limit:
        cur.execute(f"""select {', '.join('l.' + c.strip() for c in CLAIM_COLS.split(','))}
                          from breach_core.leak_claims l join breach_core.victim_checks c using (claim_key)
                         where c.label = 'ambiguous' and c.via <> 'F6' and c.checked_at < %s
                         order by c.checked_at, l.claim_key limit %s""", (now - RECHECK_AFTER, limit - len(rows)))
        rows += [_item(r) for r in cur.fetchall()]
    return rows


def cmd_run(conn, limit, deadline_min, workers=8, harvester=None, flush_every=50):
    """Harvest, store the raw pack, decide and upsert, for up to `limit` claims. Stops starting new name groups
    at the deadline; whatever was harvested is written."""
    import concurrent.futures as cf
    from . import reality_harvest as H
    t0 = time.time()
    deadline = t0 + deadline_min * 60
    report = _new_report('run')
    with conn.transaction(), conn.cursor() as cur:
        _timeouts(cur)
        lex = read_lexicon(cur)
        items = select_claims(cur, limit)
        keys = [it['claim_key'] for it in items]
        lm, co = read_leakmeta(cur, keys), read_corrob(cur, keys)
    lex_sha = lex.sha256()
    groups = collections.OrderedDict()
    for it in items:
        groups.setdefault(_group_key(it), []).append(it)
    harvester = harvester or (lambda it: H.harvest(it, lex.actor_norms))
    report['selected'] = len(items)
    report['harvest'] = collections.Counter()
    ev_buf, ck_buf = [], []

    def flush():
        report['raw_new'] += write(conn, ev_buf, ck_buf) if (ev_buf or ck_buf) else 0
        report['checks_written'] += len(ck_buf)
        ev_buf.clear()
        ck_buf.clear()

    todo = list(groups.values())
    with cf.ThreadPoolExecutor(workers) as ex:
        running = {}
        done_n = 0
        while todo or running:
            while todo and len(running) < workers and time.time() < deadline:
                g = todo.pop(0)
                running[ex.submit(harvester, g[0])] = g
            if not running:
                break
            finished, _ = cf.wait(list(running), return_when=cf.FIRST_COMPLETED)
            for f in finished:
                g = running.pop(f)
                rep = g[0]
                try:
                    pool, extras, harvested_at = f.result()
                except Exception as e:  # noqa: BLE001 - counted by type only (public log)
                    report['harvest']['error_' + type(e).__name__] += 1
                    continue
                report['harvest']['skipped_never_fetch' if pool.get('skipped') else 'harvested'] += 1
                pack = make_pack(pool, extras, lm.get(rep['claim_key']), co.get(rep['claim_key']))
                members = [it['claim_key'] for it in g]
                ev, ck = _fan_out(rep, members, pack, harvested_at, lex, lex_sha, report)
                ev_buf.extend(ev)
                ck_buf.extend(ck)
                report['groups'] += 1
                report['claims'] += len(members)
                done_n += 1
                if done_n % flush_every == 0:
                    flush()
            if time.time() >= deadline and todo:
                report['deadline_stopped'] = True
    flush()
    report['groups_left'] = len(todo)
    report['harvest'] = dict(report['harvest'])
    return _finish(report, t0)


def _jsonl(path):
    out = {}
    with open(path, encoding='utf-8') as fh:
        for line in fh:
            if line.strip():
                r = json.loads(line)
                out[r['claim_key']] = r
    return out


def cmd_load_packs(conn, pool_path, extras_path, groups_path, harvested_at=None):
    """Load packs harvested elsewhere (same harvester). groups: {representative claim_key: [claim_keys]}; every
    claim of a group gets the representative's pack and decision. Re-loading writes no new raw row."""
    t0 = time.time()
    report = _new_report('load-packs')
    pools, extras = _jsonl(pool_path), _jsonl(extras_path)
    with open(groups_path, encoding='utf-8') as fh:
        groups = json.load(fh)
    harvested_at = harvested_at or datetime.fromtimestamp(os.path.getmtime(pool_path), timezone.utc)
    reps = [k for k in groups if k in pools]
    report['groups_without_pool'] = len(groups) - len(reps)
    report['extras_missing'] = sum(1 for k in reps if k not in extras)
    with conn.transaction(), conn.cursor() as cur:
        _timeouts(cur)
        lex = read_lexicon(cur)
        all_keys = sorted({k for r in reps for k in groups[r]} | set(reps))
        cur.execute(f"select {CLAIM_COLS} from breach_core.leak_claims where claim_key = any(%s)", (all_keys,))
        known = {r[0]: _item(r) for r in cur.fetchall()}
        lm, co = read_leakmeta(cur, reps), read_corrob(cur, reps)
    lex_sha = lex.sha256()
    ev_all, ck_all = [], []
    for rep in reps:
        if rep not in known:
            report['rep_not_in_db'] = report.get('rep_not_in_db', 0) + 1
            continue
        members = [k for k in dict.fromkeys(groups[rep] + [rep]) if k in known]
        report['members_not_in_db'] = report.get('members_not_in_db', 0) + len(set(groups[rep]) - set(known))
        pack = make_pack(pools[rep], extras.get(rep), lm.get(rep), co.get(rep))
        ev, ck = _fan_out(known[rep], members, pack, harvested_at, lex, lex_sha, report)
        ev_all += ev
        ck_all += ck
        report['groups'] += 1
        report['claims'] += len(members)
    report['raw_new'] = write(conn, ev_all, ck_all)
    report['checks_written'] = len(ck_all)
    return _finish(report, t0)


def cmd_decide(conn):
    """Re-decide every claim from its latest stored pack. No network."""
    t0 = time.time()
    report = _new_report('decide')
    with conn.transaction(), conn.cursor() as cur:
        _timeouts(cur)
        lex = read_lexicon(cur)
        cur.execute(f"""select {', '.join('l.' + c.strip() for c in CLAIM_COLS.split(','))}, e.pack, e.pack_sha256
                          from (select distinct on (claim_key) claim_key, pack, pack_sha256 from breach_raw.victim_evidence
                                 order by claim_key, harvested_at desc, evidence_id desc) e
                          join breach_core.leak_claims l using (claim_key)
                         order by l.claim_key""")
        rows = cur.fetchall()
    lex_sha = lex.sha256()
    ck = []
    for r in rows:
        it, pack, sha = _item(r[:5]), r[5], r[6]
        d = check(it, pack, lex)
        report['labels'][d['label']] += 1
        report['via'][d['via']] += 1
        report['natural_person_risk'] += d['natural_person_risk']
        report['with_domain'] += bool(d['domain_candidate'])
        ck.append((it['claim_key'], d, sha, lex_sha))
    write(conn, [], ck)
    report['claims'] = report['checks_written'] = len(ck)
    return _finish(report, t0)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog='zdc-breach-reality', description=__doc__.split('\n')[0])
    sub = ap.add_subparsers(dest='cmd', required=True)
    r = sub.add_parser('run', help='harvest, store, decide and upsert unchecked / stale undecided claims')
    r.add_argument('--limit', type=int, default=500)
    r.add_argument('--deadline-min', type=float, default=30)
    r.add_argument('--workers', type=int, default=8)
    lp = sub.add_parser('load-packs', help='load locally harvested packs')
    lp.add_argument('--pool', required=True)
    lp.add_argument('--extras', required=True)
    lp.add_argument('--groups', required=True)
    lp.add_argument('--harvested-at', help='ISO timestamp (default: the pool file mtime)')
    sub.add_parser('decide', help='re-decide every latest stored pack (no network)')
    ap.add_argument('--report', help='write the counts-only JSON report here')
    args = ap.parse_args(argv)
    import psycopg
    conn = psycopg.connect(os.environ['DATABASE_URL'], autocommit=True)
    code = 0
    if args.cmd == 'run':
        rep, code = run_recorded(conn, args.limit, args.deadline_min, args.workers)
    elif args.cmd == 'load-packs':
        ha = datetime.fromisoformat(args.harvested_at) if args.harvested_at else None
        rep = cmd_load_packs(conn, args.pool, args.extras, args.groups, ha)
    else:
        rep = cmd_decide(conn)
    text = json.dumps(rep, indent=2, sort_keys=True, default=str)
    if args.report:
        with open(args.report, 'w') as fh:
            fh.write(text)
    print(text)
    return code


PIPELINE = 'breach-reality'
OUTAGE_MIN_CLAIMS = 50


def run_recorded(conn, limit, deadline_min, workers, harvester=None):
    """One recorded run (raw.pipeline_runs, watched by tools/watchdog.py). A run fails when it raises, or when it
    checked >= 50 claims and decided not one real organisation: about a quarter are real on every sealed set, so zero
    means the network or a source failed, and an outage must never read as 'no organisation found'."""
    from zdc_kev import db as runs_db
    run_id = runs_db.start_run(conn, PIPELINE, 'incremental', os.environ.get('GITHUB_EVENT_NAME') or 'manual',
                               os.environ.get('GITHUB_SHA'))
    try:
        rep = cmd_run(conn, limit, deadline_min, workers, harvester=harvester)
    except Exception as e:
        runs_db.finish_run(conn, run_id, ok=False, error=type(e).__name__)
        raise
    real = (rep.get('labels') or {}).get('real_org', 0)
    outage = rep.get('claims', 0) >= OUTAGE_MIN_CLAIMS and real == 0
    runs_db.finish_run(conn, run_id, ok=not outage, error='no real organisation among %d checked: outage?' % rep['claims'] if outage else None,
                       entries_seen=rep.get('claims', 0), entries_inserted=rep.get('checks_written', 0),
                       notes={'raw_new': rep.get('raw_new', 0), 'real_org': real, 'groups': rep.get('groups', 0)})
    return rep, (6 if outage else 0)


if __name__ == '__main__':
    sys.exit(main())
