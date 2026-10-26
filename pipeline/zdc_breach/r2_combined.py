"""R2 combined Jev classifier (owner's decision, 2026-10-26): ONE Jev question set per victim that answers breach type,
industry, data classes, company size and country, with the "is this a real organisation" gate lowered to 0.30.

It is modelled on the owner's hand-run query (state v = name, domain, source kind, listing, text) and on r2_classify's
conventions: candidate values go to the PRIVATE breach_core.r2_values (engine 'jev', engine_version `r2c-combined-v1`), the
raw Jev answers to the insert-only breach_core.r2_answers (the reproducible unit; `run --no-jev` re-derives every value from
them with no network). Nothing here changes a public object: a stratum reaches the shadow's released flags only through
breach_core.r2_field_release (see r2_combined_score.py, which measures precision against the adjudicated gate labels and
writes the release SQL).

Subjects  every row of breach_core.r2_victims_shadow (claim:<key> | incident:<uuid>).
Evidence  claim     the tracker description (ransomlook first, DESC_LATERAL order), listing = "The ransomware group <actor>
                    listed this organisation as a victim on its leak site on <date>."
          incident  the record's own words (HIBP description / CRA summary / regulator fields rendered as plain text) and,
                    separately, the news sentences that name the victim (r2_classify.press_sentences).
          no text   name + domain only: accept ONLY industry, and only when the name plainly shows it.
Rules     * is_victim_org (noul) >= 0.30 -> the text is used; below it the text is not used and the subject falls back to
            name-only (industry only).
          * choice fields (breach type, industry, size, country): top p >= 0.80 and the top is a real class (not unclear /
            not_stated / other). Data groups: noul >= 0.50. Country also needs Jev to say the text names a place
            (noul >= 0.50); the quote span is stored when the country's name occurs in the text.
          * breach type of a leak-site subject stays the deterministic ransomware_extortion of r2_classify (not asked).
          * One text item per basis; two text items of one subject that disagree on a single-valued field are both
            rejected as `conflict` ("unknown", the standing conflict rule); name-only industry is used only when no text
            item produced one.
          Acceptance thresholds are the owner's / fixed before measuring and are NOT tuned on any sealed hold-out.
Supersede migration 0190: where a RELEASED combined value exists for a group+field, the older Jev engine versions' values (engine
          'jev' only) are ignored; an UNRELEASED combined value ranks below a surviving old-version value, so it never displaces
          or conflicts with it.

CLI:  python -m zdc_breach.r2_combined run [--pilot N] [--new-only] [--limit N] [--only F] [--max-usd X] [--no-jev] [--write]
                                           [--workers N] [--report F] [--exclude F]
      python -m zdc_breach.r2_combined score [--gold-root DIR] [--out DIR]       (precision vs gold + release SQL)
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures as cf
import hashlib
import json
import os
import random
import re
import sys
import threading
import time

from . import profile
from . import r2_classify as C
from .jev import MODEL, PRICE_PER_MTOK, Budget, BudgetExhausted, Jev, JevError, OutOfFunds

METHOD = 'r2-combined-v1'
V_COMB = 'r2c-combined-v1'
QSET = 'r2-comb-q1'
# The older Jev engine versions this one supersedes for the fields it answers (see migration 0190).
SUPERSEDES = ('r2c-jev-v1', 'r2c-jev-name-v1', 'r2c-industry-v2', 'r2c-industry-v3', 'breach-profile-v1-g1')
FIELDS = ('breach_type', 'industry', 'size_band', 'country', 'data_group')

# Owner thresholds (is_victim_org) and the acceptance rules chosen here before any measurement (never tuned on a hold-out).
TAU = {'victim': 0.30,          # owner: "can be pretty low"
       'choice': 0.80,          # top class of a choice question
       'group': 0.50,           # data-group noul
       'country_named': 0.50,   # the text names a place
       'name_obvious': 0.80,    # name-only: the name itself plainly says what it is (frozen r2_classify value)
       }
PER_CALL = 4
PER_CALL_NAME = 10
WORKERS = 12
CHUNK = 600                     # subjects per load/ask/write cycle (bounds memory, makes the run resumable)
TEXT_MAX = 3000
STATEMENT_TIMEOUT = C.STATEMENT_TIMEOUT
WRITE_CHUNK = 2000

SIZE_BANDS = C.SIZE_BANDS
GROUP_Q = {
    'people': 'personal data of customers or other people (names, addresses, ID numbers, contact details)',
    'health': 'health or medical data',
    'finance': 'financial data (bank, card, payment, accounting, tax records)',
    'hr': 'employee / HR data (payroll, staff records)',
    'systems': 'technical data (credentials, source code, system or network data)',
    'documents': 'business documents (contracts, plans, internal files)',
}
BT_CRIT = dict(C.BREACH_TYPES, unclear='The sources do not show the type of breach.')
IND_CRIT = dict(C.INDUSTRIES, unclear='The sources do not show what the organisation does.')
NAME_CRIT = dict(C.INDUSTRIES, unclear='The name and domain do not plainly show what kind of organisation this is.')
SIZE_CRIT = {'lt_250': 'Fewer than 250 employees', '250_4999': '250 to 4,999 employees',
             '5000_plus': '5,000 or more employees', 'not_stated': 'The text does not state or plainly imply a headcount.'}
COUNTRY_NAMES = {
    'US': 'United States', 'GB': 'United Kingdom', 'CA': 'Canada', 'AU': 'Australia', 'NZ': 'New Zealand', 'IE': 'Ireland',
    'DE': 'Germany', 'FR': 'France', 'IT': 'Italy', 'ES': 'Spain', 'PT': 'Portugal', 'NL': 'Netherlands', 'BE': 'Belgium',
    'LU': 'Luxembourg', 'CH': 'Switzerland', 'AT': 'Austria', 'SE': 'Sweden', 'NO': 'Norway', 'DK': 'Denmark',
    'FI': 'Finland', 'IS': 'Iceland', 'PL': 'Poland', 'CZ': 'Czechia', 'SK': 'Slovakia', 'HU': 'Hungary', 'RO': 'Romania',
    'BG': 'Bulgaria', 'GR': 'Greece', 'HR': 'Croatia', 'RS': 'Serbia', 'UA': 'Ukraine', 'RU': 'Russia', 'TR': 'Turkey',
    'IL': 'Israel', 'AE': 'United Arab Emirates', 'SA': 'Saudi Arabia', 'QA': 'Qatar', 'KW': 'Kuwait', 'EG': 'Egypt',
    'ZA': 'South Africa', 'NG': 'Nigeria', 'KE': 'Kenya', 'MA': 'Morocco', 'IN': 'India', 'PK': 'Pakistan',
    'BD': 'Bangladesh', 'LK': 'Sri Lanka', 'ID': 'Indonesia', 'MY': 'Malaysia', 'SG': 'Singapore', 'TH': 'Thailand',
    'VN': 'Vietnam', 'PH': 'Philippines', 'JP': 'Japan', 'KR': 'South Korea', 'CN': 'China', 'TW': 'Taiwan',
    'HK': 'Hong Kong', 'BR': 'Brazil', 'MX': 'Mexico', 'AR': 'Argentina', 'CL': 'Chile', 'CO': 'Colombia', 'PE': 'Peru',
}
COUNTRY_ALIASES = {'US': ['United States', 'U.S.', 'USA', 'America'], 'GB': ['United Kingdom', 'U.K.', 'UK', 'Britain', 'England', 'Scotland', 'Wales'],
                   'AE': ['UAE', 'Emirates', 'Dubai', 'Abu Dhabi'], 'KR': ['South Korea', 'Korea'], 'CZ': ['Czechia', 'Czech Republic'],
                   'NL': ['Netherlands', 'Holland'], 'TR': ['Turkey', 'Türkiye'], 'DE': ['Germany', 'Deutschland']}
COUNTRY_CRIT = dict({k: v for k, v in COUNTRY_NAMES.items()},
                    other='A country that is not in this list', unclear='The text does not show where the organisation is based.')
_COUNTRY_RX = {}
for _k, _n in COUNTRY_NAMES.items():
    _alts = sorted({_n, *COUNTRY_ALIASES.get(_k, [])}, key=len, reverse=True)
    _COUNTRY_RX[_k] = re.compile(r'(?<![\w])(?:' + '|'.join(re.escape(a) for a in _alts) + r')(?![\w])')
HEADCOUNT_RX = re.compile(r'(?i)\b(\d[\d,.\s]*\d|\d)\s*\+?\s*(?:full[- ]time\s+)?(employees?|staff|workers|people|colleagues|team members|professionals)\b|'
                          r'\b(?:employ\w*|workforce of|staff of|headcount)\b[^.]{0,40}\d')
SRC_LABEL = {'leak': 'ransomware leak-site post (written by the attackers; untrusted)',
             'index': 'entry in a public data-breach index',
             'regulator': 'government regulator breach notice (structured fields rendered as text)',
             'press': 'sentences from news articles that name the organisation'}
URL_RX = re.compile(r'(?i)(?:https?://|www\.)\S+|\b[a-z2-7]{16,56}\.onion\S*')


# =====================================================================================================
# Text and items
# =====================================================================================================
def clean_text(t, limit=TEXT_MAX):
    t = profile.clean(t or '')
    t = URL_RX.sub(' ', t)
    t = re.sub(r'\s+', ' ', t).strip()
    return t[:limit]


def _fmt(label, v):
    v = '' if v is None else str(v).strip()
    return f'{label}: {v}.' if v and v.lower() not in ('none', 'null', 'n/a') else None


def regulator_text(src, r):
    """A regulator record's own fields as plain sentences (no model, no inference). None when it carries no facts."""
    r = r or {}
    parts = []
    if src == 'hhs_ocr':
        parts = [_fmt('Covered entity type', r.get('entity_type')), _fmt('Type of breach', r.get('type_of_breach')),
                 _fmt('Location of the breached information', r.get('location')), _fmt('State of the covered entity', r.get('state')),
                 _fmt('Business associate involved', r.get('business_associate_present')),
                 _fmt('Individuals affected', r.get('individuals_affected'))]
        head = 'Entry in the US HHS breach portal (protected health information).'
    elif src == 'wa_ag':
        parts = [_fmt('Industry type', r.get('industrytype')), _fmt('Business type', r.get('businesstype')),
                 _fmt('Cause of the breach', r.get('databreachcause')), _fmt('Type of cyberattack', r.get('cyberattacktype')),
                 _fmt('State of the entity', r.get('entitystate')),
                 _fmt('Washington residents affected', r.get('washingtoniansaffected'))]
        head = 'Data breach notice filed with the Washington State Attorney General.'
    elif src == 'de_ag':
        parts = [_fmt('Information breached', r.get('information_breached')), _fmt('How the breach was discovered', r.get('breach_discovered'))]
        head = 'Data breach notice filed with the Delaware Department of Justice.'
    elif src == 'sec_8k':
        sics = ', '.join(str(x) for x in (r.get('sics') or []))
        parts = [_fmt('SIC industry code(s) of the filer', sics), _fmt('Business state of the filer', ','.join(map(str, r.get('biz_states') or [])))]
        head = 'Form 8-K cybersecurity incident disclosure filed with the US SEC.'
    else:
        return None                              # ca_ag: name and dates only
    parts = [p for p in parts if p]
    return (head + ' ' + ' '.join(parts))[:TEXT_MAX] if parts else None


def listing_for(s, extra):
    if s.kind == 'claim' and extra:
        actor, seen = extra
        return (f'The ransomware group {actor} listed this organisation as a victim on its leak site' + (f' on {seen}.' if seen else '.')
                if actor else 'This organisation was listed as a victim on a ransomware leak site.')
    return None


def plan_items(s: C.Subject, extra=None):
    """Jev items of one subject: up to two text items (record words / press sentences) and the name-only item when no
    text exists. Pure."""
    items = []
    leak_site = s.kind == 'claim' or s.leak_site
    base_want = ['industry', 'size_band', 'country', 'data_group'] + ([] if leak_site else ['breach_type'])
    if s.kind == 'claim':
        t = clean_text(s.description) if s.description else ''
        if len(t) >= profile.DESC_MIN:
            items.append({'mode': 'text', 'want': base_want, 'sk': 'leak', 'basis': 'description', 'doc_ref': s.ref,
                          'text': t, 'listing': listing_for(s, extra)})
    else:
        rec = None
        for src, r in s.records:
            if src == 'hibp' and (r or {}).get('Description'):
                rec = ('index', 'description', clean_text(r['Description']), 'Listed in a public data-breach index.', f'{s.ref}#hibp')
                break
            if src == 'cra_export' and (r or {}).get('Summary'):
                rec = ('index', 'description', clean_text(r['Summary']), 'Listed in a curated data-breach database.', f'{s.ref}#cra')
                break
        if rec is None:
            lines = [(src, regulator_text(src, r)) for src, r in s.records]
            lines = [(a, b) for a, b in lines if b]
            if lines:
                rec = ('regulator', 'filing', ' '.join(b for _, b in lines)[:TEXT_MAX], 'Reported to a government regulator.',
                       f'{s.ref}#{lines[0][0]}')
        if rec and len(rec[2]) >= profile.DESC_MIN:
            items.append({'mode': 'text', 'want': base_want, 'sk': rec[0], 'basis': rec[1], 'doc_ref': rec[4], 'text': rec[2],
                          'listing': rec[3]})
        sents = C.press_sentences(s.docs, s.name, s.domain) if s.docs else []
        if sents:
            items.append({'mode': 'text', 'want': base_want, 'sk': 'press', 'basis': 'press_quote', 'doc_ref': f"doc:{s.docs[0]['doc']}",
                          'text': ' '.join(x['text'] for x in sents)[:TEXT_MAX], 'listing': 'Named in news articles about a cyber incident.'})
    for it in items:
        it.update(name=s.name, domain=s.domain, subject=s.ref)
    if not items and s.name:
        items.append({'mode': 'name', 'want': ['industry'], 'sk': name_source_kind(s), 'basis': 'name_only', 'doc_ref': None,
                      'name': s.name, 'domain': s.domain, 'subject': s.ref})
    return items


def name_source_kind(s):
    return 'leak' if s.kind == 'claim' else C._subject_kind(s)


# =====================================================================================================
# Questions
# =====================================================================================================
def item_state(it):
    if it['mode'] == 'name':
        return {'name': it['name'], 'domain': it.get('domain') or 'unknown'}
    return {'name': it['name'], 'domain': it.get('domain') or 'unknown', 'source_kind': SRC_LABEL[it['sk']],
            'listing': it.get('listing') or '', 'text': it['text']}


def questions(pid, mode, want):
    ref = 'items.' + pid
    qs = {f'{pid}_nobv': {'type': 'noul', 'instructions':
              f'Does the organisation name `{ref}.name` itself plainly say what kind of organisation it is (for example '
              '"Hospital", "School District", "Bank", "Law Firm", "City of")?'},
          f'{pid}_nind': {'type': 'choice', 'instructions':
              f'Judging only from the organisation name `{ref}.name` and its web domain `{ref}.domain`, which sector is it '
              'in? Answer unclear unless the name or domain plainly shows it.', 'criteria': NAME_CRIT}}
    if mode == 'name':
        return qs
    ctx = f'Source: `{ref}.source_kind`. `{ref}.listing` Organisation `{ref}.name`. Text: `{ref}.text`. '
    qs[f'{pid}_vic'] = {'type': 'noul', 'instructions': ctx +
        f'Is the text about a real, identifiable organisation named `{ref}.name` (not an advert, hacking tool, news article, '
        'forum post or the attackers themselves)?'}
    qs[f'{pid}_ind'] = {'type': 'choice', 'instructions': ctx +
        "Which class fits the organisation's main business? Answer unclear unless the text or name shows it.", 'criteria': IND_CRIT}
    qs[f'{pid}_size'] = {'type': 'choice', 'instructions': ctx +
        'How many employees does the organisation have? Answer not_stated unless the text states a headcount or plainly implies one.',
        'criteria': SIZE_CRIT}
    qs[f'{pid}_cty'] = {'type': 'choice', 'instructions': ctx + 'In which country is the organisation based?', 'criteria': COUNTRY_CRIT}
    qs[f'{pid}_cnamed'] = {'type': 'noul', 'instructions': ctx +
        f'Does the text name a place (a country, state, province or city) where `{ref}.name` is based or operates?'}
    if 'breach_type' in want:
        qs[f'{pid}_bt'] = {'type': 'choice', 'instructions': ctx + 'Which type of breach is this?', 'criteria': BT_CRIT}
    for g, d in GROUP_Q.items():
        qs[f'{pid}_d_{g}'] = {'type': 'noul', 'instructions': ctx + f'Does the text say that {d} was stolen or exposed?'}
    return qs


def q_hash(kind):
    """Hash of the question set of one item kind (name | text | text_bt) - a changed question is a new engine input."""
    probe = questions('p', 'name' if kind == 'name' else 'text', ('breach_type',) if kind == 'text_bt' else ())
    blob = json.dumps({'qset': QSET, 'model': MODEL, 'q': probe}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()


def kind_of(it):
    return 'name' if it['mode'] == 'name' else ('text_bt' if 'breach_type' in it['want'] else 'text')


_QH = {k: q_hash(k) for k in ('name', 'text', 'text_bt')}


def q_hash_item(it):
    return _QH[kind_of(it)]


def item_sha(it):
    blob = json.dumps({'state': item_state(it), 'want': sorted(it['want']), 'mode': it['mode']}, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode()).hexdigest()


def build_call(items):
    state, qs, meta = {'items': {}}, {}, {}
    for n, it in enumerate(items):
        pid = 'i%d' % (n + 1)
        state['items'][pid] = item_state(it)
        qs.update(questions(pid, it['mode'], it['want']))
        meta[pid] = it
    return state, qs, meta


# =====================================================================================================
# Decisions (pure): stored Jev answers -> values
# =====================================================================================================
def _probs(a):
    return (a or {}).get('probabilities') or {}


def _top(a):
    pr = _probs(a)
    if not pr:
        return None, 0.0
    k = max(pr, key=pr.get)
    return k, float(pr[k])


def _noul(a):
    return float((a or {}).get('noul') or 0.0)


def quote_for(field, value, text):
    """A verbatim sentence of the text that carries the value's cue (best effort; never gates acceptance)."""
    if not text:
        return None
    sents = [x['text'] for x in C.evidence_sentences(text, limit=40)]
    if field == 'country':
        rx = _COUNTRY_RX.get(value)
        return next((s for s in sents if rx and rx.search(s)), None)
    if field == 'size_band':
        return next((s for s in sents if HEADCOUNT_RX.search(s)), None)
    if field == 'data_group':
        for s in sents:
            if C.cue_hit(value, s):
                return s
    return None


def decide_text(it, ans, tau=TAU):
    """Candidate values of one TEXT item. Returns (vals, gate_p): every field in it['want'] gets an accepted value, an
    abstain, or (data groups) one accepted row per stated group."""
    sk, basis, ref, text = it['sk'], it['basis'], it.get('doc_ref'), it['text']
    gate = _noul(ans.get('vic'))
    V = lambda f, v, p=None, **kw: C.Val(f, v, sk, basis, 'jev', V_COMB, jev_p=None if p is None else round(p, 4), doc_ref=ref, **kw)
    out = []
    if gate < tau['victim']:
        for f in it['want']:
            out.append(V(f, None, gate, verdict='abstain', reason='not_victim_org_text'))
        return out, gate
    top, p = _top(ans.get('ind'))
    out.append(V('industry', top, p, quote=None) if top in C.INDUSTRIES and p >= tau['choice']
               else V('industry', None, p, verdict='abstain', reason='unclear_or_low_p'))
    top, p = _top(ans.get('size'))
    out.append(V('size_band', top, p, quote=quote_for('size_band', top, text)) if top in SIZE_BANDS and p >= tau['choice']
               else V('size_band', None, p, verdict='abstain', reason='not_stated_or_low_p'))
    top, p = _top(ans.get('cty'))
    named = _noul(ans.get('cnamed'))
    if top in COUNTRY_NAMES and p >= tau['choice'] and named >= tau['country_named']:
        out.append(V('country', top, p, quote=quote_for('country', top, text)))
    else:
        out.append(V('country', None, p, verdict='abstain',
                     reason='no_place_named' if (top in COUNTRY_NAMES and p >= tau['choice']) else 'unclear_or_low_p'))
    if 'breach_type' in it['want']:
        top, p = _top(ans.get('bt'))
        out.append(V('breach_type', top, p) if top in C.BREACH_TYPES and p >= tau['choice']
                   else V('breach_type', None, p, verdict='abstain', reason='unclear_or_low_p'))
    got = False
    for g in GROUP_Q:
        q = _noul(ans.get('d_' + g))
        if q >= tau['group']:
            out.append(V('data_group', g, q, quote=quote_for('data_group', g, text)))
            got = True
    if not got:
        out.append(V('data_group', None, None, verdict='abstain', reason='no_group_stated'))
    return out, gate


def decide_name(it, ans, sk, tau=TAU):
    """The name-only industry of one item's name answers (own stratum): top p >= choice AND the name plainly says it."""
    top, p = _top(ans.get('nind'))
    obv = _noul(ans.get('nobv'))
    if top in C.INDUSTRIES and p >= tau['choice'] and obv >= tau['name_obvious']:
        return C.Val('industry', top, sk, 'name_only', 'jev', V_COMB, jev_p=round(p, 4))
    return C.Val('industry', None, sk, 'name_only', 'jev', V_COMB, jev_p=round(p, 4), verdict='abstain', reason='name_not_plain')


def finalise(s: C.Subject, items, answers, tau=TAU):
    """All values of one subject from its items' Jev answers; applies the standing conflict rule (two text items that
    disagree on a single-valued field -> both rejected `conflict`, review row). Returns (vals, reviews, victim gates)."""
    sk_name = name_source_kind(s)
    acc, abst, groups, gates = collections.defaultdict(list), collections.defaultdict(list), [], []
    asked = set()
    for it in items:
        ans, key = answers[id(it)]
        asked.update(it['want'])
        if it['mode'] != 'text':
            continue
        vals, g = decide_text(it, ans, tau)
        gates.append(g)
        for v in vals:
            v.answer_key = key
            if v.field == 'data_group' and v.verdict == 'accepted':
                groups.append(v)
            elif v.verdict == 'accepted':
                acc[v.field].append(v)
            else:
                abst[v.field].append(v)
    out, reviews = [], []
    for f in ('breach_type', 'industry', 'size_band', 'country'):
        if f not in asked:
            continue
        vs = acc.get(f, [])
        if len({v.value for v in vs}) > 1:                # sources disagree -> unknown + review; no name-only fallback
            for v in vs:
                v.verdict, v.reason = 'rejected', 'conflict'
            reviews.append({'field': f, 'values': sorted({v.value for v in vs})})
            out.extend(vs)
            continue
        if not vs and f == 'industry':                    # name-only: its own stratum, only when no text gave an industry
            nv = None
            for it in items:
                ans, key = answers[id(it)]
                nv = decide_name(it, ans, sk_name, tau)
                nv.answer_key = key
                if nv.verdict == 'accepted':
                    vs = [nv]
                    break
            if not vs and not abst.get(f):
                abst[f] = [nv]
        if vs:
            out.extend(vs)
        else:
            out.append(abst[f][0] if abst.get(f) else C.Val(f, None, sk_name, 'none', 'jev', V_COMB, verdict='abstain', reason='no_evidence'))
    if 'data_group' in asked:
        if groups:
            out.extend(groups)
        else:
            out.append(abst['data_group'][0] if abst.get('data_group') else
                       C.Val('data_group', None, sk_name, 'none', 'jev', V_COMB, verdict='abstain', reason='no_evidence'))
    return out, reviews, gates


# =====================================================================================================
# Loading
# =====================================================================================================
SUBJECTS_SQL = """
select victim_id, kind, name, lower(domain) from breach_core.r2_victims_shadow
 where victim_id > %(after)s order by victim_id limit %(n)s
"""
CLAIM_META_SQL = "select claim_key, actor_group, first_seen_at::date::text from breach_core.leak_claims where claim_key = any(%(keys)s)"


def iter_pages(conn, page=CHUNK, skip=None, only=None, limit=None):
    """Yield lists of (Subject with evidence, extra) in victim_id order. Read-only."""
    after, n = '', 0
    with conn.cursor() as cur:
        cur.execute(f"set statement_timeout = '{STATEMENT_TIMEOUT}'")
        while True:
            cur.execute(SUBJECTS_SQL, {'after': after, 'n': page * 3})
            rows = cur.fetchall()
            if not rows:
                return
            after = rows[-1][0]
            batch = []
            for vid, kind, name, dom in rows:
                if skip and vid in skip:
                    continue
                if only is not None and vid not in only:
                    continue
                k, _, sid = vid.partition(':')
                batch.append(C.Subject('claim' if k == 'claim' else 'incident', sid, name, dom))
            for i in range(0, len(batch), page):
                part = batch[i:i + page]
                if limit is not None and n + len(part) > limit:
                    part = part[:limit - n]
                if part:
                    yield _load_evidence(cur, part)
                    n += len(part)
                if limit is not None and n >= limit:
                    return


def _load_evidence(cur, batch):
    claims = {s.sid: s for s in batch if s.kind == 'claim'}
    incs = {s.sid: s for s in batch if s.kind == 'incident'}
    extra = {}
    if claims:
        cur.execute(C.CLAIMS_SQL, {'keys': list(claims)})
        for key, sector, country, emp, descr, pg in cur.fetchall():
            s = claims[key]
            s.leak = {'sector': sector, 'country': country, 'employees_stated': emp}
            s.description, s.profile_groups = descr, pg
        cur.execute(CLAIM_META_SQL, {'keys': list(claims)})
        for key, actor, seen in cur.fetchall():
            extra[f'claim:{key}'] = (actor, seen)
    if incs:
        ids = list(incs)
        cur.execute(C.INC_RECORDS_SQL, {'ids': ids})
        for iid, src, rec in cur.fetchall():
            incs[iid].records.append((src, rec))
        cur.execute(C.INC_LEAK_SQL, {'ids': ids})
        for (iid,) in cur.fetchall():
            incs[iid].leak_site = True
        cur.execute(C.INC_DOCS_SQL, {'ids': ids})
        for iid, sha, title, text, src in cur.fetchall():
            incs[iid].docs.append({'doc': sha, 'title': title, 'text': text, 'source_id': src})
        for s in incs.values():
            s.records.sort(key=lambda x: x[0])
            s.docs.sort(key=lambda d: d['doc'])
    return [(s, extra.get(s.ref)) for s in batch]


def done_subjects(conn):
    """victim_ids that already have a combined value row (for --new-only)."""
    with conn.cursor() as cur:
        cur.execute(f"set statement_timeout = '{STATEMENT_TIMEOUT}'")
        cur.execute("select distinct subject_victim_id from breach_core.r2_values where engine_version = %s and subject_victim_id is not null",
                    (V_COMB,))
        return {r[0] for r in cur.fetchall()}


# =====================================================================================================
# Asking Jev
# =====================================================================================================
def ask_items(jev, items, stored, run_id, rep, workers=WORKERS):
    """Answers for items (cached ones reused). Returns ({id(item): (answers, key)}, new answer rows)."""
    res, new_rows, todo = {}, [], {}
    for it in items:
        key = (V_COMB, q_hash_item(it), item_sha(it))
        if key in stored:
            res[id(it)] = (stored[key][1].get('q') or {}, key)
            rep['jev']['items_cached'] += 1
        elif key in todo:
            todo[key].append(it)                            # same input twice in one run: ask once
        else:
            todo[key] = [it]
    firsts = [(k, v[0]) for k, v in todo.items()]
    if jev is None:
        rep['jev']['items_unanswered'] += len(firsts)
        return res, new_rows
    by_kind = collections.defaultdict(list)
    for k, it in firsts:
        by_kind[kind_of(it)].append((k, it))
    chunks = []
    for kind, lst in by_kind.items():
        per = PER_CALL_NAME if kind == 'name' else PER_CALL
        chunks += [lst[i:i + per] for i in range(0, len(lst), per)]
    lock = threading.Lock()

    def one(chunk):
        st, qs, meta = build_call([it for _, it in chunk])
        return chunk, meta, jev.ask(st, qs)

    stop = None
    with cf.ThreadPoolExecutor(workers) as ex:
        futs = [ex.submit(one, ch) for ch in chunks]
        for fu in cf.as_completed(futs):
            try:
                chunk, meta, js = fu.result()
            except (BudgetExhausted, OutOfFunds) as e:
                stop = type(e).__name__
                continue
            except JevError as e:
                rep['jev']['errors'][str(e)] += 1
                continue
            usage = js.get('usage') or {}
            cost = int(usage.get('input_tokens') or 0) * PRICE_PER_MTOK / 1e6 / max(1, len(chunk))
            by_pid = {pid: {k[len(pid) + 1:]: v for k, v in (js.get('answers') or {}).items() if k.startswith(pid + '_')} for pid in meta}
            with lock:
                rep['jev']['calls'] += 1
                for (key, it0), (pid, ans) in zip(chunk, by_pid.items()):
                    if not ans:
                        rep['jev']['errors']['empty_answer'] += 1
                        continue
                    for it in todo[key]:
                        res[id(it)] = (ans, key)
                    new_rows.append({'engine': 'jev', 'engine_version': V_COMB, 'model_id': js.get('model') or MODEL,
                                     'prompt_sha256': key[1], 'input_ref': it0['subject'], 'input_sha256': key[2],
                                     'answer': {'q': ans, 'qset': QSET, 'mode': it0['mode'], 'want': sorted(it0['want'])},
                                     'p': None, 'cost_usd': round(cost, 6), 'run_id': run_id})
    if stop:
        rep['jev']['stopped'] = stop
    return res, new_rows


# =====================================================================================================
# Writing
# =====================================================================================================
def write_chunk_values(conn, subj_vals, run_id):
    """Replace this engine version's values of the chunk's subjects (delete + COPY in one transaction)."""
    kinds = collections.defaultdict(list)
    rows = []
    for s, vals in subj_vals:
        kinds[s.kind].append(s.sid)
        for v in vals:
            rows.append((s.kind, s.sid, v.field, v.value, v.source_kind, v.basis, v.engine, v.engine_version,
                         (v.quote or None) and v.quote[:300], v.doc_ref, v.claim_ref, v.answer_id, v.jev_p, v.verdict, v.reason))
    with conn.transaction(), conn.cursor() as cur:
        C._timeouts(cur)
        for kind, ids in kinds.items():
            cur.execute("delete from breach_core.r2_values where engine_version = %s and subject_kind = %s and subject_id = any(%s)",
                        (V_COMB, kind, ids))
        with cur.copy(f"copy breach_core.r2_values ({', '.join(C.VAL_COLS)}) from stdin") as cp:
            for r in rows:
                cp.write_row(r)
    return len(rows)


# =====================================================================================================
# Reporting (counts only: no names, no text)
# =====================================================================================================
def new_report(mode):
    return {'method': METHOD, 'engine_version': V_COMB, 'mode': mode, 'model': MODEL, 'qset': QSET, 'tau': TAU,
            'subjects': 0, 'items': collections.Counter(), 'gate_fail': 0, 'gate_checked': 0,
            'fields': {f: {'accepted': 0, 'abstain': 0, 'rejected': 0, 'subjects_accepted': 0, 'subjects_open': 0, 'by_stratum': collections.Counter(),
                           'by_value': collections.Counter(), 'abstain_reason': collections.Counter()} for f in FIELDS},
            'jev': {'items_cached': 0, 'items_unanswered': 0, 'calls': 0, 'input_tokens': 0, 'usd': 0.0, 'errors': collections.Counter()},
            'written': 0, 'seconds': {}}


def tally(rep, s, vals, items, gates):
    rep['subjects'] += 1
    for it in items:
        rep['items'][f"{it['mode']}:{it['sk']}"] += 1
    rep['gate_checked'] += len(gates)
    rep['gate_fail'] += sum(g < TAU['victim'] for g in gates)
    for f in FIELDS:
        fv = [v for v in vals if v.field == f]
        if not fv:
            continue
        R = rep['fields'][f]
        accepted = [v for v in fv if v.verdict == 'accepted']
        R['subjects_accepted' if accepted else 'subjects_open'] += 1
        for v in accepted:
            R['accepted'] += 1
            R['by_stratum'][f'{v.source_kind}/{v.basis}'] += 1
            R['by_value'][v.value] += 1
        for v in fv:
            if v.verdict == 'abstain':
                R['abstain'] += 1
                R['abstain_reason'][v.reason] += 1
            elif v.verdict == 'rejected':
                R['rejected'] += 1


def report_json(rep):
    def conv(x):
        if isinstance(x, collections.Counter):
            return dict(sorted(x.items(), key=lambda kv: (-kv[1], str(kv[0]))))
        if isinstance(x, dict):
            return {k: conv(v) for k, v in x.items()}
        return x
    return json.dumps(conv(rep), indent=2, sort_keys=True, default=str)


# =====================================================================================================
# Orchestration
# =====================================================================================================
def classify_page(conn, page, jev, rep, run_id, write, workers=WORKERS, stored_fn=None, answers_fn=None, dump=None):
    """One load/ask/decide/write cycle for a list of (Subject, extra)."""
    stored_fn = stored_fn or (lambda keys: C.stored_answers(conn, keys))
    answers_fn = answers_fn or (lambda rows: C.write_answers(conn, rows))
    plans = [(s, plan_items(s, extra)) for s, extra in page]
    items = [it for _, its in plans for it in its]
    keys = [(V_COMB, q_hash_item(it), item_sha(it)) for it in items]
    stored = stored_fn(keys)
    res, new_rows = ask_items(jev, items, stored, run_id, rep, workers)
    ans_ids = {k: aid for k, (aid, _) in stored.items()}
    if new_rows:
        ans_ids.update(answers_fn(new_rows))
    out = []
    for s, its in plans:
        if not its or not all(id(it) in res for it in its):   # unanswered (budget stop / error): left for the next run
            continue
        vals, reviews, gates = finalise(s, its, res)
        for v in vals:
            v.answer_id = ans_ids.get(v.answer_key) if v.answer_key else None
        out.append((s, vals))
        tally(rep, s, vals, its, gates)
        if dump is not None:
            dump.append({'ref': s.ref, 'name': s.name, 'domain': s.domain,
                         'items': [{'mode': it['mode'], 'sk': it['sk'], 'basis': it['basis'], 'text': it.get('text')} for it in its],
                         'vals': [(v.field, v.value, v.source_kind, v.basis, v.verdict, v.reason, v.jev_p) for v in vals]})
    if write and out:
        rep['written'] += write_chunk_values(conn, out, run_id)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(prog='zdc-breach-r2-combined', description=__doc__.split('\n')[0])
    ap.add_argument('--report')
    sub = ap.add_subparsers(dest='cmd', required=True)
    r = sub.add_parser('run')
    r.add_argument('--pilot', type=int, help='random sample of N subjects (seeded)')
    r.add_argument('--seed', type=int, default=20261026)
    r.add_argument('--exclude', help='file of victim ids (one per line) never drawn by --pilot (e.g. gold-labelled subjects)')
    r.add_argument('--new-only', action='store_true', help='only subjects without a combined value row (hourly job)')
    r.add_argument('--limit', type=int)
    r.add_argument('--only', help='file of victim ids (one per line) to restrict the run to')
    r.add_argument('--max-usd', type=float, default=15.0)
    r.add_argument('--no-jev', action='store_true', help='stored answers only (re-derive values, no network)')
    r.add_argument('--write', action='store_true', help='write r2_values (answers are always stored when Jev was asked)')
    r.add_argument('--workers', type=int, default=WORKERS)
    r.add_argument('--report', dest='report_run')
    r.add_argument('--dump', help='local JSON of subject text + decisions for inspection (never commit or publish)')
    sc = sub.add_parser('score')
    sc.add_argument('--gold-root', default=os.environ.get('R2_GOLD_ROOT'), help='local folder of the adjudicated gate labels (never published)')
    sc.add_argument('--out', default='.')
    sc.add_argument('--min-n', type=int, default=50)
    args = ap.parse_args(argv)
    args.report = getattr(args, 'report_run', None) or args.report
    if args.cmd == 'score':
        from . import r2_combined_score as S
        return S.main_score(args)
    import psycopg
    conn = psycopg.connect(os.environ['DATABASE_URL'], autocommit=True)
    run_id = 'r2cb-' + time.strftime('%Y%m%dT%H%M%S')
    rep = new_report('run')
    rep['run_id'] = run_id
    t0 = time.time()
    jev = None
    if not args.no_jev:
        jev = Jev(Budget(args.max_usd), user_agent='zdc-breach-r2-combined/1', retries=6)
        if jev.pin_answers() is False:
            print(f'pinned model {MODEL} no longer answers', file=sys.stderr)
            return 5
    skip = done_subjects(conn) if args.new_only else None
    only = {x.strip() for x in open(args.only) if x.strip()} if args.only else None
    dump = [] if args.dump else None
    if args.pilot:
        excl = {x.strip() for x in open(args.exclude) if x.strip()} if args.exclude else set()
        with conn.cursor() as cur:
            cur.execute(f"set statement_timeout = '{STATEMENT_TIMEOUT}'")
            cur.execute("select victim_id from breach_core.r2_victims_shadow order by victim_id")
            allv = [v for (v,) in cur.fetchall() if v not in excl]
        random.Random(args.seed).shuffle(allv)
        only = set(allv[:args.pilot])
    n_tot = 0
    for page in iter_pages(conn, skip=skip, only=only, limit=args.limit):
        classify_page(conn, page, jev, rep, run_id, args.write, args.workers, dump=dump)
        n_tot += len(page)
        if jev is not None:
            rep['jev']['input_tokens'], rep['jev']['usd'] = jev.budget.input_tokens, round(jev.budget.spent_usd, 4)
            rep['jev']['calls_total'] = jev.budget.calls
        print(f"[{time.strftime('%H:%M:%S')}] subjects {n_tot} written {rep['written']} usd {rep['jev']['usd']} "
              f"calls {rep['jev']['calls']} errors {dict(rep['jev']['errors'])}", file=sys.stderr, flush=True)
        if rep['jev'].get('stopped'):
            break
    rep['seconds']['total'] = round(time.time() - t0, 1)
    text = report_json(rep)
    if args.report:
        open(args.report, 'w').write(text)
    if dump is not None:
        json.dump(dump, open(args.dump, 'w'), ensure_ascii=False)
    print(text)
    return 0


if __name__ == '__main__':
    sys.exit(main())
