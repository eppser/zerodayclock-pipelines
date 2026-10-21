"""Victim profile from the ransomware leak post (method breach-profile-v1).

A port of the frozen P1.2 research configuration (RUBRIC_P1.2 + RULING_P1.2, round 2, 2026-10-21): the sentence
splitter split-v1, the TypeSafe Jev question set p1-q2 on model jev-1.13.0 (14 data-type questions per
description, one class question per sentence, one stolen-data question per volume candidate, and the frozen
size question), and the frozen P1.2 decision rules (fine-tag thresholds, the eight display groups, the
profile-only sentence display gate with its whole-description veto and deterministic scrub, the volume parser).
The ported blocks below are verbatim in behaviour; tests/test_breach_profile.py proves equality against the
frozen files on the stored Jev answers.

What it produces, per leak claim with a tracker description (one description per claim: RansomLook first,
then RansomFeed, newest record version; the first 3,000 characters, as in the research sample):
  profile_tags   fine data types the post STATES were taken (R0.3: never inferred from the industry). PRIVATE.
  profile_groups the display groups of those tags (decide2.groups). Public only for groups listed in
                 profile_settings.shipping_groups (a group ships after its hold-out gate; RULING P1.2 C1).
  volumes        attacker-stated amounts of stolen data, four units never converted or merged
                 (bytes | files | records | persons, the noun kept), with qualifier and verbatim span (private)
  sentences      per sentence: class, p-values and whether it passes the display gate. The text of a
                 sentence is copied out of breach_raw ONLY when it is shown; hidden text stays in breach_raw.
  size           the Jev size estimate. PRIVATE: it failed its gate (exact 0.578 < 0.75). Never in a public view.

Rules added in production on top of the frozen code (documented in migration 0145):
  boilerplate    a sentence that appears verbatim (whitespace-normalised, lower-cased) in >= 5 descriptions of
                 the same actor_group is a template (RULING D2.5). It is never shown (frozen display()'s
                 `boilerplate` argument; it still takes part in the whole-description veto), and it gives no
                 tags beyond unspecified: when no non-template sentence the classifier saw is classed as a data
                 statement (data_summary, personal_data, sample_or_dump), the tags collapse to ['unspecified']
                 (or none). Volumes found in a template sentence are dropped. Counted per run from the database
                 (BOILERPLATE_SQL reads the groups' descriptions; the counting is in Python because the splitter is).
  display input  display() receives EVERY sentence of the description, not only the first 12 the classifier
                 saw: a sentence without a class answer vetoes the whole description, so a post longer than 12
                 sentences is never shown (its unseen tail was never checked).
  size           asked only for a claim whose victim check (0143) exists and is not not_org,
                 redacted_unresolved or natural_person_risk (RUBRIC 1: a person, placeholder or masked name is
                 never sized). The estimate is stored only when P(top band) >= 0.6 (RULING D3.2); the full
                 distribution stays in jev_answers.

The Jev answers are the reproducible unit (jev_answers): `rescore` re-applies every rule to them with no
network. Leak text is read inside this process only; nothing here logs or reports it, nor the API key.

CLI (counts-only JSON report):
  python -m zdc_breach.profile run --limit N --deadline-min M --max-usd X
  python -m zdc_breach.profile rescore
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures as cf
import hashlib
import html
import json
import os
import re
import unicodedata
import sys
import threading
import time
import urllib.error
import urllib.request

METHOD = 'breach-profile-v1'
MODEL = 'jev-1.13.0'
QV = 'p1-q2'
API = 'https://api.typesafe.ai'
PRICE_PER_MTOK = 0.042          # USD per million input tokens (docs.typesafe.ai/models.md, 2026-10-21)
DESC_MAX = 3000                 # the research sample read left(description, 3000)
DESC_MIN = 20                   # and kept descriptions of >= 20 characters
TAGS_PER_CALL = 3               # items per Jev call, as in the frozen runs (pjev.run)
SIZE_PER_CALL = 10
WORKERS = 4
WRITE_CHUNK = 30                # claims per write transaction
BOILERPLATE_MIN = 5
SIZE_SHOW_P = 0.6
BANDS = ['micro', 'small', 'medium', 'large', 'enterprise']
DATA_CLASSES = {'data_summary', 'personal_data', 'sample_or_dump'}
STATEMENT_TIMEOUT = '120s'
LOCK_TIMEOUT = '5s'

# =====================================================================================================
# Frozen: split.py (split-v1), verbatim
# =====================================================================================================
SPLITTER_VERSION = 'split-v1'


def clean(t):
    t = re.sub(r'(?i)<\s*(br|/p|p|/div|div|li|/li)\b[^>]*>', '\n', t or '')
    t = re.sub(r'<[^>]+>', ' ', t)
    return html.unescape(t)


def sentences(text):
    t = clean(text)
    parts = []
    for block in re.split(r'\n+|\s\|\s', t):
        block = re.sub(r'\s+', ' ', block).strip()
        if not block:
            continue
        for s in re.split(r'(?<=[.!?])\s+(?=[A-Z0-9"“\'(])', block):
            s = s.strip()
            if s:
                parts.append(s)
    if parts and (parts[-1].endswith('...') or parts[-1].endswith('…') or (len(text or '') >= 2900 and not re.search(r'[.!?]["”\')]?$', parts[-1]))):
        parts = parts[:-1]
    return parts


def sentence_items(text):
    """split-v1 sentences with the research sentence ids s1, s2, ..."""
    return [{'sid': 's%d' % (i + 1), 'text': s} for i, s in enumerate(sentences(text))]


# =====================================================================================================
# Frozen: pjev.py question set p1-q1 (TAGS, TAG_RULES, CLASSES, VOL_RE, builders), verbatim
# =====================================================================================================
TAGS = {
 'personal_identity': 'personal details of individuals (names together with dates of birth, "personal data", "PII", personal information of customers, patients, employees or students)',
 'contact': 'contact details of individuals (home addresses, phone numbers, email addresses; a bare "emails" or "N emails" means email addresses)',
 'government_id': 'government identity numbers (social security numbers, passports, national ID cards, driver\'s licences, personal tax IDs)',
 'health': 'health or medical information (patient records, medical or clinical files, diagnoses, prescriptions, PHI)',
 'financial_personal': 'personal financial data (bank account details, payment card numbers, IBANs, loan files, personal tax returns)',
 'financial_corporate': 'the organisation\'s own financial records (invoices, accounting, audits, budgets, financial statements, company bank statements)',
 'hr': 'employee or HR records (employee files, payroll, salaries, HR documents, CVs)',
 'credentials': 'credentials or secrets (passwords, logins, API keys, certificates, tokens)',
 'customer': 'customer or client data (customer databases, client lists, CRM data, orders). Patients are never customers: patient data is health data',
 'legal': 'contracts or legal documents (contracts, NDAs, agreements, court or legal files)',
 'technical': 'technical documents or intellectual property (drawings, CAD files, source code, designs, R&D, IT or network documentation)',
 'communications': 'message CONTENTS (mailboxes, email archives, chat logs, correspondence) - not a list of email addresses',
 'other_stated': 'a SPECIFIC kind of data that is named but is none of: personal details, contact details, ID numbers, health, personal finance, company finance, HR, credentials, customer data, contracts, technical files, emails (e.g. biometrics, student records, insurance claims, CCTV footage)',
 'unspecified': 'data whose type is NOT specified at all (only generic words such as "all data", "confidential files", "databases", "documents", with no kind of data named)',
}
TAG_NAMES = list(TAGS)
TAG_RULES = ('Answer yes only if the leak text STATES that this kind of data was stolen, is held by the attackers, or will be '
             'published. A statement that it was NOT taken is a no. Do not infer from what the organisation does: a hospital '
             'description without a statement about stolen patient data is a no for health; a payroll provider is not HR data; '
             'a bank is not personal financial data; customer counts in a company profile are not customer data.')
CLASSES = {
 'profile': 'Describes the organisation itself: what it does, where it is, its history or market (no stolen data, no threat).',
 'data_summary': 'Says which KINDS or AMOUNTS of data were stolen or will be published, without listing any actual personal values.',
 'threat_negotiation': 'A threat, deadline, payment status, ransom offer or negotiation statement ("not paid", "will be published", "they offered").',
 'contact_instructions': 'Tells someone how to contact the attackers (chat IDs, email, portal, "contact us").',
 'personal_data': 'Names a private individual, or gives personal values (an email, phone, home address, ID number), or lists personal field names such as "full name, address, SSN".',
 'sample_or_dump': 'Contains raw stolen content: field:value pairs, table rows, file listings or a data sample.',
 'accusation_or_opinion': 'The attackers\' blame or opinion about the victim (negligence, "did not care about their clients").',
 'link_or_tag': 'Only links, hashtags, or tracker boilerplate.',
 'other': 'Anything else.',
}
VOL_RE = re.compile(r'(?i)(?P<q>over|more than|above|approx(?:imately)?\.?|about|around|~|up to|nearly|almost)?\s*'
                    r'(?P<n>\d[\d,.]*\s*(?:k|m|mln|million|thousand|bn|billion)?)\s*\+?\s*'
                    r'(?P<u>tb|gb|mb|pb|kb|terabytes?|gigabytes?|megabytes?|files?|documents?|records?|rows?|entries|customers?|patients?|'
                    r'employees?|users?|clients?|students?|members?|persons?|people|individuals)\b')


def volume_candidates(sentences):
    out = []
    for s in sentences:
        for m in VOL_RE.finditer(s['text']):
            t = s['text']
            plus = t[m.end('n'):m.start('u')].strip().startswith('+') or t[m.end('u'):m.end('u') + 1] == '+'
            out.append({'sid': s['sid'], 'span': m.group(0).strip()[:80], 'n': m.group('n'), 'u': m.group('u').lower(), 'q': (m.group('q') or '').lower(), 'plus': plus})
    return out[:6]


def tags_build(items):
    state, qs, meta = {'victims': {}}, {}, {}
    for n, it in enumerate(items):
        pid = 'v%d' % (n + 1)
        ref = 'victims.' + pid
        sents = it['sentences'][:12]
        state['victims'][pid] = {'name': it['victim_name'], 'domain': it.get('victim_domain'), 'group': it['actor_group'],
                                 'leak_text': {s['sid']: s['text'][:500] for s in sents}}
        for t, d in TAGS.items():
            qs[f'{pid}_t_{t}'] = {'type': 'noul', 'instructions': f'The ransomware group\'s leak text for the victim is `{ref}.leak_text`. '
                                  f'Does it state that the attackers took {d}? {TAG_RULES}'}
        for s in sents:
            qs[f'{pid}_c_{s["sid"]}'] = {'type': 'choice', 'instructions': f'Classify the sentence `{ref}.leak_text.{s["sid"]}` from a ransomware leak post '
                                         f'about the victim `{ref}.name`.', 'criteria': CLASSES}
        cands = volume_candidates(sents)
        for k, c in enumerate(cands):
            qs[f'{pid}_v{k}'] = {'type': 'noul', 'instructions': f'In `{ref}.leak_text.{c["sid"]}`, does the figure "{c["span"]}" state an AMOUNT OF STOLEN DATA '
                                 '(data size, number of stolen files/records, or number of people whose data was taken), as opposed to a fact '
                                 'about the organisation (customers served, staff, years, locations, revenue)?'}
        meta[pid] = {'claim_key': it['claim_key'], 'sids': [s['sid'] for s in sents], 'cands': cands}
    return state, qs, meta


SIZE_LEVELS = ['micro: fewer than 10 employees (sole practice, small shop, single small office)',
               'small: 10 to 49 employees',
               'medium: 50 to 249 employees',
               'large: 250 to 4,999 employees (regional company, mid-size hospital or university)',
               'enterprise: 5,000 or more employees (national or multinational group)']


def size_build(items):
    state, qs, meta = {'organisations': {}}, {}, {}
    for n, it in enumerate(items):
        pid = 'o%d' % (n + 1)
        ref = 'organisations.' + pid
        state['organisations'][pid] = {'name': it['name'], 'domain': it.get('domain'), 'country': it.get('country'),
                                       'industry': it.get('industry'), 'description': it.get('profile_text') or None}
        qs[f'{pid}_size'] = {'type': 'score', 'instructions': f'How many employees does the organisation `{ref}` most likely have? '
                             'Judge from its name, domain, country, industry and description.', 'criteria': SIZE_LEVELS}
        meta[pid] = it['size_key']
    return state, qs, meta


# The size set's evidence: headcount and revenue sentences removed (the sealed size_items.json builder;
# reproduces its profile_text on 175 of 175 items).
HC = re.compile(r'(?i)\b(employ|staff|workers|workforce|people|personnel|team of|headcount|revenue|turnover|sales of|\$\s?\d|usd|eur|€|£|million|billion)\b')
HC_COUNT = re.compile(r'(?i)\d[\d,.]*\s*(\+)?\s*(employees|staff)')


def size_profile_text(description):
    keep = [s for s in sentences(description or '') if not HC.search(s) and not HC_COUNT.search(s)]
    return ' '.join(keep)[:1500] or None


# =====================================================================================================
# Frozen: decide2.py (P1.2: tag thresholds, groups, profile-only display gate, volume parser), verbatim
# =====================================================================================================
TAU = {'personal_identity': 0.9, 'unspecified': 0.5}
TAU_DEFAULT = 0.6
GROUP = {'personal_identity': 'people', 'contact': 'people', 'government_id': 'people', 'customer': 'people',
         'health': 'health', 'financial_personal': 'finance', 'financial_corporate': 'finance', 'hr': 'hr',
         'technical': 'systems', 'credentials': 'systems', 'legal': 'documents', 'communications': 'documents',
         'other_stated': 'other', 'unspecified': 'unspecified'}
GROUP_LABEL = {'people': 'Customer & personal data', 'health': 'Health records', 'finance': 'Financial data', 'hr': 'Employee & payroll',
               'systems': 'Technical data & credentials', 'documents': 'Contracts & emails', 'other': 'Other data', 'unspecified': 'Data (types not stated)'}


def tags(A, tag_names):
    out = [t for t in tag_names if t != 'unspecified' and A['t_' + t]['noul'] >= TAU.get(t, TAU_DEFAULT)]
    if not out and A['t_unspecified']['noul'] >= TAU['unspecified']:
        out = ['unspecified']
    return out


def groups(fine):
    g = []
    for t in fine:
        x = GROUP[t]
        if x not in g:
            g.append(x)
    if len(g) > 1 and 'unspecified' in g:
        g.remove('unspecified')
    return g


SHOW = {'profile'}
ATTACK = re.compile(r'(?i)\b(hack\w*|breach\w*|leak\w*|upload\w*|publish\w*|download\w*|encrypt\w*|decrypt\w*|ransom\w*|negotiat\w*|deadline|'
                    r'ready to|stolen|steal\w*|exfiltrat\w*|data (was|were)|compromis\w*|victim\w*|attack\w*|pwn\w*|dump\w*|archive|terabytes?|gigabytes?)\b')
HOST = re.compile(r'(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b')
IP = re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}\b')
KV = re.compile(r'(?i)\b[a-z][\w ]{0,25}:\s*\S')
SCRUB = [re.compile(p, re.I) for p in (
    r'[\w.+-]+@[\w-]+\.[\w.]+', r'(?<!\d)(\+?\d[\d\s().-]{7,}\d)(?!\d)', r'https?://|www\.|\.onion\b',
    r'@\w', r'\btox\b|\bsession id\b|\bqtox\b|\bjabber\b|\bxmpp\b|\btelegram\b',
    r'\b\d{3}-\d{2}-\d{4}\b', r'\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b', r'(?<![\d.,])\d{6,}(?![\d.,])',
    r'["“”«»]', r'\b(sample|proof|screenshot|password)s?\b',
    r'[$€£¥]|\b(usd|eur|gbp|btc|bitcoin|dollars?|euros?)\b',
    r'\b\d{1,2}[./-]\d{1,2}[./-]\d{2,4}\b|\b\d{1,2}:\d{2}\b|\b(days?|hours?)\s+(left|remaining)\b|\bcountdown\b',
    r'\b\d+(\.\d+)?\s*(tb|gb|mb|pb)\b')]


def scrub_hit(text, victim_domain=None):
    t = text    # RULING P1.2 C3: ANY hostname drops the sentence, the victim's own domain included
    return bool(any(p.search(t) for p in SCRUB) or HOST.search(t) or IP.search(t) or KV.search(t) or ATTACK.search(t))


def display(A, sentences, victim_domain=None, boilerplate=frozenset()):
    for s in sentences:
        a = A.get('c_' + s['sid'])
        if not a:
            return []
        pr = a['probabilities']
        if max(pr.get('personal_data', 0), pr.get('sample_or_dump', 0), pr.get('contact_instructions', 0)) >= 0.2:
            return []
    out = []
    for s in sentences:
        pr = A['c_' + s['sid']]['probabilities']
        ch = max(pr, key=pr.get)
        if s['text'] in boilerplate:
            continue
        if ch in SHOW and pr[ch] >= 0.9 and pr.get('personal_data', 0) < 0.05 and pr.get('sample_or_dump', 0) < 0.05 \
           and not scrub_hit(s['text'], victim_domain) and 20 <= len(s['text']) <= 400:
            out.append(s['sid'])
    total = 0
    kept = []
    for sid in out:
        L = len(next(x['text'] for x in sentences if x['sid'] == sid))
        if len(kept) < 4 and total + L <= 600:
            kept.append(sid)
            total += L
    return kept


UNIT = {'tb': 1e12, 'terabyte': 1e12, 'terabytes': 1e12, 'gb': 1e9, 'gigabyte': 1e9, 'gigabytes': 1e9, 'mb': 1e6, 'megabyte': 1e6,
        'megabytes': 1e6, 'pb': 1e15, 'kb': 1e3}
QUAL = {'over': 'over', 'more than': 'over', 'above': 'over', 'about': 'about', 'around': 'about', 'approx': 'about', 'approximately': 'about',
        '~': 'about', 'up to': 'up_to', 'nearly': 'about', 'almost': 'about'}


def parse_volume(c):
    """(unit, value, qualifier) or None. C4: trailing '+' = over; a decimal comma before exactly 1-2 digits with a byte
    unit is a decimal point; zero = no volume."""
    raw = c['n'].lower().strip()
    u = c['u']
    plus = raw.endswith('+') or c.get('plus', False)
    raw = raw.rstrip('+').replace(' ', '')
    mult = 1
    for suf, m in (('thousand', 1e3), ('million', 1e6), ('billion', 1e9), ('mln', 1e6), ('bn', 1e9), ('k', 1e3), ('m', 1e6)):
        if raw.endswith(suf):
            raw = raw[:-len(suf)]
            mult = m
            break
    if u in UNIT and re.fullmatch(r'\d+,\d{1,2}', raw):
        raw = raw.replace(',', '.')
    raw = raw.replace(',', '')
    try:
        v = float(raw) * mult
    except ValueError:
        return None
    if v <= 0:
        return None
    if u in UNIT:
        unit = 'bytes'
        v *= UNIT[u]
    elif u.startswith(('file', 'document')):
        unit = 'files'
    elif u.startswith(('record', 'row', 'entr')):
        unit = 'records'
    else:
        unit = 'persons'
    q = 'over' if plus else QUAL.get(c['q'].rstrip('.'), 'exact')
    return (unit, round(v), q)


# =====================================================================================================
# Production rules on the frozen outputs
# =====================================================================================================
def norm_sentence(s):
    return re.sub(r'\s+', ' ', s or '').strip().lower()


def count_boilerplate(rows, min_posts=BOILERPLATE_MIN):
    """rows: iterable of (actor_group, claim_key, description). Returns {actor_group: set of normalised sentences
    that appear in >= min_posts distinct descriptions of that group}. A sentence repeated inside one description
    counts once."""
    counts = collections.defaultdict(collections.Counter)
    seen = set()
    for group, key, descr in rows:
        if (group, key) in seen:
            continue
        seen.add((group, key))
        counts[group].update({norm_sentence(s) for s in sentences(descr)})
    return {g: {s for s, n in c.items() if n >= min_posts} for g, c in counts.items()}


def boilerplate_sids(sents, group_templates):
    return {s['sid'] for s in sents if norm_sentence(s['text']) in (group_templates or ())}


def profile_tags(A, sents, boiler_sids, seen_sids):
    """Frozen tags(); a description whose data statements are all templates gives at most 'unspecified'."""
    out = tags(A, TAG_NAMES)
    if boiler_sids & set(seen_sids):
        data_stated = any(((A.get('c_' + sid) or {}).get('choice') in DATA_CLASSES)
                          for sid in seen_sids if sid not in boiler_sids)
        if not data_stated:
            out = ['unspecified'] if out else []
    return out


def volumes(A, cands, boiler_sids=frozenset()):
    """Frozen parse_volume() on each candidate Jev says refers to stolen data (p >= 0.5), outside template sentences.
    The persons noun is kept (RULING D4)."""
    out = []
    for k, c in enumerate(cands):
        a = A.get('v%d' % k)
        if not a or a.get('noul', 0) < 0.5 or c['sid'] in boiler_sids:
            continue
        v = parse_volume(c)
        if v:
            unit, value, qual = v
            out.append({'sid': c['sid'], 'span': c['span'], 'value': value, 'unit': unit,
                        'noun': c['u'] if unit == 'persons' else None, 'qualifier': qual})
    return out


def size_estimate(answer):
    """(band or None, p_top). Ties go to the smaller band (dict order of 0..4, as score_size.py). Abstains
    below P(top) 0.6."""
    if not answer or not answer.get('probabilities'):
        return None, None
    pr = {int(x): v for x, v in answer['probabilities'].items()}
    pr = {k: pr[k] for k in sorted(pr)}
    top = max(pr, key=pr.get)
    p = float(pr[top])
    if not 0 <= top < len(BANDS):
        return None, p
    return (BANDS[top] if p >= SIZE_SHOW_P else None), p

# RULING_P1 D8.4: tag and show only languages with >= 30 gold items - English only. Leak posts are often telegraphic
# ("TARGET: x REVENUE: y"), so the test needs POSITIVE evidence of another language: mostly non-Latin letters, or common
# German/Dutch/French/Spanish/Italian/Portuguese function words outnumbering English ones (2026-10-21: an
# English-word-share test flagged 33 English posts of 250).
EN_WORDS = frozenset('the and of to are was were for with by from its this that which our their has have been'.split())
FOREIGN_WORDS = frozenset(('der die das und mit für ist eine einer nicht auch werden von zu den dem im '      # de
                           'het een voor zijn wordt '                                                    # nl
                           'le la les et des du une est pour dans avec sur au aux '                     # fr
                           'el los las y del una es para con por que su se '                            # es
                           'il lo gli è di della delle per con una sono '                               # it
                           'o os as e do da dos das uma é para com não em').split())                   # pt


def likely_english(text):
    letters = [c for c in text if c.isalpha()]
    if letters and sum(1 for c in letters if c.isascii() or unicodedata.category(c).startswith('L') and 'LATIN' in unicodedata.name(c, '')) / len(letters) < 0.8:
        return False
    words = re.findall(r"[^\W\d_]+", text.lower())
    foreign = sum(1 for w in words if w in FOREIGN_WORDS)
    english = sum(1 for w in words if w in EN_WORDS)
    return not (foreign >= 3 and foreign > 2 * english)


def decide_claim(item, jev_answers, group_templates):
    """Every derived value of one claim from its stored Jev answers. item: {claim_key, victim_domain, sentences}."""
    A = jev_answers['tags']
    sents = item['sentences']
    seen = jev_answers['meta']['sids']
    boiler = boilerplate_sids(sents, group_templates)
    shown = set(display(A, sents, item.get('victim_domain'),
                        boilerplate=frozenset(s['text'] for s in sents if s['sid'] in boiler)))
    rows = []
    for s in sents:
        a = A.get('c_' + s['sid'])
        pr = (a or {}).get('probabilities') or {}
        rows.append({'sid': s['sid'], 'text': s['text'] if s['sid'] in shown else None,
                     'cls': (a or {}).get('choice'), 'p_cls': pr.get((a or {}).get('choice')) if a else None,
                     'p_personal': pr.get('personal_data') if a else None, 'p_sample': pr.get('sample_or_dump') if a else None,
                     'boilerplate': s['sid'] in boiler, 'shown': s['sid'] in shown})
    band, p_top = size_estimate((jev_answers.get('size') or {}).get('size'))
    english = likely_english(' '.join(s['text'] for s in sents))
    if not english:                                   # D8.4: other languages get size only
        for r in rows:
            r['text'], r['shown'] = None, False
    fine = profile_tags(A, sents, boiler, seen) if english else []
    return {'profile_tags': fine, 'profile_groups': groups(fine),
            'volumes': volumes(A, jev_answers['meta']['cands'], boiler) if english else [],
            'size_band_est': band, 'size_p_top': p_top, 'sentences': rows}


def _probe_item():
    """A fixed synthetic item: the question hash names the question TEMPLATES, independent of any real post."""
    return {'claim_key': 'probe', 'victim_name': 'Probe Example Ltd', 'victim_domain': 'probe.example.org', 'actor_group': 'probe',
            'sentences': [{'sid': 's1', 'text': 'Probe Example Ltd makes widgets.'}, {'sid': 's2', 'text': 'We took 2 TB of files.'}]}


def q_hash():
    """sha256 over the p1-q1 questions built for the probe (tags) and a probe organisation (size), first 16 hex."""
    _, tq, _ = tags_build([_probe_item()])
    _, sq, _ = size_build([{'size_key': 'probe', 'name': 'Probe Example Ltd', 'domain': 'probe.example.org', 'country': 'GB',
                            'industry': 'Manufacturing', 'profile_text': 'Probe Example Ltd makes widgets.'}])
    blob = json.dumps({'qv': QV, 'model': MODEL, 'tags': tq, 'size': sq}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


# =====================================================================================================
# Jev client (mirrors the research client: retries, back-off, out-of-funds). Never logs the key or a body.
# =====================================================================================================
class OutOfFunds(Exception):
    pass


class BudgetExhausted(Exception):
    pass


class JevError(Exception):
    pass


def _urllib_transport(method, url, headers, body, timeout):
    r = urllib.request.Request(url, method=method, headers=headers, data=body)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        txt = e.read().decode(errors='replace')[:2000]
        return e.code, dict(e.headers), {'error': txt}


class Budget:
    """Spend guard on input tokens. `reserve()` refuses a call once the spend so far plus the average call would
    pass max_usd."""

    def __init__(self, max_usd, price_per_mtok=PRICE_PER_MTOK):
        self.max_usd, self.price = float(max_usd), price_per_mtok
        self.input_tokens = self.output_tokens = self.calls = 0
        self._lock = threading.Lock()

    @property
    def spent_usd(self):
        return self.input_tokens * self.price / 1e6

    def reserve(self):
        with self._lock:
            avg = (self.spent_usd / self.calls) if self.calls else 0.0
            if self.spent_usd + avg > self.max_usd or self.spent_usd >= self.max_usd:
                raise BudgetExhausted()

    def charge(self, usage):
        with self._lock:
            self.calls += 1
            self.input_tokens += int((usage or {}).get('input_tokens') or 0)
            self.output_tokens += int((usage or {}).get('output_tokens') or 0)


class Jev:
    def __init__(self, budget, key=None, transport=None, sleep=time.sleep, retries=4, timeout=120):
        self._key = key if key is not None else os.environ.get('TYPESAFE_API_KEY')
        if not self._key:
            raise SystemExit('TYPESAFE_API_KEY is not set')
        self.budget, self.transport, self.sleep, self.retries, self.timeout = budget, transport or _urllib_transport, sleep, retries, timeout
        self.status = collections.Counter()

    def pin_answers(self):
        """Does the pinned model still answer as itself? TypeSafe's /v1/models lists only aliases (jev-latest,
        jev-preview), so the check is one minimal real question (~300 input tokens, ~0.00002 USD): True when the
        response names MODEL, False when the API refuses the model or answers with another one, None when it cannot
        be reached (a network failure is not evidence the model is gone)."""
        try:
            js = self.ask({'probe': {'text': 'Example Org makes tools.'}},
                          {'probe': {'type': 'noul', 'instructions': 'Does `probe.text` mention tools?'}})
        except OutOfFunds:
            raise
        except JevError as e:
            return False if any(w in str(e).lower() for w in ('model', '404', '400', '422')) else None
        except (BudgetExhausted, urllib.error.URLError, TimeoutError, OSError):
            return None
        return (js or {}).get('model') == MODEL

    def ask(self, state, questions, model=MODEL):
        self.budget.reserve()
        body = json.dumps({'model': model, 'state': state, 'questions': questions}).encode()
        headers = {'Authorization': 'Bearer ' + self._key, 'Content-Type': 'application/json', 'User-Agent': 'zdc-breach-profile/1'}
        for a in range(self.retries):
            try:
                st, hd, js = self.transport('POST', API + '/v1/systemone', headers, body, self.timeout)
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                self.status['net_' + type(e).__name__] += 1
                self.sleep(2 ** a)
                continue
            self.status[str(st)] += 1
            if st == 200:
                self.budget.charge(js.get('usage'))
                return js
            low = str(js).lower()
            if st in (402, 403) or 'credit' in low or 'balance' in low or 'fund' in low:
                raise OutOfFunds(st)
            if st in (429, 500, 502, 503, 504):
                hd = hd or {}
                self.sleep(float(hd.get('retry-after') or hd.get('Retry-After') or 2 ** a))
                continue
            raise JevError(st)          # the status only: an error body may echo the request
        raise JevError('retries exhausted')


def _split_answers(js, meta):
    A = js.get('answers') or {}
    out = {}
    for pid, m in meta.items():
        out[pid] = {k[len(pid) + 1:]: v for k, v in A.items() if k.startswith(pid + '_')}
    return out


def ask_tags(jev, items):
    """items -> {claim_key: {'tags': answers, 'meta': {sids, cands}, 'model': ...}} (claims Jev did not answer
    completely are left out)."""
    st, qs, meta = tags_build(items)
    js = jev.ask(st, qs)
    res = {}
    for pid, ans in _split_answers(js, meta).items():
        m = meta[pid]
        need = {'t_' + t for t in TAG_NAMES} | {'c_' + s for s in m['sids']} | {'v%d' % k for k in range(len(m['cands']))}
        if need <= set(ans):
            res[m['claim_key']] = {'tags': ans, 'meta': {'sids': m['sids'], 'cands': m['cands']}, 'model': js.get('model')}
    return res


def ask_size(jev, items):
    st, qs, meta = size_build(items)
    js = jev.ask(st, qs)
    return {meta[pid]: {'size': ans['size'], 'model': js.get('model')}
            for pid, ans in _split_answers(js, meta).items() if 'size' in ans}


# =====================================================================================================
# Database
# =====================================================================================================
# One description per claim: RansomLook first, then RansomFeed; the newest record version; first 3,000 characters.
DESC_LATERAL = """
cross join lateral (
    select r->>'source_id' as tracker, left(s.record->>'description', 3000) as descr
      from jsonb_array_elements(l.tracker_refs) r
      join breach_raw.source_records s on s.source_id = r->>'source_id' and s.source_record_id = r->>'id'
     where coalesce(s.record->>'description', '') <> ''
     order by (r->>'source_id') = 'ransomlook' desc, s.version desc, s.source_record_id
     limit 1) d
"""

ITEM_COLS = """l.claim_key, l.actor_group, l.victim_name, l.victim_domain, d.tracker, d.descr,
       encode(sha256(convert_to(d.descr, 'UTF8')), 'hex') as sha, l.first_seen_at::date as as_of,
       coalesce(v.name, l.victim_name) as size_name, coalesce(v.domain, l.victim_domain) as size_domain,
       coalesce(v.country, l.country) as size_country, v.industry as size_industry,
       (c.claim_key is not null and c.label not in ('not_org', 'redacted_unresolved') and not c.natural_person_risk) as sizeable"""

ITEM_JOINS = """
left join breach_core.victims_list v on v.victim_id = 'claim:' || l.claim_key
left join breach_core.victim_checks c on c.claim_key = l.claim_key
"""

SELECT_SQL = f"""
select {ITEM_COLS}
  from breach_core.leak_claims l
  {DESC_LATERAL}
  {ITEM_JOINS}
 where length(d.descr) >= {DESC_MIN}
   and not exists (select 1 from breach_core.victim_profiles p
                    where p.claim_key = l.claim_key and p.method_version = %(method)s
                      and p.description_sha256 = encode(sha256(convert_to(d.descr, 'UTF8')), 'hex'))
 order by l.first_seen_at desc, l.claim_key
 limit %(limit)s
"""

RESCORE_SQL = f"""
select {ITEM_COLS}, p.description_sha256, p.jev_answers
  from breach_core.victim_profiles p
  join breach_core.leak_claims l on l.claim_key = p.claim_key
  {DESC_LATERAL}
  {ITEM_JOINS}
 where p.method_version = %(method)s
 order by l.claim_key
"""

# Every description (same selection) of the run's groups, for the template count.
BOILERPLATE_SQL = f"""
select l.actor_group, l.claim_key, d.descr
  from breach_core.leak_claims l
  {DESC_LATERAL}
 where l.actor_group = any(%(groups)s)
"""

_COLS = ['claim_key', 'actor_group', 'victim_name', 'victim_domain', 'tracker', 'descr', 'sha', 'as_of',
         'size_name', 'size_domain', 'size_country', 'size_industry', 'sizeable']


def _timeouts(cur):
    cur.execute(f"set local statement_timeout = '{STATEMENT_TIMEOUT}'")
    cur.execute(f"set local lock_timeout = '{LOCK_TIMEOUT}'")


def _item(row):
    it = dict(zip(_COLS, row[:len(_COLS)]))
    it['sentences'] = sentence_items(it['descr'])
    it['size_key'] = it['claim_key']
    return it


def read_templates(cur, groups):
    if not groups:
        return {}
    cur.execute(BOILERPLATE_SQL, {'groups': sorted(groups)})
    return count_boilerplate(cur.fetchall())


def write(conn, rows):
    """rows: [(item, jev_answers, decision)]. One transaction: upsert the profiles, replace their sentences."""
    from psycopg.types.json import Jsonb
    if not rows:
        return 0
    with conn.transaction(), conn.cursor() as cur:
        _timeouts(cur)
        cur.execute("""insert into breach_core.victim_profiles
                           (claim_key, method_version, model, q_hash, description_sha256, tracker, as_of, jev_answers,
                            profile_tags, profile_groups, volumes, size_band_est, size_p_top, profiled_at)
                       select x.k, %s, x.m, %s, x.sha, x.tr, x.d, x.a,
                              array(select jsonb_array_elements_text(x.t)), array(select jsonb_array_elements_text(x.g)),
                              x.v, x.b, x.p, now()
                         from unnest(%s::text[], %s::text[], %s::text[], %s::text[], %s::date[], %s::jsonb[],
                                     %s::jsonb[], %s::jsonb[], %s::jsonb[], %s::text[], %s::numeric[]) as x(k, m, sha, tr, d, a, t, g, v, b, p)
                       on conflict (claim_key) do update set
                           method_version = excluded.method_version, model = excluded.model, q_hash = excluded.q_hash,
                           description_sha256 = excluded.description_sha256, tracker = excluded.tracker, as_of = excluded.as_of,
                           jev_answers = excluded.jev_answers, profile_tags = excluded.profile_tags,
                           profile_groups = excluded.profile_groups, volumes = excluded.volumes,
                           size_band_est = excluded.size_band_est, size_p_top = excluded.size_p_top,
                           profiled_at = case when victim_profiles.jev_answers = excluded.jev_answers
                                              then victim_profiles.profiled_at else excluded.profiled_at end""",
                    (METHOD, q_hash(), [r[0]['claim_key'] for r in rows], [r[1].get('model') or MODEL for r in rows],
                     [r[0]['sha'] for r in rows], [r[0]['tracker'] for r in rows], [r[0]['as_of'] for r in rows],
                     [Jsonb(r[1]) for r in rows], [Jsonb(r[2]['profile_tags']) for r in rows],
                     [Jsonb(r[2]['profile_groups']) for r in rows], [Jsonb(r[2]['volumes']) for r in rows],
                     [r[2]['size_band_est'] for r in rows], [r[2]['size_p_top'] for r in rows]))
        keys = [r[0]['claim_key'] for r in rows]
        cur.execute("delete from breach_core.victim_description_sentences where claim_key = any(%s)", (keys,))
        S = [(r[0]['claim_key'], s) for r in rows for s in r[2]['sentences']]
        if S:
            cur.execute("""insert into breach_core.victim_description_sentences
                               (claim_key, sid, text, cls, p_cls, p_personal, p_sample, boilerplate, shown, splitter_version, method_version)
                           select x.k, x.sid, x.t, x.c, x.pc, x.pp, x.ps, x.b, x.sh, %s, %s
                             from unnest(%s::text[], %s::text[], %s::text[], %s::text[], %s::numeric[], %s::numeric[], %s::numeric[],
                                         %s::boolean[], %s::boolean[]) as x(k, sid, t, c, pc, pp, ps, b, sh)""",
                        (SPLITTER_VERSION, METHOD, [k for k, _ in S], [s['sid'] for _, s in S], [s['text'] for _, s in S],
                         [s['cls'] for _, s in S], [s['p_cls'] for _, s in S], [s['p_personal'] for _, s in S],
                         [s['p_sample'] for _, s in S], [s['boilerplate'] for _, s in S], [s['shown'] for _, s in S]))
    return len(rows)


# =====================================================================================================
# Commands
# =====================================================================================================
def _new_report(mode, max_usd=None):
    return {'mode': mode, 'method_version': METHOD, 'model': MODEL, 'q_hash': q_hash(), 'selected': 0, 'profiled': 0,
            'written': 0, 'sentences': 0, 'sentences_shown': 0, 'descriptions_shown': 0, 'boilerplate_sentences': 0,
            'tags': collections.Counter(), 'groups': collections.Counter(), 'no_tag': 0, 'volumes': collections.Counter(),
            'size': collections.Counter(), 'errors': collections.Counter(), 'max_usd': max_usd}


def _tally(report, dec):
    report['profiled'] += 1
    for t in dec['profile_tags']:
        report['tags'][t] += 1
    for g in dec['profile_groups']:
        report['groups'][g] += 1
    report['no_tag'] += not dec['profile_tags']
    for v in dec['volumes']:
        report['volumes'][v['unit']] += 1
    n_shown = sum(s['shown'] for s in dec['sentences'])
    report['sentences'] += len(dec['sentences'])
    report['sentences_shown'] += n_shown
    report['descriptions_shown'] += n_shown > 0
    report['boilerplate_sentences'] += sum(s['boilerplate'] for s in dec['sentences'])


def _finish(report, t0, jev=None, budget=None):
    for k in ('tags', 'groups', 'volumes', 'size', 'errors'):
        report[k] = dict(sorted(report[k].items()))
    if budget:
        report.update(calls=budget.calls, input_tokens=budget.input_tokens, output_tokens=budget.output_tokens,
                      usd=round(budget.spent_usd, 4))
    if jev:
        report['http_status'] = dict(sorted(jev.status.items()))
    report['seconds'] = round(time.time() - t0, 1)
    return report


def _ask_chunk(jev, items, report):
    """Tags (3 per call) then size (10 per call, sizeable victims only) for one write chunk. Returns
    ({claim_key: jev_answers}, stop_reason or None)."""
    stop = None
    answers = {}
    tag_calls = [items[i:i + TAGS_PER_CALL] for i in range(0, len(items), TAGS_PER_CALL)]
    with cf.ThreadPoolExecutor(WORKERS) as ex:
        futs = [ex.submit(ask_tags, jev, ch) for ch in tag_calls]
        for f in futs:
            try:
                answers.update(f.result())
            except BudgetExhausted:
                stop = stop or 'budget'
            except OutOfFunds:
                stop = 'out_of_funds'
            except Exception as e:  # noqa: BLE001 - counted by type only (public log)
                report['errors']['tags_' + type(e).__name__] += 1
        sized = [it for it in items if it['claim_key'] in answers and it['sizeable']]
        report['size']['not_sizeable'] += sum(1 for it in items if it['claim_key'] in answers and not it['sizeable'])
        size_items = [{'size_key': it['claim_key'], 'name': it['size_name'], 'domain': it['size_domain'],
                       'country': it['size_country'], 'industry': it['size_industry'],
                       'profile_text': size_profile_text(it['descr'])} for it in sized]
        if not stop:
            futs = [ex.submit(ask_size, jev, size_items[i:i + SIZE_PER_CALL]) for i in range(0, len(size_items), SIZE_PER_CALL)]
            for f in futs:
                try:
                    for k, v in f.result().items():
                        answers[k]['size'] = {'size': v['size']}
                        answers[k]['size_model'] = v['model']
                except BudgetExhausted:
                    stop = stop or 'budget'
                except OutOfFunds:
                    stop = 'out_of_funds'
                except Exception as e:  # noqa: BLE001
                    report['errors']['size_' + type(e).__name__] += 1
    for k in answers:
        answers[k].setdefault('size', None)
        answers[k]['qv'] = QV
    return answers, stop


def cmd_run(conn, limit, deadline_min, max_usd, jev=None, budget=None):
    """Profile up to `limit` claims, newest first. Stops at the deadline or the budget; what is answered is written."""
    t0 = time.time()
    deadline = t0 + deadline_min * 60
    report = _new_report('run', max_usd)
    budget = budget or Budget(max_usd)
    jev = jev or Jev(budget)
    with conn.transaction(), conn.cursor() as cur:
        _timeouts(cur)
        cur.execute(SELECT_SQL, {'method': METHOD, 'limit': limit})
        items = [_item(r) for r in cur.fetchall()]
        templates = read_templates(cur, {it['actor_group'] for it in items})
    report['selected'] = len(items)
    report['groups_with_templates'] = sum(1 for v in templates.values() if v)
    stop = None
    for i in range(0, len(items), WRITE_CHUNK):
        if time.time() >= deadline:
            stop = 'deadline'
            break
        chunk = items[i:i + WRITE_CHUNK]
        answers, stop = _ask_chunk(jev, chunk, report)
        rows = []
        for it in chunk:
            ja = answers.get(it['claim_key'])
            if not ja:
                continue
            dec = decide_claim(it, ja, templates.get(it['actor_group']))
            report['size']['estimated' if dec['size_band_est'] else ('abstained' if ja['size'] else 'not_asked')] += 1
            _tally(report, dec)
            rows.append((it, ja, dec))
        report['written'] += write(conn, rows)
        if stop:
            break
    report['stopped'] = stop
    report['left'] = len(items) - report['profiled']
    return _finish(report, t0, jev, budget)


def cmd_rescore(conn):
    """Re-apply every rule to the stored Jev answers. No network. A claim whose description changed is skipped
    (the next run re-profiles it)."""
    t0 = time.time()
    report = _new_report('rescore')
    with conn.transaction(), conn.cursor() as cur:
        _timeouts(cur)
        cur.execute(RESCORE_SQL, {'method': METHOD})
        raw = cur.fetchall()
        items = []
        for r in raw:
            it = _item(r)
            if r[len(_COLS)] != it['sha']:
                report['errors']['description_changed'] += 1
                continue
            items.append((it, r[len(_COLS) + 1]))
        templates = read_templates(cur, {it['actor_group'] for it, _ in items})
    report['selected'] = len(raw)
    rows = []
    for it, ja in items:
        dec = decide_claim(it, ja, templates.get(it['actor_group']))
        report['size']['estimated' if dec['size_band_est'] else ('abstained' if ja.get('size') else 'not_asked')] += 1
        _tally(report, dec)
        rows.append((it, ja, dec))
    for i in range(0, len(rows), 500):
        report['written'] += write(conn, rows[i:i + 500])
    return _finish(report, t0)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog='zdc-breach-profile', description=__doc__.split('\n')[0])
    ap.add_argument('--report', help='write the counts-only JSON report here')
    sub = ap.add_subparsers(dest='cmd', required=True)
    r = sub.add_parser('run', help='ask Jev about unprofiled (or changed) descriptions, newest first, and write')
    r.add_argument('--limit', type=int, default=300)
    r.add_argument('--deadline-min', type=float, default=30)
    r.add_argument('--max-usd', type=float, default=5.0, help='ceiling for this run')
    r.add_argument('--monthly-usd', type=float, default=float(os.environ.get('PROFILE_MONTHLY_USD', 10)),
                   help='ceiling for the calendar month across all runs (READINESS B: 10 USD)')
    sub.add_parser('rescore', help='re-apply the decision rules to stored Jev answers (no network)')
    args = ap.parse_args(argv)
    import psycopg
    conn = psycopg.connect(os.environ['DATABASE_URL'], autocommit=True)
    if args.cmd == 'rescore':
        rep = cmd_rescore(conn)
        code = 0
    else:
        rep, code = run_recorded(conn, args)
    text = json.dumps(rep, indent=2, sort_keys=True, default=str)
    if args.report:
        with open(args.report, 'w') as fh:
            fh.write(text)
    print(text)
    return code


PIPELINE = 'breach-profile'
EXIT_OUT_OF_FUNDS, EXIT_CEILING, EXIT_MODEL_GONE = 3, 4, 5


def month_spend_usd(conn) -> float:
    """Jev spend recorded by this pipeline's runs since the first of the month (UTC), local backfills included."""
    with conn.cursor() as cur:
        cur.execute("""select coalesce(sum((notes->>'usd')::numeric), 0) from raw.pipeline_runs
                        where pipeline = %s and started_at >= date_trunc('month', now() at time zone 'utc') at time zone 'utc'""",
                    (PIPELINE,))
        return float(cur.fetchone()[0])


def run_recorded(conn, args, transport=None, key=None, sleep=time.sleep):
    """One recorded run (raw.pipeline_runs, watched by tools/watchdog.py). Fails the run - so the watchdog and the
    workflow both see it - when TypeSafe stops offering the pinned model, when the monthly ceiling is reached, or when
    the account is out of funds. A run that profiled nothing because nothing was new is a success."""
    from zdc_kev import db as runs_db
    trigger = os.environ.get('GITHUB_EVENT_NAME') or 'manual'
    run_id = runs_db.start_run(conn, PIPELINE, 'incremental', trigger, os.environ.get('GITHUB_SHA'))
    spent = month_spend_usd(conn)
    left = max(0.0, args.monthly_usd - spent)
    budget = Budget(min(args.max_usd, left))
    jev = Jev(budget, key=key, transport=transport, sleep=sleep)
    rep, code, error = None, 0, None
    try:
        offered = jev.pin_answers() if left > 0 else None
    except OutOfFunds:
        offered, rep, code, error = None, _new_report('run', budget.max_usd), EXIT_OUT_OF_FUNDS, 'TypeSafe account out of funds'
    if code:
        pass
    elif offered is False:
        rep, code, error = _new_report('run', budget.max_usd), EXIT_MODEL_GONE, f'pinned model {MODEL} is no longer offered'
    elif left <= 0:
        rep, code, error = _new_report('run', 0), EXIT_CEILING, f'monthly ceiling {args.monthly_usd} USD reached'
    else:
        rep = cmd_run(conn, args.limit, args.deadline_min, budget.max_usd, jev=jev, budget=budget)
        if rep.get('stopped') == 'out_of_funds':
            code, error = EXIT_OUT_OF_FUNDS, 'TypeSafe account out of funds'
    rep['month_spend_usd'] = round(spent + float(rep.get('usd') or 0), 4)
    rep['monthly_ceiling_usd'] = args.monthly_usd
    rep['month_spend_share'] = round(rep['month_spend_usd'] / args.monthly_usd, 3) if args.monthly_usd else None
    rep['model_offered'] = offered
    errors = sum((rep.get('errors') or {}).values()) if isinstance(rep.get('errors'), dict) else 0
    runs_db.finish_run(conn, run_id, ok=code == 0, error=error, entries_seen=rep.get('selected', 0),
                       entries_inserted=rep.get('written', 0),
                       notes={'usd': float(rep.get('usd') or 0), 'profiled': rep.get('profiled', 0),
                              'month_spend_usd': rep['month_spend_usd'], 'errors': errors})
    return rep, code


if __name__ == '__main__':
    sys.exit(main())
