"""The company a leak post names, when the tracker's victim name is the post title (method breach-names-v1).

Some leak sites title a post with prose or decoration ("THE ENDGAME OF <COMPANY>' PSYCHOLOGICAL GAME",
"<company> - Database Leaked", "domain\\$rev\\country\\size\\DISCLOSED"), and the trackers copy the title into the
victim name. This module finds the company, or abstains. Migration 0172 shows the result on the leak list and groups
several posts of one actor group about one confirmed company into one entry.

  gate        only names carrying leak-post vocabulary are resolved (resolvable()). A name flagged only for length,
              punctuation, capitals or word count is left exactly as it is.
  candidates  deterministic (TypeSafe Jev cannot write strings): the tracker's domain and website field, the title
              with leak decoration stripped, hostnames in the title and description, capitalised spans and
              possessives, known organisation names (breach_core.organizations, multi-word only) and the actor
              group's other listed names found in the text. At most ten per post.
  Jev         one yes/no per candidate (question set names-q2, model jev-1.13.0): is it the victim this post is about?
  decide      p >= 0.6 is a yes; actor group names never count; the yes answers are clustered by name; exactly one
              company (or one name plus a hostname that is clearly the same company) renames, anything else abstains;
              a joined candidate naming several companies abstains; a pick that still carries leak wording abstains;
              a confirmed name before a comma wins over the longer string.
  canonical   one spelling per (actor group, company): swaps only among names Jev confirmed for that group's posts,
              same letters or a longer confirmed name starting with them, the spelling used by most posts.

Validation (sealed, fresh 60 title-like + 40 normal names, 2026-10-22): the right company in 31/31 renames (Wilson
LB 0.89), 0/10 no-victim or several-victim posts renamed, 0/40 normal names renamed. The owner's bar is "right
company"; a shown name can carry an extra word. Frozen research code: /tmp/zdcq/names/src3 (hashes in
FROZEN_method_v3.sha256). One deliberate change for reproducibility: the research gazetteer skipped single-word
organisation names found in the local dictionary file; production skips every single-word gazetteer name (a word list
differs between machines).

PUBLIC LOGS: the run prints and reports COUNTS ONLY - never a name, a title or a description. The dry-run plan file
of the backfill holds names and is written only where the operator asks (never in CI).

CLI:
  python -m zdc_breach.names run --limit N --deadline-min M --max-usd X     (daily, breach-profile workflow)
  python -m zdc_breach.names backfill --max-usd X [--dry-run --plan FILE]   (one-off)
  python -m zdc_breach.names recanon                                         (no network)
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
import sys
import time
import unicodedata
from datetime import timedelta

from zdc_breach.profile import MODEL, Budget, BudgetExhausted, Jev, OutOfFunds

METHOD = 'breach-names-v1'
QV = 'names-q2'
TAU = 0.6
MAX_CANDS = 10
DESC_MAX = 1500
PER_CALL = 4
WORKERS = 4
WRITE_CHUNK = 40
WINDOW_DAYS = 90
STATEMENT_TIMEOUT = '120s'
LOCK_TIMEOUT = '5s'

# =====================================================================================================
# Gate
# =====================================================================================================
DOMAIN = re.compile(r'^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$', re.I)
GATE_WORDS = re.compile(r"\b(leak(s|ed)?|drops?|dropped|updates?|secrets?|auction:|data auction|sell(ing)?|for sale|part\s*\d+|published|"
                        r"publish(ing)?|released|dump|incident|hacked|exposed|failed|stolen|compromised|full data|new data|more data|"
                        r"data of|files? of|documents? of|anatomy|endgame|game|press release|disclosed|breach(ed)?|we have|you have|"
                        r"they|their|our|your|here is|here are|download|\d+\s*(days?|hours?)|deadline|ignored?|negotiat\w*|silence|"
                        r"confidential|\d+\s*(gb|tb|mb|gigabytes?|terabytes?))\b", re.I)


def resolvable(name):
    """Only a name carrying leak-post vocabulary is resolved; a long or oddly punctuated name is left as it is."""
    n = (name or '').strip()
    return bool(n) and not DOMAIN.match(n) and bool(GATE_WORDS.search(n))


# =====================================================================================================
# Candidates
# =====================================================================================================
HOST = re.compile(r'(?i)(?<![\w@.-])(?:https?://)?(?:www\.)?((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?![\w-])')
BAD_HOST = re.compile(r'(?i)(\.onion$|^(t\.me|tox\.chat|gofile\.io|mega\.nz|mega\.io|dropmefiles|file\.io|anonfiles|qtox|telegram|'
                      r'twitter\.com|x\.com|linkedin\.com|facebook\.com|instagram\.com|youtube\.com|google\.com|github\.com|wikipedia\.org|'
                      r'bit\.ly|session\.|getsession|jabber|xmpp|proton|protonmail|gmail|outlook|hotmail|yahoo|onionmail|cock\.li|'
                      r'temp\.sh|limewire|catbox|pixeldrain|krakenfiles|sendspace|transfer\.sh|zoominfo|rocketreach|dnb\.com|'
                      r'opencorporates|crunchbase))')
FILE_EXT = re.compile(r'(?i)\.(zip|rar|7z|tar|gz|pdf|docx?|xlsx?|csv|sql|txt|bak|jpg|png|exe|dll|php|html?)$')
DECOR = [re.compile(p, re.I) for p in (
    r'^\s*\[[^\]]{2,30}\]\s*[-:–—]?\s*',                       # [Data Leaked] -, [DISCLOSED], [SELL]
    r'^\s*(leak|leaked|data leak|full leak|new leak|update|updated|sell|for sale|disclosed)\s*[:#\-–—]+\s*\d*\s*',
    r'^\s*leak\s*#?\s*\d+\s+',                                 # leak #1 <name>
    r'\s*\\\$+[\d.,]+[mbk]?\\.*$',                             # domain\$25.5M\USA\659GB\...
    r'\s*[-–—|:(<\[]*\s*(full leak|leaked|leak|data leak|database leaked|database leak|db leak|leak incident|hacked|breach(ed)?|'
    r'press release|update[ds]?|part\s*\d+|full dump|dump|disclosed|unpay|sold|for sale|file tree upload|download link updated|'
    r'data publication.*|sample.*|you have \d+ hours)\s*[)>\]]*\.?\s*$',
    r'\s*\|\s*[A-Z][\w .,]+$',                                 # "| USA, Austin, TX"
    r'\s+update\s*[-:]?\s*(full\s+)?(data\s+)?(dump|leak|data)?\s*$',
    r'\s*\(\s*\d+(\.\d+)?\s*(gb|tb|mb)\b[^)]*\)\s*$',
    r'\s*\[\s*\d+(\.\d+)?\s*(gb|tb|mb)\s*\]\s*$',
    r'\s*\((p|part)\s*\d+\)\s*$',
    r'\s+(was|were|has been|have been|got|is being)\s+(hacked|breached|attacked|compromised|encrypted)\b.*$',
    r'\s+(hacked|compromised|breached|leaked|attacked|encrypted|exposed|penetrated)\b\s*(\([^()]*\))?\s*[.!]*\s*$',
    r'\s*[-–—|:(\[]*\s*(compromised)\s*[)\]]*\.?\s*$',
)]
HACKTIVIST_PREFIX = re.compile(r"(?i)^\s*(the\s+)?(zionists?|zionist\s+regime(['’]s)?|israeli\s+occupation(['’]s)?|occupation(['’]s)?|enemy(['’]s)?)\s+")
TITLE_WORDS = re.compile(r"(?i)(?<![-\w])(leak|leaks|leaked|drops?|updates?|secrets?|auction|sell|sale|published|dump|incident|hacked|exposed|"
                         r"failed|stolen|compromised|penetrated|anatomy|endgame|we|you|they|their|our|your|here|download|"
                         r"deadline|negotiat\w*|silence|confidential|breach\w*|gb|tb)(?![-\w])")
DECOR_WORD = re.compile(r'(?i)\b(press release|full data|database|data leak|leak\w*|hacked|breach\w*|disclosed|for sale|sold|update[sd]?|'
                        r'part\s*\d+|dump|you have)\b')
STOP_SPAN = frozenset('''the a an and or of in on at to for from by with we our us you your they their them it its this that these those
he she his her i my me is are was were be been has have had will would can could should may might must not no yes
zionist zionists occupation does did do can will despite since although however besides anyways meanwhile therefore moreover furthermore
companies company also all any some more most other such into over under about after before during while if then than
there here what which who whom whose when where why how as so but up out new full data leak leaks leaked hacked breach update updates
part file files database db download sample proof today now days hours gb tb mb usd eur million billion inc ltd llc
january february march april may june july august september october november december monday tuesday wednesday thursday friday
saturday sunday headquarters industry website phone number address revenue employees ceo cfo it hr pii'''.split())
SPAN_TOKEN = r"(?:[A-Z][\w&-]*(?:\.[\w&-]+)*|\d+[A-Za-z][\w-]*)"
SPAN = re.compile(r"(?<![\w])(" + SPAN_TOKEN + r"(?:[ \t]+(?:(?:of|de|du|des|la|le|del|der|und|and|&|für|y|e|di|van|von|the)[ \t]+){0,2}"
                  + SPAN_TOKEN + r"){0,5})(['’]s?)?(?![\w])")
LEGAL_TAIL = re.compile(r"(?i)[,\s]+(inc|llc|ltd|limited|gmbh|corp|corporation|co|plc|s\.?a|s\.?r\.?l|s\.?p\.?a|ag|bv|nv|pty|pte)\.?$")
JOIN = re.compile(r'\s[-–—|/+]\s|\s{2,}[-–—]+\s{2,}')
TLD_OK = frozenset('''com net org gov edu mil int io co biz info pro app dev ai tech cloud online site store shop group global health law
ac ae ar at au az ba bd be bg bh bo br bw by ca ch cl cn cr cu cy cz de dk dz ec ee eg es et eu fi fj fr gh gr gt hk hn hr hu id ie il in iq ir
jo jp ke kg kh kr kw kz la lb lk lt lu lv ly ma md mk mm mn mo mt mu mv mx my mz na ng ni nl np nz om pa pe ph pk pl pr ps pt py qa ro rs ru
rw sa se sg si sk sn sv sy th tn tr tt tw tz ua ug uk uy uz ve vn ye za zm zw ao ga cm ci cd'''.split())
GAZ_STOP = frozenset({'linkedin', 'facebook', 'twitter', 'instagram', 'youtube', 'google', 'microsoft', 'telegram', 'verified', 'whatsapp'})
PRIO = {'dom': 0, 'strip': 1, 'sibling': 2, 'gaz': 3, 'textdom_title': 4, 'poss_title': 5, 'span_title': 5, 'poss_desc': 6,
        'textdom_desc': 6, 'span_desc': 7}


def unesc(s):
    s = s or ''
    for _ in range(12):                               # trackers double-escape: D&amp;amp;amp;V
        t = html.unescape(s)
        if t == s:
            break
        s = t
    return s


def balance(s):
    """Drop an unclosed bracket and everything after it, and a stray closing bracket."""
    s = s or ''
    for o, c in ('()', '[]', '{}', '<>'):
        while s.count(o) > s.count(c):
            s = s[:s.rfind(o)]
        while s.count(c) > s.count(o):
            i = s.find(c)
            s = s[:i] + s[i + 1:]
    return s.strip(' -–—|:,;/')


def joined(s):
    """'A - B - C': several names glued by separators."""
    return bool(JOIN.search(s or ''))


def squash(s):
    s = unicodedata.normalize('NFKD', s or '').encode('ascii', 'ignore').decode().lower()
    s = re.sub(r'^www\.', '', s)
    return re.sub(r'[^a-z0-9]', '', s)


def core_squash(s):
    """Letters and digits with a legal-form tail and a TLD removed: 'Zz Motors, Inc.' == 'zzmotors.com' == 'ZZ MOTORS'."""
    s = (s or '').strip()
    h = HOST.fullmatch(s)
    if h:
        lab = h.group(1).lower().split('.')
        lab = lab[-3] if len(lab) >= 3 and len(lab[-1]) == 2 and lab[-2] in ('co', 'com', 'org', 'net', 'ac', 'gov', 'edu') else lab[-2]
        return squash(lab)
    return squash(LEGAL_TAIL.sub('', s))


group_key = core_squash   # the SQL twin is breach_core.victim_group_key (0172); parity in test_breach_names_db.py


def case_score(s):
    return 1 if s.isupper() else 0 if s.islower() else 2


def keep_dot(s, t):
    if s and re.search(r'\b[A-Za-z]\.[A-Za-z]{1,2}$', s) and (s + '.') in (t or ''):
        return s + '.'
    return s


def strip_title(t):
    s = HACKTIVIST_PREFIX.sub('', t or '')
    for _ in range(3):
        before = s
        for p in DECOR:
            s = p.sub('', s)
        s = balance(s.strip(' -–—|:.,<>"“”'))
        if s == before:
            break
    return keep_dot(s.strip(), t)


def ok_host(h, actor_norm):
    h = h.lower()
    if h.rsplit('.', 1)[-1] not in TLD_OK:
        return False
    if BAD_HOST.search(h) or FILE_EXT.search(h) or re.match(r'^\d+(\.\d+)+$', h):
        return False
    lab = core_squash(h)
    if actor_norm and len(actor_norm) >= 3 and actor_norm in lab:
        return False                                   # the actor's own site
    return len(lab) >= 2


def name_shaped(s):
    if HOST.search(s) and not HOST.fullmatch(s.strip()):
        return False
    w = re.findall(r"[^\W_][\w'’&.-]*", s)
    return 1 <= len(w) <= 7 and len(s) <= 60 and not TITLE_WORDS.search(s) and re.search(r'[^\W\d_]{2}', s) is not None


def spans(text):
    out = []
    for m in SPAN.finditer(text or ''):
        words = m.group(1).strip(' .-&').split()
        while words and words[0].lower() in STOP_SPAN:
            words = words[1:]
        while words and words[-1].lower() in STOP_SPAN | {'of', 'de', 'and', '&', 'the'}:
            words = words[:-1]
        s = ' '.join(words)
        if not s or len(squash(s)) < 3 or (len(words) == 1 and words[0].lower() in STOP_SPAN):
            continue
        if re.fullmatch(r'(?i)[\d.,]+\s*(gb|tb|mb|kk|k|m)', s):
            continue
        out.append((s, bool(m.group(2))))
        for j in range(1, len(words)):                 # 'ENDGAME OF ZZ MOTORS' -> also 'ZZ MOTORS'
            if words[j - 1].lower() in ('of', 'the', 'de', 'at', 'for'):
                sub = ' '.join(words[j:])
                if len(squash(sub)) >= 3 and words[j].lower() not in STOP_SPAN:
                    out.append((sub, bool(m.group(2))))
    return out


def ngrams(text, nmax=6):
    toks = re.findall(r"[^\W_][\w&'’.-]*", text or '')
    for i in range(len(toks)):
        for k in range(1, nmax + 1):
            if i + k <= len(toks):
                yield ' '.join(toks[i:i + k])


class Gazetteer:
    """Known organisation names (multi-word only), keyed by squash."""

    def __init__(self, org_rows):
        self.by = {}
        for n, dom in org_rows:
            if not n or len(n.split()) < 2:
                continue
            k = squash(n)
            if len(k) >= 4:
                self.by.setdefault(k, (n, dom))

    def find(self, text):
        seen = {}
        for g in ngrams(text):
            k = squash(g)
            if k in self.by and k not in seen:
                seen[k] = self.by[k]
        return list(seen.values())


def candidates(post, gaz, siblings=()):
    """post: {title, desc, actor, domain, website}; siblings: [(name, domain)] the actor's other listed name-like names.
    -> [{name, domain, src: [...]}], merged on core_squash, at most MAX_CANDS."""
    title, desc = unesc(post.get('title')), unesc(post.get('desc'))
    actor_norm = re.sub(r'\d+$', '', squash(post.get('actor')))
    text = title + ' \n ' + desc
    raw = []
    for d in (post.get('domain'), post.get('website')):
        h = HOST.search(d or '')
        if h and ok_host(h.group(1), actor_norm):
            raw.append((h.group(1).lower(), h.group(1).lower(), 'dom'))
    st = strip_title(title)
    if st and st != title.strip():
        for part in [st] + re.split(r'\s+[-–—|/]\s+|\s{2,}', st):
            part = keep_dot(part.strip(' -–—|:.,()<>[]"“”'), title)
            hm = HOST.fullmatch(part) if part else None
            if part and name_shaped(part) and not hm:
                raw.append((part, None, 'strip'))
            elif hm and ok_host(hm.group(1), actor_norm):
                raw.append((hm.group(1).lower(), hm.group(1).lower(), 'strip'))
    for where, t in (('title', title), ('desc', desc)):
        for h in HOST.finditer(t):
            raw_h = h.group(0)
            prefixed = raw_h.lower().startswith(('http', 'www.'))
            # prose like 'action.In two days' is not a host: unprefixed hosts are lower case and not 'word.in'
            if ok_host(h.group(1), actor_norm) and (prefixed or (raw_h == raw_h.lower() and not re.match(
                    r'^[a-z]+\.(in|is|it|me|be|at|to|no|so|us|as|am|do|go|my|by|on|or|an|la|id)$', raw_h))):
                raw.append((h.group(1).lower(), h.group(1).lower(), 'textdom_' + where))
    for where, t in (('title', title), ('desc', desc[:DESC_MAX])):
        for s, poss in spans(t):
            if name_shaped(s) or poss:
                raw.append((s, None, ('poss_' if poss else 'span_') + where))
    for n, dom in gaz.find(text):
        if squash(n) not in GAZ_STOP:
            raw.append((n, dom, 'gaz'))
    sib = {core_squash(n): (n, d) for n, d in siblings if len(core_squash(n)) >= 4}
    for g in ngrams(text, 4):
        k = core_squash(g)
        if k in sib:
            raw.append((sib[k][0], sib[k][1], 'sibling'))
    raw.sort(key=lambda x: PRIO.get(x[2], 9))
    merged = {}
    for name, dom, src in raw:
        name = name if HOST.fullmatch(name) else balance(name)
        if not name:
            continue
        k = core_squash(name)
        if (len(k) < 3 and not (dom or HOST.fullmatch(name))) or len(k) < 2 or k == actor_norm:
            continue
        m = merged.setdefault(k, {'name': name, 'domain': dom, 'src': []})
        if src not in m['src']:
            m['src'].append(src)
        if dom and not m['domain']:
            m['domain'] = dom
        cur_host, new_host = HOST.fullmatch(m['name']) is not None, HOST.fullmatch(name) is not None
        if (cur_host and not new_host) or (cur_host == new_host and (case_score(name), len(name.split()))
                                           > (case_score(m['name']), len(m['name'].split()))):
            m['name'] = name
    out = list(merged.values())
    freq = lambda c: len(re.findall(re.escape(c['name']), text, re.I))  # noqa: E731
    out.sort(key=lambda c: (min(PRIO.get(x, 9) for x in c['src']), -len(c['src']), -freq(c)))
    return out[:MAX_CANDS]


# =====================================================================================================
# Decision
# =====================================================================================================
def actor_norm_set(rows):
    out = set()
    for a in rows:
        a = re.sub(r'[^a-z0-9]', '', (a or '').lower())
        if len(a) >= 3:
            out.add(a)
            out.add(re.sub(r'\d+$', '', a))
    out.discard('')
    return frozenset(out)


def is_actor(name, actor_norms):
    k = core_squash(name)
    return len(k) >= 3 and (k in actor_norms or re.sub(r'\d+$', '', k) in actor_norms)


def decorated(name):
    return bool(TITLE_WORDS.search(name) or DECOR_WORD.search(name) or strip_title(name) != name)


def host_matches(host, name):
    """A hostname and a spelled name are clearly one company: one's letters contain the other's, or the name's
    initials (3 or more) are the host's label."""
    lab, nm = core_squash(host), core_squash(name)
    ini = ''.join(w[0] for w in re.findall(r'[^\W\d_]+', name)).lower()
    return bool(lab and nm) and (lab in nm or nm in lab or (len(ini) >= 3 and ini == lab))


def same_org(a, b):
    a, b = core_squash(a), core_squash(b)
    if not a or not b:
        return False
    if a in b or b in a:
        return True
    k = 0
    while k < min(len(a), len(b)) and a[k] == b[k]:
        k += 1
    return k >= max(5, 0.8 * min(len(a), len(b)))


def clusters(yes):
    cl = []
    for c in yes:
        hits = [g for g in cl if any(same_org(c['name'], x['name']) for x in g)]
        if hits:
            hits[0].append(c)
        else:
            cl.append([c])
    return cl


def decide(cands, answers, actor_norms=frozenset(), tau=TAU):
    """-> (chosen name or None, reason, p). answers: {'c1': {'noul': p}, ...} in candidate order."""
    if not cands:
        return None, 'no_candidates', None
    scored = []
    for k, c in enumerate(cands):
        p = ((answers or {}).get('c%d' % (k + 1)) or {}).get('noul')
        if p is not None:
            scored.append(dict(c, p=p))
    yes = sorted([c for c in scored if c['p'] >= tau and not is_actor(c['name'], actor_norms)], key=lambda c: -c['p'])
    if not yes:
        return None, 'abstain_none', max([c['p'] for c in scored], default=None)
    for c in yes:                                      # a joined candidate naming several companies: several victims
        if joined(c['name']):
            parts = [x for x in JOIN.split(c['name']) if len(squash(x)) >= 3]
            if len({core_squash(x) for x in parts}) >= 2 and not all(same_org(parts[0], x) for x in parts[1:]):
                return None, 'abstain_several', c['p']
    cl = clusters([c for c in yes if not joined(c['name'])])
    if not cl:
        return None, 'abstain_none', yes[0]['p']
    # a cluster bridged by a string that holds two companies ('Zza Tools Zzb Foods') is several victims: every two
    # members of a cluster must name the same company directly
    if any(not same_org(a['name'], b['name']) for g in cl for i, a in enumerate(g) for b in g[i + 1:]):
        return None, 'abstain_several', yes[0]['p']
    names = [g for g in cl if any(not HOST.fullmatch(x['name']) for x in g)]
    hosts = [g for g in cl if g not in names]
    if len(cl) == 1:
        g = cl[0]
    elif len(names) == 1 and len(hosts) == 1 and any(host_matches(h['name'], n['name']) for h in hosts[0] for n in names[0]):
        g = names[0] + hosts[0]
    else:
        return None, 'abstain_several', yes[0]['p']
    spelled = [x for x in g if not HOST.fullmatch(x['name']) and name_shaped(x['name'])]
    stripped = [x for x in spelled if 'strip' in x['src']]
    if stripped:
        pick = sorted(stripped, key=lambda x: -x['p'])[0]
    else:
        pick = sorted(spelled or g, key=lambda x: (-round(x['p'], 1), len(x['name'])))[0]
    if ', ' in pick['name']:                           # a confirmed name before a comma wins
        head = pick['name'].split(', ')[0]
        for c in yes:
            if core_squash(c['name']) == core_squash(head) and not joined(c['name']):
                pick = c
                break
    if decorated(pick['name']):
        return None, 'abstain_decorated', pick['p']
    return pick['name'], 'renamed', pick['p']


def spelling_of(s, chosen):
    a, b = core_squash(s), core_squash(chosen)
    return bool(a and b) and a.count(b) == 1 and (a == b or (a.startswith(b) and len(b) >= 4))


def well_formed(s):
    return (not HOST.fullmatch(s) and name_shaped(s) and not s.islower() and not decorated(s)
            and not (s.isupper() and len(s.replace(' ', '')) > 5))


def canonical(chosen, confirmed):
    """One spelling per (actor group, company). confirmed: [(chosen_name, claim_key)] of the group's renamed posts."""
    if not chosen:
        return chosen
    posts = collections.defaultdict(set)
    for s, k in confirmed:
        if well_formed(s) and not joined(s) and spelling_of(s, chosen):
            posts[s].add(k)
    if not posts:
        return chosen
    best = max(posts, key=lambda x: (len(posts[x]), len(x.split()), -len(x)))
    return best if len(posts[best]) >= len(posts.get(chosen, ())) else chosen


# =====================================================================================================
# Jev
# =====================================================================================================
QUESTION = ('`{p}` is a post on a ransomware or extortion group\'s leak site (title `{p}.title`, text `{p}.text`). Every such post '
            'is about a victim: an organisation the group claims to have breached, often described only by a company profile. Is `{c}` '
            'the name (or website) of that victim organisation, the one this post is about? Answer no if `{c}` is only a country, '
            'city or region, a product, project or technology, a person, the attacking group itself, an authority or company merely '
            'mentioned (a regulator, a news outlet, a partner or customer that was not attacked), or a generic word or fragment '
            'rather than an organisation name.')


def q_hash():
    return hashlib.sha256((QV + QUESTION).encode()).hexdigest()[:16]


def build(items):
    state, qs, meta = {'posts': {}}, {}, {}
    for n, it in enumerate(items):
        pid = 'p%d' % (n + 1)
        ref = 'posts.' + pid
        cands = it['cands'][:MAX_CANDS]
        state['posts'][pid] = {'title': it['title'], 'text': (it.get('desc') or '')[:DESC_MAX] or None, 'group': it['actor'],
                               'candidates': {'c%d' % (k + 1): c['name'] for k, c in enumerate(cands)}}
        for k in range(len(cands)):
            qs[f'{pid}_c{k + 1}'] = {'type': 'noul', 'instructions': QUESTION.format(c=f'{ref}.candidates.c{k + 1}', p=ref)}
        meta[pid] = it['claim_key']
    return state, qs, meta


def ask(jev, items):
    """{claim_key: {'c1': {...}, ..., 'model': ...}} for the posts Jev answered completely."""
    st, qs, meta = build(items)
    js = jev.ask(st, qs)
    A = js.get('answers') or {}
    out = {}
    for pid, ck in meta.items():
        ans = {k[len(pid) + 1:]: v for k, v in A.items() if k.startswith(pid + '_')}
        n = len(next(it for it in items if it['claim_key'] == ck)['cands'][:MAX_CANDS])
        if all(('c%d' % (k + 1)) in ans for k in range(n)):
            ans['model'] = js.get('model')
            out[ck] = ans
    return out


# =====================================================================================================
# Grouping preview (the list itself is grouped by rebuild_victims_list() step G, 0172)
# =====================================================================================================
def plan_groups(rows, window_days=WINDOW_DAYS):
    """rows: [{victim_id, actor, name, seen (datetime), resolved (bool)}] of listed leak claims. -> [[victim_id, ...]]
    of entries with more than one post: same actor group, same group key, at least one resolved post, 90-day windows
    anchored at each window's first post. Mirrors rebuild_victims_list() step G."""
    by = collections.defaultdict(list)
    for r in rows:
        k = group_key(r['name'])
        if len(k) >= 3:
            by[(r['actor'], k)].append(r)
    out = []
    for key in sorted(by):
        rs = by[key]
        if not any(r['resolved'] for r in rs):
            continue
        rs.sort(key=lambda r: (r['seen'], r['victim_id']))
        cur, start = [], None
        for r in rs:
            if start is None or r['seen'] > start + timedelta(days=window_days):
                if len(cur) > 1:
                    out.append([x['victim_id'] for x in cur])
                cur, start = [], r['seen']
            cur.append(r)
        if len(cur) > 1:
            out.append([x['victim_id'] for x in cur])
    return out


# =====================================================================================================
# Database. Every reader takes q(sql, params) -> rows, so the dry-run can read through any read-only channel.
# =====================================================================================================
# The leak claims public.breach_leak_victims lists (its WHERE, without the joins that only add columns), by their
# ORIGINAL title: what 0149 hides is never resolved.
LISTED_SQL = """
select l.claim_key, l.victim_name, l.actor_group, l.victim_domain, l.first_seen_at
  from breach_core.leak_claims l
  left join breach_core.incidents i on i.incident_id = l.incident_id
 where (i.incident_id is null or not i.suppressed)
   and not breach_core.is_generic_name(l.victim_name, l.actor_group)
"""
DONE_SQL = "select claim_key from breach_core.victim_name_resolution where method_version = %(method)s"
TEXT_SQL = """
select l.claim_key, array_agg(x.descr order by x.ord) filter (where x.descr <> '') as descrs, max(x.website) as website
  from breach_core.leak_claims l
  cross join lateral (
        select distinct on (s.source_id, s.source_record_id) left(coalesce(s.record->>'description', ''), 1500) as descr,
               nullif(s.record->>'website', '') as website, r.ord
          from jsonb_array_elements(l.tracker_refs) with ordinality r(ref, ord)
          join breach_raw.source_records s on s.source_id = r.ref->>'source_id' and s.source_record_id = r.ref->>'id'
         order by s.source_id, s.source_record_id, s.version desc) x
 where l.claim_key = any(%(keys)s)
 group by l.claim_key
"""
ORGS_SQL = "select display_name, domain from breach_core.organizations where not coalesce(is_natural_person, false)"
ACTORS_SQL = """
select alias_norm from breach_core.actor_aliases
union
select lower(regexp_replace(actor_group, '[^a-zA-Z0-9]', '', 'g')) from breach_core.leak_claims
"""
CONFIRMED_SQL = """
select r.claim_key, l.actor_group, r.chosen_name, r.resolved_name
  from breach_core.victim_name_resolution r join breach_core.leak_claims l using (claim_key)
 where r.reason = 'renamed' and r.method_version = %(method)s and l.actor_group = any(%(actors)s)
"""


def psycopg_query(conn):
    def q(sql, params=None):
        with conn.cursor() as cur:
            cur.execute(f"set statement_timeout = '{STATEMENT_TIMEOUT}'")
            cur.execute(sql, params or {})
            return cur.fetchall() if cur.description else []
    return q


def load_context(q, dry_run=False):
    """The listed claims, the actor groups' sibling names, the gazetteer and the actor names."""
    listed = [dict(zip(('claim_key', 'title', 'actor', 'domain', 'seen'), r)) for r in q(LISTED_SQL)]
    sib = collections.defaultdict(list)
    for r in listed:
        if not resolvable(r['title']):
            sib[r['actor']].append((r['title'], r['domain']))
    gaz = Gazetteer([(n, d) for n, d in q(ORGS_SQL)])
    actor_norms = actor_norm_set([r[0] for r in q(ACTORS_SQL)])
    done = set() if dry_run else {r[0] for r in q(DONE_SQL, {'method': METHOD})}
    return listed, sib, gaz, actor_norms, done


def items_for(q, rows, sib, gaz):
    """Attach description, website and candidates to the selected listed claims."""
    if not rows:
        return []
    text = {k: (d, w) for k, d, w in q(TEXT_SQL, {'keys': [r['claim_key'] for r in rows]})}
    out = []
    for r in rows:
        descrs, website = text.get(r['claim_key'], (None, None))
        desc = ' '.join(dict.fromkeys(descrs or []))[:DESC_MAX]
        it = dict(r, desc=desc, website=website)
        it['sha'] = hashlib.sha256('\n'.join([r['title'] or '', desc, website or '', r['domain'] or '']).encode()).hexdigest()
        it['cands'] = candidates(it, gaz, [s for s in sib.get(r['actor'], []) if s[0] != r['title']])
        out.append(it)
    return out


def write(conn, rows):
    """rows: [(item, answers or None, (chosen, reason, p))]. Upsert; resolved_name is set by recanon()."""
    from psycopg.types.json import Jsonb
    if not rows:
        return 0
    with conn.transaction(), conn.cursor() as cur:
        cur.execute(f"set local statement_timeout = '{STATEMENT_TIMEOUT}'")
        cur.execute(f"set local lock_timeout = '{LOCK_TIMEOUT}'")
        cur.execute("""insert into breach_core.victim_name_resolution
                           (claim_key, method_version, model, input_sha256, candidates, jev_answers, chosen_name, resolved_name,
                            reason, p, decided_at)
                       select x.k, %s, x.m, x.sha, x.c, x.a, x.ch, x.ch, x.r, x.p, now()
                         from unnest(%s::text[], %s::text[], %s::text[], %s::jsonb[], %s::jsonb[], %s::text[], %s::text[], %s::numeric[])
                              as x(k, m, sha, c, a, ch, r, p)
                       on conflict (claim_key) do update set
                           method_version = excluded.method_version, model = excluded.model, input_sha256 = excluded.input_sha256,
                           candidates = excluded.candidates, jev_answers = excluded.jev_answers, chosen_name = excluded.chosen_name,
                           resolved_name = excluded.resolved_name, reason = excluded.reason, p = excluded.p,
                           decided_at = excluded.decided_at""",
                    (METHOD, [it['claim_key'] for it, _, _ in rows], [(a or {}).get('model') or (MODEL if a else None) for _, a, _ in rows],
                     [it['sha'] for it, _, _ in rows], [Jsonb(it['cands']) for it, _, _ in rows],
                     [Jsonb(dict(a, qv=QV)) if a else None for _, a, _ in rows], [d[0] for _, _, d in rows],
                     [d[1] for _, _, d in rows], [d[2] for _, _, d in rows]))
    return len(rows)


def recanon(conn, q, actors=None):
    """resolved_name = canonical(chosen_name) over each actor group's renamed posts. No network. -> rows changed."""
    if actors is None:
        actors = [r[0] for r in q("select distinct l.actor_group from breach_core.victim_name_resolution r "
                                  "join breach_core.leak_claims l using (claim_key) where r.reason = 'renamed'")]
    rows = q(CONFIRMED_SQL, {'method': METHOD, 'actors': sorted(set(actors))}) if actors else []
    by = collections.defaultdict(list)
    for k, a, ch, _ in rows:
        by[a].append((ch, k))
    upd = [(canonical(ch, by[a]), k) for k, a, ch, cur in rows if canonical(ch, by[a]) != cur]
    if upd:
        with conn.transaction(), conn.cursor() as cur:
            cur.execute(f"set local statement_timeout = '{STATEMENT_TIMEOUT}'")
            cur.execute("""update breach_core.victim_name_resolution r set resolved_name = x.n
                             from unnest(%s::text[], %s::text[]) as x(n, k) where r.claim_key = x.k""",
                        ([n for n, _ in upd], [k for _, k in upd]))
    return len(upd)


# =====================================================================================================
# Commands
# =====================================================================================================
def _report(mode, max_usd):
    return {'mode': mode, 'method_version': METHOD, 'model': MODEL, 'q_hash': q_hash(), 'listed': 0, 'resolvable': 0,
            'selected': 0, 'asked': 0, 'reasons': collections.Counter(), 'written': 0, 'canonical_changed': 0,
            'groups_planned': 0, 'posts_in_groups': 0, 'errors': collections.Counter(), 'max_usd': max_usd}


def resolve_items(jev, items, report, deadline, actor_norms):
    """Ask Jev (PER_CALL posts per call, WORKERS threads) and decide. -> ([(item, answers, decision)], stop)."""
    out, stop = [], None
    ask_list = [it for it in items if it['cands']]
    for it in items:
        if not it['cands']:
            out.append((it, None, decide([], None)))
    answers = {}
    calls = [ask_list[i:i + PER_CALL] for i in range(0, len(ask_list), PER_CALL)]
    with cf.ThreadPoolExecutor(WORKERS) as ex:
        futs = []
        for ch in calls:
            if time.time() >= deadline:
                stop = 'deadline'
                break
            futs.append(ex.submit(ask, jev, ch))
        for f in futs:
            try:
                answers.update(f.result())
            except BudgetExhausted:
                stop = stop or 'budget'
            except OutOfFunds:
                stop = 'out_of_funds'
            except Exception as e:  # noqa: BLE001 - counted by type only (public log)
                report['errors'][type(e).__name__] += 1
    for it in ask_list:
        a = answers.get(it['claim_key'])
        if a is None:
            continue
        report['asked'] += 1
        out.append((it, a, decide(it['cands'], a, actor_norms)))
    return out, stop


def cmd_resolve(q, conn, *, mode, limit, deadline_min, max_usd, dry_run=False, plan=None, jev=None, budget=None):
    t0 = time.time()
    report = _report(mode, max_usd)
    listed, sib, gaz, actor_norms, done = load_context(q, dry_run=dry_run)
    report['listed'] = len(listed)
    todo = [r for r in listed if resolvable(r['title'])]
    report['resolvable'] = len(todo)
    todo = sorted([r for r in todo if r['claim_key'] not in done], key=lambda r: (r['seen'], r['claim_key']), reverse=True)[:limit]
    report['selected'] = len(todo)
    budget = budget or Budget(max_usd)
    jev = jev or Jev(budget)
    deadline = t0 + deadline_min * 60
    decided, stop = [], None
    for i in range(0, len(todo), WRITE_CHUNK):
        if time.time() >= deadline:
            stop = 'deadline'
            break
        items = items_for(q, todo[i:i + WRITE_CHUNK], sib, gaz)
        rows, stop = resolve_items(jev, items, report, deadline, actor_norms)
        for _, _, d in rows:
            report['reasons'][d[1]] += 1
        decided.extend(rows)
        if not dry_run:
            report['written'] += write(conn, rows)
        if stop:
            break
    actors = sorted({it['actor'] for it, _, d in decided if d[1] == 'renamed'})
    if dry_run:
        # canonical over this plan's renamed posts (plus nothing stored: a dry run reads no resolutions)
        by = collections.defaultdict(list)
        for it, _, d in decided:
            if d[1] == 'renamed':
                by[it['actor']].append((d[0], it['claim_key']))
        resolved = {it['claim_key']: canonical(d[0], by[it['actor']]) for it, _, d in decided if d[1] == 'renamed'}
        report['canonical_changed'] = sum(1 for it, _, d in decided if d[1] == 'renamed' and resolved[it['claim_key']] != d[0])
        rows = [{'victim_id': 'claim:' + r['claim_key'], 'actor': r['actor'], 'seen': r['seen'],
                 'name': resolved.get(r['claim_key']) or r['title'], 'resolved': r['claim_key'] in resolved}
                for r in listed if r['actor'] in set(actors)]
        groups = plan_groups(rows)
        report['groups_planned'] = len(groups)
        report['posts_in_groups'] = sum(len(g) for g in groups)
        if plan:
            title = {r['claim_key']: r['title'] for r in listed}
            with open(plan, 'w') as fh:
                json.dump({'method_version': METHOD, 'q_hash': q_hash(),
                           'decisions': [{'claim_key': it['claim_key'], 'actor': it['actor'], 'post_title': it['title'],
                                          'reason': d[1], 'p': d[2], 'chosen_name': d[0],
                                          'resolved_name': resolved.get(it['claim_key']),
                                          'candidates': [c['name'] for c in it['cands']]} for it, _, d in decided],
                           'groups': [[{'victim_id': v, 'post_title': title.get(v[6:])} for v in g] for g in groups]},
                          fh, indent=1, default=str, ensure_ascii=False)
    else:
        report['canonical_changed'] = recanon(conn, q, actors)
    report['stopped'] = stop
    report['left'] = len(todo) - len(decided)
    report['reasons'] = dict(sorted(report['reasons'].items()))
    report['errors'] = dict(sorted(report['errors'].items()))
    report.update(calls=budget.calls, input_tokens=budget.input_tokens, usd=round(budget.spent_usd, 4),
                  http_status=dict(sorted(jev.status.items())) if hasattr(jev, 'status') else {},
                  seconds=round(time.time() - t0, 1))
    return report


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog='zdc-breach-names', description=__doc__.split('\n')[0])
    ap.add_argument('--report', help='write the counts-only JSON report here')
    sub = ap.add_subparsers(dest='cmd', required=True)
    r = sub.add_parser('run', help='resolve new title-like leak claims, newest first (daily)')
    r.add_argument('--limit', type=int, default=400)
    r.add_argument('--deadline-min', type=float, default=15)
    r.add_argument('--max-usd', type=float, default=0.5)
    b = sub.add_parser('backfill', help='resolve every title-like leak claim not resolved yet (one-off)')
    b.add_argument('--limit', type=int, default=100000)
    b.add_argument('--deadline-min', type=float, default=60)
    b.add_argument('--max-usd', type=float, default=0.5)
    b.add_argument('--dry-run', action='store_true', help='write nothing to the database')
    b.add_argument('--plan', help='dry run only: write the plan (names included - keep it private) here')
    sub.add_parser('recanon', help='recompute the one spelling per actor group and company (no network)')
    args = ap.parse_args(argv)
    if getattr(args, 'plan', None) and not args.dry_run:
        ap.error('--plan needs --dry-run')
    import psycopg
    conn = psycopg.connect(os.environ['DATABASE_URL'], autocommit=True)
    q = psycopg_query(conn)
    if args.cmd == 'recanon':
        rep = {'mode': 'recanon', 'method_version': METHOD, 'canonical_changed': recanon(conn, q)}
    else:
        if getattr(args, 'dry_run', False):
            conn.execute("set default_transaction_read_only = on")   # a dry run cannot write, whatever the code does
        rep = cmd_resolve(q, conn, mode=args.cmd, limit=args.limit, deadline_min=args.deadline_min, max_usd=args.max_usd,
                          dry_run=getattr(args, 'dry_run', False), plan=getattr(args, 'plan', None))
    text = json.dumps(rep, indent=2, sort_keys=True, default=str)
    if args.report:
        with open(args.report, 'w') as fh:
            fh.write(text)
    print(text)
    return 3 if rep.get('stopped') == 'out_of_funds' else 0


if __name__ == '__main__':
    sys.exit(main())
