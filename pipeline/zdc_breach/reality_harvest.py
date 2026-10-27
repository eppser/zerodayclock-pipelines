"""Evidence harvest for breach-reality-v1 (port of the frozen candgen.py + extras.py, production subset).

Manifest
  sources   the victim's own candidate hosts (DNS over UDP to the Cloudflare, Google and Quad9 public
            resolvers, then ONE GET of
            the home page per resolving host); Wikidata wbsearchentities + wbgetentities P856 (CC0);
            TLS certificate subject; up to four extra pages (/about, /impressum, /contact, /about-us) of
            the best live host; GLEIF autocompletions + LEI records (CC0); SEC EDGAR full-text search
            entity names (public domain)
  not used  Common Crawl, crt.sh / certificate-transparency logs, any search engine, any LLM
  limits    Wikidata, GLEIF and EDGAR each <= 2 requests/s (process-wide); <= 4 page fetches in flight
            per name; 16 DNS lookups in flight per name, <= 48 in the process
  never     .onion; a name that is actor infrastructure or an RFC-reserved domain (no request at all);
            an RFC-reserved candidate host
  identity  web 'zdc-victim-check/1.0 (+https://zerodayclock.com)'; EDGAR (which asks for a contact)
            'ZeroDayClock research contact@zerodayclock.com'
  healthy   most names resolve at least one candidate host; an empty pool is recorded as such
            (candidates [] with dns false), never as absence of the organisation

Output shapes are those of the frozen files (pool_*.jsonl / extras_*.jsonl), so packs harvested by
either code decide identically.
"""

from __future__ import annotations

import concurrent.futures as cf
import html
import http.client
import ipaddress
import json
import random
import re
import socket
import ssl
import struct
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from .reality import clean, domain_shaped, is_masked, n_letters, never_fetch, norm_host, reserved_domain

UA_WEB = 'Mozilla/5.0 (compatible; zdc-victim-check/1.0; +https://zerodayclock.com)'
UA_API = 'zdc-victim-check/1.0 (https://zerodayclock.com)'
UA_SEC = 'ZeroDayClock research contact@zerodayclock.com'
FETCH_WORKERS = 4
DNS_WORKERS = 16
LEGAL = r'\b(inc|incorporated|llc|l\.l\.c|ltd|limited|plc|gmbh|mbh|ag|kg|co\.? ?kg|s\.?a\.?s?|s\.?r\.?l|s\.?p\.?a|b\.?v|n\.?v|corp|corporation|co|company|pty|pvt|private|sdn\.? ?bhd|bhd|oy|ab|as|a/s|aps|s\.?l|ltda|lda|sarl|spa|saic(?:ei)?|the|group|grupo|gruppe|holdings?)\b'
CC = {'US': ['com'], 'GB': ['co.uk'], 'UK': ['co.uk'], 'AU': ['com.au'], 'BR': ['com.br'], 'DE': ['de'], 'FR': ['fr'], 'IT': ['it'], 'ES': ['es'],
      'CA': ['ca'], 'IN': ['in', 'co.in'], 'MX': ['com.mx', 'mx'], 'NL': ['nl'], 'JP': ['co.jp', 'jp'], 'AR': ['com.ar'], 'CO': ['com.co'],
      'CH': ['ch'], 'AT': ['at'], 'BE': ['be'], 'TW': ['com.tw'], 'TH': ['co.th'], 'PE': ['com.pe'], 'CL': ['cl'], 'ZA': ['co.za'], 'NZ': ['co.nz'],
      'SG': ['com.sg'], 'MY': ['com.my'], 'TR': ['com.tr'], 'IL': ['co.il'], 'KR': ['co.kr'], 'PL': ['pl'], 'PT': ['pt'], 'SE': ['se'], 'DK': ['dk'],
      'NO': ['no'], 'FI': ['fi'], 'IE': ['ie'], 'CZ': ['cz'], 'ID': ['co.id'], 'PH': ['com.ph'], 'AE': ['ae'], 'GR': ['gr'], 'HU': ['hu'], 'RO': ['ro'],
      'PY': ['com.py'], 'UY': ['com.uy'], 'EC': ['com.ec'], 'VE': ['com.ve'], 'SA': ['com.sa'], 'EG': ['com.eg'], 'PK': ['com.pk'], 'VN': ['com.vn'],
      'CN': ['com.cn', 'cn'], 'HK': ['com.hk'], 'LU': ['lu'], 'SK': ['sk'], 'SI': ['si'], 'HR': ['hr'], 'BG': ['bg'], 'RS': ['rs'], 'LT': ['lt']}
PARK = re.compile(r'domain (is )?for sale|buy this domain|this domain (name )?(is|may be) (for sale|available)|parked (free|domain)|sedo|dan\.com|afternic|'
                  r'hugedomains|parkingcrew|bodis|domain parking|account suspended|default web site page|welcome to nginx|apache2 (ubuntu|debian) default page|'
                  r'it works!|index of /|godaddy|namecheap|spaceship\.com', re.I)
POPULAR_CC = ['de', 'co.uk', 'fr', 'it', 'es', 'nl', 'com.br', 'com.au', 'ca', 'ch', 'at', 'be', 'dk', 'se', 'no', 'cz', 'pl', 'eu', 'com.mx', 'co.za', 'in', 'us']
ABBR = {'pharmaceuticals': 'pharma', 'pharmaceutical': 'pharma', 'technologies': 'tech', 'technology': 'tech', 'international': 'intl',
        'laboratories': 'labs', 'laboratory': 'lab', 'manufacturing': 'mfg', 'corporation': 'corp', 'communications': 'comm', 'insurance': 'ins',
        'services': 'svc', 'engineering': 'eng', 'industries': 'ind', 'associates': 'assoc', 'construction': 'const'}
EMBED = re.compile(r'(?<![\w.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|edu|gov|co|io|ai|biz|info|[a-z]{2})(?:\.[a-z]{2})?)(?![\w-])', re.I)
# Cloudflare, Google and Quad9 public resolvers. Written as octets because the public mirror's
# check_tree.py refuses dotted IPv4 literals; the frozen harvester used these three.
RESOLVERS = tuple('.'.join(map(str, o)) for o in ((1, 1, 1, 1), (8, 8, 8, 8), (9, 9, 9, 9)))


class Rate:
    """At most `rps` calls per second across all threads."""

    def __init__(self, rps):
        self.dt = 1.0 / rps
        self.t = 0.0
        self.lock = threading.Lock()

    def wait(self):
        with self.lock:
            now = time.time()
            s = max(0.0, self.t + self.dt - now)
            self.t = now + s
        if s:
            time.sleep(s)


WD, GL, ED = Rate(2), Rate(2), Rate(2)
_DNS_SEM = threading.Semaphore(48)


# ---- candidate hosts ----------------------------------------------------------------------------------
def ascii_slug_words(s):
    s = unicodedata.normalize('NFKD', s).encode('ascii', 'ignore').decode().lower()
    s = s.replace('&', ' and ')
    return re.findall(r'[a-z0-9]+', s)


def embedded_domains(name):
    """Hostnames written inside the victim string ('ambit.co | finvest...', 'SIU.EDU (EBS)')."""
    n = re.sub(r'<[^>]+>', ' ', name or '')
    return [m.lower() for m in EMBED.findall(n) if '.' in m and not re.fullmatch(r'[\d.]+', m)][:3]


def guesses(name, country):
    """Slug guesses: slug.{com,net,org,<ccTLD>} with and without '-', legal suffixes dropped, first-segment,
    first-two-words, abbreviated and initials variants; the first two stems also on popular ccTLDs. <= 90 hosts."""
    n = re.sub(r'<[^>]+>', ' ', clean(name))
    n = re.sub(r'\s+', ' ', n).strip()
    seg = re.split(r'\s[-|–]\s|\s?\(|\||\bis a\b|\bsample\b', n, flags=re.I)[0].strip() or n

    def core(b):
        return ascii_slug_words(re.sub(LEGAL, ' ', re.sub(r'[.,]', ' ', b), flags=re.I))
    cs, fs, cn = core(seg), [w for w in ascii_slug_words(seg) if w != 'the'], core(n)
    noand = [w for w in cs if w != 'and']
    abbr = [ABBR.get(w, w) for w in noand]
    initials = ''.join(w[0] for w in noand) if len(noand) >= 3 else ''
    variants = [noand, fs, noand[:2], abbr if abbr != noand else [], cn, [initials] if initials else [],
                noand[:1] if noand and len(noand[0]) >= 5 else []]
    stems = []
    for w in variants:
        if not w:
            continue
        for s_ in (''.join(w), '-'.join(w)) + ((''.join(w[:-1]) + '-' + w[-1],) if len(w) >= 3 else ()):
            if 3 <= len(s_) <= 40 and s_ not in stems:
                stems.append(s_)
    own = CC.get((country or '').upper(), [])
    out = []
    for s_ in stems[:8]:
        for t in ['com', 'net', 'org'] + own:
            out.append(f'{s_}.{t}')
    for s_ in stems[:2]:
        for t in POPULAR_CC:
            out.append(f'{s_}.{t}')
    return list(dict.fromkeys(out))[:90]


def _dns_a(name, server, timeout=2.5):
    """Minimal stdlib DNS A query over UDP. Returns (rcode, n_answers) or None on timeout."""
    qid = random.randrange(65536)
    q = (struct.pack('>HHHHHH', qid, 0x0100, 1, 0, 0, 0)
         + b''.join(bytes([len(p)]) + p.encode('idna') for p in name.split('.') if p) + b'\x00' + struct.pack('>HH', 1, 1))
    with _DNS_SEM:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(q, (server, 53))
            data, _ = s.recvfrom(4096)
        except Exception:  # noqa: BLE001 - a timeout is "try the next resolver"
            return None
        finally:
            s.close()
    if len(data) < 12:
        return None
    rid, flags, qd, an = struct.unpack('>HHHH', data[:8])
    return (flags & 0xF, an) if rid == qid else None


def resolves(h):
    for x in (h, 'www.' + h):
        for srv in RESOLVERS:
            try:
                r = _dns_a(x, srv)
            except Exception:  # noqa: BLE001
                r = None
            if r is None:
                continue                              # timeout: try the next resolver
            if r[0] == 0 and r[1] > 0:
                return True
            break                                     # NXDOMAIN / no data from a responsive resolver: next name
    return False


class _PublicHTTPConnection(http.client.HTTPConnection):
    """Connects only to a public address (security review 2026-10-26).

    The hosts fetched here come from leak-site posts, so a ransomware group chooses them: a victim domain whose A record
    is 127.0.0.1, 10.x or 169.254.169.254 made the runner GET an internal service. The name is resolved once, every
    address is checked, and the socket goes to the checked address, so a second lookup (DNS rebinding) cannot swap it.
    """

    def connect(self):
        self.sock = _public_socket(self.host, self.port, self.timeout)


class _PublicHTTPSConnection(http.client.HTTPSConnection):
    def connect(self):
        sock = _public_socket(self.host, self.port, self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _public_socket(host, port, timeout):
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addrs = [i[4][0] for i in infos]
    if not addrs or not all(ipaddress.ip_address(a.split('%')[0]).is_global for a in addrs):
        raise OSError(f'refused non-public address for {host}')
    fam, typ, proto, _, sa = infos[0]
    s = socket.socket(fam, typ, proto)
    s.settimeout(timeout if isinstance(timeout, (int, float)) else None)
    try:
        s.connect(sa)
    except Exception:
        s.close()
        raise
    return s


class _PublicHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_PublicHTTPConnection, req)


class _PublicHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self):
        super().__init__(context=ssl.create_default_context())

    def https_open(self, req):
        return self.do_open(_PublicHTTPSConnection, req, context=self._context)


class _WebOnlyRedirect(urllib.request.HTTPRedirectHandler):
    """urllib would follow a redirect to ftp:// as well; only http(s) here, and every hop goes through the checks above."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme not in ('http', 'https'):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_PUBLIC_WEB = urllib.request.build_opener(_PublicHTTPHandler, _PublicHTTPSHandler, _WebOnlyRedirect)


def fetch_home(h):
    """One GET of / (https, https://www., then http): status, final URL, title, og:site_name, parked."""
    o = {'host': h}
    for url in ('https://' + h + '/', 'https://www.' + h + '/', 'http://' + h + '/'):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': UA_WEB, 'Accept': 'text/html,*/*;q=0.8'})
            with _PUBLIC_WEB.open(req, timeout=10) as r:
                body = r.read(200000).decode(r.headers.get_content_charset() or 'utf-8', errors='replace')
                o['status'] = r.status
                o['final_url'] = r.geturl()
            m = re.search(r'<title[^>]*>(.*?)</title>', body, re.I | re.S)
            o['title'] = html.unescape(re.sub(r'\s+', ' ', m.group(1))).strip()[:200] if m else None
            m = (re.search(r'<meta[^>]+property=["\']og:site_name["\'][^>]+content=["\']([^"\']+)', body, re.I)
                 or re.search(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+property=["\']og:site_name', body, re.I))
            o['og_site_name'] = html.unescape(m.group(1)).strip()[:120] if m else None
            txt = re.sub(r'<[^>]+>', ' ', re.sub(r'(?is)<(script|style).*?</\1>', ' ', body))
            o['parked'] = bool(PARK.search((o.get('title') or '') + ' ' + txt[:4000]))
            if norm_host(o['final_url']) != h:
                o['redirect_host'] = norm_host(o['final_url'])
            return o
        except urllib.error.HTTPError as e:
            o['status'] = e.code
            if e.code in (401, 403, 429, 503):
                o['waf'] = True
                return o
        except Exception as e:  # noqa: BLE001 - recorded by type
            o['error'] = type(e).__name__
    return o


def wd_get(params):
    WD.wait()
    q = urllib.parse.urlencode(dict(params, format='json'))
    for a in range(3):
        try:
            req = urllib.request.Request('https://www.wikidata.org/w/api.php?' + q, headers={'User-Agent': UA_API})
            with urllib.request.urlopen(req, timeout=20) as r:
                return json.loads(r.read())
        except Exception:  # noqa: BLE001
            time.sleep(2 + 3 * a)
    return None


def wikidata(name):
    """Top three wbsearchentities hits (label, description) with their P856 official websites."""
    js = wd_get({'action': 'wbsearchentities', 'search': clean(name)[:120], 'language': 'en', 'uselang': 'en', 'limit': 3, 'type': 'item'})
    hits = [{'qid': x['id'], 'label': x.get('label'), 'description': x.get('description')} for x in (js or {}).get('search', [])]
    if hits:
        ents = wd_get({'action': 'wbgetentities', 'ids': '|'.join(h['qid'] for h in hits), 'props': 'claims'}) or {}
        for h in hits:
            cl = ents.get('entities', {}).get(h['qid'], {}).get('claims', {})
            h['p856'] = [norm_host(c['mainsnak']['datavalue']['value']) for c in cl.get('P856', []) if c.get('mainsnak', {}).get('datavalue')]
    return hits


def live(c):
    return bool(c.get('dns') and (c.get('waf') or (c.get('status') and c['status'] < 400)) and not c.get('parked'))


def harvest_pool(row, actor_norms):
    """row: {claim_key, name, domain, country, actor}. Frozen candgen.process without Common Crawl."""
    name, cands = row['name'], {}
    if never_fetch(name, row.get('actor'), actor_norms):
        return {'claim_key': row['claim_key'], 'name': name, 'candidates': [], 'wikidata': [], 'skipped': 'v2.1 rule: never fetched'}

    def add(h, src):
        h = norm_host(h)
        if not h or h.endswith('.onion') or not re.match(r'^[a-z0-9.-]+\.[a-z]{2,}$', h) or reserved_domain(h):
            return
        cands.setdefault(h, {'host': h, 'sources': []})['sources'].append(src)
    if row.get('domain'):
        add(row['domain'], 'tracker_domain')
    if domain_shaped(name):
        add(clean(name), 'name_is_domain')
    masked = is_masked(name)
    if not masked:
        for h in embedded_domains(name):
            add(h, 'embedded_in_name')
    if not masked and n_letters(name) >= 2:
        for h in guesses(name, row.get('country')):
            add(h, 'slug_guess')
    wd = wikidata(name) if not masked and n_letters(name) >= 3 else []
    for h in wd:
        for p in h.get('p856', []):
            add(p, 'wikidata_p856:' + h['qid'])
    with cf.ThreadPoolExecutor(DNS_WORKERS) as ex:
        for (h, c), ok in zip(list(cands.items()), ex.map(resolves, list(cands))):
            c['dns'] = ok
    resolving = [h for h, c in cands.items() if c['dns']]
    with cf.ThreadPoolExecutor(FETCH_WORKERS) as ex:
        res = dict(zip(resolving, ex.map(fetch_home, resolving)))
    for h, r in res.items():
        cands[h].update({k: v for k, v in r.items() if k != 'host'})
    for h, r in list(res.items()):
        rh = r.get('redirect_host')
        if rh and rh not in cands and not r.get('parked'):
            add(rh, 'redirect_of:' + h)
            if rh in cands:
                cands[rh].update({'dns': True, 'status': r.get('status'), 'title': r.get('title'),
                                  'og_site_name': r.get('og_site_name'), 'parked': False})
    for c in cands.values():
        c['live'] = live(c)
        c['historic'] = False                          # Common Crawl is not consulted in production
    return {'claim_key': row['claim_key'], 'name': name, 'candidates': list(cands.values()), 'wikidata': wd}


# ---- extras -------------------------------------------------------------------------------------------
def tls_subject(host):
    err = None
    for h in (host, 'www.' + host):
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((h, 443), timeout=8) as s:
                with ctx.wrap_socket(s, server_hostname=h) as t:
                    c = t.getpeercert()
            subj = {k: v for x in c.get('subject', ()) for k, v in x}
            iss = {k: v for x in c.get('issuer', ()) for k, v in x}
            return {'O': subj.get('organizationName'), 'CN': subj.get('commonName'), 'issuer_O': iss.get('organizationName'),
                    'san_n': len(c.get('subjectAltName', ()))}
        except Exception as e:  # noqa: BLE001
            err = type(e).__name__
    return {'error': err}


def page(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': UA_WEB, 'Accept': 'text/html'})
        with _PUBLIC_WEB.open(req, timeout=10) as r:
            body = r.read(150000).decode(r.headers.get_content_charset() or 'utf-8', errors='replace')
            st = r.status
            fu = r.geturl()
        t = re.search(r'<title[^>]*>(.*?)</title>', body, re.I | re.S)
        h1 = re.search(r'<h1[^>]*>(.*?)</h1>', body, re.I | re.S)
        txt = re.sub(r'\s+', ' ', html.unescape(re.sub(r'<[^>]+>', ' ', re.sub(r'(?is)<(script|style|nav|header).*?</\1>', ' ', body)))).strip()
        return {'url': url, 'status': st, 'final_url': fu, 'title': html.unescape(re.sub(r'\s+', ' ', t.group(1))).strip()[:200] if t else None,
                'h1': re.sub(r'\s+', ' ', html.unescape(re.sub(r'<[^>]+>', ' ', h1.group(1)))).strip()[:150] if h1 else None, 'text': txt[:300]}
    except urllib.error.HTTPError as e:
        return {'url': url, 'status': e.code}
    except Exception as e:  # noqa: BLE001
        return {'url': url, 'error': type(e).__name__}


def jget(url, rate, ua=UA_API, tries=3):
    for a in range(tries):
        rate.wait()
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': ua}), timeout=25) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            time.sleep(3 + 5 * a)
        except Exception:  # noqa: BLE001
            time.sleep(3 + 5 * a)
    return {'_error': 'unavailable'}


def gleif(name):
    js = jget('https://api.gleif.org/api/v1/autocompletions?' + urllib.parse.urlencode({'field': 'fulltext', 'q': name[:100]}), GL)
    if not js or '_error' in js:
        return js and [js]
    out = []
    for d in js.get('data', [])[:3]:
        lei = d.get('relationships', {}).get('lei-records', {}).get('data', {}).get('id')
        rec = jget(f'https://api.gleif.org/api/v1/lei-records/{lei}', GL) if lei else None
        e = ((rec or {}).get('data') or {}).get('attributes', {}).get('entity', {}) if rec and '_error' not in rec else {}
        out.append({'lei': lei, 'name': d['attributes']['value'], 'country': (e.get('legalAddress') or {}).get('country'), 'status': e.get('status')})
    return out


def edgar(name):
    js = jget('https://efts.sec.gov/LATEST/search-index?' + urllib.parse.urlencode({'keysTyped': name[:80]}), ED, ua=UA_SEC)
    if not js or '_error' in js:
        return js and [js]
    return [{'cik': h['_id'], 'entity': h['_source'].get('entity')} for h in js.get('hits', {}).get('hits', [])[:3]]


def harvest_extras(pool):
    """Frozen extras.process: TLS subject of up to 12 live hosts, four pages of the best live host, GLEIF, EDGAR."""
    name = clean(pool['name'])
    masked = is_masked(name)
    lv = [c for c in pool['candidates'] if c.get('live')]
    out = {'claim_key': pool['claim_key']}
    if lv:
        with cf.ThreadPoolExecutor(4) as ex:
            out['tls'] = dict(zip([c['host'] for c in lv[:12]], ex.map(tls_subject, [c['host'] for c in lv[:12]])))
    nt = {w for w in ascii_slug_words(name) if len(w) >= 3}

    def score(c):                                     # tracker/embedded/P856 first, then title-token overlap
        src = ' '.join(c['sources'])
        pri = 0 if re.search('tracker|name_is_domain|embedded|wikidata', src) else 1
        ov = len(nt & set(ascii_slug_words((c.get('title') or '') + ' ' + (c.get('og_site_name') or '') + ' '
                                           + c['host'].replace('-', ' ').replace('.', ' '))))
        return (pri, -ov)
    if lv:
        best = sorted(lv, key=score)[0]
        base = 'https://' + best['host']
        out['pages_host'] = best['host']
        out['pages'] = [page(base + p) for p in ('/about', '/impressum', '/contact', '/about-us')]
    if not masked and n_letters(name) >= 3 and not pool.get('skipped'):
        seg = re.split(r'\s[-|–]\s|\s?\(|\|', re.sub(r'<[^>]+>', ' ', name))[0].strip()
        out['gleif'] = gleif(seg)
        out['edgar'] = edgar(seg)
    return out


def harvest(item, actor_norms):
    """One claim item ({claim_key, name_raw, actor, domain, country}) -> (pool, extras, harvested_at)."""
    row = {'claim_key': item['claim_key'], 'name': item['name_raw'], 'domain': item.get('domain'),
           'country': item.get('country'), 'actor': item.get('actor')}
    pool = harvest_pool(row, actor_norms)
    extras = harvest_extras(pool)
    return pool, extras, datetime.now(timezone.utc)
