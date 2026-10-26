"""R2 classification (RUBRIC_R2 track T4): industry, size band, country, data groups and breach type per victim.

Writes candidate values into the PRIVATE breach_core.r2_values (contract 0185) - one row per (subject, field) per
source, with a verdict. Nothing here changes a public object: the shadow list and the release table decide what is
ever shown, and a field ships only after its sealed gate (RUBRIC_R2 s1).

Order of engines, everywhere (RUBRIC_R2 s2): a structured source field > a deterministic parse > Jev on short
evidence (a leak description, an HIBP/index summary, the press sentences that name the victim) > Jev on the name
and domain alone (its own stratum, basis `name_only`, gated on its own). Inside one subject this module applies the
rubric's precedence itself and accepts at most ONE value per single-valued field: lower-precedence values are kept as
`rejected / lower_precedence`, and two different values at the same top rank are both `rejected / conflict` plus an
r2_review row ("unknown" + review). A field with no accepted value gets one `abstain` row: the slot always exists,
"unknown" is never a value (D1).

  industry    15 classes (LABEL_RUBRIC_J1's list, snake case). Structured: HHS entity type, WA AG industry/business
              type, SEC SIC, the curated index's NAICS, Wikidata P452 matched on the exact website domain. Deterministic:
              the leak tracker's sector string. Jev: choice on the evidence, accepted only when Jev also says the text
              states what the organisation does. name_only: Jev on name + domain, its own gate.
  size_band   lt_250 | 250_4999 | 5000_plus from a STATED or MEASURED headcount only (leak-post headcount, the index's
              employee count, Wikidata P1128 by exact domain). No estimate is ever written (D5).
  country     regulator jurisdiction > Wikidata P17 (exact domain) > ccTLD (not the generic ones) > tracker country.
              No Jev (RUBRIC_R2 s2 allows an LLM quote only, which is T-B's extractor).
  data_group  people health finance hr systems documents other. Structured: regulator / HIBP / index field names via
              FIELD_RULES (src/lib/data-tags.ts, ported verbatim and pinned by its exhaustive fixture). Leak text: the
              stored breach-profile-v1 groups, each kept only when the description itself carries that group's cue
              (HEALTH_EVIDENCE generalised per group). Press/index text: Jev per tag, and a group stands only when a
              sentence naming the victim carries the group's cue AND a theft/exposure verb, not negated.
  breach_type 7 classes. Deterministic first: a leak-site listing => ransomware_extortion. Then regulator/index codes
              (HHS type of breach, WA cause/attack type, the index's breach/malware type). Then Jev choice on the
              evidence, accepted only with the class's cue in the text.

Leak text and article text are read inside this process only; the counts-only report never contains text, names or
the API key. Jev answers are stored in r2_answers (insert-only) and are the reproducible unit: `rescore` re-derives
every value from them with no network.

CLI:  python -m zdc_breach.r2_classify run [--pilot N] [--max-usd X] [--no-jev] [--write] [--report F]
      python -m zdc_breach.r2_classify rescore [--write]
      python -m zdc_breach.r2_classify wikidata --cache F          (fetch P452/P17/P1128 by exact domain)
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
import threading
import time
from dataclasses import dataclass, field as dfield

from . import profile
from .jev import MODEL, PRICE_PER_MTOK, Budget, BudgetExhausted, Jev, JevError, OutOfFunds  # noqa: F401

METHOD = 'r2-classify-v1'
V_STRUCT = 'r2c-struct-v1'          # structured + deterministic rules of this module
V_JEV = 'r2c-jev-v1'                # Jev on evidence (question set r2-q1)
V_NAME = 'r2c-jev-name-v1'          # Jev on name + domain only (its own stratum)
V_PROFILE = 'breach-profile-v1-g1'  # stored breach-profile-v1 groups + the per-group cue guard of this module
MY_VERSIONS = (V_STRUCT, V_JEV, V_NAME, V_PROFILE)
FIELDS = ('industry', 'size_band', 'country', 'data_group', 'breach_type')
STATEMENT_TIMEOUT = '60s'
LOCK_TIMEOUT = '5s'
WRITE_CHUNK = 2000
DESC_MAX = 3000
EVIDENCE_SENTS = 12
SENT_MAX = 500
PER_CALL = 4
PER_CALL_NAME = 10
WORKERS = 4

ENGINE_RANK = {'structured': 1, 'deterministic': 2, 'llm': 3, 'jev': 4}

# =====================================================================================================
# Classes
# =====================================================================================================
INDUSTRIES = {
    'healthcare': 'Healthcare: hospitals, clinics, health systems, pharma, dental, labs, medical practices',
    'finance_insurance': 'Finance & insurance: banks, credit unions, insurers, lenders, payments, investment firms, crypto exchanges',
    'government_public': 'Government & public sector: government agencies, councils, municipalities, police, military, courts, public bodies',
    'education': 'Education: schools, school districts, colleges, universities',
    'transport_logistics': 'Transport & logistics: airlines, airports, shipping, rail, trucking, logistics, ports',
    'energy_utilities': 'Energy & utilities: oil and gas, mining, electricity, water, utilities',
    'construction_real_estate': 'Construction & real estate: construction, building contractors, property, real estate',
    'professional_services': 'Professional services: law firms, accounting, consulting, engineering services, staffing, payroll and HR services, marketing agencies',
    'technology_telecom': 'Technology & telecom: software, IT vendors and services, SaaS, online platforms, telecoms, internet providers',
    'manufacturing': 'Manufacturing: manufacturers, industrial and automotive producers',
    'retail_consumer': 'Retail & consumer: shops, e-commerce, consumer brands, food and beverage companies',
    'hospitality_leisure': 'Hospitality & leisure: hotels, restaurants, travel, casinos, gaming, sport, entertainment venues',
    'media': 'Media: publishers, broadcasters, newspapers, studios',
    'nonprofit': 'Non-profit & associations: charities, non-profits, unions, associations, religious organisations',
    'agriculture': 'Agriculture: farming, agricultural producers and cooperatives',
}
NOT_STATED = 'not_stated'
SIZE_BANDS = ('lt_250', '250_4999', '5000_plus')
GROUPS = ('people', 'health', 'finance', 'hr', 'systems', 'documents', 'other')
BREACH_TYPES = {
    'ransomware_extortion': 'Ransomware or data-theft extortion: files encrypted, a ransom demanded, or the attackers threaten to publish stolen data (a leak-site listing).',
    'intrusion_hacking': 'Hacking or intrusion: attackers broke into systems or networks (malware, exploited vulnerability, cyberattack) without ransomware or extortion being stated.',
    'credential_abuse': 'Credential abuse: stolen, phished, reused or stuffed passwords or a compromised email or user account were used to get in.',
    'exposure_misconfiguration': 'Exposure or misconfiguration: data left publicly accessible (unsecured database, open cloud bucket, misconfigured server) or published by mistake.',
    'third_party_vendor': 'Third party: the breach happened at a vendor, supplier or service provider that held the organisation\'s data.',
    'insider_misuse': 'Insider misuse: an employee or other insider accessed, took or disclosed data without authorisation.',
    'lost_stolen_device': 'Lost or stolen device: a laptop, phone, drive, or paper records were lost or stolen.',
}

# =====================================================================================================
# Structured / deterministic maps
# =====================================================================================================
HHS_ENTITY = {'healthcare provider': 'healthcare', 'health plan': 'healthcare',
              'healthcare clearing house': 'healthcare', 'business associate': None}
WA_INDUSTRY = {'health': 'healthcare', 'finance': 'finance_insurance', 'education': 'education',
               'government': 'government_public', 'non-profit/charity': 'nonprofit'}
WA_BUSINESS = {'retail': 'retail_consumer', 'professional services': 'professional_services',
               'manufacturing': 'manufacturing', 'legal': 'professional_services', 'software': 'technology_telecom',
               'hospitality': 'hospitality_leisure', 'construction': 'construction_real_estate',
               'consumable': 'retail_consumer', 'web services': 'technology_telecom',
               'real estate': 'construction_real_estate', 'shipping': 'transport_logistics',
               'telecommunications': 'technology_telecom', 'human resources': 'professional_services',
               'cosmetic': 'retail_consumer', 'clothing': 'retail_consumer'}
# ('Entertainment', 'Home', 'Other') stay unmapped: each spans several classes.


def industry_wa(industrytype, businesstype):
    i = (industrytype or '').strip().lower()
    b = (businesstype or '').strip().lower()
    if i == 'business':
        return WA_BUSINESS.get(b)
    return WA_INDUSTRY.get(i)


def industry_hhs(entity_type):
    return HHS_ENTITY.get((entity_type or '').strip().lower())


def industry_sic(sic):
    """SEC Standard Industrial Classification -> class; None where a code spans classes."""
    try:
        s = int(str(sic).strip())
    except (TypeError, ValueError):
        return None
    d2 = s // 100
    if 100 <= s < 1000:
        return 'agriculture'
    if 1000 <= s < 1500:
        return 'energy_utilities'
    if 1500 <= s < 1800:
        return 'construction_real_estate'
    if 2833 <= s <= 2836:
        return 'healthcare'
    if 2711 <= s <= 2741:
        return 'media'
    if 3570 <= s <= 3579 or 3670 <= s <= 3679 or 3840 <= s <= 3851:
        return None
    if 2000 <= s < 4000:
        return 'manufacturing'
    if 4000 <= s < 4800:
        return 'transport_logistics'
    if s in (4830, 4832, 4833, 4840, 4841):
        return 'media'
    if 4800 <= s < 4900:
        return 'technology_telecom'
    if 4900 <= s < 5000:
        return 'energy_utilities'
    if d2 == 58:
        return 'hospitality_leisure'
    if 5200 <= s < 6000:
        return 'retail_consumer'
    if s == 6798:
        return 'construction_real_estate'
    if 6000 <= s < 6500 or 6700 <= s < 6800:
        return 'finance_insurance'
    if 6500 <= s < 6600:
        return 'construction_real_estate'
    if d2 == 70 or d2 == 79:
        return 'hospitality_leisure'
    if 7370 <= s <= 7379:
        return 'technology_telecom'
    if 7310 <= s <= 7319 or 7360 <= s <= 7369:
        return 'professional_services'
    if d2 == 78:
        return 'media'
    if d2 == 80:
        return 'healthcare'
    if d2 == 81 or 8710 <= s <= 8749:
        return 'professional_services'
    if d2 == 82:
        return 'education'
    if d2 == 86:
        return 'nonprofit'
    if 9100 <= s < 9800:
        return 'government_public'
    return None


def industry_naics(code):
    """NAICS (2-6 digits) -> class; None where the code spans classes."""
    c = re.sub(r'\D', '', str(code or ''))
    if len(c) < 2:
        return None
    p2, p3, p4 = c[:2], c[:3], c[:4]
    if p4 == '3254':
        return 'healthcare'
    if p4 in ('3341', '3344', '3345'):
        return None
    if p4 in ('5112', '5132'):
        return 'technology_telecom'
    if p4 == '5111':
        return 'media'
    if p3 in ('512', '515', '516'):
        return 'media'
    if p3 in ('517', '518', '519'):
        return 'technology_telecom'
    if p4 == '5415':
        return 'technology_telecom'
    if p4 == '5613':
        return 'professional_services'
    if p3 == '624':
        return None
    if p3 == '813':
        return 'nonprofit'
    if p3 == '532':
        return None
    return {'11': 'agriculture', '21': 'energy_utilities', '22': 'energy_utilities', '23': 'construction_real_estate',
            '31': 'manufacturing', '32': 'manufacturing', '33': 'manufacturing', '44': 'retail_consumer',
            '45': 'retail_consumer', '48': 'transport_logistics', '49': 'transport_logistics',
            '52': 'finance_insurance', '53': 'construction_real_estate', '54': 'professional_services',
            '61': 'education', '62': 'healthcare', '71': 'hospitality_leisure', '72': 'hospitality_leisure',
            '92': 'government_public'}.get(p2)


# breach_core.industry_of (0113) ported, order kept; used only for free-text sector strings (tracker sector,
# Wikidata P452 labels). Its classes renamed to this module's snake case.
_INDUSTRY_OF = [
    (r'health|hospital|medic|clinic|dental|pharma|physician|patient|surg|orthop|pediatr|nursing|hospice|laborator|diagnos|radiolog|oncolog|cardio|optometr|behavioral|rehab|senior|pflege|klinik|sjukhus|health ?care|wellness|veterin', 'healthcare'),
    (r'bank|financ|credit|insur|invest|capital|asset|wealth|lending|mortgage|payment|fintech|securities trading|securities|brokerage|fund\b', 'finance_insurance'),
    (r'government|municipal|city of|county|state of|ministry|police|federal|public sector|council|authority|embassy|court|kommun|gemeinde|ayuntamiento|prefeitura|military|defen[cs]e|local administration|public administration', 'government_public'),
    (r'school|universit|college|educat|academy|district|campus|student|kindergarten|schule|colegio|institute of technology', 'education'),
    (r'logistic|transport|freight|shipping|trucking|airline|aviation|railway|\bport\b|carrier|delivery|courier|maritime', 'transport_logistics'),
    (r'energy|\boil\b|\bgas\b|power|electric|utilit|water|solar|mining|petrol', 'energy_utilities'),
    (r'construct|builder|real estate|property|realty|housing|contractor|architect|arkitekt|engineering firm|\bbau', 'construction_real_estate'),
    (r'\blaw\b|legal|attorney|lawyer|accountan|accounting|audit|consult|staffing|marketing|advertis|recruit|human resources|research|professional services|notar|business services', 'professional_services'),
    (r'software|technolog|\btech\b|\bit\b|cloud|digital|telecom|internet|computer|cyber|saas|data center|semiconductor|network|high-tech', 'technology_telecom'),
    (r'manufactur|industr|factory|machin|bearing|steel|metal|plastic|chemical|automotive|electronics|aerospace|textile|packaging|fabrica', 'manufacturing'),
    (r'retail|store|shop|fashion|apparel|food|restaurant|grocery|supermarket|consumer|beverage|cosmetic|wholesale|e-?commerce|brand|distribution', 'retail_consumer'),
    (r'hotel|travel|touris|hospitality|casino|resort|entertainment|sport|leisure|gaming', 'hospitality_leisure'),
    (r'media|news|publish|broadcast|\bfilm|music|studio', 'media'),
    (r'non-?profit|charity|foundation|church|association|\bngo\b|union|stiftelse|stiftung', 'nonprofit'),
    (r'agri|farm|forestry|fishing', 'agriculture'),
]
_INDUSTRY_OF = [(re.compile(p, re.I), c) for p, c in _INDUSTRY_OF]


def industry_of_text(t):
    t = re.sub(r'(?i)^\s*\[[A-Za-z ]{2,20}\]\s*', '', (t or '').strip())
    if not t or t.lower() in ('unknown', 'other', 'n/a', 'none', 'not found'):
        return None
    for rx, c in _INDUSTRY_OF:
        if rx.search(t):
            return c
    return None


# Wikidata P452 labels: a table of their own (the free-text regex above maps "hospitality industry" to healthcare and
# every "... industry" to manufacturing). Order is the argument; a label in WD_NONE or matching nothing gives no class.
WD_NONE = re.compile(r'(?i)conglomerate|head offices|holding compan|pornograph|food delivery|artificial intelligence|^mail$|^services?$')
WD_RULES = [(re.compile(p, re.I), c) for p, c in [
    (r'hospitality|hotel|touris|travel|casino|gambling|betting|\bgames?\b|gaming|entertainment|\bsports?\b|leisure|restaurant|'
     r'fast food|food service|amusement', 'hospitality_leisure'),
    (r'health|hospital\b|hospitals|pharma|medic|biotech|dental|clinic', 'healthcare'),
    (r'real estate investment trust|real estate|property|construction|building', 'construction_real_estate'),
    (r'bank|financ|insur|invest|asset management|payment|fintech|credit|stock exchange|brokerage|cryptocurrenc', 'finance_insurance'),
    (r'energy|petroleum|\boil\b|natural gas|electric power|electricity|utilit|mining|water supply', 'energy_utilities'),
    (r'educational technology|social networking|software|telecom|information technology|information and communications|'
     r'internet|cloud|computer|cyber|data|technology|it service|semiconductor', 'technology_telecom'),
    (r'higher education|education|school|universit', 'education'),
    (r'defen[cs]e industry|weapons|arms industry|automotive|aerospace|chemical|electronics|steel|metal|machin|manufactur|'
     r'industrial|engineering|mobile phone|textile|plastic|packaging|shipbuilding|paper', 'manufacturing'),
    (r'public administration|administration publique|government|public sector|military|police', 'government_public'),
    (r'media|publishing|broadcast|news|film|music|television|radio|journalism', 'media'),
    (r'retail|e-commerce|online shopping|wholesale|consumer|food|beverage|brewing|drink|clothing|fashion|apparel|cosmetic|'
     r'product distribution|supermarket|grocery', 'retail_consumer'),
    (r'logistic|transport|aviation|airline|rail|shipping|maritime|freight|courier|postal', 'transport_logistics'),
    (r'consult|\blaw\b|legal|accounting|audit|staffing|recruit|advertising|marketing|professional services?|architecture|'
     r'public relations', 'professional_services'),
    (r'non-?profit|charit|association|religio|trade union', 'nonprofit'),
    (r'agri|farming|forestry|fishing|fishery', 'agriculture'),
]]


def industry_of_wikidata(label):
    t = (label or '').strip()
    if not t or WD_NONE.search(t):
        return None
    for rx, c in WD_RULES:
        if rx.search(t):
            return c
    return None


def band_of(n):
    try:
        n = int(n)
    except (TypeError, ValueError):
        return None
    if n <= 0:
        return None
    return 'lt_250' if n < 250 else ('250_4999' if n < 5000 else '5000_plus')


US_STATES = frozenset('''AL AK AZ AR CA CO CT DE FL GA HI ID IL IN IA KS KY LA ME MD MA MI MN MS MO MT NE NV NH NJ NM NY NC
ND OH OK OR PA RI SC SD TN TX UT VT VA WA WV WI WY DC PR GU VI AS MP'''.split())
GENERIC_TLD = frozenset('''io co ai me tv cc ws fm ly gg la to nu am vc sh ac tk ml ga cf gq so st xyz app dev eu asia'''.split())
TLD_ISO = {'uk': 'GB'}


def country_cctld(domain):
    if not domain:
        return None
    tld = domain.lower().rstrip('.').rsplit('.', 1)[-1]
    if len(tld) != 2 or not tld.isalpha() or tld in GENERIC_TLD:
        return None
    return TLD_ISO.get(tld, tld.upper())


ISO2 = re.compile(r'^[A-Z]{2}$')


def country_iso(c):
    c = (c or '').strip().upper()
    if c in ('UK',):
        return 'GB'
    if c in ('USA', 'UNITED STATES', 'US'):
        return 'US'
    return c if ISO2.match(c) and c not in ('XX', 'ZZ') else None


# ---- data-type field names: FIELD_RULES ported verbatim from src/lib/data-tags.ts (ruling R1) -------------------
_A = "(?:'|’)"
FIELD_RULES = [
    (r"\bsocial security\b|\bssns?\b|\bsocial insurance number|\bpassports?\b|\bdriver" + _A + r"?s?" + _A + r"? ?licen[cs]es?\b|\bdriverlicense\b|\blicen[cs]e (?:number|id)|\bnational (?:id|identi)|\bnational insurance\b|\btax(?:payer)? ?id\b|\btaxpayer\b|\btaxpayer identification|\bfedid\b|\bfederal identification|\bgovernment[- ]?(?:issued )?ids?\b|\bstate id|\bstate identification|\bid cards?\b|\bdd214s?\b|\bidentification card|\b(?:government|tax|tribal|military|state\/tribal)[- ](?:issued )?identification|\bgovernment[- ]issued identification|^drivers$", 'government_id'),
    (r"\bmedic|\bmed(?:diagnosis|history|treatment)\b|\bhealth|\bphi\b|\btreatments?\b|\bdiagnos[ie]s|\bdiagnostic|\bprescri|\bpatients?\b|\binsurance\b|\binsurer\b|\bclinical\b|\blabs?\b|\blaboratory\b|\btest results\b|\bimaging\b|\bhiv\b|\bvaccinat|\bdisabilit|\bdates? of (?:service|treatment)|\bphysicians?\b|\bproviders?\b|\benrollee|\bchart ids?\b|\bmember (?:and group )?id|\bconditions?\b|^(?:health |medical |insurance )?claims?(?: information| data)?$|\bmental\b|\bprocedur|\bx-?rays?\b|\badmission|\badmittance\b|\bdischarge\b|\bdental\b|\bradiolog|\bradiograph|\banesthesia\b|\bvisits?\b|\bservices? (?:received|performed|provided|rendered|dates?|codes?|descriptions?|start)\b|\bdescriptions? of (?:the )?services?\b|\bcpt\b|\bdeductibles?\b|\bout[- ]of[- ]pocket\b|\bpremiums?\b|\bcopays?\b|\bexplanations? of benefits\b|\bbenefits (?:information|identification)\b|\benrollment\b|\bbeneficiar|\bplan (?:id|codes|beneficiary|enrollment)|\bpolicy numbers\b|\bclaims? (?:numbers|codes)\b|\bgroup numbers\b|\bcharts?\b|\bencounter|\bpathology\b|\bsurger|\bsurgical\b|\bexam(?:ination)?s?\b|\bimmunizations?\b|\bvital signs\b|\bheight\b|\bweight\b|\bbody (?:mass|parts?)\b|\bobesity\b|\bprognosis\b|\bcomplaints\b|\breferrals?\b|\breferring doctors|\bprogress notes\b|\bconsultation notes\b|\bclinic\b|\bclinician|\bretinal\b|\boptical images\b|\bct scans?\b|\bultrasound\b|\baudiology\b|\bcardiac\b|\bcovid|\bwellness\b|\bpodiatric\b|\bpharmac|\bmedi-cal\b|\bpay[eo]rs?\b|\bcare information\b|\bcounseling\b|\bmobility status\b|\broom (?:assignments|numbers)\b|\brecovery room\b|\bmedial record|\bcolposcopy\b|\bmodalities\b|\btests?\b|\bassessments?\b|\bdonors?\b|\bcase managers?\b|\bcase management\b|\bdrug testing\b|\bhospital\b|\bdoctor|\bsubscriber id(?:s|entification)?\b|\bemergency department|\bcoverage\b|\btypes? of plan|\bof (?:the )?services?\b", 'health'),
    (r"^(?!.*credential)(?:.*)(?:\bip address|\bmac address|\bdevice (?:information|serial|usage|ids?|identifiers?|details)\b|\bon devices\b|\buser agent|\bbrowsers?\b|\bbrowsing\b|\bos\/browser|\bimei\b|\bimsi\b|\bsim card|\busim\b|\bcellular network|\btelecommunications carrier|\btariff plan|\bconfig(?:uration)?s?\b|\bapps installed|\breferring website|\btime zones?\b|\blogin histor|\bsource code|\bserver)", 'technical'),
    (r"\bcards?\b|\bcredit\b|\bdebit\b|\bcvv\b|\bbank|\baccount (?:number|balance)s?\b|\bibans?\b|\bfinancial\b|\bfininfo\b|\brouting\b|\bpayments?\b|\bbilling\b|\bloans?\b|\bmortgage|\bincome\b|\bearnings\b|\bnet worths?\b|\bspending\b|\btransactions?\b|\btaxation\b|\bcryptocurrency\b|\bwallets?\b|\binvestments?\b|\bliving costs\b|\bdonations?\b|\bstatements\b|\butility bills\b|\bguarantor\b|\bfunds\b|\baccount information\b|\baccounts payable\b|\bamounts? (?:paid|billed|due)\b|\bbalances? (?:owed|due)\b|^balances$|\bcharges?(?: amounts| incurred)?$|\bcosts? of service|\brefund|\bexpenses\b|\binvoices?\b|\bchecking\b|^tax$|\bfunding sources\b", 'financial_personal'),
    (r"\bpasswords?\b|\busernames?\b|\buser ?ids?\b|\baccess code|\bsecurity code|\bpins?\b|\bpuk\b|\bcredentials?\b|\bsecurity questions?\b|\bauth(?:entication)? tokens?\b|\bencrypted keys\b|\bcrypto keys\b|\bmnemonic phrases?\b|\bonline ?acc(?:oun)?t ?ids?\b|\bonlineacctid\b|\bdigital signatures?\b", 'credentials'),
    (r"\bmessages?\b|\bchats?\b|\bcorrespondence\b|\bsms\b|\bforum posts?\b|\bcomments\b|\baudio recordings?\b|\bai prompts?\b", 'communications'),
    (r"\bjob titles?\b|\bemployers?\b|\bemployees?\b|\bemployment\b|\bsalar(?:y|ies)\b|\bpayroll\b|\boccupations?\b|\bcareer\b|\bprofessional (?:skills|experience)\b|\bjob applications?\b|\bcompensation\b|\bwork (?:location|habits)\b|\bcompany names\b|\bhuman resources\b|\bstaff\b|\bcontractors\b", 'hr'),
    (r"\bsuppliers?\b|\bprocurement\b", 'financial_corporate'),
    (r"\bemails?\b|\be-mail|\bema\b|\bphones?\b|\btelephones?\b|\baddress(?:es)?\b|\bpostal\b|\bstreet\b|\bzip codes?\b|\bpostcodes?\b|\bcontacts?\b|\bmailing\b|\binstant messenger|\bsocial media profiles?\b|\bwebsite urls?\b|\bhomepage urls?\b", 'contact'),
    (r"\bpurchas|\borders?\b|\bcustomers?\b|\bclients?\b|\bbooking|\bloyalty\b|\bdelivery\b|\bshipment|\bwarranty\b|\bbuying\b|\bsurvey|\bfeedback\b|\bwebsite activity\b|\breward program|\btravel|\bflights?\b|\bfrequent flyer|\bpassengers?\b|\bprofile statistics\b|\buser status|\bvip status|\bsales\b|\bsupport tickets?\b|\bappointments?\b", 'customer'),
    (r"\bcontracts?\b|\blegal\b|\bcourt\b|\bcriminal\b", 'legal'),
    (r"\bnames?\b|\bsurnames?\b|\bnicknames?\b|\bsalutations?\b|\btitles?$|\bdates? of births?\b|\bbirth|\bdob\b|\bgenders?\b|\bages?\b|\bage groups\b|\bethnic|\braces\b|\bnationalit|\bcitizenship|\bcountry\b|\bmarital\b|\brelationship status|\bfamily\b|\bspouses?\b|\bmaiden\b|\bphotos?\b|\bavatars?\b|\bbios\b|\breligio|\bsexual\b|\bpolitical views\b|\bphysical attributes\b|\blanguages?\b|\bastrolog|\beducation\b|\bschool\b|\bacademic\b|\bpersonal\b|\bpii\b|\binterests\b|\bhabits\b|\bbiometric|\bdemographic|\blocations?\b|\blatitude|\bdeceased\b|\bvehicles?\b|\blicen[cs]e plates\b|\bregistration plates\b|\bcar (?:details|ownership)|\bhome ownership|\bclothing\b|\bbeauty\b|\biq\b|\bsocioeconomic\b|\bfitness\b|\bparenting\b|\bsocial connections\b|\btattoo|\bdisplay names?\b|\bidentit(?:y|ies)\b|\bidentifiers?\b|\bsex\b|\brace\b|\bdeath\b|\bidentif(?:ication|ying|iable)\b|\binitials?\b|\bnext of kin\b|\bparents?\b|\bliving status\b|\bphotograph|\bpictures?\b|\bstates? of residence\b|\bschools\b|\bstudent\b|\bprofile information\b", 'personal_identity'),
]
FIELD_RULES = [(re.compile(p, re.I), t) for p, t in FIELD_RULES]


def field_to_tag(field_name):
    for rx, tag in FIELD_RULES:
        if rx.search(field_name):
            return tag
    return 'other_stated'


def tag_group(tag):
    g = profile.GROUP.get(tag)
    return None if g in (None, 'unspecified') else g


NO_DATA_FIELD = re.compile(r'(?i)^\s*(none|unknown|n/?a|other|unk|null)?\s*$')

# Delaware lists the statutory items joined by ", " although one item itself contains commas; split on the
# known items first (RULING_coverage R2), then on commas.
DE_ITEMS = [
    r"account number,? (?:/ )?credit card account number,? (?:/ )?or debit card number,? in combination with any required security code,? access code,? or password that would permit access to a financial account",
    r"username or email address,? in combination with (?:a )?password or security question and answer (?:that would permit )?(?:to )?access (?:to )?(?:an )?online account",
    r"health insurance policy number,? subscriber id number,? or any other unique identifier used by (?:a )?health insurer to identify (?:the )?person",
    r"medical history,? medical treatment by a health ?care professional,? diagnosis of mental(?:/| or )physical condition by a health ?care professional,? or dna profile",
    r"diagnosis of mental/physical condition by (?:a )?health ?care professional",
    r"medical treatment by (?:a )?health ?care professional",
]
DE_ITEMS = [re.compile(p, re.I) for p in DE_ITEMS]


def split_de(s):
    s = (s or '').strip()
    out = []
    for rx in DE_ITEMS:
        for m in list(rx.finditer(s)):
            out.append(m.group(0))
        s = rx.sub(' ; ', s)
    out += [x.strip() for x in re.split(r'[;,]', s) if x.strip() and x.strip().lower() not in ('and', 'or')]
    return out


CRA_CODES = {'NAA': 'personal_identity', 'SSN': 'government_id', 'ADD': 'contact', 'DOB': 'personal_identity',
             'FIN': 'financial_personal', 'MED': 'health'}     # ACC/NUM/MISC: owner decision pending; UNK: none


def groups_from_fields(names):
    gs = []
    for n in names:
        if not n or NO_DATA_FIELD.match(n):
            continue
        g = tag_group(field_to_tag(n))
        if g and g not in gs:
            gs.append(g)
    return gs


def groups_from_cra(code):
    gs = []
    for c in re.split(r'[/,; ]+', code or ''):
        t = CRA_CODES.get(c.strip().upper())
        g = tag_group(t) if t else None
        if g and g not in gs:
            gs.append(g)
    return gs


# ---- per-group evidence cues (HEALTH_EVIDENCE generalised; frozen before dev scoring) ------------------------------
CUES = {
    'health': profile.HEALTH_EVIDENCE,
    'people': re.compile(r"(?i)\b(names?|address(?:es)?|dates? of birth|DOB|social security|SSNs?|passports?|driver'?s licen\w*|"
                         r"e-?mail address(?:es)?|e-?mails|phone(?: numbers?)?|contact (?:details|information|data)|"
                         r"personal (?:information|data|details|files|documents|records)|PII|ID (?:cards?|numbers?|documents?)|"
                         r"identity documents?|customers?'? (?:data|information|records|lists?|databases?|details|files|documents)|"
                         r"clients?'? (?:data|information|records|lists?|databases?|details|files|documents)|"
                         r"(?:student|member|citizen|user)s?'? (?:data|information|records|personal data))\b"),
    'finance': re.compile(r"(?i)\b(bank\w*|account numbers?|routing|(?:credit|debit|payment) cards?|card (?:numbers?|data|details)|payment\w*|"
                          r"financ\w*|IBANs?|tax\w*|invoices?|accounting|budgets?|audits?|balance sheets?|bookkeeping)\b"),
    'hr': re.compile(r"(?i)\b(employees?'? (?:personal )?(?:data|information|records|files|documents|details)|payroll|salar\w*|W-2s?|"
                     r"human resources|personnel (?:files|records|data)|staff (?:data|records|files|documents)|HR)\b"),
    'systems': re.compile(r"(?i)\b(passwords?|credentials?|logins?|API keys?|access tokens?|certificates?|source code|private keys?|"
                          r"network (?:diagrams?|documentation)|drawings?|CAD|blueprints?|schematics?|R&D|technical (?:documents?|documentation|data|files))\b"),
    'documents': re.compile(r"(?i)\b(contracts?|agreements?|NDAs?|legal (?:documents?|files|records)|e-?mail (?:accounts?|inbox\w*|contents?|messages|correspondence|archives?)|"
                            r"mailbox\w*|correspondence)\b"),
    'other': re.compile(r"(?i)\b(biometric\w*|fingerprints?|student (?:records?|grades)|grades|transcripts?|insurance claims?|CCTV|"
                        r"video (?:footage|recordings?)|vehicle (?:data|records))\b"),
}
TAKEN = re.compile(r"(?i)\b(st[eo]len|steal\w*|stole|exfiltrat\w*|copied|taken|took|downloaded|leak\w*|posted|published|acquired|"
                   r"obtained|removed|accessed|access to|exposed|compromised|involved|affected|impacted|breached|viewed|"
                   r"may have (?:been )?(?:included|contained))\b")
NEGATION = re.compile(r"(?i)\b(no|not|never|nor|without|neither|none|n't)\b")


def clause_negated(text, pos):
    """A negation word earlier in the same clause (sentence part between , ; : and the match)."""
    start = max(text.rfind(c, 0, pos) for c in ',;:(')
    return bool(NEGATION.search(text[start + 1:pos]))


def cue_hit(group, text):
    for m in CUES[group].finditer(text or ''):
        if not clause_negated(text, m.start()):
            return m
    return None


BT_CUES = {
    'ransomware_extortion': re.compile(r"(?i)\b(ransom\w*|encrypt\w*|extort\w*|leak site|data leak site|threat(?:en\w*)? to (?:publish|leak|release))\b"),
    'intrusion_hacking': re.compile(r"(?i)\b(hack\w*|intru\w*|malware|cyber ?-?attack\w*|attack\w*|unauthori[sz]ed (?:access|actor|party|third party)|"
                                    r"threat actors?|exploit\w*|vulnerabilit\w*|compromised|infiltrat\w*|breach\w*)\b"),
    'credential_abuse': re.compile(r"(?i)\b(credential\w*|passwords?|phish\w*|account takeover|stuffing|log-?ins?|compromised (?:e-?mail|user|employee) accounts?|"
                                   r"e-?mail accounts? (?:was|were) compromised|business e-?mail compromise|BEC)\b"),
    'exposure_misconfiguration': re.compile(r"(?i)\b(misconfigur\w*|unsecured|unprotected|publicly (?:accessible|available|exposed)|exposed (?:online|to the internet)|"
                                            r"open (?:database|bucket|server|elasticsearch|s3)|left (?:open|exposed|unprotected)|without (?:a )?password|"
                                            r"elasticsearch|mongodb|s3 bucket|inadvertent\w*|mistakenly|by mistake|accidental\w*)\b"),
    'third_party_vendor': re.compile(r"(?i)\b(vendors?|third[- ]part(?:y|ies)|suppliers?|service providers?|contractors?|business associates?|partners?)\b"),
    'insider_misuse': re.compile(r"(?i)\b(insiders?|(?:former|rogue|an?) (?:employee|staff member|worker)s?|employees? (?:who )?(?:accessed|took|stole|misused|emailed|sent)|misuse\w*|snoop\w*)\b"),
    'lost_stolen_device': re.compile(r"(?i)\b(lost|stolen|theft|misplaced)\b.{0,60}\b(laptops?|devices?|phones?|drives?|computers?|tablets?|hard ?drives?|USB|paper|records|files|bags?|backpacks?)\b|"
                                     r"\b(laptops?|devices?|phones?|computers?|hard ?drives?)\b.{0,40}\b(lost|stolen|theft)\b"),
}


# ---- regulator / index breach-type codes ---------------------------------------------------------------------------
def bt_hhs(type_of_breach, location=None, ba_present=None, entity_type=None):
    t = (type_of_breach or '').lower()
    if (ba_present or '').strip().lower() in ('yes', 'true') and (entity_type or '').lower() != 'business associate':
        return 'third_party_vendor'
    if 'hacking' in t:
        return 'intrusion_hacking'
    if t.strip() in ('theft', 'loss') and re.search(r'(?i)laptop|portable|desktop|device|computer', location or ''):
        return 'lost_stolen_device'
    return None


def bt_wa(cause, attack):
    a, c = (attack or '').strip().lower(), (cause or '').strip().lower()
    if c == 'cyberattack' or a:
        return {'ransomware': 'ransomware_extortion', 'malware': 'intrusion_hacking', 'phishing': 'credential_abuse',
                'skimmers': 'intrusion_hacking'}.get(a)
    return None


def bt_cra(breach_type, malware, third_party):
    if (malware or '').strip().lower() == 'ransomware':
        return 'ransomware_extortion'
    if (third_party or '').strip().upper() == 'TRUE':
        return 'third_party_vendor'
    if (breach_type or '').strip().lower() in ('hack', 'virus'):
        return 'intrusion_hacking'
    return None


# =====================================================================================================
# Text helpers
# =====================================================================================================
LEGAL = re.compile(r"(?i)[,\s]+(inc|llc|l\.l\.c|ltd|limited|gmbh|corp|corporation|company|co|plc|s\.?a|s\.?r\.?l|s\.?p\.?a|ag|bv|nv|pty|pte|lp|llp|pc|pa)\.?$")
STOP = frozenset('the of and a an for de la le du der die das'.split())


def core_name(name):
    n = html.unescape(name or '').strip()
    n = re.sub(r'\s*\(.*?\)\s*', ' ', n)
    for _ in range(2):
        n = LEGAL.sub('', n).strip(' ,.')
    return n


def name_pattern(name, domain=None):
    """A regex matching a sentence that names the victim: the core name, or its first two significant words, or the
    domain's label (>= 4 characters)."""
    alts = []
    c = core_name(name)
    if len(c) >= 3:
        alts.append(re.escape(c))
        toks = [t for t in re.findall(r"[\w&'’.-]+", c) if t.lower() not in STOP]
        if len(toks) >= 3:
            alts.append(re.escape(toks[0]) + r'\W+(?:\w+\W+)?' + re.escape(toks[1]))
    if domain:
        lab = domain.lower().split('.')[0]
        if len(lab) >= 4:
            alts.append(re.escape(lab))
    if not alts:
        return None
    return re.compile(r'(?i)(?<![\w])(?:' + '|'.join(alts) + r')(?![\w])')


def clean_html(t):
    return profile.clean(t or '')


def evidence_sentences(text, limit=EVIDENCE_SENTS):
    return [{'sid': 's%d' % (i + 1), 'text': s[:SENT_MAX]} for i, s in enumerate(profile.sentences(text or '')[:limit])]


def victim_sentences(doc_text, title, name, domain, limit=8):
    """Sentences of an article that name the victim (title first). None when the victim is not found."""
    rx = name_pattern(name, domain)
    if rx is None:
        return []
    out = []
    if title and rx.search(title):
        out.append(title.strip()[:SENT_MAX])
    for s in profile.sentences(doc_text or ''):
        if rx.search(s):
            out.append(s[:SENT_MAX])
        if len(out) >= limit:
            break
    return [{'sid': 's%d' % (i + 1), 'text': t} for i, t in enumerate(out)]


def press_sentences(docs, name, domain, limit=10):
    """Victim sentences over the subject's articles (in doc order), de-duplicated, at most `limit`."""
    seen, out = set(), []
    for d in docs:
        for x in victim_sentences(d.get('text'), d.get('title'), name, domain):
            k = x['text'].strip().lower()
            if k not in seen:
                seen.add(k)
                out.append(x['text'])
            if len(out) >= limit:
                break
        if len(out) >= limit:
            break
    return [{'sid': 's%d' % (i + 1), 'text': t} for i, t in enumerate(out)]


# =====================================================================================================
# Values
# =====================================================================================================
@dataclass
class Val:
    field: str
    value: str | None
    source_kind: str
    basis: str
    engine: str
    engine_version: str
    rank: int = 0                    # precedence inside the engine (lower wins); see PRECEDENCE
    quote: str | None = None
    doc_ref: str | None = None
    claim_ref: str | None = None
    jev_p: float | None = None
    answer_key: tuple | None = None  # (engine_version, prompt_sha, input_sha) -> answer_id at write time
    answer_id: int | None = None
    verdict: str = 'accepted'
    reason: str | None = None


# Rubric precedence inside a field, lowest first. A basis not listed ranks after the listed ones of its engine.
PRECEDENCE = {
    'industry': ['regulator_field', 'filing', 'index_field', 'wikidata', 'tracker_sector', 'description', 'press_quote', 'name_only'],
    'size_band': ['leak_post_headcount', 'index_field', 'wikidata'],
    'country': ['regulator_jurisdiction', 'index_field', 'wikidata', 'cctld', 'tracker_country'],
    'data_group': ['regulator_field', 'hibp_field', 'index_field', 'description', 'press_quote'],
    'breach_type': ['leak_site', 'regulator_field', 'index_field', 'description', 'press_quote'],
}
# Where the rubric orders a basis above a higher engine (leak-site > regulator code for breach type; ccTLD >
# tracker country) the order is applied here, inside one subject.
TIERS = {
    'industry': [{'regulator_field', 'filing', 'index_field', 'wikidata'}, {'tracker_sector'}, {'description', 'press_quote'}, {'name_only'}],
    'size_band': [{'leak_post_headcount', 'index_field'}, {'wikidata'}],
    'country': [{'regulator_jurisdiction'}, {'index_field', 'wikidata'}, {'cctld'}, {'tracker_country'}],
    'data_group': [{'regulator_field', 'hibp_field', 'index_field', 'hhs_phi_regime'}, {'description'}, {'press_quote'}],
    'breach_type': [{'leak_site'}, {'regulator_field', 'index_field'}, {'description', 'press_quote'}],
}


def tier_of(v):
    for i, t in enumerate(TIERS[v.field]):
        if v.basis in t:
            return i
    return len(TIERS[v.field])


def resolve(field, vals):
    """Apply precedence to the candidate values of one subject and field. Returns (values with verdicts, conflict?).
    Single-valued: the top tier must agree on one value, else every top value is rejected as a conflict. Multi-valued
    (data_group): the union of the top tier."""
    cands = [v for v in vals if v.verdict == 'accepted' and v.value is not None]
    if not cands:
        return vals, False
    top = min(tier_of(v) for v in cands)
    conflict = False
    if field != 'data_group':
        tv = {v.value for v in cands if tier_of(v) == top}
        conflict = len(tv) > 1
    for v in cands:
        if tier_of(v) != top:
            v.verdict, v.reason = 'rejected', 'lower_precedence'
        elif conflict:
            v.verdict, v.reason = 'rejected', 'conflict'
    return vals, conflict


# =====================================================================================================
# Subjects: everything one victim brings
# =====================================================================================================
@dataclass
class Subject:
    kind: str                         # claim | incident
    sid: str                          # claim_key | incident uuid
    name: str | None = None
    domain: str | None = None
    records: list = dfield(default_factory=list)       # [(source_id, record)] (incidents)
    leak_site: bool = False
    leak: dict | None = None                           # leak_claims row (claims)
    description: str | None = None                     # leak description (claims)
    profile_groups: list | None = None
    docs: list = dfield(default_factory=list)          # [{'doc': sha, 'title', 'text', 'source_id'}]
    org_size: int | None = None                        # org_sizes.employees (exact domain, Wikidata)
    wikidata: dict | None = None                       # {'qid', 'industries': [labels], 'iso': [..], 'employees': n}

    @property
    def ref(self):
        return f'{self.kind}:{self.sid}'


def regulator_kind(source_id):
    if source_id in ('hhs_ocr', 'ca_ag', 'wa_ag', 'de_ag', 'sec_8k'):
        return 'regulator'
    if source_id in ('hibp', 'cra_export'):
        return 'index'
    if source_id in ('ransomlook', 'ransomfeed'):
        return 'leak'
    return 'press'


def structured_values(s: Subject):
    """Every structured / deterministic candidate of one subject (no network, no model)."""
    out = []
    V = lambda f, val, sk, basis, eng='structured', **kw: out.append(Val(f, val, sk, basis, eng, V_STRUCT, **kw))
    if s.kind == 'claim':
        V('breach_type', 'ransomware_extortion', 'leak', 'leak_site', 'deterministic')
        lk = s.leak or {}
        ind = industry_of_text(lk.get('sector'))
        if ind:
            V('industry', ind, 'leak', 'tracker_sector', 'deterministic')
        b = band_of(lk.get('employees_stated'))
        if b:
            V('size_band', b, 'leak', 'leak_post_headcount', 'deterministic')
        c = country_iso(lk.get('country'))
        if c:
            V('country', c, 'leak', 'tracker_country', 'deterministic')
    else:
        if s.leak_site:
            V('breach_type', 'ransomware_extortion', 'leak', 'leak_site', 'deterministic')
        for src, r in s.records:
            sk = regulator_kind(src)
            r = r or {}
            if src == 'hhs_ocr':
                ind = industry_hhs(r.get('entity_type'))
                if ind:
                    V('industry', ind, sk, 'regulator_field')
                V('country', 'US', sk, 'regulator_jurisdiction')
                bt = bt_hhs(r.get('type_of_breach'), r.get('location'), r.get('business_associate_present'), r.get('entity_type'))
                if bt:
                    V('breach_type', bt, sk, 'regulator_field')
                V('data_group', 'health', sk, 'hhs_phi_regime', 'deterministic')
            elif src == 'wa_ag':
                ind = industry_wa(r.get('industrytype'), r.get('businesstype'))
                if ind:
                    V('industry', ind, sk, 'regulator_field')
                st = (r.get('entitystate') or '').strip().upper()
                if st in US_STATES:
                    V('country', 'US', sk, 'regulator_jurisdiction')
                bt = bt_wa(r.get('databreachcause'), r.get('cyberattacktype'))
                if bt:
                    V('breach_type', bt, sk, 'regulator_field')
            elif src in ('ca_ag', 'de_ag'):
                V('country', 'US', sk, 'regulator_jurisdiction')
                if src == 'de_ag':
                    for g in groups_from_fields(split_de(r.get('information_breached'))):
                        V('data_group', g, sk, 'regulator_field')
            elif src == 'sec_8k':
                inds = {industry_sic(x) for x in (r.get('sics') or [])}
                inds.discard(None)
                if len(inds) == 1:
                    V('industry', inds.pop(), sk, 'filing')
                states = {str(x).upper() for x in (r.get('biz_states') or [])}
                if states and states <= US_STATES:
                    V('country', 'US', sk, 'regulator_jurisdiction')
            elif src == 'hibp':
                for g in groups_from_fields(r.get('DataClasses') or []):
                    V('data_group', g, sk, 'hibp_field')
            elif src == 'cra_export':
                ind = industry_naics(r.get('NAICS code'))
                if ind:
                    V('industry', ind, sk, 'index_field')
                c = country_iso(r.get('Organization - Country'))
                if c:
                    V('country', c, sk, 'index_field')
                b = band_of(r.get('Employee count'))
                if b:
                    V('size_band', b, sk, 'index_field')
                for g in groups_from_cra(r.get('Data type')):
                    V('data_group', g, sk, 'index_field')
                bt = bt_cra(r.get('Breach type'), r.get('Malware Variety'), r.get('Third party'))
                if bt:
                    V('breach_type', bt, sk, 'index_field')
    sk = 'leak' if s.kind == 'claim' else _subject_kind(s)
    c = country_cctld(s.domain)
    if c:
        V('country', c, sk, 'cctld', 'deterministic')
    b = band_of(s.org_size)
    if b:
        V('size_band', b, sk, 'wikidata')
    wd = s.wikidata or {}
    if wd.get('qid'):
        q = wd['qid']
        inds = {industry_of_wikidata(x) for x in wd.get('industries') or []}
        inds.discard(None)
        if len(inds) == 1:
            V('industry', inds.pop(), sk, 'wikidata', quote=q)
        isos = {country_iso(x) for x in wd.get('iso') or []}
        isos.discard(None)
        if len(isos) == 1:
            V('country', isos.pop(), sk, 'wikidata', quote=q)
        if s.org_size is None:
            b = band_of(wd.get('employees'))
            if b:
                V('size_band', b, sk, 'wikidata', quote=q)
    if s.kind == 'claim' and s.profile_groups is not None:
        for g in s.profile_groups:
            if g in GROUPS and g != 'unspecified':
                if cue_hit(g, s.description or ''):
                    out.append(Val('data_group', g, 'leak', 'description', 'jev', V_PROFILE, doc_ref=s.ref))
                else:
                    out.append(Val('data_group', g, 'leak', 'description', 'jev', V_PROFILE, doc_ref=s.ref,
                                   verdict='rejected', reason='no_group_cue'))
    return out


def _subject_kind(s: Subject):
    kinds = [regulator_kind(src) for src, _ in s.records]
    for k in ('regulator', 'index', 'leak', 'press'):
        if k in kinds:
            return k
    return 'press' if s.docs else ('leak' if s.leak_site else 'regulator')


# =====================================================================================================
# Jev: question set r2-q1
# =====================================================================================================
QSET = 'r2-q1'
# Frozen on DEV only (seal dev partition, Haiku dev labels, 2026-10-22): industry 0.8 -> 0.948 on 173 shown, 0.9 ->
# 0.979 on 144; the other taus kept (name-only 45/45, breach type 22/22, press groups 11/11 at these values).
TAU = {'ind': 0.9, 'ind_stated': 0.7, 'ind_not_stated_max': 0.1, 'bt': 0.8, 'bt_not_stated_max': 0.1,
       'tag': 0.8, 'tag_personal_identity': 0.9, 'name': 0.9, 'name_obvious': 0.8}
IND_CRIT = dict(INDUSTRIES, not_stated='The text does not say what this organisation does beyond its name.')
BT_CRIT = dict(BREACH_TYPES, not_stated='The text does not say how the organisation was breached.')
NAME_CRIT = dict(INDUSTRIES, unclear='The name and domain do not plainly show what kind of organisation this is.')
TAG_STEM = ("A statement that it was NOT involved is a no. Do not infer from what the organisation does. A list of data "
            "types that 'may' have been involved, in a notice, counts as stated.")
TAGS = {t: d for t, d in profile.TAGS.items() if t != 'unspecified'}


def evidence_questions(pid, want):
    ref = 'items.' + pid
    qs = {}
    if 'industry' in want:
        qs[f'{pid}_ind_stated'] = {'type': 'noul', 'instructions':
            f'Does `{ref}.text` say what `{ref}.name` does - its business, sector or kind of organisation - in words beyond its name?'}
        qs[f'{pid}_ind'] = {'type': 'choice', 'instructions':
            f'Which sector does `{ref}.text` say `{ref}.name` is in? Use only what the text says about it, not its name alone.',
            'criteria': IND_CRIT}
    if 'breach_type' in want:
        qs[f'{pid}_bt'] = {'type': 'choice', 'instructions':
            f'How does `{ref}.text` say `{ref}.name` was breached? Use only what the text states.', 'criteria': BT_CRIT}
    if 'data_group' in want:
        for t, d in TAGS.items():
            qs[f'{pid}_t_{t}'] = {'type': 'noul', 'instructions':
                f'Does `{ref}.text` state that {d}, belonging to or held by `{ref}.name`, was accessed, stolen, exposed or '
                f'compromised in the incident? {TAG_STEM}'}
    return qs


def name_questions(pid):
    ref = 'items.' + pid
    return {f'{pid}_nobv': {'type': 'noul', 'instructions':
                f'Does the name `{ref}.name` itself plainly say what kind of organisation it is (for example "Hospital", '
                '"School District", "Bank", "Law Firm", "City of")?'},
            f'{pid}_nind': {'type': 'choice', 'instructions':
                f'Judging only from the organisation name `{ref}.name` and its web domain `{ref}.domain`, which sector is '
                'it in? Answer unclear unless the name or domain plainly shows it.', 'criteria': NAME_CRIT}}


def q_hash(kind):
    probe = evidence_questions('p', ('industry', 'breach_type', 'data_group')) if kind == 'evidence' else name_questions('p')
    blob = json.dumps({'qset': QSET, 'model': MODEL, 'q': probe}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()


def item_state(it):
    if it['mode'] == 'name':
        return {'name': it['name'], 'domain': it.get('domain') or 'unknown'}
    return {'name': it['name'], 'kind_of_text': it['text_kind'], 'text': {x['sid']: x['text'] for x in it['sents']}}


def item_sha(it):
    blob = json.dumps({'state': item_state(it), 'want': sorted(it['want']), 'mode': it['mode']}, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode()).hexdigest()


def build_call(items):
    state, qs, meta = {'items': {}}, {}, {}
    for n, it in enumerate(items):
        pid = 'i%d' % (n + 1)
        state['items'][pid] = item_state(it)
        qs.update(name_questions(pid) if it['mode'] == 'name' else evidence_questions(pid, it['want']))
        meta[pid] = it
    return state, qs, meta


def split_answers(js, meta):
    A = (js or {}).get('answers') or {}
    return {pid: {k[len(pid) + 1:]: v for k, v in A.items() if k.startswith(pid + '_')} for pid in meta}


def _probs(a):
    return (a or {}).get('probabilities') or {}


def _top(a):
    pr = _probs(a)
    if not pr:
        return None, 0.0
    k = max(pr, key=pr.get)
    return k, pr[k]


def _noul(a):
    return float((a or {}).get('noul') or 0.0)


def decide_item(it, ans, tau=TAU):
    """Values of one item from its stored Jev answers (pure)."""
    out = []
    sk, ref = it['source_kind'], it.get('doc_ref')
    if it['mode'] == 'name':
        top, p = _top(ans.get('nind'))
        obv = _noul(ans.get('nobv'))
        if top and top in INDUSTRIES and p >= tau['name'] and obv >= tau['name_obvious']:
            out.append(Val('industry', top, sk, 'name_only', 'jev', V_NAME, jev_p=round(p, 4)))
        else:
            out.append(Val('industry', None, sk, 'name_only', 'jev', V_NAME, verdict='abstain', reason='name_not_plain'))
        return out
    basis = it['basis']
    text = ' '.join(x['text'] for x in it['sents'])
    if 'industry' in it['want']:
        top, p = _top(ans.get('ind'))
        st = _noul(ans.get('ind_stated'))
        if top in INDUSTRIES and p >= tau['ind'] and _probs(ans.get('ind')).get(NOT_STATED, 0) < tau['ind_not_stated_max'] \
                and st >= tau['ind_stated']:
            out.append(Val('industry', top, sk, basis, 'jev', V_JEV, jev_p=round(p, 4), doc_ref=ref))
        else:
            out.append(Val('industry', None, sk, basis, 'jev', V_JEV, verdict='abstain', reason='not_stated_or_low_p'))
    if 'breach_type' in it['want']:
        top, p = _top(ans.get('bt'))
        ok = top in BREACH_TYPES and p >= tau['bt'] and _probs(ans.get('bt')).get(NOT_STATED, 0) < tau['bt_not_stated_max']
        if ok and BT_CUES[top].search(text):
            out.append(Val('breach_type', top, sk, basis, 'jev', V_JEV, jev_p=round(p, 4), doc_ref=ref))
        else:
            out.append(Val('breach_type', None, sk, basis, 'jev', V_JEV, verdict='abstain',
                           reason='no_cue' if ok else 'not_stated_or_low_p'))
    if 'data_group' in it['want']:
        fine = [t for t in TAGS if _noul(ans.get('t_' + t)) >= tau.get('tag_' + t, tau['tag'])]
        gs = []
        for t in fine:
            g = tag_group(t)
            if g and g not in gs:
                gs.append(g)
        for g in gs:
            q = group_quote(g, it['sents'], require_taken=it.get('require_taken', True))
            if q:
                out.append(Val('data_group', g, sk, basis, 'jev', V_JEV, jev_p=round(_noul_max(ans, g), 4), doc_ref=ref,
                               quote=q[:300]))
            else:
                out.append(Val('data_group', g, sk, basis, 'jev', V_JEV, verdict='rejected', reason='no_group_cue', doc_ref=ref))
    return out


def _noul_max(ans, g):
    return max([_noul(ans.get('t_' + t)) for t in TAGS if tag_group(t) == g] or [0.0])


def group_quote(group, sents, require_taken=True):
    """The first sentence carrying the group's cue (not negated) and, for press, a taken/exposed verb in a clause
    that is not negated."""
    for s in sents:
        t = s['text']
        m = cue_hit(group, t)
        if not m:
            continue
        if require_taken:
            tm = next((x for x in TAKEN.finditer(t) if not clause_negated(t, x.start())), None)
            if not tm:
                continue
        return t
    return None


# =====================================================================================================
# Planning: which subject needs which Jev question
# =====================================================================================================
def accepted_fields(vals):
    return {v.field for v in vals if v.verdict == 'accepted' and v.value is not None}


def plan_items(s: Subject, vals):
    """Jev items for one subject, given its structured values. Evidence first; name-only only for industry still open."""
    have = accepted_fields(vals)
    items = []
    want_base = [f for f in ('industry', 'breach_type') if f not in have]
    if s.kind == 'claim':
        want = [f for f in want_base if f == 'industry']
        sents = evidence_sentences(s.description)
        if want and s.description and len(s.description) >= profile.DESC_MIN and sents:
            items.append({'mode': 'evidence', 'want': want, 'sents': sents, 'text_kind': 'ransomware leak-site post about the victim',
                          'name': s.name, 'basis': 'description', 'source_kind': 'leak', 'doc_ref': s.ref, 'subject': s.ref})
    else:
        want = list(want_base)
        if 'data_group' not in have:
            want.append('data_group')
        texts = []
        for src, r in s.records:
            if src == 'hibp' and (r or {}).get('Description'):
                texts.append(('index', 'description', 'breach index entry describing the incident', clean_html(r['Description']), f'{s.ref}#hibp', False))
            elif src == 'cra_export' and (r or {}).get('Summary'):
                texts.append(('index', 'description', 'breach index summary of the incident', r['Summary'], f'{s.ref}#cra', False))
        if s.docs:
            texts.append(('press', 'press_quote', 'sentences of news articles that name the organisation', s.docs,
                          f"doc:{s.docs[0]['doc']}", True))
        for sk, basis, kind, t, ref, press in texts:
            if not want:
                break
            sents = press_sentences(t, s.name, s.domain) if press else evidence_sentences(t)
            if not sents:
                continue
            w = list(want)
            if sk == 'index' and any(src == 'hibp' for src, _ in s.records):
                w = [x for x in w if x != 'data_group']       # HIBP lists its data classes as a field
            if not w:
                continue
            items.append({'mode': 'evidence', 'want': w, 'sents': sents, 'text_kind': kind, 'name': s.name, 'basis': basis,
                          'source_kind': sk, 'doc_ref': ref, 'subject': s.ref, 'require_taken': press})
            want = [x for x in want if x not in w]           # one text answers a field; the next only what is left
    if 'industry' not in have and not any('industry' in it['want'] for it in items) and s.name:
        items.append({'mode': 'name', 'want': ['industry'], 'name': s.name, 'domain': s.domain, 'basis': 'name_only',
                      'source_kind': 'leak' if s.kind == 'claim' else _subject_kind(s), 'subject': s.ref})
    return items


def name_followup(s: Subject, vals, items_done):
    """After the evidence items: a name-only item when industry is still open."""
    have = accepted_fields(vals)
    if 'industry' in have or not s.name or any(it['mode'] == 'name' for it in items_done):
        return None
    return {'mode': 'name', 'want': ['industry'], 'name': s.name, 'domain': s.domain, 'basis': 'name_only',
            'source_kind': 'leak' if s.kind == 'claim' else _subject_kind(s), 'subject': s.ref}


# =====================================================================================================
# Finalise one subject: precedence, conflicts, abstain slots
# =====================================================================================================
def finalise(s: Subject, vals):
    by = collections.defaultdict(list)
    for v in vals:
        by[v.field].append(v)
    reviews = []
    out = []
    for f in FIELDS:
        vs, conflict = resolve(f, by.get(f, []))
        if conflict:
            reviews.append({'field': f, 'values': sorted({v.value for v in vs if v.reason == 'conflict'})})
        if not any(v.verdict == 'accepted' and v.value is not None for v in vs):
            if not any(v.verdict == 'abstain' for v in vs):
                sk = 'leak' if s.kind == 'claim' else _subject_kind(s)
                vs.append(Val(f, None, sk, 'none', 'deterministic', V_STRUCT, verdict='abstain',
                              reason='conflict' if conflict else 'no_evidence'))
        else:                                     # an abstain beside an accepted value is noise: drop it
            vs = [v for v in vs if v.verdict != 'abstain']
        out.extend(vs)
    return out, reviews


# =====================================================================================================
# Database
# =====================================================================================================
def _timeouts(cur):
    cur.execute(f"set local statement_timeout = '{STATEMENT_TIMEOUT}'")
    cur.execute(f"set local lock_timeout = '{LOCK_TIMEOUT}'")


SUBJECTS_SQL = """
select v.victim_id, v.kind, v.name, lower(v.domain) from breach_core.victims_list v
 where v.victim_id > %(after)s order by v.victim_id limit %(n)s
"""
CLAIMS_SQL = """
select l.claim_key, l.sector, l.country, l.employees_stated, d.descr, p.profile_groups
  from breach_core.leak_claims l
  left join lateral (
    select left(s.record->>'description', 3000) as descr
      from jsonb_array_elements(l.tracker_refs) r
      join breach_raw.source_records s on s.source_id = r->>'source_id' and s.source_record_id = r->>'id'
     where coalesce(s.record->>'description', '') <> ''
     order by (r->>'source_id') = 'ransomlook' desc, s.version desc, s.source_record_id
     limit 1) d on true
  left join breach_core.victim_profiles p on p.claim_key = l.claim_key and p.method_version = 'breach-profile-v1'
 where l.claim_key = any(%(keys)s)
"""
INC_RECORDS_SQL = "select incident_id::text, source_id, record from breach_core.incident_records where incident_id::text = any(%(ids)s)"
INC_LEAK_SQL = """
select incident_id::text from breach_core.incident_sources where incident_id::text = any(%(ids)s) and source_id in ('ransomlook', 'ransomfeed')
union select incident_id::text from breach_core.leak_claims where incident_id::text = any(%(ids)s)
"""
INC_DOCS_SQL = """
select distinct on (s.incident_id, d.doc_sha256) s.incident_id::text, d.doc_sha256, d.title, left(d.text, 20000), d.source_id
  from breach_core.incident_sources s join breach_raw.documents d on d.doc_sha256 = split_part(s.doc_sha256, ':', 1)
 where s.incident_id::text = any(%(ids)s) and s.source_id like 'news%%' and length(d.text) >= 200
"""
SIZES_SQL = "select domain, employees from breach_core.org_sizes where outcome = 'ok' and domain = any(%(doms)s)"


def load_subjects(conn, limit=None, page=2000, wikidata=None, only=None):
    """All victims_list subjects with their evidence, in pages (read-only, 60 s statement timeout per query)."""
    subs, after = [], ''
    with conn.cursor() as cur:
        cur.execute(f"set statement_timeout = '{STATEMENT_TIMEOUT}'")
        while True:
            cur.execute(SUBJECTS_SQL, {'after': after, 'n': page})
            rows = cur.fetchall()
            if not rows:
                break
            after = rows[-1][0]
            batch = []
            for vid, kind, name, dom in rows:
                k, _, sid = vid.partition(':')
                if only is not None and vid not in only:
                    continue
                batch.append(Subject('claim' if k == 'claim' else 'incident', sid, name, dom))
            claims = {s.sid: s for s in batch if s.kind == 'claim'}
            incs = {s.sid: s for s in batch if s.kind == 'incident'}
            if claims:
                cur.execute(CLAIMS_SQL, {'keys': list(claims)})
                for key, sector, country, emp, descr, pg in cur.fetchall():
                    s = claims[key]
                    s.leak = {'sector': sector, 'country': country, 'employees_stated': emp}
                    s.description, s.profile_groups = descr, pg
            if incs:
                ids = list(incs)
                cur.execute(INC_RECORDS_SQL, {'ids': ids})
                for iid, src, rec in cur.fetchall():
                    incs[iid].records.append((src, rec))
                cur.execute(INC_LEAK_SQL, {'ids': ids})
                for (iid,) in cur.fetchall():
                    incs[iid].leak_site = True
                cur.execute(INC_DOCS_SQL, {'ids': ids})
                for iid, sha, title, text, src in cur.fetchall():
                    incs[iid].docs.append({'doc': sha, 'title': title, 'text': text, 'source_id': src})
                for s in incs.values():
                    s.records.sort(key=lambda x: x[0])
                    s.docs.sort(key=lambda d: d['doc'])
            doms = sorted({s.domain for s in batch if s.domain})
            if doms:
                cur.execute(SIZES_SQL, {'doms': doms})
                sz = dict(cur.fetchall())
                for s in batch:
                    s.org_size = sz.get(s.domain)
            for s in batch:
                if wikidata and s.domain:
                    s.wikidata = wikidata.get(s.domain)
            subs.extend(batch)
            if limit and len(subs) >= limit:
                return subs[:limit]
    return subs


ANS_COLS = ('engine', 'engine_version', 'model_id', 'prompt_sha256', 'input_ref', 'input_sha256', 'answer', 'p', 'cost_usd', 'run_id')
VAL_COLS = ('subject_kind', 'subject_id', 'field', 'value', 'source_kind', 'basis', 'engine', 'engine_version', 'quote',
            'doc_ref', 'claim_ref', 'answer_id', 'jev_p', 'verdict', 'verdict_reason')


def new_subjects(conn):
    """Victim ids of the list without any value of this module's structured version (records ingested after the backfill)."""
    with conn.cursor() as cur:
        cur.execute(f"set statement_timeout = '{STATEMENT_TIMEOUT}'")
        cur.execute("""select l.victim_id from breach_core.victims_list l
                        where not exists (select 1 from breach_core.r2_values v
                                           where v.subject_victim_id = l.victim_id and v.engine_version = %s)""", (V_STRUCT,))
        return {r[0] for r in cur.fetchall()}


def stored_answers(conn, keys):
    """{(engine_version, prompt_sha, input_sha): (answer_id, answer)} for already asked items."""
    out = {}
    if not keys:
        return out
    with conn.cursor() as cur:
        cur.execute(f"set statement_timeout = '{STATEMENT_TIMEOUT}'")
        shas = sorted({k[2] for k in keys})
        for i in range(0, len(shas), 2000):
            cur.execute("""select answer_id, engine_version, prompt_sha256, input_sha256, answer from breach_core.r2_answers
                            where engine = 'jev' and input_sha256 = any(%s)""", (shas[i:i + 2000],))
            for aid, ev, ps, ins, ans in cur.fetchall():
                out[(ev, ps, ins)] = (aid, ans)
    return out


def write_answers(conn, rows):
    """rows: [dict(ANS_COLS)] -> {(engine_version, prompt_sha, input_sha): answer_id}. Insert-only; a re-ask with
    the same input conflicts and keeps the first answer."""
    from psycopg.types.json import Jsonb
    ids = {}
    for i in range(0, len(rows), 500):
        chunk = rows[i:i + 500]
        with conn.transaction(), conn.cursor() as cur:
            _timeouts(cur)
            cur.executemany(
                f"insert into breach_core.r2_answers ({', '.join(ANS_COLS)}) values ({', '.join(['%s'] * len(ANS_COLS))}) "
                "on conflict (engine_version, prompt_sha256, input_sha256) do nothing",
                [tuple(Jsonb(r[c]) if c == 'answer' else r[c] for c in ANS_COLS) for r in chunk])
            cur.execute("""select answer_id, engine_version, prompt_sha256, input_sha256 from breach_core.r2_answers
                            where input_sha256 = any(%s)""", ([r['input_sha256'] for r in chunk],))
            for aid, ev, ps, ins in cur.fetchall():
                ids[(ev, ps, ins)] = aid
    return ids


def clear_values(conn):
    """Remove this module's earlier candidate values (never other tracks' rows), in small batches."""
    n = 0
    while True:
        with conn.transaction(), conn.cursor() as cur:
            _timeouts(cur)
            cur.execute("""delete from breach_core.r2_values where value_id in (
                             select value_id from breach_core.r2_values where engine_version = any(%s) limit 5000)""",
                        (list(MY_VERSIONS),))
            k = cur.rowcount
        n += k
        if k == 0:
            return n


def write_values(conn, subj_vals, reviews, run_id, write_reviews=False):
    """subj_vals: [(Subject, [Val])] -> rows written. COPY in chunks, one transaction per chunk."""
    rows = []
    for s, vals in subj_vals:
        for v in vals:
            rows.append((s.kind, s.sid, v.field, v.value, v.source_kind, v.basis, v.engine, v.engine_version, v.quote,
                         v.doc_ref, v.claim_ref, v.answer_id, v.jev_p, v.verdict, v.reason))
    for i in range(0, len(rows), WRITE_CHUNK):
        with conn.transaction(), conn.cursor() as cur:
            _timeouts(cur)
            with cur.copy(f"copy breach_core.r2_values ({', '.join(VAL_COLS)}) from stdin") as cp:
                for r in rows[i:i + WRITE_CHUNK]:
                    cp.write_row(r)
    from psycopg.types.json import Jsonb
    if not write_reviews:          # T4 scope: r2_values/r2_answers only; conflicts stay as verdict_reason='conflict'
        reviews = []
    for i in range(0, len(reviews), 500):
        with conn.transaction(), conn.cursor() as cur:
            _timeouts(cur)
            cur.executemany("""insert into breach_core.r2_review (subject_kind, subject_id, field, reason, detail)
                               values (%s, %s, %s, 'conflict', %s)""",
                            [(k, sid, r['field'], Jsonb({'values': r['values'], 'run_id': run_id, 'method': METHOD}))
                             for k, sid, r in reviews[i:i + 500]])
    return len(rows)


# =====================================================================================================
# Wikidata by exact website domain (P452 industry labels, P17 -> ISO, P1128 employees)
# =====================================================================================================
WD_ENDPOINT = 'https://query.wikidata.org/sparql'


def wd_query(domains):
    from .sources_size import variants
    values = ' '.join(f'<{u}>' for d in domains for u in variants(d))
    return ('SELECT ?item ?url ?indLabel ?iso ?emp ?t WHERE { VALUES ?url { ' + values + ' } ?item wdt:P856 ?url . '
            'OPTIONAL { ?item wdt:P452 ?ind . ?ind rdfs:label ?indLabel FILTER(lang(?indLabel) = "en") } '
            'OPTIONAL { ?item wdt:P17 ?c . ?c wdt:P297 ?iso } '
            'OPTIONAL { ?item p:P1128 ?st . ?st ps:P1128 ?emp . OPTIONAL { ?st pq:P585 ?t } } }')


def wd_parse(js):
    """SPARQL JSON -> {domain: {'qid', 'industries', 'iso', 'employees'}}; a domain claimed by two items is dropped."""
    per = collections.defaultdict(lambda: collections.defaultdict(lambda: {'industries': set(), 'iso': set(), 'emp': []}))
    for b in (js.get('results') or {}).get('bindings') or []:
        u = b['url']['value']
        dom = re.sub(r'^https?://(www\.)?', '', u).rstrip('/').lower()
        q = b['item']['value'].rsplit('/', 1)[-1]
        e = per[dom][q]
        if 'indLabel' in b:
            e['industries'].add(b['indLabel']['value'])
        if 'iso' in b:
            e['iso'].add(b['iso']['value'])
        if 'emp' in b:
            try:
                e['emp'].append((b.get('t', {}).get('value') or '', float(b['emp']['value'])))
            except ValueError:
                pass
    out = {}
    for dom, items in per.items():
        if len(items) != 1:
            continue
        q, e = next(iter(items.items()))
        emp = None
        if e['emp']:
            dated = [x for x in e['emp'] if x[0]]
            emp = int(max(dated)[1]) if dated else int(max(x[1] for x in e['emp']))
        out[dom] = {'qid': q, 'industries': sorted(e['industries']), 'iso': sorted(e['iso']), 'employees': emp}
    return out


def fetch_wikidata(domains, cache_path, batch=40, sleep=1.0):
    import urllib.parse
    import urllib.request
    cache = {}
    if os.path.exists(cache_path):
        cache = json.load(open(cache_path))
    todo = [d for d in domains if d not in cache.get('_asked', {})]
    asked = cache.setdefault('_asked', {})
    found = cache.setdefault('found', {})
    for i in range(0, len(todo), batch):
        ds = todo[i:i + batch]
        q = wd_query(ds)
        req = urllib.request.Request(WD_ENDPOINT, data=urllib.parse.urlencode({'query': q}).encode(), method='POST',
                                     headers={'Accept': 'application/sparql-results+json',
                                              'User-Agent': 'ZeroDayClock-breach-r2/1 (https://zerodayclock.com; research)'})
        for a in range(4):
            try:
                with urllib.request.urlopen(req, timeout=90) as r:
                    js = json.loads(r.read().decode())
                break
            except Exception:                         # noqa: BLE001 - retried, then the batch is skipped
                time.sleep(5 * (a + 1))
        else:
            continue
        found.update(wd_parse(js))
        for d in ds:
            asked[d] = 1
        if i // batch % 10 == 0:
            json.dump(cache, open(cache_path, 'w'))
        time.sleep(sleep)
    json.dump(cache, open(cache_path, 'w'))
    return found


# =====================================================================================================
# Run
# =====================================================================================================
def _new_report(mode):
    return {'method': METHOD, 'mode': mode, 'model': MODEL, 'qset': QSET, 'subjects': 0,
            'fields': {f: {'attempted': 0, 'accepted': 0, 'abstained': 0, 'conflict': 0,
                           'by_engine': collections.Counter(), 'by_basis': collections.Counter(),
                           'by_value': collections.Counter(), 'by_stratum': collections.Counter()} for f in FIELDS},
            'jev': {'items': 0, 'items_cached': 0, 'calls': 0, 'input_tokens': 0, 'usd': 0.0, 'errors': collections.Counter()},
            'seconds': {}}


def tally(rep, s, vals):
    rep['subjects'] += 1
    for f in FIELDS:
        fv = [v for v in vals if v.field == f]
        R = rep['fields'][f]
        R['attempted'] += 1
        acc = [v for v in fv if v.verdict == 'accepted']
        if acc:
            R['accepted'] += 1
            for v in acc:
                R['by_engine'][v.engine] += 1
                R['by_basis'][v.basis] += 1
                R['by_value'][v.value] += 1
                R['by_stratum'][v.source_kind] += 1
        else:
            R['abstained'] += 1
        if any(v.reason == 'conflict' for v in fv):
            R['conflict'] += 1


def ask_items(jev, items, kind, rep, stored, run_id, deadline=None):
    """Ask Jev about items (cached answers reused). Returns {id(item): (answers, key)} and answer rows to store."""
    ev = V_NAME if kind == 'name' else V_JEV
    ph = q_hash(kind)
    res, new_rows, todo = {}, [], []
    for it in items:
        key = (ev, ph, item_sha(it))
        if key in stored:
            res[id(it)] = (stored[key][1].get('q') or {}, key)
            rep['jev']['items_cached'] += 1
        else:
            todo.append(it)
    per = PER_CALL_NAME if kind == 'name' else PER_CALL
    chunks = [todo[i:i + per] for i in range(0, len(todo), per)]
    lock = threading.Lock()

    def one(chunk):
        st, qs, meta = build_call(chunk)
        js = jev.ask(st, qs)
        return chunk, meta, js

    stop = None
    with cf.ThreadPoolExecutor(WORKERS) as ex:
        futs = []
        for ch in chunks:
            futs.append(ex.submit(one, ch))
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
            cost = int(usage.get('input_tokens') or 0) * PRICE_PER_MTOK / 1e6
            with lock:
                rep['jev']['calls'] += 1
            per_item = cost / max(1, len(chunk))
            for pid, ans in split_answers(js, meta).items():
                it = meta[pid]
                key = (ev, ph, item_sha(it))
                res[id(it)] = (ans, key)
                new_rows.append({'engine': 'jev', 'engine_version': ev, 'model_id': js.get('model') or MODEL,
                                 'prompt_sha256': ph, 'input_ref': it['subject'], 'input_sha256': key[2],
                                 'answer': {'q': ans, 'qset': QSET, 'mode': it['mode'], 'want': sorted(it['want'])},
                                 'p': None, 'cost_usd': round(per_item, 6), 'run_id': run_id})
            if deadline and time.time() > deadline:
                stop = 'deadline'
    if stop:
        rep['jev']['stopped'] = stop
    return res, new_rows


def classify(conn, subjects, jev=None, rep=None, run_id=None, write=False, jev_stage=True, stored_fn=None, answers_fn=None,
             clear=True):
    """Structured values for every subject; with jev_stage, Jev values from stored answers (asking Jev for the
    missing ones only when `jev` is given). write: store new answers (always, when Jev was asked) and the values."""
    rep = rep or _new_report('run')
    stored_fn = stored_fn or (lambda keys: stored_answers(conn, keys))
    answers_fn = answers_fn or (lambda rows: write_answers(conn, rows) if conn is not None else {})
    t0 = time.time()
    base = {s.ref: structured_values(s) for s in subjects}
    rep['seconds']['structured'] = round(time.time() - t0, 1)
    jev_vals = collections.defaultdict(list)
    ans_ids = {}

    def stage(items, kind):
        ev, ph = (V_NAME, q_hash('name')) if kind == 'name' else (V_JEV, q_hash('evidence'))
        stored = stored_fn([(ev, ph, item_sha(it)) for it in items])
        rep['jev']['items'] += len(items)
        if jev is not None:
            res, rows = ask_items(jev, items, kind, rep, stored, run_id)
        else:
            res, rows = _cached(items, kind, stored, rep), []
        if rows:
            ans_ids.update(answers_fn(rows))                # answers are the reproducible unit: always kept
        for k, (aid, _) in stored.items():
            ans_ids.setdefault(k, aid)
        for it in items:
            if id(it) in res:
                ans, key = res[id(it)]
                for v in decide_item(it, ans):
                    v.answer_key = key
                    jev_vals[it['subject']].append(v)

    if jev_stage:
        t1 = time.time()
        stage([it for s in subjects for it in plan_items(s, base[s.ref]) if it['mode'] == 'evidence'], 'evidence')
        stage([it for s in subjects for it in [name_followup(s, base[s.ref] + jev_vals[s.ref], [])] if it], 'name')
        rep['seconds']['jev'] = round(time.time() - t1, 1)
        if jev is not None:
            rep['jev']['input_tokens'] = jev.budget.input_tokens
            rep['jev']['usd'] = round(jev.budget.spent_usd, 4)
            rep['jev']['calls_total'] = jev.budget.calls
    out, reviews = [], []
    for s in subjects:
        vals = base[s.ref] + jev_vals[s.ref]
        for v in vals:
            v.answer_id = ans_ids.get(v.answer_key) if v.answer_key else None
        fin, rv = finalise(s, vals)
        out.append((s, fin))
        reviews.extend((s.kind, s.sid, r) for r in rv)
        tally(rep, s, fin)
    if write:
        t2 = time.time()
        rep['cleared'] = clear_values(conn) if clear else 0      # a partial run appends: never clear the other subjects
        rep['written'] = write_values(conn, out, reviews, run_id)
        rep['reviews'] = len(reviews)
        rep['seconds']['write'] = round(time.time() - t2, 1)
    return out, rep


def _cached(items, kind, stored, rep):
    ev = V_NAME if kind == 'name' else V_JEV
    ph = q_hash(kind)
    res = {}
    for it in items:
        key = (ev, ph, item_sha(it))
        if key in stored:
            res[id(it)] = (stored[key][1].get('q') or {}, key)
            rep['jev']['items_cached'] += 1
    return res


def report_json(rep):
    def conv(x):
        if isinstance(x, collections.Counter):
            return dict(sorted(x.items(), key=lambda kv: (-kv[1], str(kv[0]))))
        if isinstance(x, dict):
            return {k: conv(v) for k, v in x.items()}
        return x
    return json.dumps(conv(rep), indent=2, sort_keys=True, default=str)


def main(argv=None):
    ap = argparse.ArgumentParser(prog='zdc-breach-r2-classify', description=__doc__.split('\n')[0])
    ap.add_argument('--report')
    sub = ap.add_subparsers(dest='cmd', required=True)
    r = sub.add_parser('run')
    r.add_argument('--limit', type=int)
    r.add_argument('--max-usd', type=float, default=15.0)
    r.add_argument('--no-jev', action='store_true')
    r.add_argument('--write', action='store_true')
    r.add_argument('--wikidata', help='cache file written by the wikidata command')
    r.add_argument('--only', help='file of victim ids (one per line) to restrict the run to')
    r2 = sub.add_parser('rescore')
    r2.add_argument('--write', action='store_true')
    r2.add_argument('--wikidata')
    w = sub.add_parser('wikidata')
    w.add_argument('--cache', required=True)
    n = sub.add_parser('structured', help='hourly: structured/deterministic values (no Jev) for subjects that have none yet')
    n.add_argument('--write', action='store_true')
    args = ap.parse_args(argv)
    import psycopg
    conn = psycopg.connect(os.environ['DATABASE_URL'], autocommit=True)
    run_id = 'r2c-' + time.strftime('%Y%m%dT%H%M%S')
    if args.cmd == 'wikidata':
        with conn.cursor() as cur:
            cur.execute(f"set statement_timeout = '{STATEMENT_TIMEOUT}'")
            cur.execute("select distinct lower(domain) from breach_core.victims_list where domain is not null")
            doms = sorted(d for (d,) in cur.fetchall() if d and re.match(r'^[a-z0-9.-]+\.[a-z]{2,}$', d))
        found = fetch_wikidata(doms, args.cache)
        print(json.dumps({'domains': len(doms), 'found': len(found)}))
        return 0
    wd = None
    if getattr(args, 'wikidata', None):
        wd = json.load(open(args.wikidata)).get('found') or {}
    only = None
    if getattr(args, 'only', None):
        only = {x.strip() for x in open(args.only) if x.strip()}
    if args.cmd == 'structured':
        only = new_subjects(conn)
        if not only:
            print(report_json(_new_report('structured')))
            return 0
    t0 = time.time()
    subs = load_subjects(conn, limit=getattr(args, 'limit', None), wikidata=wd, only=only)
    rep = _new_report(args.cmd)
    rep['seconds']['load'] = round(time.time() - t0, 1)
    rep['run_id'] = run_id
    jev = None
    if args.cmd == 'run' and not args.no_jev:
        jev = Jev(Budget(args.max_usd), user_agent='zdc-breach-r2-classify/1')
        if jev.pin_answers() is False:
            print(f'pinned model {MODEL} no longer answers', file=sys.stderr)
            return 5
    _, rep = classify(conn, subs, jev=jev, rep=rep, run_id=run_id, write=args.write,
                      jev_stage=not getattr(args, 'no_jev', False) and args.cmd != 'structured', clear=only is None)
    rep['seconds']['total'] = round(time.time() - t0, 1)
    text = report_json(rep)
    if args.report:
        open(args.report, 'w').write(text)
    print(text)
    return 0


if __name__ == '__main__':
    sys.exit(main())
