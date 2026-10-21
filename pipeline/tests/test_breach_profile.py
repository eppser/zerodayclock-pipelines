"""Unit tests: breach-profile-v1 (zdc_breach.profile). Synthetic text only - no real leak text anywhere in this file.

Each test names the mutant it kills. The equivalence tests at the bottom import the frozen research files
(P1.2: pjev2.py, decide2.py, split.py) when they are present on this machine and skip otherwise; they never print
leak text, only difference counts.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

import pytest

from zdc_breach import profile as P

REPO = Path(__file__).resolve().parents[2]


def S(*texts):
    return [{'sid': 's%d' % (i + 1), 'text': t} for i, t in enumerate(texts)]


def choice(cls, p=0.97, **extra):
    """A Jev choice answer: `cls` at p, the rest spread over 'other', with overrides."""
    pr = {c: 0.0 for c in P.CLASSES}
    pr[cls] = p
    pr['other'] = round(pr.get('other', 0) + 1 - p, 6) if cls != 'other' else p
    pr.update(extra)
    return {'type': 'choice', 'choice': max(pr, key=pr.get), 'confidence': p, 'probabilities': pr}


def answers(sents, cls='profile', p=0.97, tags=None, **per_sid):
    A = {'t_' + t: {'type': 'noul', 'noul': 0.0} for t in P.TAG_NAMES}
    for t, v in (tags or {}).items():
        A['t_' + t] = {'type': 'noul', 'noul': v}
    for s in sents:
        A['c_' + s['sid']] = per_sid.get(s['sid']) or choice(cls, p)
    return A


CLEAN = 'Zzorb Garden Tools is a family firm making spades in a small town.'
CLEAN2 = 'The company employs craftspeople and sells through local shops.'


# ---- splitter split-v1 ---------------------------------------------------------------------------------------
def test_split_html_breaks_and_pipes():            # mutant: <br>/<p> not treated as separators; ' | ' not a separator
    assert P.sentences('Alpha one<br>beta two<p>Gamma three</p> | Delta four') == ['Alpha one', 'beta two', 'Gamma three', 'Delta four']


def test_split_only_before_capital_digit_or_quote():   # mutant: split on every '. '
    assert P.sentences('Founded in 1990 by J. smith. Now 40 staff. "Quoted" end.') == \
        ['Founded in 1990 by J. smith.', 'Now 40 staff.', '"Quoted" end.']


def test_split_drops_truncated_tail():              # mutant: trailing '...' / unicode ellipsis fragment kept
    assert P.sentences('One firm. Two things...') == ['One firm.']
    assert P.sentences('One firm. Two things…') == ['One firm.']


def test_split_drops_unterminated_tail_only_when_long():   # mutant: the 2,900-character rule dropped or applied to short text
    long = ('Word ' * 600).strip() + '. Tail without end'
    assert len(long) >= 2900 and P.sentences(long)[-1].endswith('Word.')
    assert P.sentences('Short. Tail without end') == ['Short.', 'Tail without end']


def test_split_unescapes_and_collapses_whitespace():    # mutant: html.unescape removed
    assert P.sentences('Tom &amp; Co   makes\t tools.') == ['Tom & Co makes tools.']


def test_sentence_ids_are_one_based():              # mutant: s0-based ids (would not join the stored answers)
    assert [s['sid'] for s in P.sentence_items('A one. B two.')] == ['s1', 's2']


# ---- scrub: every pattern ------------------------------------------------------------------------------------
SCRUB_CASES = [   # (index into P.SCRUB, a sentence only that pattern needs to catch)
    (0, 'Write to info@zzorb.example.com now please'),
    (1, 'Call the office on 0123 456 7890 today'),
    (2, 'More at http and www.thing and that'),
    (3, 'Reach us via @zzhandle for anything'),
    (4, 'Our tox id is given further below'),
    (5, 'The number 123-45-6789 is listed'),
    (6, 'Account DE44500105175407324931 belongs'),
    (7, 'Reference 1234567 belongs to the firm'),
    (8, 'They said “we care” about it'),
    (9, 'Here is a sample of the content'),
    (10, 'Turnover of 5 dollars per item'),
    (11, 'Opened on 12/03/2020 in the town'),
    (12, 'They hold 40 gb of data here'),
]


@pytest.mark.parametrize('idx,text', SCRUB_CASES)
def test_every_scrub_pattern_fires(idx, text):     # mutant: any single SCRUB pattern deleted or weakened
    assert P.SCRUB[idx].search(text), idx
    assert P.scrub_hit(text)


def test_scrub_cases_cover_every_pattern():        # mutant: a pattern added without a test
    assert sorted(i for i, _ in SCRUB_CASES) == list(range(len(P.SCRUB)))


@pytest.mark.parametrize('rx,text', [
    ('HOST', 'Visit zzorb.ie for more about us'),
    ('IP', 'Server at 1.2.3.4 belongs to them'),
    ('KV', 'Country is given here status: private'),
    ('ATTACK', 'The company was hacked last week by us'),
    ('ATTACK', 'We are ready to share it with the world'),
])
def test_host_ip_kv_attack_fire(rx, text):          # mutant: HOST / IP / KV / ATTACK dropped from scrub_hit
    assert getattr(P, rx).search(text)
    assert P.scrub_hit(text)


def test_victim_domain_is_not_exempt():             # mutant: the P1.1 victim-domain exemption kept (P1.2 C3: any hostname drops)
    assert P.scrub_hit('Zzorb runs zzorb.example.org for its shop', 'zzorb.example.org')


def test_clean_sentence_passes_scrub():             # mutant: a scrub that fires on everything (would show nothing)
    assert not P.scrub_hit(CLEAN) and not P.scrub_hit(CLEAN2)


# ---- display gate --------------------------------------------------------------------------------------------
def test_display_shows_clean_profile_sentences():   # control for every gate test below
    s = S(CLEAN, CLEAN2)
    assert P.display(answers(s), s) == ['s1', 's2']


@pytest.mark.parametrize('text', [
    # synthetic stand-ins for the four round-1 failures, one per filter (never real leak text: ADR 0010)
    '2TB region: Exampleland status: private',                                           # "key: value" + byte size
    'Zzexample-holdings.zz placeExampleland',                                             # a bare hostname
    'Zzexample Timber is a sawmill.We are ready to upload 30GB files of corporate records',  # attacker voice
    'Zzexample Radio Hacked This website is the largest radio site in the region',        # "Hacked" headline
])
def test_round1_bad_sentences_are_never_shown(text):  # mutant: KV, HOST, ATTACK or the byte-size scrub removed (RULING P1.2 C3)
    s = S(text)
    assert P.display(answers(s, 'profile', 0.99), s) == []


def test_whole_description_veto_at_0_2():           # mutant: veto threshold moved, or veto made per-sentence
    s = S(CLEAN, CLEAN2)
    bad = choice('profile', 0.75, personal_data=0.2)
    assert P.display(answers(s, s2=bad), s) == []
    ok = choice('profile', 0.75, personal_data=0.19)
    assert P.display(answers(s, s2=ok), s) == ['s1']


@pytest.mark.parametrize('field', ['personal_data', 'sample_or_dump', 'contact_instructions'])
def test_veto_classes(field):                       # mutant: one of the three veto classes dropped
    s = S(CLEAN, CLEAN2)
    assert P.display(answers(s, s2=choice('other', 0.7, **{field: 0.25})), s) == []


def test_missing_answer_vetoes():                   # mutant: an unclassified sentence (beyond the first 12) skipped instead of vetoing
    s = S(CLEAN, CLEAN2)
    A = answers(s)
    del A['c_s2']
    assert P.display(A, s) == []


def test_profile_only():                            # mutant: data_summary still shown (P1.1 behaviour)
    s = S(CLEAN, CLEAN2)
    assert P.display(answers(s, s2=choice('data_summary', 0.99)), s) == ['s1']


def test_p_threshold_0_9():                         # mutant: G-D1 threshold lowered
    s = S(CLEAN, CLEAN2)
    assert P.display(answers(s, s2=choice('profile', 0.89)), s) == ['s1']
    assert P.display(answers(s, s2=choice('profile', 0.9)), s) == ['s1', 's2']


def test_p_personal_and_sample_below_0_05():        # mutant: the per-sentence p_personal / p_sample bound dropped
    s = S(CLEAN, CLEAN2)
    assert P.display(answers(s, s2=choice('profile', 0.93, personal_data=0.05)), s) == ['s1']
    assert P.display(answers(s, s2=choice('profile', 0.93, sample_or_dump=0.05)), s) == ['s1']


def test_length_bounds():                           # mutant: 20..400 bounds changed
    s = S('Zzorb makes spades.', 'Zzorb makes spade s.', 'Zzorb ' + 'x' * 395)
    assert [len(x['text']) for x in s] == [19, 20, 401]
    assert P.display(answers(s), s) == ['s2']


def test_four_sentences_and_600_chars():            # mutant: the 4-sentence / 600-character caps removed
    s = S(*['Zzorb makes garden spade number %d in its town.' % i for i in range(6)])
    assert len(P.display(answers(s), s)) == 4
    big = S(*[('Zzorb makes spades ' * 15)[:280] + '.' for _ in range(3)])
    assert P.display(answers(big), big) == ['s1', 's2']


# ---- tag thresholds and groups -------------------------------------------------------------------------------
def test_tau_default_0_6():                         # mutant: TAU_DEFAULT back at 0.7 (P1.1)
    assert P.tags(answers([], tags={'health': 0.6}), P.TAG_NAMES) == ['health']
    assert P.tags(answers([], tags={'health': 0.59}), P.TAG_NAMES) == []


def test_personal_identity_0_9():                   # mutant: personal_identity at the default threshold
    assert P.tags(answers([], tags={'personal_identity': 0.89}), P.TAG_NAMES) == []
    assert P.tags(answers([], tags={'personal_identity': 0.9}), P.TAG_NAMES) == ['personal_identity']


def test_unspecified_exclusive():                   # mutant: unspecified emitted beside a real tag
    assert P.tags(answers([], tags={'unspecified': 0.9, 'hr': 0.8}), P.TAG_NAMES) == ['hr']
    assert P.tags(answers([], tags={'unspecified': 0.5}), P.TAG_NAMES) == ['unspecified']
    assert P.tags(answers([], tags={'unspecified': 0.49}), P.TAG_NAMES) == []


def test_groups():                                  # mutant: GROUP mapping changed, or duplicates / unspecified kept
    assert P.groups(['contact', 'customer', 'health']) == ['people', 'health']
    assert P.groups(['credentials', 'technical']) == ['systems']
    assert P.groups(['unspecified']) == ['unspecified']
    assert set(P.GROUP) == set(P.TAG_NAMES) and P.GROUP_LABEL['people'] == 'Customer & personal data'


# ---- boilerplate -------------------------------------------------------------------------------------------
TEMPLATE = 'All your files are with us now.'


def test_boilerplate_needs_five_posts_of_the_same_group():   # mutant: threshold 4, or counted across groups
    rows = [('zg', 'k%d' % i, 'Firm %d makes things. %s' % (i, TEMPLATE)) for i in range(4)]
    rows += [('other', 'o1', TEMPLATE)]
    assert P.norm_sentence(TEMPLATE) not in P.count_boilerplate(rows).get('zg', set())
    rows += [('zg', 'k9', 'Another firm here.  ALL your   files are with us now.')]   # whitespace and case normalised
    assert P.norm_sentence(TEMPLATE) in P.count_boilerplate(rows)['zg']


def test_boilerplate_counts_a_post_once():          # mutant: repeated sentences inside one post counted per occurrence
    rows = [('zg', 'k1', ' '.join([TEMPLATE] * 6))]
    rows += [('zg', 'k1', TEMPLATE)] * 3                # the same claim again
    assert not P.count_boilerplate(rows)['zg']


def test_boilerplate_never_shown_but_still_vetoes():  # mutant: template excluded from the veto, or still displayed
    s = S(CLEAN, 'Zzorb makes garden spades in the town.')
    tmpl = frozenset({s[1]['text']})
    assert P.display(answers(s), s, boilerplate=tmpl) == ['s1']
    A = answers(s, s2=choice('contact_instructions', 0.9))
    assert P.display(A, s, boilerplate=tmpl) == []


def test_boilerplate_collapses_tags():              # mutant: template data statements still give fine tags
    s = S(CLEAN, TEMPLATE)
    A = answers(s, tags={'hr': 0.95, 'health': 0.9}, s2=choice('data_summary', 0.95))
    assert P.profile_tags(A, s, {'s2'}, ['s1', 's2']) == ['unspecified']
    assert P.profile_tags(A, s, set(), ['s1', 's2']) == ['health', 'hr']        # control: no template
    A2 = answers(s, tags={'hr': 0.95}, s1=choice('data_summary', 0.95), s2=choice('data_summary', 0.95))
    assert P.profile_tags(A2, s, {'s2'}, ['s1', 's2']) == ['hr']                  # a non-template data statement keeps them
    A3 = answers(s, s2=choice('data_summary', 0.95))
    assert P.profile_tags(A3, s, {'s2'}, ['s1', 's2']) == []                     # nothing fired: stays empty


# ---- volumes ---------------------------------------------------------------------------------------------------
def cand(text, k=0):
    return P.volume_candidates(S(text))[k]


@pytest.mark.parametrize('text,expect', [
    ('We hold 50GB+ of it', ('bytes', 50_000_000_000, 'over')),
    ('We hold 50+ GB of it', ('bytes', 50_000_000_000, 'over')),
    ('We hold 1,4 TB of it', ('bytes', 1_400_000_000_000, 'exact')),
    ('We hold 1,400 GB of it', ('bytes', 1_400_000_000_000, 'exact')),
    ('We hold 13k files here', ('files', 13_000, 'exact')),
    ('About 3.5 million records here', ('records', 3_500_000, 'about')),
    ('Up to 2 TB was copied', ('bytes', 2_000_000_000_000, 'up_to')),
    ('More than 300 customers named', ('persons', 300, 'over')),
    ('Around 40 documents named', ('files', 40, 'about')),
    ('Some 900 rows here', ('records', 900, 'exact')),
    ('approx. 12 entries here', ('records', 12, 'about')),
])
def test_parse_volume(text, expect):                # mutant: '+' ignored, decimal comma mis-read, multiplier or unit map wrong
    assert P.parse_volume(cand(text)) == expect


def test_zero_is_no_volume():                       # mutant: '0GB' kept as a volume
    assert P.parse_volume(cand('We hold 0GB of it')) is None


def test_plus_flag_in_candidates():                 # mutant: the P1.2 'plus' flag not computed
    assert cand('We hold 50GB+ of it')['plus'] and not cand('We hold 50GB of it')['plus']


def test_volumes_need_jev_and_skip_templates():     # mutant: Jev confirmation ignored; template volumes kept
    s = S('We took 2 TB of files.', 'Zzorb serves 4,000 customers.')
    cands = P.volume_candidates(s)
    A = {'v0': {'noul': 0.9}, 'v1': {'noul': 0.49}}
    out = P.volumes(A, cands)
    assert [(v['unit'], v['value'], v['qualifier']) for v in out] == [('bytes', 2_000_000_000_000, 'exact')]
    assert P.volumes(A, cands, {'s1'}) == []


def test_persons_keep_noun():                       # mutant: the persons noun dropped (RULING D4)
    s = S('Data of 2 million patients taken.')
    out = P.volumes({'v0': {'noul': 0.8}}, P.volume_candidates(s))
    assert out[0]['unit'] == 'persons' and out[0]['noun'] == 'patients' and out[0]['value'] == 2_000_000


# ---- size --------------------------------------------------------------------------------------------------------
def test_size_abstains_below_0_6():                 # mutant: abstention removed or at 0.5
    assert P.size_estimate({'probabilities': {'0': 0, '1': 0, '2': 0.41, '3': 0.59, '4': 0}}) == (None, 0.59)
    assert P.size_estimate({'probabilities': {'0': 0, '1': 0, '2': 0.4, '3': 0.6, '4': 0}}) == ('large', 0.6)


def test_size_tie_goes_to_smaller_band():           # mutant: tie broken upward (over-calls size)
    assert P.size_estimate({'probabilities': {'4': 0.5, '1': 0.5}})[0] is None
    assert P.size_estimate({'probabilities': {'3': 0.0, '2': 0.0, '1': 0.0, '0': 0.0, '4': 1.0}})[0] == 'enterprise'


def test_size_text_drops_headcount_and_revenue():   # mutant: HC / headcount-count filters dropped
    t = 'Zzorb makes spades. It has 120 Employees. Revenue is large. Zzorb sells abroad.'
    assert P.size_profile_text(t) == 'Zzorb makes spades. Zzorb sells abroad.'
    assert P.size_profile_text('Revenue only.') is None
    assert len(P.size_profile_text('Zzorb makes spades. ' * 200)) == 1500


@pytest.mark.skipif(not (REPO / 'supabase/migrations/0145_breach_victim_profiles.sql').exists(), reason='needs the full repository')
def test_size_never_public():                       # mutant: a public view selects the private size estimate or fine tags
    sql = (REPO / 'supabase/migrations/0145_breach_victim_profiles.sql').read_text()
    for view in re.findall(r'create or replace view public\.\w+ as(.*?);', sql, re.S):
        assert 'size' not in view and 'profile_tags' not in view


def test_decide_claim_stores_only_shown_text():     # mutant: hidden sentence text copied out of breach_raw
    s = S(CLEAN, 'We will publish everything soon.')
    ja = {'tags': answers(s, s2=choice('threat_negotiation', 0.95)), 'meta': {'sids': ['s1', 's2'], 'cands': []}, 'size': None}
    d = P.decide_claim({'claim_key': 'k', 'victim_domain': None, 'sentences': s}, ja, set())
    assert [(r['sid'], r['shown'], r['text'] is not None) for r in d['sentences']] == [('s1', True, True), ('s2', False, False)]
    assert d['size_band_est'] is None and d['profile_groups'] == []


# ---- Jev client and budget ---------------------------------------------------------------------------------
KEY = 'zz-test-key-not-real-0123456789'


class FakeTransport:
    def __init__(self, script):
        self.script, self.calls = list(script), []

    def __call__(self, method, url, headers, body, timeout):
        self.calls.append((url, headers, json.loads(body)))
        st, js, hd = self.script.pop(0)
        return st, hd or {}, js


def test_retries_then_succeeds():                   # mutant: no retry on 429 / 5xx
    sleeps = []
    t = FakeTransport([(429, {'error': 'slow'}, {'Retry-After': '1'}), (503, {}, None), (200, {'answers': {}, 'usage': {'input_tokens': 1000}}, None)])
    j = P.Jev(P.Budget(1), key=KEY, transport=t, sleep=sleeps.append)
    assert j.ask({}, {}) == {'answers': {}, 'usage': {'input_tokens': 1000}}
    assert sleeps == [1.0, 2] and len(t.calls) == 3
    assert t.calls[0][1]['Authorization'] == 'Bearer ' + KEY and t.calls[0][2]['model'] == 'jev-1.13.0'


def test_out_of_funds_and_errors_never_carry_the_key_or_body():   # mutant: the exception message echoes the response / key
    t = FakeTransport([(402, {'error': 'no credit for ' + KEY}, None)])
    with pytest.raises(P.OutOfFunds) as e:
        P.Jev(P.Budget(1), key=KEY, transport=t, sleep=lambda s: None).ask({}, {})
    assert KEY not in str(e.value) and 'credit' not in str(e.value)
    t = FakeTransport([(400, {'error': 'bad state: Zzorb secret text'}, None)])
    with pytest.raises(P.JevError) as e:
        P.Jev(P.Budget(1), key=KEY, transport=t, sleep=lambda s: None).ask({}, {})
    assert 'Zzorb' not in str(e.value)


def test_missing_key_fails_clearly(monkeypatch):    # mutant: a missing key sends 'Bearer None'
    monkeypatch.delenv('TYPESAFE_API_KEY', raising=False)
    with pytest.raises(SystemExit, match='TYPESAFE_API_KEY is not set'):
        P.Jev(P.Budget(1))


def test_budget_stops_before_overspend():           # mutant: the guard checks after the call, or never
    b = P.Budget(0.042 * 2 / 1000)                      # two calls of 1,000 input tokens
    t = FakeTransport([(200, {'answers': {}, 'usage': {'input_tokens': 1000}}, None)] * 5)
    j = P.Jev(b, key=KEY, transport=t, sleep=lambda s: None)
    j.ask({}, {})
    j.ask({}, {})
    with pytest.raises(P.BudgetExhausted):
        j.ask({}, {})
    assert len(t.calls) == 2 and abs(b.spent_usd - 0.042 * 2 / 1000) < 1e-12


def test_ask_tags_drops_incomplete_items():         # mutant: a claim written with missing answers
    items = [{'claim_key': 'k1', 'victim_name': 'Zz One', 'actor_group': 'zg', 'sentences': S(CLEAN)},
             {'claim_key': 'k2', 'victim_name': 'Zz Two', 'actor_group': 'zg', 'sentences': S(CLEAN2)}]
    full = {f'v1_t_{t}': {'noul': 0.1} for t in P.TAG_NAMES} | {'v1_c_s1': choice('profile')}
    part = {f'v2_t_{t}': {'noul': 0.1} for t in P.TAG_NAMES}
    t = FakeTransport([(200, {'answers': full | part, 'usage': {'input_tokens': 10}, 'model': 'jev-1.13.0'}, None)])
    out = P.ask_tags(P.Jev(P.Budget(1), key=KEY, transport=t), items)
    assert list(out) == ['k1'] and out['k1']['meta']['sids'] == ['s1']


def test_q_hash_names_the_questions(monkeypatch):   # mutant: q_hash independent of the question wording
    h = P.q_hash()
    assert re.fullmatch(r'[0-9a-f]{16}', h) and h == P.q_hash()
    monkeypatch.setitem(P.TAGS, 'hr', 'something else')
    assert P.q_hash() != h


# =====================================================================================================
# Equivalence with the frozen research files (P1.2). Skips where they are absent (CI, the public mirror).
# =====================================================================================================
# Only where the research files are named explicitly: a default path under /tmp would be world-writable and
# would be put on sys.path.
FROZEN = Path(os.environ.get('ZDC_PROFILE_FROZEN', '/nonexistent'))
FROZEN_CLIENT = Path(os.environ.get('ZDC_PROFILE_FROZEN_CLIENT', '/nonexistent'))
need_frozen = pytest.mark.skipif(not ((FROZEN / 'bin/pjev2.py').exists() and (FROZEN / 'bin/decide2.py').exists()
                                      and (FROZEN_CLIENT / 'jev.py').exists()), reason='frozen research files not present')


@pytest.fixture(scope='module')
def frozen():
    for p in (str(FROZEN_CLIENT), str(FROZEN / 'bin')):
        if p not in sys.path:
            sys.path.insert(0, p)
    import decide2
    import pjev2
    import split
    return pjev2, decide2, split


def _load(rel):
    with open(FROZEN / rel, encoding='utf-8') as fh:
        return json.load(fh)


@need_frozen
def test_frozen_constants_equal(frozen):
    pjev2, decide2, split = frozen
    assert (P.QV, P.MODEL, P.SPLITTER_VERSION) == (pjev2.QV, pjev2.MODEL, split.SPLITTER_VERSION)
    assert P.TAGS == pjev2.TAGS and P.TAG_RULES == pjev2.TAG_RULES and P.CLASSES == pjev2.CLASSES
    assert P.SIZE_LEVELS == pjev2.SIZE_LEVELS and P.VOL_RE.pattern == pjev2.VOL_RE.pattern
    assert [p.pattern for p in P.SCRUB] == [p.pattern for p in decide2.SCRUB]
    for name in ('ATTACK', 'HOST', 'IP', 'KV'):
        assert getattr(P, name).pattern == getattr(decide2, name).pattern
    assert (P.TAU, P.TAU_DEFAULT, P.GROUP, P.GROUP_LABEL, P.SHOW, P.UNIT, P.QUAL) == \
        (decide2.TAU, decide2.TAU_DEFAULT, decide2.GROUP, decide2.GROUP_LABEL, decide2.SHOW, decide2.UNIT, decide2.QUAL)


@need_frozen
def test_equivalence_dev2(frozen):
    """Every decision on the 400 dev2 claims from the stored Jev answers: fine tags, groups, display ids, volume
    candidates, parsed volumes and the questions themselves. Prints counts only."""
    pjev2, decide2, split = frozen
    items = {i['claim_key']: i for f in ('dev', 'holdout') for i in _load(f'gold/{f}_items.json')}
    R = _load('runs_q2_dev2.json')
    diff = dict.fromkeys(['split', 'tags', 'groups', 'display', 'candidates', 'volumes', 'questions'], 0)
    shown = 0
    for k, r in R['results'].items():
        A, it = r['answers'], items[k]
        diff['split'] += P.sentences(it['descr']) != split.sentences(it['descr'])
        ft, pt = decide2.tags(A, list(pjev2.TAGS)), P.tags(A, P.TAG_NAMES)
        diff['tags'] += ft != pt
        diff['groups'] += decide2.groups(ft) != P.groups(pt)
        fd = decide2.display(A, it['sentences'], it.get('victim_domain'))
        diff['display'] += fd != P.display(A, it['sentences'], it.get('victim_domain'))
        shown += len(fd)
        pc = P.volume_candidates(it['sentences'][:12])
        diff['candidates'] += pc != pjev2.volume_candidates(it['sentences'][:12]) or pc != r['meta']['cands']
        diff['volumes'] += [decide2.parse_volume(c) for c in r['meta']['cands']] != [P.parse_volume(c) for c in r['meta']['cands']]
        diff['questions'] += pjev2.tags_build([it]) != P.tags_build([it])
    first = items[next(iter(R['results']))]
    qh = __import__('hashlib').sha256(json.dumps(P.tags_build([first])[1], sort_keys=True).encode()).hexdigest()[:16]
    print(f"\nequivalence dev2: {len(R['results'])} claims, {shown} sentences shown, differences {diff}")
    assert len(R['results']) == 400 and sum(diff.values()) == 0, diff
    assert qh == R['q_hash'] == pjev2.qhash(pjev2.tags_build, [first])


@need_frozen
def test_equivalence_negation2(frozen):
    """The round-2 negation set: fine tags, groups and volumes from the stored answers (no text is read)."""
    pjev2, decide2, _ = frozen
    R = _load('r2/runs_negation2.json')
    diff = {'tags': 0, 'groups': 0, 'volumes': 0}
    for r in R['results'].values():
        ft, pt = decide2.tags(r['answers'], list(pjev2.TAGS)), P.tags(r['answers'], P.TAG_NAMES)
        diff['tags'] += ft != pt
        diff['groups'] += decide2.groups(ft) != P.groups(pt)
        diff['volumes'] += [decide2.parse_volume(c) for c in r['meta']['cands']] != [P.parse_volume(c) for c in r['meta']['cands']]
    print(f"\nequivalence negation2: {len(R['results'])} items, differences {diff}")
    assert len(R['results']) == 30 and sum(diff.values()) == 0, diff


@need_frozen
def test_equivalence_size_evidence(frozen):
    """The sealed size set: the headcount-free evidence text and the size questions are rebuilt exactly."""
    pjev2, _, _ = frozen
    raw = {r['victim_id']: r for r in _load('size/raw.json')}
    items = _load('size/size_items.json')
    diff = sum((P.size_profile_text(raw[i['size_key']]['descr']) or None) != (i['profile_text'] or None) for i in items)
    diff += sum(P.size_build([i]) != pjev2.size_build([i]) for i in items)
    print(f'\nequivalence size: {len(items)} items, differences {diff}')
    assert len(items) == 175 and diff == 0
    assert pjev2.qhash(P.size_build, items[:1]) == '9794e87ae35a1cc2'


def test_language_guard_english_only():                 # mutant: likely_english always True
    assert P.likely_english('The company provides logistics services to retailers across the region.')
    assert P.likely_english('Insurance')
    assert not P.likely_english('Das Unternehmen bietet Logistikdienstleistungen für Händler in der ganzen Region an.')
    assert not P.likely_english('Компания предоставляет логистические услуги розничным продавцам.')
