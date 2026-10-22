"""Unit tests: breach-names-v1 (zdc_breach.names). Synthetic names and text only; Jev is a fake transport, no network.

Each test names the rule it guards; the mutation check (a rule removed or changed) makes at least one of them fail.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from zdc_breach import names as N
from zdc_breach import profile as P

KEY = 'zz-test-key-not-real'
NO_ACTORS = frozenset()


def C(*names, src='span_title'):
    return [{'name': n, 'domain': None, 'src': [src]} for n in names]


def A(*ps):
    return {'c%d' % (i + 1): {'type': 'noul', 'noul': p} for i, p in enumerate(ps)}


# ---- gate ----------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize('name', [
    'THE ENDGAME OF ZZQUORVEX MOTORS’ PSYCHOLOGICAL GAME', 'They Failed. 100GB Drops in 2 Days', 'leak #1 zzquorvexmotors',
    'Zzbolt - Database Leaked', 'zzsteel.com\\$570.3M\\USA\\679GB\\100% DISCLOSED', 'Zzmotel One FULL LEAK!', 'Zzvidisco Hacked'])
def test_gate_resolves_titles_with_leak_vocabulary(name):
    assert N.resolvable(name)


@pytest.mark.parametrize('name', [
    'Comision Municipal de Agua Potable y Alcantarillado de Zzvictoria',   # long, many words: a name
    'ZZ SUMMIT VETERINARY PHARMACEUTICALS LIMITED',                       # all capitals: a name
    'Zzgreenberg & Stein New York City Personal Injury Lawyers',          # descriptor, no leak word
    'Zzplain Tools', 'zzplain.com', '', None])
def test_gate_leaves_names_alone(name):
    assert not N.resolvable(name)


# ---- stripping and candidates --------------------------------------------------------------------------------------------
@pytest.mark.parametrize('title,stripped', [
    ('Zionists Zzsonol Hacked ( Gas Stations )', 'Zzsonol'),                 # hacktivist prefix + decorated suffix
    ('Zzsafi Oil Company (PURE IN) Hacked', 'Zzsafi Oil Company (PURE IN)'),
    ('Zzrumaila Operating Organisation Compromised', 'Zzrumaila Operating Organisation'),
    ('zzsteel.com\\$570.3M\\USA\\679GB\\100% DISCLOSED', 'zzsteel.com'),
    ('[DISCLOSED] Zzdiaz Medicina Laboratorial S.A.', 'Zzdiaz Medicina Laboratorial S.A.'),
    ('Zzcantalk, Canadian translation services - Leak', 'Zzcantalk, Canadian translation services'),
])
def test_strip_title(title, stripped):
    assert N.strip_title(title) == stripped


def test_strip_title_balances_brackets():
    assert N.strip_title('Zzsafi Oil Company (PURE IN Hacked') == 'Zzsafi Oil Company'


def test_balance_drops_an_unclosed_bracket():
    assert N.balance('Zzsafi Oil Company (PURE IN') == 'Zzsafi Oil Company'
    assert N.balance('Zzsafi) Oil') == 'Zzsafi Oil'


def test_candidates_find_the_company_in_title_description_and_siblings():
    post = {'title': 'THE ENDGAME OF ZZQUORVEX MOTORS’ PSYCHOLOGICAL GAME',
            'desc': 'Despite giving the Zzquorvex Motors company more than enough time, they failed. See zzquorvexmotors.com.',
            'actor': 'zzgang', 'domain': None, 'website': None}
    cands = N.candidates(post, N.Gazetteer([]), [('Zzquorvexmotors', None)])
    names = [c['name'] for c in cands]
    assert 'Zzquorvex Motors' in names                                    # span in the description, merged with sibling/host
    assert len(names) == len({N.core_squash(n) for n in names})           # merged on the squashed form
    assert all(not N.HOST.fullmatch(n) or n.islower() for n in names)
    zz = next(c for c in cands if c['name'] == 'Zzquorvex Motors')
    assert 'sibling' in zz['src'] and zz['domain'] == 'zzquorvexmotors.com'


def test_candidates_never_offer_the_actor_or_file_hosts():
    post = {'title': 'Zzgang leaks Zzacme Corp', 'desc': 'Download at https://gofile.io/d/x or zzgang.com/leaks', 'actor': 'zzgang',
            'domain': None, 'website': None}
    names = [c['name'] for c in N.candidates(post, N.Gazetteer([]))]
    assert not any('gofile' in n or N.core_squash(n) == 'zzgang' for n in names)


def test_gazetteer_uses_multi_word_names_only():
    g = N.Gazetteer([('Zzacme Holdings', 'zzacme.com'), ('Zzsingle', None)])
    assert g.find('a post about Zzacme Holdings and Zzsingle') == [('Zzacme Holdings', 'zzacme.com')]


def test_at_most_ten_candidates():
    post = {'title': 'Zzone Two Hacked', 'desc': ' '.join(f'Zzname{i} Corp went here.' for i in range(30)), 'actor': 'g'}
    assert len(N.candidates(post, N.Gazetteer([]))) == N.MAX_CANDS


# ---- decision ------------------------------------------------------------------------------------------------------------
def test_one_company_renames():
    assert N.decide(C('Zzacme Motors', 'Zzland'), A(0.9, 0.1)) == ('Zzacme Motors', 'renamed', 0.9)


def test_below_the_bar_abstains():
    assert N.decide(C('Zzacme Motors'), A(0.59))[1] == 'abstain_none'
    assert N.decide([], None)[1] == 'no_candidates'


def test_two_companies_abstain():
    assert N.decide(C('Zzacme Motors', 'Zzbeta Foods'), A(0.9, 0.8))[1] == 'abstain_several'


def test_spellings_of_one_company_rename():
    assert N.decide(C('ZZACME MOTORS', 'Zzacme Motors'), A(0.9, 0.8))[1] == 'renamed'


def test_an_actor_group_is_never_the_victim():
    assert N.decide(C('Zzrival'), A(0.95), frozenset({'zzrival'}))[1] == 'abstain_none'
    assert N.decide(C('Zzrival2'), A(0.95), frozenset({'zzrival'}))[1] == 'abstain_none'   # a numbered successor too


def test_joined_candidate_naming_several_companies_abstains():
    cands = C('Zzchange Health', 'Zzchange Health - Zzoptum Group - Zzunited Care')
    assert N.decide(cands, A(0.86, 0.74))[1] == 'abstain_several'


def test_a_string_bridging_two_companies_abstains():
    # 'Zzamos Spacecom' links 'Zzspacecom' and 'Zzspace Communication'? No: every two members must be one company directly
    cands = C('Zzalpha Tools Zzbeta Foods', src='strip') + C('Zzalpha Tools', 'Zzbeta Foods')
    assert N.decide(cands, A(0.9, 0.9, 0.9))[1] == 'abstain_several'


def test_host_and_name_pair_only_when_clearly_the_same_company():
    assert N.decide(C('zzaleph-farms.com', 'Zzaleph Farms'), A(0.9, 0.8))[:2] == ('Zzaleph Farms', 'renamed')
    assert N.decide(C('zzsasa.com', 'Zzhengzhou Commerce'), A(0.9, 0.8))[1] == 'abstain_several'
    assert N.decide(C('zbc.com', 'Zzalpha Bravo Charlie'), A(0.9, 0.8))[:2] == ('Zzalpha Bravo Charlie', 'renamed')   # initials


def test_a_confirmed_name_before_a_comma_wins():
    cands = C('Zzcantalk, Canadian translation services', src='strip') + C('Zzcantalk')
    assert N.decide(cands, A(0.92, 0.68))[0] == 'Zzcantalk'


def test_a_decorated_pick_abstains():
    assert N.decide(C('Zzimt Press Release'), A(0.9))[1] == 'abstain_decorated'


def test_the_stripped_title_beats_a_shorter_span_inside_it():
    cands = C('Zzdiablo Valley Oncology and Hematology Medical Group', src='strip') + C('Zzdiablo Valley Oncology')
    assert N.decide(cands, A(0.73, 0.74))[0] == 'Zzdiablo Valley Oncology and Hematology Medical Group'


# ---- one spelling per actor group and company -----------------------------------------------------------------------------
def test_canonical_swaps_to_the_spelling_most_posts_confirmed():
    conf = [('Zzlucent Motors', 'a'), ('Zzlucent Motors', 'b'), ('ZZLUCENT', 'c'), ('Zzlucentmotors', 'd')]
    assert N.canonical('ZZLUCENT', conf) == 'Zzlucent Motors'               # a longer confirmed name starting with it
    assert N.canonical('Zzlucentmotors', conf) == 'Zzlucent Motors'         # same letters


def test_canonical_never_shortens_nor_invents():
    assert N.canonical('Zzprestige Maintenance USA', [('USA', 'x'), ('Zzprestige Maintenance USA', 'y')]) == 'Zzprestige Maintenance USA'
    assert N.canonical('zzfrank.com', [('zzfrank.com', 'x')]) == 'zzfrank.com'
    assert N.canonical('Zzlucent Motors', [('Zzlucent', k) for k in 'abc'] + [('Zzlucent Motors', 'd')]) == 'Zzlucent Motors'
    # a decorated spelling is never used, however many posts carry it
    conf = [('Zzjaquith Press Release', k) for k in 'abc'] + [('Zzjaquith', 'd')]
    assert N.canonical('Zzjaquith', conf) == 'Zzjaquith'


# ---- group key and grouping -----------------------------------------------------------------------------------------------
def test_group_key():
    assert N.group_key('Zz Motors, Inc.') == N.group_key('zzmotors.com') == N.group_key('www.zzmotors.co.uk') == 'zzmotors'
    assert N.group_key('Zz Mötörs') == 'zzmotors'
    assert N.group_key('Zz Motors Group') != 'zzmotors'


def _row(vid, actor, name, day, resolved):
    return {'victim_id': vid, 'actor': actor, 'name': name, 'resolved': resolved,
            'seen': datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(days=day)}


def test_plan_groups_windows_actors_and_resolution():
    rows = [_row('a3', 'g1', 'Zzquorvexmotors', 0, False), _row('a1', 'g1', 'Zzquorvex Motors', 45, True),
            _row('a2', 'g1', 'Zzquorvex Motors', 64, True), _row('a4', 'g1', 'Zzquorvex Motors', 160, True),
            _row('b1', 'g2', 'Zzquorvex Motors', 46, True), _row('c1', 'g1', 'Zzplain Tools', 10, False),
            _row('c2', 'g1', 'Zzplain Tools', 12, False)]
    assert N.plan_groups(rows) == [['a3', 'a1', 'a2']]
    assert N.plan_groups(rows, window_days=200) == [['a3', 'a1', 'a2', 'a4']]


# ---- Jev questions -------------------------------------------------------------------------------------------------------
def test_one_question_per_candidate():
    items = [{'claim_key': 'k1', 'title': 'T', 'desc': 'D', 'actor': 'g', 'cands': C('Zza', 'Zzb')},
             {'claim_key': 'k2', 'title': 'T2', 'desc': '', 'actor': 'g', 'cands': C('Zzc')}]
    st, qs, meta = N.build(items)
    assert sorted(qs) == ['p1_c1', 'p1_c2', 'p2_c1']
    assert all(q['type'] == 'noul' for q in qs.values())
    assert st['posts']['p1']['candidates'] == {'c1': 'Zza', 'c2': 'Zzb'} and meta == {'p1': 'k1', 'p2': 'k2'}


# ---- the command, with a fake database reader and a fake Jev ---------------------------------------------------------------
LISTED = [('zzk|endgame', 'THE ENDGAME OF ZZQUORVEX MOTORS’ PSYCHOLOGICAL GAME', 'zzgang', None, datetime(2026, 3, 1, tzinfo=timezone.utc)),
          ('zzk|failed', 'They Failed. 100GB Drops in 2 Days', 'zzgang', None, datetime(2026, 3, 20, tzinfo=timezone.utc)),
          ('zzk|plain', 'Zzquorvexmotors', 'zzgang', None, datetime(2026, 1, 15, tzinfo=timezone.utc)),
          ('zzk|notice', 'Zzgang Alert: we have new rules', 'zzgang', None, datetime(2026, 3, 2, tzinfo=timezone.utc))]
TEXTS = {'zzk|endgame': ['The Zzquorvex Motors board stays silent.'], 'zzk|failed': ['Zzquorvex Motors failed to respond.'],
         'zzk|notice': ['Rules for affiliates.']}


def fake_q(sql, params=None):
    if sql is N.LISTED_SQL:
        return LISTED
    if sql is N.TEXT_SQL:
        return [(k, TEXTS.get(k), None) for k in params['keys']]
    if sql is N.ORGS_SQL:
        return []
    if sql is N.ACTORS_SQL:
        return [('zzgang',)]
    if sql is N.DONE_SQL:
        return []
    raise AssertionError('unexpected query')


def fake_transport(calls):
    def t(method, url, headers, body, timeout):
        req = json.loads(body)
        calls.append(req)
        A_ = {}
        for qid in req['questions']:
            pid, c = qid.split('_')
            name = req['state']['posts'][pid]['candidates'][c]
            A_[qid] = {'type': 'noul', 'noul': 0.95 if 'Zzquorvex' in name else 0.05}
        return 200, {}, {'answers': A_, 'model': 'jev-1.13.0', 'usage': {'input_tokens': 500, 'output_tokens': 5}}
    return t


def test_dry_run_plans_without_writing_and_reports_counts_only(tmp_path):
    calls = []
    budget = P.Budget(1)
    jev = P.Jev(budget, key=KEY, transport=fake_transport(calls), sleep=lambda s: None)
    plan = tmp_path / 'plan.json'
    rep = N.cmd_resolve(fake_q, None, mode='backfill', limit=100, deadline_min=5, max_usd=1, dry_run=True, plan=str(plan), jev=jev, budget=budget)
    assert rep['resolvable'] == 3 and rep['selected'] == 3                 # the plain name is not resolved
    assert rep['reasons'] == {'abstain_none': 1, 'renamed': 2}
    assert rep['groups_planned'] == 1 and rep['posts_in_groups'] == 3       # the plain post joins the confirmed ones
    assert rep['written'] == 0
    text = json.dumps(rep, default=str)
    assert 'Zzquorvex' not in text and 'ENDGAME' not in text and 'zzk|' not in text   # counts only
    p = json.loads(plan.read_text())
    assert {d['resolved_name'] for d in p['decisions'] if d['reason'] == 'renamed'} == {'Zzquorvex Motors'}
    assert [x['victim_id'] for x in p['groups'][0]] == ['claim:zzk|plain', 'claim:zzk|endgame', 'claim:zzk|failed']


def test_budget_stops_the_run(tmp_path):
    calls = []
    budget = P.Budget(0.0)
    jev = P.Jev(budget, key=KEY, transport=fake_transport(calls), sleep=lambda s: None)
    rep = N.cmd_resolve(fake_q, None, mode='backfill', limit=100, deadline_min=5, max_usd=0, dry_run=True, jev=jev, budget=budget)
    assert rep['stopped'] == 'budget' and not calls and rep['reasons'] == {}
