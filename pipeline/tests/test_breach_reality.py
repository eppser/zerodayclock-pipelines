"""Unit tests for breach-reality-v1 (zdc_breach.reality, zdc_breach.reality_harvest).

Synthetic fixtures only: every name below is invented (Quorvex, Zentrix, ...) or a stock placeholder;
no leak-site victim name appears here. Each test names the mutant it kills - the code change that
would leave the suite green if the test were missing.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from zdc_breach import reality as R
from zdc_breach import reality_harvest as H

LEX = R.Lexicon({'zentrix': 50, 'alpha': 50, 'quorvex': 1, 'dynamics': 3, 'lastword': 1}, frozenset({'lockbit', 'akira', 'blackcat'}))


def cand(host, sources, title='', live=True, og=None):
    return {'host': host, 'sources': list(sources), 'live': live, 'dns': True, 'status': 200, 'title': title, 'og_site_name': og}


def ev(cands=(), wd=(), extras=None, leakmeta=None, corrob=()):
    return {'pool': {'candidates': list(cands), 'wikidata': list(wd)}, 'extras': extras or {}, 'leakmeta': leakmeta, 'corrob': list(corrob)}


def item(name, domain=None, country=None, actor='zzgroup'):
    return {'claim_key': 'k|' + name, 'name_raw': name, 'actor': actor, 'domain': domain, 'country': country}


def run(name, pack=None, **kw):
    it = item(name, **kw)
    return R.check(it, pack or ev(), LEX)


# ---- A1 name rules ---------------------------------------------------------------------------------
def test_placeholder_is_not_org():                      # mutant: PLACEHOLDER regex removed
    d = run('Company #12')
    assert (d['label'], d['subtype'], d['via']) == ('not_org', 'placeholder', 'A1')


def test_announcement_beats_mask():                     # mutant: mask test before ANNOUNCE
    assert R.name_rule('WHO IS NEXT??') == ('not_org', 'placeholder')


def test_masked_name_is_redacted():                     # mutant: masked -> ambiguous
    d = run('Quorvex ***')
    assert (d['label'], d['via']) == ('redacted_unresolved', 'mask')


def test_actor_infrastructure_own_group():              # mutant: actor_infra dropped from name_rule_v21
    assert R.name_rule_v21('lockbit4.com', 'lockbit3', LEX.actor_norms) == ('not_org', 'actor_infrastructure')
    assert run('lockbit4.com', actor='lockbit3')['subtype'] == 'actor_infrastructure'


def test_actor_infrastructure_other_group_needs_decoration():   # mutant: undecorated alias treated as infra
    assert R.name_rule_v21('akiraleaks.net', 'zzgroup', LEX.actor_norms) == ('not_org', 'actor_infrastructure')
    assert R.name_rule_v21('akira.com', 'zzgroup', LEX.actor_norms) is None


def test_reserved_domain_is_placeholder_but_local_is_not():     # mutant: .local added / reserved list removed
    assert R.name_rule_v21('test.com') == ('not_org', 'placeholder')
    assert R.name_rule_v21('shop.example') == ('not_org', 'placeholder')
    assert R.name_rule_v21('QUORVEX.LOCAL') is None


def test_lexicon_never_fires_on_domain_names():         # mutant: TEST/PLACEHOLDER checked before domain_shaped
    assert R.name_rule('test.quorvex.com') is None


# ---- F6-3: hidden words, mask characters, gibberish -------------------------------------------------
def test_f6_hidden_word_is_redacted():                  # mutant: HIDDEN check removed from f6_rule
    d = run('Confidential')
    assert (d['label'], d['via']) == ('redacted_unresolved', 'mask')


def test_f6_gibberish_with_mask_char_is_redacted():     # mutant: MASKCH branch removed
    d = run('a?')
    assert (d['label'], d['via']) == ('redacted_unresolved', 'mask')


def test_f6_gibberish_abstains_never_not_org():         # mutant: f6_rule bypassed (gibberish -> not_org)
    d = run('zzz')
    assert (d['label'], d['subtype'], d['via']) == ('ambiguous', 'gibberish_abstain', 'F6')


# ---- E1: a live site naming the entity -------------------------------------------------------------
def test_tracker_domain_naming_title_is_real_with_domain():     # mutant: TR sources not allowed
    d = run('Quorvex Dynamics', ev([cand('quorvex.example.org', ['tracker_domain'], 'Quorvex Dynamics - Home')]))
    assert (d['label'], d['via'], d['domain_candidate']) == ('real_org', 'E1', 'quorvex.example.org')


def test_title_must_name_every_token():                 # mutant: site_match threshold lowered below 1.0
    d = run('Quorvex Dynamics', ev([cand('qd.com', ['slug_guess'], 'Quorvex')]))
    assert d['label'] == 'ambiguous'


def test_tracker_live_partial_title_counts():           # mutant: tracker_live_real fallback removed
    d = run('Quorvex Dynamics', ev([cand('qd-site.com', ['tracker_domain'], 'Quorvex portal')]))
    assert (d['label'], d['domain_candidate']) == ('real_org', 'qd-site.com')


def test_tracker_live_needs_some_naming_text():         # mutant: v21 guard dropped (host match alone)
    d = run('Quorvex Dynamics', ev([cand('quorvexdynamics.com', ['tracker_domain'], 'Welcome')]))
    assert (d['label'], d['subtype']) == ('ambiguous', 'no_evidence')


def test_marketplace_host_is_skipped():                 # mutant: MARKET filter removed
    d = run('Quorvex Dynamics', ev([cand('quorvexdynamics.com', ['tracker_domain'], 'Quorvex Dynamics | buy this domain')]))
    assert d['label'] == 'ambiguous'


def test_certificate_O_names_entity():                  # mutant: certO dropped from textual evidence
    pack = ev([cand('qdx.com', ['tracker_domain'], 'Home')], extras={'tls': {'qdx.com': {'O': 'Quorvex Dynamics LLC'}}})
    assert run('Quorvex Dynamics', pack)['label'] == 'real_org'


def test_about_page_names_entity():                     # mutant: pages ignored
    pack = ev([cand('qdx.com', ['tracker_domain'], 'Home')],
              extras={'pages_host': 'qdx.com', 'pages': [{'status': 200, 'title': 'About', 'h1': 'Quorvex Dynamics'}]})
    assert run('Quorvex Dynamics', pack)['label'] == 'real_org'


def test_short_name_guessed_host_never_decides():       # mutant: short_name guard removed
    d = run('QVX', ev([cand('qvx.com', ['slug_guess'], 'QVX')]))
    assert d['label'] == 'ambiguous'


def test_domain_name_judged_on_own_host_only():         # mutant: v21 domain-shaped guard removed
    d = run('quorvex.com', ev([cand('quorvex.net', ['slug_guess'], 'Quorvex')]))
    assert d['label'] == 'ambiguous'
    d = run('quorvex.com', ev([cand('quorvex.com', ['name_is_domain'], 'Quorvex')]))
    assert (d['label'], d['domain_candidate']) == ('real_org', 'quorvex.com')


def test_leak_post_domain_allows_host():                # mutant: A2 leakmeta override removed
    pack = ev([cand('qvx.com', ['slug_guess'], 'QVX')], leakmeta={'desc_domains': ['qvx.com'], 'rf_website': None})
    d = run('QVX', pack)
    assert (d['label'], d['domain_candidate']) == ('real_org', 'qvx.com') and 'A2' in d['used']


# ---- identity guard (all_slug, p856 guard) ---------------------------------------------------------
def test_slug_only_host_keeps_label_drops_domain():     # mutant: identity guard removed
    d = run('Quorvex Dynamics Ltd', ev([cand('quorvexdynamics.com', ['slug_guess'], 'Quorvex Dynamics')]))
    assert (d['label'], d['domain_candidate']) == ('real_org', None)


def test_slug_host_with_country_cctld_keeps_domain():   # mutant: second_signal country branch removed
    d = run('Quorvex Dynamics Ltd', ev([cand('quorvexdynamics.de', ['slug_guess'], 'Quorvex Dynamics')]), country='DE')
    assert (d['domain_candidate'], 'country' in d['used']) == ('quorvexdynamics.de', True)


def test_p856_host_cannot_vouch_for_itself():           # mutant: p856_guard off (exclude_p856 False)
    wd = [{'qid': 'Q1', 'label': 'Quorvex Dynamics Ltd', 'description': 'company', 'p856': ['quorvexdynamics.com']}]
    d = run('Quorvex Dynamics Ltd', ev([cand('quorvexdynamics.com', ['wikidata_p856:Q1'], 'Quorvex Dynamics')], wd=wd))
    assert (d['label'], d['domain_candidate']) == ('real_org', None)


def test_institution_name_needs_country_or_registry():  # mutant: inst_guard removed
    pack = ev([cand('stquorvex.org', ['tracker_domain'], 'St Quorvex School')])
    assert run('St Quorvex School', pack)['domain_candidate'] is None
    pack_de = ev([cand('stquorvex.de', ['tracker_domain'], 'St Quorvex School')])
    assert run('St Quorvex School', pack_de, country='DE')['domain_candidate'] == 'stquorvex.de'


# ---- F6-1: several sites carry the name ------------------------------------------------------------
def two_sites(title_a, title_b):
    return ev([cand('quorvexdynamics.com', ['slug_guess'], title_a), cand('quorvex-dynamics.net', ['slug_guess'], title_b)])


def test_multi_host_distinctive_name_is_real_without_domain():  # mutant: multi_real off
    d = run('Quorvex Dynamics Ltd', two_sites('Quorvex Dynamics Inc', 'Quorvex Dynamics GmbH Berlin'))
    assert (d['label'], d['via'], d['domain_candidate']) == ('real_org', 'multi_host_real', None)


def test_f6_multi_host_never_for_a_person():            # mutant: person_like dropped from f6_block
    d = run('John Carter', two_sites('John Carter Studio', 'John Carter Photography'))
    assert (d['label'], d['natural_person_risk']) == ('ambiguous', True)      # the F6-4b person guard now stops it first


def test_f6_multi_host_never_for_a_weak_name():         # mutant: weak_name AND distinctive dropped from f6_block
    # (weak_name alone is an equivalent mutant there: names reaching E1 that are weak are also undistinctive,
    # because ANNOUNCE/PLACEHOLDER/TEST names are decided by A1 first)
    d = run('North Construction', two_sites('North Construction', 'North Construction Ltd Leeds'))
    assert (d['label'], d['via']) == ('ambiguous', 'multi_host')


def test_f6_multi_host_needs_a_distinctive_token():     # mutant: distinctive dropped from f6_block
    d = run('Zentrix Alpha Inc', two_sites('Zentrix Alpha Inc', 'Zentrix Alpha Inc USA'))
    assert (d['label'], d['via']) == ('ambiguous', 'multi_host')


def test_multi_host_never_for_truncated_name():         # mutant: trunc_guard removed
    d = run('Quorvex Dynamics Ltd (Europe', two_sites('Quorvex Dynamics Inc', 'Quorvex Dynamics GmbH'))
    assert (d['label'], d['via']) == ('ambiguous', 'multi_host')


def test_truncated_long_name_rare_last_token():         # mutant: TOKEN_DF_DISTINCT ignored in truncated()
    assert R.truncated('Quorvex Dynamics Industrial Holdings Lastword', LEX)
    assert not R.truncated('Quorvex Dynamics Industrial Holdings Alpha', LEX)


def test_tracker_host_wins_over_guessed_hosts():        # mutant: pri (tracker/P856) narrowing removed
    pack = ev([cand('quorvexdynamics.com', ['slug_guess'], 'Quorvex Dynamics Ltd'), cand('qd-site.com', ['tracker_domain'], 'Quorvex Dynamics')])
    d = run('Quorvex Dynamics', pack)
    assert (d['label'], d['domain_candidate']) == ('real_org', 'qd-site.com')


# ---- E2 / E3 ---------------------------------------------------------------------------------------
def test_registry_match_is_real_without_domain():       # mutant: registry_real off
    wd = [{'qid': 'Q1', 'label': 'Quorvex Dynamics Ltd', 'description': 'engineering company'}]
    d = run('Quorvex Dynamics Ltd', ev(wd=wd))
    assert (d['label'], d['via'], d['domain_candidate']) == ('real_org', 'E2', None)


def test_f6_wikidata_person_hit_is_not_registry_evidence():     # mutant: wd_is_person filter removed
    wd = [{'qid': 'Q1', 'label': 'Quorvex Dynamics', 'description': 'American politician (born 1950)'}]
    assert run('Quorvex Dynamics', ev(wd=wd))['label'] == 'ambiguous'


def test_f6_person_like_name_ignores_wikidata():        # mutant: person_like dropped from wd_ok
    wd = [{'qid': 'Q1', 'label': 'John Carter', 'description': 'company'}]
    d = run('John Carter', ev(wd=wd))
    assert (d['label'], d['natural_person_risk']) == ('ambiguous', True)


def test_gleif_match_but_weak_name_is_refused():        # mutant: weak_guard removed
    d = run('North Construction', ev(extras={'gleif': [{'name': 'North Construction'}]}))
    assert d['label'] == 'ambiguous'
    assert run('Quorvex Dynamics Ltd', ev(extras={'gleif': [{'name': 'QUORVEX DYNAMICS LTD'}]}))['via'] == 'E2'


def test_edgar_entity_parenthesis_ignored():            # mutant: EDGAR "(CIK ...)" not stripped
    assert run('Quorvex Dynamics Ltd', ev(extras={'edgar': [{'entity': 'Quorvex Dynamics Ltd (QVDX)'}]}))['via'] == 'E2'


def test_corroboration_needs_independent_flag():        # mutant: corrob filter on other_sources/regulator removed
    c = {'display_name': 'Quorvex Dynamics', 'domain': None, 'other_sources': None, 'regulator_filed': False, 'victim_confirmed': False}
    assert run('Quorvex Dynamics', ev(corrob=[c]))['label'] == 'ambiguous'
    d = run('Quorvex Dynamics', ev(corrob=[dict(c, regulator_filed=True)]))
    assert (d['label'], d['via']) == ('real_org', 'E3')


def test_person_with_no_evidence_flagged_never_not_org():       # mutant: person_rule on
    for n in ('John Carter', 'Maria Kowalska', 'Ivan Petrovich Sidorov', 'Quorvex Family'):
        d = run(n)
        assert (d['label'], d['natural_person_risk']) == ('ambiguous', True), n


def test_eponymous_firm_with_naming_site_can_be_real():  # mutant: person_like blocks E1 outright
    d = run('John Carter Law Office', ev([cand('johncarterlaw.com', ['slug_guess'], 'John Carter Law Office | Attorneys')]))
    assert d['label'] == 'real_org'


# ---- lexicon, packs ---------------------------------------------------------------------------------
def test_lexicon_counts_distinct_names_and_normalises_groups():   # mutant: per-claim counts / raw group names
    lex = R.build_lexicon(['quorvex dynamics', 'quorvex dynamics', 'quorvex labs', 'zentrix inc'], ['lockbit'], ['Black Cat!', None])
    assert lex.token_df_distinct['quorvex'] == 2 and 'inc' not in lex.token_df_distinct
    assert lex.actor_norms == frozenset({'lockbit', 'blackcat'})
    assert lex.sha256() == R.build_lexicon(['zentrix inc', 'quorvex labs', 'quorvex dynamics'], ['lockbit'], ['Black Cat!']).sha256()


def test_pack_is_claim_independent_and_jsonb_safe():    # mutant: claim_key kept in pack / NUL not scrubbed
    a = R.make_pack({'claim_key': 'a', 'name': 'Q\x00', 'candidates': [], 'wikidata': []}, {'claim_key': 'a'}, {'claim_key': 'a', 'desc_domains': []},
                    [{'claim_key': 'a', 'display_name': 'B'}, {'claim_key': 'a', 'display_name': 'A'}])
    b = R.make_pack({'claim_key': 'b', 'name': 'Q', 'candidates': [], 'wikidata': []}, {'claim_key': 'b'}, {'claim_key': 'b', 'desc_domains': []},
                    [{'claim_key': 'b', 'display_name': 'A'}, {'claim_key': 'b', 'display_name': 'B'}])
    assert R.pack_sha256(a) == R.pack_sha256(b)
    assert '\x00' not in json.dumps(a) and 'claim_key' not in json.dumps(a)


def test_leakmeta_sql_returns_domains_not_text():       # mutant: description column selected out of SQL
    sel = R.LEAKMETA_SQL.split('select claim_key,', 1)[1]
    assert "record->>'description'" not in sel.replace("coalesce(s2.record->>'description','')", '').replace(
        "coalesce(record->>'description','') <> ''", '')


# ---- harvester politeness ---------------------------------------------------------------------------
@pytest.fixture
def no_network(monkeypatch):
    calls = []
    monkeypatch.setattr(H, '_dns_a', lambda *a, **k: calls.append(('dns', a)))
    monkeypatch.setattr(H, 'fetch_home', lambda h: calls.append(('http', h)) or {'host': h})
    monkeypatch.setattr(H, 'wd_get', lambda p: calls.append(('wd', p)) or None)
    monkeypatch.setattr(H, 'jget', lambda *a, **k: calls.append(('api', a)) or None)
    monkeypatch.setattr(H, 'tls_subject', lambda h: calls.append(('tls', h)) or {})
    monkeypatch.setattr(H, 'page', lambda u: calls.append(('page', u)) or {})
    return calls


def test_actor_infrastructure_and_reserved_names_send_no_request(no_network):   # mutant: fetch before the v2.1 rule
    for name, actor in (('lockbit4.com', 'lockbit3'), ('test.com', 'x'), ('printer.localhost', 'x')):
        pool, extras, _ = H.harvest(item(name, actor=actor), LEX.actor_norms)
        assert pool['candidates'] == [] and 'never fetched' in pool['skipped']
        assert set(extras) == {'claim_key'}
    assert no_network == []


def test_onion_and_reserved_candidate_hosts_never_resolved(no_network, monkeypatch):   # mutant: host guards removed
    seen = []
    monkeypatch.setattr(H, 'resolves', lambda h: seen.append(h) or False)
    monkeypatch.setattr(H, 'guesses', lambda n, c: [])
    H.harvest_pool({'claim_key': 'k', 'name': 'Quorvex', 'domain': 'quorvexabc.onion', 'country': None, 'actor': 'x'}, set())
    H.harvest_pool({'claim_key': 'k', 'name': 'Quorvex', 'domain': 'example.com', 'country': None, 'actor': 'x'}, set())
    assert seen == []


def test_identity_strings():                            # mutant: personal contact / unnamed crawler
    assert H.UA_SEC.endswith('contact@zerodayclock.com')
    assert 'zerodayclock.com' in H.UA_WEB and 'zerodayclock.com' in H.UA_API


def test_no_common_crawl_or_certificate_logs():         # mutant: CC or crt.sh pass re-added
    src = Path(H.__file__).read_text() + Path(R.__file__).read_text()
    code = [ln for ln in src.splitlines() if not ln.lstrip().startswith(('#', 'not used'))]
    joined = '\n'.join(code).lower()
    for needle in ('index.commoncrawl.org', 'crt.sh/', 'cc_lookup'):
        assert needle not in joined


def test_rate_limiter_spaces_calls():                   # mutant: Rate.wait never sleeps
    r = H.Rate(50)
    t0 = time.time()
    for _ in range(6):
        r.wait()
    assert time.time() - t0 >= 0.09
    assert H.WD.dt >= 0.5 and H.GL.dt >= 0.5 and H.ED.dt >= 0.5


def test_redirect_to_rejected_host_does_not_crash(no_network, monkeypatch):   # mutant: unguarded cands[rh]
    monkeypatch.setattr(H, 'resolves', lambda h: True)
    monkeypatch.setattr(H, 'guesses', lambda n, c: [])
    monkeypatch.setattr(H, 'fetch_home', lambda h: {'host': h, 'status': 200, 'title': 'x', 'parked': False, 'redirect_host': 'abc.onion'})
    pool = H.harvest_pool({'claim_key': 'k', 'name': 'Quorvex', 'domain': 'quorvex-site.com', 'country': None, 'actor': 'x'}, set())
    assert [c['host'] for c in pool['candidates']] == ['quorvex-site.com']


def test_report_is_counts_only():                       # mutant: names or keys in the public report
    rep = R._finish(R._new_report('decide'), time.time())
    def leaves(x):
        if isinstance(x, dict):
            for k, v in x.items():
                yield k
                yield from leaves(v)
        else:
            yield x
    assert all(isinstance(v, (int, float, str, bool)) for v in leaves(rep))
    assert set(rep) >= {'labels', 'via', 'claims', 'raw_new', 'checks_written', 'method_version'}


# ---- F6-4b person-shaped names (frozen cfg_prod_f6p; person test sets 1 and 2) --------------------------------
def test_person_shape():                                 # mutant: person_shape always False
    assert R.person_shape('Mariano Rajoy') and R.person_shape('Zilda Arns Neumann')
    assert not R.person_shape('Mariano Rajoy Ltd') and not R.person_shape('acme.com') and not R.person_shape('Acme')


def test_person_shaped_name_guessed_site_does_not_decide():   # mutant: the E1 person guard removed
    d = run('Zilda Arns', ev([cand('zildaarns.com', ['slug_guess'], 'Zilda Arns')]))
    assert (d['label'], d['via'], d['natural_person_risk']) == ('ambiguous', 'person_guard', True)


def test_person_shaped_name_tracker_domain_still_decides():   # mutant: the guard also drops tracker domains
    d = run('Zilda Arns', ev([cand('zildaarns.com', ['tracker_domain'], 'Zilda Arns')]), domain='zildaarns.com')
    assert d['label'] == 'real_org'


def test_person_shaped_name_ignores_wikidata_and_gleif():     # mutant: wd_ok/gl_ok kept for person shapes
    wd = [{'qid': 'Q1', 'label': 'Zilda Arns', 'description': 'school in Brazil'}]
    assert run('Zilda Arns', ev(wd=wd))['label'] == 'ambiguous'
    assert run('Lars Schmidt', ev(extras={'gleif': [{'name': 'c/o Lars Schmidt'}]}))['label'] == 'ambiguous'


def test_edgar_individual_filer_is_not_an_organisation():     # mutant: edgar_individual filter removed
    assert run('Patricia Martinez', ev(extras={'edgar': [{'entity': 'Martinez Patricia'}]}))['label'] == 'ambiguous'
    assert R.edgar_individual('Patricia Martinez', 'Martinez Patricia') and not R.edgar_individual('Patricia Martinez', 'Martinez Patricia Inc')
