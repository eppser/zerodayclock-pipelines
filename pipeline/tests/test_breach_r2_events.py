"""Unit tests: R2 event matcher (zdc_breach.r2_events). Synthetic names only; Jev is a fake, no network.

Each test names the rule it guards. The mutation check (tools: /tmp/zdcq/r2/t3/mutate.py) removes or flips one rule at a
time; every mutant must make at least one test here fail.
"""

from __future__ import annotations

import collections

import pytest

from zdc_breach import r2_events as R


def rec(vid, name, **kw):
    kw.setdefault('reported', '2024-03-01')
    kw.setdefault('sources', ['ca_ag'])
    return R.make_rec(vid=vid, name=name, **kw)


class FakeJev:
    """Picks the candidate whose first name shares the record's core; p_choice / p_pair configurable."""

    def __init__(self, p_choice=0.97, p_pair=0.97, pick=None, p_org=0.97):
        self.p_choice, self.p_pair, self.pick, self.p_org, self.calls = p_choice, p_pair, pick, p_org, []

    def ask(self, state, qs, model=None):
        self.calls.append((state, qs))
        cands = state['candidates']
        if self.pick is not None:
            pick = self.pick(state)
        else:
            mine = R.squash(R.core_tokens(R.clean_name(state['record']['names'][0])[0]))
            pick = next((k for k, c in cands.items()
                         if any(R.squash(R.core_tokens(R.clean_name(n)[0]))[:4] == mine[:4] for n in c['names'])), 'none')
        probs = {k: 0.0 for k in list(cands) + ['none']}
        probs[pick] = self.p_choice
        rest = [k for k in probs if k != pick]
        for k in rest:
            probs[k] = (1 - self.p_choice) / len(rest)
        ans = {'pick': {'type': 'choice', 'choice': pick, 'probabilities': probs}}
        for k in cands:
            ans['same_' + k] = {'type': 'noul', 'noul': self.p_pair if k == pick else 0.02}
            ans['org_' + k] = {'type': 'noul', 'noul': self.p_org if k == pick else 0.02}
        return {'answers': ans, 'model': 'jev-1.13.0', 'usage': {'input_tokens': 1000, 'output_tokens': 10}}


def events_of(recs, jev=None, **kw):
    asker = R.Asker(jev) if jev is not None else None
    stats = collections.Counter()
    evs = R.run(recs, asker, workers=1, stats=stats, **kw)
    by = {}
    for e in evs:
        for u in e.units:
            for r in u.recs:
                by[r.vid] = e
    return evs, by, stats, asker


# ---- names: scraping junk -------------------------------------------------------------------------------------
@pytest.mark.parametrize('raw', ['Exclusive: Zzorvex Freight Inc.', 'Zzorvex Freight, Inc', "Zzorvex Freight's",
                                 'Zzorvex Freight - Reuters', 'BREAKING: Zzorvex Freight LLC', 'Zzorvex Freight Zzorvex Freight',
                                 'Zzorvex Freight, Inc. Supplemental 2', 'Zzorvex Freight, Inc. on behalf of its clients',
                                 'Zzorvex Freight Corp and its subsidiaries', 'The Zzorvex Freight Company'])
def test_scraping_junk_reduces_to_one_core(raw):
    assert R.squash(R.core_tokens(R.clean_name(raw)[0])) == 'zzorvexfreight'


def test_truncated_name_links_by_prefix():
    a = rec('incident:a', 'Zzorvex Freightlines Intern...', sources=['news_x'])
    b = rec('incident:b', 'Zzorvex Freightlines International Holdings')
    assert a.truncated and R.name_link(a, b) in ('prefix', 'tokenset')
    c = rec('incident:c', 'Zzorvex Freightlines Intern')          # no ellipsis: not a truncation
    assert not c.truncated


def test_hostname_and_city_of():
    a = rec('claim:x|zzorvex.com|2024-03-01', 'zzorvex.com', sources=['ransomlook'], actor='akira')
    b = rec('incident:b', 'Zzorvex', domain='zzorvex.com')
    assert R.name_link(a, b) == 'domain'
    assert R.core_tokens(R.clean_name('City of Zzlington')[0]) == R.core_tokens('Zzlington')


def test_acronym_long_form():
    assert R.is_acronym(('zfh',), ('zzorvex', 'family', 'health'))
    assert R.is_acronym(('zfh', 'clinic'), ('zzorvex', 'family', 'health', 'clinic'))
    assert not R.is_acronym(('zfx',), ('zzorvex', 'family', 'health'))
    a, b = rec('incident:a', 'ZFH'), rec('incident:b', 'Zzorvex Family Health')
    assert R.name_link(a, b) == 'acronym'


def test_actor_name_stripped_from_victim():
    assert R.clean_name('akira - Zzorvex Freight', 'akira')[0] == 'Zzorvex Freight'


# ---- structured and deterministic units --------------------------------------------------------------------------
def test_claim_linked_to_incident_is_structured():
    inc = rec('incident:i1', 'Zzorvex Freight')
    cl = rec('claim:akira|zzorvex freight|2024-03-02', 'Zzorvex Freight', sources=['ransomlook'], actor='akira',
             link_to='incident:i1', reported='2024-03-02')
    evs, by, _, _ = events_of([inc, cl])
    assert by[inc.vid] is by[cl.vid]
    assert by[cl.vid].method[cl.vid][0] == 'structured_key'


def test_leak_posts_same_actor_90_days_one_event_without_jev():
    a = rec('claim:akira|zzorvex|2024-01-01', 'Zzorvex', sources=['ransomlook'], actor='akira', reported='2024-01-01')
    b = rec('claim:akira|zzorvex update|2024-03-01', 'Zzorvex', sources=['ransomlook'], actor='akira', reported='2024-03-01')
    jev = FakeJev()
    _, by, _, _ = events_of([a, b], jev)
    assert by[a.vid] is by[b.vid] and not jev.calls
    assert by[b.vid].method[b.vid][0] == 'deterministic'


def test_leak_reposts_more_than_90_days_apart_are_separate_events():
    a = rec('claim:akira|zzorvex|2024-01-01', 'Zzorvex', sources=['ransomlook'], actor='akira', reported='2024-01-01')
    b = rec('claim:akira|zzorvex|2024-09-01', 'Zzorvex', sources=['ransomlook'], actor='akira', reported='2024-09-01')
    jev = FakeJev()                                   # would say merge
    _, by, stats, _ = events_of([a, b], jev)
    assert by[a.vid] is not by[b.vid] and not jev.calls and stats['cannot_leak_repost_far'] == 1
    c = rec('claim:akira|zzorvex|2024-09-02', 'Zzorvex', sources=['ransomlook'], actor='akira', reported='2024-09-01',
            quotes=('Zzorvex data previously published, now the full archive',))
    _, by, _, _ = events_of([a, c], FakeJev())
    assert by[a.vid] is by[c.vid]                     # the post says it is the same data


def test_grouped_posts_are_members():
    a = rec('claim:akira|zzorvex|2024-01-01', 'Zzorvex', sources=['ransomlook'], actor='akira',
            extra_members=(('claim', 'akira|zzorvex update|2024-01-05'),))
    evs, _, _, _ = events_of([a])
    ms = R.member_rows(evs[0])
    assert {(m['member_kind'], m['member_id'], m['match_method']) for m in ms} >= {('claim', 'akira|zzorvex update|2024-01-05',
                                                                                   'structured_key')}


# ---- same victim breached twice ----------------------------------------------------------------------------------
def test_repeat_victim_different_actors_never_merge():
    a = rec('claim:akira|zzorvex|2024-01-01', 'Zzorvex', sources=['ransomlook'], actor='akira', reported='2024-01-01')
    b = rec('claim:play|zzorvex|2024-02-01', 'Zzorvex', sources=['ransomlook'], actor='play', reported='2024-02-01')
    jev = FakeJev()                      # would say merge
    _, by, stats, _ = events_of([a, b], jev)
    assert by[a.vid] is not by[b.vid] and not jev.calls and stats['cannot_leak_actor_differs'] == 1


def test_repeat_victim_years_apart_not_candidates():
    a = rec('incident:a', 'Zzorvex Health', reported='2019-07-29', breach='2019-03-22')
    b = rec('incident:b', 'Zzorvex Health', reported='2024-05-01', breach='2024-02-01')
    jev = FakeJev()
    _, by, _, _ = events_of([a, b], jev)
    assert by[a.vid] is not by[b.vid] and not jev.calls


def test_breach_dates_far_cannot_link_even_inside_reported_window():
    a = rec('incident:a', 'Zzorvex Health', reported='2022-06-01', breach='2019-01-10')
    b = rec('incident:b', 'Zzorvex Health', reported='2023-06-01', breach='2023-03-01')
    jev = FakeJev()
    _, by, stats, _ = events_of([a, b], jev)
    assert by[a.vid] is not by[b.vid] and stats['cannot_breach_dates_far'] == 1


# ---- Capital One 2019 vs court articles ----------------------------------------------------------------------------
def test_follow_up_court_article_attaches_to_old_event():
    reg = rec('incident:reg', 'Zzcapital One Financial Corp', reported='2019-07-29', breach='2019-03-22', sources=['sec_8k'])
    court = rec('incident:court', 'Zzcapital One', reported='2025-03-10', sources=['news_therecord'],
                titles=('Zzcapital One loses appeal over 2019 data breach settlement',))
    new = rec('incident:new', 'Zzcapital One', reported='2025-04-01', sources=['news_x'],
              titles=('Zzcapital One discloses new ransomware attack',))
    assert court.follow_up and not new.follow_up
    jev = FakeJev()
    evs, by, _, _ = events_of([reg, court, new], jev)
    assert by[court.vid] is by[reg.vid]
    assert by[reg.vid].role[court.vid] == 'follow_up'
    assert by[new.vid] is not by[reg.vid]
    row = R.event_row(by[reg.vid])
    assert row['reported_date'] == '2019-07-29' and row['breach_date'] == '2019-03-22'


def test_follow_up_does_not_widen_the_window_for_others():
    reg = rec('incident:reg', 'Zzcapital One', reported='2019-07-29', breach='2019-03-22')
    court = rec('incident:court', 'Zzcapital One', reported='2025-03-10', sources=['news_x'],
                titles=('Zzcapital One settlement approved by judge',))
    later = rec('incident:later', 'Zzcapital One', reported='2025-06-01', sources=['ca_ag'])
    jev = FakeJev()
    _, by, _, _ = events_of([reg, court, later], jev)
    assert by[court.vid] is by[reg.vid] and by[later.vid] is not by[reg.vid]


# ---- brands: Volkswagen vs Seat ------------------------------------------------------------------------------------
def test_separate_brand_parent_only_link_never_merges():
    vw = rec('incident:vw', 'Zzvolks Group', domain='zzvolks.de', related=('zzseat',), reported='2024-03-01')
    seat = rec('incident:seat', 'Zzseat', domain='zzseat.es', reported='2024-03-05')
    assert R.name_link(vw, seat) == 'parent'
    jev = FakeJev(pick=lambda s: 'e1')                  # Jev wrongly says same
    evs, by, stats, _ = events_of([vw, seat], jev)
    assert by[vw.vid] is not by[seat.vid]
    assert by[seat.vid].possible_dup == by[vw.vid].eid


def test_one_intrusion_named_for_both_brands_may_merge():
    vw = rec('incident:vw', 'Zzvolks Group', domain='zzvolks.de', related=('zzseat',), reported='2024-03-01')
    seat = rec('incident:seat', 'Zzseat', domain='zzseat.es', reported='2024-03-05', sources=['news_x'],
               titles=('Zzseat and Zzvolks Group hit by the same intrusion',))
    jev = FakeJev(pick=lambda s: 'e1')
    _, by, _, _ = events_of([vw, seat], jev)
    assert by[vw.vid] is by[seat.vid]


def test_unrelated_brands_are_not_candidates():
    vw = rec('incident:vw', 'Zzvolks Group', domain='zzvolks.de')
    seat = rec('incident:seat', 'Zzseat', domain='zzseat.es')
    assert R.name_link(vw, seat) is None


# ---- MOVEit-style campaigns ------------------------------------------------------------------------------------------
def test_moveit_customers_separate_events_one_campaign():
    t = ('{} says data stolen in MOVEit attack',)
    rs = [rec(f'incident:c{i}', n, reported='2023-06-20', sources=['news_x'], titles=(t[0].format(n),))
          for i, n in enumerate(['Zzalpha Pensions', 'Zzbeta University', 'Zzgamma Bank'])]
    vendor = rec('incident:v', 'Zzprogress Software', reported='2023-06-01', sources=['sec_8k'],
                 titles=('Zzprogress Software discloses MOVEit vulnerability',))
    evs, by, _, _ = events_of(rs + [vendor], FakeJev())
    assert len({by[r.vid].eid for r in rs + [vendor]}) == 4
    assert {R.event_row(by[r.vid])['campaign_id'] for r in rs} == {'moveit-2023'}


def test_clop_wave_sets_campaign():
    r = rec('claim:clop|zzdelta|2023-07-01', 'Zzdelta', sources=['ransomlook'], actor='clop', reported='2023-07-01')
    assert r.campaign == 'moveit-2023'


def test_two_campaigns_same_org_cannot_link():
    a = rec('incident:a', 'Zzalpha Pensions', reported='2023-06-20', sources=['news_x'], titles=('Zzalpha MOVEit breach',))
    b = rec('incident:b', 'Zzalpha Pensions', reported='2025-01-10', sources=['news_x'],
            titles=('Zzalpha hit via Cleo Harmony flaw',))
    assert a.campaign == 'moveit-2023' and b.campaign == 'cleo-2024'
    _, by, stats, _ = events_of([a, b], FakeJev())
    assert by[a.vid] is not by[b.vid] and stats['cannot_campaign_differs'] == 1


# ---- block rules: volume, industry ----------------------------------------------------------------------------------
def test_volume_more_than_10x_apart_not_candidates():
    a = rec('incident:a', 'Zzorvex Health', people=1000, sources=['hhs_ocr'])
    b = rec('incident:b', 'Zzorvex Health', people=50000, sources=['news_x'])
    assert not R.pair_ok(a, b, 'exact')
    c = rec('incident:c', 'Zzorvex Health', people=50000, sources=['wa_ag'])   # a state count, not a total
    assert R.pair_ok(a, c, 'exact')


def test_industry_must_be_compatible_for_weak_links():
    a = rec('incident:a', 'Zzorvexa Builders', industry='Construction')
    b = rec('incident:b', 'Zzorvexo Builders', industry='Healthcare')
    assert not R.pair_ok(a, b, 'trigram')
    assert R.pair_ok(a, b, 'exact')


def test_window_24_months():
    a = rec('incident:a', 'Zzorvex', reported='2020-01-01')
    b = rec('incident:b', 'Zzorvex', reported='2021-12-15')
    c = rec('incident:c', 'Zzorvex', reported='2022-02-01')
    assert R.pair_ok(a, b, 'exact') and not R.pair_ok(a, c, 'exact')


# ---- the decision ---------------------------------------------------------------------------------------------------
def test_decide_thresholds():
    A = lambda c, p, pick='e1': {'pick': pick, 'choice_p': c, 'pair_p': p}
    assert R.decide(A(0.9, 0.9), tau_c=0.8, tau_p=0.8) == 'merge'
    assert R.decide(A(0.79, 0.99), tau_c=0.8, tau_p=0.8) == 'possible'
    assert R.decide(A(0.99, 0.6), tau_c=0.8, tau_p=0.8) == 'possible'
    assert R.decide(A(0.99, 0.4), tau_c=0.8, tau_p=0.8) == 'new'
    assert R.decide(A(0.4, 0.99), tau_c=0.8, tau_p=0.8) == 'new'
    assert R.decide(A(0.99, None, 'none'), tau_c=0.8, tau_p=0.8) == 'new'
    assert R.decide(A(0.99, 0.99), tau_c=0.8, tau_p=0.8, merge_allowed=False) == 'possible'


def test_uncertain_pair_becomes_possible_duplicate_not_merge():
    a = rec('incident:a', 'Zzorvex Health', reported='2024-01-01')
    b = rec('incident:b', 'Zzorvex Health', reported='2024-02-01', sources=['news_x'])
    _, by, _, _ = events_of([a, b], FakeJev(p_choice=0.7, p_pair=0.9))
    assert by[a.vid] is not by[b.vid] and by[b.vid].possible_dup == by[a.vid].eid


def test_jev_merge_regulator_and_press():
    a = rec('incident:a', 'Zzorvex Health, Inc.', reported='2024-01-01')
    b = rec('incident:b', 'Exclusive: Zzorvex Health', reported='2024-02-01', sources=['news_x'])
    _, by, _, _ = events_of([a, b], FakeJev())
    assert by[a.vid] is by[b.vid] and by[a.vid].method[b.vid][0] == 'jev_choice_pair'


def test_candidates_capped_at_k():
    rs = [rec(f'incident:{i:02d}', 'Zzorvex Health', reported=f'2024-01-{i + 1:02d}', sources=['news_x'],
              quotes=(f'Zzorvex Health quote {i}',)) for i in range(12)]
    jev = FakeJev(pick=lambda s: 'none')
    events_of(rs, jev)
    assert max(len(s['candidates']) for s, _ in jev.calls) == R.K


def test_answers_cached_no_reask():
    a = rec('incident:a', 'Zzorvex Health', reported='2024-01-01')
    b = rec('incident:b', 'Zzorvex Health', reported='2024-02-01', sources=['news_x'])
    jev = FakeJev()
    _, _, _, asker = events_of([a, b], jev)
    asker2 = R.Asker(jev, asker.cache)
    R.run([a, b], asker2, workers=1)
    assert len(jev.calls) == 1 and asker2.cached == 1


def test_event_ids_deterministic():
    a = rec('incident:a', 'Zzorvex Health')
    e1, _, _, _ = events_of([a])
    e2, _, _, _ = events_of([a])
    assert e1[0].eid == e2[0].eid


def test_prompt_hash_changes_with_rules(monkeypatch):
    h = R.prompt_sha256()
    monkeypatch.setattr(R, 'PAIR_Q', R.PAIR_Q + ' x')
    assert R.prompt_sha256() != h


def test_event_dates_ignore_follow_up_members():
    a = rec('incident:a', 'Zzorvex Health', reported='2024-05-01', breach='2024-04-01')
    f = rec('incident:f', 'Zzorvex Health', reported='2024-01-01', breach='2020-01-01', sources=['news_x'],
            titles=('Zzorvex Health settles class action',))
    ua, uf = R.build_units([a])[0], R.build_units([f])[0]
    e = R.Event('x', [ua, uf], {a.vid: ('seed', None, None, None), f.vid: ('jev_choice_pair', 0.9, 0.9, None)},
                {a.vid: 'member', f.vid: 'follow_up'})
    row = R.event_row(e)
    assert row['reported_date'] == '2024-05-01' and row['breach_date'] == '2024-04-01'


# ---- deterministic same filing, card issuers, tiers ------------------------------------------------------------------
def test_same_breach_day_same_org_is_deterministic():
    a = rec('incident:a', 'Zzorvex Health', reported='2024-01-01', breach='2023-11-02', sources=['hhs_ocr'])
    b = rec('incident:b', 'Zzorvex Health, Inc.', reported='2024-03-01', breach='2023-11-02', sources=['wa_ag'])
    c = rec('incident:c', 'Zzorvex Health', reported='2024-03-03', breach='2023-11-09', sources=['de_ag'])
    jev = FakeJev(pick=lambda s: 'none')
    _, by, _, _ = events_of([a, b, c], jev)
    assert by[a.vid] is by[b.vid] and by[a.vid].method[b.vid][0] == 'deterministic'
    assert by[c.vid] is not by[a.vid]                  # a different breach day goes to Jev (which said none)


def test_regulator_filings_within_7_days_deterministic():
    a = rec('incident:a', 'Zzorvex Health', reported='2024-01-01', sources=['ca_ag'])
    b = rec('incident:b', 'Zzorvex Health', reported='2024-01-06', sources=['wa_ag'])
    c = rec('incident:c', 'Zzorvex Health', reported='2024-01-20', sources=['de_ag'])
    assert R.same_filing(a, b) and not R.same_filing(a, c)
    p = rec('incident:p', 'Zzorvex Health', reported='2024-01-02', sources=['news_x'])
    assert not R.same_filing(a, p)


def test_card_issuer_notices_never_merge():
    a = rec('incident:a', 'American Express Travel Related Services', reported='2013-01-11', breach='2012-08-24')
    b = rec('incident:b', 'American Express Travel Related Services', reported='2013-01-20', breach='2012-08-24')
    assert a.card_issuer and not R.same_filing(a, b) or a.card_issuer
    _, by, stats, _ = events_of([a, b], FakeJev())
    assert by[a.vid] is not by[b.vid] and stats['cannot_card_issuer'] >= 1


def test_tiers():
    reg = R.build_units([rec('incident:a', 'Zzorvex Health', reported='2024-01-01', breach='2023-12-01')])[0]
    reg2 = R.build_units([rec('incident:b', 'Zzorvex Health', reported='2024-02-01', breach='2023-12-10',
                              sources=['news_x'], quotes=('Zzorvex Health was hit',))])[0]
    assert R.tier(reg2, 'exact', [reg]) == 'A'
    assert R.tier(reg2, 'tokenset', [reg]) == 'B'
    far = R.build_units([rec('incident:c', 'Zzorvex Health', reported='2024-02-01', breach='2023-06-10')])[0]
    assert R.tier(far, 'exact', [reg]) == 'B'
    p1 = R.build_units([rec('incident:d', 'Zzorvex Health', sources=['news_x'], quotes=('Zzorvex Health q',))])[0]
    p2 = R.build_units([rec('incident:e', 'Zzorvex Health', sources=['news_y'], quotes=('Zzorvex Health r',))])[0]
    assert R.tier(p1, 'exact', [p2]) == 'C'            # press vs press
    thin = R.build_units([rec('incident:f', 'Zzorvex Health')])[0]
    assert R.tier(thin, 'exact', [reg]) == 'C'         # nothing but a name and a date
    reg2.busy = True
    assert R.tier(reg2, 'exact', [reg]) == 'C'         # a frequent victim


def test_busy_marks_frequent_victims():
    us = R.build_units([rec(f'incident:{i}', 'Zzmicro', reported=f'2024-0{i + 1}-15', sources=['news_x'])
                        for i in range(R.BUSY_UNITS)])
    R.mark_busy(us)
    assert all(u.busy for u in us)
    few = R.build_units([rec(f'incident:{i}', 'Zzsmall', reported=f'2024-0{i + 1}-15', sources=['news_x'])
                         for i in range(R.BUSY_UNITS - 1)])
    R.mark_busy(few)
    assert not any(u.busy for u in few)


def test_tier_c_needs_higher_p():
    a = rec('incident:a', 'Zzorvex Health', reported='2024-01-01', sources=['news_x'], quotes=('Zzorvex Health hit',))
    b = rec('incident:b', 'Zzorvex Health', reported='2024-02-01', sources=['news_y'], quotes=('Zzorvex Health again',))
    tc, tp = R.TAUS['C']
    _, by, _, _ = events_of([a, b], FakeJev(p_choice=tc - 0.01, p_pair=0.99))
    assert by[a.vid] is not by[b.vid]
    _, by, _, _ = events_of([a, b], FakeJev(p_choice=tc + 0.01, p_pair=0.99))
    assert by[a.vid] is by[b.vid]


def test_pair_p_asked_both_ways():
    ans = {'same_e1': {'noul': 0.9}, 'diff_e1': {'noul': 0.3}}
    assert R.pair_p(ans, 'e1') == pytest.approx(0.8)
    assert R.pair_p({'same_e1': {'noul': 0.9}}, 'e1') == pytest.approx(0.9)


def test_roundup_headline_not_shown_and_quote_names_org():
    docs = [{'doc_sha256': 'x', 'title': 'Ransomware gangs hit Zzalpha and Zzbeta',
             'text': 'Zzalpha said files were stolen. Unrelated sentence about the weather today here.'},
            {'doc_sha256': 'y', 'title': 'Zzgamma confirms attack', 'text': 'Nothing.'}]
    heads, quotes = R.press_evidence('Zzgamma Inc.', docs)
    assert heads == ('Zzgamma confirms attack',) and quotes == ()
    heads, quotes = R.press_evidence('Zzalpha', docs)
    assert quotes == ('Zzalpha said files were stolen.',)


def test_tier_a_uses_its_own_taus():
    a = rec('incident:a', 'Zzorvex Health', reported='2024-01-01', breach='2023-12-01', sources=['hhs_ocr'])
    b = rec('incident:b', 'Zzorvex Health', reported='2024-02-01', breach='2023-12-10', sources=['news_x'],
            quotes=('Zzorvex Health was hit',))
    tc, tp = R.TAUS['A']
    assert tc < R.TAU_C
    _, by, _, _ = events_of([a, b], FakeJev(p_choice=tc + 0.01, p_pair=tp + 0.01))
    assert by[a.vid] is by[b.vid]


def test_actor_spellings_are_one_actor():
    assert R.actor_key('CL0P') == R.actor_key('clop') == R.actor_key('Cl0p')
    assert R.actor_key('LockBit 3.0') == R.actor_key('lockbit3') == R.actor_key('lockbit2')
    assert R.actor_key('INC Ransom') == R.actor_key('inc ransom') and R.actor_key('akira') != R.actor_key('play')
    a = rec('claim:clop|zzorvex|2024-01-01', 'Zzorvex', sources=['ransomlook'], actor='clop', reported='2024-01-01')
    b = rec('claim:cl0p|zzorvex|2024-02-01', 'Zzorvex', sources=['ransomlook'], actor='Cl0p', reported='2024-02-01')
    _, by, _, _ = events_of([a, b], FakeJev(pick=lambda s: 'none'))
    assert by[a.vid] is by[b.vid]                       # same actor within 90 days: one episode


# ---- v2 (gate failures M456, M376, M580, M242 and the coverage gap) -----------------------------------------------------
def test_filing_agent_subject_is_the_customer():
    assert R.split_agent('Legalinc Corporate Services o/b/o Stripe GEP') == ('Stripe GEP', 'Legalinc Corporate Services', False)
    assert R.split_agent('Kirkland & Ellis LLP on behalf of the Fed. Way Sch. Dist.')[0] == 'the Fed. Way Sch. Dist'
    assert R.split_agent('Zzorvex Payroll, on behalf of its clients')[2] is True
    assert R.split_agent('Zzorvex Payroll on behalf of certain customers listed in Exhibit A')[2] is True
    assert R.split_agent('Zzorvex Health') == ('Zzorvex Health', None, False)


def test_two_customers_of_one_agent_never_merge():
    a = rec('incident:a', 'Zzlegal Services o/b/o Zzstripe GEP', reported='2024-01-01', breach='2023-12-01')
    b = rec('incident:b', 'Zzlegal Services o/b/o Zzrocket Lawyer', reported='2024-01-03', breach='2023-12-01')
    assert a.core != b.core and not R.name_link(a, b)
    evs, by, _, _ = events_of([a, b], FakeJev())
    assert by[a.vid] is not by[b.vid]


def test_agent_filing_for_unnamed_customers_never_anchors():
    a = rec('incident:a', 'Zzpayroll Inc. on behalf of its clients', reported='2024-01-01', breach='2023-12-01')
    b = rec('incident:b', 'Zzpayroll Inc.', reported='2024-01-02', breach='2023-12-01')
    assert a.agent_only
    _, by, stats, _ = events_of([a, b], FakeJev())
    assert by[a.vid] is not by[b.vid]


def test_customer_named_in_agent_filing_joins_the_customer():
    a = rec('incident:a', 'Zzlegal Services o/b/o Zzstripe Payments', reported='2024-01-01', breach='2023-12-01')
    b = rec('incident:b', 'Zzstripe Payments, Inc.', reported='2024-01-04', breach='2023-12-01', sources=['wa_ag'])
    _, by, _, _ = events_of([a, b], FakeJev())
    assert by[a.vid] is by[b.vid]


def test_name_containment_needs_same_entity_answer():
    a = rec('claim:snatch|zzcomoli zzferrari|2023-05-22', 'Zzcomoli Zzferrari', sources=['ransomlook'], actor='snatch',
            reported='2023-05-22')
    b = rec('incident:b', 'Zzferrari S.p.A.', sources=['cra_export'], reported='2023-05-30', actor='snatch')
    assert R.name_link(a, b) == 'tokenset'
    _, by, stats, _ = events_of([a, b], FakeJev(p_org=0.3, pick=lambda s: 'e1'))
    assert by[a.vid] is not by[b.vid] and by[b.vid].possible_dup == by[a.vid].eid
    _, by, _, _ = events_of([a, b], FakeJev(p_org=0.95, pick=lambda s: 'e1'))
    assert by[a.vid] is by[b.vid]


def test_containment_with_shared_domain_needs_no_entity_answer():
    a = rec('incident:a', 'Zzorvex Holdings Group', domain='zzorvex.com', reported='2024-01-01', sources=['news_x'],
            quotes=('Zzorvex Holdings Group hit',))
    b = rec('incident:b', 'Zzorvex', domain='zzorvex.com', reported='2024-01-10')
    _, by, _, _ = events_of([a, b], FakeJev(p_org=0.1))
    assert by[a.vid] is by[b.vid]


def test_two_regulator_notices_with_different_breach_dates_are_two_events():
    a = rec('incident:a', 'Zznational Wildlife Fed', reported='2019-05-24', breach='2019-01-03')
    b = rec('incident:b', 'Zznational Wildlife Fed', reported='2019-06-20', breach='2019-02-06', sources=['wa_ag'])
    _, by, stats, _ = events_of([a, b], FakeJev())
    assert by[a.vid] is not by[b.vid] and stats['cannot_reg_breach_dates'] == 1


def test_same_org_needs_date_agreement():
    a = rec('incident:a', 'Zzorvex Health', reported='2024-01-01')
    b = rec('incident:b', 'Zzorvex Health', reported='2024-07-01', sources=['news_x'], quotes=('Zzorvex Health hit',))
    _, by, stats, _ = events_of([a, b], FakeJev())
    assert by[a.vid] is not by[b.vid] and stats['cannot_episode_dates'] == 1
    c = rec('incident:c', 'Zzorvex Health', reported='2024-07-01', breach='2023-12-20', sources=['hhs_ocr'])
    d = rec('claim:akira|zzorvex health|2024-01-05', 'Zzorvex Health', reported='2024-01-05', sources=['ransomlook'],
            actor='akira')
    assert R.dates_agree(c, d) and not R.dates_agree(a, b)
    e = rec('claim:akira|zzorvex health|2025-12-01', 'Zzorvex Health', reported='2025-12-01', sources=['ransomlook'], actor='akira')
    assert not R.dates_agree(c, e)
    f = rec('incident:f', 'Zzorvex Health', reported='2024-03-01', breach='2023-09-01', sources=['news_x'])
    assert R.dates_agree(c, f) and not R.dates_agree(
        rec('incident:g', 'Zzorvex Health', reported='2024-03-01', breach='2022-06-01'), c)


def test_no_victim_titles_never_seed_or_join():
    a = rec('claim:clop|files part 1|2025-02-25', 'FILES PART 1', sources=['ransomlook'], actor='clop', reported='2025-02-25')
    b = rec('claim:clop|files part 2|2025-02-25', 'FILES PART 2', sources=['ransomlook'], actor='clop', reported='2025-02-25')
    assert a.no_victim and b.no_victim
    assert not rec('incident:x', 'Data Partners Group').no_victim
    _, by, _, _ = events_of([a, b], FakeJev())
    assert by[a.vid] is not by[b.vid]


def test_all_records_are_in_the_model():
    X = {'victims': [{'victim_id': 'claim:akira|zzorvex|2024-01-01', 'name': 'Zzorvex', 'seen_date': '2024-01-01',
                      'actor': 'akira', 'sources': ['ransomlook'], 'kind': 'leak_claim'}],
         'incidents': [{'incident_id': 'p1', 'org_id': 'o1', 'event_date': None, 'first_public_date': '2024-02-01',
                        'possible_duplicate_of': None, 'suppressed': False},
                       {'incident_id': 's1', 'org_id': 'o1', 'event_date': None, 'first_public_date': '2024-02-01',
                        'possible_duplicate_of': None, 'suppressed': True}],
         'orgs': [{'org_id': 'o1', 'display_name': 'Zzorvex', 'domain': None, 'country': None, 'is_natural_person': False}],
         'isrc': [{'incident_id': 'p1', 'source_id': 'news_x', 'doc_sha256': None}], 'docs': [],
         'claims': [{'claim_key': 'akira|zzorvex|2024-01-01', 'actor_group': 'akira', 'victim_name': 'Zzorvex'},
                    {'claim_key': 'play|zzorvex hidden|2024-03-01', 'actor_group': 'play', 'victim_name': 'Zzorvex Hidden',
                     'first_seen_at': '2024-03-01T00:00:00'}]}
    vids = {r.vid: r for r in R.records_from_extract(X)}
    assert set(vids) == {'claim:akira|zzorvex|2024-01-01', 'incident:p1', 'claim:play|zzorvex hidden|2024-03-01'}
    assert not vids['incident:p1'].listed and not vids['claim:play|zzorvex hidden|2024-03-01'].listed


def test_needs_org_check_rules():
    u = R.build_units([rec('incident:a', 'Zzorvex Group', domain='zzorvex.com')])[0]
    same_dom = R.build_units([rec('incident:b', 'Zzorvex', domain='zzorvex.com')])[0]
    other = R.build_units([rec('incident:c', 'Zzorvex')])[0]
    assert R.needs_org_check(u, [other], 'tokenset') and not R.needs_org_check(u, [same_dom], 'tokenset')
    assert not R.needs_org_check(u, [other], 'exact')


def test_record_long_before_the_breach_does_not_agree():
    c = rec('incident:c', 'Zzorvex Health', reported='2024-07-01', breach='2023-12-20', sources=['hhs_ocr'])
    early = rec('claim:akira|zzorvex health|2023-08-01', 'Zzorvex Health', reported='2023-08-01', sources=['ransomlook'])
    near = rec('claim:akira|zzorvex health|2023-11-01', 'Zzorvex Health', reported='2023-11-01', sources=['ransomlook'])
    assert not R.dates_agree(c, early) and R.dates_agree(c, near)
