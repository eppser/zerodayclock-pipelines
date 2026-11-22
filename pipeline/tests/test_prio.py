"""The prioritisation scorecard's definitions, on inputs small enough to check by hand."""

from datetime import date

from zdc_prio.compute import MonthInputs, score_month
from zdc_prio.run import coverage, is_due, kev_sets, months_after, next_month, previous_month, run_months


def _inputs(**over):
    base = dict(
        epss_start={'A': .5, 'B': .04, 'C': .001, 'D': .02, 'K': .001},
        epss_next={'A': .5, 'B': .12, 'C': .05, 'D': .02, 'N': .2},
        cvss={'A': 9.8, 'B': 5.0, 'C': 7.5, 'D': 9.1, 'N': 9.0},
        kev_start={'all': {'K', 'Z'}, 'cisa': {'K'}, 'clean': set()},
        kev_next={'all': {'K', 'Z'}, 'cisa': {'K'}, 'clean': set()},
        attacked={'A', 'C', 'K', 'X'},
        seen_before={'A'},
    )
    base.update(over)
    return MonthInputs(**base)


def rule(card, key):
    return next(r for r in card.rules if r.key == key)


def test_outcome_is_cut_to_the_scored_population():
    card = score_month(_inputs())
    # X is attacked but not in the EPSS file of day 1; A was seen before the month.
    assert (card.cves, card.attacked_all, card.attacked_new) == (5, 3, 2)


def test_a_kev_cve_missing_from_the_next_file_is_not_added():
    # K and Z are listed before day 1. Z is in neither EPSS file, K drops out of the next one:
    # neither may count as a September addition (the audited bug).
    card = score_month(_inputs())
    kev = rule(card, 'kev')
    assert kev.backlog == 1 and kev.added == 0


def test_additions_and_lanes():
    card = score_month(_inputs())
    pick = rule(card, 'pick')                    # any KEV or EPSS 3%+
    assert pick.backlog == 3                     # A, B, K
    assert pick.added == 2                       # C rose past 3%, N is new
    lane = rule(card, 'lane')                    # any KEV or EPSS 10%+
    assert (card.lanes_urgent, card.lanes_regular) == (1, 1)    # N urgent, C regular
    assert card.lanes_turned == 1                # B was listed and rose past 10%
    assert card.lanes_urgent + card.lanes_regular == pick.added
    assert lane.added == 2                       # B and N


def test_coverage_counts_and_clean_check():
    card = score_month(_inputs())
    kev = rule(card, 'kev')
    assert (kev.hit_all, kev.hit_new, kev.hit_new_clean) == (1, 1, 0)
    cvss9 = rule(card, 'cvss9')
    assert (cvss9.hit_all, cvss9.hit_new) == (1, 0)              # A, seen before
    lo, hi = rule(card, 'all').new_ci
    assert lo == hi == 1


def test_the_bootstrap_is_reproducible():
    a = [r.new_ci for r in score_month(_inputs()).rules]
    b = [r.new_ci for r in score_month(_inputs()).rules]
    assert a == b


def test_kev_sets_need_listing_and_collection_before_the_day():
    rows = [
        ('cisa', 'C1', date(2026, 8, 1), date(2026, 8, 27), False),
        ('vulncheck', 'V1', date(2026, 8, 1), date(2026, 8, 27), True),     # cites a sensor
        ('vulncheck', 'V2', date(2026, 8, 1), date(2026, 9, 3), False),     # backdated: collected later
        ('circl', 'P1', date(2026, 8, 1), date(2026, 8, 27), False),
        ('euvd', 'E1', None, date(2026, 8, 27), False),                     # no listing date
    ]
    s = kev_sets(rows, date(2026, 9, 1))
    assert s['all'] == {'C1', 'V1', 'P1'}
    assert s['cisa'] == {'C1'}
    assert s['clean'] == {'C1'}


def test_the_previous_month_is_due_from_the_fifth():
    assert previous_month(date(2026, 10, 11)) == date(2026, 9, 1)
    assert previous_month(date(2027, 1, 2)) == date(2026, 12, 1)
    assert next_month(date(2026, 12, 1)) == date(2027, 1, 1)
    assert not is_due(date(2026, 10, 1), date(2026, 11, 4))
    assert is_due(date(2026, 10, 1), date(2026, 11, 5))


def test_a_month_that_contradicts_the_title_is_refused():
    from zdc_prio.compute import RuleScore, Scorecard
    from zdc_prio.run import check
    def r(key, hit_new, added=10):
        return RuleScore(key, key, 'single', added, 100, hit_new, hit_new, (0, 1), hit_new)
    card = Scorecard(cves=300_000, attacked_all=1_000, attacked_new=100,
                     rules=[r('pick', 40, added=10), r('cvss9', 50)], lanes_urgent=4, lanes_regular=6)
    assert any('title would be wrong' in p for p in check(card))
    card.rules[0] = r('pick', 60, added=10)
    assert check(card) == []


def test_a_missed_month_is_caught_up_not_skipped():
    # September stored; the job did not run in November: on 6 Dec both Oct and Nov are due.
    assert months_after(date(2026, 9, 1), date(2026, 12, 6)) == [date(2026, 10, 1), date(2026, 11, 1)]
    assert months_after(date(2026, 9, 1), date(2026, 11, 4)) == []
    assert months_after(None, date(2026, 10, 6)) == [date(2026, 9, 1)]


def test_coverage_names_missing_days_and_where_crowdsec_starts():
    from datetime import timedelta
    lb, m, end = date(2026, 7, 13), date(2026, 9, 1), date(2026, 9, 30)
    all_days = {lb + timedelta(days=i) for i in range((end - lb).days + 1)}
    ss = all_days - {date(2026, 9, 10)}
    cs = {d for d in all_days if d >= date(2026, 8, 23)}
    c = coverage({'shadowserver_api': ss, 'crowdsec': cs}, date(2026, 8, 23), lb, m, end)
    assert c['crowdsec_from'] == date(2026, 8, 24)
    assert c['gaps'] == [(date(2026, 9, 10), 'Shadowserver')]
    assert c['gaps_in_month'] == 1


def test_an_incomplete_month_is_refused():
    from zdc_prio.compute import RuleScore, Scorecard
    from zdc_prio.run import check
    def r(key, h):
        return RuleScore(key, key, 'single', 10, 100, h, h, (0, 1), h)
    card = Scorecard(cves=300_000, attacked_all=1_000, attacked_new=100, rules=[r('pick', 60), r('cvss9', 50)])
    cov = {'gaps_in_month': 5, 'last': {'shadowserver_api': date(2026, 9, 28), 'crowdsec': date(2026, 9, 30)}}
    probs = check(card, cov, date(2026, 9, 1))
    assert any('sensor-days missing' in p for p in probs)
    assert any('not complete' in p for p in probs)


def test_catch_up_stops_at_the_first_month_not_stored():
    stored = []
    def step(m):
        if m == date(2026, 10, 1):
            return 'failed'            # e.g. October's EPSS file still missing after the 15th
        stored.append(m)
        return 'stored'
    assert run_months([date(2026, 10, 1), date(2026, 11, 1)], step) is False
    assert stored == []               # November must not be stored ahead of October
    assert run_months([date(2026, 10, 1)], lambda m: 'waiting') is True
    assert run_months([date(2026, 10, 1), date(2026, 11, 1)], lambda m: 'refused') is False


def test_crowdsec_is_named_only_when_it_shortens_the_lookback():
    from datetime import timedelta
    lb, m, end = date(2026, 10, 12), date(2026, 12, 1), date(2026, 12, 31)
    days = {lb + timedelta(days=i) for i in range((end - lb).days + 1)}
    c = coverage({'shadowserver_api': days, 'crowdsec': days}, date(2026, 8, 23), lb, m, end)
    assert c['crowdsec_from'] is None and c['gaps'] == []


def test_kev_before_our_collection_is_frozen_at_the_first_collection():
    """A day nothing can have been collected before uses the entries dated before it that were in the
    catalogue when we first collected it. An entry we first saw later was not in the catalogue then:
    whatever date it carries, it is provably backdated (V2) and must not count."""
    from zdc_prio.run import kev_basis, kev_collection_start
    rows = [
        ('cisa', 'C1', date(2026, 7, 1), date(2026, 8, 27), False),
        ('vulncheck', 'V1', date(2026, 7, 1), date(2026, 8, 29), False),    # in VulnCheck's first collection
        ('vulncheck', 'V2', date(2026, 7, 1), date(2026, 9, 3), False),     # first seen later: backdated
        ('vulncheck', 'V3', date(2026, 8, 5), date(2026, 8, 29), False),    # listed after the day
        ('euvd', 'E1', None, date(2026, 8, 27), False),                     # no listing date: never
    ]
    assert kev_collection_start(rows) == {'cisa': date(2026, 8, 27), 'vulncheck': date(2026, 8, 29), 'euvd': date(2026, 8, 27)}
    assert kev_basis(rows, date(2026, 8, 1)) == 'first_collection'
    assert kev_basis(rows, date(2026, 8, 27)) == 'first_collection'         # nothing collected BEFORE it
    assert kev_basis(rows, date(2026, 8, 28)) == 'listed_and_collected'
    assert kev_basis(rows, date(2026, 9, 1)) == 'listed_and_collected'
    assert kev_basis([], date(2026, 9, 1)) == 'listed_and_collected'        # no catalogue: nothing to relax
    aug = kev_sets(rows, date(2026, 8, 1), 'first_collection')['all']
    assert aug == {'C1', 'V1'}                                              # each catalogue's own first day
    assert kev_sets(rows, date(2026, 8, 1))['all'] == set()                 # the strict basis finds nothing
    sep = kev_sets(rows, date(2026, 9, 1))['all']
    assert sep == {'C1', 'V1', 'V3'}                                        # and still refuses V2 in September
    assert aug <= sep                                                       # so "added in August" is a true difference


def test_a_month_long_before_our_collection_is_refused():
    from zdc_prio.compute import RuleScore, Scorecard
    from zdc_prio.run import check
    def r(key, h):
        return RuleScore(key, key, 'single', 10, 100, h, h, (0, 1), h)
    card = Scorecard(cves=300_000, attacked_all=1_000, attacked_new=100, rules=[r('pick', 60), r('cvss9', 50)])
    assert check(card, {'gaps_in_month': 0, 'last': {'shadowserver_api': date(2026, 8, 31)},
                        'kev_collected_from': date(2026, 8, 27)}, date(2026, 8, 1)) == []          # 26 days: allowed
    probs = check(card, {'gaps_in_month': 0, 'last': {'shadowserver_api': date(2026, 7, 31)},
                         'kev_collected_from': date(2026, 8, 27)}, date(2026, 7, 1))               # 57 days
    assert any('cannot be reconstructed' in p for p in probs)


def test_crowdsec_counts_only_for_a_month_it_has_a_day_before():
    from zdc_prio.run import crowdsec_counts_for
    first = date(2026, 8, 23)                       # its first day is a backfilled aggregate: counted from the 24th
    assert not crowdsec_counts_for(date(2026, 8, 1), first)
    assert crowdsec_counts_for(date(2026, 9, 1), first)
    assert not crowdsec_counts_for(date(2026, 8, 24), first)                # counted from that very day: no day before
    assert crowdsec_counts_for(date(2026, 8, 25), first)
    assert not crowdsec_counts_for(date(2026, 9, 1), None)


def test_a_month_without_crowdsec_does_not_report_it_missing():
    from datetime import timedelta
    lb, m, end = date(2026, 6, 12), date(2026, 8, 1), date(2026, 8, 31)
    days = {lb + timedelta(days=i) for i in range((end - lb).days + 1)}
    cs = {d for d in days if d >= date(2026, 8, 23)}
    c = coverage({'shadowserver_api': days, 'crowdsec': cs}, date(2026, 8, 23), lb, m, end)
    assert c['sensors'] == 'shadowserver_api'
    assert c['crowdsec_from'] is None and c['gaps'] == [] and 'crowdsec' not in c['last']
    sep = coverage({'shadowserver_api': days, 'crowdsec': cs}, date(2026, 8, 23), lb, date(2026, 8, 25), end)
    assert sep['sensors'] == 'shadowserver_api,crowdsec'


def test_a_month_to_date_is_complete_when_its_last_day_has_arrived():
    from zdc_prio.compute import RuleScore, Scorecard
    from zdc_prio.run import check
    def r(key, h):
        return RuleScore(key, key, 'single', 10, 100, h, h, (0, 1), h)
    card = Scorecard(cves=300_000, attacked_all=1_000, attacked_new=100, rules=[r('pick', 60), r('cvss9', 50)])
    last = {'shadowserver_api': date(2026, 11, 18), 'crowdsec': date(2026, 11, 18)}
    assert check(card, {'gaps_in_month': 0, 'last': last, 'through': date(2026, 11, 18)}, date(2026, 11, 1)) == []
    # the same data read as the whole month is not complete, and a to-date run short of its day is not either
    assert any('not complete' in p for p in check(card, {'gaps_in_month': 0, 'last': last}, date(2026, 11, 1)))
    assert any('not complete' in p for p in
               check(card, {'gaps_in_month': 0, 'last': last, 'through': date(2026, 11, 20)}, date(2026, 11, 1)))

