"""Unit tests: R2 incremental modes (r2_events --new-only, r2_reported --new-only, r2_hourly). Synthetic names only,
fake Jev, no network, no database. Each test names the rule it guards.

The bug these modes fix: the R2 modules ran once as backfills, so every record ingested later had no event and hence no
reported date. The tests check that (a) a record with no stored membership is placed (merged into a stored event or given
its own), (b) nothing stored changes, (c) a second pass writes nothing, (d) the reported-date rows cover exactly the
events the stored rows do not.
"""

from __future__ import annotations

import collections
from datetime import date
from types import SimpleNamespace

import pytest

from zdc_breach import r2_events as R
from zdc_breach import r2_hourly as H
from zdc_breach import r2_reported as RR
from zdc_breach.profile import BudgetExhausted
from test_breach_r2_events import FakeJev, rec

D = date.fromisoformat


def stored_run(recs):
    """A 'backfill': the full run over `recs`, then its membership in the shape fetch_membership returns."""
    evs = R.run(recs, R.Asker(FakeJev()), workers=1)
    members, meta = {}, {}
    for e in evs:
        meta[e.eid] = {'status': 'active', 'merged_into': None}
        for m in R.member_rows(e):
            members[f"{m['member_kind']}:{m['member_id']}"] = {
                'event_id': e.eid, 'role': m['role'], 'match_method': m['match_method'],
                'jev_choice_p': m['jev_choice_p'], 'jev_pair_p': m['jev_pair_p']}
    return evs, members, meta


def apply(members, meta, new_events, stored, answers=()):
    """What write_new stores, replayed on the in-memory membership (the next run's input)."""
    rows = R.new_member_rows(list(stored.values()) + new_events, members)
    for e in new_events:
        meta[e.eid] = {'status': 'active', 'merged_into': None}
    for m in rows:
        members[f"{m['member_kind']}:{m['member_id']}"] = {
            'event_id': m['event_id'], 'role': m['role'], 'match_method': m['match_method'],
            'jev_choice_p': m['jev_choice_p'], 'jev_pair_p': m['jev_pair_p']}
    return rows


OLD = [rec('incident:a1', 'Zzorvex Freight', reported='2024-03-01'),
       rec('incident:b1', 'Qqyl Dental Group', reported='2024-04-01')]


# ---- placing units --------------------------------------------------------------------------------------------------
def test_unit_without_stored_member_is_new_and_stored_unit_is_placed():
    evs, members, meta = stored_run(OLD)
    fresh = rec('claim:akira|nnyx marine|2026-10-25', 'Nnyx Marine', sources=['ransomlook'], actor='akira', reported='2026-10-25')
    units = R.build_units(OLD + [fresh])
    placed, new = R.place_units(units, members, meta)
    assert [u.uid for u in new] == [fresh.vid]
    assert set(placed) == {'incident:a1', 'incident:b1'}


def test_merged_event_resolves_to_its_survivor_and_withdrawn_is_never_replaced():
    evs, members, meta = stored_run(OLD)
    ea, eb = (members['incident:a1']['event_id'], members['incident:b1']['event_id'])
    meta[ea] = {'status': 'merged', 'merged_into': eb}
    units = R.build_units(OLD)
    stats = collections.Counter()
    placed, new = R.place_units(units, members, meta, stats)
    assert placed['incident:a1'] == eb and not new
    meta[eb] = {'status': 'withdrawn', 'merged_into': None}
    stats = collections.Counter()
    placed, new = R.place_units(units, members, meta, stats)
    assert placed == {} and new == [] and stats['unit_event_withdrawn'] == 2


def test_unit_spanning_two_stored_events_keeps_the_first_and_counts_it():
    evs, members, meta = stored_run(OLD)
    link = rec('claim:akira|zzorvex|2024-03-02', 'Zzorvex Freight', sources=['ransomlook'], actor='akira', link_to='incident:a1')
    members['claim:akira|zzorvex|2024-03-02'] = dict(members['incident:b1'])
    stats = collections.Counter()
    placed, new = R.place_units(R.build_units(OLD + [link]), members, meta, stats)
    assert stats['unit_spans_events'] == 1 and len(placed) == 2 and not new


# ---- run_new ---------------------------------------------------------------------------------------------------------
def test_new_record_of_a_stored_event_merges_into_it_and_changes_nothing_stored():
    evs, members, meta = stored_run(OLD)
    before = {k: dict(v) for k, v in members.items()}
    again = rec('incident:a2', 'Zzorvex Freight', reported='2024-04-20', sources=['wa_ag'])
    asker = R.Asker(FakeJev())
    new, stored = R.run_new(OLD + [again], asker, members, meta, workers=1)
    assert new == []                                              # no new event: it joined the stored one
    rows = R.new_member_rows(list(stored.values()) + new, members)
    assert [(m['member_id'], m['event_id']) for m in rows] == [('a2', members['incident:a1']['event_id'])]
    assert rows[0]['match_method'] == 'jev_choice_pair'
    assert members == before                                      # run_new never mutates the stored membership


def test_unrelated_new_record_gets_its_own_event_with_a_deterministic_id():
    evs, members, meta = stored_run(OLD)
    fresh = rec('claim:akira|nnyx marine|2026-10-25', 'Nnyx Marine', sources=['ransomlook'], actor='akira', reported='2026-10-25')
    new, stored = R.run_new(OLD + [fresh], R.Asker(FakeJev()), members, meta, workers=1)
    assert len(new) == 1 and new[0].eid == R.event_id(fresh.vid)
    rows = R.new_member_rows(list(stored.values()) + new, members)
    assert [(m['member_kind'], m['role'], m['match_method']) for m in rows] == [('claim', 'member', 'seed')]


def test_second_pass_after_the_write_places_nothing():
    evs, members, meta = stored_run(OLD)
    recs = OLD + [rec('claim:akira|nnyx marine|2026-10-25', 'Nnyx Marine', sources=['ransomlook'], actor='akira',
                      reported='2026-10-25'),
                  rec('incident:a2', 'Zzorvex Freight', reported='2024-04-20', sources=['wa_ag'])]
    asker = R.Asker(FakeJev())
    new, stored = R.run_new(recs, asker, members, meta, workers=1)
    apply(members, meta, new, stored)
    stats = collections.Counter()
    new2, stored2 = R.run_new(recs, R.Asker(FakeJev()), members, meta, workers=1, stats=stats)
    assert new2 == [] and stats['units_new'] == 0
    assert R.new_member_rows(list(stored2.values()) + new2, members) == []


def test_new_leak_post_linked_to_a_stored_incident_is_added_to_that_event():
    """Structured key: the unit has a stored member, so the new post is a member row of the stored event, no matching."""
    evs, members, meta = stored_run(OLD)
    post = rec('claim:akira|zzorvex freight|2026-10-25', 'Zzorvex Freight', sources=['ransomlook'], actor='akira',
               reported='2026-10-25', link_to='incident:a1')
    jev = FakeJev()
    new, stored = R.run_new(OLD + [post], R.Asker(jev), members, meta, workers=1)
    assert new == [] and jev.calls == []
    rows = R.new_member_rows(list(stored.values()), members)
    assert [(m['member_kind'], m['match_method'], m['event_id']) for m in rows] == \
        [('claim', 'structured_key', members['incident:a1']['event_id'])]


def test_budget_exhaustion_leaves_the_component_unplaced_and_restores_stored_events():
    evs, members, meta = stored_run(OLD)

    class Broke:
        def ask(self, state, qs, model=None):
            raise BudgetExhausted()
    again = rec('incident:a2', 'Zzorvex Freight', reported='2024-04-20', sources=['wa_ag'])
    stats = collections.Counter()
    new, stored = R.run_new(OLD + [again], R.Asker(Broke()), members, meta, workers=1, stats=stats)
    assert new == [] and stats['components_skipped_budget'] == 1
    assert R.new_member_rows(list(stored.values()), members) == []          # the merge was undone, nothing to write
    assert all(len(e.units) == 1 for e in stored.values())


def test_budget_exhausted_midway_undoes_the_merges_already_made_in_the_component():
    evs, members, meta = stored_run(OLD)
    ok = FakeJev()

    class OnceThenBroke:
        n = 0

        def ask(self, state, qs, model=None):
            self.n += 1
            if self.n > 1:
                raise BudgetExhausted()
            return ok.ask(state, qs, model)
    a2 = rec('incident:a2', 'Zzorvex Freight', reported='2024-04-20', sources=['wa_ag'])
    a3 = rec('incident:a3', 'Zzorvex Freight', reported='2024-05-20', sources=['hhs_ocr'])
    stats = collections.Counter()
    new, stored = R.run_new(OLD + [a2, a3], R.Asker(OnceThenBroke()), members, meta, workers=1, stats=stats)
    assert stats['components_skipped_budget'] == 1 and new == []
    assert R.new_member_rows(list(stored.values()), members) == []       # a2 merged first, then undone with a3


def test_stored_unit_new_rec_roles_follow_the_unit():
    evs, members, meta = stored_run(OLD)
    post = rec('claim:akira|zzorvex freight|2026-10-25', 'Zzorvex Freight', sources=['ransomlook'], actor='akira',
               reported='2026-10-25', link_to='incident:a1')
    placed, new = R.place_units(R.build_units(OLD + [post]), members, meta)
    ev = R.stored_events(R.build_units(OLD + [post]), placed, members)[members['incident:a1']['event_id']]
    assert ev.role[post.vid] == 'member' and ev.method[post.vid][0] == 'structured_key'
    assert ev.method['incident:a1'][0] == members['incident:a1']['match_method']


# ---- reported date ---------------------------------------------------------------------------------------------------
def row(eid, day, verdict='accepted'):
    return {'subject_kind': 'event', 'subject_id': eid, 'field': 'reported_date', 'value': day, 'value_precision': 'day',
            'source_kind': 'leak', 'basis': 'leak_site', 'engine': 'structured', 'engine_version': RR.ENGINE_VERSION,
            'verdict': verdict, 'verdict_reason': None}


def test_select_new_adds_only_events_without_a_stored_row():
    existing = {'e1': {'any': True, 'accepted_min': D('2025-01-01')}}
    rows = [row('e1', '2025-01-01'), row('e2', '2026-10-25')]
    assert [r['subject_id'] for r in RR.select_new(rows, existing)] == ['e2']


def test_select_new_adds_an_earlier_accepted_day_but_never_a_later_or_equal_one():
    existing = {'e1': {'any': True, 'accepted_min': D('2025-01-10')}}
    assert RR.select_new([row('e1', '2025-01-09')], existing)
    assert not RR.select_new([row('e1', '2025-01-10')], existing)
    assert not RR.select_new([row('e1', '2025-02-01')], existing)


def test_select_new_replaces_a_stored_reject_by_an_accepted_day_but_not_by_another_reject():
    existing = {'e1': {'any': True, 'accepted_min': None}}
    assert RR.select_new([row('e1', '2025-01-10')], existing)
    assert not RR.select_new([row('e1', '1971-01-01', 'rejected')], existing)
    assert not RR.select_new([row('e1', None, 'abstain')], existing)


def test_select_new_is_empty_when_rows_are_covered():
    events = {'e1': {'status': 'active', 'merged_into': None}}
    members = [{'event_id': 'e1', 'member_kind': 'claim', 'member_id': 'c1', 'role': 'member'}]
    rows = RR.build_rows(events, members, {'c1': D('2026-10-25')}, {}, D('2026-10-26'))
    assert len(rows) == 1
    existing = {'e1': {'any': True, 'accepted_min': D('2026-10-25')}}
    assert RR.select_new(rows, existing) == []


def test_new_event_from_a_new_leak_post_gets_the_post_day():
    events = {'e9': {'status': 'active', 'merged_into': None}}
    members = [{'event_id': 'e9', 'member_kind': 'claim', 'member_id': 'c9', 'role': 'member'}]
    rows = RR.build_rows(events, members, {'c9': D('2026-10-25')}, {}, D('2026-10-26'))
    assert [(r['value'], r['verdict'], r['source_kind']) for r in rows] == [('2026-10-25', 'accepted', 'leak')]


def test_implausible_member_date_does_not_hide_a_plausible_one():
    """A 1971-01-01 placeholder on one incident must not reject an event whose other member is dated 2025-06-30."""
    from zdc_breach.r2_reported import MemberDate
    ms = [MemberDate('incident', 'a', 'member', D('1971-01-01'), 'press'),
          MemberDate('incident', 'b', 'member', D('2025-06-30'), 'regulator')]
    assert RR.event_reported(ms, D('2026-10-26')) == ('accepted', D('2025-06-30'), 'regulator', None)
    only_bad = RR.event_reported(ms[:1], D('2026-10-26'))
    assert only_bad[0] == 'rejected' and only_bad[3] == 'implausible_year'
    future = ms + [MemberDate('claim', 'c', 'member', D('2027-01-01'), 'leak')]
    assert RR.event_reported(future, D('2026-10-26'))[1] == D('2025-06-30')


# ---- hourly job ------------------------------------------------------------------------------------------------------
def test_numbers_only_drops_every_string():
    out = H.numbers_only({'a': 1, 'name': 'Zzorvex', 'nested': {'n': 2.5, 'leak': 'x', 'ok': True}, 'list': [1, 2]})
    assert out == {'a': 1, 'nested': {'n': 2.5, 'ok': True}}
    assert 'Zzorvex' not in repr(out)


def test_last_json_line_ignores_noise():
    assert H.last_json_line('log line\n{"a": 1}\n') == {'a': 1}
    assert H.last_json_line('nothing here') is None
    assert H.last_json_line('{broken}') is None


def test_error_label_carries_class_and_sqlstate_only():
    class Boom(Exception):
        sqlstate = '57014'
    assert H.error_label(Boom('row data Zzorvex')) == 'Boom:57014'
    assert H.error_label(ValueError('secret')) == 'ValueError'


def test_hourly_order_missing_combined_skipped_and_shadow_runs_after_a_failed_step(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(H, 'coverage', lambda conn: {'listed_without_event': 0})
    monkeypatch.setattr(H, 'step_events', lambda conn, a: calls.append('events') or {'new_events': 3})

    def failing(conn, a):
        calls.append('reported')
        raise RuntimeError('row data Zzorvex')
    monkeypatch.setattr(H, 'step_reported', failing)
    monkeypatch.setattr(H, 'step_combined', lambda conn, a, rem: calls.append('combined'))     # None = module missing
    monkeypatch.setattr(H, 'step_shadow', lambda conn: calls.append('shadow') or {'rows': 5})
    a = SimpleNamespace(max_usd=0.5, combined_max_usd=0.5, deadline_min=25, workers=1, dry_run=False)
    report, code = H.run(a, conn=object())
    assert calls == ['events', 'reported', 'combined', 'shadow']
    assert code == 1
    assert report['steps']['reported'] == {'status': 'failed', 'error': 'RuntimeError', 'seconds': report['steps']['reported']['seconds']}
    assert report['steps']['combined']['status'] == 'skipped_module_missing'
    assert report['steps']['shadow']['status'] == 'ok'
    assert 'Zzorvex' not in repr(report)


def test_hourly_deadline_skips_steps_and_dry_run_skips_writes(monkeypatch):
    monkeypatch.setattr(H, 'coverage', lambda conn: {})
    calls = []
    monkeypatch.setattr(H, 'step_events', lambda conn, a: calls.append('events') or {})
    monkeypatch.setattr(H, 'step_reported', lambda conn, a: calls.append('reported') or {})
    a = SimpleNamespace(max_usd=0.5, combined_max_usd=0.5, deadline_min=-1, workers=1, dry_run=False)
    report, code = H.run(a, conn=object())
    assert calls == [] and code == 2 and report['steps']['events']['status'] == 'deadline'
    a.deadline_min = 25
    a.dry_run = True
    report, code = H.run(a, conn=object())
    assert calls == ['events', 'reported'] and code == 0
    assert report['steps']['shadow']['status'] == 'skipped_dry_run' and 'after' not in report


def test_combined_step_reports_missing_module(monkeypatch):
    monkeypatch.setattr(H.importlib.util, 'find_spec', lambda name: None)
    assert H.step_combined(None, SimpleNamespace(combined_max_usd=0.5), 600) is None


# ---- review round 2: unreleased press day, effective coverage, degraded ------------------------------------------------
def _claim_press_event(leak_day, press_day):
    events = {'e1': {'status': 'active', 'merged_into': None}}
    members = [{'event_id': 'e1', 'member_kind': 'claim', 'member_id': 'c1', 'role': 'member'},
               {'event_id': 'e1', 'member_kind': 'incident', 'member_id': 'i1', 'role': 'member'}]
    incidents = {'i1': {'first_public': D(press_day), 'kinds': {'press'}, 'doc_days': [D(press_day)]}}
    return RR.build_rows(events, members, {'c1': D(leak_day)}, incidents, D('2026-10-26'))


def test_press_day_equal_to_the_leak_post_day_also_gets_a_leak_labelled_row():
    rows = _claim_press_event('2025-03-02', '2025-03-02')
    assert sorted((r['source_kind'], r['basis'], r['value']) for r in rows) == [
        ('leak', 'leak_site', '2025-03-02'), ('press', 'published_at', '2025-03-02')]


def test_earlier_press_day_is_never_replaced_by_a_later_leak_post():
    rows = _claim_press_event('2025-03-10', '2025-03-02')
    assert [(r['source_kind'], r['value']) for r in rows] == [('press', '2025-03-02')]


def test_leak_twin_is_added_once_to_a_stored_press_row_and_then_never_again():
    rows = _claim_press_event('2025-03-02', '2025-03-02')
    stored = {'e1': {'any': True, 'accepted_min': D('2025-03-02'), 'kinds_at_min': {'press'}}}
    todo = RR.select_new(rows, stored)
    assert [(r['source_kind'], r['value']) for r in todo] == [('leak', '2025-03-02')]
    stored['e1']['kinds_at_min'] = {'press', 'leak'}
    assert RR.select_new(rows, stored) == []


def test_effective_null_sql_counts_unreleased_as_unknown():
    sql = H.effective_null_sql('reported_date')
    assert 'r2_reported_date is null' in sql and 'not r2_reported_date_released' in sql


def test_degraded_lists_skipped_and_failed_steps_but_not_ok_or_dry_run():
    steps = {'events': {'status': 'ok'}, 'reported': {'status': 'ok'}, 'combined': {'status': 'skipped_module_missing'},
             'shadow': {'status': 'skipped_dry_run'}}
    assert H.degraded(steps) == ['combined:skipped_module_missing']
    assert H.degraded({'events': {'status': 'failed'}}) == ['events:failed']


def test_report_marks_a_missing_combined_module_as_degraded(monkeypatch):
    monkeypatch.setattr(H, 'coverage', lambda conn: {})
    monkeypatch.setattr(H, 'step_events', lambda conn, a: {})
    monkeypatch.setattr(H, 'step_reported', lambda conn, a: {})
    monkeypatch.setattr(H, 'step_structured', lambda a, rem: {})
    monkeypatch.setattr(H, 'step_combined', lambda conn, a, rem: None)
    monkeypatch.setattr(H, 'step_shadow', lambda conn: {'rows': 1})
    a = SimpleNamespace(max_usd=0.5, combined_max_usd=0.5, deadline_min=25, workers=1, dry_run=False)
    report, code = H.run(a, conn=object())
    assert code == 0 and report['degraded'] == ['combined:skipped_module_missing']


def test_hourly_runs_structured_before_combined_and_combined_writes(monkeypatch):
    """New leak posts need the leak-site rule (structured step), and the combined step must pass --write."""
    order = []
    monkeypatch.setattr(H, 'coverage', lambda conn: {})
    monkeypatch.setattr(H, 'step_events', lambda conn, a: order.append('events') or {})
    monkeypatch.setattr(H, 'step_reported', lambda conn, a: order.append('reported') or {})
    monkeypatch.setattr(H, 'step_structured', lambda a, rem: order.append('structured') or {})
    monkeypatch.setattr(H, 'step_shadow', lambda conn: order.append('shadow') or {'rows': 1})
    seen = {}
    monkeypatch.setattr(H.importlib.util, 'find_spec', lambda name: object())
    monkeypatch.setattr(H.subprocess, 'run', lambda cmd, **kw: seen.setdefault('cmd', cmd) and SimpleNamespace(returncode=0, stdout='{}'))
    a = SimpleNamespace(max_usd=0.5, combined_max_usd=0.5, deadline_min=25, workers=1, dry_run=False)
    report, code = H.run(a, conn=object())
    assert order == ['events', 'reported', 'structured', 'shadow'] and code == 0
    assert '--write' in seen['cmd'] and '--new-only' in seen['cmd']
