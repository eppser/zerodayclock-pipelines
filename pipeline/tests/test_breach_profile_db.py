"""Integration tests: breach-profile-v1 against the migrated schema (0145).

Gated on BREACH_TEST_DATABASE_URL. Every test runs inside one transaction that is rolled back (breach_raw is
insert-only). Synthetic names and text only. Jev is a fake transport: no network.
"""

from __future__ import annotations

import json
import os

import pytest

psycopg = pytest.importorskip("psycopg")
DSN = os.environ.get("BREACH_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DSN, reason="BREACH_TEST_DATABASE_URL not set")

from psycopg.types.json import Jsonb  # noqa: E402

from zdc_breach import profile as P  # noqa: E402

KEY = 'zz-test-key-not-real'
TEMPLATE = 'Zz group template line about everything.'
# claim_key, group, name, first_seen, description, listed, checked(label, npr)
CLAIMS = [
    ('zzpa|zzalpha|2099-03-05', 'zzpa', 'Zzalpha Widgets', '2099-03-05',
     'Zzalpha Widgets makes garden tools in a small town. Patient records and invoices were taken, 2 TB of files. '
     'Contact us on tox.', True, ('real_org', False)),
    ('zzpa|zzbeta|2099-03-04', 'zzpa', 'Zzbeta Tools', '2099-03-04',
     'Zzbeta Tools sells hand tools to local shops. Zzbeta Tools was founded by two brothers long ago. Invoices were taken.',
     True, ('real_org', False)),
    ('zzpa|zzgamma|2099-03-03', 'zzpa', 'Zzgamma Mills', '2099-03-03',
     'Zzgamma Mills grinds flour for regional bakeries. Invoices were taken.', False, None),
    ('zzpa|zzdelta|2099-03-02', 'zzpa', 'Zzdelta Lorem', '2099-03-02',
     'Zzdelta Lorem runs a quiet bookshop near the river. Invoices were taken.', True, ('ambiguous', True)),
] + [   # five posts of group zzpb share a template sentence
    (f'zzpb|zzepsilon{i}|2099-02-0{i}', 'zzpb', f'Zzepsilon{i} Farm', f'2099-02-0{i}',
     f'Zzepsilon{i} Farm grows apples on a hill. {TEMPLATE}', True, ('real_org', False)) for i in range(1, 6)
]


def fake_transport(calls):
    """Answers from the synthetic text: a sentence starting with the victim's name is profile, 'tox' is contact,
    the rest data_summary; tags from keywords; every volume candidate is stolen data; a fixed size distribution."""
    def t(method, url, headers, body, timeout):
        assert headers['Authorization'] == 'Bearer ' + KEY
        req = json.loads(body)
        calls.append(req)
        st, A = req['state'], {}
        for qid, q in req['questions'].items():
            pid, rest = qid.split('_', 1)
            if 'organisations' in st:
                A[qid] = {'type': 'score', 'probabilities': {'0': 0, '1': 0, '2': 0.1, '3': 0.7, '4': 0.2}}
                continue
            v = st['victims'][pid]
            text = ' '.join(v['leak_text'].values()).lower()
            if rest.startswith('t_'):
                tag = rest[2:]
                hit = {'health': 'patient records' in text, 'financial_corporate': 'invoices' in text,
                       'unspecified': 'template' in text}.get(tag, False)
                A[qid] = {'type': 'noul', 'noul': 0.95 if hit else 0.02}
            elif rest.startswith('c_'):
                s = v['leak_text'][rest[2:]]
                cls = 'profile' if s.startswith(v['name']) else ('contact_instructions' if 'tox' in s else 'data_summary')
                pr = {c: 0.0 for c in P.CLASSES}
                pr[cls] = 0.97
                pr['other'] = 0.03
                A[qid] = {'type': 'choice', 'choice': cls, 'probabilities': pr}
            else:
                A[qid] = {'type': 'noul', 'noul': 0.9}
        return 200, {}, {'answers': A, 'model': 'jev-1.13.0', 'usage': {'input_tokens': 1000, 'output_tokens': 10}}
    return t


@pytest.fixture
def conn():
    c = psycopg.connect(DSN, autocommit=True)
    try:
        with c.transaction(force_rollback=True):
            with c.cursor() as cur:
                # start from the 0145 defaults whatever later migrations (0146) set; rolled back after the test
                cur.execute("update breach_core.profile_settings set shipping_groups = '{}', descriptions_enabled = false, volumes_enabled = false")
                for k, g, n, f, d, listed, check in CLAIMS:
                    cur.execute("""insert into breach_core.leak_claims (claim_key, actor_group, victim_name, victim_norm, victim_domain,
                                       country, first_seen_at, last_seen_at, trackers, tracker_refs)
                                   values (%s, %s, %s, lower(%s), null, 'DE', %s, %s, array['ransomlook'], %s)""",
                                (k, g, n, n, f, f, Jsonb([{'source_id': 'ransomlook', 'id': 'zz-' + k}])))
                    cur.execute("""insert into breach_raw.source_records (source_id, source_record_id, version, content_hash, record)
                                   values ('ransomlook', %s, 1, 'h', %s)""", ('zz-' + k, Jsonb({'description': d})))
                    if listed:
                        cur.execute("insert into breach_core.victims_list (victim_id, name, country, industry) values (%s, %s, 'DE', 'Manufacturing')",
                                    ('claim:' + k, n))
                    if check:
                        cur.execute("""insert into breach_raw.victim_evidence (claim_key, method_version, harvested_at, pack, pack_sha256)
                                       values (%s, 'breach-reality-v1', '2099-04-01', '{"pool": {}, "extras": {}, "leakmeta": null, "corrob": []}', %s)""",
                                    (k, 'f' * 64))
                        cur.execute("""insert into breach_core.victim_checks (claim_key, label, via, method_version, evidence_sha256, natural_person_risk)
                                       values (%s, %s, 'none', 'breach-reality-v1', %s, %s)""", (k, check[0], 'f' * 64, check[1]))
            yield c
    finally:
        c.close()


def run(conn, limit=50, max_usd=5.0):
    calls = []
    budget = P.Budget(max_usd)
    jev = P.Jev(budget, key=KEY, transport=fake_transport(calls), sleep=lambda s: None)
    return P.cmd_run(conn, limit, 5, max_usd, jev=jev, budget=budget), calls


def q(conn, sql, *args):
    with conn.cursor() as cur:
        cur.execute(sql, args)
        return cur.fetchall()


PROFILE_COLS = "claim_key, method_version, model, q_hash, description_sha256, tracker, as_of, profile_tags, profile_groups, volumes, size_band_est, size_p_top"
SENT_COLS = "claim_key, sid, text, cls, p_cls, p_personal, p_sample, boilerplate, shown"


def snapshot(conn):
    return (q(conn, f"select {PROFILE_COLS} from breach_core.victim_profiles where claim_key like 'zzp%%' order by 1"),
            q(conn, f"select {SENT_COLS} from breach_core.victim_description_sentences where claim_key like 'zzp%%' order by 1, 2"))


def test_run_writes_and_is_idempotent(conn):        # mutant: the skip on (method, description sha) removed -> re-asks and re-pays
    rep, calls = run(conn)
    assert rep['selected'] == rep['written'] == len(CLAIMS) and rep['stopped'] is None
    assert len(q(conn, "select 1 from breach_core.victim_profiles where claim_key like 'zzp%%'")) == len(CLAIMS)
    again, calls2 = run(conn)
    assert again['selected'] == 0 and calls2 == []


def test_newest_first_and_limit(conn):              # mutant: oldest first
    rep, _ = run(conn, limit=1)
    assert q(conn, "select claim_key from breach_core.victim_profiles where claim_key like 'zzp%%'") == [('zzpa|zzalpha|2099-03-05',)]


def test_changed_description_is_reprofiled(conn):   # mutant: a new record version ignored (stale answers kept)
    run(conn)
    with conn.cursor() as cur:
        cur.execute("""insert into breach_raw.source_records (source_id, source_record_id, version, content_hash, record)
                       values ('ransomlook', 'zz-zzpa|zzbeta|2099-03-04', 2, 'h2', %s)""",
                    (Jsonb({'description': 'Zzbeta Tools sells hand tools. Patient records were taken.'}),))
    rep, _ = run(conn)
    assert rep['selected'] == 1
    assert q(conn, "select profile_tags from breach_core.victim_profiles where claim_key = 'zzpa|zzbeta|2099-03-04'") == [(['health'],)]


def test_decisions_and_privacy(conn):               # mutant: hidden text stored; size asked for unchecked / person-risk names
    rep, calls = run(conn)
    alpha = q(conn, "select profile_tags, profile_groups, volumes, size_band_est from breach_core.victim_profiles where claim_key = 'zzpa|zzalpha|2099-03-05'")[0]
    assert alpha[0] == ['health', 'financial_corporate'] and alpha[1] == ['health', 'finance']
    assert [(v['unit'], v['value'], v['qualifier']) for v in alpha[2]] == [('bytes', 2_000_000_000_000, 'exact')]
    assert alpha[3] == 'large'
    # alpha's contact sentence vetoes the whole description; no hidden text is ever stored
    assert q(conn, "select count(*) from breach_core.victim_description_sentences where claim_key = 'zzpa|zzalpha|2099-03-05' and shown") == [(0,)]
    assert q(conn, "select count(*) from breach_core.victim_description_sentences where claim_key like 'zzp%%' and not shown and text is not null") == [(0,)]
    # size: only checked, unflagged names are asked (gamma unchecked, delta person risk)
    sized = {o['name'] for c in calls if 'organisations' in c['state'] for o in c['state']['organisations'].values()}
    assert 'Zzgamma Mills' not in sized and 'Zzdelta Lorem' not in sized and 'Zzalpha Widgets' in sized
    assert q(conn, "select size_band_est from breach_core.victim_profiles where claim_key in ('zzpa|zzgamma|2099-03-03', 'zzpa|zzdelta|2099-03-02')") == [(None,), (None,)]
    # the report carries counts only: no description text, no key
    blob = json.dumps(rep, default=str)
    assert KEY not in blob and 'garden' not in blob and 'Zz' not in blob


def test_boilerplate(conn):                         # mutant: templates computed per claim instead of per group, or shown
    run(conn)
    rows = q(conn, """select bool_and(boilerplate), bool_or(shown) from breach_core.victim_description_sentences
                       where claim_key like 'zzpb|%%' and sid = 's2'""")
    assert rows == [(True, False)]
    assert q(conn, "select count(*) from breach_core.victim_description_sentences where claim_key like 'zzpb|%%' and sid = 's1' and shown") == [(5,)]


def test_rescore_reproduces_rows(conn):             # mutant: rescore uses other rules than run, or does not rewrite
    run(conn)
    before = snapshot(conn)
    with conn.cursor() as cur:
        cur.execute("update breach_core.victim_profiles set profile_tags = '{}', profile_groups = '{}', volumes = '[]', size_band_est = null where claim_key like 'zzp%%'")
        cur.execute("delete from breach_core.victim_description_sentences where claim_key like 'zzp%%'")
    rep = P.cmd_rescore(conn)
    assert rep['errors'] == {} and rep['written'] >= len(CLAIMS)
    assert snapshot(conn) == before


def test_budget_stops_cleanly(conn):                # mutant: budget ignored, or the stop raises instead of writing what was answered
    rep, calls = run(conn, max_usd=0.042 * 1000 / 1e6)      # exactly one call of 1,000 input tokens
    assert rep['stopped'] == 'budget' and len(calls) == 1 and rep['usd'] <= 0.042 * 1000 / 1e6 + 1e-12


def test_public_views_gate(conn):                   # mutant: switches ignored; unlisted / person-risk / unchecked claims published
    run(conn)
    pub = "select victim_id, profile_groups, volumes from public.breach_victim_profiles where victim_id like 'claim:zzp%%' order by 1"
    desc = "select victim_id, sentences from public.breach_victim_descriptions where victim_id like 'claim:zzpa%%' order by 1"
    assert q(conn, pub) == [] and q(conn, desc) == []
    with conn.cursor() as cur:
        cur.execute("update breach_core.profile_settings set shipping_groups = array['finance'], descriptions_enabled = true")
    rows = q(conn, pub)
    assert [r[0] for r in rows] == ['claim:zzpa|zzalpha|2099-03-05', 'claim:zzpa|zzbeta|2099-03-04']   # not gamma (unlisted), not delta (person risk)
    assert rows[0][1] == ['finance'] and rows[0][2] == []                                            # health withheld; volumes off
    d = q(conn, desc)
    assert d == [('claim:zzpa|zzbeta|2099-03-04', ['Zzbeta Tools sells hand tools to local shops.',
                                                    'Zzbeta Tools was founded by two brothers long ago.'])]
    cols = q(conn, """select column_name from information_schema.columns where table_schema = 'public'
                       and table_name in ('breach_victim_profiles', 'breach_victim_descriptions')""")
    assert not [c for (c,) in cols if 'size' in c or c == 'profile_tags']


# ---- recorded runs: the watchdog's view (READINESS B) ----------------------------------------------------------
from argparse import Namespace


def models_and(calls, offered=('jev-1.13.0',), status=200, out_of_funds=False):
    inner = fake_transport(calls)
    def t(method, url, headers, body, timeout):
        if method == 'GET':
            return 200, {}, {'data': [{'id': m} for m in offered]}
        if out_of_funds:
            return 402, {}, {'error': 'insufficient credit balance'}
        return inner(method, url, headers, body, timeout)
    return t


def recorded(conn, transport, monthly=10.0):
    args = Namespace(limit=50, deadline_min=5, max_usd=5.0, monthly_usd=monthly)
    return P.run_recorded(conn, args, transport=transport, key=KEY, sleep=lambda s: None)


def last_run(conn):
    return q(conn, "select ok, error, notes->>'usd' from raw.pipeline_runs where pipeline = 'breach-profile' order by started_at desc limit 1")[0]


def test_recorded_run_is_a_successful_run_row(conn):   # mutant: no run row, so the watchdog sees silence
    rep, code = recorded(conn, models_and([]))
    ok, err, usd = last_run(conn)
    assert code == 0 and ok and err is None and float(usd) > 0 and rep['profiled'] > 0


def test_monthly_ceiling_stops_and_fails(conn):         # mutant: per-run cap only (~150 USD/month worst case)
    recorded(conn, models_and([]))
    rep, code = recorded(conn, models_and([]), monthly=0.000001)
    ok, err, _ = last_run(conn)
    assert code == P.EXIT_CEILING and not ok and 'ceiling' in err and rep['profiled'] == 0


def test_pinned_model_withdrawn_fails_loudly(conn):     # mutant: model list ignored
    rep, code = recorded(conn, models_and([], offered=('jev-2.0.0',)))
    ok, err, _ = last_run(conn)
    assert code == P.EXIT_MODEL_GONE and not ok and 'jev-1.13.0' in err and rep['profiled'] == 0


def test_out_of_funds_is_a_failed_run(conn):            # mutant: out of funds recorded as ok (green and silent)
    rep, code = recorded(conn, models_and([], out_of_funds=True))
    ok, err, _ = last_run(conn)
    assert code == P.EXIT_OUT_OF_FUNDS and not ok and 'funds' in err
