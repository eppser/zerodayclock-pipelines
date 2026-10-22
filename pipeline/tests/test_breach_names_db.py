"""Integration tests: breach-names-v1 against the migrated schema (0172).

Gated on BREACH_TEST_DATABASE_URL. Each test runs inside one transaction that is rolled back. Synthetic names and text
only; Jev is a fake transport, no network.
"""

from __future__ import annotations

import json
import os

import pytest

psycopg = pytest.importorskip("psycopg")
DSN = os.environ.get("BREACH_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DSN, reason="BREACH_TEST_DATABASE_URL not set")

from psycopg.types.json import Jsonb  # noqa: E402

from zdc_breach import names as N  # noqa: E402
from zdc_breach import profile as P  # noqa: E402

KEY = 'zz-test-key-not-real'
# claim_key, actor, title, first seen, description
CLAIMS = [
    ('zzn|plain', 'zzgang', 'Zzquorvexmotors', '2099-01-15', 'Zzquorvex Motors builds electric cars.'),
    ('zzn|endgame', 'zzgang', 'THE ENDGAME OF ZZQUORVEX MOTORS’ PSYCHOLOGICAL GAME', '2099-03-01', 'The Zzquorvex Motors board stays silent.'),
    ('zzn|failed', 'zzgang', 'They Failed. 100GB Drops in 2 Days', '2099-03-20', 'Zzquorvex Motors failed to respond.'),
    ('zzn|caps', 'zzgang', 'ZZQUORVEX’S SECRETS ARE UNRAVELED', '2099-03-21', 'We watched ZZQUORVEX for months.'),
    ('zzn|rival', 'zzgang', 'Hacked Zzrival', '2099-03-02', "Next time, don't play with the big boys."),
    ('zzn|rivalown', 'zzrival', 'Zzsomeone Ltd leak', '2099-02-01', ''),          # makes zzrival an actor group
    ('zzn|two', 'zzgang', 'Zzalpha Tools, Zzbeta Foods leaked', '2099-03-03', 'Zzalpha Tools runs one network with Zzbeta Foods.'),
    ('zzn|other', 'zzother', 'Zzquorvex Motors - Database Leaked', '2099-03-02', ''),
    ('zzn|hidden', 'zzgang', 'Important Announcement: Zzquorvex Motors data leak', '2099-03-04', 'Zzquorvex Motors.'),
]


def fake_transport(calls):
    def t(method, url, headers, body, timeout):
        assert headers['Authorization'] == 'Bearer ' + KEY
        req = json.loads(body)
        calls.append(req)
        A = {}
        for qid in req['questions']:
            pid, c = qid.split('_')
            name = req['state']['posts'][pid]['candidates'][c].lower().replace(' ', '')
            A[qid] = {'type': 'noul', 'noul': 0.95 if any(x in name for x in ('zzquorvex', 'zzalpha', 'zzbeta', 'zzrival')) else 0.05}
        return 200, {}, {'answers': A, 'model': 'jev-1.13.0', 'usage': {'input_tokens': 500, 'output_tokens': 5}}
    return t


@pytest.fixture
def conn():
    c = psycopg.connect(DSN, autocommit=True)
    try:
        with c.transaction(force_rollback=True):
            with c.cursor() as cur:
                for k, a, n, f, d in CLAIMS:
                    cur.execute("""insert into breach_core.leak_claims (claim_key, actor_group, victim_name, victim_norm, first_seen_at,
                                       last_seen_at, trackers, tracker_refs)
                                   values (%s, %s, %s, lower(%s), %s, %s, array['ransomlook'], %s)""",
                                (k, a, n, n + ' ' + k, f, f, Jsonb([{'source_id': 'ransomlook', 'id': 'zz-' + k}])))
                    cur.execute("""insert into breach_raw.source_records (source_id, source_record_id, version, content_hash, record)
                                   values ('ransomlook', %s, 1, 'h', %s)""", ('zz-' + k, Jsonb({'description': d, 'post_title': n})))
            yield c
    finally:
        c.close()


def resolve(conn, **kw):
    calls = []
    budget = P.Budget(5)
    jev = P.Jev(budget, key=KEY, transport=fake_transport(calls), sleep=lambda s: None)
    rep = N.cmd_resolve(N.psycopg_query(conn), conn, mode='run', limit=100, deadline_min=5, max_usd=5, jev=jev, budget=budget, **kw)
    return rep, calls


def rows(conn, sql, *a):
    with conn.cursor() as cur:
        cur.execute(sql, a or None)
        return cur.fetchall()


def test_run_writes_resolutions_and_one_spelling(conn):
    rep, calls = resolve(conn)
    got = dict(rows(conn, "select claim_key, reason from breach_core.victim_name_resolution where claim_key like 'zzn|%'"))
    assert 'zzn|plain' not in got                                    # not title-like: never resolved
    assert 'zzn|hidden' not in got                                   # hidden by 0149: not listed, never resolved
    assert got['zzn|rival'] == 'abstain_none'                        # another actor group is never the victim
    assert got['zzn|two'] == 'abstain_several'
    res = dict(rows(conn, "select claim_key, resolved_name from breach_core.victim_name_resolution where reason = 'renamed' and claim_key like 'zzn|%'"))
    assert res['zzn|endgame'] == res['zzn|failed'] == 'Zzquorvex Motors'
    assert res['zzn|caps'] == 'Zzquorvex Motors'                     # 'ZZQUORVEX' takes the group's confirmed spelling
    assert rep['canonical_changed'] >= 1 and rep['written'] == len(got)
    assert 'Zzquorvex' not in json.dumps(rep, default=str)           # the report is counts only
    # a second run asks nothing: everything is resolved
    rep2, calls2 = resolve(conn)
    assert rep2['selected'] == 0 and not calls2


def test_the_list_shows_the_company_and_groups_the_posts(conn):
    resolve(conn)
    with conn.cursor() as cur:
        cur.execute("select breach_core.rebuild_victims_list()")
    lst = {r[0]: r[1:] for r in rows(conn, """select victim_id, name, post_count, post_title, posts from breach_core.victims_list
                                               where victim_id like 'claim:zzn|%'""")}
    entry = lst['claim:zzn|plain']                                   # the window's first post is the entry
    assert entry[0] == 'Zzquorvex Motors' and entry[1] == 4
    assert [p['post_title'] for p in entry[3]][1:] == ['THE ENDGAME OF ZZQUORVEX MOTORS’ PSYCHOLOGICAL GAME',
                                                       'They Failed. 100GB Drops in 2 Days', 'ZZQUORVEX’S SECRETS ARE UNRAVELED']
    assert 'claim:zzn|endgame' not in lst
    assert lst['claim:zzn|other'][1] == 1                            # another group's post is its own entry
    assert lst['claim:zzn|two'][0] == 'Zzalpha Tools, Zzbeta Foods leaked'   # two companies: listed as it was
    assert 'claim:zzn|hidden' not in lst                             # 0149 still reads the original title


def test_dry_run_writes_nothing(conn, tmp_path):
    plan = tmp_path / 'plan.json'
    rep, _ = resolve(conn, dry_run=True, plan=str(plan))
    assert rep['written'] == 0 and rep['reasons'].get('renamed', 0) >= 3
    assert rows(conn, "select count(*) from breach_core.victim_name_resolution where claim_key like 'zzn|%'")[0][0] == 0
    assert json.loads(plan.read_text())['groups']


def test_group_key_matches_sql():
    names = ['Zz Motors, Inc.', 'zzmotors.com', 'www.zzmotors.co.uk', 'ZZ MOTORS', 'Zz Mötörs', 'Zz Motors Group', 'Zzacme S.p.A.',
             'Zzbank Ltd.', 'https://www.zzsite.org', 'Zzfirm (Zz)', 'ŞZz İnşaat', '株式会社Zz', '', 'Zz-Data Business Systems',
             'zz.k12.mi.us', 'Zz & Co', 'zz.com.br', 'Zz plc']
    with psycopg.connect(DSN) as c, c.cursor() as cur:
        cur.execute("select n, breach_core.victim_group_key(n) from unnest(%s::text[]) n", (names,))
        for n, k in cur.fetchall():
            assert k == N.group_key(n), n


def test_the_resolution_table_is_private():
    with psycopg.connect(DSN) as c, c.cursor() as cur:
        for role in ('anon', 'authenticated'):
            cur.execute("select has_table_privilege(%s, 'breach_core.victim_name_resolution', 'select')", (role,))
            assert cur.fetchone()[0] is False
