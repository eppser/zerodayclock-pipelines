"""Integration tests: breach-reality-v1 against the migrated schema (0143).

Gated on BREACH_TEST_DATABASE_URL. Every test runs inside one transaction that is rolled back, because
breach_raw.victim_evidence is insert-only and cannot be cleaned up afterwards. Synthetic names only.
"""

from __future__ import annotations

import json
import os

import pytest

psycopg = pytest.importorskip("psycopg")
DSN = os.environ.get("BREACH_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DSN, reason="BREACH_TEST_DATABASE_URL not set")

from psycopg.types.json import Jsonb  # noqa: E402

from zdc_breach import reality as R  # noqa: E402

# group A: the same name, domain, country and actor seen in three weeks; group B: one claim
CLAIMS = [
    ('zzqa|zzquorvex dynamics|2099-01-05', 'zzqa', 'Zzquorvex Dynamics', 'zzquorvex dynamics', 'zzquorvex.example.org', 'DE', '2099-01-05'),
    ('zzqa|zzquorvex dynamics|2099-01-12', 'zzqa', 'Zzquorvex Dynamics', 'zzquorvex dynamics', 'zzquorvex.example.org', 'DE', '2099-01-12'),
    ('zzqa|zzquorvex dynamics|2099-01-19', 'zzqa', 'Zzquorvex Dynamics', 'zzquorvex dynamics', 'zzquorvex.example.org', 'DE', '2099-01-19'),
    ('zzqa|zzlorem family|2099-01-05', 'zzqa', 'Zzlorem Family', 'zzlorem family', None, None, '2099-01-05'),
]
REP_A, REP_B = CLAIMS[0][0], CLAIMS[3][0]
POOL = {
    REP_A: {'claim_key': REP_A, 'name': 'Zzquorvex Dynamics', 'wikidata': [],
            'candidates': [{'host': 'zzquorvex.example.org', 'sources': ['tracker_domain'], 'dns': True, 'status': 200, 'live': True,
                            'title': 'Zzquorvex Dynamics GmbH', 'og_site_name': None, 'parked': False, 'historic': False}]},
    REP_B: {'claim_key': REP_B, 'name': 'Zzlorem Family', 'candidates': [], 'wikidata': []},
}
EXTRAS = {REP_A: {'claim_key': REP_A, 'tls': {'zzquorvex.example.org': {'O': None}}, 'gleif': [], 'edgar': []}}
GROUPS = {REP_A: [c[0] for c in CLAIMS[:3]], REP_B: [REP_B]}


@pytest.fixture
def conn():
    c = psycopg.connect(DSN, autocommit=True)
    try:
        with c.transaction(force_rollback=True):
            with c.cursor() as cur:
                for k, g, n, nn, d, cc, f in CLAIMS:
                    cur.execute("""insert into breach_core.leak_claims (claim_key, actor_group, victim_name, victim_norm, victim_domain,
                                       country, first_seen_at, last_seen_at, trackers, tracker_refs)
                                   values (%s, %s, %s, %s, %s, %s, %s, %s, array['ransomlook'], %s)""",
                                (k, g, n, nn, d, cc, f, f, Jsonb([{'source_id': 'ransomlook', 'id': 'zz-' + k}])))
                # a leak post whose text names a domain: only the domain may leave SQL
                cur.execute("""insert into breach_raw.source_records (source_id, source_record_id, version, content_hash, record)
                               values ('ransomlook', %s, 1, 'h', %s)""",
                            ('zz-' + REP_A, Jsonb({'description': 'Secret files of the victim, see www.zzquorvex-dyn.com for more'})))
            yield c
    finally:
        c.close()


def files(tmp_path):
    for name, data in (('pool.jsonl', POOL), ('extras.jsonl', EXTRAS)):
        (tmp_path / name).write_text(''.join(json.dumps(v) + '\n' for v in data.values()))
    (tmp_path / 'groups.json').write_text(json.dumps(GROUPS))
    return tmp_path / 'pool.jsonl', tmp_path / 'extras.jsonl', tmp_path / 'groups.json'


def rows(conn):
    with conn.cursor() as cur:
        cur.execute("""select claim_key, label, subtype, via, used, natural_person_risk, domain_candidate, method_version,
                              evidence_sha256, lexicon_sha256
                         from breach_core.victim_checks where claim_key like 'zzqa|%%' order by claim_key""")
        return cur.fetchall()


def test_load_packs_is_idempotent(conn, tmp_path):     # mutant: insert without on-conflict / pack not canonical
    rep = R.cmd_load_packs(conn, *files(tmp_path))
    assert (rep['raw_new'], rep['checks_written'], rep['groups']) == (4, 4, 2)
    again = R.cmd_load_packs(conn, *files(tmp_path))
    assert again['raw_new'] == 0
    with conn.cursor() as cur:
        cur.execute("select count(*) from breach_raw.victim_evidence where claim_key like 'zzqa|%%'")
        assert cur.fetchone()[0] == 4


def test_group_fan_out_shares_pack_and_decision(conn, tmp_path):   # mutant: members decided on their own (empty) pack
    R.cmd_load_packs(conn, *files(tmp_path))
    got = {r[0]: r for r in rows(conn)}
    a = [got[k] for k in GROUPS[REP_A]]
    assert len({json.dumps(r[1:], default=str) for r in a}) == 1
    assert a[0][1:4] == ('real_org', None, 'E1') and a[0][6] == 'zzquorvex.example.org'
    assert got[REP_B][1] == 'ambiguous' and got[REP_B][5] is True          # person-like, flagged for review


def test_leak_post_domain_reaches_pack_but_text_does_not(conn, tmp_path):   # mutant: description returned by the query
    R.cmd_load_packs(conn, *files(tmp_path))
    with conn.cursor() as cur:
        cur.execute("select pack from breach_raw.victim_evidence where claim_key = %s", (REP_A,))
        pack = cur.fetchone()[0]
    assert pack['leakmeta']['desc_domains'] == ['zzquorvex-dyn.com']
    assert 'Secret files' not in json.dumps(pack)


def test_decide_reproduces_identical_rows(conn, tmp_path):   # mutant: decide reads a different pack / lexicon
    R.cmd_load_packs(conn, *files(tmp_path))
    before = rows(conn)
    with conn.cursor() as cur:   # scramble the decisions, then re-derive them from the stored packs
        cur.execute("update breach_core.victim_checks set label = 'ambiguous', via = 'x', domain_candidate = null where claim_key like 'zzqa|%%'")
    rep = R.cmd_decide(conn)
    assert rows(conn) == before
    assert rep['checks_written'] >= 4


def test_raw_pack_is_insert_only(conn, tmp_path):     # mutant: trigger missing
    R.cmd_load_packs(conn, *files(tmp_path))
    with pytest.raises(psycopg.errors.RaiseException), conn.transaction(), conn.cursor() as cur:
        cur.execute("update breach_raw.victim_evidence set method_version = 'x' where claim_key = %s", (REP_A,))


def test_run_selects_unchecked_then_stale_ambiguous(conn):   # mutant: re-checks fresh or decided claims
    calls = []

    def fake(it):
        calls.append(it['claim_key'])
        pool = next(v for v in POOL.values() if v['name'] == it['name_raw'])
        return dict(pool, claim_key=it['claim_key']), {}, \
            __import__('datetime').datetime(2099, 2, 1, tzinfo=__import__('datetime').timezone.utc)
    rep = R.cmd_run(conn, limit=4, deadline_min=5, workers=2, harvester=fake)
    assert sorted(calls) == sorted([CLAIMS[2][0], REP_B])   # one harvest per name group (newest claim), not per claim
    assert rep['claims'] == 4 and rep['groups'] == 2
    assert json.dumps(rep).find('Zz') == -1                 # counts only: no name in the public report
    with conn.cursor() as cur:
        cur.execute("update breach_core.victim_checks set checked_at = now() - interval '100 days' where claim_key = %s", (REP_B,))
        cur.execute("update breach_core.victim_checks set checked_at = now() - interval '100 days', label = 'real_org' where claim_key = %s", (REP_A,))
        stale = [i['claim_key'] for i in R.select_claims(cur, 100000) if i['claim_key'].startswith('zzqa|')]
    assert stale == [REP_B]


def test_tables_are_private(conn):                      # mutant: grants left to anon
    with conn.cursor() as cur:
        for t in ('breach_raw.victim_evidence', 'breach_core.victim_checks'):
            cur.execute("select has_table_privilege('anon', %s, 'select') or has_table_privilege('authenticated', %s, 'select')", (t, t))
            assert cur.fetchone()[0] is False


# ---- recorded runs: the watchdog's view (READINESS B) ----------------------------------------------------------
def _last_run(conn):
    with conn.cursor() as cur:
        cur.execute("select ok, error from raw.pipeline_runs where pipeline = 'breach-reality' order by started_at desc limit 1")
        return cur.fetchone()


def test_recorded_run_writes_a_run_row(conn):              # mutant: no run row, so the watchdog sees silence
    def fake(it):
        pool = next(v for v in POOL.values() if v['name'] == it['name_raw'])
        return dict(pool, claim_key=it['claim_key']), {}, __import__('datetime').datetime(2099, 2, 1, tzinfo=__import__('datetime').timezone.utc)
    rep, code = R.run_recorded(conn, 4, 5, 2, harvester=fake)
    assert code == 0 and _last_run(conn) == (True, None)


def test_outage_is_a_failed_run_not_an_answer(conn, monkeypatch):   # mutant: an empty harvest recorded as a good run
    monkeypatch.setattr(R, 'OUTAGE_MIN_CLAIMS', 1)
    def down(it):                                          # every lookup failed: no candidates, no registry hits
        return {'claim_key': it['claim_key'], 'name': it['name_raw'], 'candidates': [], 'wikidata': []}, {}, \
            __import__('datetime').datetime(2099, 2, 1, tzinfo=__import__('datetime').timezone.utc)
    rep, code = R.run_recorded(conn, 4, 5, 2, harvester=down)
    ok, err = _last_run(conn)
    assert code == 6 and ok is False and 'outage' in err
