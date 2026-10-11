"""zdc_prio end-to-end against a migrated database, with synthetic data and fake EPSS files.

Runs only when PRIO_TEST_DATABASE_URL points at a THROWAWAY database with every migration
applied (CI's service container; never a Supabase project: the fixture deletes rows). The
month scored is March 2034, far from any real data, and everything synthetic is removed after.

What it proves that the unit tests cannot: the SQL runs against the real schema and returns
what compute.py expects, store() writes what the view serves, --if-due catches up and stops,
and the refusal and waiting paths behave as documented.
"""

from __future__ import annotations

import os
from datetime import date, timedelta

import psycopg
import pytest

from zdc_prio import run as prio_run
from zdc_prio.compute import MonthInputs, score_month

DSN = os.environ.get("PRIO_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DSN, reason="needs PRIO_TEST_DATABASE_URL")

M = date(2034, 3, 1)
NXT = date(2034, 4, 1)
N_EPSS = 200_000
ATTACKED = [f"CVE-2034-{10000 + i}" for i in range(400)]      # attacked in March
SEEN = set(ATTACKED[:300])                                    # also attacked in February
NEW = ATTACKED[300:]                                          # newly targeted: 100
HEARTBEAT = "CVE-2033-99999"                                  # every day, not in EPSS


def epss_files(month_scores: dict) -> dict:
    base = {f"CVE-2034-{200000 + i}": 0.0005 for i in range(N_EPSS - len(ATTACKED))}
    start = {**base, **{c: 0.001 for c in ATTACKED}}
    for c in NEW[:60] + ATTACKED[:200]:
        start[c] = 0.2                                        # 60 new and 200 repeat targets above 10%
    nxt = dict(start)
    for i in range(1000):
        nxt[f"CVE-2034-{900000 + i}"] = 0.0001                # 1,000 new CVEs in April's file
    nxt[ATTACKED[0]] = 0.05                                    # one rises past 3% during March
    month_scores.update({M: start, NXT: nxt})
    return month_scores


SEED = """
insert into raw.pipeline_runs (pipeline, mode, trigger) values ('prio-test', 'full', 'test');
insert into raw.source_fetches (run_id, source_id, url, request_mode, ok, http_status)
select run_id, s, 'https://example.invalid/' || s, 'full', true, 200
  from raw.pipeline_runs, unnest(array['cisa', 'vulncheck']) s where pipeline = 'prio-test';
insert into obs_raw.pipeline_runs (pipeline, mode, trigger) values ('prio-test', 'full', 'test');
insert into obs_raw.source_fetches (run_id, source_id, url, request_mode, ok, http_status)
select run_id, s, 'https://example.invalid/' || s, 'full', true, 200
  from obs_raw.pipeline_runs, unnest(array['shadowserver_api', 'crowdsec']) s where pipeline = 'prio-test';
"""
CVES = """
insert into core.cves (cve_id, cve_year, date_published, cna_cvss_score)
select c, 2034, timestamptz '2034-01-01', case when i %% 4 = 0 then 9.8 else 5.0 end
  from unnest(%(attacked)s::text[]) with ordinality as a(c, i)
on conflict (cve_id) do nothing
"""

OBS = """
insert into obs_core.exploitation_observations (
    source_id, source_entry_id, observation_type, vuln_id, vuln_id_type, cve_id,
    observed_at, observation_count, product_key, product, vendor, device_class,
    raw, content_hash, first_fetch_id, last_fetch_id)
select x.src, x.cve || '@' || x.d, 'attempt_observed', x.cve, 'cve', x.cve, x.d, 3,
       'P', 'P', 'V', 'router', '{}'::jsonb, md5(x.src || x.cve || x.d),
       f.fetch_id, f.fetch_id
  from (select %(src)s::text src, unnest(%(cves)s::text[]) cve, unnest(%(days)s::date[]) d) x
 cross join lateral (select fetch_id from obs_raw.source_fetches
                      where source_id = x.src limit 1) f
"""

KEV = """
insert into core.kev_entries (source_id, upstream_source, source_entry_id, vuln_id, vuln_id_type,
    cve_id, date_added, raw, content_hash, first_fetch_id, last_fetch_id, first_seen_at)
select %(src)s, %(src)s, %(cve)s, %(cve)s, 'cve', %(cve)s, %(added)s, %(raw)s::jsonb, md5(%(cve)s),
       f.fetch_id, f.fetch_id, %(seen)s
  from (select fetch_id from raw.source_fetches where source_id = %(src)s limit 1) f
"""


def days(a: date, b: date) -> list[date]:
    return [a + timedelta(days=i) for i in range((b - a).days + 1)]


def cleanup(cx) -> None:
    cx.execute("delete from derived.patch_prioritisation where month >= '2034-01-01'")
    cx.execute("delete from core.kev_entries where cve_id like 'CVE-2034-%'")
    cx.execute("delete from obs_core.exploitation_observations where cve_id like 'CVE-2034-%%' "
               "or cve_id = %s", (HEARTBEAT,))
    cx.execute("delete from core.cves where cve_id like 'CVE-2034-%'")
    cx.commit()


@pytest.fixture()
def db(monkeypatch):
    cx = psycopg.connect(DSN)
    cleanup(cx)
    cx.execute(SEED)
    cx.execute(CVES, {"attacked": ATTACKED})
    lookback = M - timedelta(days=50)
    end = NXT - timedelta(days=1)
    # Heartbeats: both networks report every day (CrowdSec's first, backfilled day included).
    cx.execute(OBS, {"src": "shadowserver_api", "cves": [HEARTBEAT] * 81, "days": days(lookback, end)})
    cx.execute(OBS, {"src": "crowdsec", "cves": [HEARTBEAT] * 82,
                     "days": days(lookback - timedelta(days=1), end)})
    cx.execute(OBS, {"src": "shadowserver_api", "cves": sorted(SEEN), "days": [date(2034, 2, 10)] * len(SEEN)})
    cx.execute(OBS, {"src": "shadowserver_api", "cves": ATTACKED, "days": [date(2034, 3, 15)] * len(ATTACKED)})
    # KEV: two CISA listings known before March; a VulnCheck one backdated (collected in March)
    # that may count only as a March addition; a CIRCL one citing a sensor.
    for src, cve, added, seen, raw in [
        ("cisa", NEW[60], "2034-02-01", "2034-02-02", '{}'),
        ("cisa", NEW[61], "2034-02-01", "2034-02-02", '{}'),
        ("vulncheck", NEW[62], "2034-02-01", "2034-03-10", '{}'),
        ("vulncheck", NEW[63], "2034-02-01", "2034-02-02", '{"source": "shadowserver"}'),
    ]:
        cx.execute(KEV, {"src": src, "cve": cve, "added": added, "seen": seen, "raw": raw})
    cx.commit()
    files = epss_files({})

    def fake_fetch(client, day):
        if day not in files:
            raise prio_run.EpssMissing(f"no file for {day}")
        return files[day], "v2034.01.01"

    monkeypatch.setattr(prio_run, "fetch_epss", fake_fetch)
    monkeypatch.setenv("DATABASE_URL", DSN)
    yield cx, files
    cleanup(cx)
    cx.execute("delete from obs_core.exploitation_observations where cve_id = %s", (HEARTBEAT,))
    cx.commit()
    cx.close()


def stored(cx, month=M) -> dict:
    cur = cx.execute("select rule_key, added, backlog, hit_all, hit_new, hit_new_clean, attacked_all, "
                     "attacked_new, lanes_urgent, lanes_regular, lanes_turned, refused_reason, "
                     "crowdsec_from, gap_days from public.patch_prioritisation where month = %s", (month,))
    cx.commit()
    return {r[0]: r[1:] for r in cur.fetchall()}


def test_scores_a_month_end_to_end(db):
    cx, files = db
    assert prio_run.main(["--month", "2034-03", "--today", "2034-04-06"]) == 0
    s = stored(cx)
    assert len(s) == 12
    added, backlog, hit_all, hit_new, clean, att_all, att_new, *_rest, refused, cs_from, gaps = s["pick"]
    assert (att_all, att_new) == (400, 100)
    assert refused is None and gaps is None
    assert cs_from is None                                  # CrowdSec covers the whole lookback
    assert s["cisa"][1] == 2 and s["kev"][1] == 3           # backlog: 2 CISA + 1 VulnCheck known
    assert s["kev"][0] == 1                                 # the backdated VulnCheck one: added in March
    assert s["kev"][4] == 2                                 # clean: the sensor-citing entry dropped
    assert s["pick"][3] == 63                               # 60 new above 10% + 3 KEV known on 1 Mar
    assert s["pick"][2] == 263                              # + the 200 repeat targets above 10%

    # The same answer as the pure function on the same inputs: the SQL feeds compute.py truly.
    kev_all = {NEW[60], NEW[61], NEW[63]}
    inp = MonthInputs(
        epss_start=files[M], epss_next=files[NXT],
        cvss={c: (9.8 if (i + 1) % 4 == 0 else 5.0) for i, c in enumerate(ATTACKED)},
        kev_start={"all": kev_all, "cisa": {NEW[60], NEW[61]}, "clean": {NEW[60], NEW[61]}},
        kev_next={"all": kev_all | {NEW[62]}, "cisa": {NEW[60], NEW[61]}, "clean": {NEW[60], NEW[61], NEW[62]}},
        attacked=set(ATTACKED), seen_before=SEEN)
    card = score_month(inp)
    for r in card.rules:
        assert s[r.key][:5] == (r.added, r.backlog, r.hit_all, r.hit_new, r.hit_new_clean), r.key


def test_if_due_catches_up_and_stops_at_a_missing_file(db):
    cx, files = db
    # Pretend February 2034 is the latest stored month.
    cx.execute("insert into derived.patch_prioritisation select (date '2034-02-01') as month, rule_key, "
               "rule_label, kind, sort_order, added, backlog, hit_all, hit_new, new_ci_lo, new_ci_hi, "
               "hit_new_clean, cves, attacked_all, attacked_new, lookback_days, lanes_urgent, "
               "lanes_regular, lanes_turned, epss_model, method_version, git_sha, crowdsec_from, gap_days, "
               "refused_reason, computed_at from derived.patch_prioritisation where month = '2026-09-01'")
    cx.commit()
    assert prio_run.main(["--if-due", "--today", "2034-04-04"]) == 0     # March not due before the 5th
    assert stored(cx) == {}
    assert prio_run.main(["--if-due", "--today", "2034-04-06"]) == 0     # due: scored once
    assert len(stored(cx)) == 12
    assert prio_run.main(["--if-due", "--today", "2034-04-07"]) == 0     # already stored: nothing
    # On 6 May both April (no EPSS file for 1 May) and nothing after are due: April waits, unstored.
    assert prio_run.main(["--if-due", "--today", "2034-05-06"]) == 0
    assert stored(cx, date(2034, 4, 1)) == {}
    assert prio_run.main(["--if-due", "--today", "2034-05-16"]) == 1     # past the 15th: a failure


def test_an_incomplete_month_waits_then_is_refused_on_record(db):
    cx, files = db
    cx.execute("delete from obs_core.exploitation_observations where cve_id = %s and observed_at >= '2034-03-29'",
               (HEARTBEAT,))
    cx.commit()
    assert prio_run.main(["--month", "2034-03", "--today", "2034-04-06"]) == 0   # waiting
    assert stored(cx) == {}
    assert prio_run.main(["--month", "2034-03", "--today", "2034-04-16"]) == 1   # refused, stored
    s = stored(cx)
    assert len(s) == 12 and "not complete" in s["pick"][-3]
