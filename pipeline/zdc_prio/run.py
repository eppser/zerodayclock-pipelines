"""Monthly patch prioritisation scorecard -> derived.patch_prioritisation.

    python -m zdc_prio.run --if-due          # what the enrichment workflow runs, every pass
    python -m zdc_prio.run --month 2026-09   # one month, even if it is already stored
    python -m zdc_prio.run --month 2026-09 --dry-run

ALWAYS THE PREVIOUS MONTH. The chart shows the last complete month: a month is scored once
its last day has fully arrived from both networks. CrowdSec reports a day in full only after
three days and the scheduled runs land hours late, so a month is due from the 5th of the
next one. --if-due scores every due month after the latest one stored, oldest first, and does
nothing once they are stored, so the enrichment workflow can call it on every pass: it computes
once a month, and a month missed by a failure is caught up rather than skipped.

A MONTH IS STORED EVEN WHEN IT IS REFUSED. A month whose data is incomplete, or whose result
contradicts the chart's title, is stored with refused_reason set: the chart then says that month
is under review rather than silently showing an older one, and the job stops retrying it. Re-run
it with --month once the cause is fixed.

Re-running --month for a stored month replaces it, computed with today's CVSS scores; the
seeded September 2026 rows (migration 0093) would be replaced the same way.

Inputs, all as knowable on the month's first day:
  * EPSS: FIRST's dated daily files (epss.empiricalsecurity.com) for day 1 of the month and
    day 1 of the next; dated files stay published, so a late run reads the same file.
  * KEV: core.kev_entries listed before the day AND first collected by us before it, so a
    listing backdated after the fact cannot count.
  * CVSS: today's score (CNA, else NVD). The one leak; it can only flatter the CVSS rows.
  * Outcome: obs_core.exploitation_observations, exactly as the observatory's daily activity
    and scanning tables count it (Shadowserver API attempts, CrowdSec occurrences without its
    backfilled first day).
"""

from __future__ import annotations

import argparse
import gzip
import json
import logging
import os
import sys
from datetime import date, timedelta

import psycopg

from zdc_enrich.models import parse_epss
from zdc_kev.http import PoliteClient

from .compute import LOOKBACK_DAYS, MonthInputs, Scorecard, score_month

log = logging.getLogger("zdc_prio")
METHOD_VERSION = "prio-1.0"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-{d}.csv.gz"
DUE_DAY = 5
EPSS_GRACE_DAY = 15         # a missing EPSS file is "not yet" until then, a failure after
MAX_GAP_DAYS = 3            # missing sensor days tolerated within the scored month
FIRST_MONTH = date(2026, 9, 1)   # the first month both networks cover with a lookback
KEV_SOURCES = ("cisa", "euvd", "circl", "vulncheck")


def month_start(d: date) -> date:
    return d.replace(day=1)


def next_month(m: date) -> date:
    return (m.replace(day=28) + timedelta(days=4)).replace(day=1)


def previous_month(today: date) -> date:
    return month_start(month_start(today) - timedelta(days=1))


def is_due(month: date, today: date) -> bool:
    return today >= next_month(month).replace(day=DUE_DAY)


class EpssMissing(RuntimeError):
    """FIRST has not published (or we cannot reach) a dated EPSS file."""


def fetch_epss(client: PoliteClient, day: date) -> tuple[dict[str, float], str]:
    rec = client.get(EPSS_URL.format(d=day.isoformat()), expect_json=False)
    if not rec.ok or not rec.body:
        raise EpssMissing(f"EPSS file for {day} not available: {rec.error or rec.http_status}")
    body = rec.body
    try:
        text = gzip.decompress(body).decode("utf-8", errors="replace")
    except (OSError, EOFError):
        text = body.decode("utf-8", errors="replace")
    records, model, score_date, skipped = parse_epss(text)
    if str(score_date)[:10] != day.isoformat():
        raise RuntimeError(f"EPSS file for {day} is dated {score_date}")
    return {r.cve_id: float(r.epss_score) for r in records}, model


KEV_SQL = """
select source_id, cve_id, min(date_added) as listed, min(first_seen_at)::date as collected,
       bool_or(raw::text ilike '%%shadowserver%%' or raw::text ilike '%%crowdsec%%') as sensor_cited
  from core.kev_entries
 where cve_id is not null and source_id = any(%s)
 group by 1, 2
"""

# The union of the two daily tables' own definitions (derived.rebuild_cve_activity and
# derived.rebuild_cve_scanning_daily), read from the observations so the lookback is not
# limited by those tables' 90-day window.
OBS_SQL = """
with cs_first as (
  select min(observed_at) as d from obs_core.exploitation_observations
   where source_id = 'crowdsec' and observation_type = 'attempt_observed')
select o.cve_id, o.observed_at < %(start)s as before
  from obs_core.exploitation_observations o, cs_first
 where o.cve_id is not null and o.observation_count is not null
   and o.observed_at between %(lookback)s and %(end)s
   and (o.source_id = 'shadowserver_api'
        or (derived.is_scanning_count(o.source_id, o.observation_type)
            and o.withdrawn_at is null
            and not (o.source_id = 'crowdsec' and o.observed_at <= cs_first.d)))
 group by o.cve_id, o.observed_at
having sum(o.observation_count) > 0
"""


COVERAGE_SQL = """
select source_id, observed_at from obs_core.exploitation_observations
 where source_id in ('shadowserver_api', 'crowdsec') and cve_id is not null
   and observation_count > 0
   and observed_at between %(lookback)s and %(end)s
 group by 1, 2
"""


def coverage(days_by_source: dict[str, set[date]], cs_first: date | None, lookback: date,
             month: date, end: date) -> dict:
    """Which days each network is missing, in the lookback and in the scored month.

    CrowdSec is counted from the day after its first (that day is a backfilled aggregate), so
    before then it is absent by design, not missing: crowdsec_from records where it starts.
    """
    cs_from = cs_first + timedelta(days=1) if cs_first else None
    def missing(src: str, frm: date) -> list[date]:
        have = days_by_source.get(src, set())
        return [frm + timedelta(days=i) for i in range((end - frm).days + 1)
                if frm + timedelta(days=i) not in have]
    ss = missing("shadowserver_api", lookback)
    cs = missing("crowdsec", max(lookback, cs_from)) if cs_from and cs_from <= end else []
    last = {s: max(d) if d else None for s, d in days_by_source.items()}
    return {
        # Only when CrowdSec starts inside the lookback, i.e. its lookback really is shorter.
        "crowdsec_from": cs_from if cs_from and cs_from > lookback else None,
        "gaps": [(d, "Shadowserver") for d in ss] + [(d, "CrowdSec") for d in cs],
        "gaps_in_month": sum(1 for d in ss + cs if d >= month),
        "last": last,
    }


def kev_sets(rows, day: date) -> dict[str, set[str]]:
    out = {"all": set(), "cisa": set(), "clean": set()}
    for source, cve, listed, collected, sensor in rows:
        if listed is None or listed >= day or collected is None or collected >= day:
            continue
        out["all"].add(cve)
        if source in ("cisa", "euvd"):
            out["cisa"].add(cve)
        if source != "circl" and not (source == "vulncheck" and sensor):
            out["clean"].add(cve)
    return out


def load_inputs(conn, month: date, client: PoliteClient) -> tuple[MonthInputs, str, date, dict]:
    nxt = next_month(month)
    e0, model = fetch_epss(client, month)
    e1, _ = fetch_epss(client, nxt)
    lookback = month - timedelta(days=LOOKBACK_DAYS)
    with conn.cursor() as cur:
        cur.execute(KEV_SQL, (list(KEV_SOURCES),))
        kev = cur.fetchall()
        cur.execute("select cve_id, coalesce(cna_cvss_score, nvd_cvss_score)::float from core.cves "
                    "where coalesce(cna_cvss_score, nvd_cvss_score) is not null")
        cvss = dict(cur.fetchall())
        cur.execute(OBS_SQL, {"start": month, "lookback": lookback, "end": nxt - timedelta(days=1)})
        obs = cur.fetchall()
        cur.execute(COVERAGE_SQL, {"lookback": lookback, "end": nxt - timedelta(days=1)})
        days: dict[str, set[date]] = {}
        for src, d in cur.fetchall():
            days.setdefault(src, set()).add(d)
        cur.execute("select min(observed_at) from obs_core.exploitation_observations "
                    "where source_id = 'crowdsec' and observation_type = 'attempt_observed'")
        cs_first = cur.fetchone()[0]
    cov = coverage(days, cs_first, lookback, month, nxt - timedelta(days=1))
    inp = MonthInputs(epss_start=e0, epss_next=e1, cvss=cvss,
                      kev_start=kev_sets(kev, month), kev_next=kev_sets(kev, nxt),
                      attacked={c for c, before in obs if not before},
                      seen_before={c for c, before in obs if before})
    return inp, model, lookback, cov


def check(card: Scorecard, cov: dict | None = None, month: date | None = None) -> list[str]:
    """Reasons a month cannot be published as what the chart claims it is. Empty = publish."""
    problems = []
    if card.cves < 200_000:
        problems.append(f"only {card.cves:,} CVEs in the EPSS file")
    if card.attacked_all < 300:
        problems.append(f"only {card.attacked_all} attacked CVEs: a sensor feed is missing")
    if card.attacked_new < 20:
        problems.append(f"only {card.attacked_new} newly targeted CVEs: too few to rank rules")
    pick = next(r for r in card.rules if r.key == "pick")
    crit = next(r for r in card.rules if r.key == "cvss9")
    # The chart's title says to prioritise by exploitation, not severity. A month that says
    # otherwise is a finding for a person to look at, not something to publish under it.
    if pick.hit_new < crit.hit_new or pick.hit_all < crit.hit_all:
        problems.append(f"recommended rule covers {pick.hit_new}/{pick.hit_all} (newly targeted/all), "
                        f"CVSS 9+ {crit.hit_new}/{crit.hit_all}: the chart's title would be wrong")
    if cov is not None and month is not None:
        end = next_month(month) - timedelta(days=1)
        if cov["gaps_in_month"] > MAX_GAP_DAYS:
            problems.append(f"{cov['gaps_in_month']} sensor-days missing in the month")
        for src, last in cov["last"].items():
            if last is None or last < end:
                problems.append(f"{src} has no data after {last}: the month is not complete")
    return problems


def store(conn, month: date, card: Scorecard, *, model: str, git_sha: str | None, cov: dict,
          refused: str | None) -> None:
    gaps = "; ".join(f"{d.isoformat()} {s}" for d, s in cov["gaps"]) or None
    with conn.cursor() as cur:
        cur.execute("delete from derived.patch_prioritisation where month = %s", (month,))
        for i, r in enumerate(card.rules):
            cur.execute(
                """insert into derived.patch_prioritisation (
                       month, rule_key, rule_label, kind, sort_order, added, backlog, hit_all,
                       hit_new, new_ci_lo, new_ci_hi, hit_new_clean, cves, attacked_all,
                       attacked_new, lookback_days, lanes_urgent, lanes_regular, lanes_turned,
                       epss_model, method_version, git_sha, crowdsec_from, gap_days, refused_reason)
                   values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (month, r.key, r.label, r.kind, i, r.added, r.backlog, r.hit_all, r.hit_new,
                 r.new_ci[0], r.new_ci[1], r.hit_new_clean, card.cves, card.attacked_all,
                 card.attacked_new, LOOKBACK_DAYS, card.lanes_urgent, card.lanes_regular,
                 card.lanes_turned, model, METHOD_VERSION, git_sha, cov["crowdsec_from"], gaps, refused))
    conn.commit()


def months_after(latest: date | None, today: date) -> list[date]:
    """Every due month after `latest` (or from FIRST_MONTH), oldest first."""
    m = next_month(latest) if latest else FIRST_MONTH
    out = []
    while is_due(m, today):
        out.append(m)
        m = next_month(m)
    return out


def due_months(conn, today: date) -> list[date]:
    """Every due month after the latest one stored (refused ones count as stored), oldest first."""
    with conn.cursor() as cur:
        cur.execute("select max(month) from derived.patch_prioritisation")
        return months_after(cur.fetchone()[0], today)


def score_and_store(conn, month: date, *, dry_run: bool, report: dict, today: date) -> str:
    """'stored', 'refused' (stored with its reason), 'waiting' (not yet), or 'failed'."""
    client = PoliteClient("epss", per_minute=10, timeout=180.0,
                          headers={"Accept": "application/gzip, text/csv"})
    try:
        inp, model, lookback, cov = load_inputs(conn, month, client)
    except EpssMissing as exc:
        # FIRST publishes daily and keeps dated files; a missing one is usually late, not gone.
        late = today >= next_month(month).replace(day=EPSS_GRACE_DAY)
        log.log(logging.ERROR if late else logging.WARNING, "%s: %s", month.strftime("%Y-%m"), exc)
        report[month.isoformat()] = {"skipped": str(exc)}
        return "failed" if late else "waiting"
    card = score_month(inp)
    problems = check(card, cov, month)
    report[month.isoformat()] = {
        "lookback_from": lookback.isoformat(), "epss_model": model, "cves": card.cves,
        "attacked_all": card.attacked_all, "attacked_new": card.attacked_new,
        "crowdsec_from": str(cov["crowdsec_from"]), "gap_days": [f"{d} {s}" for d, s in cov["gaps"]],
        "rules": {r.key: {"added": r.added, "backlog": r.backlog, "hit_all": r.hit_all,
                          "hit_new": r.hit_new} for r in card.rules},
        "lanes": [card.lanes_urgent, card.lanes_regular, card.lanes_turned], "problems": problems}
    if any("not complete" in x for x in problems) and today < next_month(month).replace(day=EPSS_GRACE_DAY):
        # A network that has not delivered the month's last days yet is late, not wrong: wait
        # (until the 15th) rather than record a refusal that would stop the retries.
        log.warning("%s waiting for data: %s", month.strftime("%Y-%m"), "; ".join(problems))
        return "waiting"
    if problems:
        log.error("%s refused: %s", month.strftime("%Y-%m"), "; ".join(problems))
    if not dry_run:
        store(conn, month, card, model=model, git_sha=os.environ.get("GITHUB_SHA"), cov=cov,
              refused="; ".join(problems) or None)
        log.info("stored %s (%s)", month.strftime("%Y-%m"), "REFUSED" if problems else "published")
    return "refused" if problems else "stored"


def run_months(months: list[date], step) -> bool:
    """Score months oldest first and STOP at the first one that was not stored.

    The next pass starts after the latest stored month, so storing November while October is
    waiting or failed would skip October for good. Returns False if anything failed or was
    refused (a refusal is stored, but a person should look at it).
    """
    ok = True
    for m in months:
        status = step(m)
        if status == "refused":
            ok = False
        elif status != "stored":
            return ok and status == "waiting"
    return ok


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--month", help="YYYY-MM to score, replacing it if stored")
    ap.add_argument("--if-due", action="store_true",
                    help="score every due month after the latest stored one (the scheduled call)")
    ap.add_argument("--dry-run", action="store_true", help="compute and print, write nothing")
    ap.add_argument("--report", help="write a JSON report here")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    today = date.today()
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        raise RuntimeError("DATABASE_URL is not set")
    report: dict = {}
    ok = True
    with psycopg.connect(dsn, autocommit=False) as conn:
        if args.month:
            months = [date.fromisoformat(args.month + "-01")]
            if not is_due(months[0], today):
                log.info("%s is not due until %s", args.month, next_month(months[0]).replace(day=DUE_DAY))
                return 0
        else:
            months = due_months(conn, today)
            if not months:
                log.info("nothing due")
        ok = run_months(months, lambda m: score_and_store(conn, m, dry_run=args.dry_run,
                                                          report=report, today=today))
    print(json.dumps(report, indent=1, default=str))
    if args.report:
        with open(args.report, "w") as f:
            json.dump(report, f, indent=1, default=str)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
