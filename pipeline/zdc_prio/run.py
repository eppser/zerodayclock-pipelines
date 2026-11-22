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

TWO DECLARED VARIANTS, each stored on the row so the chart can say which it is showing:
  * A MONTH BEFORE OUR OWN COLLECTION. "Collected before the day" cannot be asked of a day before
    the KEV catalogues were first collected. Such a day uses kev_basis 'first_collection': the
    entries a catalogue dates before the day AND that were in it at our first collection of that
    catalogue. That set is frozen (a later backdated listing cannot join it), but a listing
    backdated between the day and our first collection cannot be told apart, which flatters every
    rule that includes KEV. Allowed only when the first collection is within MAX_KEV_GAP_DAYS of
    the day. CrowdSec is left out of a month it has no earlier day for (every CVE it reported
    would count as newly targeted because the network was new, not the attack). Both follow from
    the data, not from a flag.
  * A MONTH TO DATE (--month YYYY-MM --through YYYY-MM-DD): the running month scored on its days
    so far, against the lists of the day after. Stored with outcome_through set, shown as
    provisional, never counted as the month's score: --if-due replaces it with the full month.

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
METHOD_VERSION = "prio-1.1"     # 1.0 plus the two declared variants above; a full month scores identically
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-{d}.csv.gz"
DUE_DAY = 5
EPSS_GRACE_DAY = 15         # a missing EPSS file is "not yet" until then, a failure after
MAX_GAP_DAYS = 3            # missing sensor days tolerated within the scored month
# CrowdSec's feed looks back seven days, and a day's rows keep arriving for that long: measured on
# 2026-10-01..11-10, 88% of a day's rows are first seen the next day and about 2% more on each of the
# six after. A month to date stops at a day that has had all seven.
CROWDSEC_SETTLE_DAYS = 7
MIN_TO_DATE_DAYS = 7        # a month to date shorter than a week is not scored
MAX_KEV_GAP_DAYS = 31       # how long after a day our first KEV collection may be and still stand in for it
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
        or (%(crowdsec)s
            and derived.is_scanning_count(o.source_id, o.observation_type)
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


def crowdsec_counts_for(month: date, cs_first: date | None) -> bool:
    """CrowdSec is part of a month's outcome only if it has at least one counted day before it.

    With none, everything it reports in the month is "not seen attacked before" because the
    network is new: the strict outcome would measure CrowdSec arriving, not attackers moving.
    """
    return cs_first is not None and cs_first + timedelta(days=1) < month


def coverage(days_by_source: dict[str, set[date]], cs_first: date | None, lookback: date,
             month: date, end: date) -> dict:
    """Which days each network is missing, in the lookback and in the scored month.

    CrowdSec is counted from the day after its first (that day is a backfilled aggregate), so
    before then it is absent by design, not missing: crowdsec_from records where it starts.
    """
    cs_from = cs_first + timedelta(days=1) if crowdsec_counts_for(month, cs_first) else None
    if cs_from is None:
        days_by_source = {s: d for s, d in days_by_source.items() if s != "crowdsec"}
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
        "sensors": "shadowserver_api,crowdsec" if cs_from else "shadowserver_api",
    }


def kev_collection_start(rows) -> dict[str, date]:
    """Per catalogue, the first day we collected it."""
    out: dict[str, date] = {}
    for source, _, _, collected, _ in rows:
        if collected is not None and (source not in out or collected < out[source]):
            out[source] = collected
    return out


def kev_basis(rows, day: date) -> str:
    """'listed_and_collected' wherever it can be asked; 'first_collection' for a day on or before
    our first collection of any catalogue, when nothing can have been collected before it."""
    start = kev_collection_start(rows)
    return "first_collection" if start and day <= min(start.values()) else "listed_and_collected"


def kev_sets(rows, day: date, basis: str = "listed_and_collected") -> dict[str, set[str]]:
    """The KEV lists as of `day`.

    listed_and_collected: listed before the day and already collected by us before it.
    first_collection:     listed before the day and present at our first collection of that
                          catalogue. An entry we first saw later was not in the catalogue then, so
                          whatever date it carries it is provably backdated and does not count.
    """
    out = {"all": set(), "cisa": set(), "clean": set()}
    start = kev_collection_start(rows) if basis == "first_collection" else {}
    for source, cve, listed, collected, sensor in rows:
        if listed is None or listed >= day or collected is None:
            continue
        if basis == "listed_and_collected" and collected >= day:
            continue
        if basis == "first_collection" and collected > start[source]:
            continue
        out["all"].add(cve)
        if source in ("cisa", "euvd"):
            out["cisa"].add(cve)
        if source != "circl" and not (source == "vulncheck" and sensor):
            out["clean"].add(cve)
    return out


def load_inputs(conn, month: date, client: PoliteClient,
                through: date | None = None) -> tuple[MonthInputs, str, date, dict]:
    """`through` scores a month to date: outcomes to that day, the lists of the day after."""
    end = through or next_month(month) - timedelta(days=1)
    nxt = end + timedelta(days=1)
    e0, model = fetch_epss(client, month)
    e1, _ = fetch_epss(client, nxt)
    lookback = month - timedelta(days=LOOKBACK_DAYS)
    with conn.cursor() as cur:
        cur.execute(KEV_SQL, (list(KEV_SOURCES),))
        kev = cur.fetchall()
        cur.execute("select cve_id, coalesce(cna_cvss_score, nvd_cvss_score)::float from core.cves "
                    "where coalesce(cna_cvss_score, nvd_cvss_score) is not null")
        cvss = dict(cur.fetchall())
        cur.execute("select min(observed_at) from obs_core.exploitation_observations "
                    "where source_id = 'crowdsec' and observation_type = 'attempt_observed'")
        cs_first = cur.fetchone()[0]
        cur.execute(OBS_SQL, {"start": month, "lookback": lookback, "end": end,
                              "crowdsec": crowdsec_counts_for(month, cs_first)})
        obs = cur.fetchall()
        cur.execute(COVERAGE_SQL, {"lookback": lookback, "end": end})
        days: dict[str, set[date]] = {}
        for src, d in cur.fetchall():
            days.setdefault(src, set()).add(d)
    cov = coverage(days, cs_first, lookback, month, end)
    cov["kev_basis"] = kev_basis(kev, month)
    first = kev_collection_start(kev)
    cov["kev_collected_from"] = min(first.values()) if cov["kev_basis"] == "first_collection" else None
    cov["through"] = through
    inp = MonthInputs(epss_start=e0, epss_next=e1, cvss=cvss,
                      kev_start=kev_sets(kev, month, cov["kev_basis"]),
                      kev_next=kev_sets(kev, nxt, kev_basis(kev, nxt)),
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
    if cov is not None and cov.get("kev_collected_from") is not None and month is not None:
        gap = (cov["kev_collected_from"] - month).days
        if gap > MAX_KEV_GAP_DAYS:
            problems.append(f"the KEV catalogues were first collected {gap} days after the month began: "
                            "what they listed on its first day cannot be reconstructed")
    if cov is not None and month is not None:
        end = cov.get("through") or next_month(month) - timedelta(days=1)
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
                       epss_model, method_version, git_sha, crowdsec_from, gap_days, refused_reason,
                       outcome_through, kev_basis, kev_collected_from, sensors)
                   values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                           %s,%s,%s,%s)""",
                (month, r.key, r.label, r.kind, i, r.added, r.backlog, r.hit_all, r.hit_new,
                 r.new_ci[0], r.new_ci[1], r.hit_new_clean, card.cves, card.attacked_all,
                 card.attacked_new, LOOKBACK_DAYS, card.lanes_urgent, card.lanes_regular,
                 card.lanes_turned, model, METHOD_VERSION, git_sha, cov["crowdsec_from"], gaps, refused,
                 cov.get("through"), cov.get("kev_basis", "listed_and_collected"),
                 cov.get("kev_collected_from"), cov.get("sensors", "shadowserver_api,crowdsec")))
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
    """Every due month after the latest one stored (refused ones count as stored), oldest first.
    A month stored to date is not stored: its full score is still owed and replaces it."""
    with conn.cursor() as cur:
        cur.execute("select max(month) from derived.patch_prioritisation where outcome_through is null")
        return months_after(cur.fetchone()[0], today)


def score_and_store(conn, month: date, *, dry_run: bool, report: dict, today: date,
                    through: date | None = None) -> str:
    """'stored', 'refused' (stored with its reason), 'waiting' (not yet), or 'failed'."""
    client = PoliteClient("epss", per_minute=10, timeout=180.0,
                          headers={"Accept": "application/gzip, text/csv"})
    try:
        inp, model, lookback, cov = load_inputs(conn, month, client, through)
    except EpssMissing as exc:
        # FIRST publishes daily and keeps dated files; a missing one is usually late, not gone.
        # A month to date asks for the file of a day that has already settled: missing is a failure.
        late = through is not None or today >= next_month(month).replace(day=EPSS_GRACE_DAY)
        log.log(logging.ERROR if late else logging.WARNING, "%s: %s", month.strftime("%Y-%m"), exc)
        report[month.isoformat()] = {"skipped": str(exc)}
        return "failed" if late else "waiting"
    try:
        card = score_month(inp)
    except ValueError as exc:
        # No attacked or no newly targeted CVE in the window: nothing to rank, and nothing is stored.
        log.error("%s: %s", month.strftime("%Y-%m"), exc)
        report[month.isoformat()] = {"skipped": str(exc)}
        return "failed"
    problems = check(card, cov, month)
    report[month.isoformat()] = {
        "lookback_from": lookback.isoformat(), "epss_model": model, "cves": card.cves,
        "attacked_all": card.attacked_all, "attacked_new": card.attacked_new,
        "crowdsec_from": str(cov["crowdsec_from"]), "gap_days": [f"{d} {s}" for d, s in cov["gaps"]],
        "outcome_through": str(through) if through else None, "kev_basis": cov["kev_basis"],
        "kev_collected_from": str(cov["kev_collected_from"]) if cov["kev_collected_from"] else None,
        "sensors": cov["sensors"],
        "rules": {r.key: {"added": r.added, "backlog": r.backlog, "hit_all": r.hit_all,
                          "hit_new": r.hit_new} for r in card.rules},
        "lanes": [card.lanes_urgent, card.lanes_regular, card.lanes_turned], "problems": problems}
    if (through is None and any("not complete" in x for x in problems)
            and today < next_month(month).replace(day=EPSS_GRACE_DAY)):
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
    ap.add_argument("--through", help="with --month: score the month to date, outcomes to this day "
                                      "(YYYY-MM-DD); stored as provisional")
    ap.add_argument("--dry-run", action="store_true", help="compute and print, write nothing")
    ap.add_argument("--report", help="write a JSON report here")
    ap.add_argument("--today", help=argparse.SUPPRESS)   # tests: pretend today is this date
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    today = date.fromisoformat(args.today) if args.today else date.today()
    through = date.fromisoformat(args.through) if args.through else None
    if through is not None:
        m = date.fromisoformat(args.month + "-01") if args.month else None
        if m is None or not (m + timedelta(days=MIN_TO_DATE_DAYS - 1) <= through < next_month(m) - timedelta(days=1)):
            log.error("--through needs --month and a day inside it, from its %dth and before its last", MIN_TO_DATE_DAYS)
            return 2
        if through > today - timedelta(days=CROWDSEC_SETTLE_DAYS):
            log.error("--through %s is not settled yet: the latest day that is, is %s",
                      through, today - timedelta(days=CROWDSEC_SETTLE_DAYS))
            return 2
        if is_due(m, today):
            log.error("%s is over and due in full: score it with --month alone", args.month)
            return 2
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        raise RuntimeError("DATABASE_URL is not set")
    report: dict = {}
    ok = True
    with psycopg.connect(dsn, autocommit=False) as conn:
        if args.month:
            months = [date.fromisoformat(args.month + "-01")]
            if through is not None:
                with conn.cursor() as cur:
                    cur.execute("select 1 from derived.patch_prioritisation "
                                "where month = %s and outcome_through is null limit 1", (months[0],))
                    if cur.fetchone():
                        log.error("%s is already scored in full: a month to date may not replace it", args.month)
                        return 2
                conn.rollback()
            if through is None and not is_due(months[0], today):
                log.info("%s is not due until %s", args.month, next_month(months[0]).replace(day=DUE_DAY))
                return 0
        else:
            months = due_months(conn, today)
            if not months:
                log.info("nothing due")
        ok = run_months(months, lambda m: score_and_store(conn, m, dry_run=args.dry_run, report=report,
                                                          today=today, through=through))
    print(json.dumps(report, indent=1, default=str))
    if args.report:
        with open(args.report, "w") as f:
            json.dump(report, f, indent=1, default=str)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
