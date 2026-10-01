"""Gate checks for the honeypot pipeline.

Every check exists because of a specific way this pipeline could be wrong and still look
fine. ERROR blocks promotion; WARN is visible; INFO is a diagnostic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, timedelta

ERROR, WARN, INFO = "error", "warn", "info"


@dataclass(frozen=True, slots=True)
class EvalResult:
    name: str
    severity: str
    passed: bool
    summary: str
    detail: dict = field(default_factory=dict)

    @property
    def blocking(self) -> bool:
        return self.severity == ERROR and not self.passed


def check_fetch_succeeded(fetches) -> EvalResult:
    """A day that returned nothing must say WHY. v1 recorded a WAF block as 220 good rows."""
    failed = [f for f in fetches if not f.ok]
    return EvalResult(
        "fetch_succeeded", ERROR, not failed,
        f"all {len(fetches)} day fetches succeeded" if not failed
        else f"{len(failed)} of {len(fetches)} day fetches failed: "
             + "; ".join(str(f.error)[:80] for f in failed[:3]),
        {"failed": len(failed), "total": len(fetches)})


def check_parse_errors(errors, rows) -> EvalResult:
    """Rows we could not parse are reported, never dropped silently."""
    ok = not errors
    return EvalResult(
        "parse_clean", ERROR, ok,
        f"{len(rows):,} rows parsed with no errors" if ok
        else f"{len(errors)} unparseable rows: " + "; ".join(errors[:3]),
        {"errors": len(errors), "rows": len(rows)})


def check_day_not_truncated(rows_by_day, suspicious=(100, 500, 1000, 5000)) -> EvalResult:
    """A row count landing exactly on a round number is what silent truncation looks like.

    This method documents no pagination and none was observed (677 rows on 2026-08-30),
    but VulnCheck's index silently truncated at max_pages and cost us real data, so the
    same failure is watched for here rather than assumed away.
    """
    hits = {d: n for d, n in rows_by_day.items() if n in suspicious}
    return EvalResult(
        "day_not_truncated", WARN, not hits,
        "no day returned a suspiciously round row count" if not hits
        else f"possible truncation on {len(hits)} day(s): {hits}",
        {"suspicious_days": {str(k): v for k, v in hits.items()}})


def measure_list_length_volatility(conn, window_days: int = 21) -> EvalResult:
    """Make the daily list length visible, because it is not a measurement.

    Measured over 14 consecutive days: the row count swung 125..921 (mean 465) while
    total connections stayed in the same band, and on 2026-08-22 -> 08-23 the count fell
    86% while volume ROSE 12% — with 19 of the top 20 vulnerabilities still present.
    The head is stable; the tail churns with sensor coverage.

    This is INFO on purpose. It is a property of the source, not a fault in the pipeline,
    and failing a run over it would be failing on correct data. But it must be VISIBLE,
    because the one way to get this source badly wrong is to read a short day as a quiet
    day — which is what filling absent rows with zeros would do.
    """
    with conn.cursor() as cur:
        cur.execute(
            """select observed_at, count(*), sum(observation_count)
                 from obs_core.exploitation_observations
                where source_id = 'shadowserver_api'
                  and observed_at > (select max(observed_at) - %s::int
                                       from obs_core.exploitation_observations
                                      where source_id = 'shadowserver_api')
                group by 1 order by 1""", (window_days,))
        days = cur.fetchall()
    if len(days) < 3:
        return EvalResult("list_length_volatility", INFO, True,
                          f"only {len(days)} day(s) stored — not enough to characterise",
                          {"days": len(days)})
    counts = [d[1] for d in days]
    lo, hi = min(counts), max(counts)
    mean = sum(counts) / len(counts)
    return EvalResult(
        "list_length_volatility", INFO, True,
        f"daily list length over {len(days)} days: {lo}..{hi} (mean {mean:.0f}, "
        f"{hi / max(lo, 1):.1f}x spread) — absence of a row is NOT a zero",
        {"days": len(days), "min": lo, "max": hi, "mean": round(mean, 1)})


def check_head_is_stable(conn, top_n: int = 20, min_retention: float = 0.6) -> EvalResult:
    """The high-volume head must persist day to day, even when the tail churns.

    If the HEAD starts disappearing too, the cause is no longer sensor coverage — it is
    truncation or a broken fetch, and that would corrupt every trend built on this table.
    Measured baseline: 19 of 20 retained across the worst observed drop.
    """
    with conn.cursor() as cur:
        cur.execute("""select max(observed_at) from obs_core.exploitation_observations
                        where source_id = 'shadowserver_api'""")
        last = cur.fetchone()[0]
        if last is None:
            return EvalResult("head_is_stable", INFO, True, "no data yet", {})
        cur.execute(
            """with ranked as (
                   select observed_on, vuln_id,
                          row_number() over (partition by observed_on
                                             order by total desc) rn
                     from (select observed_at as observed_on, vuln_id,
                                  sum(observation_count) total
                             from obs_core.exploitation_observations
                            where source_id = 'shadowserver_api'
                              and observed_at in (%s, %s - 1)
                            group by 1, 2) s)
               select
                 (select count(*) from ranked a
                   where a.observed_on = %s - 1 and a.rn <= %s
                     and exists (select 1 from ranked b
                                  where b.observed_on = %s and b.vuln_id = a.vuln_id)),
                 (select count(*) from ranked where observed_on = %s - 1 and rn <= %s)""",
            (last, last, last, top_n, last, last, top_n))
        retained, base = cur.fetchone()
    if not base:
        return EvalResult("head_is_stable", INFO, True,
                          "no prior day to compare the head against", {})
    ratio = retained / base
    return EvalResult(
        "head_is_stable", WARN, ratio >= min_retention,
        f"{retained}/{base} of the previous day's top {top_n} vulnerabilities are still "
        f"present ({ratio:.0%})" if ratio >= min_retention else
        f"only {retained}/{base} of the previous day's top {top_n} survived ({ratio:.0%}) "
        "— the head should be stable even when the tail churns; suspect truncation",
        {"retained": retained, "base": base, "ratio": round(ratio, 3)})


def check_persisted(conn, expected_rows: int) -> EvalResult:
    """Fetching is not ingesting. A run that collects and stores nothing must fail."""
    with conn.cursor() as cur:
        cur.execute("""select count(*) from obs_core.exploitation_observations
                        where source_id = 'shadowserver_api'""")
        stored = cur.fetchone()[0]
    ok = stored > 0 or expected_rows == 0
    return EvalResult(
        "persisted", ERROR, ok,
        f"exploitation_observations holds {stored:,} shadowserver_api rows" if ok
        else f"collected {expected_rows:,} rows but the table is empty",
        {"stored": stored, "collected": expected_rows})


def check_row_shape(conn) -> EvalResult:
    """Identity, typing and the product key must agree, on every row this source wrote.

    The natural key is (vulnerability, product, day) — one CVE is reported against several
    products — so source_entry_id must encode all three, or a day's second product row
    silently overwrites the first.
    """
    with conn.cursor() as cur:
        cur.execute("""
            select
              count(*) filter (where product_key is distinct from coalesce(product, '')),
              count(*) filter (where (vuln_id_type = 'cve') <> (cve_id is not null)),
              count(*) filter (where source_entry_id <> vuln_id
                     || case when coalesce(product_key,'') <> '' then '|' || product_key else '' end
                     || '@' || observed_at::text),
              count(*) filter (where observation_type <> 'attempt_observed')
              from obs_core.exploitation_observations where source_id = 'shadowserver_api'""")
        bad_key, mistyped, bad_identity, bad_claim = cur.fetchone()
    ok = not (bad_key or mistyped or bad_identity or bad_claim)
    return EvalResult(
        "row_shape", ERROR, ok,
        "product_key, identifier typing and source_entry_id all agree on every row" if ok
        else f"{bad_key} mis-keyed products; {mistyped} mistyped identifiers; "
             f"{bad_identity} malformed identities; {bad_claim} wrong observation_type",
        {"bad_product_key": bad_key, "mistyped": mistyped,
         "bad_identity": bad_identity, "bad_claim": bad_claim})


def check_sources_not_conflated(conn) -> EvalResult:
    """The two Shadowserver feeds must stay distinguishable inside the one table.

    They are the same sensor network read two ways: the public dashboard (carries
    unique_ips, which the granted API method does not) and the documented API (carries 13
    fields the dashboard does not). Consolidating them into one table was the point of
    0029; conflating them into one source_id would not be — a figure quoted as "from
    Shadowserver" must still say which feed produced it.
    """
    with conn.cursor() as cur:
        cur.execute("""select source_id, count(*) from obs_core.exploitation_observations
                        where source_id like 'shadowserver%' group by 1 order by 1""")
        feeds = dict(cur.fetchall())
        cur.execute("""select count(*) from obs_core.observation_sources
                        where source_id like 'shadowserver%'""")
        registered = cur.fetchone()[0]
    ok = registered >= len(feeds) and len(feeds) <= 2
    return EvalResult(
        "sources_not_conflated", ERROR, ok,
        f"{len(feeds)} Shadowserver feed(s) present and registered separately: "
        + ", ".join(f"{k}={v:,}" for k, v in feeds.items()) if ok
        else f"feeds {feeds} but only {registered} registered",
        {"feeds": {k: v for k, v in feeds.items()}, "registered": registered})


def check_no_future_days(conn, censored_at: date) -> EvalResult:
    """No observation may be dated in the real future.

    Checked against TODAY, not against this run's window end. A backfill of an old range
    ends at an old date, and the table legitimately holds newer rows from the incremental
    stream — failing that would mean a historical sweep could never run without being
    blocked by data collected since. The property worth protecting is that a sensor has
    not reported a day that has not happened yet.
    """
    horizon = max(censored_at, date.today())
    with conn.cursor() as cur:
        cur.execute("""select count(*), max(observed_at) from obs_core.exploitation_observations
                        where source_id = 'shadowserver_api' and observed_at > %s""",
                    (horizon,))
        n, mx = cur.fetchone()
    return EvalResult(
        "no_future_days", ERROR, n == 0,
        f"no observation dated after {horizon}" if n == 0
        else f"{n} rows dated after {horizon} (max {mx})",
        {"future_rows": n, "horizon": str(horizon)})


def check_freshness(conn, censored_at: date, max_lag_days: int | None = None) -> EvalResult:
    """A stopped collector must show up as a growing number, not an empty column.

    This is the check that did not exist in v1, where exploitation data quietly ended
    2026-02-28 while the site kept publishing 'current' figures for six months.

    THE THRESHOLD COMES FROM THE REGISTRY, not from this signature. 0063 declares
    max_silence_days per source and 0068 recalibrated it; a constant here meant those
    declared values were documentation the pipeline ignored, so tuning the data changed
    nothing and the two could disagree silently. An explicit argument still wins, for
    tests. A source with no declared threshold falls back to 3 rather than passing
    vacuously — an unmonitored source is the failure this whole check exists to prevent.
    """
    with conn.cursor() as cur:
        if max_lag_days is None:
            cur.execute("""select max_silence_days from obs_core.observation_sources
                            where source_id = 'shadowserver_api'""")
            row = cur.fetchone()
            max_lag_days = (row[0] if row and row[0] is not None else 3)
        cur.execute("""select max(observed_at) from obs_core.exploitation_observations
                        where source_id = 'shadowserver_api'""")
        last = cur.fetchone()[0]
    if last is None:
        return EvalResult("freshness", ERROR, False, "no observation days stored at all",
                          {"last_day": None})
    lag = (censored_at - last).days
    return EvalResult(
        "freshness", ERROR if lag > max_lag_days else INFO, lag <= max_lag_days,
        f"most recent observation day {last}, {lag} day(s) behind the censoring date",
        {"last_day": str(last), "lag_days": lag})


def check_gap_free(conn, start: date, end: date) -> EvalResult:
    """Missing days inside the COVERED range are invisible in a chart and fatal to a trend.

    The window is clipped to the range the source actually serves. Shadowserver's history
    begins 2022-06-23; asking for 2022-06-01 and then failing on the 22 days before the
    source existed reports a collection gap where there is only a calendar.
    """
    with conn.cursor() as cur:
        cur.execute("""select min(observed_at), max(observed_at)
                         from obs_core.exploitation_observations
                        where source_id = 'shadowserver_api'""")
        have_lo, have_hi = cur.fetchone()
    if have_lo is None:
        return EvalResult("gap_free", WARN, True, "no days stored yet", {})
    start = max(start, have_lo)
    end = min(end, have_hi)
    if start > end:
        return EvalResult("gap_free", WARN, True,
                          "the requested range lies outside the source's history", {})
    with conn.cursor() as cur:
        cur.execute("""select count(*) from generate_series(%s::date, %s::date, '1 day') g(d)
                        where not exists (select 1 from obs_core.exploitation_observations
                                           where source_id = 'shadowserver_api'
                                             and observed_at = g.d)""", (start, end))
        missing = cur.fetchone()[0]
    total = (end - start).days + 1
    return EvalResult(
        "gap_free", WARN, missing == 0,
        f"every one of {total} days in {start}..{end} has data" if missing == 0
        else f"{missing} of {total} days missing between {start} and {end}",
        {"missing_days": missing, "total_days": total})


def measure_pre_kev_scanning(conn) -> EvalResult:
    """How often did the sensor see a vulnerability before any catalogue listed it?

    INFO, deliberately, and it must stay INFO. sensor_first_seen is when Shadowserver's
    honeypot first MATCHED a signature, and signatures are written when a vulnerability
    becomes notable. A lead here is a hypothesis about signature timing, not evidence of
    earlier exploitation. Published as a diagnostic to bound the discussion.
    """
    with conn.cursor() as cur:
        cur.execute("""
            select count(*),
                   count(*) filter (where v.sensor_first_seen::date < k.first_kev_date),
                   percentile_cont(0.5) within group (
                       order by (k.first_kev_date - v.sensor_first_seen::date))
              from (select vuln_id, min(sensor_first_seen) sensor_first_seen
                      from obs_core.exploitation_observations
                     where sensor_first_seen is not null group by 1) v
              join derived.kev_consolidated k on k.vuln_id = v.vuln_id
             where v.sensor_first_seen is not null and k.first_kev_date is not null""")
        n, earlier, med = cur.fetchone()
    if not n:
        return EvalResult("pre_kev_scanning", INFO, True, "no comparable vulnerabilities yet")
    return EvalResult(
        "pre_kev_scanning", INFO, True,
        f"{earlier:,} of {n:,} catalogued vulnerabilities were seen by the sensor first "
        f"(median {float(med or 0):.0f}d) — signature timing, NOT evidence of earlier exploitation",
        {"comparable": n, "sensor_first": earlier, "median_lead_days": float(med or 0)})


def run_db_evals(conn, censored_at: date, expected_rows: int,
                 start: date | None = None, end: date | None = None) -> list[EvalResult]:
    out = [
        check_persisted(conn, expected_rows),
        check_row_shape(conn),
        check_sources_not_conflated(conn),
        check_no_future_days(conn, censored_at),
        check_freshness(conn, censored_at),
        check_head_is_stable(conn),
        measure_list_length_volatility(conn),
        measure_pre_kev_scanning(conn),
    ]
    if start and end:
        out.append(check_gap_free(conn, start, end))
    return out


def render(results) -> str:
    lines = [f"[{'PASS' if r.passed else 'FAIL'}] {r.severity:5} {r.name}: {r.summary}"
             for r in results]
    ok = not any(r.blocking for r in results)
    lines.append("")
    lines.append("RESULT: OK — safe to promote" if ok else "RESULT: BLOCKED — do not promote")
    return "\n".join(lines)
