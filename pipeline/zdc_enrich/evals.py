"""Eval gate for the enrichment pipeline.

The failure this gate exists to catch is the one that already happened once: a
development run had every source fetch cleanly, persist nothing, and still report
"safe to promote". Fetching is not the contract — a correct, deduplicated, populated
table is. So the checks below assert against the DATABASE after the rebuild, not
against what the adapters returned.

Every check is written so that it can fail. `check_detail_one_row_per_cve` would still
pass if the primary key were the only thing enforcing it, so it is paired with
`check_kev_membership_matches_source`, which recomputes the KEV membership count
independently from core.kev_entries and compares. Remove the aggregation from the
transform and that check goes red.
"""

from __future__ import annotations

import re

from datetime import date

from zdc_kev.evals import ERROR, INFO, WARN, EvalReport, EvalResult  # noqa: F401

#: A stale observation window is normal (Shadowserver publishes daily, the pipeline
#: runs twice daily); a *growing* one is a dead collector. Warn past a week.
OBS_LAG_WARN_DAYS = 7

#: ...and BLOCK past three weeks. v1 published "current" figures against a collector
#: that had been dead for six months; the check that was supposed to prevent that
#: returned WARN in both branches and could never fail a run. Three weeks is loose
#: enough to ride out an upstream outage without halting promotion, and decisive
#: enough that six months is unreachable.
#:
#: This blocks on upstream silence as well as on our own breakage, deliberately.
#: Publishing a "last 7 days" column computed from a 21-day-old window is the same
#: defect to a reader whichever end it came from.
OBS_LAG_ERROR_DAYS = 21


def check_epss_collected(result) -> EvalResult:
    if result.skipped_reason:
        return EvalResult("epss_collected", INFO, True,
                          f"EPSS not fetched: {result.skipped_reason}", {})
    if result.error:
        return EvalResult("epss_collected", ERROR, False,
                          f"EPSS failed: {result.error}", {"error": result.error})
    n = len(result.records)
    return EvalResult("epss_collected", ERROR, n > 0,
                      f"{n:,} EPSS scores, model {result.model_version}, "
                      f"score_date {result.score_date}"
                      if n else "EPSS returned no rows and no reason",
                      {"rows": n, "model_version": result.model_version,
                       "score_date": str(result.score_date) if result.score_date else None,
                       "skipped_rows": result.skipped_rows})


def check_epss_rows_not_skipped(result, limit: int = 100) -> EvalResult:
    """Malformed rows are counted, not dropped silently. A rising count is a signal."""
    n = result.skipped_rows
    return EvalResult("epss_rows_not_skipped", WARN, n <= limit,
                      f"{n} malformed EPSS rows skipped (limit {limit})",
                      {"skipped": n, "limit": limit})


def check_epss_persisted(conn) -> EvalResult:
    """Fetching is not persisting. This is the check that a clean run can still fail."""
    with conn.cursor() as cur:
        cur.execute("select count(*), max(score_date), count(distinct model_version) "
                    "from core.cve_epss")
        n, score_date, versions = cur.fetchone()
    return EvalResult("epss_persisted", ERROR, n > 0,
                      f"core.cve_epss holds {n:,} scores (score_date {score_date})"
                      if n else "core.cve_epss is EMPTY after a run that reported success",
                      {"rows": n, "score_date": str(score_date) if score_date else None,
                       "distinct_model_versions": versions})


def check_epss_single_model_version(conn) -> EvalResult:
    """Percentiles are not comparable across EPSS model generations.

    A table holding two versions means a partial update landed, and any percentile
    comparison across it is meaningless.
    """
    with conn.cursor() as cur:
        cur.execute("select model_version, count(*) from core.cve_epss group by 1 order by 2 desc")
        rows = cur.fetchall()
    return EvalResult("epss_single_model_version", WARN, len(rows) <= 1,
                      f"one EPSS model version in the table ({rows[0][0]})" if len(rows) == 1
                      else (f"{len(rows)} model versions present: {rows}"
                            if rows else "no EPSS rows"),
                      {"versions": [{"version": v, "rows": n} for v, n in rows]})


def check_detail_populated(conn) -> EvalResult:
    with conn.cursor() as cur:
        cur.execute("select count(*) from derived.cve_detail")
        n = cur.fetchone()[0]
    return EvalResult("detail_populated", ERROR, n > 0,
                      f"derived.cve_detail holds {n:,} rows" if n
                      else "derived.cve_detail is EMPTY after a successful rebuild",
                      {"rows": n})


def check_detail_one_row_per_cve(conn) -> EvalResult:
    """The deduplication contract, asserted rather than assumed.

    14,301 KEV assertions cover 5,198 CVEs. A join instead of an aggregate would
    multiply rows by observer count.
    """
    with conn.cursor() as cur:
        cur.execute("select count(*), count(distinct cve_id) from derived.cve_detail")
        total, distinct = cur.fetchone()
    return EvalResult("detail_one_row_per_cve", ERROR, total == distinct,
                      f"{total:,} rows for {distinct:,} distinct CVEs"
                      + ("" if total == distinct else " — DUPLICATED"),
                      {"rows": total, "distinct_cves": distinct})


def check_kev_membership_matches_source(conn) -> EvalResult:
    """Recompute KEV membership straight from core.kev_entries and compare.

    This is the check that catches a broken aggregation. It does not read the
    transform's own output for the expected value — it derives it independently, so a
    transform that drops or multiplies CVEs cannot satisfy both sides.
    """
    with conn.cursor() as cur:
        cur.execute("select max(censored_at) from derived.cve_detail")
        censored = cur.fetchone()[0]
        cur.execute("""select count(distinct cve_id) from core.kev_entries
                        where cve_id is not null
                          and (date_added is null or date_added <= %s)""", (censored,))
        expected = cur.fetchone()[0]
        cur.execute("select count(*) from derived.cve_detail where kev_status='in_kev'")
        actual = cur.fetchone()[0]
    return EvalResult("kev_membership_matches_source", ERROR, expected == actual,
                      f"{actual:,} rows flagged in_kev; core.kev_entries has {expected:,} "
                      f"distinct CVEs at censoring date {censored}"
                      + ("" if expected == actual else " — MISMATCH"),
                      {"expected": expected, "actual": actual, "censored_at": str(censored)})


def check_no_epoch_sentinels(conn) -> EvalResult:
    """1970-01-01 rows won least() in v1 and dragged every interval to nonsense."""
    with conn.cursor() as cur:
        cur.execute("""select count(*) from derived.cve_detail
                        where first_kev_date <= date '1971-01-01'
                           or t0 <= date '1971-01-01'
                           or earliest_exploited_since <= date '1971-01-01'""")
        n = cur.fetchone()[0]
    return EvalResult("no_epoch_sentinels", ERROR, n == 0,
                      "no epoch-sentinel dates survived into the detail table" if n == 0
                      else f"{n} rows carry a date at or before 1971-01-01",
                      {"rows": n})


def check_zero_day_consistent(conn) -> EvalResult:
    """The flag must agree with the interval it is derived from, in both directions."""
    with conn.cursor() as cur:
        cur.execute("""select count(*) from derived.cve_detail
                        where is_zero_day_by_kev_date is distinct from
                              (case when first_kev_date is not null and t0 is not null
                                    then days_kev_after_publication <= 0 end)""")
        n = cur.fetchone()[0]
    return EvalResult("zero_day_consistent", ERROR, n == 0,
                      "zero-day flag agrees with days_kev_after_publication on every row"
                      if n == 0 else f"{n} rows disagree with their own interval",
                      {"rows": n})


def check_zero_day_signal_agreement(conn) -> EvalResult:
    """Measure how much the two zero-day flags actually disagree.

    They look like independent confirmations and are not: exploited_since is identical
    to date_added on 99.9% of the KEV rows carrying both, CISA never supplies it, and
    EUVD supplies it INSTEAD of date_added. This check reports the disagreement rate
    every run rather than asserting a threshold, so if a genuinely independent onset
    source is ever added, the number moves and the claim can be revisited. INFO, not a
    gate — the finding is the point, not a failure.
    """
    with conn.cursor() as cur:
        cur.execute("""select
                 count(*) filter (where is_zero_day_by_kev_date is not null
                                    and is_zero_day_by_exploited_since is not null),
                 count(*) filter (where is_zero_day_by_kev_date
                                     is distinct from is_zero_day_by_exploited_since
                                    and is_zero_day_by_kev_date is not null
                                    and is_zero_day_by_exploited_since is not null)
             from derived.cve_detail""")
        comparable, disagree = cur.fetchone()
    pct = (100.0 * disagree / comparable) if comparable else 0.0
    return EvalResult("zero_day_signal_agreement", INFO, True,
                      f"the two zero-day flags disagree on {disagree} of {comparable:,} "
                      f"comparable CVEs ({pct:.2f}%) — they are near-identical inputs, "
                      "not independent confirmations",
                      {"comparable": comparable, "disagree": disagree,
                       "disagreement_pct": round(pct, 3)})


def check_censoring_recorded(conn) -> EvalResult:
    """Every row states the window it was computed over, and it is one window."""
    with conn.cursor() as cur:
        cur.execute("""select count(distinct censored_at), count(distinct method_version),
                              max(censored_at), max(method_version)
                         from derived.cve_detail""")
        dates, versions, censored, method = cur.fetchone()
    ok = dates == 1 and versions == 1
    return EvalResult("censoring_recorded", ERROR, ok,
                      f"one censoring date ({censored}) and one method version ({method})"
                      if ok else f"{dates} censoring dates / {versions} method versions "
                                 "in one table — a partial rebuild landed",
                      {"distinct_censored_at": dates, "distinct_method_versions": versions})


def check_observation_window_fresh(conn) -> EvalResult:
    """A collector that stopped makes the last-7-days columns measure silence.

    v1 kept publishing "current" numbers for six months against a dead collector. This
    check is the reason that cannot happen quietly here — and it earns that sentence
    only because it can BLOCK. It previously returned WARN on both branches, so it
    reported the staleness and promoted the run anyway.

    Three tiers: within a week is normal, past a week is visible, past three weeks
    stops the run. `blocking` is `severity == ERROR and not passed`, so only the
    third tier gates promotion.
    """
    with conn.cursor() as cur:
        cur.execute("""select max(obs_window_end), max(obs_window_lag_days),
                              max(censored_at) from derived.cve_detail""")
        window_end, lag, censored = cur.fetchone()
    if window_end is None:
        # No observations at all is a different failure from a stale window, and it is
        # unambiguous: the 7-day columns are empty by construction. Block on it.
        return EvalResult("observation_window_fresh", ERROR, False,
                          "no exploitation observations at all — the 7-day columns are "
                          "empty by construction, not by absence of exploitation", {})
    lag = lag or 0
    if lag > OBS_LAG_ERROR_DAYS:
        severity, passed = ERROR, False
        verdict = (f" — over the {OBS_LAG_ERROR_DAYS}-day blocking threshold; the "
                   "collector has stopped, do not promote")
    elif lag > OBS_LAG_WARN_DAYS:
        severity, passed = WARN, False
        verdict = (f" — over the {OBS_LAG_WARN_DAYS}-day threshold; "
                   "treat last-7-days columns as stale")
    else:
        severity, passed, verdict = INFO, True, ""
    return EvalResult("observation_window_fresh", severity, passed,
                      f"observations run to {window_end}, {lag} day(s) behind the "
                      f"censoring date {censored}" + verdict,
                      {"obs_window_end": str(window_end), "lag_days": lag,
                       "warn_threshold": OBS_LAG_WARN_DAYS,
                       "error_threshold": OBS_LAG_ERROR_DAYS})

def check_registry_orphans_kept(conn) -> EvalResult:
    """Rows a KEV catalogue lists but the registry does not carry must survive.

    Dropping the rows you cannot verify is selection bias — in v1 the unverifiable
    half carried almost the entire slow tail.

    BOTH SIDES MUST BE CENSORED ON THE SAME DATE. The kept side comes from
    derived.cve_detail, which is built at the enrichment censoring date; the expected
    side reads core.kev_entries, which the KEV pipeline advances on its own schedule.
    Comparing them without censoring the second made this check fail on correct data
    whenever the KEV harvester ran more recently than the CVE registry fetch — which is
    the normal state, not the exception, because they are separate workflows. Measured
    2026-09-01: kept 10, uncensored expected 13, censored expected 10. It had only ever
    passed because both pipelines happened to sit on the same day.
    """
    with conn.cursor() as cur:
        cur.execute("select max(censored_at) from derived.cve_detail")
        censored_at = cur.fetchone()[0]
        cur.execute("""select count(*) from derived.cve_detail where in_cve_registry = false""")
        orphans = cur.fetchone()[0]
        cur.execute("""select count(distinct k.cve_id) from core.kev_entries k
                        left join core.cves c on c.cve_id = k.cve_id
                        where k.cve_id is not null and c.cve_id is null
                          and (k.date_added is null or k.date_added <= %s)""",
                    (censored_at,))
        expected = cur.fetchone()[0]
        # Diagnostic only: how far ahead the KEV layer is running.
        cur.execute("""select count(distinct k.cve_id) from core.kev_entries k
                        left join core.cves c on c.cve_id = k.cve_id
                        where k.cve_id is not null and c.cve_id is null
                          and k.date_added > %s""", (censored_at,))
        beyond = cur.fetchone()[0]
    ahead = f", {beyond} more asserted after it" if beyond else ""
    return EvalResult("registry_orphans_kept", ERROR, orphans == expected,
                      f"{orphans} catalogued CVEs absent from the CVE registry are kept "
                      f"and flagged at censoring date {censored_at}{ahead}"
                      if orphans == expected else
                      f"{orphans} orphans kept but {expected} expected at censoring date "
                      f"{censored_at}{ahead}",
                      {"kept": orphans, "expected": expected,
                       "censored_at": str(censored_at), "asserted_beyond_censoring": beyond})


def check_patch_basis_declared(conn) -> EvalResult:
    """No row may carry a patch date without saying how it was established.

    And no basis may be an inference: v1's heuristic ran +98 days late on average and
    biased 'exploited before a patch existed' upward.
    """
    with conn.cursor() as cur:
        cur.execute("""select count(*) from derived.cve_detail
                        where patch_available_date is not null
                          and patch_date_basis not in
                              ('vendor_fix_record','vcs_commit','release_artifact')""")
        undeclared = cur.fetchone()[0]
        cur.execute("select count(*) from derived.cve_detail where patch_available_date is not null")
        with_date = cur.fetchone()[0]
    return EvalResult("patch_basis_declared", ERROR, undeclared == 0,
                      f"{with_date:,} rows carry a patch date, all with a measured basis"
                      if undeclared == 0
                      else f"{undeclared} rows carry a patch date with no measured basis",
                      {"with_patch_date": with_date, "undeclared": undeclared})


def check_technology_cohorts_populated(conn) -> EvalResult:
    """Every category the taxonomy defines must appear in the cohorts, and no others.

    THE COUNT WAS HARD-CODED TO 6 AND WENT STALE. The taxonomy grew to nine categories and
    this eval failed on correct data from that moment, blocking every enrichment run. A gate
    that is always red is a broken alarm: nobody sees the day it goes red for a real reason.

    It is compared against core.technology_taxonomy rather than against a number, so adding a
    category can never fail it again, while a category that the taxonomy defines and the
    rebuild drops still does.
    """
    with conn.cursor() as cur:
        cur.execute("select count(*), count(distinct category) from derived.technology_cohorts")
        rows, cats = cur.fetchone()
        cur.execute("select count(distinct category) from core.technology_taxonomy")
        defined = cur.fetchone()[0]
    ok = rows > 0 and cats == defined
    return EvalResult("technology_cohorts_populated", ERROR, ok,
                      f"{rows} series rows across all {cats} taxonomy categories" if ok
                      else f"technology_cohorts holds {rows} rows / {cats} categories, "
                           f"but the taxonomy defines {defined}",
                      {"rows": rows, "categories": cats, "taxonomy_categories": defined})


def check_cohort_window_rolls(conn) -> EvalResult:
    """The window must track the censoring date, not a hard-coded year.

    This is the check that fails in January 2027 if the chart has silently frozen on
    2026. It compares the window actually written against the one the censoring date
    implies, so a stale rebuild is caught rather than quietly served.
    """
    with conn.cursor() as cur:
        cur.execute("""select min(cohort_year), max(cohort_year),
                              max(boundary_year), max(boundary_month), max(censored_at)
                         from derived.technology_cohorts""")
        lo, hi, byear, bmonth, censored = cur.fetchone()
    if censored is None:
        return EvalResult("cohort_window_rolls", ERROR, False,
                          "no technology cohort rows to check", {})
    # Last complete month at or before the censoring date.
    exp_year, exp_month = (censored.year, censored.month - 1) if censored.month > 1 \
        else (censored.year - 1, 12)
    ok = (byear, bmonth) == (exp_year, exp_month) and hi == exp_year and lo == exp_year - 5
    return EvalResult("cohort_window_rolls", ERROR, ok,
                      f"window {lo}..{hi}, boundary {byear}-{bmonth:02d}, censored {censored}"
                      + ("" if ok else f" — expected boundary {exp_year}-{exp_month:02d} "
                                       f"and window {exp_year-5}..{exp_year}; the chart "
                                       "has frozen"),
                      {"window": [lo, hi], "boundary": [byear, bmonth],
                       "expected_boundary": [exp_year, exp_month],
                       "censored_at": str(censored)})


def check_scan_age_window_rolls(conn) -> EvalResult:
    """The age stream must ROLL twelve months, never accumulate them.

    This is the check that fails the month the window silently freezes. The failure it
    guards is slow and quiet: a rebuild that appended instead of replacing would look
    right for a year, then become a different chart with an axis nobody chose and a
    stack height no longer comparable to its own past. Nothing errors; it is only
    visible to somebody who remembers what the chart used to show.

    Three properties, all derived from the data rather than asserted as constants:
      * the newest month drawn is the last COMPLETE month at the observation window end,
        never the one in progress;
      * the span is at most the twelve months the method declares, and no month sits
        outside it;
      * every month drawn carries all four bands, so the stack cannot silently lose one.

    The month count is read from core.method_registry rather than hard-coded, the way
    kev_technology_window_rolls reads p_span_years out of the function signature: an
    eval that pins what the method declares fails on correct data the day the method
    changes.
    """
    with conn.cursor() as cur:
        cur.execute("""select min(month), max(month), count(distinct month),
                              max(obs_window_end), max(censored_at)
                         from derived.scan_age_mix""")
        lo, hi, n_months, obs_end, censored = cur.fetchone()
        cur.execute("""select (parameters->>'months')::int
                         from core.method_registry
                        where metric_id = 'scan_age_mix' and superseded_at is null
                        order by introduced_at desc nulls last, method_version desc
                        limit 1""")
        row = cur.fetchone()
        declared = row[0] if row and row[0] else 12
        cur.execute("""select count(*) from (
                          select month from derived.scan_age_mix
                           group by month having count(*) <> 4) t""")
        short_months = cur.fetchone()[0]

    if obs_end is None:
        return EvalResult("scan_age_window_rolls", ERROR, False,
                          "no scan_age_mix rows to check", {})

    # The last complete calendar month at the observation window end. Anchored to the
    # SENSOR window, not the censoring date, because that is what the rebuild anchors to
    # — an eval that measured the other one would fail whenever the collector lagged.
    from calendar import monthrange
    last_day = monthrange(obs_end.year, obs_end.month)[1]
    if obs_end.day == last_day:
        exp_y, exp_m = obs_end.year, obs_end.month
    else:
        exp_y, exp_m = (obs_end.year, obs_end.month - 1) if obs_end.month > 1 \
            else (obs_end.year - 1, 12)

    newest_ok = (hi.year, hi.month) == (exp_y, exp_m)
    span_ok = n_months <= declared
    # Oldest month strictly inside the rolling window: eleven months back from newest.
    back_y, back_m = divmod((hi.year * 12 + hi.month - 1) - (declared - 1), 12)
    oldest_ok = (lo.year, lo.month) >= (back_y, back_m + 1)
    bands_ok = short_months == 0
    ok = newest_ok and span_ok and oldest_ok and bands_ok

    why = []
    if not newest_ok:
        why.append(f"newest month {hi} is not the last complete month "
                   f"{exp_y}-{exp_m:02d} — the window has frozen")
    if not span_ok:
        why.append(f"{n_months} months drawn against {declared} declared — "
                   "the rebuild is accumulating instead of replacing")
    if not oldest_ok:
        why.append(f"oldest month {lo} sits outside the {declared}-month window")
    if not bands_ok:
        why.append(f"{short_months} month(s) do not carry all four bands")

    return EvalResult("scan_age_window_rolls", ERROR, ok,
                      f"{n_months}/{declared} months, {lo}..{hi}, sensor data to "
                      f"{obs_end}, censored {censored}"
                      + ("" if ok else " — " + "; ".join(why)),
                      {"months": n_months, "declared": declared,
                       "window": [str(lo), str(hi)],
                       "expected_newest": f"{exp_y}-{exp_m:02d}",
                       "obs_window_end": str(obs_end)})


# The rebuild runs twice daily and the honeypot feed lands between runs, so the window
# legitimately trails the sensor by up to a day. Beyond this it has stopped moving.
REBUILD_LAG_TOLERANCE_DAYS = 3


def check_scan_pressure_window_rolls(conn) -> EvalResult:
    """The scan-pressure ladder must ROLL with the sensor, never accumulate.

    scan_pressure is the project's only SENSOR-anchored window: every offset hangs off
    max(observed_at) for the feed rather than the censoring date. Doctrine requires that
    specifically, because anchoring to "today" would render a stalled collector as a
    collapse in attempts — v1's exact failure, drawn as a finding.

    Four properties, every parameter read from core.method_registry rather than written
    here. That is not tidiness: it makes the registry and the function cross-check each
    other. 0052 registered this metric with ANOTHER chart's description, another chart's
    parameters and a code_path naming a file that does not exist, and nothing noticed
    because nothing compared the two. Now a change to one without the other fails.

      * the newest window end IS the sensor's newest day — not the censoring date, and
        not the query date;
      * the offsets are contiguous 0..N-1, so the ladder cannot lose a rung silently;
      * the span is bounded by offsets x window_days — this is the one that fails the
        day a rebuild appends instead of replacing;
      * no row reaches back further than the declared lookback.
    """
    with conn.cursor() as cur:
        cur.execute("""select (parameters->>'offsets')::int,
                              (parameters->>'window_days')::int,
                              (parameters->>'lookback_days')::int,
                              parameters->>'source_id',
                              parameters->>'observation_type'
                         from core.method_registry
                        where metric_id = 'scan_pressure' and superseded_at is null
                        order by introduced_at desc nulls last, method_version desc
                        limit 1""")
        row = cur.fetchone()
        if not row or row[0] is None:
            return EvalResult("scan_pressure_window_rolls", ERROR, False,
                              "no current scan_pressure row in core.method_registry, "
                              "or it declares no offsets", {})
        offsets, window_days, lookback, src, obs_type = row

        cur.execute("""select count(distinct offset_weeks), min(offset_weeks),
                              max(offset_weeks), min(window_start), max(obs_window_end)
                         from derived.scan_pressure""")
        n_off, k_lo, k_hi, oldest, newest = cur.fetchone()
        if newest is None:
            return EvalResult("scan_pressure_window_rolls", ERROR, False,
                              "no scan_pressure rows to check", {})

        cur.execute("""select max(observed_at)::date
                         from obs_core.exploitation_observations
                        where source_id = %s and observation_type = %s""",
                    (src, obs_type))
        sensor_max = cur.fetchone()[0]

    # Two distinct failures, and only one of them is about the clock.
    #
    # AHEAD of the sensor is impossible if the window is anchored to max(observed_at),
    # and is exactly what anchoring to the censoring or query date produces the moment
    # the collector stalls — the case that draws a collection failure as a collapse in
    # attempts. That is a hard error at any margin.
    #
    # BEHIND the sensor by a day is normal: the rebuild runs twice daily and the
    # honeypot feed lands between runs, so obs_window_end legitimately trails until the
    # next enrich. Only a window that has stopped moving for days is a frozen rebuild.
    ahead = sensor_max is not None and newest > sensor_max
    lag = (sensor_max - newest).days if sensor_max is not None else None
    anchored_ok = sensor_max is not None and not ahead and lag <= REBUILD_LAG_TOLERANCE_DAYS
    rungs_ok = n_off == offsets and k_lo == 0 and k_hi == offsets - 1
    span = (newest - oldest).days
    span_ok = span <= offsets * window_days
    reach_ok = span <= lookback

    ok = anchored_ok and rungs_ok and span_ok and reach_ok
    why = []
    if sensor_max is None:
        why.append("the feed has no observations at all")
    elif ahead:
        why.append(f"newest window end {newest} is AHEAD of the sensor's newest day "
                   f"{sensor_max} — the window is anchored to the censoring or query "
                   "date, not to the feed")
    elif not anchored_ok:
        why.append(f"newest window end {newest} trails the sensor's newest day "
                   f"{sensor_max} by {lag}d — the rebuild has stopped moving")
    if not rungs_ok:
        why.append(f"offsets {k_lo}..{k_hi} ({n_off} distinct) against {offsets} declared")
    if not span_ok:
        why.append(f"span {span}d exceeds {offsets} x {window_days}d — "
                   "the rebuild is accumulating instead of replacing")
    if not reach_ok:
        why.append(f"span {span}d reaches past the declared {lookback}d lookback")

    return EvalResult("scan_pressure_window_rolls", ERROR, ok,
                      f"{n_off} offsets, {oldest}..{newest}, {span}d span, "
                      f"sensor day {sensor_max}, rebuild lag {lag}d"
                      + ("" if ok else " — " + "; ".join(why)),
                      {"offsets": n_off, "declared_offsets": offsets,
                       "window": [str(oldest), str(newest)], "span_days": span,
                       "sensor_max": str(sensor_max) if sensor_max else None,
                       "rebuild_lag_days": lag,
                       "lookback_days": lookback})


def check_partial_year_not_extended(conn) -> EvalResult:
    """A partial cohort must stop at the boundary, and a complete one must not be dashed."""
    with conn.cursor() as cur:
        cur.execute("""select count(*) from derived.technology_cohorts
                        where is_partial_year and month_index > boundary_month""")
        overrun = cur.fetchone()[0]
        cur.execute("""select count(*) from derived.technology_cohorts t
                        where not t.is_partial_year and t.cohort_year = t.boundary_year
                          and t.boundary_month < 12""")
        mislabelled = cur.fetchone()[0]
    ok = overrun == 0 and mislabelled == 0
    return EvalResult("partial_year_not_extended", ERROR, ok,
                      "the partial cohort stops at the boundary and no complete year is "
                      "flagged partial" if ok
                      else f"{overrun} rows past the boundary, {mislabelled} mislabelled",
                      {"overrun": overrun, "mislabelled": mislabelled})


def check_technology_single_assignment(conn) -> EvalResult:
    """One category per CVE. A CVE matching two rules must resolve, not duplicate."""
    with conn.cursor() as cur:
        cur.execute("select count(*), count(distinct cve_id) from derived.cve_technology")
        total, distinct = cur.fetchone()
    return EvalResult("technology_single_assignment", ERROR, total == distinct,
                      f"{total:,} assignments for {distinct:,} distinct CVEs"
                      + ("" if total == distinct else " — DUPLICATED"),
                      {"assignments": total, "distinct_cves": distinct})


def check_technology_coverage_published(conn) -> EvalResult:
    """The classified share must be recorded, because it is a minority of the corpus.

    INFO, not a gate: a low share is honest, not broken. Hiding it would be the fault.
    """
    with conn.cursor() as cur:
        cur.execute("""select classified_pct, cves_classified, cves_unclassified,
                              window_start_year, boundary_year
                         from derived.technology_coverage order by censored_at desc limit 1""")
        row = cur.fetchone()
    if not row:
        return EvalResult("technology_coverage_published", ERROR, False,
                          "no coverage row was written", {})
    pct, clf, unclf, y0, y1 = row
    return EvalResult("technology_coverage_published", INFO, True,
                      f"{pct}% of {y0}-{y1} CVEs fall in the six named domains "
                      f"({clf:,} classified, {unclf:,} outside them)",
                      {"classified_pct": float(pct), "classified": clf,
                       "unclassified": unclf})


def check_classification_evidence(conn) -> EvalResult:
    """The three evidence tiers are actually being used.

    ERROR, and specifically a PERSISTENCE gate rather than a coverage one. The failure
    this exists for is silent: if the evidence build stops writing — a scope query that
    returns nothing, a rename upstream — every classification quietly falls back to
    whatever the registry alone can place, the charts lose about a third of their rows,
    and nothing else in the pipeline notices. Same class as `persisted` in the KEV
    evals: a gate on fetching says nothing about storing.
    """
    with conn.cursor() as cur:
        cur.execute("select count(*), count(distinct censored_at) from derived.cve_evidence")
        rows, dates = cur.fetchone()
        cur.execute("""select evidence_tier, count(*) from derived.cve_technology
                        group by 1 order by 2 desc""")
        tiers = dict(cur.fetchall())
    known = {"registry", "kev_catalogue", "sensor", "inferred", "assumed"}
    unknown = set(tiers) - known
    ok = rows > 0 and dates <= 1 and not unknown
    detail = ", ".join(f"{k}={v:,}" for k, v in tiers.items()) or "none"
    if rows == 0:
        msg = "derived.cve_evidence is EMPTY — classification has silently fallen back to registry data only"
    elif dates > 1:
        msg = (f"derived.cve_evidence holds {dates} censoring dates; the prune in "
               "rebuild_cve_evidence is not running and a stale scope has survived")
    elif unknown:
        msg = f"unreviewed evidence tier(s) in cve_technology: {sorted(unknown)}"
    else:
        msg = f"{rows:,} evidence rows; classifications by tier: {detail}"
    return EvalResult("classification_evidence", ERROR, ok, msg,
                      {"evidence_rows": rows, "tiers": tiers})


def check_kev_classification_complete(conn) -> EvalResult:
    """Every catalogued vulnerability is placed, and the guesses are declared.

    ERROR on an unplaced row, because complete coverage is now a published claim and a
    claim with a silent hole in it is worse than an honest gap. ERROR too if anything
    inferred or assumed is recorded at high confidence — that is the line the whole
    five-tier design exists to hold, and it is cheap to check every run.
    """
    with conn.cursor() as cur:
        cur.execute("""select coalesce(sum(year_classified), 0), coalesce(sum(year_measured), 0),
                              coalesce(sum(year_unclassified), 0)
                         from (select distinct cohort_year, year_classified, year_measured,
                                      year_unclassified
                                 from derived.kev_technology_cohorts
                                where kev_scope = 'all') x""")
        placed, measured, unplaced = cur.fetchone()
        cur.execute("""select count(*) from derived.cve_classification
                        where evidence_tier in ('inferred', 'assumed') and confidence = 'high'""")
        mislabelled = cur.fetchone()[0]

    total = placed + unplaced
    if total == 0:
        return EvalResult("kev_classification_complete", ERROR, False,
                          "no catalogued vulnerabilities to classify", {})
    ok = unplaced == 0 and mislabelled == 0
    if unplaced:
        msg = (f"{unplaced:,} of {total:,} catalogued vulnerabilities are UNPLACED, but the "
               "site publishes complete coverage")
    elif mislabelled:
        msg = f"{mislabelled:,} inferred or assumed rows are recorded at HIGH confidence"
    else:
        msg = (f"{placed:,}/{total:,} catalogued vulnerabilities placed (100%), of which "
               f"{measured:,} ({measured / total * 100:.1f}%) rest on a named source")
    return EvalResult("kev_classification_complete", ERROR, ok, msg,
                      {"placed": placed, "measured": measured, "unplaced": unplaced,
                       "inferred_pct": round((placed - measured) / total * 100, 1)})


def check_independence_counts_agree(conn) -> EvalResult:
    """The two tables that count independent observers must agree.

    ERROR. 0027 measured that KEVIntel is not an independent observer of anything CISA
    lists and taught rebuild_kev_consolidated to discount it. The fix went into ONE
    table: derived.cve_detail kept its own plain count(distinct canonical_source), which
    knows nothing about observer dependencies, and that is the table the explorer reads.
    Measured before the fix: 1,684 of 5,211 CVEs, 32.3%, published one more independent
    observer than the consolidation said.

    This exists because two implementations of the same quantity is two chances to
    disagree, and the gap was invisible for as long as nobody compared them. It also
    guards the fallback in cve_detail_independent_sources: if the consolidation has not
    been rebuilt, that fallback quietly serves the undiscounted number, and this is what
    makes that state loud instead of comfortable.
    """
    # IT MUST NAME THE ROWS. This fired on both scheduled runs of 2026-09-17 with
    # "1 of 5,316 CVEs" and nothing else, and by the time anyone looked the next
    # rebuild had cleared it. A count alone cannot distinguish the systemic defect
    # this exists to catch - the discount reaching neither table, which is every CVE
    # carrying a dependent observer - from one row that is briefly stale because
    # kev_consolidated moved after cve_detail was built. Those want opposite
    # responses, and the message is the only evidence that survives the run.
    with conn.cursor() as cur:
        cur.execute("""select d.cve_id, d.kev_independent_source_count, k.independent_source_count
                         from derived.cve_detail d
                         join derived.kev_consolidated k on k.cve_id = d.cve_id
                        where d.kev_independent_source_count <> k.independent_source_count
                        order by d.cve_id
                        limit 6""")
        sample = cur.fetchall()
        cur.execute("""select count(*) from derived.cve_detail d
                         join derived.kev_consolidated k on k.cve_id = d.cve_id
                        where d.kev_independent_source_count <> k.independent_source_count""")
        differ = cur.fetchone()[0]
        cur.execute("""select count(*) from derived.cve_detail d
                         join derived.kev_consolidated k on k.cve_id = d.cve_id""")
        total = cur.fetchone()[0]
    ok = differ == 0
    named = ", ".join(f"{c} (detail {d} vs consolidation {n})" for c, d, n in sample[:5])
    if len(sample) > 5:
        named += ", ..."
    msg = (f"cve_detail and kev_consolidated agree on independent observers for all "
           f"{total:,} shared CVEs" if ok else
           f"{differ:,} of {total:,} CVEs publish an independence count that disagrees "
           "with the consolidation; the observer dependency discount is not reaching "
           f"derived.cve_detail — {named}")
    return EvalResult("independence_counts_agree", ERROR, ok, msg,
                      {"differ": differ, "total": total,
                       "sample": [{"cve_id": c, "cve_detail": d, "kev_consolidated": n}
                                  for c, d, n in sample[:5]]})


def check_corpus_cohorts_populated(conn) -> EvalResult:
    with conn.cursor() as cur:
        cur.execute("""select count(*), count(distinct metric) from derived.corpus_cohorts""")
        rows, metrics = cur.fetchone()
    ok = rows > 0 and metrics == 2
    return EvalResult("corpus_cohorts_populated", ERROR, ok,
                      f"{rows} rows across {metrics} metrics" if ok
                      else f"corpus_cohorts holds {rows} rows / {metrics} metrics "
                           "— expected both cves_published and kev_entered",
                      {"rows": rows, "metrics": metrics})


def check_cohort_boundaries_agree(conn) -> EvalResult:
    """The two cohort charts sit on one page and must stop at the same month.

    They call one shared window function, so this asserts the property the refactor
    was for. If it ever fails, the page is showing two charts censored differently and
    a reader has no way to tell.
    """
    with conn.cursor() as cur:
        cur.execute("""select
              (select count(distinct (boundary_year, boundary_month)) from derived.corpus_cohorts),
              (select count(distinct (boundary_year, boundary_month)) from derived.technology_cohorts),
              (select max(boundary_year) from derived.corpus_cohorts),
              (select max(boundary_month) from derived.corpus_cohorts),
              (select max(boundary_year) from derived.technology_cohorts),
              (select max(boundary_month) from derived.technology_cohorts)""")
        cn, tn, cy, cm, ty, tm = cur.fetchone()
    ok = cn == 1 and tn == 1 and (cy, cm) == (ty, tm)
    return EvalResult("cohort_boundaries_agree", ERROR, ok,
                      f"both cohort charts stop at {cy}-{cm:02d}" if ok
                      else f"BOUNDARY DRIFT: corpus {cy}-{cm}, technology {ty}-{tm}",
                      {"corpus": [cy, cm], "technology": [ty, tm]})


def check_corpus_monotonic(conn) -> EvalResult:
    """A cumulative series that falls is arithmetically impossible; catch it here."""
    with conn.cursor() as cur:
        cur.execute("""select count(*) from derived.corpus_cohorts a
                         join derived.corpus_cohorts b
                           on b.metric = a.metric and b.cohort_year = a.cohort_year
                          and b.month_index = a.month_index + 1
                        where b.cumulative_count < a.cumulative_count""")
        bad = cur.fetchone()[0]
    return EvalResult("corpus_monotonic", ERROR, bad == 0,
                      "every cumulative series is non-decreasing" if bad == 0
                      else f"{bad} month-pairs where the cumulative count FELL",
                      {"violations": bad})


def check_kev_bulk_loads_flagged(conn) -> EvalResult:
    """Report the catalogue onboarding events the chart is marking.

    INFO by design. Their presence is a property of the catalogues, not a fault in the
    pipeline — but they are the single most important caveat on the KEV panel, so the
    run states them rather than leaving them to be rediscovered.
    """
    with conn.cursor() as cur:
        cur.execute("""select event_date, source_id, entries, multiple_of_median
                         from derived.kev_bulk_loads order by rank_in_window limit 5""")
        rows = cur.fetchall()
    top = "; ".join(f"{d} {s} {n} entries ({m}x median)" for d, s, n, m in rows[:3])
    return EvalResult("kev_bulk_loads_flagged", INFO, True,
                      f"{len(rows)} catalogue onboarding event(s) marked on the chart"
                      + (f" — {top}" if top else ""),
                      {"events": [{"date": str(d), "source": s, "entries": n,
                                   "multiple_of_median": float(m)} for d, s, n, m in rows]})


def check_patch_window_bands_sum(conn) -> EvalResult:
    """The three bands must partition the 90-day total exactly.

    A gap between bands would silently drop rows; an overlap would double-count them.
    Either way the stacked bar would not equal the number printed above it.
    """
    with conn.cursor() as cur:
        cur.execute("""select count(*) from derived.patch_window_cohorts
                        where emergency + out_of_band + scheduled <> attacked_within_90d""")
        bad = cur.fetchone()[0]
        cur.execute("select count(*) from derived.patch_window_cohorts")
        total = cur.fetchone()[0]
    return EvalResult("patch_window_bands_sum", ERROR, bad == 0 and total > 0,
                      f"the three bands partition the 90-day total on all {total} cohorts"
                      if bad == 0 and total > 0
                      else f"{bad} of {total} cohorts where the bands do not sum",
                      {"cohorts": total, "violations": bad})


def check_patch_window_maturity_ordered(conn) -> EvalResult:
    """Maturity must fall as the band gets longer — 0 days >= 29 days >= 90 days.

    This is what lets the frontend draw a young cohort honestly: its emergency band is
    complete while its scheduled band is not.
    """
    with conn.cursor() as cur:
        cur.execute("""select count(*) from derived.patch_window_cohorts
                        where maturity_emergency_pct < maturity_out_of_band_pct
                           or maturity_out_of_band_pct < maturity_scheduled_pct""")
        bad = cur.fetchone()[0]
        cur.execute("""select period_label, maturity_out_of_band_pct, maturity_scheduled_pct
                         from derived.patch_window_cohorts
                        where not is_complete order by period_start""")
        young = cur.fetchall()
    detail = "; ".join(f"{p}: 29d {a}%, 90d {b}%" for p, a, b in young)
    return EvalResult("patch_window_maturity_ordered", ERROR, bad == 0,
                      f"maturity falls monotonically with band length"
                      + (f" — still filling: {detail}" if detail else " — every cohort complete")
                      if bad == 0 else f"{bad} cohorts with out-of-order maturity",
                      {"violations": bad, "incomplete": [
                          {"period": p, "maturity_29d": float(a), "maturity_90d": float(b)}
                          for p, a, b in young]})


#: Internal bookkeeping a public view is entitled to withhold. These describe the RUN,
#: not the vulnerability, and publishing them would put a rebuild timestamp on every
#: exported row without telling a reader anything. Everything else must be exposed.
VIEW_INTERNAL_COLUMNS = {"computed_at", "computed_by_run"}

#: Public views and the table each one is supposed to expose in full.
VIEW_BASE_TABLES = [
    ("public.cve_detail",            "derived.cve_detail"),
    ("public.technology_cohorts",    "derived.technology_cohorts"),
    ("public.technology_coverage",   "derived.technology_coverage"),
    ("public.corpus_cohorts",        "derived.corpus_cohorts"),
    ("public.kev_bulk_loads",        "derived.kev_bulk_loads"),
    ("public.patch_window_cohorts",  "derived.patch_window_cohorts"),
    ("public.kev_technology_cohorts","derived.kev_technology_cohorts"),
    ("public.severity_predictiveness","derived.severity_predictiveness"),
    ("public.scan_age_mix",          "derived.scan_age_mix"),
    ("public.kev_lag_points",        "derived.kev_lag_points"),
]


def check_kev_technology_consistent(conn) -> EvalResult:
    """Emergency must be a strict subset of all, in every cell, and shares must sum.

    Both properties are cheap and both would break silently: a scope filter applied to
    the wrong side of the union would let emergency exceed all, and a share computed
    against the wrong denominator would still render a plausible-looking chart.
    """
    with conn.cursor() as cur:
        cur.execute("""select count(*) from derived.kev_technology_cohorts e
                         join derived.kev_technology_cohorts a
                           on a.kev_scope='all' and a.category=e.category
                          and a.cohort_year=e.cohort_year
                        where e.kev_scope='emergency' and e.entries > a.entries""")
        subset_violations = cur.fetchone()[0]
        cur.execute("""select count(*) from (
                         select kev_scope, cohort_year, sum(share_pct) s
                           from derived.kev_technology_cohorts
                          where year_classified > 0
                          group by 1,2) t
                        where abs(t.s - 100) > 0.6""")
        share_violations = cur.fetchone()[0]
        cur.execute("select count(*), count(distinct kev_scope) from derived.kev_technology_cohorts")
        rows, scopes = cur.fetchone()
    ok = rows > 0 and scopes == 2 and subset_violations == 0 and share_violations == 0
    return EvalResult("kev_technology_consistent", ERROR, ok,
                      f"{rows} cells across 2 scopes; emergency is a subset of all "
                      "everywhere and shares sum to 100" if ok
                      else f"{subset_violations} cells where emergency exceeds all, "
                           f"{share_violations} scope-years whose shares do not sum",
                      {"rows": rows, "scopes": scopes,
                       "subset_violations": subset_violations,
                       "share_violations": share_violations})


def check_kev_technology_window_rolls(conn) -> EvalResult:
    """The bottom chart must track the censoring date like every other cohort chart.

    THE SPAN IS READ OUT OF THE FUNCTION, NOT WRITTEN HERE. This eval asserted
    ``lo == exp_year - 5`` against a six-year span; 0044 widened the default to nine so
    the chart could offer a from-2018 view, and the literal would have failed every
    scheduled run on correct data. A constant mirrored in two places is the same defect
    as ``coverage_not_dropped`` comparing two different quantities — it passes only while
    nobody changes the other copy. Introspecting the default means a change to it moves
    this check with it, and a span the function does not actually declare still fails.
    """
    with conn.cursor() as cur:
        cur.execute("""select min(cohort_year), max(cohort_year), max(boundary_year),
                              max(boundary_month), max(censored_at)
                         from derived.kev_technology_cohorts""")
        lo, hi, byear, bmonth, censored = cur.fetchone()
        cur.execute("""select pg_get_function_arguments(p.oid)
                         from pg_proc p join pg_namespace n on n.oid = p.pronamespace
                        where n.nspname = 'derived' and p.proname = 'rebuild_kev_technology'""")
        sig = cur.fetchone()
    if censored is None:
        return EvalResult("kev_technology_window_rolls", ERROR, False,
                          "no kev_technology rows to check", {})
    m = re.search(r"p_span_years\s+integer\s+DEFAULT\s+(\d+)", sig[0] if sig else "",
                  re.IGNORECASE)
    if m is None:
        return EvalResult("kev_technology_window_rolls", ERROR, False,
                          "rebuild_kev_technology declares no p_span_years default — the "
                          "window this eval is meant to check is not knowable", {})
    span = int(m.group(1))
    exp_year, exp_month = (censored.year, censored.month - 1) if censored.month > 1 \
        else (censored.year - 1, 12)
    ok = (byear, bmonth) == (exp_year, exp_month) and hi == exp_year \
        and lo == exp_year - (span - 1)
    return EvalResult("kev_technology_window_rolls", ERROR, ok,
                      f"window {lo}..{hi} ({span}y), boundary {byear}-{bmonth:02d}" if ok
                      else f"window {lo}..{hi} boundary {byear}-{bmonth} — expected "
                           f"{exp_year-(span-1)}..{exp_year} boundary "
                           f"{exp_year}-{exp_month:02d}; the chart has frozen",
                      {"window": [lo, hi], "span_years": span, "boundary": [byear, bmonth],
                       "expected_boundary": [exp_year, exp_month]})


def check_severity_windows_nest(conn) -> EvalResult:
    """Where both windows cover the SAME population, 90-day attacks nest inside 180-day.

    The restriction matters and is not pedantry. Each window's denominator is limited to
    vulnerabilities that have had that window to be observed in, so the two windows do
    not describe the same set in a young cohort: measured 2026-08-31, the 2026 cohort is
    ~60% mature at 90 days and ~20% at 180, and the 180-day view therefore drops most of
    the cohort INCLUDING attacked rows. attacked(90) legitimately exceeds attacked(180)
    in all four 2026 bands.

    Checking nesting globally would fail on correct data every time the newest cohort is
    young — which is always. Restricting to cohorts complete in both windows tests the
    invariant where it actually holds, and would still catch a window filter applied to
    the wrong side of the comparison.
    """
    with conn.cursor() as cur:
        cur.execute("""select count(*) from derived.severity_predictiveness a
                         join derived.severity_predictiveness b
                           on b.cohort_year = a.cohort_year and b.band = a.band
                        where a.window_days = 90 and b.window_days = 180
                          and not a.is_partial and not b.is_partial
                          and a.attacked > b.attacked""")
        bad = cur.fetchone()[0]
        cur.execute("""select count(*) from derived.severity_predictiveness
                        where published_mature > published_all""")
        denom = cur.fetchone()[0]
        cur.execute("select count(*), count(distinct window_days) from derived.severity_predictiveness")
        rows, windows = cur.fetchone()
    ok = rows > 0 and windows == 2 and bad == 0 and denom == 0
    return EvalResult("severity_windows_nest", ERROR, ok,
                      f"{rows} cells across both windows; in cohorts complete in both, "
                      "90d attacks nest inside 180d and no mature denominator exceeds "
                      "its cohort" if ok
                      else f"{bad} complete cells where 90d exceeds 180d, {denom} with "
                           "an impossible denominator",
                      {"rows": rows, "windows": windows,
                       "nesting_violations": bad, "denominator_violations": denom})


def check_severity_separation(conn) -> EvalResult:
    """Report what the chart claims, so a change in the headline is visible in the log.

    INFO: the numbers are the finding, not a pass/fail condition. Printing them each run
    means a shift shows up in the pipeline output rather than only on the page.
    """
    with conn.cursor() as cur:
        cur.execute("""select window_days,
                 round(10000.0*sum(attacked) filter (where band='CRITICAL')
                       / nullif(sum(published_mature) filter (where band='CRITICAL'),0)) crit,
                 round(10000.0*sum(attacked) filter (where band='HIGH')
                       / nullif(sum(published_mature) filter (where band='HIGH'),0)) high,
                 round(100.0*sum(attacked) filter (where band<>'CRITICAL')
                       / nullif(sum(attacked),0)) below
               from derived.severity_predictiveness group by 1 order by 1""")
        rows = cur.fetchall()
    parts = [f"{w}d: critical {c}/10k vs high {h}/10k, {b}% of attacked rated below critical"
             for w, c, h, b in rows]
    return EvalResult("severity_separation", INFO, True, " · ".join(parts),
                      {"windows": [{"window_days": w, "critical_per_10k": float(c or 0),
                                    "high_per_10k": float(h or 0),
                                    "pct_attacked_below_critical": float(b or 0)}
                                   for w, c, h, b in rows]})


def check_no_telemetry_in_kev(conn) -> EvalResult:
    """The KEV layer holds catalogue listings only. Sensor telemetry lives in obs_core.

    CIRCL's kev_entries dump passes Shadowserver honeypot data through in the same shape
    as a real catalogue entry, and it was ingested as one until 2026-09-01: 1,296 rows
    that set first_kev_date for 506 CVEs and counted as an independent observer for
    1,231. A CHECK constraint now blocks the known telemetry types; this asserts the
    constraint is present AND looks for types it does not yet know about, so a new sensor
    feed from any aggregator shows up as a failed run rather than as exploitation dates.
    """
    with conn.cursor() as cur:
        cur.execute("""select coalesce(string_agg(distinct evidence_type, ', '), '')
                         from core.kev_entries
                        where evidence_type in ('honeypot', 'sinkhole')""")
        known = cur.fetchone()[0]
        # Anything not on the allow-list is a claim basis nobody has reviewed.
        cur.execute("""select coalesce(string_agg(distinct evidence_type, ', '), '')
                         from core.kev_entries
                        where evidence_type is not null
                          and evidence_type not in ('public_report', 'vendor_report',
                                                    'csirt_report', 'incident_response')""")
        unknown = cur.fetchone()[0]
        cur.execute("select count(*) from pg_constraint where conname = 'kev_entries_no_telemetry'")
        guarded = cur.fetchone()[0] == 1
        cur.execute("""select canonical_source from core.upstream_canonical
                        where upstream_source = 'shadowserver'""")
        row = cur.fetchone()
        sensor_mapped = (row is None) or (row[0] == 'sensor-not-a-catalogue')
    ok = not known and not unknown and guarded and sensor_mapped
    return EvalResult("no_telemetry_in_kev", ERROR, ok,
                      "the KEV layer holds catalogue listings only; the constraint is in "
                      "place and Shadowserver cannot count as an observer" if ok
                      else f"telemetry present: [{known}]; unreviewed evidence types: "
                           f"[{unknown}]; constraint: {guarded}; sensor mapped: {sensor_mapped}",
                      {"telemetry": known, "unreviewed_types": unknown,
                       "constraint_present": guarded, "sensor_demapped": sensor_mapped})


def check_kev_sources_say_kev(conn) -> EvalResult:
    """Every KEV catalogue must name itself as one, and no observation source may.

    The site draws on two pipelines that answer different questions — a catalogue
    LISTING and a sensor OBSERVATION — and VulnCheck sits in both, as a KEV catalogue and
    as a canary sensor. A figure quoted as coming from "VulnCheck" is ambiguous between
    them. A CHECK constraint enforces the naming in the table; this asserts the constraint
    is still there and still true, and that the observation sources were NOT swept up in
    it — labelling Shadowserver "Shadowserver KEV" would assert the corroboration it is
    measured not to provide.
    """
    with conn.cursor() as cur:
        cur.execute("""select coalesce(string_agg(source_id, ', '), '')
                         from core.kev_sources
                        where short_name not like '%KEV%' or display_name not like '%KEV%'""")
        bad_kev = cur.fetchone()[0]
        cur.execute("""select coalesce(string_agg(source_id, ', '), '')
                         from obs_core.observation_sources where display_name like '%KEV%'""")
        bad_obs = cur.fetchone()[0]
        cur.execute("select count(*) from pg_constraint where conname = 'kev_sources_name_says_kev'")
        guarded = cur.fetchone()[0] == 1
        cur.execute("select count(*) from core.kev_sources")
        n = cur.fetchone()[0]
    ok = not bad_kev and not bad_obs and guarded
    return EvalResult("kev_sources_say_kev", ERROR, ok,
                      f"all {n} KEV sources carry KEV in their name, the CHECK constraint "
                      "is in place, and no observation source claims to be a catalogue"
                      if ok else
                      f"KEV sources missing KEV: [{bad_kev}]; observation sources claiming "
                      f"KEV: [{bad_obs}]; constraint present: {guarded}",
                      {"kev_sources_missing_kev": bad_kev,
                       "obs_sources_claiming_kev": bad_obs,
                       "constraint_present": guarded})


def check_kev_consolidated_has_no_orphans(conn) -> EvalResult:
    """Every consolidated vulnerability must still have a live assertion beneath it.

    rebuild_kev_consolidated was upsert-only until migration 0025: it refreshed every
    vuln_id present in core.kev_entries but never removed one that had disappeared from
    it. Nothing had ever disappeared, so the gap was invisible until 0024 purged the
    telemetry — 60 sensor-only identifiers then sat in derived.kev_consolidated, and in
    the public view, citing evidence that no longer existed. A published row whose
    primary evidence cannot be re-fetched is exactly what the provenance rule forbids.

    This also re-checks the sensor demapping downstream of the KEV layer, because a row
    can only cite Shadowserver as an observer if a purge was reverted upstream.
    """
    with conn.cursor() as cur:
        cur.execute("""select count(*) from derived.kev_consolidated k
                        where not exists (select 1 from core.kev_entries e
                                           where e.vuln_id = k.vuln_id)""")
        orphans = cur.fetchone()[0]
        cur.execute("""select count(*) from derived.kev_consolidated
                        where 'shadowserver' = any(upstream_sources)
                           or 'sensor-not-a-catalogue' = any(canonical_sources)""")
        sensor_cited = cur.fetchone()[0]
        cur.execute("""select count(*) from pg_proc p join pg_namespace n on n.oid = p.pronamespace
                        where n.nspname = 'derived' and p.proname = 'rebuild_kev_consolidated'
                          and pg_get_functiondef(p.oid) ilike '%delete from derived.kev_consolidated%'""")
        prunes = cur.fetchone()[0] == 1
        cur.execute("select count(*) from derived.kev_consolidated")
        n = cur.fetchone()[0]
    ok = orphans == 0 and sensor_cited == 0 and prunes
    return EvalResult("kev_consolidated_has_no_orphans", ERROR, ok,
                      f"all {n:,} consolidated vulnerabilities rest on a live assertion, "
                      "none cites a sensor, and the rebuild prunes what disappears"
                      if ok else
                      f"{orphans} consolidated rows have no backing assertion; "
                      f"{sensor_cited} cite a sensor; rebuild prunes: {prunes}",
                      {"orphans": orphans, "sensor_cited": sensor_cited,
                       "rebuild_prunes": prunes, "rows": n})


def check_schema_matches_migrations(conn) -> EvalResult:
    """Every live table and view must be created by a migration in this repository.

    IRON RULE 1 is that a stranger can rebuild every number from public sources plus this
    repo; IRON RULE 4 is that no SQL is run by hand. An object that exists only in the
    database satisfies neither — it cannot be rebuilt, cannot be reviewed, and is
    indistinguishable from a real derived table to anyone reading the schema, so it can be
    cited. derived.dashboard_halfyear (55 rows, hand-created during an exploration
    session, read by nothing) survived a fortnight before this check existed.

    The match is deliberately by NAME, not by parsing DDL: a stricter check would need a
    SQL parser and would fail on the many legitimate ways a migration alters an object.
    Name-presence is enough to catch the thing that actually happens — an object created
    outside the migration set entirely.
    """
    from pathlib import Path
    import re

    # ONLY supabase/migrations, deliberately. Widening this to game/server/migrations was
    # tried and reverted: game/ has never been committed (1.8 GB with node_modules), so
    # the check passed on a laptop and failed in CI — an eval reading untracked files is
    # worse than the defect it hides. The scoreboard is adopted into this set by 0067
    # instead, which is also what makes it reproducible by pipeline/tools/migrate.py.
    mig_dir = Path(__file__).resolve().parents[2] / "supabase" / "migrations"
    if not mig_dir.is_dir():
        return EvalResult("schema_matches_migrations", WARN, True,
                          f"migrations directory not found at {mig_dir} — check skipped",
                          {"migrations_dir": str(mig_dir)})
    corpus = "\n".join(p.read_text() for p in sorted(mig_dir.glob("*.sql")))
    with conn.cursor() as cur:
        cur.execute("""
            select schemaname, relname from pg_stat_user_tables
             where schemaname in ('raw','core','derived','obs_raw','obs_core','obs_derived','public')
            union
            select table_schema, table_name from information_schema.views
             where table_schema in ('public','derived','core','obs_core','obs_derived')
            order by 1, 2""")
        live = cur.fetchall()
    orphans = [f"{s}.{n}" for s, n in live
               if not re.search(rf"\b{re.escape(n)}\b", corpus)]
    ok = not orphans
    return EvalResult("schema_matches_migrations", ERROR, ok,
                      f"all {len(live)} live tables and views are created by a migration"
                      if ok else
                      f"{len(orphans)} object(s) exist in no migration — not reproducible: "
                      + ", ".join(orphans[:5]),
                      {"checked": len(live), "orphans": orphans})


def check_kev_lag_points_fresh(conn) -> EvalResult:
    """The lag chart's table is populated, current, and still rolling forward.

    NOTHING WATCHED THIS TABLE. It was registered in all four enumerated lists —
    REBUILDS, EXPORTS, VIEW_BASE_TABLES and the method-version union — and every one
    of those checks a property that stays true of an EMPTY or FROZEN table. A rebuild
    that started returning zero rows, or a censoring date stuck in the past, would
    have shipped a blank or stale chart on the home page with every eval green.

    Three properties, each one a way this has failed elsewhere on this site:

      1. POPULATED. `rebuild_kev_lag_points` is delete-then-insert, so a transform
         that silently matched nothing leaves an empty table rather than a stale one.
         v1's collector death is this shape.
      2. CURRENT. `censored_at` comes from `derived.kev_lag_censoring_date()`, the
         minimum last-successful fetch across the registry and the four catalogues.
         If that stalls, the chart keeps drawing and quietly stops moving — the exact
         failure the project's censoring-date doctrine exists to prevent. 45 days is
         deliberately loose: the rebuild runs twice daily, so anything beyond a few
         days is already a problem, and this is the backstop that must not cry wolf.
      3. ROLLING. The newest publication cohort must reach the present. The chart has
         a measured FLOOR (2021H1) and no ceiling anywhere — columns, lane heights,
         the y domain and the axis ticks are all derived from the data — so a frozen
         top is not something the code can cause, only something a dead upstream can.
         Asserting it here is what turns that from a claim into a check, and it is
         what makes the table's behaviour in 2027 and beyond a test rather than a
         hope.
    """
    with conn.cursor() as cur:
        cur.execute("""
            select count(*),
                   max(censored_at),
                   max(publication_half),
                   max(report_half)
              from derived.kev_lag_points
        """)
        rows, censored, newest_pub, newest_report = cur.fetchone()
        cur.execute("select derived.half_year(current_date)")
        now_half = cur.fetchone()[0]

    if not rows:
        return EvalResult("kev_lag_points_fresh", ERROR, False,
                          "derived.kev_lag_points is EMPTY — the lag chart has no data",
                          {"rows": 0})

    lag_days = (date.today() - censored).days if censored else None
    # The newest cohort may legitimately trail the current half by one: a half that has
    # only just begun can hold no listed CVE yet. Two halves behind is a stopped feed.
    def half_index(h: str) -> int:
        return int(h[:4]) * 2 + (1 if h.endswith("H2") else 0)
    behind = half_index(now_half) - half_index(newest_report) if newest_report else 99

    problems = []
    if lag_days is None or lag_days > 45:
        problems.append(f"censoring date is {censored} ({lag_days} days old)")
    if behind > 1:
        problems.append(f"newest reporting half is {newest_report}, {behind} halves "
                        f"behind {now_half} — the window has stopped rolling")

    return EvalResult(
        "kev_lag_points_fresh", ERROR, not problems,
        f"{rows:,} lag points · censored {censored} · publication cohorts to "
        f"{newest_pub} · listings to {newest_report}" if not problems
        else "the lag chart's table is not current: " + "; ".join(problems),
        {"rows": rows, "censored_at": str(censored), "censoring_age_days": lag_days,
         "newest_publication_half": newest_pub, "newest_report_half": newest_report,
         "current_half": now_half, "halves_behind": behind})


def check_views_expose_all_columns(conn) -> EvalResult:
    """A view's `select *` is frozen at CREATE time — catch the columns it now misses.

    Postgres expands `select *` into an explicit column list when the view is created.
    Add a column to the table afterwards and the view silently keeps serving the old
    shape: the API returns rows without the new field and the frontend renders NaN,
    with no error anywhere. This shipped once (migration 0019's rate columns against
    0018's view) and cost a debugging cycle.

    Migrations must therefore re-issue CREATE OR REPLACE VIEW whenever they add a
    column. This asserts they did.
    """
    missing: dict[str, list[str]] = {}
    with conn.cursor() as cur:
        for view, table in VIEW_BASE_TABLES:
            vs, vn = view.split(".")
            ts, tn = table.split(".")
            cur.execute("""select column_name from information_schema.columns
                            where table_schema=%s and table_name=%s""", (ts, tn))
            base = {r[0] for r in cur.fetchall()}
            cur.execute("""select column_name from information_schema.columns
                            where table_schema=%s and table_name=%s""", (vs, vn))
            seen = {r[0] for r in cur.fetchall()}
            if not seen:
                continue  # view absent in this environment; other checks cover that
            gap = sorted(base - seen - VIEW_INTERNAL_COLUMNS)
            if gap:
                missing[view] = gap
    return EvalResult("views_expose_all_columns", ERROR, not missing,
                      f"all {len(VIEW_BASE_TABLES)} public views expose every data "
                      "column of their base table" if not missing
                      else "views are missing columns their table has — the view was not "
                           f"replaced after a column was added: {missing}",
                      {"missing": missing})


def check_explorer_list_fresh(conn) -> EvalResult:
    """The Explorer list must have been rebuilt in the same pass as the table it projects.

    THIS IS THE HAZARD-1 CHECK FOR THE EXPLORER. derived.explorer_list is a materialised
    projection of derived.cve_detail. If its rebuild is dropped from run.py, or throws while
    cve_detail succeeds, the page keeps serving whatever set it last held, for ever, with no
    error anywhere. That is exactly how v1 published six months of stale exploitation data.

    Equality of censoring dates is the tightest available signal: both are written from the
    same censored_at parameter inside one run.
    """
    with conn.cursor() as cur:
        cur.execute("select max(censored_at) from derived.cve_detail")
        detail = cur.fetchone()[0]
        cur.execute("select max(censored_at), count(*) from derived.explorer_list")
        listed, n = cur.fetchone()
    ok = detail is not None and listed == detail
    return EvalResult(
        "explorer_list_fresh", ERROR, ok,
        f"explorer_list censored {listed} matches cve_detail, {n:,} rows" if ok
        else f"explorer_list censored {listed} but cve_detail censored {detail}",
        {"list_censored_at": str(listed), "detail_censored_at": str(detail), "rows": n})


def check_explorer_list_complete(conn) -> EvalResult:
    """Every row the predicate selects is in the list, and nothing else is.

    A partial rebuild is worse than no rebuild: the page looks healthy and is quietly missing
    vulnerabilities. Compared against the predicate rather than a fixed number, so the check
    stays valid as the corpus grows.
    """
    with conn.cursor() as cur:
        cur.execute("""select count(*) from derived.cve_detail
                        where kev_status = 'in_kev' or observation_count_total > 0""")
        expect = cur.fetchone()[0]
        cur.execute("select count(*) from derived.explorer_list")
        got = cur.fetchone()[0]
    return EvalResult(
        "explorer_list_complete", ERROR, got == expect,
        f"{got:,} rows, matching the predicate exactly" if got == expect
        else f"explorer_list holds {got:,} rows but the predicate selects {expect:,}",
        {"in_list": got, "expected": expect})


def check_explorer_strata_agree(conn) -> EvalResult:
    """The header numbers must describe the same corpus the list is drawn from.

    The strata are precomputed because exact counts over 366,854 rows blocked the first paint.
    Precomputing them means they can go stale independently of everything else, and three
    confident wrong numbers at the top of the page is a worse failure than a slow page.
    """
    with conn.cursor() as cur:
        cur.execute("""select count(*),
                              count(*) filter (where kev_status = 'in_kev'),
                              count(*) filter (where observation_count_total > 0)
                         from derived.cve_detail""")
        pub, kev, scan = cur.fetchone()
        cur.execute("select published, catalogued, scanned from derived.explorer_strata")
        row = cur.fetchone()
    if row is None:
        return EvalResult("explorer_strata_agree", ERROR, False,
                          "derived.explorer_strata is empty", {})
    ok = (row[0], row[1], row[2]) == (pub, kev, scan)
    return EvalResult(
        "explorer_strata_agree", ERROR, ok,
        f"published {pub:,}, catalogued {kev:,}, scanned {scan:,}" if ok
        else f"strata {tuple(row)} but cve_detail says {(pub, kev, scan)}",
        {"strata": list(row), "detail": [pub, kev, scan]})


def check_activity_window_fresh(conn, max_lag_days: int = 3) -> EvalResult:
    """The sparkline window must track the sensor, not drift behind it.

    Anchored to max(observed_at) rather than to today, so a stalled collector shows as a stale
    window rather than as an empty chart. This asserts the ANCHOR still moves: if the activity
    rebuild stops while the honeypot harvester keeps writing, the gap grows and this fails.
    """
    with conn.cursor() as cur:
        cur.execute("""select max(observed_at) from obs_core.exploitation_observations
                        where source_id = 'shadowserver_api'""")
        feed = cur.fetchone()[0]
        cur.execute("select max(window_end), count(*) from derived.cve_activity_daily")
        win, n = cur.fetchone()
    if feed is None:
        return EvalResult("activity_window_fresh", INFO, True,
                          "no shadowserver_api observations to window", {})
    if win is None:
        return EvalResult("activity_window_fresh", ERROR, False,
                          "the activity table is empty while the feed has data", {})
    lag = (feed - win).days
    return EvalResult(
        "activity_window_fresh", ERROR if lag > max_lag_days else INFO, lag <= max_lag_days,
        f"activity window ends {win}, {lag} day(s) behind the feed, {n:,} rows",
        {"window_end": str(win), "feed_end": str(feed), "lag_days": lag})



def check_method_versions_registered(conn) -> EvalResult:
    """Every published method_version must name a row in core.method_registry.

    The scoreboard promises that a chart's version identifies the method that made
    it. That promise is only worth something if the stamp cannot be an arbitrary
    string: `--method-version` is a free-text argument, and one global value was
    being applied to ten metrics with ten independent version histories. Measured
    2026-09-03: patch_window_cohorts and pressure_index were correctly on v5 while
    the pipeline default was v3, so a scheduled run would have re-stamped them and
    pointed every reader at the wrong method description.

    Asserts the join in the direction that catches it — a stamp with no registry row
    is a defect; a registry row with no data yet is just an unreleased version.
    """
    with conn.cursor() as cur:
        cur.execute("""
            with stamped as (
                select 'patch_window_cohorts' m, method_version v
                  from derived.patch_window_cohorts
                union select 'pressure_index', method_version from derived.pressure_index
                union select 'kev_technology_cohorts', method_version
                  from derived.kev_technology_cohorts
                union select 'technology_cohorts', method_version from derived.technology_cohorts
                union select 'corpus_cohorts', method_version from derived.corpus_cohorts
                union select 'severity_predictiveness', method_version
                  from derived.severity_predictiveness
                union select 'scan_pressure', method_version from derived.scan_pressure
                union select 'scan_age_mix', method_version from derived.scan_age_mix
            union select 'kev_lag_points', method_version from derived.kev_lag_points
                union select 'cve_detail', method_version from derived.cve_detail
                union select 'cve_technology', method_version from derived.cve_technology
                union select 'kev_consolidated', method_version from derived.kev_consolidated
            )
            select s.m, s.v from stamped s
             where s.v is not null
               and not exists (select 1 from core.method_registry r
                                where r.metric_id = s.m and r.method_version = s.v)
             order by 1, 2
        """)
        orphans = cur.fetchall()
    return EvalResult(
        "method_versions_registered", ERROR, not orphans,
        "every published method_version names a registry row" if not orphans
        else f"{len(orphans)} stamped version(s) absent from core.method_registry: "
             + ", ".join(f"{m}={v}" for m, v in orphans),
        {"orphans": [{"metric": m, "version": v} for m, v in orphans]})


def check_patch_dates_not_backdated(conn, max_share_pct: float = 2.0) -> EvalResult:
    """A Microsoft-assigned CVE fixed long before its own record existed is a parsing error.

    THIS IS THE REGRESSION GUARD FOR A BUG THAT SHIPPED. The first version of the MSRC rule
    read the document's InitialReleaseDate for every CVE in it, and MSRC back-adds CVEs to old
    documents. CVE-2022-41082 came out at 2022-09-13 when its fix shipped 2022-11-08: seven
    weeks early, and on the wrong side of the KEV listing, which turns "exploited before a
    patch existed" from true into false.

    Only MICROSOFT-ASSIGNED CVEs are bounded. Microsoft ships fixes for third-party components
    it bundles, so a Chromium or Linux CVE legitimately shows a Microsoft fix date before the
    upstream record was published: measured 36-50% early for those CNAs against 5.25% for
    Microsoft's own, and 0.55% beyond thirty days. A bound over the whole corpus would have to
    be so loose it could not fail.
    """
    with conn.cursor() as cur:
        cur.execute("""select count(*),
                              count(*) filter (where patch_available_date
                                               < date_published - 30)
                         from derived.cve_detail
                        where assigner_short_name = 'microsoft'
                          and patch_available_date is not null
                          and date_published is not null""")
        n, early = cur.fetchone()
    if not n:
        return EvalResult("patch_dates_not_backdated", INFO, True,
                          "no Microsoft-assigned CVE carries a patch date yet", {})
    share = 100.0 * early / n
    return EvalResult(
        "patch_dates_not_backdated", ERROR, share <= max_share_pct,
        f"{early:,} of {n:,} Microsoft CVEs ({share:.2f}%) patched >30d before publication",
        {"early": early, "total": n, "share_pct": round(share, 2),
         "max_share_pct": max_share_pct})


def check_sensors_are_not_vendor_reports(conn) -> EvalResult:
    """A vendor statement must never be published as a sensor sighting.

    obs_core carries two observation types and the distinction is the reason the observation
    pipeline exists: attempt_observed means a sensor saw someone try it, while
    vendor_reports_exploitation means the vendor says it happened. Microsoft's "Exploited: Yes"
    is the second, and rendering it as "scanned" would claim evidence that does not exist.

    The Explorer splits them once, in rebuild_explorer_list, into sensor_sources and
    vendor_reported_by. This asserts the split held: no source that only ever reports vendor
    statements may appear in sensor_sources, and every id in either array must be a registered
    observation source.
    """
    with conn.cursor() as cur:
        cur.execute("""select distinct source_id from obs_core.exploitation_observations
                        where observation_type = 'vendor_reports_exploitation'
                          and source_id not in (
                              select source_id from obs_core.exploitation_observations
                               where observation_type = 'attempt_observed')""")
        vendor_only = {r[0] for r in cur.fetchall()}
        cur.execute("""select count(*) from derived.explorer_list
                        where sensor_sources && %s""", (list(vendor_only) or [""],))
        leaked = cur.fetchone()[0]
        cur.execute("""select count(*) from derived.explorer_list
                        where cardinality(sensor_sources) > 0""")
        sensed = cur.fetchone()[0]
    ok = leaked == 0
    return EvalResult(
        "sensors_are_not_vendor_reports", ERROR, ok,
        f"{sensed:,} rows carry a sensor sighting; no vendor-only source among them "
        f"({', '.join(sorted(vendor_only)) or 'none registered'})" if ok
        else f"{leaked:,} rows list a vendor-report-only source as a sensor",
        {"leaked": leaked, "sensed": sensed, "vendor_only_sources": sorted(vendor_only)})


def check_scan_state_consistent(conn) -> EvalResult:
    """Counted attempts imply a sensor. The page reads the two together and they must agree.

    scanState() calls a row 'counted' on observation_count_total and 'sighted' on
    sensor_sources. A row with counts but no sensor id, or a date but neither, would make the
    tag, the dates row and the chart disagree again, which is the bug this replaced.
    """
    with conn.cursor() as cur:
        cur.execute("""select
              count(*) filter (where observation_count_total > 0
                               and cardinality(sensor_sources) = 0)                 as counts_no_sensor,
              count(*) filter (where first_observed_at is not null
                               and cardinality(sensor_sources) = 0)                 as date_no_sensor,
              count(*) filter (where cardinality(sensor_sources) > 0
                               and first_observed_at is null)                       as sensor_no_date
            from derived.explorer_list""")
        a, b, c = cur.fetchone()
    ok = a == 0 and b == 0 and c == 0
    return EvalResult(
        "scan_state_consistent", ERROR, ok,
        "every counted row names a sensor, and every sensor row carries a date" if ok
        else f"{a} rows counted with no sensor, {b} dated with no sensor, "
             f"{c} sensed with no date",
        {"counts_without_sensor": a, "date_without_sensor": b, "sensor_without_date": c})


def check_public_views_readonly(conn) -> EvalResult:
    """Supabase's ALTER DEFAULT PRIVILEGES makes every new public view anon-writeable.

    Neither a local Postgres nor CI can catch this — the default privilege only exists
    on Supabase, which is why the assertion runs here, against the live database.
    """
    with conn.cursor() as cur:
        cur.execute("""select table_name, grantee, privilege_type
                         from information_schema.role_table_grants
                        where table_schema = 'public'
                          and grantee in ('anon','authenticated')
                          and privilege_type <> 'SELECT'
                        order by 1,2,3""")
        rows = cur.fetchall()
    return EvalResult("public_views_readonly", ERROR, not rows,
                      "anon/authenticated hold SELECT only on public.*" if not rows
                      else f"{len(rows)} write grants leaked to anon/authenticated",
                      {"leaks": [{"table": t, "grantee": g, "privilege": p}
                                 for t, g, p in rows[:20]]})


def check_pressure_window_matured(conn) -> EvalResult:
    """The published window must be as finished as the window it is divided by.

    The Pressure Index reads observed / prior_1 over the same three calendar months a
    year apart. That is only a year-on-year comparison if both sides have had equal time
    to be filed. Before 0079 they had not: 836 of August 2026's CVE records - 6.8% -
    arrived after the window closed, the vulnerability reading drifted 2.628x -> 2.704x
    on late filing alone, and the zero-day stream's published band moved `down` -> `level`
    with no new exploitation anywhere.

    This asserts the guard is APPLIED. `check_pressure_late_arrivals_settled` asserts the
    guard is BIG ENOUGH. Both are needed: the first catches the rebuild ignoring the
    parameter, the second catches the parameter being wrong.
    """
    with conn.cursor() as cur:
        # resolved exactly as db.current_method_versions() does, so the eval reads the
        # same registry row the rebuild applied rather than a string-sorted guess.
        cur.execute("""select (parameters ->> 'maturity_days')::int
                         from core.method_registry
                        where metric_id = 'pressure_index' and superseded_at is null
                        order by introduced_at desc nulls last, method_version desc
                        limit 1""")
        row = cur.fetchone()
        declared = row[0] if row and row[0] is not None else None
        cur.execute("""select min(window_matured_days), max(censored_at), count(*)
                         from derived.pressure_index""")
        matured, censored, n = cur.fetchone()

    if declared is None:
        return EvalResult("pressure_window_matured", ERROR, False,
                          "core.method_registry declares no maturity_days for "
                          "pressure_index — the rebuild would silently fall back to a "
                          "literal and nothing would check it",
                          {"rows": n})
    if n == 0:
        return EvalResult("pressure_window_matured", ERROR, False,
                          "derived.pressure_index is empty", {"rows": 0})
    if matured is None:
        return EvalResult("pressure_window_matured", ERROR, False,
                          "window_matured_days is null — rows were written by a rebuild "
                          "older than 0079 and their windows are unverifiable",
                          {"rows": n, "declared_maturity_days": declared})
    ok = matured >= declared
    return EvalResult("pressure_window_matured", ERROR, ok,
                      f"every published window had at least {matured}d to settle against "
                      f"a declared {declared}d (censored {censored})"
                      if ok else
                      f"a window was published with only {matured}d of settling against a "
                      f"declared {declared}d — the numerator is still being filed while "
                      f"the year-earlier denominator is finished, so the reading is "
                      f"biased upward and will drift",
                      {"min_window_matured_days": matured,
                       "declared_maturity_days": declared, "rows": n})


def check_pressure_late_arrivals_settled(conn) -> EvalResult:
    """Is maturity_days still big enough? Measured from the data, every run.

    The constant rests on ONE month of clean evidence - core.cves.first_seen_at begins
    2026-08-27, so earlier months read as "100% arrived late" purely from backfill. A
    number that thin must not sit in a migration comment going stale. This re-measures
    the real settling time and fails when filing behaviour outgrows the threshold, which
    is what makes the constant self-correcting rather than merely documented.

    Only months whose whole settling window is observable are used: a month that ended
    before ingestion started would report its backfill date, not its filing date.
    """
    with conn.cursor() as cur:
        # resolved exactly as db.current_method_versions() does, so the eval reads the
        # same registry row the rebuild applied rather than a string-sorted guess.
        cur.execute("""select (parameters ->> 'maturity_days')::int
                         from core.method_registry
                        where metric_id = 'pressure_index' and superseded_at is null
                        order by introduced_at desc nulls last, method_version desc
                        limit 1""")
        row = cur.fetchone()
        declared = row[0] if row and row[0] is not None else 14
        cur.execute("""
          with era as (select min(first_seen_at)::date + 1 as usable_from
                         from core.cves where first_seen_at is not null),
          x as (
            select ((first_seen_at at time zone 'UTC')::date
                    - (date_trunc('month', date_published at time zone 'UTC')
                       + interval '1 month - 1 day')::date) as settle_days
              from core.cves, era
             where state <> 'REJECTED' and date_published is not null
               and first_seen_at is not null
               -- the month must have STARTED after ingestion began, or first_seen_at is
               -- a backfill timestamp and says nothing about how fast the CNA filed
               and date_trunc('month', date_published at time zone 'UTC')::date
                   >= era.usable_from)
          select count(*), count(*) filter (where settle_days > %s), max(settle_days)
            from x""", (declared,))
        n, beyond, worst = cur.fetchone()

    if not n:
        return EvalResult("pressure_late_arrivals_settled", WARN, True,
                          "no month has yet been observed end to end, so the settling "
                          "time cannot be re-measured; maturity_days rests on the "
                          "migration's stated evidence alone",
                          {"declared_maturity_days": declared, "measurable_rows": 0})
    share = beyond / n
    ok = share <= 0.001
    return EvalResult("pressure_late_arrivals_settled", ERROR, ok,
                      f"records settle within the declared {declared}d: {beyond} of {n:,} "
                      f"({100 * share:.3f}%) arrived later, worst {worst}d"
                      if ok else
                      f"{beyond} of {n:,} ({100 * share:.2f}%) records arrived MORE than "
                      f"{declared}d after their month closed, worst {worst}d — "
                      f"maturity_days is too small and the published window is being "
                      f"cut before filing has finished",
                      {"declared_maturity_days": declared, "rows": n,
                       "arrived_late": beyond, "worst_settle_days": worst})


def run_db_evals(conn) -> list[EvalResult]:
    return [
        check_epss_persisted(conn),
        check_epss_single_model_version(conn),
        check_detail_populated(conn),
        check_detail_one_row_per_cve(conn),
        check_kev_membership_matches_source(conn),
        check_no_epoch_sentinels(conn),
        check_zero_day_consistent(conn),
        check_censoring_recorded(conn),
        check_zero_day_signal_agreement(conn),
        check_observation_window_fresh(conn),
        check_registry_orphans_kept(conn),
        check_patch_basis_declared(conn),
        check_technology_cohorts_populated(conn),
        check_cohort_window_rolls(conn),
        check_scan_age_window_rolls(conn),
        check_scan_pressure_window_rolls(conn),
        check_pressure_window_matured(conn),
        check_pressure_late_arrivals_settled(conn),
        check_partial_year_not_extended(conn),
        check_technology_single_assignment(conn),
        check_technology_coverage_published(conn),
        check_classification_evidence(conn),
        check_kev_classification_complete(conn),
        check_independence_counts_agree(conn),
        check_corpus_cohorts_populated(conn),
        check_cohort_boundaries_agree(conn),
        check_corpus_monotonic(conn),
        check_kev_bulk_loads_flagged(conn),
        check_patch_window_bands_sum(conn),
        check_patch_window_maturity_ordered(conn),
        check_kev_technology_consistent(conn),
        check_kev_technology_window_rolls(conn),
        check_severity_windows_nest(conn),
        check_severity_separation(conn),
        check_no_telemetry_in_kev(conn),
        # The Explorer's own chain: the projection, its completeness, the header counts, the
        # sparkline window, and the regression guard for the MSRC back-add bug.
        check_explorer_list_fresh(conn),
        check_explorer_list_complete(conn),
        check_explorer_strata_agree(conn),
        check_activity_window_fresh(conn),
        check_patch_dates_not_backdated(conn),
        check_method_versions_registered(conn),
        check_sensors_are_not_vendor_reports(conn),
        check_scan_state_consistent(conn),
        check_kev_sources_say_kev(conn),
        check_kev_consolidated_has_no_orphans(conn),
        check_schema_matches_migrations(conn),
        check_kev_lag_points_fresh(conn),
        check_views_expose_all_columns(conn),
        check_public_views_readonly(conn),
    ]
