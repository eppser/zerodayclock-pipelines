"""Eval gate for the observation pipeline.

Reuses the KEV suite's severity contract and report type. The checks differ because
the failure modes differ: the danger here is not a stale catalogue, it is quietly
promoting a *prediction* or an *attempt* into evidence of exploitation.
"""

from __future__ import annotations

from datetime import date

from zdc_kev.evals import ERROR, INFO, WARN, EvalReport, EvalResult  # noqa: F401
# Same contract as the KEV pipeline: a malformed record costs one record, visibly.
from zdc_kev.evals import check_skipped_records  # noqa: F401


def check_no_silent_empty(results) -> EvalResult:
    offenders = [r.source_id for r in results
                 if not r.observations and r.error is None and not r.unchanged]
    return EvalResult("no_silent_empty", ERROR, not offenders,
                      "every source returned data, was unchanged, or gave a reason"
                      if not offenders else f"empty with no reason: {offenders}",
                      {"offenders": offenders})


def check_sources_reported(results) -> EvalResult:
    failed = {r.source_id: r.error for r in results if r.error}
    return EvalResult("sources_reported", WARN, not failed,
                      "every source completed" if not failed
                      else f"{len(failed)} source(s) failed: {sorted(failed)}", failed)


def check_collectors_have_adapters(conn) -> EvalResult:
    """Every enabled source is collected by somebody, and ours all have an adapter.

    The filter in db.enabled_sources() stops zdc_obs trying to collect shadowserver_api,
    which zdc_honeypot owns (migration 0062). That filter is also the thing that could
    hide a real problem: a source whose adapter is deleted, or whose collector is set to
    a pipeline that does not fetch it, would simply stop being collected and nothing
    would say so — silent collector death, arriving through the fix for a loud one.

    So assert both directions. Every source WE collect must have a registered adapter,
    and every adapter we have registered must correspond to an enabled source we are
    told to collect. An unknown collector value cannot occur — the CHECK constraint in
    0062 blocks it at write time — so it is not re-tested here.
    """
    from .db import COLLECTOR, sources_by_collector
    from .sources import registered_ids

    by_collector = sources_by_collector(conn)
    ours = {sid for sid, c in by_collector.items() if c == COLLECTOR}
    adapters = set(registered_ids())

    missing_adapter = sorted(ours - adapters)      # we are told to collect it, we cannot
    idle_adapter = sorted(adapters - ours)         # we can collect it, nobody asked
    ok = not missing_adapter and not idle_adapter
    summary = (f"{len(ours)} source(s) assigned to {COLLECTOR}, all with adapters" if ok
               else "; ".join(filter(None, [
                   f"no adapter for {missing_adapter}" if missing_adapter else "",
                   f"adapter registered but source not enabled for us: {idle_adapter}"
                   if idle_adapter else ""])))
    return EvalResult("collectors_have_adapters", ERROR, ok, summary,
                      {"ours": sorted(ours), "adapters": sorted(adapters),
                       "missing_adapter": missing_adapter, "idle_adapter": idle_adapter,
                       "by_collector": by_collector})


def check_source_freshness(conn, censored_at: date) -> EvalResult:
    """Every source we collect is still producing, and still reachable.

    v1 published "current" figures for six months after its collector died on
    2026-02-28. The obs suite could not have caught that: check_no_silent_empty only
    sees a source returning nothing DURING a run, and a source that returns the same
    stale rows forever returns plenty.

    Thresholds are read per source from obs_core.observation_sources (0063), not fixed
    here, because the sources differ by more than an order of magnitude: shadowserver's
    largest gap in 180 days is 1 day, vulncheck_canary's is 13. One constant would
    either page every week on the canary or never fire on Shadowserver.

    Two quantities, because they fail independently:
      * SILENCE  — no observation dated more recently than max_silence_days ago.
                   Skipped where the threshold is NULL, meaning the source carries no
                   dates at all (msrc has 195 rows and zero observed_at).
      * RE-READ  — we have not successfully re-read the source in max_reread_days.
                   Applies to every source: reaching a source with no news is healthy,
                   failing to reach it is not.

    A source with NEITHER threshold set FAILS. That is the point — it makes the eval
    self-defending, so a source cannot be registered and then sit unmonitored, which is
    the shape of every silent-collector bug this project has had.
    """
    from .db import COLLECTOR

    with conn.cursor() as cur:
        cur.execute("""select s.source_id, s.max_silence_days, s.max_reread_days,
                              max(o.observed_at)::date, max(o.last_seen_at)::date
                         from obs_core.observation_sources s
                         left join obs_core.exploitation_observations o
                                on o.source_id = s.source_id and o.withdrawn_at is null
                        where s.enabled and s.collector = %s
                        group by 1, 2, 3
                        order by 1""", (COLLECTOR,))
        rows = cur.fetchall()

    problems, detail = [], {}
    for sid, max_silence, max_reread, last_obs, last_seen in rows:
        d = {"max_silence_days": max_silence, "max_reread_days": max_reread,
             "last_observed": str(last_obs) if last_obs else None,
             "last_seen": str(last_seen) if last_seen else None}
        if max_silence is None and max_reread is None:
            problems.append(f"{sid}: no freshness expectation declared")
        if last_seen is None:
            problems.append(f"{sid}: no rows stored at all")
        else:
            if max_reread is not None:
                lag = (censored_at - last_seen).days
                d["reread_lag_days"] = lag
                if lag > max_reread:
                    problems.append(f"{sid}: not re-read for {lag}d (max {max_reread})")
            if max_silence is not None:
                if last_obs is None:
                    problems.append(f"{sid}: silence threshold set but no dated observations")
                else:
                    lag = (censored_at - last_obs).days
                    d["silence_lag_days"] = lag
                    if lag > max_silence:
                        problems.append(
                            f"{sid}: newest observation {lag}d old (max {max_silence})")
        detail[sid] = d

    if not rows:
        return EvalResult("source_freshness", ERROR, False,
                          f"no enabled sources assigned to {COLLECTOR}", {})
    return EvalResult(
        "source_freshness", ERROR, not problems,
        f"{len(rows)} source(s) within their declared freshness window" if not problems
        else "; ".join(problems), detail)


def check_observation_types(observations) -> EvalResult:
    """Every observation must carry a valid, closed-vocabulary type."""
    bad = sorted({o.observation_type for o in observations
                  if o.observation_type not in
                  ("attempt_observed", "vendor_reports_exploitation")})
    return EvalResult("observation_types", ERROR, not bad,
                      "all observation types valid" if not bad else f"invalid types: {bad}",
                      {"invalid": bad})


def check_forecast_not_used_as_evidence(observations) -> EvalResult:
    """Every vendor observation must rest on an explicit exploitation flag.

    The invariant that matters is *why* a row exists: it must come from
    ``Exploited:Yes``, never from a forecast. An earlier version of this check
    asserted that ``Exploited:Yes`` implies a "Exploitation Detected" forecast — which
    the data disproves. Microsoft rates exploitability **per software release**:

        Exploited:Yes; Latest Software Release:Exploitation More Likely;
                       Older Software Release:Exploitation Detected

    i.e. exploitation was detected against older builds while the current build is only
    rated more-likely. Measured over the 2016+ backfill: of 195 vendor observations,
    155 carry "Exploitation Detected" on the latest release, 21 "More Likely", 4 "Less
    Likely", 1 "Unlikely", 4 "N/A" and 10 none at all. All 195 are legitimately
    exploited; the forecast simply describes a different thing.

    So the check verifies provenance instead: the source record must actually say
    Exploited:Yes.
    """
    unbacked = []
    for o in observations:
        if o.observation_type != "vendor_reports_exploitation":
            continue
        statuses = (o.raw or {}).get("statuses") or []
        if not any(str(s.get("Exploited", "")).lower() == "yes"
                   for s in statuses if isinstance(s, dict)):
            unbacked.append((o.source_id, o.vuln_id, o.vendor_forecast))
    return EvalResult(
        "forecast_not_evidence", ERROR, not unbacked,
        "every vendor observation is backed by an explicit Exploited:Yes flag"
        if not unbacked
        else f"{len(unbacked)} vendor observations lack an Exploited:Yes flag",
        {"examples": unbacked[:10]},
    )


def check_dates_present(observations, censored_at: date) -> EvalResult:
    undated = [(o.source_id, o.vuln_id) for o in observations if o.effective_date is None]
    future = [(o.source_id, o.vuln_id, o.effective_date.isoformat())
              for o in observations
              if o.effective_date and o.effective_date > censored_at]
    bad = bool(undated) or bool(future)
    return EvalResult("dates_sane", WARN, not bad,
                      f"all observations dated on or before {censored_at}" if not bad
                      else f"{len(undated)} undated, {len(future)} after the censoring date",
                      {"undated": undated[:5], "future": future[:5]})


def check_persisted(conn, results, persistence_errors: dict) -> EvalResult:
    from . import db
    live = db.live_counts(conn)
    missing = {}
    for r in results:
        if r.unchanged or not r.observations:
            continue
        stored = live.get(r.source_id, 0)
        if stored < len(r.observations) * 0.5:
            missing[r.source_id] = {"collected": len(r.observations), "stored": stored}
    missing.update({k: {"error": v} for k, v in persistence_errors.items()})
    return EvalResult("persisted", ERROR, not missing,
                      f"all observations reached the database ({sum(live.values())} live rows)"
                      if not missing else f"did not land: {sorted(missing)}", missing)


def check_public_views_readonly(conn) -> EvalResult:
    """Supabase grants ALL on new public views to anon by default; see migration 0006."""
    with conn.cursor() as cur:
        cur.execute("""select table_name, grantee,
                              string_agg(privilege_type, ',' order by privilege_type)
                       from information_schema.role_table_grants
                       where table_schema='public' and grantee in ('anon','authenticated')
                         and privilege_type <> 'SELECT' group by 1,2""")
        offenders = {f"{t}/{g}": p for t, g, p in cur.fetchall()}
    return EvalResult("public_views_readonly", ERROR, not offenders,
                      "anon holds SELECT only on published views" if not offenders
                      else f"{len(offenders)} view/role pair(s) allow public writes", offenders)


def measure_type_split(conn) -> EvalResult:
    with conn.cursor() as cur:
        cur.execute("""select observation_type, count(*), count(distinct cve_id)
                       from obs_core.exploitation_observations
                       where withdrawn_at is null group by 1 order by 2 desc""")
        rows = cur.fetchall()
    detail = {t: {"observations": n, "vulnerabilities": v} for t, n, v in rows}
    return EvalResult("type_split", INFO, True,
                      "; ".join(f"{t}: {n} obs / {v} vulns" for t, n, v in rows) or "no observations",
                      detail)


def measure_overlap_with_kev(conn) -> EvalResult:
    """How much do observations and KEV catalogues actually agree?

    This is the reason the two layers are stored separately rather than merged: an
    observation that predates every catalogue listing is the interesting case, and
    merging would have hidden it.
    """
    with conn.cursor() as cur:
        cur.execute("""
            select count(*) filter (where k.cve_id is not null)                      as in_both,
                   count(*) filter (where k.cve_id is null)                          as obs_only,
                   count(*) filter (where k.cve_id is not null
                                      and r.first_observation < k.first_kev_date)     as obs_earlier,
                   percentile_cont(0.5) within group (
                       order by (k.first_kev_date - r.first_observation))            as median_lead_days
            from obs_derived.observation_rollup r
            left join derived.kev_consolidated k on k.cve_id = r.cve_id
            where r.cve_id is not null""")
        both, obs_only, earlier, median = cur.fetchone()

        # Observations with no CVE at all are excluded from the join above, which
        # hides the most interesting rows: a KEV catalogue can never list them,
        # because KEV is keyed on CVE ids (Iron Rule 8). Count them explicitly.
        cur.execute("""select count(distinct vuln_id), coalesce(sum(observation_count), 0)
                       from obs_core.exploitation_observations
                       where cve_id is null and withdrawn_at is null""")
        non_cve, non_cve_volume = cur.fetchone()

    return EvalResult(
        "overlap_with_kev", INFO, True,
        f"{both} observed vulns also in a KEV catalogue, {obs_only} seen only as observations; "
        f"{earlier} observed before any catalogue listed them"
        + (f" (median lead {median:.0f}d)" if median is not None else "")
        + f"; {non_cve} non-CVE identifiers structurally uncatalogueable "
          f"({int(non_cve_volume):,} attempts)",
        {"in_both": both, "observation_only": obs_only, "observed_first": earlier,
         "median_lead_days": float(median) if median is not None else None,
         "non_cve_vulnerabilities": non_cve, "non_cve_attempts": int(non_cve_volume)},
    )


def run_db_evals(conn, results=(), persistence_errors=None) -> list[EvalResult]:
    return [
        check_persisted(conn, results, persistence_errors or {}),
        check_public_views_readonly(conn),
        measure_type_split(conn),
        measure_overlap_with_kev(conn),
    ]
