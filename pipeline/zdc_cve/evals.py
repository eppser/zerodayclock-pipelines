"""Eval gate for the CVE registry.

This table is the denominator of every rate the scoreboard publishes, so the failure
that matters most is a *quietly short corpus*: a truncated sweep looks exactly like a
world with fewer vulnerabilities in it.
"""

from __future__ import annotations

from zdc_kev.evals import ERROR, INFO, WARN, EvalReport, EvalResult  # noqa: F401


def check_no_silent_empty(results) -> EvalResult:
    offenders = [r.source_id for r in results
                 if not r.records and r.error is None and not r.unchanged]
    return EvalResult("no_silent_empty", ERROR, not offenders,
                      "every source returned data, was unchanged, or gave a reason"
                      if not offenders else f"empty with no reason: {offenders}",
                      {"offenders": offenders})


def check_sources_reported(results) -> EvalResult:
    failed = {r.source_id: r.error for r in results if r.error}
    return EvalResult("sources_reported", WARN, not failed,
                      "every source completed" if not failed
                      else f"{len(failed)} source(s) failed: {sorted(failed)}", failed)


def check_cve_ids_wellformed(records) -> EvalResult:
    import re
    pat = re.compile(r"^CVE-\d{4}-\d{4,}$")
    bad = sorted({r.cve_id for r in records if not pat.match(r.cve_id)})
    return EvalResult("cve_ids_wellformed", ERROR, not bad,
                      "all CVE ids well-formed" if not bad else f"{len(bad)} malformed",
                      {"examples": bad[:10]})


def check_year_from_identifier(records) -> EvalResult:
    """cve_year must come from the ID, never from a publication timestamp.

    v1 cohorted on NVD publication year, so a CVE-2019-* published by NVD in 2023
    landed in the 2023 cohort. Every cross-year comparison built on that was wrong.
    """
    mismatched = [
        (r.cve_id, r.year, r.nvd_published.year)
        for r in records
        if r.nvd_published and r.year != r.nvd_published.year
    ]
    return EvalResult(
        "year_from_identifier", INFO, True,
        f"{len(mismatched)} records whose NVD publication year differs from their ID year"
        " — cohorting uses the ID, which is why this is INFO and not a failure",
        {"examples": mismatched[:5], "count": len(mismatched)})


def check_corpus_not_shrunk(conn, tolerance: float = 0.02) -> EvalResult:
    """A truncated sweep is indistinguishable from a smaller world. Catch it."""
    with conn.cursor() as cur:
        cur.execute("select count(*) from core.cves")
        current = cur.fetchone()[0]
        cur.execute("""select (notes->>'corpus_total')::bigint from raw.pipeline_runs
                       where ok and pipeline='cve' and notes ? 'corpus_total'
                       order by started_at desc limit 1 offset 0""")
        row = cur.fetchone()
    previous = row[0] if row and row[0] else None
    shrunk = previous is not None and current < previous * (1 - tolerance)
    return EvalResult(
        "corpus_not_shrunk", ERROR, not shrunk,
        f"corpus holds {current:,} CVEs"
        + (f" (previous run: {previous:,})" if previous else " (no prior run to compare)")
        if not shrunk else f"corpus shrank {previous:,} -> {current:,}",
        {"current": current, "previous": previous})


def check_every_owned_source_has_an_adapter(conn) -> EvalResult:
    """Every source this pipeline claims must have code that can actually fetch it.

    core.cve_sources is the manifest for the whole CVE layer; this runner's work list is
    the subset with collected_by = 'zdc_cve' (migration 0026). Before that split, EPSS —
    collected by zdc_enrich — sat in the work list, and every cve-pipeline run did its
    real work, passed every eval, printed "safe to promote", and exited 1 on
    "no adapter for 'epss'".

    The split fixes that, but it opens the opposite hole: a source could now claim this
    pipeline and have no adapter, and simply never be fetched. So assert the two sets
    match exactly, in both directions — an unfetched source is a silent collection gap,
    which is the failure this project exists to not repeat.
    """
    from .sources import registered_ids
    have = set(registered_ids())
    with conn.cursor() as cur:
        cur.execute("""select source_id from core.cve_sources
                        where enabled and collected_by = 'zdc_cve'""")
        claimed = {r[0] for r in cur.fetchall()}
        cur.execute("""select source_id, collected_by from core.cve_sources
                        where enabled and collected_by <> 'zdc_cve'""")
        elsewhere = {r[0]: r[1] for r in cur.fetchall()}
    no_adapter = sorted(claimed - have)
    no_registration = sorted(have - claimed)
    ok = not no_adapter and not no_registration
    other = (" · collected elsewhere: "
             + ", ".join(f"{k}->{v}" for k, v in sorted(elsewhere.items()))) if elsewhere else ""
    return EvalResult(
        "every_owned_source_has_an_adapter", ERROR, ok,
        f"{len(claimed)} enabled sources claimed by zdc_cve, all with adapters{other}"
        if ok else
        f"registered with no adapter: {no_adapter}; adapter with no enabled "
        f"registration: {no_registration}",
        {"claimed": sorted(claimed), "adapters": sorted(have),
         "no_adapter": no_adapter, "no_registration": no_registration,
         "collected_elsewhere": elsewhere})


def check_public_views_readonly(conn) -> EvalResult:
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


def measure_source_coverage(conn) -> EvalResult:
    with conn.cursor() as cur:
        cur.execute("""select count(*), count(*) filter (where in_cve_project),
                              count(*) filter (where in_nvd),
                              count(*) filter (where in_cve_project and in_nvd),
                              count(*) filter (where in_cve_project and not in_nvd),
                              count(*) filter (where in_nvd and not in_cve_project)
                       from core.cves""")
        t, c, n, both, only_c, only_n = cur.fetchone()
    return EvalResult(
        "source_coverage", INFO, True,
        f"{t:,} CVEs — {both:,} in both, {only_c:,} CVE-Project only, {only_n:,} NVD only",
        {"total": t, "cve_project": c, "nvd": n, "both": both,
         "cve_project_only": only_c, "nvd_only": only_n})


def measure_publication_lag(conn) -> EvalResult:
    """Reservation -> publication, and CNA publication -> NVD publication.

    Exactly the quantity the CVE/NVD timing disclaimer says nobody should assume. It is
    reported as a diagnostic, not as a headline.
    """
    with conn.cursor() as cur:
        cur.execute("""
          select percentile_cont(0.5) within group (
                     order by extract(epoch from (date_published - date_reserved))/86400)
                 filter (where date_published is not null and date_reserved is not null),
                 percentile_cont(0.5) within group (
                     order by extract(epoch from (nvd_published - date_published))/86400)
                 filter (where nvd_published is not null and date_published is not null),
                 count(*) filter (where date_published is not null and date_reserved is not null)
          from core.cves""")
        res_to_pub, pub_to_nvd, n = cur.fetchone()
    # Each median can be absent independently: before NVD has loaded, every
    # nvd_published is NULL and only the reservation lag is computable.
    parts = []
    if res_to_pub is not None:
        parts.append(f"median reservation->publication {res_to_pub:.0f}d (n={n:,})")
    if pub_to_nvd is not None:
        parts.append(f"CNA publication->NVD {pub_to_nvd:.1f}d")
    return EvalResult(
        "publication_lag", INFO, True,
        "; ".join(parts) or "not enough dated records yet",
        {"median_reservation_to_publication_days": float(res_to_pub) if res_to_pub else None,
         "median_cna_to_nvd_days": float(pub_to_nvd) if pub_to_nvd else None, "n": n})


def measure_cvss_disagreement(conn) -> EvalResult:
    """Where both sources scored a CVE, how often do they differ?"""
    with conn.cursor() as cur:
        cur.execute("""select count(*) filter (where cna_cvss_score is not null
                                                 and nvd_cvss_score is not null),
                              count(*) filter (where cna_cvss_score is distinct from nvd_cvss_score
                                                 and cna_cvss_score is not null
                                                 and nvd_cvss_score is not null),
                              percentile_cont(0.5) within group (
                                  order by abs(cna_cvss_score - nvd_cvss_score))
                              filter (where cna_cvss_score is not null and nvd_cvss_score is not null)
                       from core.cves""")
        both, differ, median = cur.fetchone()
    pct = (differ * 100 // both) if both else 0
    return EvalResult(
        "cvss_disagreement", INFO, True,
        f"{both:,} CVEs scored by both; {differ:,} ({pct}%) differ, median gap {median or 0:.1f}"
        if both else "no CVE scored by both sources yet",
        {"scored_by_both": both, "differ": differ,
         "median_abs_gap": float(median) if median is not None else None})


def run_db_evals(conn) -> list[EvalResult]:
    return [check_corpus_not_shrunk(conn),
            check_every_owned_source_has_an_adapter(conn),
            check_public_views_readonly(conn),
            measure_source_coverage(conn), measure_publication_lag(conn),
            measure_cvss_disagreement(conn)]
