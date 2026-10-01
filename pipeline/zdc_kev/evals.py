"""Evaluation suite — runs after ingestion, gates promotion to production.

These are not unit tests. Unit tests prove the code does what it says on fixtures;
these prove *this run's data* is fit to publish, against the live database. They exist
because v1's failure mode was not a crash — it was six months of successful-looking
runs producing quietly wrong numbers.

Severity contract:
  ERROR — do not promote. The run produced data that would mislead.
  WARN  — publish, but a human should look.
  INFO  — diagnostic measurement, no pass/fail.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

ERROR, WARN, INFO = "error", "warn", "info"


@dataclass
class EvalResult:
    name: str
    severity: str
    passed: bool
    summary: str
    detail: dict = field(default_factory=dict)

    @property
    def blocking(self) -> bool:
        return self.severity == ERROR and not self.passed


@dataclass
class EvalReport:
    results: list[EvalResult] = field(default_factory=list)

    def add(self, result: EvalResult) -> None:
        self.results.append(result)

    @property
    def ok(self) -> bool:
        return not any(r.blocking for r in self.results)

    def render(self) -> str:
        icon = {True: "PASS", False: "FAIL"}
        lines = []
        for r in self.results:
            mark = "INFO" if r.severity == INFO else icon[r.passed]
            lines.append(f"[{mark:4}] {r.severity:5} {r.name}: {r.summary}")
        lines.append("")
        lines.append("RESULT: " + ("OK — safe to promote" if self.ok else "BLOCKED — do not promote"))
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Pure checks — usable on in-memory observations, no database needed
# ---------------------------------------------------------------------------


def check_no_silent_empty(collect_results) -> EvalResult:
    """The v1 bug, made unrepeatable.

    A source that yields zero records while reporting no error is the exact shape of a
    WAF block recorded as success. Either there is data, or there is a stated reason.
    """
    offenders = [
        r.source_id
        for r in collect_results
        if not r.observations and r.error is None and not r.unchanged
    ]
    return EvalResult(
        name="no_silent_empty",
        severity=ERROR,
        passed=not offenders,
        summary=(
            "every source returned data, was unchanged, or reported a reason"
            if not offenders
            else f"sources returned nothing with no error recorded: {offenders}"
        ),
        detail={"offenders": offenders},
    )


def check_sources_reported(collect_results) -> EvalResult:
    """Any source that errored leaves the consolidated view stale, not wrong.

    WARN rather than ERROR on purpose: existing entries still stand (nothing is
    withdrawn on a failed fetch), so the data remains publishable — but a reader of
    the report must see which source is missing from this run.
    """
    failed = {r.source_id: r.error for r in collect_results if r.error}
    return EvalResult(
        name="sources_reported",
        severity=WARN,
        passed=not failed,
        summary=(
            "every source completed"
            if not failed
            else f"{len(failed)} source(s) failed; their data is stale: {sorted(failed)}"
        ),
        detail=failed,
    )


def check_cve_shape(observations) -> EvalResult:
    bad = sorted({o.cve_id for o in observations if o.cve_id and not CVE_RE.match(o.cve_id)})
    return EvalResult(
        name="cve_shape",
        severity=ERROR,
        passed=not bad,
        summary="all CVE ids well-formed" if not bad else f"{len(bad)} malformed CVE ids",
        detail={"examples": bad[:10]},
    )


def check_no_future_dates(observations, censored_at: date) -> EvalResult:
    future = [
        (o.source_id, o.vuln_id, o.date_added.isoformat())
        for o in observations
        if o.date_added and o.date_added > censored_at
    ]
    return EvalResult(
        name="no_future_dates",
        severity=WARN,
        passed=not future,
        summary=(
            f"no date_added after {censored_at}"
            if not future
            else f"{len(future)} entries dated after the censoring date"
        ),
        detail={"examples": future[:10]},
    )


def check_source_yield(collect_results, expected: dict[str, int | None]) -> EvalResult:
    """Freshness floor. A source that suddenly halves is a broken source, not news."""
    short = {}
    for r in collect_results:
        floor = expected.get(r.source_id)
        if floor and not r.unchanged and len(r.observations) < floor:
            short[r.source_id] = {"got": len(r.observations), "expected_min": floor}
    return EvalResult(
        name="source_yield",
        severity=ERROR,
        passed=not short,
        summary="all sources met their minimum" if not short else f"below floor: {sorted(short)}",
        detail=short,
    )


def check_signal_not_inflated(observations) -> EvalResult:
    """PoC availability must never be recorded as exploitation.

    v1 conflated exploit-code availability with in-the-wild exploitation. Nothing in
    these adapters should ever emit a signal from a proof-of-concept field; this
    asserts the invariant holds for the data actually produced.
    """
    poc_words = ("proof of concept", "proof-of-concept", "poc only", "no evidence of exploitation")
    suspects = [
        (o.source_id, o.vuln_id)
        for o in observations
        if o.signal in ("confirmed_compromise", "successful_exploitation")
        and o.short_description
        and any(w in o.short_description.lower() for w in poc_words)
    ]
    return EvalResult(
        name="signal_not_inflated",
        severity=WARN,
        passed=not suspects,
        summary=(
            "no exploitation claim backed only by PoC language"
            if not suspects
            else f"{len(suspects)} entries claim exploitation but read like PoC-only"
        ),
        detail={"examples": suspects[:10]},
    )


# ---------------------------------------------------------------------------
# Database checks
# ---------------------------------------------------------------------------


def check_persisted(conn, collect_results, persistence_errors: dict) -> EvalResult:
    """Prove the data actually reached the database.

    Added after a live run in which all four sources fetched cleanly, every other
    check passed, the consolidation produced zero rows — and the suite still reported
    "safe to promote". Fetching is not ingesting. A gate that only inspects what was
    downloaded reproduces the exact v1 failure it exists to prevent.
    """
    from . import db

    live = db.live_entry_counts(conn)
    missing = {}
    for result in collect_results:
        if result.unchanged or not result.observations:
            continue
        stored = live.get(result.source_id, 0)
        # Observations collapse on (source, upstream, entry_id), so stored can be
        # legitimately lower — but not by an order of magnitude.
        if stored < len(result.observations) * 0.5:
            missing[result.source_id] = {
                "collected": len(result.observations), "stored": stored
            }
    if persistence_errors:
        missing.update({k: {"error": v} for k, v in persistence_errors.items()})

    return EvalResult(
        name="persisted",
        severity=ERROR,
        passed=not missing,
        summary=(
            f"all collected observations reached the database ({sum(live.values())} live rows)"
            if not missing
            else f"collected data did not land: {sorted(missing)}"
        ),
        detail=missing,
    )


def check_consolidation_populated(conn) -> EvalResult:
    """A consolidated table with no rows is not a quiet day, it is a broken run."""
    with conn.cursor() as cur:
        cur.execute("select count(*) from derived.kev_consolidated")
        rows = cur.fetchone()[0]
        cur.execute("select count(*) from core.kev_entries where withdrawn_at is null")
        entries = cur.fetchone()[0]
    ok = rows > 0 or entries == 0
    return EvalResult(
        name="consolidation_populated",
        severity=ERROR,
        passed=ok,
        summary=(
            f"{rows} consolidated vulnerabilities from {entries} live entries"
            if ok
            else f"consolidation is empty despite {entries} live entries"
        ),
        detail={"consolidated_rows": rows, "live_entries": entries},
    )


def check_no_telemetry_in_kev(conn) -> EvalResult:
    """The KEV layer holds catalogue listings only. Sensor telemetry lives in obs_core.

    CIRCL's kev_entries dump passes Shadowserver honeypot data through in the same shape
    as a real catalogue entry, and it was ingested as one until 2026-09-01: 1,296 rows
    that set first_kev_date for 506 CVEs and counted as an independent observer for
    1,231. A honeypot hit is not a catalogue listing and Shadowserver publishes no KEV.
    The adapter now drops these at ingestion and a CHECK constraint blocks them at the
    table; this asserts both, and also flags evidence types nobody has reviewed, so a new
    sensor feed arriving through any aggregator fails the run instead of becoming an
    exploitation date.
    """
    with conn.cursor() as cur:
        cur.execute(
            """select coalesce(string_agg(distinct evidence_type, ', '), '')
                 from core.kev_entries where evidence_type in ('honeypot', 'sinkhole')"""
        )
        known = cur.fetchone()[0]
        cur.execute(
            """select coalesce(string_agg(distinct evidence_type, ', '), '')
                 from core.kev_entries
                where evidence_type is not null
                  and evidence_type not in ('public_report', 'vendor_report',
                                            'csirt_report', 'incident_response')"""
        )
        unknown = cur.fetchone()[0]
        cur.execute("select count(*) from pg_constraint where conname = 'kev_entries_no_telemetry'")
        guarded = cur.fetchone()[0] == 1
        cur.execute(
            "select canonical_source from core.upstream_canonical where upstream_source = 'shadowserver'"
        )
        row = cur.fetchone()
        sensor_mapped = (row is None) or (row[0] == 'sensor-not-a-catalogue')
    ok = not known and not unknown and guarded and sensor_mapped
    return EvalResult(
        name="no_telemetry_in_kev",
        severity=ERROR,
        passed=ok,
        summary=(
            "the KEV layer holds catalogue listings only; the constraint is in place "
            "and Shadowserver cannot count as an observer"
            if ok
            else f"telemetry present: [{known}]; unreviewed evidence types: [{unknown}]; "
                 f"constraint: {guarded}; sensor demapped: {sensor_mapped}"
        ),
        detail={
            "telemetry": known,
            "unreviewed_types": unknown,
            "constraint_present": guarded,
            "sensor_demapped": sensor_mapped,
        },
    )


def check_kev_consolidated_has_no_orphans(conn) -> EvalResult:
    """Every consolidated vulnerability must still have a live assertion beneath it.

    rebuild_kev_consolidated was upsert-only until migration 0025: it refreshed every
    vuln_id present in core.kev_entries but never removed one that had disappeared from
    it. Nothing had ever disappeared, so the gap stayed invisible until the telemetry
    purge — 60 sensor-only identifiers then sat in derived.kev_consolidated, and in the
    public view, citing evidence that no longer existed. A published row whose primary
    evidence cannot be re-fetched is what the provenance rule forbids, and an upstream
    withdrawal would have produced the same stale row.
    """
    with conn.cursor() as cur:
        cur.execute(
            """select count(*) from derived.kev_consolidated k
                where not exists (select 1 from core.kev_entries e where e.vuln_id = k.vuln_id)"""
        )
        orphans = cur.fetchone()[0]
        cur.execute(
            """select count(*) from derived.kev_consolidated
                where 'shadowserver' = any(upstream_sources)
                   or 'sensor-not-a-catalogue' = any(canonical_sources)"""
        )
        sensor_cited = cur.fetchone()[0]
        cur.execute(
            """select count(*) from pg_proc p join pg_namespace n on n.oid = p.pronamespace
                where n.nspname = 'derived' and p.proname = 'rebuild_kev_consolidated'
                  and pg_get_functiondef(p.oid) ilike '%delete from derived.kev_consolidated%'"""
        )
        prunes = cur.fetchone()[0] == 1
        cur.execute("select count(*) from derived.kev_consolidated")
        rows = cur.fetchone()[0]
    ok = orphans == 0 and sensor_cited == 0 and prunes
    return EvalResult(
        name="kev_consolidated_has_no_orphans",
        severity=ERROR,
        passed=ok,
        summary=(
            f"all {rows:,} consolidated vulnerabilities rest on a live assertion, none "
            "cites a sensor, and the rebuild prunes what disappears"
            if ok
            else f"{orphans} consolidated rows have no backing assertion; {sensor_cited} "
                 f"cite a sensor; rebuild prunes: {prunes}"
        ),
        detail={
            "orphans": orphans,
            "sensor_cited": sensor_cited,
            "rebuild_prunes": prunes,
            "rows": rows,
        },
    )


def check_observer_dependencies_applied(conn) -> EvalResult:
    """A measured dependency must actually be discounted, on every affected row.

    KEVIntel's date_added equals CISA's on 82.2% of the 1,684 vulnerabilities both list
    (median 0 days) against a 25.5% non-derived baseline, so it is not an independent
    observer of anything CISA already carries. core.observer_dependencies records that,
    and rebuild_kev_consolidated discounts the dependent wherever the dominant is also
    present.

    The dependency is PARTIAL and that is the point: on the 1,099 vulnerabilities CISA
    does not list, KEVIntel is retained, because it cannot be CISA-derived there and it
    is the only corroboration for 1,075 of them. So this asserts BOTH directions — the
    discount is applied where it should be, AND it is not over-applied where it should
    not be. An over-applied discount would understate corroboration just as badly as
    none at all.
    """
    with conn.cursor() as cur:
        cur.execute("select count(*) from core.observer_dependencies")
        declared = cur.fetchone()[0]
        # A row must never count a dependent as independent while its dominant is present.
        cur.execute("""
            select count(*) from derived.kev_consolidated k
             where exists (
                select 1 from core.observer_dependencies od
                 where od.dependent_observer = any(k.canonical_sources)
                   and od.dominant_observer  = any(k.canonical_sources)
                   and not (od.dependent_observer = any(k.discounted_sources)))""")
        missed = cur.fetchone()[0]
        # And must never discount one whose dominant is absent.
        cur.execute("""
            select count(*) from derived.kev_consolidated k
             where exists (
                select 1 from core.observer_dependencies od
                 where od.dependent_observer = any(k.discounted_sources)
                   and not (od.dominant_observer = any(k.canonical_sources)))""")
        over = cur.fetchone()[0]
        # The count must equal distinct canonical observers minus those discounted.
        cur.execute("""
            select count(*) from derived.kev_consolidated
             where independent_source_count <> (
                select count(*) from unnest(canonical_sources) cs
                 where not (cs = any(discounted_sources)))""")
        mismatch = cur.fetchone()[0]
        cur.execute("""select count(*) from derived.kev_consolidated
                        where discounted_sources <> '{}'""")
        applied = cur.fetchone()[0]
    ok = missed == 0 and over == 0 and mismatch == 0
    return EvalResult(
        name="observer_dependencies_applied",
        severity=ERROR,
        passed=ok,
        summary=(
            f"{declared} measured dependency/ies discounted on {applied:,} vulnerabilities; "
            "none missed, none over-applied, counts consistent"
            if ok else
            f"dependency not discounted on {missed} rows; over-discounted on {over}; "
            f"independent_source_count inconsistent on {mismatch}"
        ),
        detail={"declared": declared, "applied": applied, "missed": missed,
                "over_applied": over, "count_mismatch": mismatch},
    )


def check_public_views_readonly(conn) -> EvalResult:
    """Assert `anon` holds nothing but SELECT on the published views.

    This can only be checked against the live database. Supabase grants ALL on new
    `public` objects to anon by default, so a view created by a future migration is
    writeable from the internet the moment it exists — and the views are auto-updatable
    and definer-owned, so a write through one bypasses the RLS on the tables beneath.
    A local Postgres has no such default and CI therefore passes regardless.

    Measured on the first production deploy: anon held DELETE, INSERT, TRUNCATE and
    UPDATE on all six views.
    """
    with conn.cursor() as cur:
        cur.execute(
            """select table_name, grantee,
                      string_agg(privilege_type, ',' order by privilege_type)
               from information_schema.role_table_grants
               where table_schema = 'public'
                 and grantee in ('anon', 'authenticated')
                 and privilege_type <> 'SELECT'
               group by 1, 2 order by 1, 2"""
        )
        offenders = {f"{t}/{g}": p for t, g, p in cur.fetchall()}
    return EvalResult(
        name="public_views_readonly",
        severity=ERROR,
        passed=not offenders,
        summary=(
            "anon and authenticated hold SELECT only on the published views"
            if not offenders
            else f"{len(offenders)} view/role pair(s) grant write access to the public"
        ),
        detail=offenders,
    )


def check_unmapped_upstreams(conn) -> EvalResult:
    with conn.cursor() as cur:
        cur.execute(
            """select distinct e.upstream_source
               from core.kev_entries e
               left join core.upstream_canonical c on c.upstream_source = e.upstream_source
               where c.upstream_source is null"""
        )
        unmapped = sorted(r[0] for r in cur.fetchall())
    return EvalResult(
        name="unmapped_upstreams",
        severity=WARN,
        passed=not unmapped,
        summary=(
            "every upstream feed is mapped to a canonical observer"
            if not unmapped
            else f"unmapped feeds inflate independence counts: {unmapped}"
        ),
        detail={"unmapped": unmapped},
    )


def check_unmapped_origins(conn) -> EvalResult:
    """A GCVE origin we have never seen before is a new issuing authority.

    The adapter falls back to the evidence citation so no data is lost, but the
    resulting observer name is a guess. Left unreviewed it either invents an observer
    (inflating independence) or merges two (deflating it).
    """
    with conn.cursor() as cur:
        cur.execute(
            """select e.origin_uuid, count(*)
               from core.kev_entries e
               left join core.kev_origins o on o.origin_uuid = e.origin_uuid
               where e.origin_uuid is not null and o.origin_uuid is null
               group by 1 order by 2 desc"""
        )
        unknown = {row[0]: row[1] for row in cur.fetchall()}
    return EvalResult(
        name="unmapped_origins",
        severity=WARN,
        passed=not unknown,
        summary=(
            "every GCVE origin is a known issuing authority"
            if not unknown
            else f"{len(unknown)} unknown issuing origin(s) need review"
        ),
        detail=unknown,
    )


def measure_source_agreement(conn) -> EvalResult:
    """How much do the sources actually agree, given nothing is deduplicated?"""
    with conn.cursor() as cur:
        cur.execute(
            """select observer_a, observer_b, shared_count, only_a, only_b, jaccard,
                      date_comparable, same_day, within_7d, median_abs_date_diff
               from derived.kev_source_agreement
               where shared_count > 0 order by shared_count desc limit 12"""
        )
        rows = cur.fetchall()

    pairs = [
        {
            "pair": f"{a} x {b}", "shared": shared, "only_a": oa, "only_b": ob,
            "jaccard": float(j) if j is not None else None,
            "date_comparable": dc, "same_day": sd, "within_7d": w7,
            "median_abs_date_diff_days": float(md) if md is not None else None,
        }
        for a, b, shared, oa, ob, j, dc, sd, w7, md in rows
    ]
    if pairs:
        top = pairs[0]
        same_day_pct = (
            round(top["same_day"] * 100 / top["date_comparable"])
            if top["date_comparable"] else 0
        )
        summary = (
            f"largest overlap {top['pair']}: {top['shared']} shared, "
            f"Jaccard {top['jaccard']}, {same_day_pct}% agree on the exact date"
        )
    else:
        summary = "no observer pair shares a vulnerability"

    return EvalResult(
        name="source_agreement", severity=INFO, passed=True,
        summary=summary, detail={"pairs": pairs},
    )


def check_suspected_non_independence(conn, threshold: float = 0.95) -> EvalResult:
    """Flag observer pairs whose catalogues are near-identical.

    Two observers with a Jaccard above ~0.95 are almost certainly not making
    independent determinations — one is derived from the other, or both from a common
    upstream. That is invisible in the registry (nothing declares it) but fatal to
    capture-recapture, which assumes independent catch probabilities.

    Measured on the first full run: cisa x enisa scored 0.996 — 1,683 of CISA's 1,683
    entries also appear in EUVD's exploited slice, with only 6 unique to EUVD. They are
    registered as separate sources and counted as separate observers, and on this
    evidence they should not be.
    """
    with conn.cursor() as cur:
        cur.execute(
            """select observer_a, observer_b, jaccard, shared_count, only_a, only_b
               from derived.kev_source_agreement
               where jaccard >= %s order by jaccard desc""",
            (threshold,),
        )
        rows = cur.fetchall()

    suspects = {
        f"{a} x {b}": {
            "jaccard": float(j), "shared": shared, "only_a": oa, "only_b": ob,
        }
        for a, b, j, shared, oa, ob in rows
    }
    return EvalResult(
        name="suspected_non_independence",
        severity=WARN,
        passed=not suspects,
        summary=(
            "no observer pair is suspiciously identical"
            if not suspects
            else f"{len(suspects)} pair(s) look derived, not independent: {sorted(suspects)}"
        ),
        detail=suspects,
    )


def check_coverage_not_dropped(conn, tolerance: float = 0.20) -> EvalResult:
    """Has any source lost more than `tolerance` of its STORED assertions?

    BOTH SIDES MUST BE THE SAME QUANTITY. This originally compared the previous run's
    summed raw.source_fetches.record_count against the current count in core.kev_entries.
    Those are different things: record_count counts records RETURNED BY A FETCH, and the
    VulnCheck adapter fetches its paginated index AND its backup snapshot, so summing
    them double-counts one catalogue. Measured 2026-09-01: baseline 6,585 "records"
    against 5,201 stored rows = 79%, tripping a 20% collapse alarm on a source that had
    just GROWN from 5,185 to 5,201. It would have blocked the next scheduled run.

    The baseline is now the previous run's own stored counts, recorded in
    raw.pipeline_runs.notes->'source_counts'. Same quantity on both sides, and
    independent of whether a run was incremental or full — an incremental run fetches a
    delta but still stores the whole catalogue.
    """
    with conn.cursor() as cur:
        cur.execute(
            """select notes->'source_counts' from raw.pipeline_runs
                where ok and pipeline = 'kev' and notes ? 'source_counts'
                order by started_at desc limit 1"""
        )
        row = cur.fetchone()
        previous = {k: int(v) for k, v in (row[0] or {}).items()} if row else {}
        cur.execute(
            """select source_id, count(*) from core.kev_entries
               where withdrawn_at is null group by source_id"""
        )
        current = {r[0]: r[1] for r in cur.fetchall()}

    drops = {}
    for source_id, before in previous.items():
        after = current.get(source_id, 0)
        if before and after < before * (1 - tolerance):
            drops[source_id] = {"previous": before, "current": after}
    return EvalResult(
        name="coverage_not_dropped",
        severity=ERROR,
        passed=not drops,
        summary=(
            ("no source lost more than %d%% of its stored entries" % int(tolerance * 100))
            + ("" if previous else " (no prior run recorded counts — nothing to compare yet)")
            if not drops
            else f"coverage collapse in {sorted(drops)}"
        ),
        detail={"drops": drops, "baseline": previous, "current": current},
    )


def check_withdrawal_spike(conn, max_fraction: float = 0.05) -> EvalResult:
    with conn.cursor() as cur:
        cur.execute(
            """select source_id,
                      count(*) filter (where withdrawn_at is not null and
                                             withdrawn_at > now() - interval '1 hour') as fresh,
                      count(*) as total
               from core.kev_entries group by source_id"""
        )
        rows = cur.fetchall()
    spikes = {
        source: {"withdrawn": fresh, "total": total}
        for source, fresh, total in rows
        if total and fresh > total * max_fraction
    }
    return EvalResult(
        name="withdrawal_spike",
        severity=ERROR,
        passed=not spikes,
        summary=(
            "no unusual withdrawal volume"
            if not spikes
            else f"withdrawal spike suggests a truncated snapshot: {sorted(spikes)}"
        ),
        detail=spikes,
    )


def measure_source_overlap(conn) -> EvalResult:
    """Capture-recapture groundwork — reported as a diagnostic, never as a headline.

    A two-source Chapman estimate of the unobserved population is computed for the two
    largest *canonical* observers. Its assumptions (independence, homogeneous catch
    probability) are known to be violated here, so it is INFO: it bounds the scale of
    the coverage problem, it does not solve it. Solving it needs three or more
    genuinely independent observers — see CLAUDE.md, "Source coverage".
    """
    with conn.cursor() as cur:
        cur.execute(
            """select coalesce(c.canonical_source, e.upstream_source) as observer,
                      count(distinct e.cve_id) as cves
               from core.kev_entries e
               left join core.upstream_canonical c on c.upstream_source = e.upstream_source
               where e.cve_id is not null and e.withdrawn_at is null
               group by 1 order by cves desc"""
        )
        observers = cur.fetchall()

        detail: dict = {"observers": {name: count for name, count in observers}}
        if len(observers) >= 2:
            (a, n1), (b, n2) = observers[0], observers[1]
            cur.execute(
                """with obs as (
                       select e.cve_id, coalesce(c.canonical_source, e.upstream_source) as observer
                       from core.kev_entries e
                       left join core.upstream_canonical c on c.upstream_source = e.upstream_source
                       where e.cve_id is not null and e.withdrawn_at is null)
                   select count(*) from (
                       select cve_id from obs where observer = %s
                       intersect
                       select cve_id from obs where observer = %s) x""",
                (a, b),
            )
            overlap = cur.fetchone()[0]
            chapman = ((n1 + 1) * (n2 + 1) / (overlap + 1)) - 1
            union_size = n1 + n2 - overlap
            detail.update(
                {
                    "pair": [a, b],
                    "n1": n1, "n2": n2, "overlap": overlap,
                    "observed_union": union_size,
                    "chapman_estimate": round(chapman, 1),
                    "implied_unobserved": round(max(chapman - union_size, 0), 1),
                    "caveat": (
                        "Chapman assumes independent observers with homogeneous catch "
                        "probability. Neither holds here. Diagnostic only."
                    ),
                }
            )
            summary = (
                f"{a} x {b}: {overlap} shared of {union_size} observed; "
                f"Chapman suggests ~{int(max(chapman - union_size, 0))} unobserved"
            )
        else:
            summary = "fewer than two observers; overlap not computable"

    return EvalResult(
        name="source_overlap", severity=INFO, passed=True, summary=summary, detail=detail
    )


def measure_multi_source_agreement(conn) -> EvalResult:
    with conn.cursor() as cur:
        cur.execute(
            """select independent_source_count, count(*)
               from derived.kev_consolidated
               where cve_id is not null
               group by 1 order by 1"""
        )
        histogram = {int(k): int(v) for k, v in cur.fetchall()}
    total = sum(histogram.values()) or 1
    singletons = histogram.get(1, 0)
    return EvalResult(
        name="multi_source_agreement",
        severity=INFO,
        passed=True,
        summary=(
            f"{singletons}/{total} ({singletons * 100 // total}%) of CVEs are asserted "
            "by exactly one independent observer"
        ),
        detail={"histogram": histogram},
    )


def run_db_evals(conn, collect_results=(), persistence_errors=None) -> list[EvalResult]:
    return [
        check_persisted(conn, collect_results, persistence_errors or {}),
        check_consolidation_populated(conn),
        check_no_telemetry_in_kev(conn),
        check_kev_consolidated_has_no_orphans(conn),
        check_observer_dependencies_applied(conn),
        check_public_views_readonly(conn),
        check_unmapped_upstreams(conn),
        check_unmapped_origins(conn),
        measure_source_agreement(conn),
        check_suspected_non_independence(conn),
        check_coverage_not_dropped(conn),
        check_withdrawal_spike(conn),
        measure_source_overlap(conn),
        measure_multi_source_agreement(conn),
    ]
