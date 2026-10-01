"""Persistence for the enrichment pipeline."""

from __future__ import annotations

import gzip
import logging
import time
import os
from datetime import date, datetime, timezone
from typing import Sequence

import psycopg
from psycopg.types.json import Jsonb

from zdc_kev.models import FetchRecord

from .models import EpssRecord

log = logging.getLogger(__name__)

MAX_STORED_PAYLOAD_BYTES = int(os.environ.get("ZDC_MAX_PAYLOAD_BYTES", 32 * 1024 * 1024))

# Supabase gives this role a two minute statement_timeout, and the enrichment rebuilds
# are the only thing on this site that comes near it: derived.rebuild_technology is
# measured at 90 to 102 seconds against six years of data, and it grows with the corpus.
# Ninety seconds against a hundred and twenty is not headroom, it is a scheduled failure
# waiting for a slow week, and the failure mode is a whole run lost rather than one
# metric degraded.
#
# The timeout is raised for THIS SESSION only. It is not a fix for a slow query and it is
# not a licence to stop watching: check_rebuild_duration reports how long the longest
# rebuild took on every run, so the number stays visible instead of being discovered by
# a red pipeline one morning.
STATEMENT_TIMEOUT = os.environ.get("ZDC_STATEMENT_TIMEOUT", "10min")


def connect(dsn: str | None = None) -> psycopg.Connection:
    dsn = dsn or os.environ.get("DATABASE_URL")
    if not dsn:
        raise RuntimeError("DATABASE_URL is not set")
    conn = psycopg.connect(dsn, autocommit=False)
    with conn.cursor() as cur:
        # set_config, not SET: SET takes a literal and will not bind a parameter, so
        # the obvious spelling raises "syntax error at or near $1" and the value would
        # otherwise have to be interpolated into SQL by hand.
        cur.execute("select set_config('statement_timeout', %s, false)", (STATEMENT_TIMEOUT,))
    conn.commit()
    return conn


def start_run(conn, pipeline: str, mode: str, trigger: str, git_sha: str | None) -> str:
    with conn.cursor() as cur:
        cur.execute("""insert into raw.pipeline_runs (pipeline, mode, trigger, git_sha)
                       values (%s,%s,%s,%s) returning run_id""",
                    (pipeline, mode, trigger, git_sha))
        return cur.fetchone()[0]


def finish_run(conn, run_id: str, *, ok: bool, error: str | None = None, **c) -> None:
    with conn.cursor() as cur:
        cur.execute("""update raw.pipeline_runs set finished_at=now(), ok=%s, error=%s,
                          sources_attempted=%s, sources_ok=%s, entries_seen=%s,
                          entries_inserted=%s, entries_updated=%s, notes=%s
                       where run_id=%s""",
                    (ok, error, c.get("sources_attempted", 0), c.get("sources_ok", 0),
                     c.get("entries_seen", 0), c.get("entries_inserted", 0),
                     c.get("entries_updated", 0), Jsonb(c.get("notes", {})), run_id))


def record_fetch(conn, run_id: str, fetch: FetchRecord) -> str:
    """Store the fetch and its body. Recorded whether or not it succeeded."""
    stored_hash = None
    if fetch.body and fetch.content_hash:
        if len(fetch.body) <= MAX_STORED_PAYLOAD_BYTES:
            with conn.cursor() as cur:
                cur.execute("""insert into raw.payloads (content_hash, media_type, byte_size, body_gzip)
                               values (%s,%s,%s,%s) on conflict (content_hash) do nothing""",
                            (fetch.content_hash, fetch.media_type, len(fetch.body),
                             gzip.compress(fetch.body)))
            stored_hash = fetch.content_hash
        else:
            log.info("payload for %s is %.0f MB (> cap); hash recorded, body not stored",
                     fetch.url, len(fetch.body) / 1e6)

    with conn.cursor() as cur:
        cur.execute("""insert into raw.source_fetches (
                           run_id, source_id, url, request_mode, window_start, window_end,
                           http_status, ok, not_modified, etag, last_modified, content_hash,
                           record_count, bytes_downloaded, started_at, finished_at,
                           duration_ms, error, attempt)
                       values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                       returning fetch_id""",
                    (run_id, fetch.source_id, fetch.url, fetch.request_mode,
                     fetch.window_start, fetch.window_end, fetch.http_status, fetch.ok,
                     fetch.not_modified, fetch.etag, fetch.last_modified, stored_hash,
                     fetch.record_count, fetch.bytes_downloaded, fetch.started_at,
                     fetch.finished_at or datetime.now(timezone.utc), fetch.duration_ms,
                     fetch.error, fetch.attempt))
        return cur.fetchone()[0]


def last_epss_fetch_date(conn) -> date | None:
    """Date of the last successful EPSS fetch that actually returned rows.

    Gates the once-a-day self-limit. A fetch that failed or returned nothing must not
    suppress the next attempt.
    """
    with conn.cursor() as cur:
        cur.execute("""select max(started_at)::date from raw.source_fetches
                       where source_id='epss' and ok and coalesce(record_count,0) > 0""")
        return cur.fetchone()[0]


def upsert_epss(conn, records: Sequence[EpssRecord], fetch_id: str) -> tuple[int, int]:
    """Replace the current EPSS scores.

    Staged through a TEMP table so the whole day lands in one statement rather than
    366k round trips. ``last_changed_at`` only moves when a value actually changed,
    which is what makes "EPSS has been static for a week" detectable.
    """
    if not records:
        return (0, 0)

    with conn.cursor() as cur:
        cur.execute("""create temp table _epss_stage (
                           cve_id text, epss_score numeric, epss_percentile numeric,
                           model_version text, score_date date
                       ) on commit drop""")
        with cur.copy("copy _epss_stage (cve_id, epss_score, epss_percentile, "
                      "model_version, score_date) from stdin") as copy:
            for r in records:
                copy.write_row((r.cve_id, r.epss_score, r.epss_percentile,
                                r.model_version, r.score_date))

        cur.execute("select count(*) from core.cve_epss")
        before = cur.fetchone()[0]

        cur.execute("""
            insert into core.cve_epss (cve_id, epss_score, epss_percentile,
                                       model_version, score_date, last_fetch_id)
            select cve_id, epss_score, epss_percentile, model_version, score_date, %s
              from _epss_stage
            on conflict (cve_id) do update set
                epss_score      = excluded.epss_score,
                epss_percentile = excluded.epss_percentile,
                model_version   = excluded.model_version,
                score_date      = excluded.score_date,
                last_fetch_id   = excluded.last_fetch_id,
                last_seen_at    = now(),
                last_changed_at = case
                    when core.cve_epss.epss_score      is distinct from excluded.epss_score
                      or core.cve_epss.epss_percentile is distinct from excluded.epss_percentile
                    then now() else core.cve_epss.last_changed_at end
        """, (fetch_id,))
        touched = cur.rowcount

        cur.execute("select count(*) from core.cve_epss")
        after = cur.fetchone()[0]

    inserted = after - before
    return (inserted, max(0, touched - inserted))


def rebuild_cve_detail(conn, *, method_version: str, censored_at: date,
                       run_id: str | None = None) -> int:
    """Run the SQL transform. The censoring date is a parameter, never now()."""
    with conn.cursor() as cur:
        cur.execute("select derived.rebuild_cve_detail(%s, %s, %s)",
                    (method_version, censored_at, run_id))
        return cur.fetchone()[0]


def rebuild_technology(conn, *, method_version: str, censored_at: date,
                       run_id: str | None = None) -> int:
    """Rebuild the technology cohort series.

    Runs in the SAME transaction context and with the SAME censoring date as the
    detail rebuild, deliberately. Computing it on its own weekly schedule would let
    the two tables drift apart, and the site would show a chart censored on one date
    beside a figure censored on another — the sort of inconsistency a reader is right
    to treat as carelessness. It costs about 8 seconds, so there is no reason to
    decouple it.
    """
    with conn.cursor() as cur:
        cur.execute("select derived.rebuild_technology(%s, %s, %s)",
                    (method_version, censored_at, run_id))
        return cur.fetchone()[0]


def rebuild_corpus_cohorts(conn, *, method_version: str, censored_at: date,
                          run_id: str | None = None) -> int:
    """Rebuild the attack-surface and KEV-entry cohort series.

    Same run and same censoring date as the technology cohorts and the detail table.
    Both cohort charts sit on one page; computing them on separate schedules would let
    them disagree about where the data stops, and a reader would have no way to tell.
    """
    with conn.cursor() as cur:
        cur.execute("select derived.rebuild_corpus_cohorts(%s, %s, %s)",
                    (method_version, censored_at, run_id))
        return cur.fetchone()[0]


def rebuild_patch_window_cohorts(conn, *, method_version: str, censored_at: date,
                                 run_id: str | None = None) -> int:
    """Rebuild the patch-window band series (the top chart)."""
    with conn.cursor() as cur:
        cur.execute("select derived.rebuild_patch_window_cohorts(%s, %s, %s)",
                    (method_version, censored_at, run_id))
        return cur.fetchone()[0]


def rebuild_kev_technology(conn, *, method_version: str, censored_at: date,
                          run_id: str | None = None) -> int:
    """Rebuild catalogued exploitation by technology domain (the bottom chart)."""
    with conn.cursor() as cur:
        cur.execute("select derived.rebuild_kev_technology(%s, %s, %s)",
                    (method_version, censored_at, run_id))
        return cur.fetchone()[0]


def rebuild_severity_predictiveness(conn, *, method_version: str, censored_at: date,
                                   run_id: str | None = None) -> int:
    """Rebuild the CVSS-band attack rates (both windows)."""
    with conn.cursor() as cur:
        cur.execute("select derived.rebuild_severity_predictiveness(%s, %s, %s)",
                    (method_version, censored_at, run_id))
        return cur.fetchone()[0]


def rebuild_scan_pressure(conn, *, method_version: str, censored_at: date,
                          run_id: str | None = None) -> int:
    """Rebuild the scanning-attempts-by-publication-date scatter.

    The function anchors its window to max(observed_at) for the Shadowserver API feed,
    NOT to censored_at, so a stalled collector surfaces as a stale obs_window_end rather
    than as a collapse in attempts.
    """
    with conn.cursor() as cur:
        cur.execute("select derived.rebuild_scan_pressure(%s, %s, %s)",
                    (method_version, censored_at, run_id))
        return cur.fetchone()[0]


def rebuild_kev_lag_points(conn, *, method_version: str, censored_at: date,
                           run_id: str | None = None) -> int:
    """Rebuild the per-CVE reporting-lag points the interactive lag chart draws.

    One row per KEV-listed CVE: publication date, the EARLIEST live listing date at
    or before the censoring date, and the lag between them. Full refresh, not an
    upsert: a CVE whose assertions are all withdrawn upstream must leave the table
    rather than stay behind citing evidence that no longer exists.
    """
    with conn.cursor() as cur:
        cur.execute("select derived.rebuild_kev_lag_points(%s, %s, %s)",
                    (method_version, censored_at, run_id))
        return cur.fetchone()[0]


def rebuild_scan_age_mix(conn, *, method_version: str, censored_at: date,
                         run_id: str | None = None) -> int:
    """Rebuild the scanning-traffic-by-vulnerability-age stream.

    Twelve COMPLETE calendar months, anchored to max(observed_at) for the Shadowserver
    API feed rather than to censored_at, so a stalled collector reads as a stale
    obs_window_end instead of twelve months of decline. The basket of 100 CVEs is
    recomputed for every month: Shadowserver changes which CVEs its sensors report, so
    a basket fixed at the start of the window would measure sensor coverage by the end
    of it.
    """
    with conn.cursor() as cur:
        cur.execute("select derived.rebuild_scan_age_mix(%s, %s, %s)",
                    (method_version, censored_at, run_id))
        return cur.fetchone()[0]


def rebuild_cve_activity(conn, *, method_version: str, censored_at: date,
                         run_id: str | None = None, days: int = 90) -> int:
    """Rebuild the trailing-window daily attempt series behind the Explorer sparkline.

    Anchored to max(observed_at) for the Shadowserver API feed, not to censored_at, so a
    stalled collector shows as a stale window_end rather than as an empty sparkline. The
    function prunes the whole window before inserting: a rolling window drops days on every
    run, and an upsert-only rebuild would publish the oldest day forever (see migration 0025).
    """
    with conn.cursor() as cur:
        cur.execute("select derived.rebuild_cve_activity(%s, %s, %s, %s)",
                    (method_version, censored_at, run_id, days))
        return cur.fetchone()[0]


def current_method_versions(conn) -> dict[str, str]:
    """The current method_version per metric, read from core.method_registry.

    THE REGISTRY IS THE SOURCE OF TRUTH FOR A METRIC'S VERSION, NOT THE PIPELINE.
    Ten metrics with ten independent version histories were all being stamped with
    one global --method-version. Measured 2026-09-03: patch_window_cohorts and
    pressure_index are genuinely on v5 (registered, and the charts render it), while
    the pipeline default is v3 — so the next scheduled run would have silently
    re-stamped correct v5 rows as v3, and a reader following the version on the chart
    would have been shown the wrong method description.

    "Current" is the highest introduced_at among rows not yet superseded, with the
    version string as a deterministic tiebreak so two rows introduced in the same
    migration still resolve. A metric absent here falls back to the caller's global
    version, which is what an unregistered metric should do — loudly, via the
    method_versions_registered eval, not silently.
    """
    with conn.cursor() as cur:
        cur.execute("""
            select distinct on (metric_id) metric_id, method_version
              from core.method_registry
             where superseded_at is null
             order by metric_id, introduced_at desc nulls last, method_version desc
        """)
        return {m: v for m, v in cur.fetchall()}


def run_rebuilds(conn, rebuilds, *, method_version, censored_at, run_id, log) -> tuple[dict, dict]:
    """Run each rebuild in its OWN transaction and report per table.

    Extracted from run.py so the isolation is testable: the property that matters is that a
    failure in one rebuild leaves the others committed, and that cannot be asserted against a
    loop buried in main().

    Returns (rows_by_key, errors_by_table, seconds_by_table). A caller that treats a non-empty
    errors dict as a run failure keeps the loud alarm; what changes is that nine good tables are
    no longer discarded to punish the tenth.

    EVERY REBUILD IS TIMED. These are the only statements on this site that come near the
    database's statement timeout: derived.rebuild_technology measures 90 to 102 seconds against
    six years of data and grows with the corpus. The session raises the timeout to ten minutes,
    which buys room but hides the trend, so the durations go into the run notes. The number to
    watch should be in a report while there is still headroom, not discovered as a failed run.
    """
    rows = {key: 0 for key, _, _ in rebuilds}
    errors: dict[str, str] = {}
    seconds: dict[str, float] = {}
    # Per-metric, from the registry. `method_version` is now only the fallback for a
    # metric nobody has registered yet.
    registered = current_method_versions(conn)
    for key, table, fn in rebuilds:
        metric = table.split(".", 1)[-1]
        version = registered.get(metric, method_version)
        started = time.monotonic()
        try:
            rows[key] = fn(conn, method_version=version,
                           censored_at=censored_at, run_id=run_id)
            conn.commit()
            seconds[table] = round(time.monotonic() - started, 1)
            log.info("%s: %d rows in %.1fs (method %s)", table, rows[key],
                     seconds[table], version)
        except Exception as exc:  # noqa: BLE001
            conn.rollback()
            seconds[table] = round(time.monotonic() - started, 1)
            errors[table] = f"{type(exc).__name__}: {exc}"
            log.exception("%s: rebuild failed after %.1fs", table, seconds[table])
    return rows, errors, seconds


def rebuild_explorer_list(conn, *, method_version: str, censored_at: date,
                          run_id: str | None = None) -> int:
    """Materialise the Explorer list.

    It was a view over 366,854 rows and every request re-filtered them to return 60; measured
    3.2 to 7.7 s per call. As a 5,211 row table the same query is a scan of the answer.
    """
    with conn.cursor() as cur:
        cur.execute("select derived.rebuild_explorer_list(%s, %s, %s)",
                    (method_version, censored_at, run_id))
        return cur.fetchone()[0]


def rebuild_explorer_strata(conn, *, method_version: str, censored_at: date,
                            run_id: str | None = None) -> int:
    """Recount the three Explorer strata. Exact, and computed once rather than per request."""
    with conn.cursor() as cur:
        cur.execute("select derived.rebuild_explorer_strata(%s, %s, %s)",
                    (method_version, censored_at, run_id))
        return cur.fetchone()[0]


def rebuild_pressure_index(conn, *, method_version: str, censored_at: date,
                           run_id: str | None = None) -> int:
    """Rebuild the three-stream pressure board (monthly series + 3-month readings)."""
    with conn.cursor() as cur:
        cur.execute("select derived.rebuild_pressure_index(%s, %s, %s)",
                    (method_version, censored_at, run_id))
        return cur.fetchone()[0]


def censoring_date(conn) -> date:
    """The date past which the detectors are NOT known to have been working.

    Not the query date. The CVE registry is the binding constraint for a per-CVE table:
    a CVE published after our last successful CVE harvest simply is not here yet, and
    crediting follow-up time past that point is the exact error that halved v1's 2026
    incidence estimate (Hazard 2).
    """
    with conn.cursor() as cur:
        cur.execute("""select max(f.started_at)::date
                         from raw.source_fetches f
                        where f.source_id in ('cve_project','nvd') and f.ok""")
        row = cur.fetchone()
    if not row or row[0] is None:
        raise RuntimeError("no successful CVE registry fetch on record — refusing to "
                           "guess a censoring date")
    return row[0]
