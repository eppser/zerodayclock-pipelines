"""Postgres/Supabase persistence.

Writes go through the service role over a direct Postgres connection (``DATABASE_URL``),
never through the browser-facing REST API. Bulk upserts use COPY into an UNLOGGED temp
table followed by a single INSERT ... ON CONFLICT, which keeps a 10k-row run to a
handful of statements.
"""

from __future__ import annotations

import gzip
import json
import logging
import os
from datetime import date, datetime, timezone
from typing import Iterable, Sequence

import psycopg
from psycopg import sql
from psycopg.types.json import Jsonb

from .models import FetchRecord, KevObservation
from .sources.base import SourceState

log = logging.getLogger(__name__)

#: Payloads larger than this are hashed and logged but not stored inline. Guards
#: against an upstream feed suddenly shipping something enormous.
MAX_STORED_PAYLOAD_BYTES = int(os.environ.get("ZDC_MAX_PAYLOAD_BYTES", 32 * 1024 * 1024))

ENTRY_COLUMNS = (
    "source_id", "upstream_source", "evidence_source", "evidence_type", "origin_uuid",
    "source_entry_id", "vuln_id", "vuln_id_type",
    "cve_id", "aliases", "exploited", "signal", "status_reason", "confidence",
    "ransomware_use", "date_added", "exploited_since", "due_date", "source_published",
    "source_updated", "vendor_project", "product", "vulnerability_name",
    "short_description", "reference_urls", "raw", "content_hash",
    "first_fetch_id", "last_fetch_id",
)


def connect(dsn: str | None = None) -> psycopg.Connection:
    dsn = dsn or os.environ.get("DATABASE_URL")
    if not dsn:
        raise RuntimeError("DATABASE_URL is not set")
    return psycopg.connect(dsn, autocommit=False)


# ---------------------------------------------------------------------------
# Run + fetch logging
# ---------------------------------------------------------------------------


def start_run(conn, pipeline: str, mode: str, trigger: str, git_sha: str | None) -> str:
    with conn.cursor() as cur:
        cur.execute(
            """insert into raw.pipeline_runs (pipeline, mode, trigger, git_sha)
               values (%s, %s, %s, %s) returning run_id""",
            (pipeline, mode, trigger, git_sha),
        )
        return cur.fetchone()[0]


def live_entry_counts(conn) -> dict[str, int]:
    """Live assertions per source, as STORED. This is the quantity coverage is measured
    in — never raw.source_fetches.record_count, which counts records *returned by a
    fetch* and double-counts VulnCheck (its index and its backup snapshot are separate
    fetches of the same catalogue)."""
    with conn.cursor() as cur:
        cur.execute("""select source_id, count(*) from core.kev_entries
                        where withdrawn_at is null group by source_id""")
        return {r[0]: r[1] for r in cur.fetchall()}


def finish_run(conn, run_id: str, *, ok: bool, error: str | None = None, **counters) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """update raw.pipeline_runs set
                   finished_at = clock_timestamp(), ok = %s, error = %s,
                   sources_attempted = %s, sources_ok = %s, entries_seen = %s,
                   entries_inserted = %s, entries_updated = %s, entries_withdrawn = %s,
                   notes = %s
               where run_id = %s""",
            (
                ok, error,
                counters.get("sources_attempted", 0), counters.get("sources_ok", 0),
                counters.get("entries_seen", 0), counters.get("entries_inserted", 0),
                counters.get("entries_updated", 0), counters.get("entries_withdrawn", 0),
                Jsonb(counters.get("notes", {})), run_id,
            ),
        )


def record_fetch(conn, run_id: str, fetch: FetchRecord) -> str:
    """Persist one fetch attempt and its payload. Returns the fetch_id."""
    body = fetch.body
    stored_hash = None
    if body and fetch.content_hash:
        if len(body) <= MAX_STORED_PAYLOAD_BYTES:
            with conn.cursor() as cur:
                cur.execute(
                    """insert into raw.payloads (content_hash, media_type, byte_size, body_gzip)
                       values (%s, %s, %s, %s)
                       on conflict (content_hash) do nothing""",
                    (fetch.content_hash, fetch.media_type, len(body), gzip.compress(body)),
                )
            stored_hash = fetch.content_hash
        else:
            log.warning(
                "payload for %s is %d bytes (> %d); hash recorded, body not stored",
                fetch.url, len(body), MAX_STORED_PAYLOAD_BYTES,
            )

    with conn.cursor() as cur:
        cur.execute(
            """insert into raw.source_fetches (
                   run_id, source_id, url, request_mode, window_start, window_end,
                   http_status, ok, not_modified, etag, last_modified, content_hash,
                   record_count, bytes_downloaded, started_at, finished_at,
                   duration_ms, error, attempt)
               values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
               returning fetch_id""",
            (
                run_id, fetch.source_id, fetch.url, fetch.request_mode,
                fetch.window_start, fetch.window_end, fetch.http_status, fetch.ok,
                fetch.not_modified, fetch.etag, fetch.last_modified, stored_hash,
                fetch.record_count, fetch.bytes_downloaded, fetch.started_at,
                fetch.finished_at or datetime.now(timezone.utc), fetch.duration_ms,
                fetch.error, fetch.attempt,
            ),
        )
        return cur.fetchone()[0]


def get_source_state(conn, source_id: str) -> SourceState:
    """Reconstruct incremental state from the fetch log.

    Deliberately derived from the database rather than a local file: a CI runner keeps
    nothing between jobs, and state that lives outside the audit trail is state nobody
    can review.
    """
    with conn.cursor() as cur:
        cur.execute(
            """select etag, last_modified, content_hash, started_at
               from raw.source_fetches
               where source_id = %s and ok and content_hash is not null
               order by started_at desc limit 1""",
            (source_id,),
        )
        row = cur.fetchone()

        cur.execute(
            """select max(started_at) from raw.source_fetches
               where source_id = %s and ok""",
            (source_id,),
        )
        last_success = cur.fetchone()[0]

        cur.execute(
            """select max(f.started_at)
               from raw.source_fetches f
               join raw.pipeline_runs r on r.run_id = f.run_id
               where f.source_id = %s and f.ok and r.mode = 'full'""",
            (source_id,),
        )
        last_full = cur.fetchone()[0]

    if row is None:
        return SourceState(last_success_at=last_success, last_full_sync_at=last_full)
    return SourceState(
        last_etag=row[0],
        last_modified=row[1],
        last_content_hash=row[2],
        last_success_at=last_success,
        last_full_sync_at=last_full,
    )


# ---------------------------------------------------------------------------
# Observation upsert
# ---------------------------------------------------------------------------


def upsert_observations(
    conn, observations: Sequence[KevObservation], fetch_id: str
) -> tuple[int, int]:
    """Insert new observations, update changed ones, touch unchanged ones.

    Returns (inserted, updated). ``last_changed_at`` only moves when content_hash
    actually differs, so it stays a meaningful signal rather than a run timestamp.
    """
    if not observations:
        return (0, 0)

    with conn.cursor() as cur:
        cur.execute(
            """create temp table _kev_incoming (like core.kev_entries including defaults)
               on commit drop"""
        )
        cur.execute("alter table _kev_incoming drop column entry_id")

        columns = sql.SQL(", ").join(sql.Identifier(c) for c in ENTRY_COLUMNS)
        copy_stmt = sql.SQL("copy _kev_incoming ({}) from stdin").format(columns)
        with cur.copy(copy_stmt) as copy:
            for obs in observations:
                copy.write_row(
                    (
                        obs.source_id, obs.upstream_source, obs.evidence_source,
                        obs.evidence_type,
                        obs.origin_uuid, obs.source_entry_id,
                        obs.vuln_id, obs.vuln_id_type, obs.cve_id, list(obs.aliases),
                        obs.exploited, obs.signal, obs.status_reason, obs.confidence,
                        obs.ransomware_use, obs.date_added, obs.exploited_since,
                        obs.due_date, obs.source_published, obs.source_updated,
                        obs.vendor_project, obs.product, obs.vulnerability_name,
                        obs.short_description, list(obs.reference_urls),
                        Jsonb(obs.raw), obs.content_hash(), fetch_id, fetch_id,
                    )
                )

        # Deduplicate within the batch: a source can legitimately emit the same
        # identity twice (VulnCheck multi-CVE records), and ON CONFLICT cannot see
        # two conflicting rows in the same statement.
        cur.execute(
            """delete from _kev_incoming a using _kev_incoming b
               where a.ctid < b.ctid
                 and a.source_id = b.source_id
                 and a.upstream_source = b.upstream_source
                 and a.source_entry_id = b.source_entry_id"""
        )

        cur.execute(
            sql.SQL(
                """insert into core.kev_entries ({cols})
                   select {cols} from _kev_incoming
                   on conflict (source_id, upstream_source, source_entry_id) do update set
                       evidence_source    = excluded.evidence_source,
                       evidence_type      = excluded.evidence_type,
                       origin_uuid        = excluded.origin_uuid,
                       vuln_id            = excluded.vuln_id,
                       vuln_id_type       = excluded.vuln_id_type,
                       cve_id             = excluded.cve_id,
                       aliases            = excluded.aliases,
                       exploited          = excluded.exploited,
                       signal             = excluded.signal,
                       status_reason      = excluded.status_reason,
                       confidence         = excluded.confidence,
                       ransomware_use     = excluded.ransomware_use,
                       date_added         = excluded.date_added,
                       exploited_since    = excluded.exploited_since,
                       due_date           = excluded.due_date,
                       source_published   = excluded.source_published,
                       source_updated     = excluded.source_updated,
                       vendor_project     = excluded.vendor_project,
                       product            = excluded.product,
                       vulnerability_name = excluded.vulnerability_name,
                       short_description  = excluded.short_description,
                       reference_urls     = excluded.reference_urls,
                       raw                = excluded.raw,
                       content_hash       = excluded.content_hash,
                       last_fetch_id      = excluded.last_fetch_id,
                       last_seen_at       = now(),
                       withdrawn_at       = null,
                       last_changed_at    = case
                           when core.kev_entries.content_hash is distinct from excluded.content_hash
                           then now() else core.kev_entries.last_changed_at end
                   returning (xmax = 0) as inserted"""
            ).format(cols=columns)
        )
        flags = cur.fetchall()

    inserted = sum(1 for (is_insert,) in flags if is_insert)
    return inserted, len(flags) - inserted


def apply_assertion_withdrawals(conn) -> int:
    """Withdraw assertions listed in core.kev_assertion_withdrawals.

    A relay (CIRCL) can keep carrying an entry its origin has dropped. The upsert resets
    withdrawn_at on everything the relay still lists, so without this the withdrawal
    would be undone on every run. Withdraws only the named source's assertion.
    """
    with conn.cursor() as cur:
        cur.execute(
            """update core.kev_entries e
                  set withdrawn_at = w.checked_on::timestamptz
                 from core.kev_assertion_withdrawals w
                where e.source_id = w.source_id
                  and coalesce(e.upstream_source, e.source_id) = w.upstream_source
                  and e.vuln_id = w.vuln_id
                  and e.withdrawn_at is null"""
        )
        return cur.rowcount


def reconcile_withdrawals(conn, source_id: str, seen: Iterable[tuple[str, str]]) -> int:
    """Mark entries absent from a COMPLETE snapshot as withdrawn.

    Only ever called when the adapter reported ``complete_snapshot``. An incremental
    pull that omits an entry says nothing about whether the source removed it, and
    treating silence as withdrawal there would delete the back-catalogue.
    """
    seen_list = list(seen)
    with conn.cursor() as cur:
        cur.execute("create temp table _kev_seen (upstream_source text, source_entry_id text) on commit drop")
        with cur.copy("copy _kev_seen (upstream_source, source_entry_id) from stdin") as copy:
            for upstream, entry_id in seen_list:
                copy.write_row((upstream, entry_id))
        cur.execute("create index on _kev_seen (upstream_source, source_entry_id)")
        cur.execute(
            """update core.kev_entries e set withdrawn_at = now()
               where e.source_id = %s and e.withdrawn_at is null
                 and not exists (
                     select 1 from _kev_seen s
                     where s.upstream_source = e.upstream_source
                       and s.source_entry_id = e.source_entry_id)""",
            (source_id,),
        )
        return cur.rowcount


def rebuild_source_agreement(conn, method_version: str, censored_at: date) -> int:
    with conn.cursor() as cur:
        cur.execute(
            "select derived.rebuild_kev_source_agreement(%s, %s)",
            (method_version, censored_at),
        )
        return cur.fetchone()[0]


def rebuild_consolidated(conn, method_version: str, censored_at: date, run_id: str | None) -> int:
    with conn.cursor() as cur:
        cur.execute(
            "select derived.rebuild_kev_consolidated(%s, %s, %s)",
            (method_version, censored_at, run_id),
        )
        return cur.fetchone()[0]


def live_entry_counts(conn) -> dict[str, int]:
    """Entries currently visible per source. Used to prove ingestion reached the DB."""
    with conn.cursor() as cur:
        cur.execute(
            """select source_id, count(*) from core.kev_entries
               where withdrawn_at is null group by source_id"""
        )
        return {row[0]: row[1] for row in cur.fetchall()}


def enabled_sources(conn) -> list[dict]:
    with conn.cursor() as cur:
        cur.execute(
            """select source_id, priority, expected_min_entries, requires_credential,
                      credential_env, is_aggregator
               from core.kev_sources where enabled order by priority"""
        )
        return [
            {
                "source_id": r[0], "priority": r[1], "expected_min_entries": r[2],
                "requires_credential": r[3], "credential_env": r[4], "is_aggregator": r[5],
            }
            for r in cur.fetchall()
        ]
