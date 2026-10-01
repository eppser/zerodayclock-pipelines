"""Persistence for the observation layer (obs_raw / obs_core / obs_derived)."""

from __future__ import annotations

import gzip
import logging
import os
from datetime import date, datetime, timezone
from typing import Sequence

import psycopg
from psycopg import sql
from psycopg.types.json import Jsonb

from zdc_kev.models import FetchRecord

from .models import ExploitationObservation
from .sources.base import ObsSourceState

log = logging.getLogger(__name__)

MAX_STORED_PAYLOAD_BYTES = int(os.environ.get("ZDC_MAX_PAYLOAD_BYTES", 32 * 1024 * 1024))

OBS_COLUMNS = (
    "source_id", "source_entry_id", "observation_type", "vuln_id", "vuln_id_type",
    "cve_id", "observed_at", "first_observed_at", "last_observed_at", "asserted_at",
    "observation_count", "publicly_disclosed", "vendor_forecast", "revision_dates",
    "vendor", "product", "title", "raw", "content_hash",
    "first_fetch_id", "last_fetch_id",
)


def connect(dsn: str | None = None) -> psycopg.Connection:
    dsn = dsn or os.environ.get("DATABASE_URL")
    if not dsn:
        raise RuntimeError("DATABASE_URL is not set")
    return psycopg.connect(dsn, autocommit=False)


def start_run(conn, pipeline: str, mode: str, trigger: str, git_sha: str | None) -> str:
    with conn.cursor() as cur:
        cur.execute(
            """insert into obs_raw.pipeline_runs (pipeline, mode, trigger, git_sha)
               values (%s,%s,%s,%s) returning run_id""",
            (pipeline, mode, trigger, git_sha),
        )
        return cur.fetchone()[0]


def finish_run(conn, run_id: str, *, ok: bool, error: str | None = None, **c) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """update obs_raw.pipeline_runs set finished_at=clock_timestamp(), ok=%s, error=%s,
                   sources_attempted=%s, sources_ok=%s, observations_seen=%s,
                   observations_inserted=%s, observations_updated=%s, notes=%s
               where run_id=%s""",
            (ok, error, c.get("sources_attempted", 0), c.get("sources_ok", 0),
             c.get("observations_seen", 0), c.get("observations_inserted", 0),
             c.get("observations_updated", 0), Jsonb(c.get("notes", {})), run_id),
        )


def record_fetch(conn, run_id: str, fetch: FetchRecord) -> str:
    stored_hash = None
    if fetch.body and fetch.content_hash and len(fetch.body) <= MAX_STORED_PAYLOAD_BYTES:
        with conn.cursor() as cur:
            cur.execute(
                """insert into obs_raw.payloads (content_hash, media_type, byte_size, body_gzip)
                   values (%s,%s,%s,%s) on conflict (content_hash) do nothing""",
                (fetch.content_hash, fetch.media_type, len(fetch.body),
                 gzip.compress(fetch.body)),
            )
        stored_hash = fetch.content_hash

    with conn.cursor() as cur:
        cur.execute(
            """insert into obs_raw.source_fetches (
                   run_id, source_id, url, request_mode, window_start, window_end,
                   http_status, ok, not_modified, etag, last_modified, content_hash,
                   record_count, bytes_downloaded, started_at, finished_at,
                   duration_ms, error, attempt)
               values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
               returning fetch_id""",
            (run_id, fetch.source_id, fetch.url, fetch.request_mode, fetch.window_start,
             fetch.window_end, fetch.http_status, fetch.ok, fetch.not_modified,
             fetch.etag, fetch.last_modified, stored_hash, fetch.record_count,
             fetch.bytes_downloaded, fetch.started_at,
             fetch.finished_at or datetime.now(timezone.utc), fetch.duration_ms,
             fetch.error, fetch.attempt),
        )
        return cur.fetchone()[0]


def get_source_state(conn, source_id: str) -> ObsSourceState:
    with conn.cursor() as cur:
        cur.execute(
            """select etag, last_modified, content_hash, started_at
               from obs_raw.source_fetches
               where source_id=%s and ok and content_hash is not null
               order by started_at desc limit 1""", (source_id,))
        row = cur.fetchone()
        cur.execute("select max(started_at) from obs_raw.source_fetches where source_id=%s and ok",
                    (source_id,))
        last_success = cur.fetchone()[0]
        cur.execute(
            """select max(f.started_at) from obs_raw.source_fetches f
               join obs_raw.pipeline_runs r on r.run_id=f.run_id
               where f.source_id=%s and f.ok and r.mode='full'""", (source_id,))
        last_full = cur.fetchone()[0]
    if row is None:
        return ObsSourceState(last_success_at=last_success, last_full_sync_at=last_full)
    return ObsSourceState(last_etag=row[0], last_modified=row[1], last_content_hash=row[2],
                          last_success_at=last_success, last_full_sync_at=last_full)


def upsert_observations(conn, observations: Sequence[ExploitationObservation],
                        fetch_id: str) -> tuple[int, int]:
    if not observations:
        return (0, 0)
    with conn.cursor() as cur:
        cur.execute("""create temp table _obs_in
                       (like obs_core.exploitation_observations including defaults)
                       on commit drop""")
        cur.execute("alter table _obs_in drop column observation_id")

        columns = sql.SQL(", ").join(sql.Identifier(c) for c in OBS_COLUMNS)
        with cur.copy(sql.SQL("copy _obs_in ({}) from stdin").format(columns)) as copy:
            for o in observations:
                copy.write_row((
                    o.source_id, o.source_entry_id, o.observation_type, o.vuln_id,
                    o.vuln_id_type, o.cve_id, o.observed_at, o.first_observed_at,
                    o.last_observed_at, o.asserted_at, o.observation_count,
                    o.publicly_disclosed, o.vendor_forecast, list(o.revision_dates),
                    o.vendor, o.product, o.title, Jsonb(o.raw), o.content_hash(),
                    fetch_id, fetch_id,
                ))

        # A source can legitimately emit the same identity twice within one batch
        # (a CVE appearing in two monthly documents resolves to distinct ids, but a
        # multi-CVE record can repeat); ON CONFLICT cannot see two conflicting rows
        # in the same statement.
        cur.execute("""delete from _obs_in a using _obs_in b
                       where a.ctid < b.ctid and a.source_id=b.source_id
                         and a.source_entry_id=b.source_entry_id""")

        cur.execute(sql.SQL(
            """insert into obs_core.exploitation_observations ({cols})
               select {cols} from _obs_in
               on conflict (source_id, source_entry_id) do update set
                   observation_type   = excluded.observation_type,
                   vuln_id            = excluded.vuln_id,
                   vuln_id_type       = excluded.vuln_id_type,
                   cve_id             = excluded.cve_id,
                   observed_at        = excluded.observed_at,
                   first_observed_at  = excluded.first_observed_at,
                   last_observed_at   = excluded.last_observed_at,
                   asserted_at        = excluded.asserted_at,
                   observation_count  = excluded.observation_count,
                   publicly_disclosed = excluded.publicly_disclosed,
                   vendor_forecast    = excluded.vendor_forecast,
                   revision_dates     = excluded.revision_dates,
                   vendor             = excluded.vendor,
                   product            = excluded.product,
                   title              = excluded.title,
                   raw                = excluded.raw,
                   content_hash       = excluded.content_hash,
                   last_fetch_id      = excluded.last_fetch_id,
                   last_seen_at       = now(),
                   withdrawn_at       = null,
                   last_changed_at    = case
                       when obs_core.exploitation_observations.content_hash
                            is distinct from excluded.content_hash
                       then now() else obs_core.exploitation_observations.last_changed_at end
               returning (xmax = 0) as inserted"""
        ).format(cols=columns))
        flags = cur.fetchall()

    inserted = sum(1 for (i,) in flags if i)
    return inserted, len(flags) - inserted


def rebuild_rollup(conn, method_version: str, censored_at: date, run_id: str | None) -> int:
    with conn.cursor() as cur:
        cur.execute("select obs_derived.rebuild_observation_rollup(%s,%s,%s)",
                    (method_version, censored_at, run_id))
        return cur.fetchone()[0]


COLLECTOR = "zdc_obs"


def enabled_sources(conn) -> list[dict]:
    """Sources THIS pipeline collects — not every source registered.

    obs_core.observation_sources is shared: a source must be registered there for the
    exploitation_observations foreign key, whoever fetches it. shadowserver_api is
    registered but collected by zdc_honeypot. Without the collector filter this function
    returned it too, get_source() raised "no adapter", and every run exited 1 while the
    three sources we do own had already been collected and persisted (migration 0062).
    """
    with conn.cursor() as cur:
        cur.execute("""select source_id, observation_type, priority, requires_credential
                       from obs_core.observation_sources
                        where enabled and collector = %s
                        order by priority""", (COLLECTOR,))
        return [{"source_id": r[0], "observation_type": r[1], "priority": r[2],
                 "requires_credential": r[3]} for r in cur.fetchall()]


def sources_by_collector(conn) -> dict[str, str]:
    """Every enabled source and who collects it — for the collectors_have_adapters eval."""
    with conn.cursor() as cur:
        cur.execute("""select source_id, collector from obs_core.observation_sources
                        where enabled""")
        return {r[0]: r[1] for r in cur.fetchall()}


def live_counts(conn) -> dict[str, int]:
    with conn.cursor() as cur:
        cur.execute("""select source_id, count(*) from obs_core.exploitation_observations
                       where withdrawn_at is null group by source_id""")
        return {r[0]: r[1] for r in cur.fetchall()}
