"""Persistence for the CVE registry.

Each source owns its own columns. A cve_project upsert never touches nvd_* and vice
versa, so an incremental run from one source cannot blank the other's data — which is
what would happen with a naive "update every column" upsert.
"""

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

from .models import CveRecord
from .sources.base import CveSourceState

log = logging.getLogger(__name__)

MAX_STORED_PAYLOAD_BYTES = int(os.environ.get("ZDC_MAX_PAYLOAD_BYTES", 32 * 1024 * 1024))

# Columns each source is authoritative for.
CVE_PROJECT_COLUMNS = (
    "cve_id", "cve_year", "state", "assigner_org_id", "assigner_short_name",
    "date_reserved", "date_published", "date_updated", "title", "description",
    "cna_cvss_version", "cna_cvss_score", "cna_cvss_vector",
    "cwe_ids", "affected_vendors", "affected_products", "reference_count",
    "cve_content_hash", "cve_fetch_id",
)
NVD_COLUMNS = (
    "cve_id", "cve_year", "nvd_published", "nvd_last_modified", "vuln_status",
    "nvd_cvss_version", "nvd_cvss_score", "nvd_cvss_vector", "cwe_ids",
    "nvd_content_hash", "nvd_fetch_id",
)


def connect(dsn: str | None = None) -> psycopg.Connection:
    dsn = dsn or os.environ.get("DATABASE_URL")
    if not dsn:
        raise RuntimeError("DATABASE_URL is not set")
    return psycopg.connect(dsn, autocommit=False)


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
    """Store the fetch. Bodies above the cap are hashed but not kept.

    That is the documented raw-layer exception from migration 0009: the CVE Project
    baseline is 562 MB and its GitHub release asset is immutable, so the tag plus hash
    is enough to re-fetch the exact artifact.
    """
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


def get_source_state(conn, source_id: str) -> CveSourceState:
    with conn.cursor() as cur:
        cur.execute("""select max(started_at) from raw.source_fetches
                       where source_id=%s and ok""", (source_id,))
        last_success = cur.fetchone()[0]
        cur.execute("""select max(f.started_at) from raw.source_fetches f
                       join raw.pipeline_runs r on r.run_id=f.run_id
                       where f.source_id=%s and f.ok and r.mode='full'""", (source_id,))
        last_full = cur.fetchone()[0]
        # Resume by release tag rather than by clock: the cursor is the last release
        # actually consumed, so a missed day cannot be silently skipped.
        #
        # Deliberately NOT filtered on r.ok. A cursor is only ever written for a source
        # that succeeded, so a run where a *different* source failed still holds a valid
        # cursor for this one. Requiring the whole run to be ok discarded it and made
        # the next run re-download the 589MB baseline.
        cur.execute("""select r.notes->'cursor'->>%s from raw.pipeline_runs r
                       where r.pipeline='cve' and r.notes->'cursor' ? %s
                       order by r.started_at desc limit 1""", (source_id, source_id))
        row = cur.fetchone()
    return CveSourceState(last_success_at=last_success, last_full_sync_at=last_full,
                          cursor=row[0] if row else None)


def _upsert(conn, records: Sequence[CveRecord], fetch_id: str, columns: tuple[str, ...],
            source: str) -> tuple[int, int]:
    if not records:
        return (0, 0)
    owned = [c for c in columns if c not in ("cve_id", "cve_year")]

    with conn.cursor() as cur:
        cur.execute("create temp table _cve_in (like core.cves including defaults) on commit drop")
        cols = sql.SQL(", ").join(sql.Identifier(c) for c in columns)
        with cur.copy(sql.SQL("copy _cve_in ({}) from stdin").format(cols)) as copy:
            for r in records:
                base = {
                    "cve_id": r.cve_id, "cve_year": r.year,
                    "state": r.state, "assigner_org_id": r.assigner_org_id,
                    "assigner_short_name": r.assigner_short_name,
                    "date_reserved": r.date_reserved, "date_published": r.date_published,
                    "date_updated": r.date_updated, "title": r.title,
                    "description": r.description,
                    "cna_cvss_version": r.cna_cvss_version, "cna_cvss_score": r.cna_cvss_score,
                    "cna_cvss_vector": r.cna_cvss_vector,
                    "cwe_ids": list(r.cwe_ids), "affected_vendors": list(r.affected_vendors),
                    "affected_products": list(r.affected_products),
                    "reference_count": r.reference_count,
                    "cve_content_hash": r.content_hash(), "cve_fetch_id": fetch_id,
                    "nvd_published": r.nvd_published, "nvd_last_modified": r.nvd_last_modified,
                    "vuln_status": r.vuln_status, "nvd_cvss_version": r.nvd_cvss_version,
                    "nvd_cvss_score": r.nvd_cvss_score, "nvd_cvss_vector": r.nvd_cvss_vector,
                    "nvd_content_hash": r.content_hash(), "nvd_fetch_id": fetch_id,
                }
                copy.write_row(tuple(base[c] for c in columns))

        cur.execute("delete from _cve_in a using _cve_in b where a.ctid < b.ctid and a.cve_id = b.cve_id")

        flag = "in_cve_project" if source == "cve_project" else "in_nvd"
        hash_col = "cve_content_hash" if source == "cve_project" else "nvd_content_hash"
        sets = []
        for c in owned:
            if c == "cwe_ids" and source == "nvd":
                # The CNA owns CWEs; NVD only fills the gap when the CNA gave none.
                sets.append(sql.SQL("cwe_ids = case when cardinality(core.cves.cwe_ids) = 0 "
                                    "then excluded.cwe_ids else core.cves.cwe_ids end"))
            else:
                sets.append(sql.SQL("{c} = excluded.{c}").format(c=sql.Identifier(c)))
        sets.append(sql.SQL("{f} = true").format(f=sql.Identifier(flag)))
        sets.append(sql.SQL("last_seen_at = now()"))
        sets.append(sql.SQL(
            "last_changed_at = case when core.cves.{h} is distinct from excluded.{h} "
            "then now() else core.cves.last_changed_at end").format(h=sql.Identifier(hash_col)))

        # Aggregate the insert/update split server-side. A bare RETURNING would ship
        # 384k rows back across the pooler purely to be counted, which dominated the
        # first backfill; wrapping it in a CTE returns one row instead.
        cur.execute(sql.SQL(
            "with upsert as ("
            "  insert into core.cves ({cols}, {flag}) select {cols}, true from _cve_in "
            "  on conflict (cve_id) do update set {sets} returning (xmax = 0) as inserted"
            ") select count(*) filter (where inserted), count(*) filter (where not inserted) "
            "from upsert"
        ).format(cols=cols, flag=sql.Identifier(flag), sets=sql.SQL(", ").join(sets)))
        inserted, updated = cur.fetchone()

    return int(inserted or 0), int(updated or 0)


def upsert_records(conn, records: Sequence[CveRecord], fetch_id: str, source: str) -> tuple[int, int]:
    columns = CVE_PROJECT_COLUMNS if source == "cve_project" else NVD_COLUMNS
    return _upsert(conn, records, fetch_id, columns, source)


# core.cve_sources is the manifest for the whole CVE layer, not this runner's work
# list. EPSS lives in it (registered by 0013 so it is discoverable alongside the others)
# but is fetched by zdc_enrich, so collecting every enabled row made every cve-pipeline
# run exit 1 on "no adapter for 'epss'" after its real work had already succeeded.
# Filter on the owning pipeline; a source that claims THIS pipeline and has no adapter
# is still a hard error, because that is a genuine failure and must not be softened.
COLLECTED_BY = "zdc_cve"


def enabled_sources(conn) -> list[dict]:
    with conn.cursor() as cur:
        cur.execute("""select source_id, priority, requires_credential
                       from core.cve_sources
                       where enabled and collected_by = %s
                       order by priority""", (COLLECTED_BY,))
        return [{"source_id": r[0], "priority": r[1], "requires_credential": r[2]}
                for r in cur.fetchall()]


def corpus_counts(conn) -> dict:
    with conn.cursor() as cur:
        cur.execute("""select count(*), count(*) filter (where in_cve_project),
                              count(*) filter (where in_nvd),
                              count(*) filter (where state='PUBLISHED'),
                              count(*) filter (where state='REJECTED')
                       from core.cves""")
        t, c, n, p, r = cur.fetchone()
    return {"total": t, "in_cve_project": c, "in_nvd": n, "published": p, "rejected": r}
