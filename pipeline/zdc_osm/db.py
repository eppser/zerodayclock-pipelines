"""Persistence for the OSM feed. Writes osm_raw and osm_core and nothing else."""

from __future__ import annotations

from datetime import datetime

from psycopg.types.json import Jsonb

from .client import Response
from .models import Downloads, Threat, changed_fields, ts

#: A lookup that errored is retried on later runs until it has failed this many times.
MAX_DOWNLOAD_ATTEMPTS = 3


def previous_newest(conn, ecosystem: str) -> datetime | None:
    """The watermark: newest last_updated of this ecosystem's last poll that saw records."""
    with conn.cursor() as cur:
        cur.execute("""select newest_last_updated from osm_raw.polls
                        where ecosystem = %s and ok and record_count > 0
                        order by requested_at desc limit 1""", (ecosystem,))
        row = cur.fetchone()
    return row[0] if row else None


def stored_count(conn, ecosystem: str) -> int:
    with conn.cursor() as cur:
        cur.execute("select count(*) from osm_core.threats where ecosystem = %s", (ecosystem,))
        return cur.fetchone()[0]


def load_current(conn, ids: list[str]) -> dict[str, tuple[int, str, dict]]:
    if not ids:
        return {}
    with conn.cursor() as cur:
        cur.execute("""select t.threat_id::text, t.current_version, t.content_hash, v.record
                         from osm_core.threats t
                         join osm_raw.threat_versions v
                           on v.threat_id = t.threat_id and v.version = t.current_version
                        where t.threat_id = any(%s::uuid[])""", (ids,))
        return {r[0]: (r[1], r[2], r[3]) for r in cur.fetchall()}


def classify(threats: list[Threat], current: dict) -> tuple[list, list, list]:
    new, changed, unchanged = [], [], []
    for t in threats:
        cur = current.get(t.threat_id)
        if cur is None:
            new.append(t)
        elif cur[1] != t.content_hash:
            changed.append(t)
        else:
            unchanged.append(t)
    return new, changed, unchanged


def insert_poll(conn, run_id: str, ecosystem: str, r: Response, *, record_count: int,
                malformed: int, oldest, newest, previous, complete, counts=(0, 0, 0),
                error: str | None = None) -> str:
    with conn.cursor() as cur:
        cur.execute(
            """insert into osm_raw.polls
                   (run_id, ecosystem, url, requested_at, finished_at, http_status, ok, error,
                    record_count, malformed_count, oldest_last_updated, newest_last_updated,
                    previous_newest, window_complete, new_count, changed_count, unchanged_count)
               values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
               returning poll_id""",
            (run_id, ecosystem, r.url, r.requested_at, r.finished_at, r.status,
             error is None, error, record_count, malformed, oldest, newest, previous,
             complete, *counts))
        return cur.fetchone()[0]


def _col(rec: dict, k: str):
    v = rec.get(k)
    return v if isinstance(v, str) else (None if v is None else str(v))


def write_threats(conn, poll_id: str, captured_at: datetime, new: list[Threat],
                  changed: list[Threat], unchanged: list[Threat], current: dict) -> None:
    versions, upserts = [], []
    for t in new + changed:
        cur = current.get(t.threat_id)
        version = 1 if cur is None else cur[0] + 1
        diff = changed_fields(None if cur is None else cur[2], t.record)
        versions.append((t.threat_id, version, t.content_hash, captured_at, poll_id,
                         diff, Jsonb(t.record)))
        upserts.append(_threat_row(t, version, captured_at, changed=True))
    for t in unchanged:
        upserts.append(_threat_row(t, current[t.threat_id][0], captured_at, changed=False))

    with conn.cursor() as cur:
        if versions:
            cur.executemany(
                """insert into osm_raw.threat_versions
                       (threat_id, version, content_hash, captured_at, poll_id,
                        changed_fields, record)
                   values (%s,%s,%s,%s,%s,%s,%s)""", versions)
        if upserts:
            cur.executemany(
                """insert into osm_core.threats as t
                       (threat_id, ecosystem, report_type, package_name, resource_identifier,
                        severity_level, status, version_info, tags, osm_created_at,
                        osm_verified_at, osm_last_updated, osm_first_seen, current_version,
                        content_hash, first_captured_at, last_captured_at, last_changed_at)
                   values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                   on conflict (threat_id) do update set
                       ecosystem = excluded.ecosystem, report_type = excluded.report_type,
                       package_name = excluded.package_name,
                       resource_identifier = excluded.resource_identifier,
                       severity_level = excluded.severity_level, status = excluded.status,
                       version_info = excluded.version_info, tags = excluded.tags,
                       osm_created_at = excluded.osm_created_at,
                       osm_verified_at = excluded.osm_verified_at,
                       osm_last_updated = excluded.osm_last_updated,
                       osm_first_seen = excluded.osm_first_seen,
                       current_version = excluded.current_version,
                       content_hash = excluded.content_hash,
                       last_captured_at = excluded.last_captured_at,
                       last_changed_at = case when t.content_hash = excluded.content_hash
                                              then t.last_changed_at
                                              else excluded.last_changed_at end""",
                upserts)


def _threat_row(t: Threat, version: int, captured_at: datetime, *, changed: bool) -> tuple:
    r = t.record
    tags = r.get("tags") if isinstance(r.get("tags"), list) else []
    return (t.threat_id, t.ecosystem, _col(r, "report_type"), _col(r, "package_name"),
            _col(r, "resource_identifier"), _col(r, "severity_level"), _col(r, "status"),
            _col(r, "version_info"), [str(x) for x in tags if x is not None],
            ts(r.get("created_at")), t.verified_at, t.last_updated, ts(r.get("first_seen")),
            version, t.content_hash, captured_at, captured_at, captured_at)


# ---- downloads ----------------------------------------------------------------

def pending_downloads(conn, limit: int) -> list[tuple[str, str, str | None, int]]:
    """npm/pypi threats with no conclusive lookup yet, oldest capture first."""
    with conn.cursor() as cur:
        cur.execute("""select threat_id::text, ecosystem, package_name, download_attempts
                         from osm_core.threats
                        where ecosystem in ('npm', 'pypi') and downloads_outcome is null
                          and download_attempts < %s
                        order by first_captured_at, threat_id
                        limit %s""", (MAX_DOWNLOAD_ATTEMPTS, limit))
        return cur.fetchall()


def record_lookup(conn, run_id: str, threat_id: str, registry: str, name: str | None,
                  url: str | None, requested_at: datetime, status: int,
                  d: Downloads, *, count_attempt: bool = True) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """insert into osm_raw.download_lookups
                   (run_id, threat_id, registry, package_name, source_url, requested_at,
                    http_status, outcome, downloads_last_week, window_start, window_end, error)
               values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (run_id, threat_id, registry, name or "", url, requested_at, status, d.outcome,
             d.weekly, d.window_start, d.window_end, d.error))
        conclusive = d.outcome != "error"
        cur.execute(
            """update osm_core.threats set
                   download_attempts = download_attempts + %s,
                   downloads_outcome = case when %s then %s else downloads_outcome end,
                   downloads_last_week = case when %s then %s else downloads_last_week end,
                   downloads_measured_at = case when %s then %s else downloads_measured_at end
                where threat_id = %s""",
            (1 if count_attempt else 0, conclusive, d.outcome, conclusive, d.weekly,
             conclusive, requested_at, threat_id))


def summary(conn) -> dict:
    with conn.cursor() as cur:
        cur.execute("""select ecosystem, count(*), min(first_captured_at), max(osm_last_updated)
                         from osm_core.threats group by 1 order by 2 desc""")
        eco = {r[0]: {"threats": r[1], "first_captured": str(r[2]), "newest": str(r[3])}
               for r in cur.fetchall()}
        cur.execute("""select downloads_outcome, count(*) from osm_core.threats
                        where ecosystem in ('npm','pypi') group by 1""")
        dl = {str(r[0]): r[1] for r in cur.fetchall()}
    return {"ecosystems": eco, "downloads": dl}
