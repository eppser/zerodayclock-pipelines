"""Persistence for the Shadowserver honeypot API.

Writes obs_core.exploitation_observations — the SINGLE observation store. 0028 briefly
had purpose-shaped honeypot_* tables; 0029 retired them, because only one of the three
observation sources is a daily series and the generic table already modelled that grain
(its dashboard rows are keyed 'CVE-2025-58360@2026-08-30'). Two stores for one sensor
meant derived.cve_detail could see only half the data.

The identity extends the existing dashboard convention with the product, because one CVE
is genuinely reported against several products on the same day.
"""

from __future__ import annotations

import hashlib
import json
from datetime import date
from typing import Sequence

from psycopg.types.json import Jsonb

from .models import HoneypotRow

SOURCE_ID = "shadowserver_api"

# The vuln_id_type values obs_core.exploitation_observations accepts (widened by 0029 to
# carry edb/cnvd, which are exactly the identifiers no KEV catalogue can list).
ALLOWED_ID_TYPES = frozenset({"cve", "euvd", "ghsa", "gcve", "edb", "cnvd", "other"})


def entry_id(row: HoneypotRow) -> str:
    product = f"|{row.product_key}" if row.product_key else ""
    return f"{row.vuln_id}{product}@{row.observed_on.isoformat()}"


def _raw(row: HoneypotRow) -> dict:
    """The row as the API reported it, minus nulls. obs_raw.payloads holds the true
    bytes; this is the per-row copy the table has always carried."""
    yn = lambda b: None if b is None else ("yes" if b else "no")  # noqa: E731
    out = {
        "vulnerability": row.vuln_id, "connections": row.connections,
        "1d": row.avg_1d, "7d_avg": row.avg_7d, "30d_avg": row.avg_30d,
        "90d_avg": row.avg_90d, "cisa_kev": yn(row.cisa_kev), "vendor": row.vendor,
        "product": row.product, "class": row.device_class, "type": row.scan_type,
        "vulnerability_severity": row.severity, "vulnerability_score": row.cvss_score,
        "vulnerability_class": row.scoring_class, "iot": yn(row.is_iot),
        "euvd": row.euvd_id,
        "first_seen": row.sensor_first_seen.isoformat() if row.sensor_first_seen else None,
    }
    return {k: v for k, v in out.items() if v is not None}


def upsert_observations(conn, rows: Sequence[HoneypotRow], fetch_id: str) -> tuple[int, int]:
    """Idempotent on (source_id, source_entry_id): re-running a day revises it."""
    if not rows:
        return (0, 0)
    # The unique key is (source_id, source_entry_id); a single statement must not offer
    # the same key twice or Postgres raises a cardinality violation.
    latest: dict[str, HoneypotRow] = {}
    for r in rows:
        latest[entry_id(r)] = r

    values, flat = [], []
    for eid, r in latest.items():
        raw = _raw(r)
        values.append(eid)
        flat.extend([
            SOURCE_ID, eid, "attempt_observed", r.vuln_id,
            r.vuln_id_type if r.vuln_id_type in ALLOWED_ID_TYPES else "other",
            r.cve_id, r.observed_on, r.observed_on, r.observed_on, r.connections,
            r.product_key, r.vendor, r.product, r.device_class, r.sensor_first_seen,
            r.is_iot, Jsonb(raw),
            hashlib.md5(json.dumps(raw, sort_keys=True, default=str).encode()).hexdigest(),
            fetch_id, fetch_id,
        ])
    placeholders = ",".join(["(" + ",".join(["%s"] * 20) + ")"] * len(values))
    with conn.cursor() as cur:
        cur.execute(
            f"""
            insert into obs_core.exploitation_observations (
                source_id, source_entry_id, observation_type, vuln_id, vuln_id_type,
                cve_id, observed_at, first_observed_at, last_observed_at,
                observation_count, product_key, vendor, product, device_class,
                sensor_first_seen, is_iot, raw, content_hash,
                first_fetch_id, last_fetch_id)
            values {placeholders}
            on conflict (source_id, source_entry_id) do update set
                observation_count = excluded.observation_count,
                vendor            = excluded.vendor,
                product           = excluded.product,
                device_class      = excluded.device_class,
                is_iot            = excluded.is_iot,
                -- Keep the EARLIEST sighting ever reported: a later fetch reporting a
                -- later date must not silently shorten history.
                sensor_first_seen = least(
                    obs_core.exploitation_observations.sensor_first_seen,
                    excluded.sensor_first_seen),
                raw               = excluded.raw,
                content_hash      = excluded.content_hash,
                last_fetch_id     = excluded.last_fetch_id,
                last_seen_at      = now(),
                last_changed_at   = case
                    when obs_core.exploitation_observations.content_hash
                         is distinct from excluded.content_hash
                    then now()
                    else obs_core.exploitation_observations.last_changed_at end
            returning (xmax = 0) as inserted
            """,
            flat,
        )
        results = cur.fetchall()
    inserted = sum(1 for r in results if r[0])
    return inserted, len(results) - inserted


def days_present(conn, start: date, end: date) -> set[date]:
    """Which days already hold data — lets a backfill resume instead of restarting."""
    with conn.cursor() as cur:
        cur.execute(
            """select distinct observed_at from obs_core.exploitation_observations
                where source_id = %s and observed_at between %s and %s""",
            (SOURCE_ID, start, end))
        return {r[0] for r in cur.fetchall()}


def coverage(conn) -> dict:
    with conn.cursor() as cur:
        cur.execute(
            """select count(*), count(distinct vuln_id), min(observed_at),
                      max(observed_at), count(distinct observed_at)
                 from obs_core.exploitation_observations where source_id = %s""",
            (SOURCE_ID,))
        n, v, lo, hi, days = cur.fetchone()
    return {"rows": n, "vulnerabilities": v, "first_day": lo, "last_day": hi, "days": days}
