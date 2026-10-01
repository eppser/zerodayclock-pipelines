"""Persistence for the CrowdSec tracker.

Writes obs_core.exploitation_observations and nothing else. In particular it MUST NOT
write core.kev_entries: CrowdSec is a sensor, and migration 0024 exists because 1,296
rows of Shadowserver telemetry were once ingested as catalogue listings. The
`kev_entries_no_telemetry` CHECK and the `no_telemetry_in_kev` eval both still stand.

The identity is `CVE@YYYY-MM-DD`, the same convention shadowserver_api uses, so a
re-run of any day revises it rather than duplicating it and the 30-day re-read window
is free of charge.
"""

from __future__ import annotations

import hashlib
import json
from typing import Sequence

from psycopg.types.json import Jsonb

from .models import CveState, DayCount

SOURCE_ID = "crowdsec"
COLS = 17
# Postgres refuses a statement carrying more than 65,535 bind parameters. A daily
# harvest is ~21,000 (CVE, day) rows at 17 columns each = ~356,000, so this MUST be
# chunked - the honeypot never meets the limit because it stores ~700 rows a day and
# copying its single-statement shape is what broke the first live run here.
# 2,000 x 17 = 34,000, half the ceiling, so the headroom survives a column being added.
CHUNK = 2_000


def entry_id(cve_id: str, day) -> str:
    return f"{cve_id}@{day.isoformat()}"


def _raw(s: CveState, c: DayCount) -> dict:
    """The CVE-level state as it stood on the day we read it.

    Carrying it per row is what makes the exploitation_phase series recoverable later
    WITHOUT a second table - 0029's lesson was that splitting one sensor across two
    stores left derived.cve_detail able to see only half of it. `first_seen` and
    `rule_release_date` are provenance only: see 0081 for why first_seen is not a
    start date.
    """
    out = {
        "occurrences": c.count,
        "exploitation_phase": s.phase,
        "nb_ips_total": s.nb_ips,
        "crowdsec_score": s.crowdsec_score,
        "opportunity_score": s.opportunity_score,
        "momentum_score": s.momentum_score,
        "cvss_score": s.cvss_score,
        "has_public_exploit": s.has_public_exploit,
        "rule_release_date": s.rule_release_date.isoformat() if s.rule_release_date else None,
        "tracker_first_seen": s.first_seen.isoformat() if s.first_seen else None,
        "cwes": s.cwes or None,
        "tags": s.tags or None,
    }
    return {k: v for k, v in out.items() if v is not None}


def upsert_observations(conn, states: dict[str, CveState],
                        counts: Sequence[DayCount], fetch_id: str) -> tuple[int, int]:
    if not counts:
        return (0, 0)
    # One statement must not offer the same key twice or Postgres raises a cardinality
    # violation; the last value for a key wins, as it does for the honeypot.
    latest: dict[str, DayCount] = {entry_id(c.cve_id, c.day): c for c in counts}

    flat: list = []
    for eid, c in latest.items():
        s = states.get(c.cve_id)
        if s is None:
            continue
        raw = _raw(s, c)
        flat.extend([
            SOURCE_ID, eid, "attempt_observed", c.cve_id, "cve", c.cve_id,
            c.day, c.day, c.day, c.count, s.vendor, s.product, s.title, Jsonb(raw),
            hashlib.md5(json.dumps(raw, sort_keys=True, default=str).encode()).hexdigest(),
            fetch_id, fetch_id,
        ])
    n = len(flat) // COLS
    if not n:
        return (0, 0)
    ins = upd = 0
    for start in range(0, n, CHUNK):
        rows = min(CHUNK, n - start)
        chunk = flat[start * COLS:(start + rows) * COLS]
        i, u = _write(conn, chunk, rows)
        ins += i
        upd += u
    return (ins, upd)


def _write(conn, flat: list, n: int) -> tuple[int, int]:
    placeholders = ",".join(["(" + ",".join(["%s"] * COLS) + ")"] * n)
    with conn.cursor() as cur:
        cur.execute(
            f"""
            insert into obs_core.exploitation_observations (
                source_id, source_entry_id, observation_type, vuln_id, vuln_id_type,
                cve_id, observed_at, first_observed_at, last_observed_at,
                observation_count, vendor, product, title, raw, content_hash,
                first_fetch_id, last_fetch_id)
            values {placeholders}
            on conflict (source_id, source_entry_id) do update set
                observation_count = excluded.observation_count,
                vendor            = excluded.vendor,
                product           = excluded.product,
                title             = excluded.title,
                raw               = excluded.raw,
                content_hash      = excluded.content_hash,
                last_fetch_id     = excluded.last_fetch_id,
                last_seen_at      = now()
            returning (xmax = 0) as inserted
            """, flat)
        res = cur.fetchall()
    ins = sum(1 for r in res if r[0])
    return (ins, len(res) - ins)


def stored_day_span(conn) -> tuple:
    with conn.cursor() as cur:
        cur.execute("""select min(observed_at), max(observed_at), count(*),
                              count(distinct cve_id)
                         from obs_core.exploitation_observations
                        where source_id = %s""", (SOURCE_ID,))
        return cur.fetchone()
