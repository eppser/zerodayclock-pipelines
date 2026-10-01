"""Persistence for vendor fix records."""
from __future__ import annotations

import hashlib
import json
from datetime import date

SOURCE_ID = "msrc_cvrf"


def ensure_source(conn) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """insert into core.cve_sources
                 (source_id, display_name, role, priority, requires_credential, enabled,
                  collected_by)
               values (%s, %s, %s, %s, false, true, %s)
               on conflict (source_id) do nothing""",
            (SOURCE_ID, "MSRC Security Update Guide (CVRF)", "patch_dates", 60, "zdc_patch"),
        )


def purge(conn) -> int:
    """Drop every row this collector wrote.

    Only ever called on a BACKFILL, which re-reads every document and is therefore a complete
    snapshot. An incremental run reads two months: its silence about the other 127 is not
    evidence that those fix records stopped existing, and deleting on it would empty the table
    daily. This is the distinction migration 0025 exists to record.
    """
    with conn.cursor() as cur:
        cur.execute("delete from core.cve_patch_dates where source_id = %s", (SOURCE_ID,))
        return cur.rowcount


def upsert(conn, records, *, fetch_id=None) -> int:
    """Write fix records. Keyed on (cve_id, source_id, patch_date), so re-reading a document
    revises rather than duplicates, and a CVE fixed in two months keeps both dates: cve_detail
    takes min() and the earlier one wins."""
    if not records:
        return 0
    rows = []
    for r in records:
        h = hashlib.sha256(
            json.dumps([r.cve_id, r.patch_date, r.fix_version, r.evidence_url],
                       sort_keys=True).encode()
        ).hexdigest()
        rows.append((r.cve_id, SOURCE_ID, r.patch_date, "vendor_fix_record",
                     r.product, r.fix_version, r.evidence_url, h, fetch_id))
    with conn.cursor() as cur:
        cur.executemany(
            """insert into core.cve_patch_dates
                 (cve_id, source_id, patch_date, basis, product, fix_version,
                  evidence_url, content_hash, fetch_id, first_seen_at, last_seen_at)
               values (%s,%s,%s,%s,%s,%s,%s,%s,%s, now(), now())
               on conflict (cve_id, source_id, patch_date) do update
                 set fix_version = excluded.fix_version,
                     evidence_url = excluded.evidence_url,
                     content_hash = excluded.content_hash,
                     last_seen_at = now()""",
            rows,
        )
    return len(rows)


def coverage(conn) -> dict:
    with conn.cursor() as cur:
        cur.execute("""select count(*), count(distinct cve_id), min(patch_date), max(patch_date)
                         from core.cve_patch_dates""")
        n, cves, lo, hi = cur.fetchone()
        cur.execute("""select count(*) from derived.cve_detail d
                        where exists (select 1 from core.cve_patch_dates p
                                       where p.cve_id = d.cve_id)
                          and (d.kev_status = 'in_kev' or d.observation_count_total > 0)""")
        in_explorer = cur.fetchone()[0]
    return {"rows": n, "cves": cves, "first": str(lo) if lo else None,
            "last": str(hi) if hi else None, "explorer_rows_covered": in_explorer}
