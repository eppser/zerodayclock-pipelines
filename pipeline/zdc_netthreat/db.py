"""Persistence for the network threat atlas. Writes net_raw, net_core, net_derived only."""

from __future__ import annotations

import datetime as dt

from psycopg.types.json import Jsonb

from .client import Response


def insert_fetch(conn, run_id, source_id: str, week_start: dt.date, r: Response, *,
                 records=0, ipv4=0, unmapped=0, excluded=0, error=None, notes=None) -> str:
    with conn.cursor() as cur:
        cur.execute(
            """insert into net_raw.fetches (run_id, source_id, week_start, url, requested_at, finished_at,
                   http_status, ok, error, bytes, content_sha256, records, ipv4, unmapped, excluded, notes)
               values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) returning fetch_id""",
            (run_id, source_id, week_start, r.url, r.requested_at, r.finished_at, r.status,
             r.ok and not error, error or r.error, getattr(r, 'total_bytes', len(r.body or b"")), r.sha256, records, ipv4,
             unmapped, excluded, Jsonb(notes or {})))
        return cur.fetchone()[0]


def insert_asn_counts(conn, fetch_id: str, rows) -> int:
    """rows: iterable of (asn, ips, slash24s, categories dict, listed, score)."""
    rows = list(rows)
    with conn.cursor() as cur:
        cur.executemany(
            """insert into net_raw.asn_counts (fetch_id, asn, ips, slash24s, categories, listed, score)
               values (%s,%s,%s,%s,%s,%s,%s)""",
            [(fetch_id, a, i, s, Jsonb(c), l, sc) for a, i, s, c, l, sc in rows])
    return len(rows)


def insert_union(conn, run_id, week_start, rows) -> None:
    with conn.cursor() as cur:
        cur.executemany("insert into net_raw.asn_union values (%s,%s,%s,%s,%s)",
                        [(run_id, week_start, a, i, n) for a, i, n in rows])


def latest_union(conn, week_start) -> dict[int, tuple[int, int]]:
    with conn.cursor() as cur:
        cur.execute("""select asn, ips, slash24s from net_raw.asn_union
                        where run_id = (select u.run_id from net_raw.asn_union u
                                          join raw.pipeline_runs r using (run_id)
                                         where u.week_start = %s
                                         order by r.started_at desc limit 1)""", (week_start,))
        return {a: (i, n) for a, i, n in cur.fetchall()}


def insert_cloudflare(conn, fetch_id: str, rows) -> None:
    with conn.cursor() as cur:
        cur.executemany(
            """insert into net_raw.cloudflare_lists (fetch_id, list, date_range, asn, name, share, key)
               values (%s,%s,%s,%s,%s,%s,%s) on conflict do nothing""",
            [(fetch_id, l, rng, a, n, s, k) for l, rng, a, n, s, k in rows])


def insert_country(conn, fetch_id: str, rows) -> None:
    with conn.cursor() as cur:
        cur.executemany(
            """insert into net_raw.country_counts (fetch_id, dataset, day, cc, count, per_million_users)
               values (%s,%s,%s,%s,%s,%s) on conflict do nothing""",
            [(fetch_id, d, day, cc, n, pu) for d, day, cc, n, pu in rows])


def insert_reference(conn, fetch_id: str, kind: str, snapshot: str, rows: int) -> None:
    with conn.cursor() as cur:
        cur.execute("insert into net_raw.reference_snapshots values (%s,%s,%s,%s)",
                    (fetch_id, kind, snapshot, rows))


def upsert_networks(conn, rows: list[dict]) -> int:
    cols = ["asn", "name", "handle", "org_id", "org_name", "siblings", "cc", "rir", "registered",
            "network_type", "type_basis", "routed_24s", "announced_ipv4", "prefixes", "pdb_type",
            "pdb_traffic", "pdb_scope", "pdb_policy", "website", "scanner", "updated_week", "routing_fetch_id"]
    with conn.cursor() as cur:
        cur.executemany(
            f"""insert into net_core.networks ({', '.join(cols)}) values ({', '.join(['%s'] * len(cols))})
                on conflict (asn) do update set {', '.join(f'{c} = excluded.{c}' for c in cols[1:])}""",
            [[r.get(c) for c in cols] for r in rows])
    return len(rows)


def abuse_due(conn, asns: list[int], limit: int) -> list[int]:
    """Networks never checked, or checked over 90 days ago, among those with evidence."""
    with conn.cursor() as cur:
        cur.execute("""select asn from net_core.networks
                        where asn = any(%s) and (abuse_checked_at is null
                              or abuse_checked_at < now() - interval '90 days')
                        order by abuse_checked_at nulls first, asn limit %s""", (asns, limit))
        return [r[0] for r in cur.fetchall()]


def set_abuse(conn, asn: int, role: str | None, personal: bool) -> None:
    with conn.cursor() as cur:
        cur.execute("""update net_core.networks set abuse_contact = %s, abuse_personal = %s,
                              abuse_checked_at = now() where asn = %s""", (role, personal, asn))


# ---- reads for scoring --------------------------------------------------------------------
def latest_fetches(conn, week_start: dt.date) -> dict[str, str]:
    """The newest successful fetch per source for the week (a re-run supersedes)."""
    with conn.cursor() as cur:
        cur.execute("""select distinct on (source_id) source_id, fetch_id from net_raw.fetches
                        where week_start = %s and ok and source_id <> 'reference'
                        order by source_id, finished_at desc""", (week_start,))
        return dict(cur.fetchall())


def counts_for(conn, fetch_ids: list[str]) -> dict[str, dict[int, tuple]]:
    with conn.cursor() as cur:
        cur.execute("""select f.source_id, c.asn, c.ips, c.slash24s, c.categories, c.listed, c.score
                         from net_raw.asn_counts c join net_raw.fetches f using (fetch_id)
                        where c.fetch_id = any(%s::uuid[])""", (fetch_ids,))
        out: dict[str, dict[int, tuple]] = {}
        for s, a, i, n, cat, l, sc in cur.fetchall():
            out.setdefault(s, {})[a] = (i, n, cat, l, sc)
        return out


def cloudflare_rows(conn, fetch_id: str) -> list[tuple]:
    with conn.cursor() as cur:
        cur.execute("select list, date_range, asn, share, key from net_raw.cloudflare_lists where fetch_id = %s", (fetch_id,))
        return cur.fetchall()


def country_rows(conn, fetch_id: str) -> list[tuple]:
    with conn.cursor() as cur:
        cur.execute("select dataset, day, cc, count, per_million_users from net_raw.country_counts where fetch_id = %s", (fetch_id,))
        return cur.fetchall()


def networks(conn) -> dict[int, dict]:
    with conn.cursor() as cur:
        cur.execute("select asn, routed_24s, network_type, scanner from net_core.networks")
        return {a: {"routed_24s": r, "type": t, "scanner": s} for a, r, t, s in cur.fetchall()}


# ---- derived: a rebuild for a week REPLACES that week (doctrine: never append) ---------------
def replace_week(conn, week_start: dt.date, method_version: str, source_rows, network_rows,
                 model_rows, country_rows_) -> None:
    with conn.cursor() as cur:
        for t in ("source_scores", "network_scores", "model_fits"):
            cur.execute(f"delete from net_derived.{t} where week_start = %s and method_version = %s",
                        (week_start, method_version))
        cur.execute("delete from net_derived.country_week where week_start = %s", (week_start,))
        cur.executemany(
            """insert into net_derived.source_scores (week_start, method_version, asn, source_id, n, ips,
                   expected, excess_mean, excess_lo90, excess_hi90, p_excess3, above_threshold, categories)
               values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            [(week_start, method_version, *r[:10], Jsonb(r[10])) for r in source_rows])
        cur.executemany(
            """insert into net_derived.network_scores (week_start, method_version, asn, score, groups, sensors,
                   distinct_ips, distinct_24s, spamhaus_asndrop, spamhaus_drop_ranges, uceprotect_score, tor_exits,
                   cf_waf_x, cf_rep_x, cf_waf_bound, cf_rep_bound, cf_traffic_share, cf_bot_share, censored_at)
               values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            [(week_start, method_version, *r) for r in network_rows])
        cur.executemany(
            """insert into net_derived.model_fits values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            [(week_start, method_version, *r) for r in model_rows])
        cur.executemany(
            """insert into net_derived.country_week values (%s,%s,%s,%s,%s,%s)""",
            [(week_start, *r) for r in country_rows_])


# ---- v2: routed sizes, per-side unions, the two-sided score ---------------------------------
def insert_routed_sizes(conn, fetch_id: str, size24: dict[int, int]) -> int:
    """Every routed ASN's /24 count, on the routing fetch (~79k rows a week)."""
    rows = [(fetch_id, a, n) for a, n in size24.items() if a and n > 0]
    # executemany, not COPY: the pipeline reaches Supabase through its pooler, and COPY is the
    # one statement a transaction-mode pooler may refuse. psycopg3 batches this in a pipeline.
    with conn.cursor() as cur:
        cur.executemany("insert into net_raw.routed_sizes (fetch_id, asn, slash24s) values (%s, %s, %s)", rows)
    return len(rows)


def routed_sizes(conn, week_start: dt.date) -> tuple[dict[int, int], str | None]:
    """The week's stored routed sizes (from its newest routing fetch) and the routing file name.
    An empty dict means the week predates 0102: the caller refetches the named file."""
    with conn.cursor() as cur:
        # the newest routing fetch of the week THAT HAS SIZES: a collect since 0102, or a recorded
        # refetch (notes.kind = 'pfx2as_refetch') made by an earlier score-only run of an older week
        cur.execute("""select f.fetch_id, f.notes->>'file' from net_raw.fetches f
                        where f.week_start = %s and f.source_id = 'reference' and f.ok
                          and f.notes->>'kind' in ('pfx2as', 'pfx2as_refetch')
                          and exists (select 1 from net_raw.routed_sizes r where r.fetch_id = f.fetch_id)
                        order by f.finished_at desc limit 1""", (week_start,))
        r = cur.fetchone()
        if r:
            cur.execute("select asn, slash24s from net_raw.routed_sizes where fetch_id = %s", (r[0],))
            return {a: n for a, n in cur.fetchall()}, r[1]
        cur.execute("""select notes->>'file' from net_raw.fetches
                        where week_start = %s and source_id = 'reference' and notes->>'kind' = 'pfx2as' and ok
                        order by finished_at desc limit 1""", (week_start,))
        r = cur.fetchone()
        return {}, (r[0] if r else None)


def insert_union_side(conn, run_id, week_start, side: str, rows) -> None:
    with conn.cursor() as cur:
        cur.executemany("insert into net_raw.asn_union_side values (%s,%s,%s,%s,%s,%s)",
                        [(run_id, week_start, side, a, i, n) for a, i, n in rows])


def latest_union_side(conn, week_start, side: str, feeds: tuple[str, ...] = ()) -> tuple[dict[int, tuple[int, int]], str | None]:
    """The side's union from the RUN that supplied the newest ok fetch of its feeds (so the
    de-duplication factor and the counts come from the same collection); the newest run with
    a union otherwise. Returns (rows, run_id)."""
    with conn.cursor() as cur:
        run = None
        if feeds:
            cur.execute("""select run_id from net_raw.fetches
                            where week_start = %s and ok and source_id = any(%s)
                            order by finished_at desc limit 1""", (week_start, list(feeds)))
            r = cur.fetchone()
            if r:
                cur.execute("select 1 from net_raw.asn_union_side where run_id = %s and side = %s limit 1", (r[0], side))
                run = r[0] if cur.fetchone() else None
        if run is None:
            cur.execute("""select u.run_id from net_raw.asn_union_side u join raw.pipeline_runs r using (run_id)
                            where u.week_start = %s and u.side = %s order by r.started_at desc limit 1""", (week_start, side))
            r = cur.fetchone()
            run = r[0] if r else None
        if run is None:
            return {}, None
        cur.execute("select asn, ips, slash24s from net_raw.asn_union_side where run_id = %s and side = %s", (run, side))
        return {a: (i, n) for a, i, n in cur.fetchall()}, str(run)


def previously_listed(conn, week_start: dt.date, method_version: str, max_gap_days: int = 21) -> tuple[dict[str, set[int]], dict[str, str | None]]:
    """Who was on each side's list in the most recent NON-PROVISIONAL scored week before this
    one, if it is at most `max_gap_days` old (hysteresis). A provisional base week (a feed
    absent, a fit unconverged, a blocked run) is skipped: its list is not evidence. Returns
    (sets per side, the base week per side) so the fit can record its provenance."""
    out: dict[str, set[int]] = {"attack": set(), "host": set()}
    base: dict[str, str | None] = {"attack": None, "host": None}
    with conn.cursor() as cur:
        for side in ("attack", "host"):
            cur.execute("""select max(week_start) from net_derived.fits_v2
                            where method_version = %s and side = %s and not provisional
                              and week_start < %s and week_start >= %s""",
                        (method_version, side, week_start, week_start - dt.timedelta(days=max_gap_days)))
            r = cur.fetchone()
            if not r or r[0] is None:
                continue
            base[side] = r[0].isoformat()
            cur.execute("""select asn from net_derived.network_scores_v2
                            where method_version = %s and side = %s and listed and week_start = %s""",
                        (method_version, side, r[0]))
            out[side] = {a for (a,) in cur.fetchall()}
    return out, base


def replace_week_v2(conn, week_start: dt.date, method_version: str, score_rows, fit_rows) -> None:
    """A rebuild REPLACES its week (doctrine: never append).
    score_rows: (asn, side, lo_x, best_x, se, mass, obs, own_x, top_share, listed, band, comp|None, n|None, provisional, censored_at)
    fit_rows:   dicts with the fits_v2 columns"""
    with conn.cursor() as cur:
        for t in ("network_scores_v2", "fits_v2"):
            cur.execute(f"delete from net_derived.{t} where week_start = %s and method_version = %s", (week_start, method_version))
        cur.executemany(
            """insert into net_derived.network_scores_v2 (week_start, method_version, asn, side, lo_x, best_x, se, mass, obs,
                   own_x, top_share, listed, band, comp, n, provisional, censored_at)
               values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            [(week_start, method_version, *r[:11], Jsonb(r[11]) if r[11] is not None else None,
              Jsonb(r[12]) if r[12] is not None else None, r[13], r[14]) for r in score_rows])
        cols = ["side", "feeds", "absent_feeds", "alpha", "phi", "mu0", "tau", "ref", "rho_union", "kappa", "feed_total",
                "loglik", "iterations", "converged", "seconds", "networks", "listed", "mass_total", "top10_share",
                "top100_share", "gini", "type_ref", "provisional", "notes"]
        js = {"feeds", "absent_feeds", "alpha", "phi", "feed_total", "type_ref", "notes"}
        cur.executemany(
            f"""insert into net_derived.fits_v2 (week_start, method_version, {', '.join(cols)})
                values (%s, %s, {', '.join(['%s'] * len(cols))})""",
            [(week_start, method_version, *[Jsonb(f[c]) if c in js else f[c] for c in cols]) for f in fit_rows])


def mark_week_blocked(conn, week_start: dt.date, method_version: str, failed: list[str]) -> None:
    """A week whose run failed a blocking gate stays stored (the raw rows are evidence) but is
    marked provisional on every v2 row and fit, with the failed gates in the fit notes, so the
    page prints PROVISIONAL rather than serving a blocked week as a clean one."""
    with conn.cursor() as cur:
        cur.execute("""update net_derived.fits_v2 set provisional = true,
                              notes = notes || jsonb_build_object('blocked', %s::jsonb)
                        where week_start = %s and method_version = %s""", (Jsonb(failed), week_start, method_version))
        cur.execute("""update net_derived.network_scores_v2 set provisional = true
                        where week_start = %s and method_version = %s""", (week_start, method_version))


def week_fetch_status(conn, week_start: dt.date) -> tuple[dict[str, tuple[bool, str | None]], dict[str, int]]:
    """What the week's newest fetch per source recorded, for the gates a --score-only run must
    still apply: (status per source as collect reports it, volume per source)."""
    with conn.cursor() as cur:
        cur.execute("""select distinct on (source_id) source_id, fetch_id, ok, error, records, ipv4
                         from net_raw.fetches where week_start = %s and source_id <> 'reference'
                        order by source_id, ok desc, finished_at desc""", (week_start,))
        rows = cur.fetchall()
        status, volumes = {}, {}
        for sid, fid, ok, err, records, ipv4 in rows:
            status[sid] = (bool(ok), err)
            if sid == "cloudflare":
                cur.execute("select count(*) from net_raw.cloudflare_lists where fetch_id = %s", (fid,))
                volumes[sid] = cur.fetchone()[0]
            elif sid == "shadowserver_country":
                cur.execute("select count(*) from net_raw.country_counts where fetch_id = %s", (fid,))
                volumes[sid] = cur.fetchone()[0]
            elif sid == "shodan":
                cur.execute("select coalesce(sum(ips), 0) from net_raw.asn_counts where fetch_id = %s", (fid,))
                volumes[sid] = int(cur.fetchone()[0])
            else:
                volumes[sid] = int(ipv4 or records or 0)
        return status, volumes


def side_union_stored(conn, week_start: dt.date) -> dict[str, bool]:
    """Whether this week's collect stored a per-side union (0102 or later)."""
    with conn.cursor() as cur:
        cur.execute("select side, count(*) from net_raw.asn_union_side where week_start = %s group by side", (week_start,))
        got = dict(cur.fetchall())
    return {s: bool(got.get(s)) for s in ("attack", "host")}


def previous_week_v2(conn, week_start: dt.date, method_version: str, max_gap_days: int = 21):
    """The last non-provisional week's fits (side -> alpha, phi, tau, checks) and rows
    ((asn, side) -> (lo_x, listed)), for the week-to-week gates. None, None when there is none."""
    with conn.cursor() as cur:
        cur.execute("""select max(week_start) from net_derived.fits_v2
                        where method_version = %s and not provisional and week_start < %s and week_start >= %s""",
                    (method_version, week_start, week_start - dt.timedelta(days=max_gap_days)))
        r = cur.fetchone()
        if not r or r[0] is None:
            return None, None
        base = r[0]
        cur.execute("select side, alpha, phi, tau, notes->'checks' from net_derived.fits_v2 where method_version = %s and week_start = %s",
                    (method_version, base))
        fits = {side: {"alpha": a, "phi": p, "tau": t, "checks": c} for side, a, p, t, c in cur.fetchall()}
        cur.execute("select asn, side, lo_x, listed from net_derived.network_scores_v2 where method_version = %s and week_start = %s",
                    (method_version, base))
        rows = {(a, s): (lo, l) for a, s, lo, l in cur.fetchall()}
    return fits, rows
