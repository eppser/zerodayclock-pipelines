"""Persistence for the agentic-C2 pipeline. Writes aof_raw, aof_core and aof_derived only.

Two rules live here because this is the only place a response body can reach the database:

  A BODY THAT CARRIES AN ADDRESS IS NEVER STORED. `store_fetch` checks the plaintext itself, so
  a caller cannot forget to. The fetch row still records the hash, size and record count.

  A DAY IS REPLACED, NEVER APPENDED TO. Derived rows for (day, source) are deleted and
  re-inserted in one transaction, so a second run for the same day revises it.
"""

from __future__ import annotations

import gzip
import ipaddress
import re
from datetime import date, timedelta

from .client import Response
from .models import Agent, Fingerprint

METHOD_VERSION = "v1"
NETWORK_DAY_RETENTION_DAYS = 90
OA, SHODAN = "offensive_agency", "shodan"

#: Four numbers under 256 joined by dots. Not the tail of a longer dotted number on the left
#: (1.2.3.4.5 is a version; static.1.2.3.4.example is a hostname with an address in it). On the right a dot is allowed when no digit follows it, so the
#: address ending a sentence or starting a hostname (8.8.4.4.clients.example) is still found.
IPV4 = re.compile(rb"(?<![0-9])(?<![0-9]\.)(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}"
                  rb"(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])(?![0-9])(?!\.[0-9])")
#: The same four numbers joined by hyphens inside a hostname, as reverse DNS writes them
#: (ec2-203-0-113-9.compute.example). Needs a letter or hyphen before and a dot or hyphen after,
#: which a date or an identifier does not have.
IPV4_DASHED = re.compile(rb"(?<=[A-Za-z-])(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])-){3}"
                         rb"(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])(?=[.-])")
#: Candidate IPv6: hex groups and colons containing "::" or seven colons. `_ipv6` decides.
IPV6 = re.compile(rb"(?<![0-9A-Za-z:.])[0-9A-Fa-f:]*(?:::|(?:[0-9A-Fa-f]{1,4}:){7})[0-9A-Fa-f:]*(?![0-9A-Za-z:])")


def _host_address(quad: bytes) -> bool:
    """A dotted (or dashed) quad that could be a listed host. Not one: loopback, unspecified,
    private and link-local ranges, netmasks, and x.0.0.0, which is how a browser version reads
    ("Chrome/128.0.0.0", measured in 15 framework profiles on 2026-11-25) and is never a host."""
    a, b, c, d = (int(x) for x in re.split(rb"[.-]", quad))
    if a in (0, 10, 127, 255) or (a, b) == (169, 254) or (a, b) == (192, 168) or (a == 172 and 16 <= b <= 31):
        return False
    return not (b == c == d == 0)


def _ipv6(token: bytes) -> bool:
    """A real IPv6 address, not `std::cout`, `a::before` or `dead::beef`: it parses, is not
    loopback or unspecified, and has a group of three or more characters that contains a digit."""
    try:
        addr = ipaddress.IPv6Address(token.decode())
    except ValueError:
        return False
    if addr.is_loopback or addr.is_unspecified:
        return False
    return any(len(g) >= 3 and any(ch.isdigit() for ch in g) for g in token.decode().split(":"))


def address_spans(body: bytes) -> list[tuple[int, int]]:
    spans = [m.span() for rx in (IPV4, IPV4_DASHED) for m in rx.finditer(body) if _host_address(m.group())]
    spans += [m.span() for m in IPV6.finditer(body) if _ipv6(m.group())]
    return spans


def carries_addresses(body: bytes) -> bool:
    return bool(address_spans(body))


def scrub(text: str) -> str:
    """`text` with every address replaced. For anything headed to a log, a run row or the
    report: those are public, and an exception message can quote the data it choked on."""
    raw = text.encode()
    for a, b in sorted(address_spans(raw), reverse=True):
        raw = raw[:a] + b"<address>" + raw[b:]
    return raw.decode(errors="replace")


def store_fetch(conn, run_id, source_id: str, endpoint: str, day: date, r: Response, *,
                record_count: int | None = None, error: str | None = None,
                keep_body: bool = True) -> None:
    """Record one request. The body is kept only if asked AND it carries no address."""
    err = error or r.error
    content_hash = r.content_hash
    stored, withheld = None, None
    if r.body is None:
        withheld = "no_body"
    elif not keep_body or carries_addresses(r.body):
        withheld = "carries_addresses"
    else:
        stored = content_hash
    with conn.cursor() as cur:
        if stored:
            cur.execute(
                """insert into aof_raw.bodies (content_hash, bytes, body_gz) values (%s, %s, %s)
                   on conflict (content_hash) do nothing""",
                (stored, len(r.body), gzip.compress(r.body, compresslevel=9, mtime=0)))
        cur.execute(
            """insert into aof_raw.fetches
                   (run_id, source_id, endpoint, url, day, requested_at, finished_at, http_status,
                    ok, error, content_hash, bytes, record_count, stored_hash, body_withheld)
               values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (run_id, source_id, endpoint, r.url, day, r.requested_at, r.finished_at, r.status,
             err is None, err, content_hash, None if r.body is None else len(r.body),
             record_count, stored, withheld))


def body_of(conn, content_hash: str) -> bytes | None:
    with conn.cursor() as cur:
        cur.execute("select body_gz from aof_raw.bodies where content_hash = %s", (content_hash,))
        row = cur.fetchone()
    return gzip.decompress(bytes(row[0])) if row else None


# ---- core ---------------------------------------------------------------------

def upsert_frameworks(conn, agents: list[Agent], day: date) -> None:
    rows = []
    for a in agents:
        rec = a.record
        port = rec.get("default_port")
        port = port if isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535 else None
        text = lambda k: rec.get(k)[:2000] if isinstance(rec.get(k), str) and rec.get(k).strip() else None  # noqa: E731
        rows.append((a.slug, a.name[:200], text("repository"), text("summary"), port, a.tracked, day, day))
    with conn.cursor() as cur:
        cur.executemany(
            """insert into aof_core.frameworks as f
                   (slug, name, repository, summary, default_port, tracked, first_seen_day, last_seen_day)
               values (%s,%s,%s,%s,%s,%s,%s,%s)
               on conflict (slug) do update set
                   name = excluded.name, repository = excluded.repository, summary = excluded.summary,
                   default_port = excluded.default_port, tracked = excluded.tracked,
                   first_seen_day = least(f.first_seen_day, excluded.first_seen_day),
                   last_seen_day = greatest(f.last_seen_day, excluded.last_seen_day)""", rows)


def upsert_rules(conn, framework: str, rules: list[Fingerprint], day: date) -> tuple[int, int]:
    """Store the rules published for one framework today; retire the ones no longer published.
    Call it only for a framework whose rules were fetched successfully, in a run whose source
    passed its checks: silence from a failed request is not evidence a rule was withdrawn. An
    EMPTY answer retires nothing either: a profile that suddenly lists no rule at all is far
    more likely a changed response shape than a framework the source stopped detecting, and the
    rules come back un-retired the day they are published again. Returns (new, retired)."""
    with conn.cursor() as cur:
        cur.execute("""select query from aof_core.detection_rules
                        where source_id = %s and framework = %s""", (OA, framework))
        known = {r[0] for r in cur.fetchall()}
        if rules:
            cur.executemany(
                """insert into aof_core.detection_rules as d
                       (source_id, framework, query, family, name, first_seen_day, last_seen_day)
                   values (%s,%s,%s,%s,%s,%s,%s)
                   on conflict (source_id, framework, query) do update set
                       family = excluded.family, name = excluded.name, retired_day = null,
                       first_seen_day = least(d.first_seen_day, excluded.first_seen_day),
                       last_seen_day = greatest(d.last_seen_day, excluded.last_seen_day)""",
                [(OA, framework, f.query, f.family[:60], f.name, day, day) for f in rules])
        retired = 0
        if rules:
            cur.execute(
                """update aof_core.detection_rules set retired_day = %s
                    where source_id = %s and framework = %s and retired_day is null
                      and last_seen_day < %s and not (query = any(%s))""",
                (day, OA, framework, day, [f.query for f in rules]))
            retired = cur.rowcount
    return len({f.query for f in rules} - known), retired


def upsert_network_names(conn, orgs: dict[int, str], day: date) -> None:
    if not orgs:
        return
    with conn.cursor() as cur:
        cur.executemany(
            """insert into aof_core.network_names as n (asn, org, last_seen_day) values (%s,%s,%s)
               on conflict (asn) do update set org = excluded.org,
                   last_seen_day = greatest(n.last_seen_day, excluded.last_seen_day)""",
            [(asn, org, day) for asn, org in sorted(orgs.items())])


# ---- derived ------------------------------------------------------------------

def replace_day(conn, run_id, source_id: str, day: date, censored_at: date, *,
                framework_values: dict[tuple[str, str], int],
                network_values: dict[tuple[str, int, str], int]) -> int:
    """Replace everything stored for (day, source): framework totals and per-network counts.

    framework_values: (framework, metric) -> value.  network_values: (framework, asn, cc) -> value.
    seen_day_addresses is NOT touched here; the timeline owns it (see upsert_timeline).
    """
    with conn.cursor() as cur:
        cur.execute("""delete from aof_derived.framework_day
                        where day = %s and source_id = %s and metric <> 'seen_day_addresses'""",
                    (day, source_id))
        cur.execute("delete from aof_derived.network_day where day = %s and source_id = %s",
                    (day, source_id))
        cur.executemany(
            """insert into aof_derived.framework_day
                   (day, source_id, framework, metric, value, method_version, censored_at, run_id)
               values (%s,%s,%s,%s,%s,%s,%s,%s)""",
            [(day, source_id, fw, metric, v, METHOD_VERSION, censored_at, run_id)
             for (fw, metric), v in sorted(framework_values.items())])
        rows = [(day, source_id, fw, asn, cc, v, METHOD_VERSION, run_id)
                for (fw, asn, cc), v in sorted(network_values.items()) if v > 0]
        cur.executemany(
            """insert into aof_derived.network_day
                   (day, source_id, framework, asn, cc, value, method_version, run_id)
               values (%s,%s,%s,%s,%s,%s,%s,%s)""", rows)
        # What the database now holds for this run, not what we meant to write: `persisted`
        # compares this with the number computed, and must be able to disagree.
        cur.execute("""select (select count(*) from aof_derived.framework_day
                                where run_id = %s and day = %s and source_id = %s and metric <> 'seen_day_addresses')
                            + (select count(*) from aof_derived.network_day
                                where run_id = %s and day = %s and source_id = %s)""",
                    (run_id, day, source_id, run_id, day, source_id))
        return cur.fetchone()[0]


def upsert_timeline(conn, run_id, rows: list[tuple[date, str, int]], censored_at: date) -> int:
    """offensive.agency's per-day "addresses seen", for every day it holds. Only rows whose value
    differs are rewritten, so a daily re-read of an unchanged history writes nothing. A row we hold
    inside the span the source just answered for, which the source no longer lists, is deleted:
    the source withdrew it, and keeping it would leave a number nobody publishes. Returns the
    number of rows inserted, revised or removed."""
    if not rows:
        return 0
    changed = 0
    days = [d for d, _, _ in rows]
    with conn.cursor() as cur:
        cur.execute("""select day, framework from aof_derived.framework_day
                        where source_id = %s and metric = 'seen_day_addresses' and day between %s and %s""",
                    (OA, min(days), max(days)))
        gone = set(cur.fetchall()) - {(d, slug) for d, slug, _ in rows}
        for d, slug in sorted(gone):
            cur.execute("""delete from aof_derived.framework_day
                            where source_id = %s and metric = 'seen_day_addresses' and day = %s and framework = %s""",
                        (OA, d, slug))
            changed += cur.rowcount
        for d, slug, v in rows:
            cur.execute(
                """insert into aof_derived.framework_day as f
                       (day, source_id, framework, metric, value, method_version, censored_at, run_id)
                   values (%s,%s,%s,'seen_day_addresses',%s,%s,%s,%s)
                   on conflict (day, source_id, framework, metric) do update
                       set value = excluded.value, censored_at = excluded.censored_at,
                           run_id = excluded.run_id, method_version = excluded.method_version
                     where f.value is distinct from excluded.value""",
                (d, OA, slug, v, METHOD_VERSION, censored_at, run_id))
            changed += cur.rowcount
    return changed


def prune_network_days(conn, newest: date) -> int:
    """Per-network rows are kept NETWORK_DAY_RETENTION_DAYS; the framework totals are kept for good."""
    with conn.cursor() as cur:
        cur.execute("delete from aof_derived.network_day where day < %s",
                    (newest - timedelta(days=NETWORK_DAY_RETENTION_DAYS),))
        return cur.rowcount


def stored_bytes(conn) -> int:
    with conn.cursor() as cur:
        cur.execute("""select coalesce(sum(pg_total_relation_size(c.oid)), 0)::bigint
                         from pg_class c join pg_namespace n on n.oid = c.relnamespace
                        where n.nspname in ('aof_raw', 'aof_core', 'aof_derived') and c.relkind = 'r'""")
        return cur.fetchone()[0]


def previous_services(conn, day: date) -> dict[str, int]:
    """Shodan's per-framework figure from the newest earlier day, for the run report."""
    with conn.cursor() as cur:
        cur.execute("""select framework, value from aof_derived.framework_day
                        where source_id = 'shodan' and metric = 'services_7d'
                          and day = (select max(day) from aof_derived.framework_day
                                      where source_id = 'shodan' and day < %s)""", (day,))
        return dict(cur.fetchall())


def summary(conn) -> dict:
    with conn.cursor() as cur:
        cur.execute("""select source_id, count(distinct day), min(day)::text, max(day)::text
                         from aof_derived.framework_day where metric <> 'seen_day_addresses'
                        group by 1 order by 1""")
        days = {r[0]: {"days": r[1], "first": r[2], "latest": r[3]} for r in cur.fetchall()}
        cur.execute("select count(*) from aof_core.frameworks")
        fw = cur.fetchone()[0]
        cur.execute("select count(*) filter (where retired_day is null), count(*) from aof_core.detection_rules")
        live, total = cur.fetchone()
    return {"sources": days, "frameworks": fw, "detection_rules": {"live": live, "ever": total}}
