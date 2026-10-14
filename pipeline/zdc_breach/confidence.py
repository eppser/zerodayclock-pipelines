"""How far each source's word is borne out by other sources (migration 0109). Rebuilt every run.

RANSOMWARE GROUPS. Of a group's claims old enough to have been reported (60+ days), the share a
regulator filing or the press later corroborated: the claim is linked to such an incident (exact
domain), or an incident with the exact normalised victim name was made public between 60 days
before and 180 days after the claim. US regulators and the press see a small part of the world,
so the figure is a LOWER BOUND, useful to compare groups, never a probability that a claim is true.

NEWS OUTLETS. Of the victims an outlet reported, the share a regulator filing or another outlet
also reported.

REGULATORS AND INDEXES are primary records; their row says so rather than pretending to a rate.
Wilson 95% intervals throughout, so a group with 8 claims does not outrank one with 800.
"""

from __future__ import annotations

METHOD_VERSION = "breach-confidence-v1"
MIN_AGE_DAYS = 60

GROUPS_SQL = """
with eligible as (
    select c.claim_key, c.actor_group, c.victim_norm, c.victim_domain, c.first_seen_at::date as seen, c.incident_id
      from breach_core.leak_claims c
     where c.first_seen_at < now() - make_interval(days => %(age)s)
       and not breach_core.is_generic_name(c.victim_name)
), corroborated as (
    select e.claim_key from eligible e
      join breach_core.incidents i on i.incident_id = e.incident_id
     where i.regulator_filed or i.victim_confirmed or i.media_reported
    union
    select e.claim_key from eligible e
      join breach_core.organizations o on o.norm_name = e.victim_norm and length(e.victim_norm) >= 6
      join breach_core.incidents i on i.org_id = o.org_id
     where (i.regulator_filed or i.victim_confirmed or i.media_reported)
       and i.first_public_date between e.seen - 60 and e.seen + 180
)
select e.actor_group, count(*)::int, count(c.claim_key)::int
  from eligible e left join corroborated c using (claim_key)
 group by 1
"""

OUTLETS_SQL = """
with per as (
    select s.source_id, s.incident_id from breach_core.incident_sources s
      join breach_core.sources src using (source_id) where src.kind = 'news'
), others as (
    select p.source_id, p.incident_id,
           exists (select 1 from breach_core.incident_sources x join breach_core.sources sx using (source_id)
                    where x.incident_id = p.incident_id and x.source_id <> p.source_id
                      and sx.kind in ('regulator', 'news')) as corroborated
      from per p
)
select source_id, count(distinct incident_id)::int, count(distinct incident_id) filter (where corroborated)::int
  from others group by 1
"""


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float | None, float | None, float | None]:
    if n == 0:
        return None, None, None
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return round(p, 4), round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4)


def build(cur) -> int:
    rows = []
    cur.execute(GROUPS_SQL, {"age": MIN_AGE_DAYS})
    for group, n, k in cur.fetchall():
        r, lo, hi = wilson(k, n)
        rows.append(("actor_group", group, n, k, r, lo, hi,
                     f"claims {MIN_AGE_DAYS}+ days old later corroborated by a regulator filing or the press "
                     "(a lower bound: those see a small part of the world)"))
    cur.execute(OUTLETS_SQL)
    for source, n, k in cur.fetchall():
        r, lo, hi = wilson(k, n)
        rows.append(("source", source, n, k, r, lo, hi, "victims a regulator filing or another outlet also reported"))
    cur.execute("select source_id, kind from breach_core.sources where kind in ('regulator', 'breach_index', 'leak_tracker')")
    for source, kind in cur.fetchall():
        note = {"regulator": "primary record: the organisation's own filing with a regulator",
                "breach_index": "verified breach dataset (HIBP); counts are accounts",
                "leak_tracker": "copies of ransomware leak-site posts: claims by attackers, see each group's rate"}[kind]
        rows.append(("source", source, 0, 0, None, None, None, note))
    cur.execute("delete from breach_core.source_confidence")
    if rows:
        with cur.connection.pipeline():
            cur.executemany("""insert into breach_core.source_confidence (scope, key, claims, corroborated, rate, rate_low,
                                   rate_high, basis_note, method_version)
                               values (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                            [r + (METHOD_VERSION,) for r in rows])
    return len(rows)
