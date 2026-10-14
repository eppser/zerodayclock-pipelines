"""Which organisation, which incident: matching every source row to one canonical breach.

THE RULES (advisor review 2026-10-14, docs/decisions/0006):

Organisation identity, strongest first: SEC CIK; exact domain (never reduced to the parent's
registrable domain); normalised legal name. A name match alone identifies an organisation only
together with the same country, and two hospitals called "St. Mary's" in different states are
still the same norm_name - which is why a name never merges INCIDENTS on its own.

Incident identity for one organisation:
- MERGE when a hard key matched the organisation (CIK or domain) and the two event dates are
  within 30 days, or neither states an event date and the first public dates are within 90;
- MERGE when the names match and both rows state the SAME event date (two regulators
  describing one breach - the common multi-state filing);
- LINK (possible_duplicate_of) when the names match and the dates are within 30/90 days but
  not equal: both incidents stay, and the page counts the pair once;
- otherwise a new incident.
A manual override (breach_core.match_overrides) beats every rule.
"""

from __future__ import annotations

from datetime import date, timedelta

from .normalize import norm_domain, norm_name

EVENT_WINDOW = timedelta(days=30)
PUBLIC_WINDOW = timedelta(days=90)


def find_or_create_org(cur, *, name: str, domain: str | None = None, cik: str | None = None,
                       country: str | None = None, sector: str | None = None) -> tuple[str, str]:
    """(org_id, how) where how is 'sec_cik' | 'domain' | 'name' | 'new'."""
    nn = norm_name(name)
    domain = norm_domain(domain)
    if cik:
        cur.execute("select org_id from breach_core.organizations where sec_cik = %s", (cik,))
        r = cur.fetchone()
        if r:
            return r[0], "sec_cik"
    if domain:
        cur.execute("select org_id from breach_core.organizations where domain = %s order by created_at limit 1", (domain,))
        r = cur.fetchone()
        if r:
            if cik:
                cur.execute("update breach_core.organizations set sec_cik = coalesce(sec_cik, %s) where org_id = %s", (cik, r[0]))
            return r[0], "domain"
    if nn:
        cur.execute("""select org_id from breach_core.organizations
                        where norm_name = %s and coalesce(country, '') = coalesce(%s, '')
                          and (%s::text is null or sec_cik is null or sec_cik = %s)
                        order by created_at limit 1""", (nn, country, cik, cik))
        r = cur.fetchone()
        if r:
            cur.execute("""update breach_core.organizations set
                               domain = coalesce(domain, %s), sec_cik = coalesce(sec_cik, %s),
                               sector = coalesce(sector, %s)
                            where org_id = %s""", (domain, cik, sector, r[0]))
            return r[0], "name"
    cur.execute("""insert into breach_core.organizations (display_name, norm_name, domain, country, sector, sec_cik)
                   values (%s,%s,%s,%s,%s,%s) returning org_id""",
                (name.strip()[:300], nn, domain, country, sector, cik))
    return cur.fetchone()[0], "new"


def _override(cur, source_id: str, record_id: str, doc: str):
    cur.execute("""select incident_id from breach_core.match_overrides
                    where source_id = %s and source_record_id = %s and doc_sha256 = %s""",
                (source_id, record_id or "", doc or ""))
    r = cur.fetchone()
    return (True, r[0]) if r else (False, None)


def already_linked(cur, source_id: str, record_id: str = "", doc: str = ""):
    cur.execute("""select incident_id from breach_core.incident_sources
                    where source_id = %s and source_record_id = %s and doc_sha256 = %s""",
                (source_id, record_id or "", doc or ""))
    r = cur.fetchone()
    return r[0] if r else None


def resolve_incident(cur, *, org_id: str, org_how: str, source_id: str, record_id: str = "",
                     doc: str = "", event_date: date | None, public_date: date) -> tuple[str, str]:
    """(incident_id, match_method) for this source row, creating the incident if needed, and
    recording the link. Idempotent: a row already linked returns its incident unchanged."""
    linked = already_linked(cur, source_id, record_id, doc)
    if linked:
        return linked, "source_key"
    has, forced = _override(cur, source_id, record_id, doc)
    method, incident, dup_of = None, None, None
    if has and forced:
        incident, method = forced, "manual"
    elif not has:
        cur.execute("""select incident_id, event_date, first_public_date from breach_core.incidents
                        where org_id = %s order by first_public_date""", (org_id,))
        for inc_id, ev, pub in cur.fetchall():
            if event_date and ev:
                close, same = abs(ev - event_date) <= EVENT_WINDOW, ev == event_date
            else:
                close, same = abs(pub - public_date) <= PUBLIC_WINDOW, False
            if not close:
                continue
            if org_how in ("sec_cik", "domain"):
                incident, method = inc_id, org_how
                break
            if same:
                incident, method = inc_id, "event_window"
                break
            dup_of = dup_of or inc_id
    if incident is None:
        cur.execute("""insert into breach_core.incidents (org_id, event_date, first_public_date, possible_duplicate_of)
                       values (%s,%s,%s,%s) returning incident_id""",
                    (org_id, event_date, public_date, dup_of))
        incident, method = cur.fetchone()[0], method or "new"
    else:
        cur.execute("""update breach_core.incidents set
                           event_date = coalesce(event_date, %s),
                           first_public_date = least(first_public_date, %s), updated_at = now()
                        where incident_id = %s""", (event_date, public_date, incident))
    cur.execute("""insert into breach_core.incident_sources (incident_id, source_id, source_record_id, doc_sha256, match_method)
                   values (%s,%s,%s,%s,%s) on conflict do nothing""",
                (incident, source_id, record_id or "", doc or "", method))
    return incident, method


FLAG_FOR_BASIS = {"regulator_filing": "regulator_filed", "victim_statement": "victim_confirmed",
                  "news_citing_victim": "media_reported", "news": "media_reported",
                  "threat_actor_claim": "actor_claimed"}


def set_flag(cur, incident_id: str, basis: str) -> None:
    flag = FLAG_FOR_BASIS.get(basis)
    if flag:
        cur.execute(f"update breach_core.incidents set {flag} = true, updated_at = now() where incident_id = %s and not {flag}",
                    (incident_id,))


def add_claim(cur, *, incident_id: str, field: str, value_num=None, value_text=None, unit="none",
              qualifier="not_applicable", as_of: date, basis: str, source_id: str,
              source_record_id: str | None = None, doc_sha256: str | None = None, quote=None,
              quote_start=None, quote_end=None, subject_match=None, extraction_id=None,
              accepted=True, reject_reason=None, money_kind=None, currency=None, amount_usd=None,
              fx_rate=None, fx_date=None, fx_source=None) -> None:
    cur.execute(
        """insert into breach_core.claims (incident_id, field, value_num, value_text, unit, qualifier,
               money_kind, currency, amount_usd, fx_rate, fx_date, fx_source, as_of, basis, source_id,
               source_record_id, doc_sha256, quote, quote_start, quote_end, subject_match,
               extraction_id, accepted, reject_reason)
           values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
           on conflict do nothing""",
        (incident_id, field, value_num, value_text, unit, qualifier, money_kind, currency,
         amount_usd, fx_rate, fx_date, fx_source, as_of, basis, source_id, source_record_id,
         doc_sha256, quote, quote_start, quote_end, subject_match, extraction_id, accepted,
         reject_reason))


# ---- batched form ------------------------------------------------------------------------------
import uuid  # noqa: E402

_CLAIM_SQL = """insert into breach_core.claims (incident_id, field, value_num, value_text, unit, qualifier,
               money_kind, currency, amount_usd, fx_rate, fx_date, fx_source, as_of, basis, source_id,
               source_record_id, doc_sha256, quote, quote_start, quote_end, subject_match,
               extraction_id, accepted, reject_reason)
           values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
           on conflict do nothing"""


class Resolver:
    """The rules above, unchanged, for a batch of structured rows.

    MEASURED 2026-10-14: the per-row functions cost about a dozen round trips per regulator row,
    and a GitHub runner sits ~100 ms from the database, so Washington's 1,000 rows took 15+
    minutes and California's 5,300 would outlive the job. This reads the organisations, incidents,
    links and overrides once, decides in memory, generates ids client-side and sends every write
    in one pipelined batch. Same inputs, same decisions (tests run both paths)."""

    def __init__(self, cur):
        self.cur = cur
        self.writes: list[tuple[str, tuple]] = []
        cur.execute("""select org_id, norm_name, domain, country, sec_cik from breach_core.organizations
                        order by created_at, org_id""")
        self.by_cik, self.by_domain, self.by_name = {}, {}, {}
        self.org_cik = {}
        for oid, nn, dom, ctry, cik in cur.fetchall():
            self._index_org(oid, nn, dom, ctry, cik)
        cur.execute("""select org_id, incident_id, event_date, first_public_date from breach_core.incidents
                        order by first_public_date, incident_id""")
        self.incidents: dict = {}
        for oid, iid, ev, pub in cur.fetchall():
            self.incidents.setdefault(oid, []).append([iid, ev, pub])
        cur.execute("select source_id, source_record_id, doc_sha256, incident_id from breach_core.incident_sources")
        self.linked = {(s, r, d): i for s, r, d, i in cur.fetchall()}
        cur.execute("select source_id, source_record_id, doc_sha256, incident_id from breach_core.match_overrides")
        self.overrides = {(s, r, d): i for s, r, d, i in cur.fetchall()}
        self.flags: set = set()

    def _index_org(self, oid, nn, dom, ctry, cik):
        if cik:
            self.by_cik.setdefault(cik, oid)
        if dom:
            self.by_domain.setdefault(dom, oid)
        self.by_name.setdefault((nn, ctry or ""), oid)
        self.org_cik[oid] = cik

    def org(self, *, name, domain=None, cik=None, country=None, sector=None):
        nn, domain = norm_name(name), norm_domain(domain)
        if cik and cik in self.by_cik:
            return self.by_cik[cik], "sec_cik"
        if domain and domain in self.by_domain:
            oid = self.by_domain[domain]
            if cik:
                self.writes.append(("update breach_core.organizations set sec_cik = coalesce(sec_cik, %s) where org_id = %s", (cik, oid)))
                self.by_cik.setdefault(cik, oid)
                self.org_cik[oid] = self.org_cik.get(oid) or cik
            return oid, "domain"
        if nn:
            oid = self.by_name.get((nn, country or ""))
            if oid and (cik is None or self.org_cik.get(oid) in (None, cik)):
                self.writes.append(("""update breach_core.organizations set domain = coalesce(domain, %s),
                                          sec_cik = coalesce(sec_cik, %s), sector = coalesce(sector, %s)
                                       where org_id = %s""", (domain, cik, sector, oid)))
                if domain:
                    self.by_domain.setdefault(domain, oid)
                if cik:
                    self.by_cik.setdefault(cik, oid)
                    self.org_cik[oid] = self.org_cik.get(oid) or cik
                return oid, "name"
        oid = uuid.uuid4()
        self.writes.append(("""insert into breach_core.organizations (org_id, display_name, norm_name, domain, country, sector, sec_cik)
                               values (%s,%s,%s,%s,%s,%s,%s)""", (oid, name.strip()[:300], nn, domain, country, sector, cik)))
        self._index_org(oid, nn, domain, country, cik)
        return oid, "new"

    def incident(self, *, org_id, org_how, source_id, record_id="", doc="", event_date, public_date):
        key = (source_id, record_id or "", doc or "")
        if key in self.linked:
            return self.linked[key], "source_key"
        method = incident = dup_of = None
        if key in self.overrides and self.overrides[key]:
            incident, method = self.overrides[key], "manual"
        elif key not in self.overrides:
            for inc in self.incidents.get(org_id, []):
                inc_id, ev, pub = inc
                if event_date and ev:
                    close, same = abs(ev - event_date) <= EVENT_WINDOW, ev == event_date
                else:
                    close, same = abs(pub - public_date) <= PUBLIC_WINDOW, False
                if not close:
                    continue
                if org_how in ("sec_cik", "domain"):
                    incident, method = inc_id, org_how
                    break
                if same:
                    incident, method = inc_id, "event_window"
                    break
                dup_of = dup_of or inc_id
        if incident is None:
            incident, method = uuid.uuid4(), method or "new"
            self.writes.append(("""insert into breach_core.incidents (incident_id, org_id, event_date, first_public_date, possible_duplicate_of)
                                   values (%s,%s,%s,%s,%s)""", (incident, org_id, event_date, public_date, dup_of)))
            self.incidents.setdefault(org_id, []).append([incident, event_date, public_date])
        else:
            self.writes.append(("""update breach_core.incidents set event_date = coalesce(event_date, %s),
                                      first_public_date = least(first_public_date, %s), updated_at = now()
                                   where incident_id = %s""", (event_date, public_date, incident)))
            for inc in self.incidents.get(org_id, []):
                if inc[0] == incident:
                    inc[1] = inc[1] or event_date
                    inc[2] = min(inc[2], public_date)
        self.writes.append(("""insert into breach_core.incident_sources (incident_id, source_id, source_record_id, doc_sha256, match_method)
                               values (%s,%s,%s,%s,%s) on conflict do nothing""",
                            (incident, source_id, record_id or "", doc or "", method)))
        self.linked[key] = incident
        return incident, method

    def flag(self, incident_id, basis):
        flag = FLAG_FOR_BASIS.get(basis)
        if flag and (incident_id, flag) not in self.flags:
            self.flags.add((incident_id, flag))
            self.writes.append((f"update breach_core.incidents set {flag} = true, updated_at = now() where incident_id = %s and not {flag}",
                                (incident_id,)))

    def claim(self, *, incident_id, field, value_num=None, value_text=None, unit="none",
              qualifier="not_applicable", as_of, basis, source_id, source_record_id=None):
        self.writes.append((_CLAIM_SQL, (incident_id, field, value_num, value_text, unit, qualifier, None, None,
                                         None, None, None, None, as_of, basis, source_id, source_record_id,
                                         None, None, None, None, None, None, True, None)))

    def flush(self):
        if not self.writes:
            return 0
        n = len(self.writes)
        with self.cur.connection.pipeline():
            for sql, params in self.writes:
                self.cur.execute(sql, params)
        self.writes = []
        return n
