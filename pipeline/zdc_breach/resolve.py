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
  not equal: both incidents stay, and the page counts the pair once. Never for a card issuer
  (CARD_ISSUERS): American Express and Discover file one notice per merchant breach, usually
  without naming the merchant, so two of their notices a month apart are different breaches
  (owner decision 2026-10-20; 0 of 4 such links were right on the labelled pairs);
- otherwise a new incident.
A manual override (breach_core.match_overrides) beats every rule.

ACROSS LANGUAGES (0130). An extractor may give an organisation's English or romanised name
(organization_en) beside the name as written in a Japanese article. It is stored as an alias
(organizations.aliases) and, ONLY when the article itself writes that name, as a match key
(alias_norms). A key is used for ONE thing: finding the same organisation by name when the
article's own name does not match - "アスクル" with alias
"ASKUL" is found by a later English "Askul", and the reverse. It is a NAME match, with the same
country rule and the same consequence (incidents merge only on the same stated event date,
otherwise possible_duplicate_of); it never makes a hard key and is never evidence.

PRIVATE SOURCES (0136-0137, ADR 0009). A source with publication = 'private' (the curated export) is
resolved PASSIVELY: it may create organisations and incidents of its own and attach to existing ones by
the rules above, but it never writes to an organisation or incident another source created (no domain,
sector or date of its own lands on a public row). In the other direction, an incident known only from
private sources is invisible to the public list, so a public source never marks a row as a possible
duplicate of one (that would hide the public row behind an invisible one); when a public source merges
into such an incident by a hard key, the incident takes the public source's dates, and an ORGANISATION
the private source created (organizations.created_by_source) takes the public source's name, domain,
country and sector the first time a public source matches it - the public source wins, so no export
value reaches a public row through the organisation either (review 2026-10-20, must-fix 2).
"""

from __future__ import annotations

from datetime import date, timedelta

from .normalize import has_cjk, norm_domain, norm_name

EVENT_WINDOW = timedelta(days=30)
CARD_ISSUERS = ("american express", "discover financial")   # = linkage.CARD_ISSUERS
PUBLIC_WINDOW = timedelta(days=90)


# An alias shorter than this is not used to find an organisation: "NTT" or "AGC" alone names
# too many things to carry a model's romanisation across languages.
MIN_ALIAS_LEN = 4


def _alias(name_en: str | None, nn: str, name: str, in_text: bool) -> tuple[str, str, bool] | None:
    """(alias, its norm, is_key) when name_en is worth storing: given for a name written in Han or
    kana (this is for crossing languages, not for a model's view that "Change Healthcare" is
    "UnitedHealth"), long enough, and distinct from the name itself. is_key - whether it may be
    used to MATCH - only when the document itself writes the name (review 2026-10-19: a model's
    "Toyota" for トヨタ紡織 would otherwise join every Toyota report to the subsidiary)."""
    if not name_en or not has_cjk(name):
        return None
    an = norm_name(name_en)
    if len(an.replace(" ", "")) < MIN_ALIAS_LEN or an == nn:
        return None
    return name_en.strip()[:300], an, bool(in_text)


def _add_alias(cur, org_id, alias):
    """Store the alias on a Han/kana-named organisation; add its norm to alias_norms (the match
    keys) only when it is a key. An organisation named in Latin script never takes one."""
    if not alias:
        return
    cur.execute("""update breach_core.organizations
                      set aliases = case when %s = any(aliases) then aliases else array_append(aliases, %s) end,
                          alias_norms = case when not %s or alias_norms @> array[%s] then alias_norms
                                             else array_append(alias_norms, %s) end
                    where org_id = %s and breach_core.norm_name_cjk(display_name) is not null""",
                (alias[0], alias[0], alias[2], alias[1], alias[1], org_id))


_TAKE_OVER_SQL = """update breach_core.organizations
                        set display_name = %s, norm_name = %s, domain = %s, country = %s, sector = %s,
                            sec_cik = coalesce(%s, sec_cik), created_by_source = null
                      where org_id = %s
                        and created_by_source in (select source_id from breach_core.private_sources)"""


def _take_over(cur, org_id, name, domain, country, sector, cik):
    """A public source matched an organisation a private source created: its own values replace the
    private ones (a no-op for any other organisation)."""
    cur.execute(_TAKE_OVER_SQL, (name.strip()[:300], norm_name(name), domain, country, sector, cik, org_id))


def find_or_create_org(cur, *, name: str, domain: str | None = None, cik: str | None = None,
                       country: str | None = None, sector: str | None = None,
                       name_en: str | None = None, name_en_in_text: bool = False) -> tuple[str, str]:
    """(org_id, how) where how is 'sec_cik' | 'domain' | 'name' | 'name_en' | 'new'."""
    nn = norm_name(name)
    domain = norm_domain(domain)
    alias = _alias(name_en, nn, name, name_en_in_text)
    if cik:
        cur.execute("select org_id from breach_core.organizations where sec_cik = %s", (cik,))
        r = cur.fetchone()
        if r:
            _take_over(cur, r[0], name, domain, country, sector, cik)
            _add_alias(cur, r[0], alias)
            return r[0], "sec_cik"
    if domain:
        cur.execute("select org_id from breach_core.organizations where domain = %s order by created_at limit 1", (domain,))
        r = cur.fetchone()
        if r:
            if cik:
                cur.execute("update breach_core.organizations set sec_cik = coalesce(sec_cik, %s) where org_id = %s", (cik, r[0]))
            _take_over(cur, r[0], name, domain, country, sector, cik)
            _add_alias(cur, r[0], alias)
            return r[0], "domain"
    # By name: the organisation's own normalised name first, then a match key another language
    # gave it, then this row's alias - only if it is a key - against names and keys stored (0130).
    # `alias_norms @> array[...]` rather than `= any(...)`, so the GIN index serves it.
    steps = [(nn, "name", "norm_name = %s", 1), (nn, "name", "alias_norms @> array[%s]", 1)]
    if alias and alias[2]:
        steps.append((alias[1], "name_en", "(norm_name = %s or alias_norms @> array[%s])", 2))
    for key, how, where, n in steps:
        if not key or ("alias_norms" in where and len(key.replace(" ", "")) < MIN_ALIAS_LEN):
            continue
        cur.execute(f"""select org_id from breach_core.organizations
                         where {where} and coalesce(country, '') = coalesce(%s, '')
                           and (%s::text is null or sec_cik is null or sec_cik = %s)
                         order by created_at limit 1""", (key,) * n + (country, cik, cik))
        r = cur.fetchone()
        if r:
            cur.execute("""update breach_core.organizations set
                               domain = coalesce(domain, %s), sec_cik = coalesce(sec_cik, %s),
                               sector = coalesce(sector, %s)
                            where org_id = %s""", (domain, cik, sector, r[0]))
            _take_over(cur, r[0], name, domain, country, sector, cik)
            _add_alias(cur, r[0], alias)
            return r[0], how
    cur.execute("""insert into breach_core.organizations (display_name, norm_name, domain, country, sector, sec_cik,
                                                          aliases, alias_norms)
                   values (%s,%s,%s,%s,%s,%s,%s,%s) returning org_id""",
                (name.strip()[:300], nn, domain, country, sector, cik,
                 [alias[0]] if alias else [], [alias[1]] if alias and alias[2] else []))
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
        cur.execute("""select incident_id, event_date, first_public_date,
                              incident_id in (select incident_id from breach_core.private_only_incidents)
                         from breach_core.incidents
                        where org_id = %s order by first_public_date""", (org_id,))
        for inc_id, ev, pub, private_only in cur.fetchall():
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
            if not private_only:      # never hide a public row behind an invisible one (0137)
                dup_of = dup_of or inc_id
        if dup_of:
            cur.execute("select norm_name from breach_core.organizations where org_id = %s", (org_id,))
            row = cur.fetchone()
            if row and (row[0] or "").startswith(CARD_ISSUERS):
                dup_of = None
    if incident is None:
        cur.execute("""insert into breach_core.incidents (org_id, event_date, first_public_date, possible_duplicate_of)
                       values (%s,%s,%s,%s) returning incident_id""",
                    (org_id, event_date, public_date, dup_of))
        incident, method = cur.fetchone()[0], method or "new"
    else:
        # an incident only private sources knew takes this (public) source's dates: no private date surfaces
        cur.execute("""update breach_core.incidents set
                           event_date = case when incident_id in (select incident_id from breach_core.private_only_incidents)
                                             then %s else coalesce(event_date, %s) end,
                           first_public_date = case when incident_id in (select incident_id from breach_core.private_only_incidents)
                                                    then %s else least(first_public_date, %s) end,
                           updated_at = now()
                        where incident_id = %s""", (event_date, event_date, public_date, public_date, incident))
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
    in one pipelined batch. Same inputs, same decisions (tests run both paths).

    passive=True is for a private source (see PRIVATE SOURCES above): it creates its own rows and links to
    existing ones, but never updates a row it did not create. id_namespace makes the ids it creates a
    function of the source record (uuid5), so re-normalising the same raw layer into an empty core gives
    the same ids, and the same links (curated_export renormalise)."""

    def __init__(self, cur, *, passive: bool = False, id_namespace: uuid.UUID | None = None):
        self.cur = cur
        self.passive, self.ns = passive, id_namespace
        self.writes: list[tuple[str, tuple]] = []
        cur.execute("""select org_id, norm_name, domain, country, sec_cik, alias_norms,
                              created_by_source in (select source_id from breach_core.private_sources)
                         from breach_core.organizations
                        order by created_at, org_id""")
        self.by_cik, self.by_domain, self.by_name, self.by_alias = {}, {}, {}, {}
        self.org_cik, self.org_nn = {}, {}
        self.private_orgs: set = set()     # organisations a private source created; a public match takes them over
        for oid, nn, dom, ctry, cik, aliases, private in cur.fetchall():
            if private:
                self.private_orgs.add(oid)
            self._index_org(oid, nn, dom, ctry, cik)
            for an in aliases or ():
                self.by_alias.setdefault((an, ctry or ""), oid)
        cur.execute("""select org_id, incident_id, event_date, first_public_date from breach_core.incidents
                        order by first_public_date, incident_id""")
        self.incidents: dict = {}
        for oid, iid, ev, pub in cur.fetchall():
            self.incidents.setdefault(oid, []).append([iid, ev, pub])
        cur.execute("select source_id, source_record_id, doc_sha256, incident_id from breach_core.incident_sources")
        self.linked = {(s, r, d): i for s, r, d, i in cur.fetchall()}
        cur.execute("select source_id, source_record_id, doc_sha256, incident_id from breach_core.match_overrides")
        self.overrides = {(s, r, d): i for s, r, d, i in cur.fetchall()}
        cur.execute("select incident_id from breach_core.private_only_incidents")
        self.private_only = {r[0] for r in cur.fetchall()}
        self.flags: set = set()

    def _index_org(self, oid, nn, dom, ctry, cik):
        if cik:
            self.by_cik.setdefault(cik, oid)
        if dom:
            self.by_domain.setdefault(dom, oid)
        self.by_name.setdefault((nn, ctry or ""), oid)
        self.org_cik[oid] = cik
        self.org_nn[oid] = nn or ""

    def _new_id(self, kind: str, seed: str | None):
        return uuid.uuid5(self.ns, f"{kind}:{seed}") if self.ns and seed else uuid.uuid4()

    def org(self, *, name, domain=None, cik=None, country=None, sector=None, seed=None, source_id=None):
        """source_id is passed by a private source only: it is recorded as the creator of a new row."""
        oid, how = self._org(name=name, domain=domain, cik=cik, country=country, sector=sector, seed=seed,
                             source_id=source_id)
        if not self.passive and oid in self.private_orgs:
            self.writes.append((_TAKE_OVER_SQL, (name.strip()[:300], norm_name(name), norm_domain(domain), country,
                                                 sector, cik, oid)))
            self.private_orgs.discard(oid)
        return oid, how

    def _org(self, *, name, domain, cik, country, sector, seed, source_id):
        nn, domain = norm_name(name), norm_domain(domain)
        if cik and cik in self.by_cik:
            return self.by_cik[cik], "sec_cik"
        if domain and domain in self.by_domain:
            oid = self.by_domain[domain]
            if cik and not self.passive:
                self.writes.append(("update breach_core.organizations set sec_cik = coalesce(sec_cik, %s) where org_id = %s", (cik, oid)))
                self.by_cik.setdefault(cik, oid)
                self.org_cik[oid] = self.org_cik.get(oid) or cik
            return oid, "domain"
        if nn:
            oid = self.by_name.get((nn, country or ""))
            if oid is None and len(nn.replace(" ", "")) >= MIN_ALIAS_LEN:
                oid = self.by_alias.get((nn, country or ""))     # an alias another language gave (0130)
            if oid and (cik is None or self.org_cik.get(oid) in (None, cik)):
                if self.passive:
                    return oid, "name"
                self.writes.append(("""update breach_core.organizations set domain = coalesce(domain, %s),
                                          sec_cik = coalesce(sec_cik, %s), sector = coalesce(sector, %s)
                                       where org_id = %s""", (domain, cik, sector, oid)))
                if domain:
                    self.by_domain.setdefault(domain, oid)
                if cik:
                    self.by_cik.setdefault(cik, oid)
                    self.org_cik[oid] = self.org_cik.get(oid) or cik
                return oid, "name"
        oid = self._new_id("org", seed)
        self.writes.append(("""insert into breach_core.organizations (org_id, display_name, norm_name, domain, country, sector, sec_cik,
                                                                     created_by_source)
                               values (%s,%s,%s,%s,%s,%s,%s,%s)""", (oid, name.strip()[:300], nn, domain, country, sector, cik,
                                                                    source_id if self.passive else None)))
        if self.passive:
            self.private_orgs.add(oid)
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
                if self.passive or inc_id not in self.private_only:   # never hide a public row behind an invisible one
                    dup_of = dup_of or inc_id
        if dup_of and self.org_nn.get(org_id, "").startswith(CARD_ISSUERS):
            dup_of = None
        if incident is None:
            incident, method = self._new_id("incident", f"{source_id}:{record_id or ''}:{doc or ''}"), method or "new"
            self.writes.append(("""insert into breach_core.incidents (incident_id, org_id, event_date, first_public_date, possible_duplicate_of)
                                   values (%s,%s,%s,%s,%s)""", (incident, org_id, event_date, public_date, dup_of)))
            self.incidents.setdefault(org_id, []).append([incident, event_date, public_date])
            if self.passive:
                self.private_only.add(incident)
        elif self.passive:
            pass                       # a private source never moves another source's row
        elif incident in self.private_only:
            # an incident only private sources knew takes this public source's dates
            self.writes.append(("""update breach_core.incidents set event_date = %s, first_public_date = %s, updated_at = now()
                                   where incident_id = %s""", (event_date, public_date, incident)))
            self.private_only.discard(incident)
            for inc in self.incidents.get(org_id, []):
                if inc[0] == incident:
                    inc[1], inc[2] = event_date, public_date
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
