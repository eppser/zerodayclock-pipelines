"""Washington AG's own web list of data-breach notices: the "Information Compromised" column.

WHY A SECOND ENDPOINT FOR AN EXISTING SOURCE (ruling R4, 2026-10-21). The data.wa.gov dataset
(sources_reg.WA_URL) carries who, when, how many Washingtonians and the cause, but no data
types. The AG's list at atg.wa.gov carries the types for every notice (150/150 sampled, 1,883/1,883
on the 2026-10-21 read), from a closed vocabulary of 17 terms. This module reads that list and
attaches a data_types claim to the incident the dataset row already created. It never creates an
organisation or an incident: a notice it cannot join stays in the raw layer and changes nothing.

THE JOIN (and why it is the only one):
1. exact normalised organisation name (normalize.norm_name) AND the site's "Date Reported" equal
   to the dataset's datesubmitted;
2. the dataset's own id, if the site exposed it - it does not (the notice PDFs are numbered
   BreachA43155 / BreachM12345, a different series from the dataset's 11442), so rule 2 never
   fires today and is not guessed at;
3. anything else - two dataset rows with the same key, or two site rows claiming one dataset row -
   is AMBIGUOUS and joins nothing.
Measured on a sealed sample of 100 site rows: see /tmp/zdcq/dtypes/B_REPORT.md and
tests/test_wa_site.py (the rule itself is tested on synthetic rows).

RAW FIRST. Each page fetch is a breach_raw.fetches row (URL, status, bytes, sha256), and each
notice is a breach_raw.source_records row under source 'wa_ag' with id 'site:<notice id>', so the
dataset's numeric ids and the site's ids can never collide. No breach_core.incident_sources row is
written for a site notice: the incident is already linked to its dataset record, and a second
'wa_ag' link would make one filing look like two records to every view that reads the links.

"Unknown" is dropped from the list (it names no data type); a notice whose only term is
"Unknown" gives no claim. Every other term is kept verbatim - mapping to tags is FIELD_RULES' job.
"""

from __future__ import annotations

import hashlib
import html
import re
from dataclasses import dataclass, field
from datetime import date, datetime
from html.parser import HTMLParser

from .normalize import norm_name

SITE_URL = "https://www.atg.wa.gov/data-breach-notifications"
MAX_PAGES = 80                     # 38 pages on 2026-10-21; a runaway pager stops here
PAGE_DELAY_S = 1.0                 # a state AG site: at most one request a second
DROP_TERMS = {"unknown"}

_COLS = {"view-field-report-date-table-column": "date_reported",
         "view-field-full-title-table-column": "organization",
         "view-field-start-date-table-column": "date_of_breach",
         "view-field-number-wa-affected-table-column": "wa_affected",
         "view-field-information-compromised-table-column": "information_compromised"}
_NOTICE_ID = re.compile(r"/Breach([A-Za-z]*\d+)\.pdf$")


def page_url(page: int) -> str:
    return f"{SITE_URL}?page={page}"


@dataclass
class Notice:
    site_id: str                      # 'site:A43155' - the notice PDF's own number
    organization: str
    date_reported: date
    date_of_breach: date | None
    wa_affected: int | None
    terms: list[str]                  # Information Compromised, verbatim, 'Unknown' dropped
    notice_url: str | None
    record: dict = field(default_factory=dict)

    @property
    def data_types(self) -> str | None:
        return ", ".join(self.terms) if self.terms else None


class _Table(HTMLParser):
    """Rows of the view's <tbody>; each cell keyed by its `headers` attribute."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.rows: list[dict] = []
        self.pages: list[int] = []
        self._tbody = False
        self._row: dict | None = None
        self._cell: str | None = None
        self._buf: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and (a.get("href") or "").startswith("?page="):
            m = re.match(r"\?page=(\d+)$", a["href"])
            if m:
                self.pages.append(int(m.group(1)))
        if tag == "tbody":
            self._tbody = True
        elif self._tbody and tag == "tr":
            self._row = {}
        elif self._row is not None and tag == "td":
            self._cell = _COLS.get(a.get("headers") or "")
            self._buf = []
        elif self._cell and tag == "a" and a.get("href"):
            self._row.setdefault("notice_url", a["href"])

    def handle_endtag(self, tag):
        if tag == "tbody":
            self._tbody = False
        elif tag == "td" and self._row is not None and self._cell:
            self._row[self._cell] = " ".join("".join(self._buf).split())
            self._cell = None
        elif tag == "tr" and self._row is not None:
            if self._row:
                self.rows.append(self._row)
            self._row = None

    def handle_data(self, data):
        if self._cell:
            self._buf.append(data)


def _mdy(v: str | None) -> date | None:
    try:
        return datetime.strptime((v or "").strip(), "%m/%d/%Y").date()
    except ValueError:
        return None


def _count(v: str | None) -> int | None:
    v = (v or "").replace(",", "").strip()
    return int(v) if v.isdigit() and int(v) > 0 else None


def parse_page(body: str) -> tuple[list[Notice], int, int | None]:
    """(notices, malformed, last page index the pager names). A row without a name or a
    reported date is malformed and counted, never guessed."""
    t = _Table()
    t.feed(body)
    out, bad = [], 0
    for r in t.rows:
        name = html.unescape(r.get("organization") or "").strip()
        reported = _mdy(r.get("date_reported"))
        if not name or not reported:
            bad += 1
            continue
        url = r.get("notice_url")
        m = _NOTICE_ID.search(url or "")
        sid = f"site:{m.group(1)}" if m else \
            "site:h" + hashlib.sha1(f"{norm_name(name)}|{reported}".encode()).hexdigest()[:12]
        terms = [x.strip() for x in (r.get("information_compromised") or "").split(";")]
        terms = [x for x in terms if x and x.lower() not in DROP_TERMS]
        rec = {"organization": name, "date_reported": reported.isoformat(),
               "date_of_breach": r.get("date_of_breach") or None, "wa_affected": r.get("wa_affected") or None,
               "information_compromised": r.get("information_compromised") or None, "notice_url": url}
        out.append(Notice(sid, name, reported, _mdy(r.get("date_of_breach")), _count(r.get("wa_affected")),
                          terms, url, rec))
    return out, bad, (max(t.pages) if t.pages else None)


def from_record(site_id: str, rec: dict) -> Notice | None:
    """A stored raw record back into a Notice: the join is always re-run over the raw layer."""
    try:
        reported = date.fromisoformat(rec["date_reported"])
    except (KeyError, TypeError, ValueError):
        return None
    terms = [x.strip() for x in (rec.get("information_compromised") or "").split(";")]
    return Notice(site_id, rec.get("organization") or "", reported, _mdy(rec.get("date_of_breach")),
                  _count(rec.get("wa_affected")), [x for x in terms if x and x.lower() not in DROP_TERMS],
                  rec.get("notice_url"), rec)


def dedupe_ids(notices: list[Notice]) -> list[Notice]:
    """One notice per id. A row the list shows twice, identically (5 of 1,883 on 2026-10-21),
    is one notice. Rows that share a notice PDF but differ each get an id suffixed with a hash of
    their content, so neither overwrites the other in the raw layer."""
    groups: dict[str, list[Notice]] = {}
    for n in notices:
        groups.setdefault(n.site_id, []).append(n)
    out, seen = [], set()
    for n in notices:
        if len({_rec_key(x) for x in groups[n.site_id]}) > 1:
            n.site_id += "#" + hashlib.sha1(_rec_key(n).encode()).hexdigest()[:10]
        if n.site_id in seen:
            continue
        seen.add(n.site_id)
        out.append(n)
    return out


def _rec_key(n: Notice) -> str:
    return "|".join(str(n.record.get(k)) for k in sorted(n.record))


# ---- the join ---------------------------------------------------------------------------------
JOINED, NO_MATCH, AMBIG_DATASET, AMBIG_SITE = "name_date", "no_match", "ambiguous_dataset", "ambiguous_site"


def join(notices: list[Notice], dataset: list[tuple[str, str, date | None]]) -> dict[str, tuple[str | None, str]]:
    """site_id -> (dataset id or None, outcome). `dataset` is (id, name, datesubmitted).

    A dataset key with two rows is ambiguous; a dataset row that two site rows (with different
    ids) would both join is ambiguous for both. Neither joins anything."""
    idx: dict[tuple[str, date], list[str]] = {}
    for rid, name, sub in dataset:
        nn = norm_name(name or "")
        if nn and sub:
            idx.setdefault((nn, sub), []).append(str(rid))
    first: dict[str, tuple[str | None, str]] = {}
    claimed: dict[str, list[str]] = {}
    for n in notices:
        nn = norm_name(n.organization)
        cands = sorted(set(idx.get((nn, n.date_reported), []))) if nn else []
        if not cands:
            first[n.site_id] = (None, NO_MATCH)
        elif len(cands) > 1:
            first[n.site_id] = (None, AMBIG_DATASET)
        else:
            first[n.site_id] = (cands[0], JOINED)
            claimed.setdefault(cands[0], []).append(n.site_id)
    for did, sids in claimed.items():
        if len(set(sids)) > 1:
            for s in sids:
                first[s] = (None, AMBIG_SITE)
    return first
