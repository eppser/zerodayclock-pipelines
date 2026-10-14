"""Regulator disclosures and breach indexes: the sources that may name a victim.

Each parser turns one upstream row into a Disclosure: who, when, and the structured facts the
row states, each with the unit and qualifier the regulator used. No model touches these rows.

WHAT EACH COUNT MEANS (they are not the same quantity, and are never summed together):
- HHS OCR "Individuals Affected": persons, all US, filed by HIPAA entities; >= 500 by rule, and
  500/501 is a common placeholder filed before the count is known -> qualifier 'placeholder'.
- Washington AG "washingtoniansaffected": persons IN WASHINGTON only, >= 500 by rule. Stored
  as a claim with field people_affected but qualifier 'at_least': it is a floor on the total.
- Delaware "total_affected": persons, all jurisdictions, as the notice states.
- California AG: no count at all; a 'who and when' trigger only.
- HIBP PwnCount: ACCOUNTS (unique email addresses), never persons.
- SEC 8-K Item 1.05: no structured count; the filing text goes to the extractor.
"""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass, field
from datetime import date, datetime

from .normalize import norm_domain


@dataclass
class Fact:
    field: str
    value_num: float | None = None
    value_text: str | None = None
    unit: str = "none"
    qualifier: str = "not_applicable"


@dataclass
class Disclosure:
    source_id: str
    source_record_id: str
    organization: str
    as_of: date                        # the date this source published the fact
    basis: str                         # regulator_filing | breach_index
    event_date: date | None = None
    domain: str | None = None
    state: str | None = None
    sector: str | None = None
    sec_cik: str | None = None
    url: str | None = None
    facts: list[Fact] = field(default_factory=list)
    record: dict = field(default_factory=dict)


def _d(v) -> date | None:
    """A date as the filer wrote it, or None. Dates before 1990 are placeholders, not facts:
    Delaware carries 19 notices dated 1971-01-01 (advisor review 2)."""
    d = _parse_d(v)
    return d if d is None or d.year >= 1990 else None


def _parse_d(v) -> date | None:
    if not v:
        return None
    v = str(v).strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%m/%d/%Y"):
        try:
            return datetime.strptime(v[:26], fmt).date()
        except ValueError:
            continue
    m = re.match(r"(\d{4}-\d{2}-\d{2})", v)
    return date.fromisoformat(m.group(1)) if m else None


def _int(v) -> int | None:
    try:
        n = int(str(v).replace(",", "").strip())
    except (TypeError, ValueError):
        return None
    return n if n > 0 else None


# ---- Washington AG -----------------------------------------------------------------------------
WA_URL = ("https://data.wa.gov/resource/sb4j-ca4h.json?$order=datesubmitted%20DESC,id%20DESC"
          "&$limit=1000")

# WA's own taxonomy mapped onto ours; the original value is kept in the claim's value_text.
# Ransomware is what was done, not how they got in, so it is not a vector.
WA_VECTOR = {"ransomware": None, "malware": "malware", "phishing": "phishing",
             "skimmers": "malware", "other": None, "unclear/unknown": "unknown"}
WA_CAUSE = {"theft or mistake": "physical_loss", "unauthorized access": None, "cyberattack": None}


def parse_wa(rows: list) -> tuple[list[Disclosure], int]:
    out, bad = [], 0
    for r in rows if isinstance(rows, list) else []:
        name, rid, submitted = (r.get("name") or "").strip(), r.get("id"), _d(r.get("datesubmitted"))
        if not name or not rid or not submitted:
            bad += 1
            continue
        d = Disclosure("wa_ag", str(rid), name, submitted, "regulator_filing",
                       event_date=_d(r.get("datestart")), state=r.get("entitystate"),
                       sector=r.get("businesstype") or r.get("industrytype"),
                       url="https://www.atg.wa.gov/data-breach-notifications", record=r)
        n = _int(r.get("washingtoniansaffected"))
        if n:
            d.facts.append(Fact("people_affected", n, None, "persons", "at_least"))
        cause = (r.get("databreachcause") or "").strip()
        kind = (r.get("cyberattacktype") or "").strip()
        vec = WA_VECTOR.get(kind.lower()) if kind else WA_CAUSE.get(cause.lower())
        if vec:
            d.facts.append(Fact("vector", None, vec, "none", "not_applicable"))
        if kind.lower() == "ransomware":
            d.facts.append(Fact("ransomware_family", None, "unspecified"))
        out.append(d)
    return out, bad


# ---- Delaware AG -------------------------------------------------------------------------------
DE_URL = "https://data.delaware.gov/resource/dir6-wx8v.json?$order=date_of_notice%20DESC&$limit=1000"


def parse_de(rows: list) -> tuple[list[Disclosure], int]:
    out, bad = [], 0
    for r in rows if isinstance(rows, list) else []:
        name, notice = (r.get("company_name") or "").strip(), _d(r.get("date_of_notice"))
        if not name or not notice:
            bad += 1
            continue
        pdf = (r.get("sample_of_notice") or {}).get("url") if isinstance(r.get("sample_of_notice"), dict) else None
        rid = f"{name}|{r.get('date_of_notice')}|{r.get('date_of_breach')}"
        d = Disclosure("de_ag", rid, name, notice, "regulator_filing",
                       event_date=_d(r.get("date_of_breach")), url=pdf, record=r)
        n = _int(r.get("total_affected"))
        if n:
            d.facts.append(Fact("people_affected", n, None, "persons", "exact"))
        if r.get("information_breached"):
            d.facts.append(Fact("data_types", None, str(r["information_breached"])[:500]))
        out.append(d)
    return out, bad


# ---- California AG -----------------------------------------------------------------------------
CA_URL = "https://oag.ca.gov/privacy/databreach/list-export"


def parse_ca(body: str) -> tuple[list[Disclosure], int]:
    out, bad = [], 0
    for r in csv.DictReader(io.StringIO(body.lstrip("﻿"))):
        name = (r.get("Organization Name") or "").strip()
        reported = _d(r.get("Reported Date"))
        if not name or not reported:
            bad += 1
            continue
        breach = (r.get("Date(s) of Breach  (if known)") or r.get("Date(s) of Breach (if known)") or "").strip()
        first = _d(breach.split(",")[0]) if breach else None
        out.append(Disclosure("ca_ag", f"{name}|{reported.isoformat()}|{breach}", name, reported,
                              "regulator_filing", event_date=first,
                              url="https://oag.ca.gov/privacy/databreach/list", record=dict(r)))
    return out, bad


# ---- HHS OCR -----------------------------------------------------------------------------------
HHS_FRONT = "https://ocrportal.hhs.gov/ocr/breach/breach_frontpage.jsf"
HHS_REPORT = "https://ocrportal.hhs.gov/ocr/breach/breach_report_hip.jsf"
HHS_TYPE_VECTOR = {"theft": "physical_loss", "loss": "physical_loss", "improper disposal": "physical_loss"}


def parse_hhs(body: str) -> tuple[list[Disclosure], int]:
    out, bad = [], 0
    rows = list(csv.reader(io.StringIO(body.lstrip("﻿"))))
    if not rows:
        return out, 0
    for r in rows[1:]:
        if len(r) < 7:
            bad += 1
            continue
        name, state, etype, n, submitted, btype, loc = (x.strip() for x in r[:7])
        when = _d(submitted)
        if not name or not when:
            bad += 1
            continue
        rec = {"name": name, "state": state, "entity_type": etype, "individuals_affected": n,
               "submitted": submitted, "type_of_breach": btype, "location": loc,
               "business_associate_present": r[7].strip() if len(r) > 7 else None}
        d = Disclosure("hhs_ocr", f"{name}|{state}|{submitted}", name, when, "regulator_filing",
                       state=state, sector=f"Health: {etype}" if etype else "Health",
                       url="https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf", record=rec)
        cnt = _int(n)
        if cnt:
            # 500/501 is filed when the true count is not yet known (HHS's own threshold).
            d.facts.append(Fact("people_affected", cnt, None, "persons",
                                "placeholder" if cnt in (500, 501) else "exact"))
        # "Hacking/IT Incident" is not a vector (advisor); only physical types map.
        for k, v in HHS_TYPE_VECTOR.items():
            if btype.lower().startswith(k):
                d.facts.append(Fact("vector", None, v))
                break
        out.append(d)
    return out, bad


_VIEWSTATE = re.compile(r'name="javax\.faces\.ViewState"[^>]*value="([^"]+)"')


def viewstate(html_text: str) -> str | None:
    m = _VIEWSTATE.search(html_text)
    return m.group(1) if m else None


def jsf_button(html_text: str, label: str) -> str | None:
    """The generated id (ocrForm:j_idtNNN) of the command link whose content matches `label`
    (link text, or an image file name such as 'csv'). JSF renders it as
    onclick="mojarra.jsfcljs(...,{'ocrForm:j_idt39':'ocrForm:j_idt39'},'')...">View ...</a>.
    Ids change between deployments, so they are found, never hard-coded."""
    m = re.search(r"'(ocrForm:j_idt\d+)'[^>]*>\s*(?:<img[^>]*" + label + r"|" + label + r")",
                  html_text, re.I)
    return m.group(1) if m else None


# ---- HIBP --------------------------------------------------------------------------------------
HIBP_URL = "https://haveibeenpwned.com/api/v3/breaches"


def parse_hibp(rows: list) -> tuple[list[Disclosure], int]:
    out, bad = [], 0
    for r in rows if isinstance(rows, list) else []:
        name, added = (r.get("Title") or r.get("Name") or "").strip(), _d(r.get("AddedDate"))
        if not name or not added or r.get("IsFabricated") or r.get("IsSpamList"):
            bad += 0 if (name and added) else 1
            continue
        d = Disclosure("hibp", str(r.get("Name")), name, added, "breach_index",
                       event_date=_d(r.get("BreachDate")), domain=norm_domain(r.get("Domain")),
                       url=f"https://haveibeenpwned.com/Breach/{r.get('Name')}", record=r)
        if _int(r.get("PwnCount")):
            d.facts.append(Fact("accounts_affected", _int(r["PwnCount"]), None, "accounts", "exact"))
        if r.get("DataClasses"):
            d.facts.append(Fact("data_types", None, ", ".join(r["DataClasses"])[:500]))
        out.append(d)
    return out, bad


# ---- SEC EDGAR 8-K Item 1.05 -------------------------------------------------------------------
def efts_url(start: date, end: date, offset: int = 0, form: str = "8-K") -> str:
    return ("https://efts.sec.gov/LATEST/search-index?q=%22Item%201.05%22"
            f"&forms={form}&dateRange=custom&startdt={start.isoformat()}&enddt={end.isoformat()}"
            + (f"&from={offset}" if offset else ""))


_CIK_NAME = re.compile(r"^(.*?)\s*(?:\([A-Z0-9.\- ,]+\))?\s*\(CIK (\d+)\)\s*$")


def parse_efts(payload: dict) -> tuple[list[Disclosure], int]:
    out, bad = [], 0
    for h in (payload.get("hits") or {}).get("hits") or []:
        s = h.get("_source") or {}
        # The phrase search also finds filings that merely mention Item 1.05; only filings
        # that report the item count (efts `items=1.05` is not a filter: measured 0 hits).
        if "1.05" not in (s.get("items") or []):
            continue
        names = s.get("display_names") or []
        m = _CIK_NAME.match(names[0]) if names else None
        filed = _d(s.get("file_date"))
        if not m or not filed or not s.get("adsh"):
            bad += 1
            continue
        name, cik = m.group(1).strip(), str(int(m.group(2)))
        doc = (h.get("_id") or "").split(":", 1)[-1]
        url = (f"https://www.sec.gov/Archives/edgar/data/{cik}/{s['adsh'].replace('-', '')}/{doc}"
               if doc else None)
        out.append(Disclosure("sec_8k", s["adsh"], name, filed, "regulator_filing",
                              event_date=_d(s.get("period_ending")), sec_cik=cik,
                              state=(s.get("biz_states") or [None])[0], url=url,
                              record={k: s.get(k) for k in ("ciks", "display_names", "file_date",
                                      "period_ending", "form", "adsh", "items", "biz_states", "sics")}
                              | {"doc": doc}))
    return out, bad
