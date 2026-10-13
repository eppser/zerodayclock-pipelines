"""Names and domains, normalised just enough to match and no further.

DOMAINS ARE KEPT WHOLE. Reducing to the registrable domain (eTLD+1) would map a subsidiary's
host onto its parent and merge two victims (advisor review, 2026-10-14). Only the scheme,
path, port, a leading "www." and case are removed.

NAMES LOSE LEGAL FORM AND PUNCTUATION ONLY. "Acme, Inc." and "ACME Inc" match; "Acme Health"
and "Acme" do not. A name is a weak key: it never merges two incidents on its own.
"""

from __future__ import annotations

import re
import unicodedata

_LEGAL = re.compile(
    r"\b(incorporated|inc|corp|corporation|co|company|llc|l\.l\.c|ltd|limited|plc|gmbh|ag|sa|"
    r"s\.a|sas|sarl|srl|spa|s\.p\.a|bv|b\.v|nv|n\.v|oy|ab|as|a/s|pty|pvt|kg|kgaa|se|lp|llp|pc|"
    r"pllc|the)\b\.?", re.I)
_NONWORD = re.compile(r"[^a-z0-9]+")


def norm_name(name: str) -> str:
    s = unicodedata.normalize("NFKD", name or "").encode("ascii", "ignore").decode().lower()
    s = s.replace("&", " and ")
    s = _LEGAL.sub(" ", s)
    return _NONWORD.sub(" ", s).strip()


_HOST = re.compile(r"^(?:[a-z][a-z0-9+.-]*://)?(?:[^@/]*@)?([^/:?#\s]+)", re.I)
_DOMAIN_OK = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$")


def norm_domain(value: str | None) -> str | None:
    if not value:
        return None
    m = _HOST.match(value.strip().lower())
    if not m:
        return None
    host = m.group(1).rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    host = host.encode("idna").decode() if not host.isascii() else host
    return host if _DOMAIN_OK.match(host) else None


def domain_from_title(title: str) -> str | None:
    """Leak posts are often titled with the victim's domain ("acme.com"). Only a title that is
    nothing but a domain counts; "Acme.com Ltd" or a sentence does not."""
    t = (title or "").strip().lower()
    return norm_domain(t) if _DOMAIN_OK.match(t.removeprefix("www.")) else None


COUNTRY_ALIASES = {
    "usa": "US", "united states": "US", "united states of america": "US", "us": "US",
    "uk": "GB", "united kingdom": "GB", "great britain": "GB", "england": "GB",
    "germany": "DE", "france": "FR", "italy": "IT", "spain": "ES", "canada": "CA",
    "australia": "AU", "brazil": "BR", "india": "IN", "japan": "JP", "mexico": "MX",
    "netherlands": "NL", "switzerland": "CH", "austria": "AT", "belgium": "BE",
    "sweden": "SE", "norway": "NO", "denmark": "DK", "finland": "FI", "poland": "PL",
    "portugal": "PT", "ireland": "IE", "israel": "IL", "turkey": "TR", "turkiye": "TR",
    "south africa": "ZA", "argentina": "AR", "chile": "CL", "colombia": "CO", "peru": "PE",
    "china": "CN", "taiwan": "TW", "south korea": "KR", "korea": "KR", "singapore": "SG",
    "thailand": "TH", "vietnam": "VN", "viet nam": "VN", "indonesia": "ID", "malaysia": "MY",
    "philippines": "PH", "new zealand": "NZ", "saudi arabia": "SA", "united arab emirates": "AE",
    "uae": "AE", "egypt": "EG", "nigeria": "NG", "kenya": "KE", "czech republic": "CZ",
    "czechia": "CZ", "romania": "RO", "greece": "GR", "hungary": "HU", "ukraine": "UA",
    "russia": "RU", "pakistan": "PK", "bangladesh": "BD", "hong kong": "HK",
}


def norm_country(value: str | None) -> str | None:
    if not value:
        return None
    v = value.strip()
    if re.fullmatch(r"[A-Za-z]{2}", v):
        return v.upper()
    return COUNTRY_ALIASES.get(v.lower())
