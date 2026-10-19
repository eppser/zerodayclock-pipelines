"""Names and domains, normalised just enough to match and no further.

DOMAINS ARE KEPT WHOLE. Reducing to the registrable domain (eTLD+1) would map a subsidiary's
host onto its parent and merge two victims (advisor review, 2026-10-14). Only the scheme,
path, port, a leading "www." and case are removed.

NAMES LOSE LEGAL FORM AND PUNCTUATION ONLY. "Acme, Inc." and "ACME Inc" match; "Acme Health"
and "Acme" do not. A name is a weak key: it never merges two incidents on its own. A name with
Han or kana in it keeps those characters (0130); "アスクル株式会社" and "アスクル" match.
"""

from __future__ import annotations

import re
import unicodedata

_LEGAL_WORDS = (r"incorporated|inc|corp|corporation|co|company|llc|l\.l\.c|ltd|limited|plc|gmbh|ag|sa|"
                r"s\.a|sas|sarl|srl|spa|s\.p\.a|bv|b\.v|nv|n\.v|oy|ab|as|a/s|pty|pvt|kg|kgaa|se|lp|llp|pc|"
                r"pllc|the")
_LEGAL = re.compile(r"\b(" + _LEGAL_WORDS + r")\b\.?", re.I)
_NONWORD = re.compile(r"[^a-z0-9]+")

# ---- Japanese (and any Han / kana) names, 0130 ------------------------------------------------
# The ASCII path above drops every character it cannot spell in ASCII, so a Japanese-only name
# normalised to "" and every such organisation collided with every other. A name that contains
# Han or kana takes the path below instead; a name that contains none takes the path above,
# unchanged byte for byte (tested against a frozen copy).
#
# Han, hiragana, katakana (and the iteration marks 々〆〇) are kept. The katakana middle dot ・
# is NOT: "ソフトバンク・テクノロジー" and "ソフトバンクテクノロジー" are one name.
_CJK_CLASS = ("\u3005-\u3007\u3041-\u3096\u309d-\u309f\u30a1-\u30fa\u30fc-\u30ff\u31f0-\u31ff"
              "\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\U00020000-\U0002fa1f")
_CJK = re.compile("[" + _CJK_CLASS + "]")
_MARKS = re.compile("[\u0300-\u036f]")                    # Latin diacritics after NFKD
_NOT_KEPT = re.compile("[^\x00-\x7f" + _CJK_CLASS + "]")   # neither ASCII nor CJK: a space
# Legal forms. Like "Inc"/"Ltd"/"Corporation" above, these say what kind of legal person the
# organisation is, not which one: the company forms 株式会社 / 有限会社 / 合同会社 / 合資会社 /
# 合名会社 and their bracketed abbreviations ((株), ㈱ and （株） all become "(株)" under NFKC),
# and the corporation-type prefixes of non-profits, hospitals, schools and agencies. KEPT, as
# "Holdings" and "Group" are kept in English: ホールディングス, グループ, and any word for what
# the organisation is (病院 hospital, 大学 university, 協会 association, 銀行 bank).
_JA_LEGAL = re.compile(
    r"株式会社|有限会社|合同会社|合資会社|合名会社|\((?:株|有|合|資|名)\)|"
    r"一般社団法人|公益社団法人|一般財団法人|公益財団法人|社会福祉法人|社会医療法人|医療法人社団|"
    r"医療法人財団|医療法人|学校法人|特定非営利活動法人|npo法人|地方独立行政法人|独立行政法人|"
    r"国立研究開発法人|国立大学法人|公立大学法人|宗教法人")
# Same words as _LEGAL, but bounded by "not an ASCII letter or digit" rather than \b: \b treats a
# Han character as a word character, so "ABC Co株式会社" would keep its "co".
_LEGAL_CJK = re.compile(r"(?<![a-z0-9])(" + _LEGAL_WORDS + r")(?![a-z0-9])")
_NONWORD_CJK = re.compile("[^a-z0-9" + _CJK_CLASS + "]+")
_CJK_GAP = re.compile("(?<=[" + _CJK_CLASS + "]) +(?=[" + _CJK_CLASS + "])")
_ASCII_TO_CJK = re.compile("(?<=[a-z0-9])(?=[" + _CJK_CLASS + "])")
_CJK_TO_ASCII = re.compile("(?<=[" + _CJK_CLASS + "])(?=[a-z0-9])")


# A Japanese name ends where a Han or katakana character does not continue it: "日本航空" is not
# found in "日本航空電子工業" or "全日本航空", nor "アスクル" in "アスクルロジスト". Hiragana may follow or
# precede - that is a particle ("日本航空に", "とアスクル"), not more name.
_NAME_CHAR = "\u3005-\u3007\u30a1-\u30fa\u30fc-\u30ff\u31f0-\u31ff\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff"


def cjk_contains(haystack: str, needle: str) -> bool:
    """needle occurs in haystack (both already normalised) as a whole Japanese name."""
    if not needle:
        return False
    return bool(re.search("(?<![" + _NAME_CHAR + "])" + re.escape(needle) + "(?![" + _NAME_CHAR + "])", haystack))


def has_cjk(text: str | None) -> bool:
    return bool(_CJK.search(unicodedata.normalize("NFKC", text or "")))


def _norm_name_cjk(name: str) -> str:
    """NFKD and drop Latin diacritics, then NFKC (which recomposes kana voicing marks and turns
    full-width ASCII and half-width katakana into their ordinary forms); delete the middle dot ・;
    anything else that is neither ASCII nor CJK (「」、。 and the like) becomes a space; lower-case; strip Japanese and English legal forms; punctuation to spaces.
    Then one spelling for spacing: none between two CJK characters (Japanese is written without
    spaces, so "アサヒ グループ" and "アサヒグループ" are one name), one between CJK and Latin
    ("NTTデータ" and "NTT データ" both become "ntt データ").
    breach_core.norm_name_cjk() is the SQL twin, parity-tested; change both or neither."""
    s = unicodedata.normalize("NFKD", name)
    s = unicodedata.normalize("NFKC", _MARKS.sub("", s))
    s = _NOT_KEPT.sub(" ", s.replace("\u30fb", "")).lower().replace("&", " and ")
    s = _JA_LEGAL.sub(" ", s)
    s = _LEGAL_CJK.sub(" ", s)
    s = _NONWORD_CJK.sub(" ", s).strip()
    s = _CJK_GAP.sub("", s)
    s = _CJK_TO_ASCII.sub(" ", _ASCII_TO_CJK.sub(" ", s))
    return re.sub(" +", " ", s).strip()


def norm_name(name: str) -> str:
    if has_cjk(name):
        return _norm_name_cjk(name)
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
