"""The evidence gate: an extracted value is accepted only if the text proves it.

A language model reading a news article will, now and then, produce a number that is not in
the article: a rounded figure, a figure from a different breach it remembers, a conversion it
did silently. Each of those reads as a fact on the page. So nothing an extractor returns is
believed on its own word. Every value arrives with a verbatim quote, and the gate checks,
deterministically and without a model:

1. the quote occurs in the document (after whitespace and quote-mark normalisation only);
2. for a number, the number itself occurs in the quote, in any of the spellings an article
   uses ("4.2 million", "4,200,000", "4.2M");
3. for a CVE ID, the ID occurs in the quote;
4. the quote does not negate the value ("no evidence that data was stolen").

A value that fails is kept as a rejected claim with the reason, never published. This is the
same rule as the patch-date corpus's invariant I5, and for the same reason: a gate that runs
on every row is the only thing that makes an LLM extraction reproducible by a stranger.
"""

from __future__ import annotations

import re
import unicodedata
from decimal import Decimal, InvalidOperation

_WS = re.compile(r"\s+")
_QUOTES = str.maketrans({"‘": "'", "’": "'", "“": '"', "”": '"',
                         "–": "-", "—": "-", " ": " "})


def norm(text: str) -> str:
    """Whitespace, typographic quotes and dashes only. Case is kept: changing case would let
    a quote match text it does not literally appear in."""
    text = unicodedata.normalize("NFKC", text or "").translate(_QUOTES)
    return _WS.sub(" ", text).strip()


def quote_in_document(quote: str, document: str) -> bool:
    q = norm(quote)
    # A quote under 12 characters proves nothing: "10,000" occurs in many articles about
    # many things. The extractor is told to quote the sentence.
    return len(q) >= 12 and q in norm(document)


_SCALE = {"thousand": 10**3, "k": 10**3, "million": 10**6, "m": 10**6, "mn": 10**6,
          "billion": 10**9, "bn": 10**9, "b": 10**9, "trillion": 10**12}
_NUM = re.compile(
    r"(?<![\w.])(\d{1,3}(?:[,  ]\d{3})+|\d+(?:\.\d+)?)\s*"
    r"(thousand|million|billion|trillion|mn|bn|k|m|b)?(?![a-z])", re.I)


# Japanese counts (0130): 万 = 10^4, 億 = 10^8, 千 = 10^3, 千万 = 10^7, chained largest first,
# each part optionally carrying its own digits and commas - "126万", "1億2000万", "54万2513",
# "2,251万9,960", "5,310,000". Full-width digits are already ASCII after norm()'s NFKC. Only
# read in a sentence that contains Han or kana, so an English sentence yields exactly the
# numbers it always did ("4.2" is not a new number in "4.2 million").
_JA_PART = r"(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d+)?"
_JA_NUM = re.compile(r"(?<![0-9A-Za-z.,])" + _JA_PART + r"(?:\s*(?:千万|億|万|千)(?:" + _JA_PART + r")?)*")
_JA_TOKEN = re.compile(r"[0-9][0-9,]*(?:\.[0-9]+)?|千万|億|万|千")
_JA_SCALE = {"千万": 10**7, "億": 10**8, "万": 10**4, "千": 10**3}
_JA_BARE_THOUSAND = re.compile(r"(?<![0-9.,数何幾一二三四五六七八九十百])千(?=\s*(?:人|件|名))")
_CJK = re.compile("[\u3041-\u30ff\u3400-\u4dbf\u4e00-\u9fff]")


def _ja_value(span: str) -> Decimal | None:
    total, current = Decimal(0), None
    for tok in _JA_TOKEN.findall(span):
        if tok in _JA_SCALE:
            total += (current if current is not None else Decimal(1)) * _JA_SCALE[tok]
            current = None
        else:
            try:
                current = Decimal(tok.replace(",", ""))
            except InvalidOperation:
                return None
    return total + (current or 0)


def number_spans(text: str) -> list[tuple[Decimal, int, int]]:
    """(value, start, end) for every number in the NORMALISED text: the English spellings, plus
    the Japanese ones when the text has Han or kana in it."""
    t = norm(text)
    out = []
    for m in _NUM.finditer(t):
        raw, scale = m.group(1), (m.group(2) or "").lower()
        try:
            v = Decimal(re.sub(r"[,\u202f ]", "", raw))
        except InvalidOperation:
            continue
        out.append((v * _SCALE.get(scale, 1), m.start(), m.end()))
    if _CJK.search(t):
        for m in _JA_NUM.finditer(t):
            v = _ja_value(m.group(0))
            if v is not None:
                out.append((v, m.start(), m.end()))
        # "千人" / "千件" with no digit before it is one thousand - but not 数千 (several
        # thousand), 何千, or a kanji numeral (五千 = 5,000, which is not read here at all).
        for m in _JA_BARE_THOUSAND.finditer(t):
            out.append((Decimal(1000), m.start(), m.end()))
    return out


def numbers_in(text: str) -> set[Decimal]:
    """Every number a sentence states, scaled: '4.2 million' and '4,200,000' both -> 4200000;
    '約126万件' -> 1260000. Plain years are included too; the caller decides which number it
    is looking for."""
    return {v for v, _, _ in number_spans(text)}


# The qualifier a Japanese sentence states for a number, read from the text rather than taken
# from the model: 約/およそ/概ね/程度/前後 -> approx, 最大/上限/最多 -> at_most,
# 以上/超/余り/少なくとも -> at_least, nothing -> exact.
_JA_APPROX_BEFORE = re.compile(r"(?:約|およそ|概ね|おおよそ)\s*$")
_JA_AT_MOST_BEFORE = re.compile(r"(?:最大|上限|最多)\s*(?:で|約)?\s*$")
_JA_AT_LEAST_BEFORE = re.compile(r"(?:少なくとも|最低)\s*(?:でも|約)?\s*$")
_JA_AT_LEAST_AFTER = re.compile(r"^\s*\S{0,4}?(?:以上|超|余り|あまり|を超え)")
_JA_APPROX_AFTER = re.compile(r"^\s*\S{0,4}?(?:程度|前後|ほど)")


def ja_qualifier(quote: str, value) -> str | None:
    """None when the quote is not Japanese or does not state the value."""
    t = norm(quote)
    if not _CJK.search(t):
        return None
    try:
        want = Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None
    for v, a, b in number_spans(t):
        if v != want:
            continue
        before, after = t[max(0, a - 8):a], t[b:b + 8]
        if _JA_AT_MOST_BEFORE.search(before):
            return "at_most"
        if _JA_AT_LEAST_BEFORE.search(before) or _JA_AT_LEAST_AFTER.search(after):
            return "at_least"
        if _JA_APPROX_BEFORE.search(before) or _JA_APPROX_AFTER.search(after):
            return "approx"
        return "exact"
    return None


_BYTES = {"b": 1, "kb": 10**3, "mb": 10**6, "gb": 10**9, "tb": 10**12, "pb": 10**15,
          "kib": 2**10, "mib": 2**20, "gib": 2**30, "tib": 2**40}
_SIZE = re.compile(r"(\d+(?:[.,]\d+)?)\s*(pb|tb|gb|mb|kb|tib|gib|mib|kib|terabytes?|gigabytes?|"
                   r"megabytes?|petabytes?)\b", re.I)
_SIZE_WORDS = {"terabyte": "tb", "terabytes": "tb", "gigabyte": "gb", "gigabytes": "gb",
               "megabyte": "mb", "megabytes": "mb", "petabyte": "pb", "petabytes": "pb"}


# Japanese spells units in katakana, and writes "1.5TB分" with no break before the Han character,
# where \b does not fire. Read only in a sentence with Han or kana in it.
_SIZE_JA = re.compile(r"(\d+(?:[.,]\d+)?)\s*(pb|tb|gb|mb|kb|tib|gib|mib|kib|ペタバイト|テラバイト|ギガバイト|"
                      r"メガバイト)(?![a-z])", re.I)
_SIZE_WORDS_JA = {"ペタバイト": "pb", "テラバイト": "tb", "ギガバイト": "gb", "メガバイト": "mb"}


def sizes_in(text: str) -> set[int]:
    out = set()
    t = norm(text)
    if _CJK.search(t):
        for m in _SIZE_JA.finditer(t):
            unit = _SIZE_WORDS_JA.get(m.group(2), m.group(2).lower())
            try:
                out.add(int(Decimal(m.group(1).replace(",", ".")) * _BYTES[unit]))
            except (InvalidOperation, KeyError):
                continue
    for m in _SIZE.finditer(norm(text)):
        unit = m.group(2).lower()
        unit = _SIZE_WORDS.get(unit, unit)
        try:
            out.add(int(Decimal(m.group(1).replace(",", ".")) * _BYTES[unit]))
        except (InvalidOperation, KeyError):
            continue
    return out


_NEGATION = re.compile(
    r"\b(no evidence|not believe|no indication|did not|didn't|has not been|have not been|"
    r"was not|were not|denied|denies|unconfirmed|could not confirm|cannot confirm|"
    r"not been able to (?:confirm|verify)|refused to (?:confirm|comment))\b", re.I)


# Japanese negation (0130). \b means nothing between two Han characters, so these are bare
# patterns: the negative verb endings in their common forms, and 否定 (denied). "ない" on its own
# counts only before a clause or sentence end or a quoting particle, and never in 少ない (few),
# 間もない (soon after) or 危ない (dangerous), which negate nothing.
_NEGATION_JA = re.compile(
    r"ありません|ございません|ませんでした|されていません|されていない|されておらず|されなかった|"
    r"確認できていない|確認できない|確認しておらず|なかった|おらず|おりません|ていません|れず(?![みん])|無い|無かった|"
    r"(?<!少)(?<!間も)(?<!危)ない(?=[。、,.!！」』)）]|と|こと|もの|よう|$)|否定")


def negated(quote: str) -> bool:
    """Sentence-level and conservative: a quote that negates anything is not evidence for a
    positive value. Over-rejecting costs a fact; under-rejecting publishes "data stolen" on
    a sentence that said it was not (v1 hazard 6)."""
    q = norm(quote)
    return bool(_NEGATION.search(q) or _NEGATION_JA.search(q))


CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)


# Japanese clauses end at 、 and 。 (and ；：), and at ものの / しかし (although / but).
_CLAUSE = re.compile(r"[,;:]|\b(?:which|but|although|while|whereas)\b|[、。；：]|ものの|しかし", re.I)


def _clause_with(quote: str, needle_pos: int) -> str:
    """The clause of the quote around a position: negation has to sit in the same clause as the
    value. "demanded a $5 million ransom, which Acme did not pay" negates the payment, not the
    demand; "no evidence that 2 million records were taken" negates the count."""
    q = norm(quote)
    cuts = [0] + [m.end() for m in _CLAUSE.finditer(q)] + [len(q)]
    for a, b in zip(cuts, cuts[1:]):
        if a <= needle_pos < b:
            return q[a:b]
    return q


def _negated_near_value(field: str, value, quote: str) -> bool:
    if field not in NUMERIC_FIELDS:
        return negated(quote)
    q = norm(quote)
    for v, start, _ in number_spans(q):
        if field == "data_bytes" or v == Decimal(str(value)):
            return negated(_clause_with(q, start))
    return negated(q)


def check(field: str, value, quote: str, document: str) -> str | None:
    """None if the value is proven by the quote, else the reason it is rejected."""
    if not quote or not isinstance(quote, str):
        return "no_quote"
    if not quote_in_document(quote, document):
        return "quote_not_in_document"
    if field in NUMERIC_FIELDS:
        try:
            v = Decimal(str(value))
        except (InvalidOperation, ValueError):
            return "not_a_number"
        if v <= 0:
            return "non_positive"
        if field == "data_bytes":
            if int(v) not in sizes_in(quote):
                return "size_not_in_quote"
        elif v not in numbers_in(quote):
            return "number_not_in_quote"
    if field == "cve_id":
        if not isinstance(value, str) or value.upper() not in {c.upper() for c in CVE.findall(quote)}:
            return "cve_not_in_quote"
    if field in NEGATABLE_FIELDS and _negated_near_value(field, value, quote):
        return "negated"
    return None


NUMERIC_FIELDS = {"people_affected", "records_affected", "data_bytes", "ransom_demand_amount",
                  "ransom_paid_amount"}
NEGATABLE_FIELDS = NUMERIC_FIELDS | {"data_exfiltrated", "ransom_paid", "vector", "cve_id",
                                     "data_types", "actor"}
