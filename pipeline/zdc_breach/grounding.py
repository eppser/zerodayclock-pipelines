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


def numbers_in(text: str) -> set[Decimal]:
    """Every number a sentence states, scaled: '4.2 million' and '4,200,000' both -> 4200000.
    Plain years are included too; the caller decides which number it is looking for."""
    out: set[Decimal] = set()
    for m in _NUM.finditer(norm(text)):
        raw, scale = m.group(1), (m.group(2) or "").lower()
        try:
            v = Decimal(re.sub(r"[,  ]", "", raw))
        except InvalidOperation:
            continue
        out.add(v * _SCALE.get(scale, 1))
    return out


_BYTES = {"b": 1, "kb": 10**3, "mb": 10**6, "gb": 10**9, "tb": 10**12, "pb": 10**15,
          "kib": 2**10, "mib": 2**20, "gib": 2**30, "tib": 2**40}
_SIZE = re.compile(r"(\d+(?:[.,]\d+)?)\s*(pb|tb|gb|mb|kb|tib|gib|mib|kib|terabytes?|gigabytes?|"
                   r"megabytes?|petabytes?)\b", re.I)
_SIZE_WORDS = {"terabyte": "tb", "terabytes": "tb", "gigabyte": "gb", "gigabytes": "gb",
               "megabyte": "mb", "megabytes": "mb", "petabyte": "pb", "petabytes": "pb"}


def sizes_in(text: str) -> set[int]:
    out = set()
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


def negated(quote: str) -> bool:
    """Sentence-level and conservative: a quote that negates anything is not evidence for a
    positive value. Over-rejecting costs a fact; under-rejecting publishes "data stolen" on
    a sentence that said it was not (v1 hazard 6)."""
    return bool(_NEGATION.search(norm(quote)))


CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)


_CLAUSE = re.compile(r"[,;:]|\b(?:which|but|although|while|whereas)\b", re.I)


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
    for m in _NUM.finditer(q):
        raw, scale = m.group(1), (m.group(2) or "").lower()
        try:
            v = Decimal(re.sub(r"[,\u202f ]", "", raw)) * _SCALE.get(scale, 1)
        except InvalidOperation:
            continue
        if field == "data_bytes" or v == Decimal(str(value)):
            return negated(_clause_with(q, m.start()))
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
