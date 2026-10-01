"""Parsing for Shadowserver's honeypot/exploited-vulnerabilities response.

The endpoint returns JSON Lines, one object per vulnerability per requested day. The
field types are NOT uniform and that is the whole reason this module exists:

  * ``1d`` arrives as a STRING ("486") while ``7d_avg``/``30d_avg``/``90d_avg`` arrive
    as integers. Coercing blindly with int() works; assuming a type does not.
  * ``vulnerability_score``, ``vulnerability_severity`` and ``vulnerability_class`` are
    null on rows Shadowserver has not scored (36 of 677 on 2026-08-30).
  * ``euvd`` is absent on a minority of rows (9 of 677).
  * ``iot`` and ``cisa_kev`` are the strings "yes"/"no", not booleans.
  * ``vulnerability`` is not always a CVE: EDB-*, CNVD-* and GCVE-* appear, and those are
    exactly the identifiers no KEV catalogue can ever list, so they must survive.
  * The SAME CVE appears more than once in a day, against different products — a day
    returns 677 rows for 674 vulnerabilities. So the natural key is (vulnerability,
    product, day), and ``product_key`` normalises the null product into ''. Keying on the
    CVE alone silently discards one of the rows.

Every one of those is measured against the live API, not assumed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
_ID_PREFIX = (("CVE-", "cve"), ("EDB-", "edb"), ("CNVD-", "cnvd"), ("GCVE-", "gcve"))


class HoneypotParseError(ValueError):
    """A row that cannot be parsed. Never silently dropped — the caller counts these."""


def id_type(vuln_id: str) -> str:
    up = vuln_id.upper()
    for prefix, kind in _ID_PREFIX:
        if up.startswith(prefix):
            return kind
    return "other"


def _int(value, field: str) -> int | None:
    """Coerce a count. Accepts int or numeric string; rejects anything else loudly."""
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise HoneypotParseError(f"{field}: bool is not a count")
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise HoneypotParseError(f"{field}: {value!r} is not a count") from exc


def _yesno(value) -> bool | None:
    if value is None or value == "":
        return None
    v = str(value).strip().lower()
    if v in ("yes", "true", "1"):
        return True
    if v in ("no", "false", "0"):
        return False
    return None


def _score(value) -> float | None:
    if value is None or value == "":
        return None
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    # CVSS is 0.0-10.0. A value outside that is a contract change, not a score.
    return f if 0.0 <= f <= 10.0 else None


def _first_seen(value) -> datetime | None:
    if not value:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(str(value).strip(), fmt)
        except ValueError:
            continue
    return None


@dataclass(frozen=True, slots=True)
class HoneypotRow:
    """One vulnerability on one day. Splits into the two tables 0028 defines."""

    # --- identity ---------------------------------------------------------
    vuln_id: str
    product_key: str          # coalesce(product, "") — part of the natural key
    vuln_id_type: str
    cve_id: str | None
    observed_on: date
    # --- day-varying: the observation itself ------------------------------
    connections: int
    avg_1d: int | None
    avg_7d: int | None
    avg_30d: int | None
    avg_90d: int | None
    cisa_kev: bool | None
    # --- static per (vulnerability, product) ------------------------------
    vendor: str | None
    product: str | None
    device_class: str | None
    scan_type: str | None
    severity: str | None
    cvss_score: float | None
    scoring_class: str | None
    is_iot: bool | None
    euvd_id: str | None
    sensor_first_seen: datetime | None


def _clean(value) -> str | None:
    if value is None:
        return None
    s = str(value).strip()
    return s or None


def parse_row(obj: dict, observed_on: date) -> HoneypotRow:
    vuln_id = _clean(obj.get("vulnerability"))
    if not vuln_id:
        raise HoneypotParseError("row has no vulnerability identifier")
    kind = id_type(vuln_id)
    # Only a well-formed CVE id populates cve_id; the CHECK constraint in 0028 enforces
    # the same rule at the table, so a malformed 'CVE-...' must not be typed as a cve.
    if kind == "cve" and not CVE_RE.match(vuln_id):
        kind = "other"
    connections = _int(obj.get("connections"), "connections")
    if connections is None:
        raise HoneypotParseError(f"{vuln_id}: connections is required")
    product = _clean(obj.get("product"))
    return HoneypotRow(
        vuln_id=vuln_id,
        product_key=product or "",
        vuln_id_type=kind,
        cve_id=vuln_id.upper() if kind == "cve" else None,
        observed_on=observed_on,
        connections=connections,
        avg_1d=_int(obj.get("1d"), "1d"),
        avg_7d=_int(obj.get("7d_avg"), "7d_avg"),
        avg_30d=_int(obj.get("30d_avg"), "30d_avg"),
        avg_90d=_int(obj.get("90d_avg"), "90d_avg"),
        cisa_kev=_yesno(obj.get("cisa_kev")),
        vendor=_clean(obj.get("vendor")),
        product=product,
        device_class=_clean(obj.get("class")),
        scan_type=_clean(obj.get("type")),
        severity=_clean(obj.get("vulnerability_severity")),
        cvss_score=_score(obj.get("vulnerability_score")),
        scoring_class=_clean(obj.get("vulnerability_class")),
        is_iot=_yesno(obj.get("iot")),
        euvd_id=_clean(obj.get("euvd")),
        sensor_first_seen=_first_seen(obj.get("first_seen")),
    )


def parse_response(body: str, observed_on: date) -> tuple[list[HoneypotRow], list[str]]:
    """Parse JSON Lines. Returns (rows, errors) — malformed rows are REPORTED, not dropped.

    A harvester that silently discards what it cannot parse reports a smaller world
    instead of a broken parser, which is the v1 failure this project exists to avoid.
    """
    rows: list[HoneypotRow] = []
    errors: list[str] = []
    for n, line in enumerate(body.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(parse_row(__import__("json").loads(line), observed_on))
        except Exception as exc:  # noqa: BLE001 - recorded, not swallowed
            errors.append(f"line {n}: {exc}")
    return rows, errors
