"""Parse OSM records, diff them against what is stored, judge window completeness."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import date, datetime

#: query-latest returns at most this many records and cannot page.
PAGE = 100

#: Excluded from the content hash. `updated_at`/`last_updated` move on every touch, and
#: `download_count` is null today but would churn daily if OSM ever fills it - either would
#: turn every poll into a "change". They are still stored on the current-state row.
VOLATILE = frozenset({"updated_at", "last_updated", "download_count"})


@dataclass(frozen=True)
class Threat:
    threat_id: str
    ecosystem: str
    record: dict
    content_hash: str
    last_updated: datetime | None
    verified_at: datetime | None


def ts(v) -> datetime | None:
    if not v or not isinstance(v, str):
        return None
    try:
        d = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else None   # a naive timestamp is ambiguous; refuse it


def content_hash(record: dict) -> str:
    stable = {k: v for k, v in record.items() if k not in VOLATILE}
    return hashlib.sha256(json.dumps(stable, sort_keys=True, default=str).encode()).hexdigest()


def parse_latest(body, ecosystem: str) -> tuple[list[Threat], int, str | None]:
    """(threats, malformed, error). Duplicate ids in one response: the last one wins."""
    if not isinstance(body, dict) or not isinstance(body.get("threats"), list):
        return [], 0, "response has no threats list"
    out: dict[str, Threat] = {}
    malformed = 0
    for r in body["threats"]:
        if not isinstance(r, dict):
            malformed += 1
            continue
        try:
            tid = str(uuid.UUID(str(r.get("id"))))
        except ValueError:
            malformed += 1
            continue
        lu = ts(r.get("last_updated")) or ts(r.get("updated_at"))
        if lu is None:
            # Without last_updated the record cannot be placed in the window, and the
            # completeness test would silently lose its anchor.
            malformed += 1
            continue
        out[tid] = Threat(tid, (r.get("registry") or ecosystem), r, content_hash(r),
                          lu, ts(r.get("verified_at")))
    return list(out.values()), malformed, None


def changed_fields(old: dict | None, new: dict) -> list[str]:
    if old is None:
        return []
    keys = (set(old) | set(new)) - VOLATILE
    return sorted(k for k in keys if old.get(k) != new.get(k))


def window_complete(record_count: int, oldest: datetime | None,
                    previous_newest: datetime | None) -> bool | None:
    """Did this poll reach back to everything updated since the previous poll?

    Under PAGE records the response is the ecosystem's entire verified set, so nothing
    can be missing. At PAGE, it is complete only if its oldest record is no newer than
    the previous poll's newest - otherwise more than PAGE updates landed in between and
    some were pushed out unseen. With no previous poll there is nothing to compare to.
    """
    if record_count < PAGE:
        return True
    if previous_newest is None or oldest is None:
        return None
    return oldest <= previous_newest


@dataclass(frozen=True)
class Downloads:
    outcome: str                  # ok | not_found | error
    weekly: int | None
    window_start: date | None
    window_end: date | None
    error: str | None = None


def parse_downloads(registry: str, status: int, body, error: str | None) -> Downloads:
    if status == 404:
        return Downloads("not_found", None, None, None, error)
    if status != 200 or not isinstance(body, dict):
        return Downloads("error", None, None, None, error or f"HTTP {status}")
    if registry == "npm":
        if "error" in body:
            # npm answers some unknown packages with 200 {"error": "package x not found"}
            msg = str(body["error"])[:200]
            return Downloads("not_found" if "not found" in msg.lower() else "error",
                             None, None, None, msg)
        n = body.get("downloads")
        if not isinstance(n, int) or isinstance(n, bool) or n < 0:
            return Downloads("error", None, None, None, "npm body has no download count")
        return Downloads("ok", n, _d(body.get("start")), _d(body.get("end")))
    if registry == "pypi":
        n = (body.get("data") or {}).get("last_week") if isinstance(body.get("data"), dict) else None
        if not isinstance(n, int) or isinstance(n, bool) or n < 0:
            return Downloads("error", None, None, None, "pypistats body has no last_week")
        # pypistats states no window; its last_week is the trailing 7 days to yesterday.
        return Downloads("ok", n, None, None)
    return Downloads("error", None, None, None, f"unsupported registry {registry}")


def parse_npm_bulk(status: int, body, error: str | None, names: list[str]) -> dict[str, Downloads]:
    """One Downloads per requested name. A name mapped to null is unknown to npm; a name
    absent from an otherwise good answer is an error, never a silent not-found."""
    if status != 200 or not isinstance(body, dict) or "error" in body:
        msg = error or (str(body.get("error"))[:200] if isinstance(body, dict) else f"HTTP {status}")
        return {n: Downloads("error", None, None, None, msg) for n in names}
    out = {}
    for n in names:
        if n not in body:
            out[n] = Downloads("error", None, None, None, "name missing from bulk answer")
        elif body[n] is None:
            out[n] = Downloads("not_found", None, None, None, "null in bulk answer")
        else:
            out[n] = parse_downloads("npm", 200, body[n], None)
    return out


def _d(v) -> date | None:
    try:
        return date.fromisoformat(v) if isinstance(v, str) else None
    except ValueError:
        return None
