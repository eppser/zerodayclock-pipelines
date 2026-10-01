"""CVE Project (cvelistV5) — the authoritative CNA record.

Efficiency is the whole design here. The corpus is ~384k CVE records and the project
republishes a **562 MB baseline bundle every midnight**. Downloading that daily would
cost ~200 GB/year to learn about a few thousand changes.

Instead, GitHub releases also carry deltas:

    cve_2026-08-27_at_end_of_day  ->  2026-08-27_delta_CVEs_at_end_of_day.zip   ~4.5 MB
    cve_2026-08-28_0100Z          ->  2026-08-28_delta_CVEs_at_0100Z.zip        <1 MB
    cve_2026-08-28_0400Z          ->  2026-08-28_delta_CVEs_at_0400Z.zip        <1 MB

Measured 2026-08-27: the end-of-day delta held **2,439 changed CVE records** (2,275
PUBLISHED, 164 REJECTED) in 4.5 MB. So a daily run consumes deltas only — roughly
0.001% of the baseline's bytes for the same information.

Resumption is by **release tag**, not by clock. The adapter walks releases newest-first
until it reaches the tag it last consumed, then processes what it found oldest-first.
A missed day is picked up automatically on the next run; there is no window to get
wrong and no way to silently skip a release.

``--mode full`` fetches the 562 MB baseline for a complete reconciliation. That is a
deliberate, occasional operation, not something the schedule does.

Records are CVE JSON 5.1: ``cveMetadata`` (state, assigner, the three dates) plus
``containers.cna`` (title, descriptions, affected, metrics, problemTypes, references).
``containers.adp`` also exists — CISA's enrichment — and is deliberately ignored here so
that this source stays purely the CNA's own assertion.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import tempfile
import zipfile
from datetime import date

from ..models import CveCollectResult, CveRecord, NormalisationError, clamp, parse_timestamp
from .base import CveSource, CveSourceState, register

RELEASES_URL = "https://api.github.com/repos/CVEProject/cvelistV5/releases"
#: Measured 2026-08-28: releases land every 1-3 hours, so one page of 40 spans only
#: about THREE DAYS — not a week. Walking further back is what makes a missed run
#: recoverable, so the adapter paginates.
RELEASE_PAGE = 100
#: 5 pages x 100 = ~500 releases, roughly five weeks of history. Beyond that the
#: baseline is cheaper and certainly correct.
MAX_RELEASE_PAGES = 5
#: Sanity bound on a single incremental replay. Hitting it escalates to the baseline
#: rather than failing: catching up is the pipeline's job, not the operator's.
MAX_DELTAS = 200


@register
class CveProject(CveSource):
    source_id = "cve_project"
    rate_per_minute = 30

    def headers(self) -> dict[str, str]:
        return {"Accept": "application/vnd.github+json"}

    def collect(self, client, state: CveSourceState, mode: str,
                *, today: date | None = None) -> CveCollectResult:
        result = CveCollectResult(source_id=self.source_id)

        if mode == "full":
            releases, err = self._fetch_releases(client, result, pages=1)
            if err:
                result.error = err
                return result
            return self._collect_baseline(client, result, releases)

        # A delta walk needs somewhere to walk back to. With no cursor there is no
        # anchor, and consuming "whatever is on page one" would quietly yield a
        # three-day corpus that looks complete.
        if not state.cursor:
            result.covered.append("no cursor: falling back to the baseline")
            log_reason = "no cursor recorded"
            releases, err = self._fetch_releases(client, result, pages=1)
            if err:
                result.error = err
                return result
            out = self._collect_baseline(client, result, releases)
            out.covered.insert(0, f"ESCALATED to baseline ({log_reason})")
            return out

        # Walk back through release pages until the cursor is found. One page spans
        # ~3 days, so a run that missed a long weekend needs more than one.
        releases: list = []
        found = False
        for page in range(1, MAX_RELEASE_PAGES + 1):
            batch, err = self._fetch_releases(client, result, pages=1, page=page)
            if err:
                result.error = err
                return result
            if not batch:
                break
            releases.extend(batch)
            if any(r.get("tag_name") == state.cursor for r in batch):
                found = True
                break

        if not found:
            # THE IMPORTANT CASE. The cursor is older than everything we can see, so
            # there is a gap between it and the oldest release in hand. Consuming the
            # deltas we do have would advance the cursor past that gap and lose every
            # CVE changed inside it — silently, with no error. Escalate instead.
            result.records = []
            result.fetches = result.fetches[:1]
            note = (f"cursor {state.cursor!r} not found within "
                    f"{MAX_RELEASE_PAGES * RELEASE_PAGE} releases — a gap exists, so "
                    "the deltas in hand are not sufficient")
            result.covered.append(note)
            fresh, err = self._fetch_releases(client, result, pages=1)
            if err:
                result.error = err
                return result
            out = self._collect_baseline(client, result, fresh)
            out.covered.insert(0, f"ESCALATED to baseline ({note})")
            return out

        return self._collect_deltas(client, result, releases, state)

    def _fetch_releases(self, client, result: CveCollectResult, pages: int = 1,
                        page: int = 1) -> tuple[list, str | None]:
        fetch = client.get(RELEASES_URL, request_mode="incremental",
                           params={"per_page": RELEASE_PAGE, "page": page})
        result.fetches.append(fetch)
        if not fetch.ok:
            return [], fetch.error
        try:
            releases = json.loads(fetch.body)
        except (json.JSONDecodeError, TypeError) as exc:
            fetch.ok = False
            fetch.error = f"unparseable release index: {exc}"
            return [], fetch.error
        if not isinstance(releases, list):
            fetch.ok = False
            fetch.error = "release index was not a list"
            return [], fetch.error
        if page == 1 and not releases:
            fetch.ok = False
            fetch.error = "release index was empty"
            return [], fetch.error
        return releases, None

    # -- baseline ------------------------------------------------------------------

    def _collect_baseline(self, client, result: CveCollectResult, releases: list) -> CveCollectResult:
        asset = url = tag = None
        for release in releases:
            for candidate in release.get("assets") or []:
                if "all_CVEs_at_midnight" in (candidate.get("name") or ""):
                    asset, url, tag = candidate["name"], candidate["browser_download_url"], release["tag_name"]
                    break
            if url:
                break
        if not url:
            result.error = "no baseline bundle found in the latest releases"
            return result

        fetch = client.get(url, request_mode="full", expect_json=False)
        result.fetches.append(fetch)
        if not fetch.ok:
            result.error = fetch.error
            return result
        try:
            records, bad = _read_bundle(fetch.body)
        except (zipfile.BadZipFile, ValueError) as exc:
            result.error = f"unreadable baseline bundle: {exc}"
            fetch.ok = False
            fetch.error = result.error
            return result
        finally:
            # 562 MB. The release asset is immutable on GitHub, so recording the tag
            # and hash keeps the run reproducible without storing the bytes — the
            # documented raw-layer exception in migration 0009.
            fetch.body = None

        result.records = records
        result.covered = [f"{tag}:{asset}"]
        fetch.record_count = len(records)
        result.complete_snapshot = True
        if bad:
            result.error = f"{bad} unreadable record(s) in the baseline bundle"
        return result

    # -- deltas --------------------------------------------------------------------

    def _collect_deltas(self, client, result: CveCollectResult, releases: list,
                        state: CveSourceState) -> CveCollectResult:
        pending = []
        for release in releases:
            tag = release.get("tag_name")
            if tag and tag == state.cursor:
                break                      # everything from here down is already in
            for asset in release.get("assets") or []:
                name = asset.get("name") or ""
                if "delta" in name.lower() and name.endswith(".zip"):
                    pending.append((tag, name, asset["browser_download_url"]))

        if not pending:
            result.unchanged = True
            return result
        if len(pending) > MAX_DELTAS:
            # Catching up is the pipeline's job. Replaying hundreds of deltas is slower
            # and less certain than one baseline, so take the baseline.
            note = f"{len(pending)} deltas pending since {state.cursor!r}; baseline is cheaper"
            result.records = []
            fresh, err = self._fetch_releases(client, result, pages=1)
            if err:
                result.error = err
                return result
            out = self._collect_baseline(client, result, fresh)
            out.covered.insert(0, f"ESCALATED to baseline ({note})")
            return out

        # Oldest first, so later releases legitimately overwrite earlier ones.
        pending.reverse()
        seen: dict[str, CveRecord] = {}
        bad_total = 0
        for tag, name, url in pending:
            fetch = client.get(url, request_mode="incremental", expect_json=False)
            result.fetches.append(fetch)
            if not fetch.ok:
                result.error = f"{name}: {fetch.error}"
                return result           # stop: the cursor must not advance past a gap
            try:
                records, bad = _read_bundle(fetch.body, require_records=False)
            except (zipfile.BadZipFile, ValueError) as exc:
                result.error = f"{name}: unreadable delta: {exc}"
                fetch.ok = False
                fetch.error = result.error
                return result
            bad_total += bad
            fetch.record_count = len(records)
            for record in records:
                seen[record.cve_id] = record
            result.covered.append(f"{tag}:{name}")

        result.records = list(seen.values())
        if bad_total:
            result.error = f"{bad_total} unreadable record(s) across the deltas"
        return result


def _is_cve_json(name: str) -> bool:
    if not name.endswith(".json") or "/" not in name:
        return False
    return name.rsplit("/", 1)[1].upper().startswith("CVE-")


def _read_bundle(body: bytes, require_records: bool = True) -> tuple[list[CveRecord], int]:
    """Parse a bundle zip, transparently unwrapping the nested baseline.

    The baseline asset is named ``*_all_CVEs_at_midnight.zip.zip`` and really is
    doubly wrapped: a 589 MB outer archive containing a single ``cves.zip`` of ~652 MB,
    which holds the per-CVE JSON files. The inner archive is spilled to a temp file
    rather than decompressed into memory — holding both would cost well over a
    gigabyte of RSS on a CI runner for no benefit.

    ``require_records`` is True for the baseline, where an empty archive means a broken
    download. It is False for deltas: a quiet window legitimately produces an empty
    22-byte zip with zero entries, and treating that as an error would fail the run
    every time nothing happened to change.
    """
    with zipfile.ZipFile(io.BytesIO(body)) as outer:
        names = outer.namelist()
        members = [n for n in names if _is_cve_json(n)]
        if members:
            return _read_members(outer, members, require_records)

        nested = [n for n in names if n.lower().endswith(".zip")]
        if len(nested) == 1:
            tmp = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
            try:
                with outer.open(nested[0]) as src:
                    shutil.copyfileobj(src, tmp, length=8 * 1024 * 1024)
                tmp.close()
                with zipfile.ZipFile(tmp.name) as inner:
                    inner_members = [n for n in inner.namelist() if _is_cve_json(n)]
                    return _read_members(inner, inner_members, require_records)
            finally:
                tmp.close()
                os.unlink(tmp.name)

    if require_records:
        raise ValueError("bundle contained no CVE records")
    return [], 0


def _read_members(archive: zipfile.ZipFile, members: list[str],
                  require_records: bool) -> tuple[list[CveRecord], int]:
    records, bad = [], 0
    for name in members:
        try:
            record = _to_record(json.loads(archive.read(name)))
        except (json.JSONDecodeError, NormalisationError, KeyError, TypeError, ValueError):
            bad += 1
            continue
        if record is not None:
            records.append(record)
    if require_records and not records:
        raise ValueError("bundle contained no CVE records")
    return records, bad


def _to_record(document: dict) -> CveRecord | None:
    meta = document.get("cveMetadata") or {}
    cve_id = (meta.get("cveId") or "").strip().upper()
    if not cve_id:
        return None

    cna = (document.get("containers") or {}).get("cna") or {}

    descriptions = [d.get("value") for d in (cna.get("descriptions") or [])
                    if isinstance(d, dict) and (d.get("lang") or "en").lower().startswith("en")]
    description = (descriptions[0] if descriptions else None)

    version = score = vector = None
    for metric in cna.get("metrics") or []:
        if not isinstance(metric, dict):
            continue
        # Prefer the newest CVSS the CNA supplied; the key names carry the version.
        for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
            block = metric.get(key)
            if isinstance(block, dict) and block.get("baseScore") is not None:
                version = block.get("version") or key
                score = float(block["baseScore"])
                vector = block.get("vectorString")
                break
        if score is not None:
            break

    cwes = []
    for problem in cna.get("problemTypes") or []:
        for entry in (problem.get("descriptions") or []) if isinstance(problem, dict) else []:
            cwe = entry.get("cweId") if isinstance(entry, dict) else None
            if cwe:
                cwes.append(cwe)

    affected = cna.get("affected") or []
    vendors = [a.get("vendor") for a in affected if isinstance(a, dict)]
    products = [a.get("product") for a in affected if isinstance(a, dict)]

    state = meta.get("state")
    return CveRecord(
        cve_id=cve_id,
        source="cve_project",
        state=state if state in ("PUBLISHED", "REJECTED", "RESERVED") else None,
        assigner_org_id=meta.get("assignerOrgId"),
        assigner_short_name=meta.get("assignerShortName"),
        date_reserved=parse_timestamp(meta.get("dateReserved")),
        date_published=parse_timestamp(meta.get("datePublished")),
        date_updated=parse_timestamp(meta.get("dateUpdated")),
        title=(cna.get("title") or None),
        description=(description[:8000] if description else None),
        cna_cvss_version=str(version) if version else None,
        cna_cvss_score=score,
        cna_cvss_vector=vector,
        cwe_ids=clamp(cwes),
        affected_vendors=clamp(vendors),
        affected_products=clamp(products),
        reference_count=len(cna.get("references") or []),
    )
