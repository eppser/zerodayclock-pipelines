"""EPSS — Exploit Prediction Scoring System (FIRST.org / Empirical Security).

MANIFEST
    Licence     CC BY 4.0. Attribution required wherever a score is shown or exported.
    Terms       https://www.first.org/epss/  — free, no authentication, no registered
                rate limit. We self-limit to one fetch per calendar day regardless.
    Cadence     The model scores once daily. Fetching twice would download 2.5 MB to
                learn nothing, so the adapter checks the last successful fetch date and
                skips when it already has today's file.
    Healthy run 350,000-400,000 rows, a parseable header, and fewer than 100 skipped
                rows. Measured 2026-08-31: 366,357 rows, 2.5 MB gzipped.

WHAT THIS IS NOT
    EPSS is a PREDICTION of exploitation in the next 30 days. It is not evidence that
    exploitation happened, and it never populates an exploitation column. This is the
    same rule that keeps MSRC's "Latest Software Release" forecast out of the
    observation tables: reading a forecast as an observation is v1's
    PoC-as-exploitation error wearing a different hat.

TWO TRAPS, BOTH MEASURED
    * The ``-current`` URL 302-redirects to a dated file. The FetchRecord must carry the
      RESOLVED url, otherwise every fetch looks identical in raw.source_fetches and the
      snapshot cannot be re-fetched.
    * Percentiles are relative to the population scored on that day and are not
      comparable across model versions. Both the version and the date are stored per
      row so a consumer cannot accidentally compare across a model change.
"""

from __future__ import annotations

import gzip
import logging
from datetime import date

from zdc_kev.http import PoliteClient
from zdc_kev.models import FetchRecord

from .models import EpssCollectResult, parse_epss

log = logging.getLogger(__name__)

SOURCE_ID = "epss"
CURRENT_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

MIN_PLAUSIBLE_ROWS = 100_000


def make_client() -> PoliteClient:
    return PoliteClient(SOURCE_ID, per_minute=10, timeout=180.0,
                        headers={"Accept": "application/gzip, text/csv"})


def _decompress(body: bytes) -> str:
    """Return CSV text.

    httpx transparently decodes ``Content-Encoding: gzip``, but this is a gzip *file*
    served as ``Content-Type: application/gzip``, so it usually arrives compressed.
    Some CDN configurations do both. Handle either without guessing from headers.
    """
    try:
        return gzip.decompress(body).decode("utf-8", errors="replace")
    except (OSError, EOFError):
        return body.decode("utf-8", errors="replace")


def collect(client: PoliteClient, *, last_fetch_date: date | None = None,
            today: date | None = None, force: bool = False) -> EpssCollectResult:
    result = EpssCollectResult()
    today = today or date.today()

    if not force and last_fetch_date is not None and last_fetch_date >= today:
        result.skipped_reason = f"already fetched today ({last_fetch_date.isoformat()})"
        log.info("epss: %s", result.skipped_reason)
        return result

    fetch: FetchRecord = client.get(CURRENT_URL, request_mode="full", expect_json=False)
    result.fetches.append(fetch)

    if not fetch.ok:
        result.error = fetch.error or f"HTTP {fetch.http_status}"
        return result
    if fetch.not_modified:
        result.unchanged = True
        return result
    if not fetch.body:
        # A 200 with an empty body is a block or an outage, never evidence of absence.
        result.error = "EPSS returned HTTP 200 with an empty body"
        return result

    try:
        records, model_version, score_date, skipped = parse_epss(_decompress(fetch.body))
    except ValueError as exc:
        result.error = f"parse failed: {exc}"
        return result

    if len(records) < MIN_PLAUSIBLE_ROWS:
        # Refuse to persist a truncated file. Overwriting 366k good scores with 500
        # would look like a successful run and silently gut the column.
        result.error = (f"only {len(records)} rows parsed, below the "
                        f"{MIN_PLAUSIBLE_ROWS} floor — treating as a truncated fetch")
        return result

    result.records = records
    result.model_version = model_version
    result.score_date = score_date
    result.skipped_rows = skipped
    fetch.record_count = len(records)
    log.info("epss: %d scores, model %s, score_date %s (%d rows skipped)",
             len(records), model_version, score_date, skipped)
    return result
