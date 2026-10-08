"""Gate checks for the OSM feed. ERROR blocks; WARN is visible; INFO is diagnostic.

Each exists because of a way this pipeline could be wrong and still look fine.
"""

from __future__ import annotations

from zdc_crowdsec.evals import ERROR, INFO, WARN, EvalResult


def check_authenticated(statuses: dict[str, int]) -> EvalResult:
    """A revoked or mistyped token answers 401 on every ecosystem. Said once, plainly."""
    bad = sorted(e for e, s in statuses.items() if s in (401, 403))
    return EvalResult(
        "authenticated", ERROR, not bad,
        "the API accepted the token" if not bad
        else f"{len(bad)} ecosystem(s) refused the token ({statuses[bad[0]]}) - "
             "OSM_API_KEY is invalid, revoked or lacks access",
        {"refused": bad})


def check_polls_answered(statuses: dict[str, int], errors: dict[str, str]) -> EvalResult:
    """One ecosystem failing is a transient on a 17-request run and must not discard the
    other 16. More than a quarter failing is an outage or a rate limit wearing a success
    badge."""
    failed = sorted(e for e in statuses if errors.get(e))
    share = len(failed) / len(statuses) if statuses else 1.0
    ok = bool(statuses) and share <= 0.25
    return EvalResult(
        "polls_answered", ERROR, ok,
        f"{len(statuses) - len(failed)} of {len(statuses)} ecosystems answered"
        + (f"; failed: {', '.join(failed)}" if failed else "") if ok
        else f"{len(failed)} of {len(statuses)} ecosystems failed - "
             + "; ".join(f"{e}: {errors[e]}" for e in failed[:3]),
        {"failed": failed, "share": round(share, 3)})


def check_not_silently_empty(record_counts: dict[str, int]) -> EvalResult:
    """Every ecosystem answered 200 and not one carried a record.

    THE FAILURE THIS PROJECT KEEPS MEETING, and this API makes it easy: an unknown
    ecosystem returns 200 {"count":0}, so a renamed parameter would turn every poll into
    a clean, green, empty run."""
    total = sum(record_counts.values())
    return EvalResult(
        "not_silently_empty", ERROR, total > 0,
        f"{total:,} records across {sum(1 for v in record_counts.values() if v)} ecosystems"
        if total else "every ecosystem answered and none returned a record",
        {"records": total})


def check_ecosystem_went_empty(went_empty: list[str]) -> EvalResult:
    """An ecosystem we hold records for now answers with none. OSM does not delete its
    history, so this is a renamed registry value or an API change - and it is invisible
    to `not_silently_empty` while any other ecosystem still returns data."""
    return EvalResult(
        "ecosystem_went_empty", ERROR, not went_empty,
        "every ecosystem with stored records still returns records" if not went_empty
        else f"returned zero records but we hold some: {', '.join(went_empty)}",
        {"ecosystems": went_empty})


def check_window_complete(incomplete: dict[str, str]) -> EvalResult:
    """More than 100 updates between two polls pushes records out of reach for good.

    WARN, not ERROR: what was fetched is still correct and still worth storing, and
    blocking would lose it too. But it is a permanent hole, so it is never silent. The
    remedy is a higher cadence for that ecosystem, which is a code change."""
    return EvalResult(
        "window_complete", WARN, not incomplete,
        "every full window reached back to the previous poll" if not incomplete
        else "records may have been missed (oldest returned > previous newest): "
             + "; ".join(f"{e} {v}" for e, v in incomplete.items()),
        {"incomplete": incomplete})


def check_malformed(parsed: int, malformed: int) -> EvalResult:
    """A few unparseable records are skipped and counted. Many means the shape changed."""
    seen = parsed + malformed
    share = malformed / seen if seen else 0.0
    return EvalResult(
        "records_parse", ERROR, share <= 0.05,
        f"{malformed} of {seen:,} records unparseable ({share:.1%})",
        {"malformed": malformed, "seen": seen})


def check_persisted(parsed: int, stored: int) -> EvalResult:
    """Fetching cleanly and storing nothing once reported "safe to promote" in KEV."""
    return EvalResult(
        "persisted", ERROR, stored == parsed,
        f"{stored:,} of {parsed:,} parsed records written or confirmed"
        if stored == parsed else f"parsed {parsed:,} records but stored {stored:,}",
        {"parsed": parsed, "stored": stored})


def check_downloads(outcomes: dict[str, int]) -> EvalResult:
    """Lookup errors are retried, so a few are harmless. Mostly errors means a counter is
    blocking us, and every un-looked-up npm package is one npm may remove meanwhile."""
    asked = sum(outcomes.values())
    errors = outcomes.get("error", 0)
    ok = asked == 0 or errors / asked <= 0.5
    return EvalResult(
        "downloads_resolved", WARN, ok,
        f"{asked} lookups: " + ", ".join(f"{k} {v}" for k, v in sorted(outcomes.items()))
        if asked else "no lookups pending",
        {"outcomes": outcomes})


def check_no_token_leak(report_text: str, token: str) -> EvalResult:
    """The report is uploaded as a workflow artifact. Assert it, do not assume it."""
    leaked = bool(token) and token in report_text
    return EvalResult(
        "no_token_in_report", ERROR, not leaked,
        "the API token appears nowhere in the run report" if not leaked
        else "the API token is present in the run report", {})


def check_registry_mismatch(mismatches: int) -> EvalResult:
    return EvalResult(
        "registry_matches_request", INFO, mismatches == 0,
        f"{mismatches} record(s) carried a registry other than the ecosystem asked for",
        {"mismatches": mismatches})
