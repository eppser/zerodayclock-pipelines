"""Gate checks for the CrowdSec pipeline.

Each one exists because of a specific way this pipeline could be wrong and still look
fine. ERROR blocks promotion; WARN is visible; INFO is a diagnostic.
"""

from __future__ import annotations

from dataclasses import dataclass, field

ERROR, WARN, INFO = "error", "warn", "info"


@dataclass(frozen=True, slots=True)
class EvalResult:
    name: str
    severity: str
    passed: bool
    summary: str
    detail: dict = field(default_factory=dict)

    @property
    def blocking(self) -> bool:
        return self.severity == ERROR and not self.passed


def check_catalogue_fetched(total, error) -> EvalResult:
    """An empty corpus must say why. v1 recorded a WAF block as 220 successful rows."""
    ok = error is None and bool(total)
    return EvalResult(
        "catalogue_fetched", ERROR, ok,
        f"tracker listed {total:,} CVEs" if ok
        else f"could not read the CVE catalogue: {error or 'zero CVEs returned'}",
        {"total": total, "error": error})


def check_timelines_fetched(asked, failed) -> EvalResult:
    """A partial harvest is allowed; a mostly-failed one is not.

    One CVE's timeline failing is a transient on a 780-request run and must not discard
    the other 779. A tenth of them failing is a rate limit or an outage wearing a
    success badge, which is the failure mode this project keeps meeting.
    """
    share = (len(failed) / asked) if asked else 0.0
    ok = asked > 0 and share <= 0.10
    return EvalResult(
        "timelines_fetched", ERROR, ok,
        f"{asked - len(failed):,} of {asked:,} timelines fetched "
        f"({share:.1%} failed)" if ok
        else f"{len(failed):,} of {asked:,} timelines failed ({share:.1%}) — "
             + "; ".join(f"{c}: {e}" for c, e in failed[:3]),
        {"asked": asked, "failed": len(failed), "share": round(share, 4)})


def check_not_silently_empty(asked: int, day_counts: int) -> EvalResult:
    """Every timeline answered 200 and every one of them was empty.

    THIS IS THE ONE FAILURE THIS PROJECT KEEPS MEETING. v1 recorded a WAF block as
    220 successful rows; the KEV pipeline once had all four sources fetch cleanly,
    persist nothing, and still report "safe to promote". Here the shape is subtler
    still: `catalogue_fetched` passes because the CVE list is fine, `timelines_fetched`
    passes because no request errored, and `persisted` passes because storing nothing
    when there is nothing to store is not a fault. The run goes green.

    `freshness` would catch it, but only after max_silence_days - up to three days of
    green runs publishing a series that stopped moving. A green run is what stops
    people looking, so the day it happens has to be the day it goes red.

    Asking for nothing is not a fault; asking for 819 timelines and receiving no
    dated observation at all is.
    """
    ok = asked == 0 or day_counts > 0
    return EvalResult(
        "not_silently_empty", ERROR, ok,
        f"{day_counts:,} day-counts from {asked:,} timelines" if ok
        else f"{asked:,} timelines all answered and not one carried a dated "
             "observation - the source returned success and no data",
        {"asked": asked, "day_counts": day_counts})


def check_persisted(inserted, updated, parsed) -> EvalResult:
    """Fetching cleanly and storing nothing once reported "safe to promote" in the KEV
    pipeline. Persistence is checked separately from collection for that reason."""
    ok = (inserted + updated) > 0 or parsed == 0
    return EvalResult(
        "persisted", ERROR, ok,
        f"{inserted:,} inserted, {updated:,} revised" if ok
        else f"parsed {parsed:,} day-counts and stored none",
        {"inserted": inserted, "updated": updated, "parsed": parsed})


def check_window_complete(days_seen, expected_days) -> EvalResult:
    """The 30-day re-read is what makes a missed run harmless. If the window arrives
    short, that property is gone and nobody would notice from the row count alone."""
    ok = days_seen >= expected_days
    return EvalResult(
        "window_complete", WARN, ok,
        f"{days_seen} distinct days in this harvest (expected >= {expected_days})",
        {"days_seen": days_seen, "expected": expected_days})


def check_not_in_kev_layer(conn) -> EvalResult:
    """CrowdSec must never reach the catalogue layer.

    Migration 0024 purged 1,296 rows of Shadowserver telemetry from core.kev_entries.
    The same mistake is available here and would be worse: CrowdSec carries 150 CVEs no
    catalogue lists, which would arrive looking like 150 new listings. The CHECK
    constraint blocks the write; this asserts the outcome as well, because a constraint
    that is dropped in a future migration fails silently.
    """
    with conn.cursor() as cur:
        cur.execute("""select count(*) from core.kev_entries
                        where upstream_source = 'crowdsec' or source_id = 'crowdsec'""")
        n = cur.fetchone()[0]
    return EvalResult(
        "crowdsec_not_in_kev_layer", ERROR, n == 0,
        "the KEV layer holds catalogue listings only; crowdsec is absent from it"
        if n == 0 else
        f"{n:,} crowdsec rows have reached core.kev_entries — a sensor is not a catalogue",
        {"rows": n})


def check_no_per_ip_data(counts_raw) -> EvalResult:
    """We deliberately do not fetch the ips-details endpoints.

    The licence does not grant redistribution of feed content, and the project has no
    use for addresses: every IP in the game is synthetic and Shadowserver offers none.
    Storing one would create a personal-data question nothing here needs to answer.
    """
    leaked = [k for r in counts_raw for k in r
              if k in ("ip", "ips", "ip_range", "source_ip", "addresses")]
    return EvalResult(
        "no_per_ip_data", ERROR, not leaked,
        "no per-IP field reached the observation rows" if not leaked
        else f"per-IP fields present in stored raw: {sorted(set(leaked))[:5]}",
        {"fields": sorted(set(leaked))})


def check_tag_characters_stripped(rows) -> EvalResult:
    """CrowdSec free text is untrusted: /v1/info was measured returning an invisible
    prompt-injection template in Unicode tag characters. Nothing carrying that block
    may be stored, because a later reader - human or model - cannot see it."""
    bad = []
    for r in rows:
        for v in r.values():
            if isinstance(v, str) and any(0xE0000 <= ord(ch) <= 0xE007F for ch in v):
                bad.append(v[:40])
    return EvalResult(
        "tag_characters_stripped", ERROR, not bad,
        "no Unicode tag characters survived into stored text" if not bad
        else f"{len(bad)} stored strings still carry U+E0000-block characters",
        {"count": len(bad)})


def check_freshness(conn, censored_at, max_lag_days: int | None = None) -> EvalResult:
    """A stopped collector must show up as a growing number, not an empty column.

    zdc_obs's own `check_source_freshness` scopes itself to `collector = 'zdc_obs'`, so
    it will never look at this source. Without this check, 0081 would declare
    max_silence_days and nothing on earth would read it — a source registered and then
    left unmonitored, which is the shape of every silent-collector bug this project has
    had. The honeypot pipeline carries the same check for the same reason (0068).

    THE THRESHOLD COMES FROM THE REGISTRY, never from this signature: a constant here
    would make the declared value documentation the pipeline ignores. An explicit
    argument still wins, for tests. No declared threshold falls back to 3 rather than
    passing vacuously.
    """
    with conn.cursor() as cur:
        if max_lag_days is None:
            cur.execute("""select max_silence_days from obs_core.observation_sources
                            where source_id = 'crowdsec'""")
            row = cur.fetchone()
            max_lag_days = (row[0] if row and row[0] is not None else 3)
        cur.execute("""select max(observed_at) from obs_core.exploitation_observations
                        where source_id = 'crowdsec'""")
        last = cur.fetchone()[0]
    if last is None:
        return EvalResult("freshness", ERROR, False,
                          "no observation days stored at all", {"last_day": None})
    lag = (censored_at - last).days
    return EvalResult(
        "freshness", ERROR if lag > max_lag_days else INFO, lag <= max_lag_days,
        f"most recent observation day {last}, {lag} day(s) behind the censoring date",
        {"last_day": str(last), "lag_days": lag, "threshold": max_lag_days})
