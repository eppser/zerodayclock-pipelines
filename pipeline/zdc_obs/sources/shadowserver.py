"""Shadowserver honeypot telemetry — attempt_observed.

Daily, per-vulnerability exploitation-attempt volume from Shadowserver's global
honeypot sensor network, read from the public dashboard's own JSON endpoint:

    GET dashboard.shadowserver.org/statistics/honeypot/vulnerability/time-series/
        ?json=1&dataset=connections&group_by=vulnerability
        &stacking=overlap&host_type=src&limit=5000&date_range=365

Two datasets are fetched and joined on (vulnerability, date):

    connections  total exploitation attempts seen that day
    unique_ips   distinct source addresses seen that day

Both matter. Measured 2026-08-27: CVE-2022-40684 drew 8,625 attempts from just 18
addresses while CVE-2023-20198 drew 2,466 from 286 — a handful of noisy hosts versus
broad botnet scanning. No catalogue publishes that distinction.

ACCESS AND ETHICS
-----------------
This is an unauthenticated endpoint the public dashboard itself calls; `json=1` is the
parameter its own JavaScript sets. Shadowserver is a non-profit and charges nothing,
but the *documented* equivalent (``honeypot/exploited-vulnerabilities`` on
transform.shadowserver.org/api2) is gated behind approved membership of their
``honeypot`` group, and the response carries ``"allow_download_as_csv": false``.

So we deliberately self-limit: one run per day, two requests, an identifying
User-Agent carrying a contact address, and no bulk re-export. An access request has
been sent; when credentials arrive this adapter should move to the documented API,
which additionally supplies cisa_kev, iot, severity and product fields under a stable
contract. Until then, treat this endpoint as a courtesy that can be withdrawn — if
Shadowserver objects or the shape changes, stop rather than work around it.

WHAT THIS SOURCE IS AND IS NOT
------------------------------
It is **attempt** telemetry: somebody aimed an exploit at a sensor. It is not evidence
that any real system was compromised, and nothing here may be promoted to one.

It is also **not independent of the KEV catalogues**, which is the opposite of what we
first assumed. Measured over 365 days against our KEV corpus: of 89 vulnerabilities
that entered a catalogue during the window, the honeypot led the catalogue **zero**
times, and its first sighting fell on the *exact same day* in 49 of them (median lag
0 days). That is the signature of detection signatures being written when a
vulnerability becomes notable — before that, attempts are unclassified traffic. So this
source cannot provide early warning and must not be used as an independent leg in
capture-recapture.

Its real value is intensity (volume no catalogue publishes), persistence (CVE-2017-17215
is nine years old and still draws ~1,700 attempts/day), and the twelve non-CVE
identifiers (EDB-*, CNVD-*) that are structurally uncatalogueable because KEV requires
a CVE to exist first.
"""

from __future__ import annotations

import json
from datetime import date

from ..models import ExploitationObservation, ObsCollectResult, extract_cve, parse_date
from .base import ObservationSource, ObsSourceState, register

BASE = "https://dashboard.shadowserver.org/statistics/honeypot/vulnerability/time-series/"

#: The endpoint returns a top-N ranked list, so the limit must exceed the true series
#: count or the long tail is silently dropped — and the uncatalogued EDB/CNVD entries
#: live in that tail. Measured 2026-08-28: a 7-day window has 977 distinct
#: vulnerabilities, a 365-day window has 1,209 (identical at limit=3000 and
#: limit=10000, so 1,209 is the complete set). 5000 leaves ~4x headroom.
#: If a run ever returns >= LIMIT series the result IS truncated, and the adapter
#: fails loudly rather than publishing a partial tail.
LIMIT = 5000
#: Every response carries the full window, so a missed day is recoverable — we cannot
#: lose data by not running. Incremental keeps the request small; full backfills a year.
INCREMENTAL_DAYS = 7
FULL_DAYS = 365
DATASETS = ("connections", "unique_ips")


@register
class ShadowserverObservations(ObservationSource):
    source_id = "shadowserver"
    observation_type = "attempt_observed"
    #: Deliberately slow. Two requests per run is all this adapter ever makes.
    rate_per_minute = 4
    requires_credential = False
    credential_env = None

    def headers(self) -> dict[str, str]:
        # The dashboard serves HTML unless the request looks like its own XHR.
        return {
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": "https://dashboard.shadowserver.org/",
        }

    def collect(self, client, state: ObsSourceState, mode: str,
                *, today: date | None = None) -> ObsCollectResult:
        result = ObsCollectResult(source_id=self.source_id)
        today = today or date.today()

        # We promised Shadowserver one run per day. The observation pipeline is
        # scheduled twice daily, so the limit is enforced here rather than by the
        # schedule — that way it holds however the pipeline is invoked. Every response
        # carries the whole window, so skipping a run loses nothing.
        if mode != "full" and state.last_success_at is not None \
                and state.last_success_at.date() >= today:
            result.unchanged = True
            return result

        days = FULL_DAYS if mode == "full" else INCREMENTAL_DAYS

        series: dict[str, dict[str, dict[str, int]]] = {}
        for dataset in DATASETS:
            fetch = client.get(
                BASE, request_mode="full" if mode == "full" else "incremental",
                params={"json": 1, "dataset": dataset, "group_by": "vulnerability",
                        "stacking": "overlap", "host_type": "src",
                        "limit": LIMIT, "date_range": days},
            )
            result.fetches.append(fetch)
            if not fetch.ok:
                result.error = f"{dataset}: {fetch.error}"
                return result

            try:
                payload = json.loads(fetch.body)
            except (json.JSONDecodeError, TypeError) as exc:
                result.error = f"{dataset}: unparseable response: {exc}"
                fetch.ok = False
                fetch.error = result.error
                return result

            # The endpoint answers 200 with a validation error body rather than 4xx.
            if isinstance(payload, dict) and payload.get("errors"):
                result.error = f"{dataset}: rejected: {payload['errors']}"
                fetch.ok = False
                fetch.error = result.error
                return result

            columns = ((payload.get("data") or {}).get("columns")) or []
            if len(columns) < 2:
                result.error = f"{dataset}: response carried no series"
                fetch.ok = False
                fetch.error = result.error
                return result

            dates = [parse_date(d) for d in columns[0][1:]]
            count = 0
            for column in columns[1:]:
                vuln = str(column[0]).strip()
                if not vuln:
                    continue
                for day, value in zip(dates, column[1:]):
                    if day is None or not value:
                        continue
                    series.setdefault(vuln, {}).setdefault(day.isoformat(), {})[dataset] = int(value)
                    count += 1
            fetch.record_count = count

            if len(columns) - 1 >= LIMIT:
                # Silent truncation would understate the long tail exactly where the
                # uncatalogued vulnerabilities live.
                result.error = (
                    f"{dataset}: {len(columns) - 1} series returned at limit={LIMIT}; "
                    "the result is truncated and the tail is missing"
                )
                return result

        for vuln, by_day in series.items():
            for day_iso, values in by_day.items():
                observation = _to_observation(vuln, day_iso, values)
                if observation is not None:
                    result.observations.append(observation)

        # Every response contains the whole window, so a clean fetch is a complete
        # snapshot *of that window* — but only a full run covers the year.
        result.complete_snapshot = mode == "full"
        return result


def _to_observation(vuln: str, day_iso: str, values: dict[str, int]) -> ExploitationObservation | None:
    observed = parse_date(day_iso)
    if observed is None:
        return None

    cve_id = extract_cve(vuln)
    # Shadowserver tracks identifiers that are not CVEs at all — EDB-41471,
    # CNVD-2018-24942, CVE-UNASSIGNED-2020-Zyxel-CPE-Command-Injection-RCE-01. These are
    # the only exploitation we can see that no KEV catalogue can ever list, so they must
    # survive rather than be filtered out for failing a CVE regex.
    vuln_id, vuln_id_type = ObservationSource.primary_id(cve_id, vuln.upper())

    connections = values.get("connections")
    unique_ips = values.get("unique_ips")
    if not connections and not unique_ips:
        return None

    return ExploitationObservation(
        source_id="shadowserver",
        # One observation per vulnerability per day: this is a daily time series, and
        # collapsing it to "first seen" would discard the intensity signal that is the
        # entire reason for ingesting it.
        source_entry_id=f"{vuln_id}@{day_iso}",
        observation_type="attempt_observed",
        vuln_id=vuln_id,
        vuln_id_type=vuln_id_type,
        cve_id=cve_id,
        observed_at=observed,
        first_observed_at=observed,
        last_observed_at=observed,
        # Attempts that day. Unlike VulnCheck, Shadowserver does publish volume.
        observation_count=connections,
        raw={"vulnerability": vuln, "date": day_iso,
             "connections": connections, "unique_ips": unique_ips},
    )
