"""Gate checks for the breach pipeline. ERROR fails the run; WARN is visible; INFO is diagnostic.

Each exists because of a way this pipeline could be wrong and still look green.
"""

from __future__ import annotations

from zdc_crowdsec.evals import ERROR, INFO, WARN, EvalResult

from . import grounding


def sources_answered(report) -> EvalResult:
    """One source failing is ordinary (a regulator portal down for an hour). Half of those
    attempted failing is an outage or a block wearing a success badge."""
    tried = {k: v for k, v in report["sources"].items() if "ok" in v}
    failed = sorted(k for k, v in tried.items() if not v["ok"])
    ok = not tried or len(failed) <= len(tried) / 2
    return EvalResult("sources_answered", ERROR, ok,
                      f"{len(tried) - len(failed)} of {len(tried)} sources answered"
                      + (f"; failed: {', '.join(failed)}" if failed else ""), {"failed": failed})


def leak_not_silently_empty(report) -> EvalResult:
    """Leak trackers post dozens of victims a day (RansomLook: 58 in 24h, 2026-10-14). A 200
    with nothing parsed is a format change, not a quiet day."""
    bad = [k for k in ("ransomlook", "ransomfeed")
           if report["sources"].get(k, {}).get("ok") and report["sources"][k].get("parsed", 1) == 0]
    return EvalResult("leak_not_silently_empty", ERROR, not bad,
                      "every leak tracker fetched returned posts" if not bad
                      else f"answered with zero parsed posts: {', '.join(bad)}", {"empty": bad})


def regulators_not_silently_empty(report) -> EvalResult:
    """A regulator list that parses to nothing has changed shape; the run would otherwise
    record 'no new breaches' for as long as nobody looks."""
    bad = [k for k in ("wa_ag", "de_ag", "ca_ag", "hhs_ocr", "hibp")
           if report["sources"].get(k, {}).get("ok") and report["sources"][k].get("parsed", 1) == 0]
    return EvalResult("regulators_not_silently_empty", ERROR, not bad,
                      "every regulator list fetched parsed to rows" if not bad
                      else f"parsed to zero rows: {', '.join(bad)}", {"empty": bad})


def records_parse(report) -> EvalResult:
    worst, where = 0.0, None
    for k, v in report["sources"].items():
        seen = (v.get("parsed") or 0) + (v.get("malformed") or 0)
        if seen >= 20:
            share = (v.get("malformed") or 0) / seen
            if share > worst:
                worst, where = share, k
    return EvalResult("records_parse", ERROR, worst <= 0.05,
                      f"worst unparseable share {worst:.1%}" + (f" ({where})" if where else ""),
                      {"worst": round(worst, 3), "source": where})


def quote_offsets_valid(new_quotes) -> EvalResult:
    """Every claim accepted this run: its quote is in its document. Re-checked here, after
    storage, so a bug between the gate and the database cannot slip a quote through."""
    bad = sum(1 for q, doc in new_quotes if not grounding.quote_in_document(q, doc))
    return EvalResult("quote_offsets_valid", ERROR, bad == 0,
                      f"{len(new_quotes)} accepted quotes re-checked, {bad} not found in their document",
                      {"checked": len(new_quotes), "bad": bad})


def budget(report) -> EvalResult:
    stopped = report["llm"]["budget_stopped"]
    return EvalResult("llm_budget", WARN, not stopped,
                      f"LLM spend this run {report['llm']['cost_usd']:.4f} USD over {report['llm']['docs']} documents"
                      if not stopped else f"extraction stopped: {stopped}", {"llm": report["llm"]})


def no_unconfirmed_names_public(cur) -> EvalResult:
    """The rule that matters most: no organisation reaches the public view on a criminal's or a
    journalist's say-so alone. Asserted against the live view, every run."""
    cur.execute("""select count(*) from public.breach_incidents p
                     join breach_core.incidents i using (incident_id)
                    where not (i.victim_confirmed or i.regulator_filed) or i.suppressed""")
    n = cur.fetchone()[0]
    return EvalResult("no_unconfirmed_names_public", ERROR, n == 0,
                      "every published incident is victim-confirmed or regulator-filed" if n == 0
                      else f"{n} published incident(s) lack confirmation", {"violations": n})


def unit_integrity(cur) -> EvalResult:
    """No reconciled count was fed by a claim of another unit (the CHECKs make this
    impossible today; this catches the day someone relaxes one)."""
    cur.execute("""select count(*) from breach_core.claims
                    where accepted and ((field = 'people_affected' and unit <> 'persons')
                       or (field = 'records_affected' and unit <> 'records')
                       or (field = 'accounts_affected' and unit <> 'accounts')
                       or (field = 'data_bytes' and unit <> 'bytes'))""")
    n = cur.fetchone()[0]
    return EvalResult("unit_integrity", ERROR, n == 0, f"{n} count claims with a foreign unit", {"bad": n})


def placeholders_excluded(cur) -> EvalResult:
    """HHS's 500/501 placeholder must never be the published count when a real one exists."""
    cur.execute("""select count(*) from breach_core.incident_facts f
                    where f.people_qualifier = 'placeholder'
                      and exists (select 1 from breach_core.claims c
                                   where c.incident_id = f.incident_id and c.accepted
                                     and c.field = 'people_affected' and c.qualifier <> 'placeholder')""")
    n = cur.fetchone()[0]
    return EvalResult("placeholders_excluded", ERROR, n == 0,
                      f"{n} incidents show a placeholder count while a real count exists", {"bad": n})


def censoring(cur) -> EvalResult:
    cur.execute("""select min(last_success_at), count(*) filter (where last_success_at < now() - interval '3 days')
                     from breach_core.source_state st join breach_core.sources s using (source_id)
                    where s.enabled""")
    oldest, stale = cur.fetchone()
    return EvalResult("sources_fresh", WARN, not stale,
                      f"oldest last success {oldest}; {stale or 0} source(s) stale for 3+ days",
                      {"censoring_date": str(oldest) if oldest else None, "stale": stale or 0})


def run_all(cur, ctx) -> list[EvalResult]:
    r = ctx.report
    return [sources_answered(r), leak_not_silently_empty(r), regulators_not_silently_empty(r),
            records_parse(r), quote_offsets_valid(ctx.new_quotes), budget(r),
            no_unconfirmed_names_public(cur), unit_integrity(cur), placeholders_excluded(cur),
            censoring(cur),
            EvalResult("claims_gate", INFO, True,
                       f"{r['claims']['accepted']} accepted, {r['claims']['rejected']} rejected",
                       r["claims"])]
