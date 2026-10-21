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


def wa_site_harvested(report) -> EvalResult:
    """The atg.wa.gov list (R4) is the only source of WA data types. A read that parses to no
    notice has changed shape (ERROR); a blocked or unreachable list is visible (WARN), and the
    dataset rows still landed because the list runs in its own savepoint."""
    site = (report["sources"].get("wa_ag") or {}).get("site")
    if site is None:
        return EvalResult("wa_site_harvested", INFO, True, "atg.wa.gov list not read this run", {})
    if site.get("ok") and site.get("pages", 0) and not site.get("notices"):
        return EvalResult("wa_site_harvested", ERROR, False, "atg.wa.gov list parsed to zero notices", site)
    if not site.get("ok"):
        return EvalResult("wa_site_harvested", WARN, False,
                          f"atg.wa.gov list not read: {site.get('error')}", site)
    return EvalResult("wa_site_harvested", INFO, True,
                      f"{site['pages']} pages, {site['notices']} notices, {site.get('claims_written', 0)} claims written",
                      site)


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


def public_rows_have_status(cur) -> EvalResult:
    """Owner decision 2026-10-14 (migration 0105): every victim is named, and every named row
    says how we know - filed, confirmed, reported, or only claimed by attackers. A row with no
    status, or a suppressed incident still on the page, fails the run."""
    cur.execute("""select count(*) filter (where p.status is null),
                          count(*) filter (where i.suppressed)
                     from public.breach_incidents p join breach_core.incidents i using (incident_id)""")
    no_status, suppressed = cur.fetchone()
    ok = no_status == 0 and suppressed == 0
    return EvalResult("public_rows_have_status", ERROR, ok,
                      "every published incident carries a status; none is suppressed" if ok
                      else f"{no_status} without a status, {suppressed} suppressed but published",
                      {"no_status": no_status, "suppressed": suppressed})


def victims_list_current(cur) -> EvalResult:
    """The public list is a per-run table (0118). If the rebuild stopped running, the page would
    keep showing an old snapshot with no error anywhere; compare it with its definition. Since 0134
    the rebuild records what it removed (merged leak claims, rows hidden by an active linkage
    method), so the list must equal the definition minus exactly those."""
    cur.execute("""select (select count(*) from breach_core.victims_list),
                          (select count(*) from breach_core.victims_source),
                          (select max(built_at) from breach_core.victim_facets)""")
    listed, source, built = cur.fetchone()
    cur.execute("""select source_rows, claims_merged, linkage_hidden, listed from breach_core.victims_list_builds
                    where target = 'public' order by built_at desc limit 1""")
    b = cur.fetchone()
    removed = (b[1] + b[2]) if b else 0
    # 0135: the public list never reads the linkage store, so nothing is hidden by linkage there
    ok = (built is not None and b is not None and b[0] == source and b[3] == listed and listed == source - removed
          and b[2] == 0)
    return EvalResult("victims_list_current", ERROR, ok,
                      f"{listed} rows listed, {source} in the definition, {removed} removed by the last build "
                      f"(claims merged, rows hidden by linkage), facets built {built}",
                      {"listed": listed, "source": source, "build": list(b) if b else None})


def linked_list_current(cur) -> EvalResult:
    """0135: while a method is active, the private linked list is the public list minus exactly the rows the
    linkage step hid, built in this run (a stale linked list would quietly diverge)."""
    cur.execute("select exists (select 1 from breach_core.link_methods where active and cardinality(active_classes) > 0)")
    if not cur.fetchone()[0]:
        return EvalResult("linked_list_current", INFO, True, "no active linkage method: no linked list is built", {})
    cur.execute("select (select count(*) from breach_core.victims_list), (select count(*) from breach_core.victims_list_linked)")
    public, linked = cur.fetchone()
    cur.execute("""select source_rows, linkage_hidden, listed from breach_core.victims_list_builds
                    where target = 'linked' order by built_at desc limit 1""")
    b = cur.fetchone()
    ok = b is not None and b[0] == public and b[2] == linked and linked == public - b[1]
    return EvalResult("linked_list_current", ERROR, ok,
                      f"public {public}, linked {linked}, last linked build {list(b) if b else None}",
                      {"public": public, "linked": linked, "build": list(b) if b else None})


def linkage_clusters_valid(cur) -> EvalResult:
    """An active record-linkage method (0134) must leave clusters that are recorded under it, no
    larger than the cap, and never span two domains or two CIKs (design s5 stop conditions)."""
    cur.execute("select method_version, active_classes from breach_core.link_methods where active")
    row = cur.fetchone()
    if not row or not row[1]:
        return EvalResult("linkage_clusters_valid", INFO, True, "no active linkage method: the list is the legacy list", {})
    mv = row[0]
    cur.execute("""with m as (select c.cluster_id, count(*) n,
                                     count(distinct o.domain) d, count(distinct o.sec_cik) k
                                from breach_core.incident_clusters c
                                join breach_core.incidents i on i.incident_id = c.incident_id
                                join breach_core.organizations o on o.org_id = i.org_id
                               where c.method_version = %s group by c.cluster_id)
                   select coalesce(max(n), 0), count(*) filter (where d > 1 or k > 1),
                          (select count(*) from breach_core.incident_clusters where method_version <> %s),
                          (select count(*) from breach_core.incident_clusters where method_version = %s)
                     from m""", (mv, mv, mv))
    biggest, cross, other, rows = cur.fetchone()
    ok = rows > 0 and biggest <= 10 and cross == 0 and other == 0
    return EvalResult("linkage_clusters_valid", ERROR, ok,
                      f"{mv}: {rows} incidents clustered, largest {biggest}, {cross} clusters across a domain or CIK, "
                      f"{other} rows of another method version",
                      {"method_version": mv, "largest": biggest, "cross": cross, "other_version_rows": other})


# ---- the CVE link layer (0137, ADR 0009) ------------------------------------------------------------
RECALL_FROM = "2024-07-01"   # the news window the extractor has read since (first stored document)


def cve_links_current(cur) -> EvalResult:
    """The links are rebuilt inside the list rebuild, in this transaction. A link table left from an
    earlier run would let the Explorer and /breaches show pairs the current list no longer has."""
    cur.execute("""select count(*), count(*) filter (where public), count(distinct built_at),
                          coalesce(bool_and(built_at = now()), true),
                          (select count(*) from public.breach_cve_links)
                     from breach_core.cve_links""")
    n, public, stamps, this_run, view = cur.fetchone()
    ok = public == view and stamps <= 1 and this_run
    return EvalResult("cve_links_current", ERROR, ok,
                      f"{n} links ({public} public) built in this run's rebuild; the view serves {view}" if ok
                      else f"{n} links, {public} public, view {view}, {stamps} build stamps, built this run: {this_run}",
                      {"links": n, "public": public, "view": view, "build_stamps": stamps, "this_run": this_run})


def cve_links_one_view(cur) -> EvalResult:
    """T2 on the live data: the (CVE, victim) pairs the Explorer reads are exactly the pairs the
    /breaches rows carry in cve_ids. Two pages, one set."""
    cur.execute("""select count(*) from (
                     (select cve_id, victim_id from public.breach_cve_links
                      except select c, victim_id from breach_core.victims_list, unnest(cve_ids) c)
                     union all
                     (select c, victim_id from breach_core.victims_list, unnest(cve_ids) c
                      except select cve_id, victim_id from public.breach_cve_links)) d""")
    n = cur.fetchone()[0]
    return EvalResult("cve_links_one_view", ERROR, n == 0,
                      "the Explorer's links and the /breaches rows hold the same (CVE, victim) pairs" if n == 0
                      else f"{n} (CVE, victim) pairs are on one page and not the other", {"mismatched": n})


def cve_links_have_evidence(cur) -> EvalResult:
    """T4 on the live data: no link without an accepted, current claim behind it, and no public link
    resting on a claim a person rejected."""
    cur.execute("""select count(*) from breach_core.cve_links l
                    where cardinality(l.claim_ids) = 0
                       or exists (select 1 from unnest(l.claim_ids) k left join breach_core.claims c on c.claim_id = k
                                   where c.claim_id is null or not c.accepted or c.superseded_by is not null
                                      or (l.public and c.review_verdict = 'rejected'))""")
    n = cur.fetchone()[0]
    return EvalResult("cve_links_have_evidence", ERROR, n == 0,
                      "every link names accepted, current claims" if n == 0
                      else f"{n} links without valid evidence", {"bad": n})


def no_machine_link_public_ungated(cur) -> EvalResult:
    """A machine-extracted CVE is public only from an extractor version that passed a gold set FOR
    cve_id (none has, 2026-10-20) or by a person's confirmation. A public extractor_active link with no
    such version behind it means the gate was bypassed."""
    cur.execute("""select count(*) from breach_core.cve_links l
                    where l.public and l.gate = 'extractor_active'
                      and not exists (select 1 from unnest(l.claim_ids) k
                                        join breach_core.claims c on c.claim_id = k
                                        join breach_core.extractions e on e.extraction_id = c.extraction_id
                                        join breach_core.extractor_versions x on x.extractor_id = e.extractor_id
                                       where x.active and 'cve_id' = any(x.active_fields))""")
    n = cur.fetchone()[0]
    return EvalResult("no_machine_link_public_ungated", ERROR, n == 0,
                      "every public machine link comes from a version active for cve_id" if n == 0
                      else f"{n} public machine links without an extractor version active for cve_id", {"bad": n})


def cve_links_no_pii(cur) -> EvalResult:
    """A private source can carry people's names (the curated export does). Their hashes are stored
    (breach_core.source_pii_hashes, never the names); no victim the link view publishes may be one."""
    cur.execute("""select count(*) from public.breach_cve_links l
                     join breach_core.source_pii_hashes h
                       on h.sha256 = encode(sha256(convert_to(lower(btrim(l.name)), 'UTF8')), 'hex')""")
    n = cur.fetchone()[0]
    return EvalResult("cve_links_no_pii", ERROR, n == 0,
                      "no published victim name is a person a source named" if n == 0
                      else f"{n} published links name a person", {"bad": n})


def cve_links_held(cur) -> EvalResult:
    """What the gate holds back, by reason: the queue for review and for a cve_id gold set."""
    cur.execute("""select coalesce(hold_reason, 'public'), count(*), count(distinct cve_id)
                     from breach_core.cve_links group by 1 order by 1""")
    rows = {r: {"links": n, "cves": c} for r, n, c in cur.fetchall()}
    cur.execute("""select count(*) from breach_raw.source_records r
                    where r.source_id in (select source_id from breach_core.private_sources)
                      and not exists (select 1 from breach_core.incident_sources s
                                       where s.source_id = r.source_id and s.source_record_id = r.source_record_id)
                      and r.version = (select max(version) from breach_raw.source_records x
                                        where x.source_id = r.source_id and x.source_record_id = r.source_record_id)""")
    unnormalised = cur.fetchone()[0]
    pub = rows.get("public", {"links": 0, "cves": 0})
    return EvalResult("cve_links_held", INFO, True,
                      f"{pub['links']} public links over {pub['cves']} CVEs; held: "
                      + (", ".join(f"{k} {v['links']}" for k, v in rows.items() if k != "public") or "none")
                      + f"; {unnormalised} private records not normalised (unnamed or undated)",
                      {"by_reason": rows, "private_records_not_normalised": unnormalised})


def cve_extraction_recall_vs_export(cur) -> EvalResult:
    """How much of a private reference source's (victim, CVE) pairs the pipeline finds on its own
    (addendum, s4): pairs whose victim is on the list with seen_date >= RECALL_FROM, and the share also
    asserted by a non-private claim (any role, gate passed or not). Counts only. A measured recall
    before anyone proposes running the Explorer on the pipeline alone."""
    cur.execute("""with lv as (select * from breach_core.listed_victim_of()),
                   pairs as (
                       select ic.cve_id, lv.victim_id,
                              bool_or(c.source_id in (select source_id from breach_core.private_sources)) as reference,
                              bool_or(c.source_id not in (select source_id from breach_core.private_sources)) as found
                         from breach_core.incident_cves ic
                         join breach_core.claims c on c.claim_id = ic.claim_id
                         join lv on lv.incident_id = ic.incident_id
                         join breach_core.victims_list v on v.victim_id = lv.victim_id
                        where c.accepted and c.superseded_by is null and v.seen_date >= %s::date
                        group by 1, 2)
                   select count(*) filter (where reference), count(*) filter (where reference and found) from pairs""",
                (RECALL_FROM,))
    ref, found = cur.fetchone()
    share = round(found / ref, 4) if ref else None
    return EvalResult("cve_extraction_recall_vs_export", INFO, True,
                      f"of {ref} reference (victim, CVE) pairs since {RECALL_FROM}, the pipeline found {found}"
                      + (f" ({share:.1%})" if share is not None else ""),
                      {"reference_pairs": ref, "found": found, "recall": share, "since": RECALL_FROM})


def no_incident_from_cve_pass(cur) -> EvalResult:
    """RULING verify-B3 test 10: the CVE pass only attaches. An incident whose every claim comes from a CVE-pass
    extractor version (schema breach-cve-v1) was created by it, which file_cve_output must never do."""
    cur.execute("""select count(*) from (
                       select c.incident_id
                         from breach_core.claims c
                         left join breach_core.extractions e on e.extraction_id = c.extraction_id
                         left join breach_core.extractor_versions x on x.extractor_id = e.extractor_id
                        group by c.incident_id
                       having bool_and(coalesce(x.schema_hash, '') = 'breach-cve-v1')) z""")
    n = cur.fetchone()[0]
    return EvalResult("no_incident_from_cve_pass", ERROR, n == 0,
                      "no incident rests on CVE-pass claims alone" if n == 0
                      else f"{n} incidents whose every claim is from the CVE pass", {"bad": n})


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
            wa_site_harvested(r), records_parse(r), quote_offsets_valid(ctx.new_quotes), budget(r),
            public_rows_have_status(cur), victims_list_current(cur), linked_list_current(cur), linkage_clusters_valid(cur),
            cve_links_current(cur), cve_links_one_view(cur), cve_links_have_evidence(cur),
            no_machine_link_public_ungated(cur), cve_links_no_pii(cur), cve_links_held(cur),
            cve_extraction_recall_vs_export(cur),
            no_incident_from_cve_pass(cur),
            unit_integrity(cur), placeholders_excluded(cur),
            censoring(cur),
            EvalResult("claims_gate", INFO, True,
                       f"{r['claims']['accepted']} accepted, {r['claims']['rejected']} rejected",
                       r["claims"])]
