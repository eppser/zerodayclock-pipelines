"""Gate checks for the AI cyber capability tracker. ERROR blocks the write; WARN is visible; INFO
is diagnostic. Each exists because of a specific way this data could be wrong and still look fine.
"""

from __future__ import annotations

from zdc_crowdsec.evals import ERROR, INFO, WARN, EvalResult

from .registry import is_self_evaluation
from .source_vals import Board

#: A model whose tasks errored more than this share was limited by the harness or the provider, not
#: by capability; its row is flagged on the page.
ERROR_SHARE = 0.2
#: Within one board version a model's score should not move. More than this many standard errors
#: means Vals re-scored silently, or we read the wrong field.
JUMP_SE = 3.0
#: A board losing more than this share of its models is a broken read, not a pruning.
MODEL_DROP = 0.2


def registry_valid(problems: list[str]) -> EvalResult:
    """The curated registry must be valid before anything is written: a bad row there is a wrong
    number on the page with nothing upstream to catch it."""
    return EvalResult("registry_valid", ERROR, not problems,
                      "registry: evaluators, benchmarks, results and events are valid" if not problems
                      else f"{len(problems)} registry problem(s): " + "; ".join(problems[:4]), {"problems": problems})


def board_read(error: str | None, paths: list[str]) -> EvalResult:
    """The page names exactly one board file and it parsed. Two names mean the page changed shape;
    none means the file moved; either way, write nothing from vals this week."""
    ok = error is None and len(paths) == 1
    return EvalResult("vals_board_read", ERROR, ok,
                      f"read {paths[0]}" if ok else f"vals board not read: {error or ''} (board files named: {len(paths)})",
                      {"paths": paths, "error": error})


def board_shape(board: Board, expected_tasks: dict[str, int]) -> EvalResult:
    """Every model has all three tracks, scores in 0..100, non-negative cost and error; the track
    sizes match the registry. A changed task count without a version change is a silent re-cut."""
    probs = []
    by = {}
    for r in board.rows:
        by.setdefault(r.model_id, set()).add(r.track)
        if r.accuracy is None or not 0 <= r.accuracy <= 100:
            probs.append(f"{r.track}/{r.model_id}: accuracy {r.accuracy}")
        if r.stderr is not None and r.stderr < 0 or r.cost is not None and r.cost < 0:
            probs.append(f"{r.track}/{r.model_id}: negative stderr or cost")
    probs += [f"{m}: tracks {sorted(t)}" for m, t in by.items() if t != {"overall", "poc", "patch"}]
    for track, n in expected_tasks.items():
        sizes = {r.n_tasks for r in board.rows if r.track == track}
        if sizes != {n}:
            probs.append(f"{track}: task counts {sorted(sizes)}, registry says {n}")
    return EvalResult("vals_board_shape", ERROR, not probs,
                      f"{len(by)} models x 3 tracks, task counts {expected_tasks}" if not probs else "; ".join(probs[:5]),
                      {"problems": probs})


def overall_is_mean(board: Board) -> EvalResult:
    """Vals defines the overall score as the mean of the two tracks (checked for all 47 models on
    2026-10-14). If that stops holding, the definition changed or we are reading another field."""
    t = {(r.model_id, r.track): r.accuracy for r in board.rows}
    bad = [m for m in board.models if None in (t.get((m, "overall")), t.get((m, "poc")), t.get((m, "patch")))
           or abs(t[(m, "overall")] - (t[(m, "poc")] + t[(m, "patch")]) / 2) > 0.5]
    return EvalResult("vals_overall_is_mean", ERROR, not bad,
                      "overall = mean of finding and patching for every model" if not bad
                      else f"overall differs from the track mean for {len(bad)}: {', '.join(bad[:4])}", {"models": bad})


def matches_index(board: Board, index_version: str | None, top10: list[tuple[str, float]], names: dict,
                  index_read: bool = False) -> EvalResult:
    """Vals' own index states the top ten. Same version, the same ten scores, and the same names at
    each score (tied scores compared as sets, since their order is arbitrary): otherwise the board
    file is not the one the page shows. An index that answered but carried no top ten is an ERROR,
    because without it a version change would also stand down the rescore and model-count gates."""
    if not top10:
        return EvalResult("vals_matches_index", ERROR if index_read else WARN, False,
                          "vals index answered without a CyberBench top ten (or refused the request)" if index_read else "vals index not reachable this week", {})
    probs = []
    if index_version and index_version != board.version:
        probs.append(f"index version {index_version} vs board {board.version}")
    # names per score over the WHOLE board, so a tie at the tenth place may list either model
    by_score_ix, by_score_us = {}, {}
    for n, p in top10:
        by_score_ix.setdefault(round(p, 2), set()).add(n)
    for r in board.rows:
        if r.track == "overall":
            by_score_us.setdefault(round(r.accuracy, 2), set()).add(names.get(r.model_id, [r.model_id])[0])
    floor = min(by_score_ix)
    above_ix = sum(len(v) for k, v in by_score_ix.items() if k > floor)
    above_us = sum(len(v) for k, v in by_score_us.items() if k > floor)
    if above_ix != above_us:
        probs.append(f"{above_us} board models score above the index's tenth place, the index lists {above_ix}")
    for sc, ix_names in by_score_ix.items():
        ours = by_score_us.get(sc, set())
        if (ix_names != ours) if sc > floor else not ix_names <= ours:
            probs.append(f"at {sc}: index names {sorted(ix_names)}, board names {sorted(ours)}")
    return EvalResult("vals_matches_index", ERROR, not probs,
                      f"top {len(top10)} agree with vals' index (v{board.version})" if not probs else "; ".join(probs[:4]),
                      {"problems": probs})


def names_known(board: Board, names: dict) -> EvalResult:
    """Every model on the board has a display name and a developer in the registry. An unknown id
    is shown under its raw id until someone adds it, and its developer is unknown, so the
    independence check cannot see it: WARN so it gets added the same week."""
    missing = [m for m in board.models if m not in names]
    return EvalResult("vals_names_known", WARN, not missing,
                      "every board model has a name and developer" if not missing
                      else f"{len(missing)} new model id(s) need a name and developer: {', '.join(missing[:6])}", {"missing": missing})


def no_silent_rescore(board: Board, previous: dict) -> EvalResult:
    """Same board version, same model, same track: the score must not move by more than 3 SE.
    `previous` maps (model, track) -> (accuracy, stderr) from the last stored snapshot of this
    version. A version change starts a new series and is not compared."""
    moves = []
    for r in board.rows:
        p = previous.get((r.model_id, r.track))
        if not p or r.accuracy is None:
            continue
        se = max(r.stderr or 0, p[1] or 0, 1.0)
        if abs(r.accuracy - p[0]) > JUMP_SE * se:
            moves.append(f"{r.track}/{r.model_id}: {p[0]:.1f} -> {r.accuracy:.1f}")
    return EvalResult("vals_no_silent_rescore", ERROR, not moves,
                      f"no score moved more than {JUMP_SE:g} SE within v{board.version}" if not moves else "; ".join(moves[:5]),
                      {"moves": moves})


def model_count(board: Board, previous_count: int | None) -> EvalResult:
    """A board that loses more than a fifth of its models in a week is a broken read."""
    n = len(board.models)
    if not previous_count:
        return EvalResult("vals_model_count", INFO, True, f"{n} models (first snapshot of v{board.version})", {"n": n})
    ok = n >= previous_count * (1 - MODEL_DROP)
    return EvalResult("vals_model_count", ERROR, ok, f"{n} models (was {previous_count})", {"n": n, "previous": previous_count})


def error_share(board: Board) -> EvalResult:
    """Tasks that ended in an error count as failures on the board. Where they are a large share,
    the score measures the harness or the provider: flagged, not hidden."""
    hi = sorted({f"{r.model_id} ({r.track} {r.n_errors}/{r.n_tasks})" for r in board.rows
                 if r.track != "overall" and r.n_tasks and r.n_errors / r.n_tasks > ERROR_SHARE})
    return EvalResult("vals_error_share", WARN, not hi,
                      f"no model has more than {ERROR_SHARE:.0%} errored tasks" if not hi
                      else f"{len(hi)} model-track(s) over {ERROR_SHARE:.0%} errored, flagged: {', '.join(hi[:4])}", {"models": hi})


def independence(rows: list[dict], evaluators: dict) -> EvalResult:
    """No stored result may come from an evaluator that develops the model. Checked again here on
    the rows about to be written, fetched and curated alike, after registry validation."""
    bad = [f"{r['benchmark_id']}/{r['model']}" for r in rows
           if is_self_evaluation(r.get("developer"), evaluators.get(r["evaluator_id"], {}).get("develops_models", []))]
    return EvalResult("independent_only", ERROR, not bad,
                      f"all {len(rows)} results come from evaluators that did not build the model" if not bad
                      else f"{len(bad)} self-evaluation(s): {', '.join(bad[:4])}", {"rows": bad})


def staleness(latest: dict[str, str], today_iso: str, days: int = 365) -> EvalResult:
    """A benchmark whose newest independent result is over a year old is drawn faded on the page;
    this says which, so someone looks for a newer report or retires it."""
    import datetime as dt
    t = dt.date.fromisoformat(today_iso)
    old = sorted(b for b, d in latest.items() if (t - dt.date.fromisoformat(d)).days > days)
    return EvalResult("stale_benchmarks", WARN, not old,
                      "every benchmark has a result from the last 12 months" if not old else f"no result in 12 months: {', '.join(old)}",
                      {"stale": old})


def candidates_found(new: list, errors: dict[str, str]) -> EvalResult:
    """New candidate benchmarks wait for a person. A source that failed is named, so a week of
    silence from discovery is not mistaken for 'nothing new'."""
    msg = f"{len(new)} new candidate benchmark(s) to review" if new else "no new candidate benchmarks"
    if errors:
        msg += "; discovery sources failed: " + ", ".join(f"{k} ({v[:60]})" for k, v in errors.items())
    return EvalResult("discovery", WARN, not new and not errors, msg, {"new": [c.url for c in new], "errors": errors})


def document_sane(doc: dict | None) -> EvalResult:
    """After the write, the page document builds and carries benchmarks and results on both sides."""
    if not doc:
        return EvalResult("document_sane", ERROR, False, "the page document did not build", {})
    sides = {b.get("side") for b in doc.get("benchmarks", [])}
    ok = bool(doc.get("results")) and sides >= {"offence", "defence"}
    return EvalResult("document_sane", ERROR, ok,
                      f"{len(doc.get('benchmarks', []))} benchmarks, {len(doc.get('results', []))} results, sides {sorted(sides)}",
                      {"sides": sorted(sides)})


#: The vals board must have been read successfully within this many days; past it the cost chart
#: and the CyberBench rows are stale and the run fails, so the watchdog sees it.
BOARD_MAX_AGE_DAYS = 21


def board_fresh(last_ok: str | None, today_iso: str) -> EvalResult:
    """The last successful read of the vals board, this run's or an earlier one. A week's outage is a
    WARN elsewhere; three weeks without a board is an ERROR, so a permanent block does not hide."""
    import datetime as dt
    if not last_ok:
        return EvalResult("vals_board_fresh", ERROR, False, "the vals board has never been read", {})
    age = (dt.date.fromisoformat(today_iso) - dt.date.fromisoformat(last_ok[:10])).days
    return EvalResult("vals_board_fresh", ERROR, age <= BOARD_MAX_AGE_DAYS,
                      f"vals board last read {age} day(s) ago (limit {BOARD_MAX_AGE_DAYS})", {"last_ok": last_ok, "age_days": age})


#: Checks whose detail can carry vals.ai board content (scores, model ids). The board is all rights
#: reserved, and the pipeline runs in a public repository: their detail goes to the database only.
PRIVATE_DETAIL = {"run_completed", "vals_board_read", "vals_board_shape", "vals_overall_is_mean", "vals_matches_index", "vals_names_known",
                  "vals_no_silent_rescore", "vals_model_count", "vals_error_share", "independent_only", "registry_valid"}


def public_summary(r: EvalResult) -> str:
    """What may be printed to a public log or step summary: for a check that can carry board content,
    pass or fail with a count only; otherwise the summary with markdown table syntax and workflow
    commands neutralised."""
    if r.name in PRIVATE_DETAIL:
        if r.passed:
            return "ok"
        n = next((len(v) for v in (r.detail or {}).values() if isinstance(v, list)), None)
        return (f"{n} problem(s)" if n else "failed") + "; detail in the run record (not printed: licensed data)"
    s = " ".join(str(r.summary).split()).replace("|", "\\|")
    return s[2:] if s.startswith("::") else s
