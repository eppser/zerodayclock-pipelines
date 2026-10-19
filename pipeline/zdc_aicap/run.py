"""AI cyber capability tracker: weekly.

    python -m zdc_aicap.run                    # read sources, check, write
    python -m zdc_aicap.run --no-write         # read and check, write nothing
    python -m zdc_aicap.run --skip-discovery

One run: validate the curated registry; read vals.ai's CyberBench board (and its index, which must
agree); search arXiv, GitHub, Hugging Face and vals' index for candidate new benchmarks; run every
gate; then, if nothing blocks, write the registry, the run's observations and the candidates in one
transaction and check that the page document builds. Nothing a lab reports about its own model is
read or stored.

WEEKLY because the sources change weekly at most: vals updates its board when it adds models
(several a month), government reports arrive about monthly, papers whenever. A missed week loses
nothing: every source keeps its history.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import uuid
import json
import logging
import os
import sys
import time

import httpx

from zdc_crowdsec.evals import ERROR, WARN, EvalResult

from . import checks, discover, registry, source_vals

PIPELINE = "aicap"
UA = "zerodayclock.com research (sergej.epp@zerodayclock.com)"
log = logging.getLogger("zdc_aicap")


class TooLarge(Exception):
    """Not a network failure: nothing that big is a board. Never retried, never an outage."""


class TooSlow(Exception):
    """A response still dripping past the deadline. Never retried."""


class Http:
    """GET with a polite user agent, a timeout and two retries on transient failures."""

    def __init__(self, token: str | None = None, transport: httpx.BaseTransport | None = None):
        h = {"User-Agent": UA}
        self._gh = {"Authorization": f"Bearer {token}"} if token else {}
        self.c = httpx.Client(headers=h, timeout=httpx.Timeout(30, connect=15), follow_redirects=True, transport=transport)

    MAX_BYTES = 20_000_000       # the board is about 2 MB; anything near this is not a board
    DEADLINE_S = 120             # per request, across a slow drip

    def _get_once(self, url: str, github: bool) -> httpx.Response:
        start, chunks, size = time.monotonic(), [], 0
        with self.c.stream("GET", url, headers=self._gh if github else None) as r:
            for chunk in r.iter_bytes():
                size += len(chunk)
                if size > self.MAX_BYTES:
                    raise TooLarge(f"response over {self.MAX_BYTES} bytes")
                if time.monotonic() - start > self.DEADLINE_S:
                    raise TooSlow("response deadline passed")
                chunks.append(chunk)
            # iter_bytes() has already decoded gzip/deflate: drop the encoding headers, or the new
            # Response would decode the plain body a second time and fail
            hdrs = [(k, v) for k, v in r.headers.multi_items()
                    if k.lower() not in ("content-encoding", "content-length", "transfer-encoding")]
            return httpx.Response(r.status_code, headers=hdrs, content=b"".join(chunks), request=r.request)

    def get(self, url: str, github: bool = False) -> httpx.Response:
        last = None
        for i in range(3):
            try:
                r = self._get_once(url, github)
                if r.status_code in (429, 500, 502, 503, 504) and i < 2:
                    time.sleep(2 ** i * 3)
                    continue
                return r
            except httpx.HTTPError as e:
                last = e
                time.sleep(2 ** i * 3)
        raise last or RuntimeError(f"GET {url} failed")


def fetch_record(source: str, url: str, r: httpx.Response | None, error: str | None = None, notes: dict | None = None) -> dict:
    body = r.content if r is not None else b""
    return {"source": source, "url": url, "ok": r is not None and r.status_code == 200 and error is None,
            "status": r.status_code if r is not None else None, "bytes": len(body),
            "sha256": hashlib.sha256(body).hexdigest() if body else None, "error": error, "notes": notes or {}}


def read_vals(http: Http) -> dict:
    """The board, the index's top ten, and the fetch records. `net_error` is set when vals could not
    be reached at all (keep last week's board); `parse_error` when it answered but did not parse."""
    out = {"fetches": [], "board": None, "paths": [], "index_version": None, "top10": [], "net_error": None, "parse_error": None,
           "index_text": ""}
    try:
        page = http.get(source_vals.PAGE)
    except httpx.HTTPError as e:     # recorded, not raised: the rest of the run goes on
        out["net_error"] = f"{type(e).__name__}"
        out["fetches"].append(fetch_record("vals-page", source_vals.PAGE, None, out["net_error"]))
        return out
    except (TooLarge, TooSlow) as e:
        out["parse_error"] = f"page {type(e).__name__}"
        out["fetches"].append(fetch_record("vals-page", source_vals.PAGE, None, out["parse_error"]))
        return out
    out["fetches"].append(fetch_record("vals-page", source_vals.PAGE, page))
    if page.status_code == 429 or page.status_code >= 500:
        out["net_error"] = f"page HTTP {page.status_code}"
        return out
    if page.status_code != 200:
        out["parse_error"] = f"page HTTP {page.status_code}"         # moved or blocked: not a passing outage
        return out
    out["paths"] = source_vals.json_paths(page.text)
    if len(out["paths"]) != 1:
        out["parse_error"] = "the page does not name exactly one board file"
        return out
    url = source_vals.BASE + out["paths"][0]
    try:
        r = http.get(url)
        out["fetches"].append(fetch_record("vals-board", url, r))
        if r.status_code in (429,) or r.status_code >= 500:
            out["net_error"] = f"board HTTP {r.status_code}"          # an outage: keep last week's board
            return out
        if r.status_code != 200:
            out["parse_error"] = f"board HTTP {r.status_code}"        # the page names a file that is not there
            return out
        out["board"] = source_vals.parse(r.json())
    except httpx.HTTPError as e:
        out["net_error"] = f"board {type(e).__name__}"           # unreachable: keep last week's board
        return out
    except Exception as e:  # noqa: BLE001 - anything else means the file is not what we expect
        out["parse_error"] = f"{type(e).__name__}: {str(e)[:160]}"
        if out["fetches"] and out["fetches"][-1]["source"] == "vals-board":
            out["fetches"][-1].update(ok=False, error=out["parse_error"][:200])   # fetched, but not a board
        return out
    try:
        ix = http.get(source_vals.INDEX)
        out["fetches"].append(fetch_record("vals-index", source_vals.INDEX, ix))
        out["index_read"] = ix.status_code == 200
        # answered, but not with the index (moved, blocked, gone): the cross-check must not stand down quietly
        out["index_refused"] = ix.status_code != 200 and ix.status_code != 429 and ix.status_code < 500
        if ix.status_code == 200:
            out["index_text"] = ix.text
            try:
                out["index_version"], out["top10"] = source_vals.top10_from_index(ix.text)
            except ValueError:
                pass            # index_read and no top ten: the index gate reports it as an ERROR
    except Exception as e:  # noqa: BLE001
        out["fetches"].append(fetch_record("vals-index", source_vals.INDEX, None, type(e).__name__))
    return out


def discover_all(http: Http, today: dt.date, index_text: str, known_titles: set[str]) -> tuple[list, dict]:
    since = today - dt.timedelta(days=14)
    found, errors = [], {}
    steps = [
        ("arxiv", lambda: discover.parse_arxiv(http.get(discover.arxiv_query()).text, since)),
        ("github", lambda: discover.parse_github(http.get(discover.github_query(since), github=True).json())),
        ("huggingface", lambda: discover.parse_hf(http.get(discover.hf_query()).json(), since)),
        ("vals-index", lambda: discover.parse_vals_index(index_text, known_titles)),
    ]
    for name, fn in steps:
        try:
            found += fn()
        except Exception as e:  # noqa: BLE001 - one source failing must not hide the others
            errors[name] = f"{type(e).__name__}: {str(e)[:80]}"
    seen, uniq = set(), []
    for c in found:
        if c.url and c.url not in seen:
            seen.add(c.url)
            uniq.append(c)
    return uniq, errors


def curated_rows(reg: dict, run_id: str) -> list[dict]:
    bm, ev = registry.benchmark_by_id(reg), registry.evaluator_by_id(reg)
    rows = []
    for r in reg["results"]:
        b = bm[r["benchmark"]]
        ci = r.get("ci") or [None, None]
        rows.append({"run_id": run_id, "fetch_id": None, "benchmark_id": b.get("series") or b["id"], "version": r["version"],
                     "track": b.get("track") or "main", "model": r["model"], "model_label": r["model"], "developer": r["developer"],
                     "evaluator_id": b["evaluator"], "score": r["score"], "stderr": r.get("stderr"), "ci_low": ci[0], "ci_high": ci[1],
                     "n": r.get("n"), "n_errors": None, "cost_per_task": r.get("cost_per_task"), "published_on": r["published_on"],
                     "source_url": r["source_url"], "origin": "curated", "verified": bool(r.get("verified_on")),
                     "evidence": r.get("evidence"), "conditions": r.get("conditions")})
        assert ev[b["evaluator"]]
    return rows


def vals_rows(board, names: dict, run_id: str, fetch_id: str | None) -> list[dict]:
    rows = []
    for r in board.rows:
        label, dev = names.get(r.model_id, [r.model_id, r.provider or "unknown"])
        rows.append({"run_id": run_id, "fetch_id": fetch_id, "benchmark_id": "vals-cyberbench", "version": board.version,
                     "track": r.track, "model": r.model_id, "model_label": label, "developer": dev, "evaluator_id": "vals",
                     "score": round(r.accuracy, 3), "stderr": None if r.stderr is None else round(r.stderr, 3), "ci_low": None,
                     "ci_high": None, "n": r.n_tasks or None, "n_errors": r.n_errors, "cost_per_task": r.cost,
                     "published_on": board.updated, "source_url": source_vals.PAGE, "origin": "fetched", "verified": True,
                     "evidence": None, "conditions": None})
    return rows


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="zdc-aicap")
    ap.add_argument("--no-write", action="store_true", help="read and check, write nothing")
    ap.add_argument("--skip-discovery", action="store_true")
    ap.add_argument("--report")
    ap.add_argument("--trigger", default=os.environ.get("GITHUB_EVENT_NAME", "manual"))
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    return run(args, Http(os.environ.get("GITHUB_TOKEN")), dt.date.today())


def run(args, http: Http, today: dt.date) -> int:
    """One week. The run row is opened as soon as the database is reached and always closed, so a
    crash is seen by the watchdog the same day. Fetches and candidates are committed first, as the
    record; results are written in a savepoint that rolls back alone when a gate blocks."""
    report: dict = {"pipeline": PIPELINE, "started_at": dt.datetime.now(dt.timezone.utc).isoformat(), "checks": []}
    results: list[EvalResult] = []
    conn = rid = None
    writing = not args.no_write
    if writing or os.environ.get("DATABASE_URL"):
        import psycopg
        conn = psycopg.connect(os.environ["DATABASE_URL"], autocommit=False)
    if conn and writing:
        from zdc_kev import db as runs_db
        rid = runs_db.start_run(conn, PIPELINE, "full", args.trigger, os.environ.get("GITHUB_SHA"))
        conn.commit()
    run_ok, rows, v, cands = False, [], {"fetches": []}, []
    try:
        try:
            run_ok, rows, v, cands = _week(args, http, today, conn, rid, results, report)
        except BaseException as e:  # noqa: BLE001 - incl. a cancelled job: the run row is closed below
            try:
                if conn:
                    conn.rollback()
            except Exception:  # noqa: BLE001 - a dead connection is handled in finally
                pass
            run_ok = False
            # the exception text can quote a row (psycopg's DETAIL line), so the full text goes to
            # the private run record only; the public check gets the class and SQLSTATE
            report["error"] = f"{type(e).__name__}: {str(e)[:300]}"
            results.append(EvalResult("run_completed", ERROR, False,
                                      f"{type(e).__name__} (sqlstate {getattr(e, 'sqlstate', None)})", {"error": [report['error']]}))
            if not isinstance(e, Exception):
                raise
    finally:
        blocking = [r for r in results if r.blocking]
        run_ok = run_ok and not blocking
        if rid:
            import psycopg
            c = conn if conn is not None and not conn.closed and not conn.broken else psycopg.connect(os.environ["DATABASE_URL"])
            try:
                runs_db.finish_run(c, rid, ok=run_ok, error=report.get("error") or ("; ".join(b.name for b in blocking) or None),
                                   sources_attempted=len(v["fetches"]), sources_ok=sum(1 for f in v["fetches"] if f.get("ok")),
                                   entries_seen=len(rows), entries_inserted=report.get("written", 0),
                                   # the full check detail, board content included, lives only in the private database
                                   notes={"vals_version": report.get("vals_version"), "candidates_found": len(cands),
                                          "checks": [{"name": r.name, "severity": r.severity, "passed": r.passed, "summary": r.summary}
                                                     for r in results]})
                c.commit()
            finally:
                if c is not conn:
                    c.close()
        if conn and not conn.closed:
            conn.close()
    report.pop("error", None)
    report["checks"] = [{"name": r.name, "severity": r.severity, "passed": r.passed, "summary": checks.public_summary(r)}
                        for r in results]
    report["ok"] = run_ok
    report.pop("error_detail", None)
    for r in results:
        log.info("[%s] %-5s %s: %s", "PASS" if r.passed else "FAIL", r.severity, r.name, checks.public_summary(r))
    if args.report:
        with open(args.report, "w") as f:
            json.dump(report, f, indent=1, default=str)
    return 0 if run_ok else 1


def _week(args, http: Http, today: dt.date, conn, rid, results: list, report: dict):
    reg = registry.load()
    problems = registry.validate(reg, today)
    names = reg["model_names"]
    results.append(checks.registry_valid(problems))

    v = read_vals(http)
    board = v["board"]
    if v["net_error"]:
        results.append(EvalResult("vals_board_read", WARN, False, f"vals not reachable this week ({v['net_error']}); last board kept", {}))
    else:
        results.append(checks.board_read(v["parse_error"], v["paths"]))
    known_titles = {f"CyberBench v{board.version}"} if board else set()
    cands, d_err = ([], {}) if args.skip_discovery else discover_all(http, today, v.get("index_text", ""), known_titles | {"CyberBench v1.1"})

    from . import db
    prev, prev_n, last_ok = {}, None, None
    if conn:
        if board:
            prev, prev_n = db.previous_vals(conn, board.version)
            if not prev_n:
                prev_n = db.previous_model_count(conn)          # a new version is still compared on size
        last_ok = db.last_ok_board(conn)
    if board:
        expected = {b["track"]: b["tasks"] for b in reg["benchmarks"] if b["source"] == "vals"}
        results += [checks.board_shape(board, expected), checks.overall_is_mean(board),
                    checks.matches_index(board, v["index_version"], v["top10"], names, v.get("index_read", False) or v.get("index_refused", False)),
                    checks.names_known(board, names), checks.no_silent_rescore(board, prev), checks.model_count(board, prev_n),
                    checks.error_share(board)]
        last_ok = today.isoformat()
    if conn:
        results.append(checks.board_fresh(last_ok, today.isoformat()))

    rows = curated_rows(reg, rid or str(uuid.uuid4())) if not problems else []
    if board:
        rows += vals_rows(board, names, rid or "", None)
        if conn:
            seen = db.first_seen(conn, board.version)
            for r in rows:
                if r["origin"] == "fetched":
                    r["published_on"] = seen.get((r["model"], r["track"]), r["published_on"])
    results.append(checks.independence(rows, registry.evaluator_by_id(reg)))
    latest = {}
    for r in rows:
        if r["origin"] == "curated" or r["track"] in ("poc", "patch"):
            k = r["benchmark_id"] + ":" + r["track"]
            latest[k] = max(latest.get(k, "0000-00-00"), str(r["published_on"]))
    results.append(checks.staleness(latest, today.isoformat()))
    report.update({"vals_version": board.version if board else None, "vals_models": len(board.models) if board else 0,
                   "curated_results": sum(1 for r in rows if r["origin"] == "curated"), "observations": len(rows),
                   "candidates_found": len(cands)})
    # A vals gate that blocks fails the run (the watchdog and the Actions badge see it) and keeps the
    # board out, but does not hold back this week's curated results, which do not depend on vals.
    vals_blocked = any(r.blocking and r.name.startswith("vals_") for r in results)
    if vals_blocked:
        rows = [r for r in rows if r["origin"] != "fetched"]
    ok = not any(r.blocking for r in results if not r.name.startswith("vals_"))
    if not (conn and rid):
        results.append(checks.candidates_found(cands, d_err))
        return ok, rows, v, cands

    # the record first: every fetch, and the candidate list, committed whatever the gates say
    fetch_ids = [db.insert_fetch(conn, rid, f) for f in v["fetches"]]
    board_fetch = next((fid for fid, f in zip(fetch_ids, v["fetches"]) if f["source"] == "vals-board"), None)
    for r in rows:
        r["run_id"] = rid
        if r["origin"] == "fetched":
            r["fetch_id"] = board_fetch
    try:
        with conn.transaction():
            new = db.upsert_candidates(conn, cands)
    except Exception as e:  # noqa: BLE001 - one bad candidate must not cost the week
        new, d_err = [], {**d_err, "store": f"{type(e).__name__}"}
    results.append(checks.candidates_found(new, d_err))
    report["candidates_new"] = [c.url for c in new]
    conn.commit()
    if not ok:
        return False, rows, v, cands

    class _Blocked(Exception):
        pass
    try:
        with conn.transaction():
            db.replace_registry(conn, reg)
            db.insert_observations(conn, rows)
            report["written"] = len(rows)
            ds = checks.document_sane(db.document(conn))
            results.append(ds)
            if ds.blocking:
                raise _Blocked
    except _Blocked:
        report["written"] = 0
        return False, rows, v, cands
    conn.commit()
    return True, rows, v, cands


if __name__ == "__main__":
    sys.exit(main())
