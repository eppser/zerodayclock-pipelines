"""Persistence for the AI cyber capability tracker (migration 0129)."""

from __future__ import annotations

from psycopg.types.json import Jsonb


def replace_registry(conn, reg: dict) -> None:
    """The curated tables are configuration: replaced whole from the registry files, in the run's
    transaction, so the page never sees half of an edit."""
    with conn.cursor() as cur:
        cur.execute("delete from aicap.events")
        cur.execute("delete from aicap.benchmarks")
        cur.execute("delete from aicap.evaluators")
        cur.executemany("insert into aicap.evaluators (id, name, kind, url, develops_models, note) values (%s,%s,%s,%s,%s,%s)",
                        [(e["id"], e["name"], e["kind"], e["url"], e["develops_models"], e.get("note")) for e in reg["evaluators"]])
        cur.executemany("""insert into aicap.benchmarks (id, name, side, skill, unit, scale_max, tasks, evaluator, source, series,
                                                         track, url, licence, republish, status)
                           values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                        [(b["id"], b["name"], b["side"], b["skill"], b["unit"], b["scale_max"], b.get("tasks"), b["evaluator"],
                          b["source"], series_of(b), track_of(b), b["url"], b["licence"], b["republish"], b["status"]) for b in reg["benchmarks"]])
        cur.executemany("""insert into aicap.events (id, date, precision, lane, evaluator, title, detail, source_url, verified_on)
                           values (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                        [(e["id"], e["date"], e["precision"], e["lane"], e["evaluator"], e["title"], e["detail"],
                          e["source_url"], e.get("verified_on")) for e in reg["events"]])


def series_of(b: dict) -> str:
    return b.get("series") or b["id"]


def track_of(b: dict) -> str:
    return b.get("track") or "main"


def insert_fetch(conn, run_id: str, f: dict) -> str:
    with conn.cursor() as cur:
        cur.execute("""insert into aicap.fetches (run_id, source, url, ok, http_status, bytes, sha256, error, notes)
                       values (%s,%s,%s,%s,%s,%s,%s,%s,%s) returning fetch_id""",
                    (run_id, f["source"], f["url"], f["ok"], f.get("status"), f.get("bytes"), f.get("sha256"), f.get("error"),
                     Jsonb(f.get("notes", {}))))
        return str(cur.fetchone()[0])


COLS = ("run_id", "fetch_id", "benchmark_id", "version", "track", "model", "model_label", "developer", "evaluator_id", "score",
        "stderr", "ci_low", "ci_high", "n", "n_errors", "cost_per_task", "published_on", "source_url", "origin", "verified",
        "evidence", "conditions")


def insert_observations(conn, rows: list[dict]) -> int:
    with conn.cursor() as cur:
        cur.executemany(f"insert into aicap.observations ({', '.join(COLS)}) values ({', '.join(['%s'] * len(COLS))})",
                        [[r.get(c) for c in COLS] for r in rows])
    return len(rows)


def previous_vals(conn, version: str) -> tuple[dict, int | None]:
    """The last stored snapshot of this vals board version: (model, track) -> (score, stderr), and
    its model count. Empty for a version never stored."""
    with conn.cursor() as cur:
        cur.execute("""select run_id from aicap.observations where origin = 'fetched' and version = %s
                        order by observed_at desc limit 1""", (version,))
        r = cur.fetchone()
        if not r:
            return {}, None
        cur.execute("""select model, track, score, stderr from aicap.observations
                        where run_id = %s and origin = 'fetched' and benchmark_id = 'vals-cyberbench'""", (r[0],))
        rows = cur.fetchall()
    prev = {(m, t): (float(s), float(se) if se is not None else None) for m, t, s, se in rows}
    return prev, len({m for m, *_ in rows})


def upsert_candidates(conn, cands: list) -> list:
    """Store candidates; return the ones never seen before (the review list)."""
    new = []
    with conn.cursor() as cur:
        for c in cands:
            cur.execute("""insert into aicap.candidates (url, title, source, published, summary) values (%s,%s,%s,%s,%s)
                           on conflict (url) do update set last_seen = now() returning (xmax = 0)""",
                        (c.url, c.title[:300], c.source, c.published, c.summary[:300] or None))
            if cur.fetchone()[0]:
                new.append(c)
    return new


def document(conn) -> dict | None:
    with conn.cursor() as cur:
        cur.execute("select public.aicap_document()")
        r = cur.fetchone()
    return r[0] if r else None


def previous_model_count(conn) -> int | None:
    """The model count of the last stored vals board, any version: a new version that arrives with
    far fewer models is still a broken read."""
    with conn.cursor() as cur:
        cur.execute("""select count(distinct model) from aicap.observations where run_id = (
                         select run_id from aicap.observations where origin = 'fetched' and benchmark_id = 'vals-cyberbench'
                          order by observed_at desc limit 1) and origin = 'fetched'""")
        n = cur.fetchone()[0]
    return n or None


def first_seen(conn, version: str) -> dict:
    """(model, track) -> the date a model's score first appeared on this board version. Within a
    version a score cannot move (the rescore gate), so this is when the result became available:
    the date the six-month tick compares on. Without it every row would carry this week's date."""
    with conn.cursor() as cur:
        cur.execute("""select model, track, min(published_on)::text from aicap.observations
                        where origin = 'fetched' and benchmark_id = 'vals-cyberbench' and version = %s
                        group by model, track""", (version,))
        return {(m, t): d for m, t, d in cur.fetchall()}


def last_ok_board(conn) -> str | None:
    """When the vals board was last read successfully, from the fetch record."""
    with conn.cursor() as cur:
        # a board counts as read only once its scores were stored: a fetch that failed a gate is not one
        cur.execute("""select max(observed_at)::date::text from aicap.observations
                        where origin = 'fetched' and benchmark_id = 'vals-cyberbench'""")
        return cur.fetchone()[0]
