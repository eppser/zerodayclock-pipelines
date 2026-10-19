"""The curated registry: evaluators, benchmarks, results from published reports, and timeline events.

Everything a person decides lives here, in four JSON files under `registry/`, and is checked by
`validate()` before any run writes and by the test suite before any change merges. A benchmark is
added by editing `benchmarks.json`; the pipeline never adds one by itself (discovery only proposes).

THE INDEPENDENCE RULE IS TESTED ON EVERY RESULT, not on every benchmark: a result counts only if
its evaluator did not develop the model and was not commissioned by the developer. A benchmark
written by a company that also builds models stays, but its scores for that company's models are
refused.

A RESULT IS VERIFIED ONLY WITH A QUOTE. `evidence` is the passage of the source that states the
number, and `validate()` checks that the number (or the k-of-n count it comes from) is in it.
"""

from __future__ import annotations

import datetime as dt
import json
import math
import pathlib
import re

DIR = pathlib.Path(__file__).parent / "registry"

EVALUATOR_KINDS = {"independent", "government", "academic", "vendor_research"}
SIDES = {"offence", "defence"}
# percent: share of tasks solved. points: share of points with partial credit or best of N attempts,
# on a 0-100 scale but not a pass rate. reward: a 0-1 partial-credit score.
UNITS = {"percent": 100.0, "points": 100.0, "reward": 1.0}
SOURCES = {"vals", "curated"}
REPUBLISH = {"allowed", "cite", "pending", "denied"}
STATUSES = {"active", "retired"}
LANES = {"government", "benchmark"}
PRECISION = {"day", "month"}
ISO = re.compile(r"^\d{4}-\d{2}-\d{2}$")
NUM = re.compile(r"(?<![\d.])\d+(?:\.\d+)?")


def load(directory: pathlib.Path = DIR) -> dict:
    return {name: json.loads((directory / f"{name}.json").read_text()) for name in
            ("evaluators", "benchmarks", "results", "events", "model_names")}


def _date(s, field, where, problems, today):
    if not isinstance(s, str) or not ISO.match(s):
        problems.append(f"{where}: {field} {s!r} is not YYYY-MM-DD")
        return None
    try:
        d = dt.date.fromisoformat(s)
    except ValueError:
        problems.append(f"{where}: {field} {s!r} is not a real date")
        return None
    if d > today:
        problems.append(f"{where}: {field} {s} is in the future")
    return d


def _https(u, where, problems):
    if not isinstance(u, str) or not u.startswith("https://") or " " in u:
        problems.append(f"{where}: source URL {u!r} must be an https URL")


def _norm(s) -> str:
    # all whitespace removed, as in the SQL read (0129): "Lab Co", "Lab\tCo" and "LabCo" are one name
    return "".join(str(s or "").split()).lower()


def is_self_evaluation(developer, develops_models) -> bool:
    """The evaluator builds this model, compared without case or spacing. An undisclosed developer
    from an evaluator that builds models also counts: its independence cannot be shown."""
    if not isinstance(develops_models, (list, tuple, set)):
        develops_models = []
    own = {_norm(d) for d in develops_models}
    return _norm(developer) in own or (bool(own) and _norm(developer) in ("undisclosed", "", "unknown"))


def evidence_states(evidence: str, score: float, n: int | None, scale: float) -> bool:
    """The quote must state the number: the score itself (as written, to the precision given), or a
    k of n count (k/n or 'k of those n') whose share is the score."""
    nums = [float(x) for x in NUM.findall(evidence or "")]
    if any(abs(x - score) < 1e-9 for x in nums):
        return True
    if n:
        return any(abs(k / n * scale - score) < 0.006 * scale for k in nums if k <= n)
    return False


def validate(reg: dict, today: dt.date | None = None) -> list[str]:
    """Every problem with the registry, as readable lines; empty means valid."""
    today = today or dt.date.today()
    p: list[str] = []
    ev = {e.get("id"): e for e in reg["evaluators"]}
    if len(ev) != len(reg["evaluators"]):
        p.append("evaluators: duplicate id")
    for e in reg["evaluators"]:
        w = f"evaluator {e.get('id')}"
        if e.get("kind") not in EVALUATOR_KINDS:
            p.append(f"{w}: kind {e.get('kind')!r} not in {sorted(EVALUATOR_KINDS)}")
        if not isinstance(e.get("develops_models"), list):
            p.append(f"{w}: develops_models must be a list (empty if it builds no models)")
        _https(e.get("url"), w, p)

    bm = {b.get("id"): b for b in reg["benchmarks"]}
    if len(bm) != len(reg["benchmarks"]):
        p.append("benchmarks: duplicate id")
    vals_tracks = set()
    for b in reg["benchmarks"]:
        w = f"benchmark {b.get('id')}"
        if b.get("side") not in SIDES:
            p.append(f"{w}: side {b.get('side')!r} must be offence or defence")
        if b.get("unit") not in UNITS:
            p.append(f"{w}: unit {b.get('unit')!r} not in {sorted(UNITS)}")
        elif b.get("scale_max") != UNITS[b["unit"]]:
            p.append(f"{w}: scale_max {b.get('scale_max')} must be {UNITS[b['unit']]} for unit {b['unit']}")
        if b.get("evaluator") not in ev:
            p.append(f"{w}: evaluator {b.get('evaluator')!r} is not in evaluators.json")
        if b.get("source") not in SOURCES:
            p.append(f"{w}: source {b.get('source')!r} not in {sorted(SOURCES)}")
        if b.get("source") == "vals":
            if b.get("track") not in ("poc", "patch") or b.get("series") != "vals-cyberbench":
                p.append(f"{w}: a vals benchmark needs series vals-cyberbench and track poc or patch")
            if (b.get("series"), b.get("track")) in vals_tracks:
                p.append(f"{w}: series and track already used by another benchmark")
            vals_tracks.add((b.get("series"), b.get("track")))
        if b.get("republish") not in REPUBLISH:
            p.append(f"{w}: republish {b.get('republish')!r} not in {sorted(REPUBLISH)}")
        if b.get("status") not in STATUSES:
            p.append(f"{w}: status {b.get('status')!r} not in {sorted(STATUSES)}")
        if b.get("tasks") is not None and (not isinstance(b["tasks"], int) or b["tasks"] <= 0):
            p.append(f"{w}: tasks must be a positive integer or null")
        if not b.get("name") or not b.get("skill") or len(b.get("skill", "")) > 110:
            p.append(f"{w}: needs a name and a one-line skill (110 characters at most)")
        _https(b.get("url"), w, p)

    seen = set()
    for i, r in enumerate(reg["results"]):
        w = f"result {i} ({r.get('benchmark')} / {r.get('model')})"
        b = bm.get(r.get("benchmark"))
        if not b:
            p.append(f"{w}: benchmark is not in benchmarks.json")
            continue
        if b.get("source") != "curated":
            p.append(f"{w}: results for a {b.get('source')} benchmark come from its fetcher, not the registry")
        key = (r.get("benchmark"), r.get("version"), r.get("model"))
        if key in seen:
            p.append(f"{w}: duplicate of an earlier result")
        seen.add(key)
        if not r.get("version") or not r.get("model") or not r.get("developer"):
            p.append(f"{w}: needs version, model and developer ('undisclosed' when the source names none)")
        sc, scale = r.get("score"), b.get("scale_max", 100)
        if not isinstance(sc, (int, float)) or not 0 <= sc <= scale:
            p.append(f"{w}: score {sc!r} outside 0..{scale}")
            continue
        ci = r.get("ci")
        if ci is not None and (len(ci) != 2 or not 0 <= ci[0] <= sc + 1e-9 or not sc - 1e-9 <= ci[1] <= scale):
            p.append(f"{w}: interval {ci} must contain the score and lie within 0..{scale}")
        for f in ("stderr", "cost_per_task"):
            if r.get(f) is not None and (not isinstance(r[f], (int, float)) or not math.isfinite(r[f]) or r[f] < 0):
                p.append(f"{w}: {f} must be a finite number >= 0")
        if ci is not None and not all(isinstance(x, (int, float)) and math.isfinite(x) for x in ci):
            p.append(f"{w}: interval must be finite numbers")
        if r.get("n") is not None and (not isinstance(r["n"], int) or r["n"] <= 0):
            p.append(f"{w}: n must be a positive integer")
        _date(r.get("published_on"), "published_on", w, p, today)
        _https(r.get("source_url"), w, p)
        e = ev.get(b.get("evaluator"), {})
        if is_self_evaluation(r.get("developer"), e.get("develops_models", [])):
            p.append(f"{w}: the evaluator ({e.get('id')}) develops this model: a self-evaluation cannot be recorded")
        if r.get("commissioned_by_developer"):
            p.append(f"{w}: commissioned by the model's developer: not independent")
        if r.get("verified_on"):
            _date(r.get("verified_on"), "verified_on", w, p, today)
            if not evidence_states(r.get("evidence", ""), sc, r.get("n"), scale):
                p.append(f"{w}: the evidence quote does not state {sc} (nor a count giving it)")

    ids = set()
    for e in reg["events"]:
        w = f"event {e.get('id')}"
        if e.get("id") in ids:
            p.append(f"{w}: duplicate id")
        ids.add(e.get("id"))
        _date(e.get("date"), "date", w, p, today)
        if e.get("precision") not in PRECISION:
            p.append(f"{w}: precision must be day or month")
        if e.get("lane") not in LANES:
            p.append(f"{w}: lane {e.get('lane')!r} must be government or benchmark")
        if e.get("evaluator") not in ev:
            p.append(f"{w}: evaluator {e.get('evaluator')!r} is not in evaluators.json")
        if not e.get("title") or not e.get("detail") or len(e.get("detail", "")) > 200:
            p.append(f"{w}: needs a title and a one-sentence finding (200 characters at most)")
        _https(e.get("source_url"), w, p)
        if e.get("verified_on") and not (e.get("evidence") or "").strip():
            p.append(f"{w}: verified without an evidence quote")

    names = reg.get("model_names", {})
    for k, v in names.items():
        if not isinstance(v, list) or len(v) != 2 or not all(isinstance(x, str) and x for x in v):
            p.append(f"model name {k}: must be [display name, developer]")
    return p


def benchmark_by_id(reg: dict) -> dict:
    return {b["id"]: b for b in reg["benchmarks"]}


def evaluator_by_id(reg: dict) -> dict:
    return {e["id"]: e for e in reg["evaluators"]}
