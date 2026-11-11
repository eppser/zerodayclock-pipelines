"""vals.ai CyberBench: the board its page publishes, read once a week.

Vals publishes no API (checked 2026-10-14). The page embeds a static JSON file whose name carries a
build hash (`/_astro/benchmark_view_cyberbench.<hash>.json`), so every run reads the page to find
the current name. Vals' machine-readable index (`/llms-full.txt`, "regenerated with each results
export") states the top ten; it is read too and must agree with the JSON, which catches a parser
reading the wrong file or the wrong field.

Licence: "All rights reserved", no terms page. The board is shown on staging only until Vals AI
grants permission (benchmarks.json republish: pending); production must not render it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

PAGE = "https://www.vals.ai/benchmarks/cyber"
INDEX = "https://www.vals.ai/llms-full.txt"
BASE = "https://www.vals.ai"
JSON_PATH = re.compile(r"/_astro/benchmark_view_cyberbench\.[A-Za-z0-9_-]+\.json")
TRACKS = ("overall", "poc", "patch")


@dataclass
class Row:
    model_id: str
    track: str
    accuracy: float
    stderr: float | None
    cost: float | None
    latency_s: float | None
    provider: str | None
    n_tasks: int
    n_errors: int
    n_passed: int


@dataclass
class Board:
    version: str
    updated: str
    title: str
    rows: list[Row] = field(default_factory=list)
    models: list[str] = field(default_factory=list)


def json_paths(html: str) -> list[str]:
    """Every distinct board-file path the page names. More than one is ambiguous and refused."""
    return sorted(set(JSON_PATH.findall(html or "")))


def _num(v):
    # json.loads accepts NaN and Infinity; a non-finite number would disable every numeric gate
    import math
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) else None


def parse(doc: dict) -> Board:
    """The board as rows per (model, track). Raises ValueError on any missing structure, so a
    changed format stops the run instead of writing half a board."""
    if not isinstance(doc, dict):
        raise ValueError("board file is not an object")
    md, tasks = doc.get("metadata"), doc.get("tasks")
    if not isinstance(md, dict) or not isinstance(tasks, dict):
        raise ValueError("board file has no metadata/tasks")
    for t in TRACKS:
        if not isinstance(tasks.get(t), dict) or not tasks[t]:
            raise ValueError(f"board file has no {t!r} track")
    version, updated = str(md.get("version") or ""), str(md.get("updated") or "")
    if not version or not re.match(r"^\d{4}-\d{2}-\d{2}$", updated):
        raise ValueError(f"board metadata lacks a version or an updated date ({version!r}, {updated!r})")
    board = Board(version=version, updated=updated, title=str(md.get("benchmark") or ""),
                  models=sorted(tasks["overall"]))
    for t in TRACKS:
        for mid, r in tasks[t].items():
            if not isinstance(r, dict):
                raise ValueError(f"{t}: a model entry is not an object")
            acc = _num(r.get("accuracy"))
            if acc is None:
                raise ValueError(f"{t}/{mid}: accuracy missing")
            tr = r.get("task_results") or {}
            board.rows.append(Row(
                model_id=mid, track=t, accuracy=acc, stderr=_num(r.get("stderr")), cost=_num(r.get("cost_per_test")),
                latency_s=_num(r.get("latency")), provider=r.get("provider"), n_tasks=len(tr),
                n_errors=sum(1 for v in tr.values() if isinstance(v, dict) and v.get("status") == "error"),
                n_passed=sum(1 for v in tr.values() if isinstance(v, dict) and v.get("passed") is True)))
    return board


def top10_from_index(text: str, version: str | None = None) -> tuple[str | None, list[tuple[str, float]]]:
    """(version, [(display name, percent)]) from the CyberBench section of llms-full.txt.

    Since 2026-11 the index carries one section per version: `CyberBench v1` (archived, 26 models,
    frozen) ABOVE `CyberBench v1.1` (live). Taking the first section compared the live board with
    the archived top ten and blocked the 2026-11-09 run. The section is chosen by `version` (the
    board's); without one, the live section wins over an archived one, then the highest version."""
    sections = []
    for m in re.finditer(r"^## CyberBench v?([\w.]+)\s*$(.*?)(?=^## |\Z)", text or "", re.M | re.S):
        ver, body = m.group(1), m.group(2)
        archived = bool(re.search(r"^- Category:.*archived", body, re.M | re.I))
        sections.append((ver, archived, body))
    if not sections:
        return None, []
    if version is not None and any(v == version for v, _a, _b in sections):
        ver, _archived, body = next(s for s in sections if s[0] == version)
    else:
        live = [s for s in sections if not s[1]] or sections
        ver, _archived, body = max(live, key=lambda s: _version_key(s[0]))
    rows = re.findall(r"^\d+\.\s+\[(.+?)\]\((.*?)\):\s*([\d.]+)%\s*$", body, re.M)
    if len(rows) != len(re.findall(r"^\d+\.\s", body, re.M)):
        raise ValueError("the index's top-ten list changed format")
    return ver, [(n.strip(), float(p)) for n, _u, p in rows]


def _version_key(v: str) -> tuple:
    return tuple(int(x) if x.isdigit() else x for x in re.split(r"[.]", v))
