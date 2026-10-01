"""The two canonical disclaimers must match the specification, character for character.

CLAUDE.md calls these strings normative and forbids paraphrase. A rule like that survives
only if something checks it: the strings are quoted in three places — the specification,
the TypeScript module the site imports, and the Python module the pipeline imports — and
nothing but a test stops them drifting a word apart over a year of edits.

The failure this guards against is not a typo. It is somebody "improving" the wording in
one copy, which turns a normative disclaimer into two different claims shown to two
different audiences about the same number.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

from conftest import requires_repo_files  # noqa: E402

pytestmark = requires_repo_files("CLAUDE.md", "src/lib/disclaimers.ts")

from lib.disclaimers import CVE_NVD_TIMING, DELAYED_EXPLOITATION  # noqa: E402


def _from_spec() -> dict[str, str]:
    md = (ROOT / "CLAUDE.md").read_text()
    section = md[md.index("## The two canonical disclaimers"):md.index("## First principles")]
    blocks = re.findall(r"\*\*(.+?):\*\*\n\n((?:> .*\n)+)", section)
    return {name: " ".join(l.lstrip("> ").rstrip() for l in body.strip().splitlines())
            for name, body in blocks}


def test_spec_still_defines_exactly_two() -> None:
    """If a third is added, or one renamed, this test must be updated deliberately."""
    spec = _from_spec()
    assert sorted(spec) == ["CVE and NVD timing", "Delayed exploitation"], sorted(spec)


def test_python_copy_matches_the_specification() -> None:
    spec = _from_spec()
    assert DELAYED_EXPLOITATION == spec["Delayed exploitation"]
    assert CVE_NVD_TIMING == spec["CVE and NVD timing"]


def test_typescript_copy_matches_the_python_copy() -> None:
    """The site and the pipeline must show the reader the same sentence."""
    ts = (ROOT / "src/lib/disclaimers.ts").read_text()
    found = {}
    for const in ("DELAYED_EXPLOITATION", "CVE_NVD_TIMING"):
        m = re.search(rf"export const {const} = (\".*?\");\n", ts, re.S)
        assert m, f"{const} not exported from src/lib/disclaimers.ts"
        found[const] = json.loads(m.group(1))
    assert found["DELAYED_EXPLOITATION"] == DELAYED_EXPLOITATION
    assert found["CVE_NVD_TIMING"] == CVE_NVD_TIMING


def test_the_check_can_fail() -> None:
    """A comparison that cannot fail proves nothing. Mutate one word and require a miss."""
    spec = _from_spec()
    mutated = spec["Delayed exploitation"].replace("months", "weeks", 1)
    assert mutated != spec["Delayed exploitation"], "the fixture did not actually mutate"
    assert DELAYED_EXPLOITATION != mutated


@pytest.mark.parametrize("text", [DELAYED_EXPLOITATION, CVE_NVD_TIMING])
def test_no_stray_markdown_survived_extraction(text: str) -> None:
    """The strings are rendered as prose, so quote markers would be visible to a reader."""
    assert not text.startswith(">")
    assert "\n" not in text
    assert text == text.strip()
