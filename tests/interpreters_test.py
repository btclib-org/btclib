# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The interpreters this package claims are the ones it runs on.

One fact, declared three times: `requires-python` is the floor,
`Programming Language :: Python :: X.Y` is what PyPI shows whoever is
choosing the package, and the platform sweeps' own list is what actually
runs. Nothing compared them, and the three drift in the direction that is
hardest to notice -- a classifier left behind when a floor moves is a
package advertising an interpreter its suite never touches, and the
person it misleads is not reading this repository.

The organization standard's rule is that a library covers every Python
that is not out of support, so all three move together twice around each
October: one version leaves support as another is released. This module
does not know that calendar and does not try to -- python.org keeps it,
and a test that hard-coded a date would be one more thing to move. What
it holds is the weaker and checkable claim: whatever the three say, they
say the same thing.

Read with a regex rather than parsed. `tomllib` arrives in 3.11 and the
floor here is 3.10, which is the reason `copyright_test.py` reads
pyproject.toml the same way; the workflows are yaml and no group here
carries a parser for that either.
"""

import re
from pathlib import Path

_ROOT = Path(__file__).parents[1]
_PYPROJECT = (_ROOT / "pyproject.toml").read_text(encoding="utf-8")
_WORKFLOWS = sorted((_ROOT / ".github/workflows").glob("*.yml"))

# "3.10" out of `requires-python = ">=3.10"`, the floor and nothing else:
# an upper bound is not declared here and would be a different claim
_FLOOR = re.compile(r'^requires-python = ">=(?P<version>3\.\d+)"', re.MULTILINE)
# the per-version classifiers, not `:: 3` or `:: 3 :: Only`, which say
# something about the major version rather than about an interpreter
_CLASSIFIER = re.compile(
    r'^    "Programming Language :: Python :: (?P<version>3\.\d+)",$', re.MULTILINE
)
_PYPY_CLASSIFIER = "Programming Language :: Python :: Implementation :: PyPy"
# PyPI's free-threading classifiers, the bare one and its maturity levels
# alike: each is a claim about the code under a free-threaded build, and
# which is claimed is not this module's question
_FREE_THREADING_CLASSIFIER = re.compile(
    r'^    "Programming Language :: Python :: Free Threading(?: :: .+)?",$',
    re.MULTILINE,
)
# the matrix list a suite workflow builds its cells from. The gate runs
# one interpreter, so the list lives in the weekly platform sweeps now --
# in each of them, which is why they are read together below rather than
# one of them being named here as the one that counts
_PYTHONS = re.compile(
    r"^        python:\n(?P<block>(?:^          - \"\S+\"\n)+)", re.MULTILINE
)
# the platform sweeps, named rather than counted: the pattern above reads
# a block sequence, so one sweep rewritten as a flow sequence -- which is
# how deps-latest.yml writes its own, and why that file is skipped here
# -- would drop out of the comparison below in silence, leaving the
# remaining two to agree with each other and the test green
_SWEEPS = ("os-macos.yml", "os-ubuntu.yml", "os-windows.yml")
# the merge gate, which its own header says is one cell rather than a
# matrix: each job writes the interpreter it runs into itself, as
# `python-version: "3.14"` or `--python 3.14`, so the gate's interpreters
# are read as tokens off the file rather than out of a matrix block. A
# free-threaded build there is a "3.14t" of the same shape. Comments go
# first, so that a sentence about a sweep's free-threaded cell does not
# read as the gate running one. The `dist` job is the exception: its
# `astral-sh/setup-uv` step passes no `python-version:`, and its bare
# `uv build` and "Smoke-test the wheel" step's `uv venv` take their
# interpreter from `.python-version` instead of naming it in the job, so
# a change to that file would move `dist`'s interpreter unseen here
_GATE = _ROOT / ".github/workflows/test.yml"
_COMMENT = re.compile(r"(?:^|\s)#.*$", re.MULTILINE)
_INTERPRETER = re.compile(r"\b3\.\d+t?\b")


def _versions(pattern: re.Pattern[str], text: str) -> tuple[str, ...]:
    """Return every `version` group `pattern` finds, in order."""
    return tuple(m["version"] for m in pattern.finditer(text))


def _declared() -> dict[str, tuple[str, ...]]:
    """Return each workflow's interpreter list, those that declare one."""
    found: dict[str, tuple[str, ...]] = {}
    for workflow in _WORKFLOWS:
        listed: set[str] = set()
        text = workflow.read_text(encoding="utf-8")
        for match in _PYTHONS.finditer(text):
            listed.update(
                line.strip().removeprefix('- "').removesuffix('"')
                for line in match["block"].splitlines()
            )
        if listed:
            found[workflow.name] = tuple(sorted(listed))
    return found


def _gate_interpreters() -> tuple[str, ...]:
    """Return every interpreter the merge gate names outside its comments."""
    text = _COMMENT.sub("", _GATE.read_text(encoding="utf-8"))
    return tuple(sorted(set(_INTERPRETER.findall(text))))


def _matrix() -> tuple[str, ...]:
    """Return the interpreters the platform sweeps name."""
    found: set[str] = set()
    for listed in _declared().values():
        found.update(listed)
    return tuple(sorted(found))


_CLASSIFIED = _versions(_CLASSIFIER, _PYPROJECT)
_MATRIX = _matrix()
# the free-threaded build and PyPy are the same interpreter version as
# far as a classifier is concerned: "3.14t" is CPython 3.14, and
# "pypy3.11" is what the PyPy classifier covers rather than a version
# of its own
_CPYTHON = tuple(sorted({v.rstrip("t") for v in _MATRIX if not v.startswith("pypy")}))


def test_the_three_declarations_were_read() -> None:
    """Each pattern found something, so the checks below quantify over it.

    A key renamed, a classifier reindented, the workflow's block moved:
    each would leave one of these empty and every comparison below
    trivially true.
    """
    assert _FLOOR.search(_PYPROJECT), "pyproject.toml declares no requires-python"
    assert _CLASSIFIED, "pyproject.toml declares no per-version Python classifier"
    assert _MATRIX, "no workflow declares a python matrix block"


def test_the_floor_is_the_lowest_classifier() -> None:
    """`requires-python` and the classifiers name the same oldest Python."""
    floor = _FLOOR.search(_PYPROJECT)
    assert floor, "pyproject.toml declares no requires-python"
    lowest = min(_CLASSIFIED, key=lambda v: tuple(int(p) for p in v.split(".")))
    assert floor["version"] == lowest, (
        f"requires-python is >={floor['version']} and the lowest classifier"
        f" is {lowest}: one of the two was moved and the other was not"
    )


def test_every_classified_interpreter_is_in_the_matrix() -> None:
    """A version PyPI advertises is a version the suite runs."""
    unrun = [v for v in _CLASSIFIED if v not in _CPYTHON]
    assert not unrun, (
        f"classified and no workflow runs it: {', '.join(unrun)}."
        " PyPI shows a classifier to whoever is choosing this package"
    )


def test_every_matrix_interpreter_is_classified() -> None:
    """A version the suite runs is a version PyPI advertises."""
    unclassified = [v for v in _CPYTHON if v not in _CLASSIFIED]
    assert not unclassified, (
        f"run by a workflow and not classified: {', '.join(unclassified)}"
    )


def test_pypy_is_classified_exactly_when_it_is_run() -> None:
    """The PyPy classifier is a claim about the matrix, not a decoration."""
    classified = _PYPY_CLASSIFIER in _PYPROJECT
    run = any(v.startswith("pypy") for v in _MATRIX)
    assert classified == run, (
        f"the PyPy classifier is {'present' if classified else 'absent'} and"
        f" the matrix {'runs' if run else 'does not run'} a PyPy interpreter"
    )


def test_free_threading_is_classified_exactly_when_the_gate_runs_it() -> None:
    """The free-threading classifier is a claim about the merge gate.

    The organization standard declares one where the gate exercises the
    free-threaded build: a gate refuses the landing that breaks that
    build, where a sweep runs beside a landing and blocks nothing. So the
    second side here is test.yml alone and not `_MATRIX` -- the sweeps
    name "3.14t" as readily as the gate would, and a sweep passing is the
    ground the standard declines.
    """
    gate = _gate_interpreters()
    assert gate, "test.yml names no interpreter"
    classified = bool(_FREE_THREADING_CLASSIFIER.search(_PYPROJECT))
    run = [v for v in gate if v.endswith("t")]
    assert classified == bool(run), (
        f"the free-threading classifier is {'present' if classified else 'absent'}"
        f" and test.yml names {', '.join(run) or 'no free-threaded interpreter'}"
    )


def test_every_sweep_runs_the_same_interpreters() -> None:
    """One interpreter set, however many platforms sweep it.

    The gate runs one, so the list is declared once per platform sweep
    and nowhere else. Three copies of a list is three chances for one of
    them to be left behind, and a platform quietly running a narrower set
    than another reads, from the outside, as that platform passing.

    Every sweep has to be read for that to mean anything, which is the
    first assertion: agreement among however many were found is a claim
    that gets weaker the fewer there are, and vacuous at one.
    """
    declared = _declared()
    assert tuple(sorted(declared)) == _SWEEPS, (
        f"the platform sweeps are {', '.join(_SWEEPS)} and the interpreter"
        f" block was read from {', '.join(sorted(declared)) or 'none of them'}"
    )
    lists = set(declared.values())
    assert len(lists) <= 1, (
        f"the workflows do not name the same interpreters: {declared}"
    )
