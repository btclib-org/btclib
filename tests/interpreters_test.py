# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The interpreters this package claims are the ones it runs on.

One fact, declared three times: `requires-python` is the floor,
`Programming Language :: Python :: X.Y` is what PyPI shows whoever is
choosing the package, and `test.yml`'s own list is what actually runs.
Nothing compared them, and the three drift in the direction that is
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
pyproject.toml the same way; the workflow is yaml and no group here
carries a parser for it.
"""

import re
from pathlib import Path

_ROOT = Path(__file__).parents[1]
_PYPROJECT = (_ROOT / "pyproject.toml").read_text(encoding="utf-8")
_TEST_WORKFLOW = (_ROOT / ".github/workflows/test.yml").read_text(encoding="utf-8")

# "3.10" out of `requires-python = ">=3.10"`, the floor and nothing else:
# an upper bound is not declared here and would be a different claim
_FLOOR = re.compile(r'^requires-python = ">=(?P<version>3\.\d+)"', re.MULTILINE)
# the per-version classifiers, not `:: 3` or `:: 3 :: Only`, which say
# something about the major version rather than about an interpreter
_CLASSIFIER = re.compile(
    r'^    "Programming Language :: Python :: (?P<version>3\.\d+)",$', re.MULTILINE
)
_PYPY_CLASSIFIER = "Programming Language :: Python :: Implementation :: PyPy"
# the matrix list `test.yml` builds its suite cells from
_PYTHONS = re.compile(
    r"^        python:\n(?P<block>(?:^          - \"\S+\"\n)+)", re.MULTILINE
)


def _versions(pattern: re.Pattern[str], text: str) -> tuple[str, ...]:
    """Return every `version` group `pattern` finds, in order."""
    return tuple(m["version"] for m in pattern.finditer(text))


def _matrix() -> tuple[str, ...]:
    """Return the interpreters `test.yml`'s suite matrices name."""
    found: set[str] = set()
    for match in _PYTHONS.finditer(_TEST_WORKFLOW):
        found.update(
            line.strip().removeprefix('- "').removesuffix('"')
            for line in match["block"].splitlines()
        )
    return tuple(sorted(found))


_CLASSIFIED = _versions(_CLASSIFIER, _PYPROJECT)
_MATRIX = _matrix()
# the free-threaded build and PyPy are the same interpreter version as
# far as a classifier is concerned: "3.14t" is CPython 3.14, and
# "pypy-3.11" is what the PyPy classifier covers rather than a version
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
    assert _MATRIX, "test.yml declares no PYTHONS block"


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
        f"classified and not in test.yml's matrix: {', '.join(unrun)}."
        " PyPI shows a classifier to whoever is choosing this package"
    )


def test_every_matrix_interpreter_is_classified() -> None:
    """A version the suite runs is a version PyPI advertises."""
    unclassified = [v for v in _CPYTHON if v not in _CLASSIFIED]
    assert not unclassified, (
        f"in test.yml's matrix and not classified: {', '.join(unclassified)}"
    )


def test_pypy_is_classified_exactly_when_it_is_run() -> None:
    """The PyPy classifier is a claim about the matrix, not a decoration."""
    classified = _PYPY_CLASSIFIER in _PYPROJECT
    run = any(v.startswith("pypy") for v in _MATRIX)
    assert classified == run, (
        f"the PyPy classifier is {'present' if classified else 'absent'} and"
        f" the matrix {'runs' if run else 'does not run'} a PyPy interpreter"
    )
