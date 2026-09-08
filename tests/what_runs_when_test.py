# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""`CONTRIBUTING.md`'s *What runs when* table names every workflow.

The paragraph under that table leaves *which day* each workflow runs to
section 10 of the organization standard, "not this file's to restate",
which reads the table as covering the rest: every workflow this tree
holds, with the calendar deliberately out of the `when` cell. A table
exhaustive but for one workflow is read as exhaustive, so a missing row
says "there is no such workflow" rather than "nobody wrote the row", and
the reader it misleads is the one who went to the table to find out
(issue #1849).

Nothing else compares the two. For the interpreters their matrices name,
`interpreters_test.py` reads the workflows; for a command spelled in
several places, `docs_commands_test.py` reads one of them. Neither asks
which workflows exist.

Both directions are checked, because a renamed workflow is both failures
at once -- a row naming a file that is gone, and a file no row names --
and either half alone reports it as the other thing. The converse also
catches what no reading of `.github/workflows/` would: a row for a
workflow that was proposed and never written.

Neither comparison goes quietly vacuous on its own, both being set
differences: a side that comes back empty leaves the other one naming
every element of the side that did not. An extraction that finds nothing
fails the forward comparison with every workflow in its message, and a
glob that finds nothing fails the converse with every row in its own.
What that leaves is both sides empty at once, which is the whole of what
`test_both_sides_were_read` refuses. A table this module cannot locate
is refused a layer earlier, by the `assert` inside `_named_workflows`,
which fires through every test that calls it.

The cells are not read. A `when` naming triggers the workflow's own `on:`
block does not carry, or a `what it varies` describing a matrix it no
longer has, is as invisible here as a missing row is without this
module. Neither is this a count: `lint`/`docs` and `links`/`mutation`
each share a row, so rows and workflows do not correspond one to one,
and what is compared is the set of names.

Only the first cell of a row is read. The last cell of the `release` row
names `release.yml`, so a pattern taking every backticked word in a row
would read that file as named by whichever row mentioned it.

`REPOSITORY.md` is not read the same way, and could not be: it names the
workflows a setting or a measurement is about and is silent on the rest,
which is what makes the reading above this table's own.
"""

import re
from pathlib import Path

_ROOT = Path(__file__).parents[1]
_CONTRIBUTING = (_ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")

# both extensions GitHub reads, rather than the `.yml` every file here
# happens to use: a workflow added as `.yaml` runs, and a comparison
# that could not see it would leave open the same thing a missing row
# leaves open
_WORKFLOWS = frozenset(
    path.stem for path in (_ROOT / ".github/workflows").glob("*.y*ml")
)

# scoped to the one table, its heading and its header row included: a
# renamed heading, a reordered column or a reindented table leaves this
# unmatched, which the `assert` in `_named_workflows` below refuses
# rather than reading as a table that names nothing
_TABLE = re.compile(
    r"^### What runs when\n\n"
    r"^\| workflow \| when \| what it varies \|\n"
    r"^\| --- \| --- \| --- \|\n"
    r"(?P<rows>(?:^\|.*\|\n)+)",
    re.MULTILINE,
)


def _named_workflows() -> frozenset[str]:
    """Return the workflow stems the table's first column names."""
    table = _TABLE.search(_CONTRIBUTING)
    assert table, (
        "CONTRIBUTING.md's *What runs when* heading, or the table under it,"
        " was not found where this test expects it"
    )
    return frozenset(
        stem
        for row in table["rows"].splitlines()
        for stem in re.findall(r"`([^`]+)`", row.split("|")[1])
    )


def test_both_sides_were_read() -> None:
    """Neither side of the comparison is empty, so neither is vacuous.

    The two below are set differences, so a single empty side is loud
    already: the other comparison names every element of the side that
    came back full. Both empty at once is the case neither of them can
    see -- a table matching the pattern while naming nothing, and a glob
    finding no workflow -- and this is what refuses it, naming the side
    that was empty rather than leaving a difference of nothing to read
    as agreement.
    """
    assert _named_workflows(), "CONTRIBUTING.md's *What runs when* table names none"
    assert _WORKFLOWS, "no workflow was read from .github/workflows/"


def test_every_workflow_has_a_row() -> None:
    """A workflow the table does not name reads as one that does not exist."""
    missing = sorted(_WORKFLOWS - _named_workflows())
    assert not missing, (
        "CONTRIBUTING.md's *What runs when* table names no row for"
        f" .github/workflows/: {missing}"
    )


def test_no_row_names_an_absent_workflow() -> None:
    """A row for a file the tree does not hold answers for a run nobody makes.

    It is what a rename or a removal leaves behind, and the row goes on
    telling a reader when that workflow runs.
    """
    stale = sorted(_named_workflows() - _WORKFLOWS)
    assert not stale, (
        "CONTRIBUTING.md's *What runs when* table names workflows"
        f" .github/workflows/ does not hold: {stale}"
    )
