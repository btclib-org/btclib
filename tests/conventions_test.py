# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The convention-test declaration in tests/README.md is true.

Section 7 of the organization standard lists conventions a suite can
turn into a red test, and closes with the clause that makes the list
usable: a repository needs the ones its own prose states rather than all
of them. That clause is right, and its price is that an *absent*
convention test is indistinguishable from a convention this repository
does not have. Nothing anywhere recorded which of the two it was.

A filename cannot answer it either. The suites of the organization name
the same idea three ways -- a module per bullet here, a `test_` prefix in
btclib-secp256k1, and in bitcoin-core-rpc several of these checks folded
into the one file that is about its single module, which is the honest
shape for a package that is one module. So the audit reads a declaration
rather than a directory, and this module is what keeps the declaration
from being prose: section 7's own rule, that a convention worth stating
is worth a test, applied to section 7 itself.

What it does not check is whether a named module tests the convention it
is named against. Nothing short of reading it can, and the four
assertions below are the ones that fail on the ways a declaration
actually rots: a convention invented here rather than taken from section
7, a module renamed or deleted with the row left behind, a module emptied
of its tests, and a bullet that quietly stops being accounted for by
either half.
"""

import ast
import re
from pathlib import Path

import pytest

_TESTS = Path(__file__).parent
_README = _TESTS / "README.md"

# section 7's conventions, in its order and its words: the lead of each
# bullet, which is what the first column of the table repeats. This
# tuple is the standard's rather than this repository's, so a bullet
# added there is a failure here until both this and the table have
# caught up -- which is the point of naming them rather than accepting
# whatever the table says.
_CONVENTIONS = (
    "the public surface",
    "the copyright header",
    "the documentation",
    "the import graph",
    "the changelog",
    "the build system",
    "the calling convention",
    "input validation",
    "the suite opens no socket",
)

_HEADING = "## Convention tests"
# the sentinel for the other half of the declaration. DOTALL as well as
# MULTILINE because eighty columns wrap the list of names across lines
# and the non-greedy match then stops at the first full stop that ends
# one -- which is why no name in that list may carry a full stop of its
# own. "none" is a legal answer and the one this repository gives, and it
# fits a line; the six btclib-secp256k1 names do not, which is where the
# single-line form was found wanting. The two halves are checked against
# each other below rather than each against nothing
_NOT_TESTED = re.compile(r"^Not tested here: (.+?)\.$", re.MULTILINE | re.DOTALL)
# a table row, and the separator row is what the second group's leading
# backtick excludes: `| --- | --- |` has no backtick to match
_ROW = re.compile(
    r"^\| (?P<convention>[^|]+?) \| `(?P<module>[^`]+)` \|$", re.MULTILINE
)


def _section() -> str:
    """Return the declaration section, heading to the next one or the end.

    Read rather than the whole file: a `##` heading elsewhere in
    tests/README.md must not contribute rows. The slice ends at the next
    `## ` rather than at the end of the file, so that a section added
    after this one is not read as part of it.
    """
    text = _README.read_text(encoding="utf-8")
    assert text.count(_HEADING) == 1, f"{_README.name} has no one {_HEADING}"
    section = text[text.index(_HEADING) + len(_HEADING) :]
    return _HEADING + section.split("\n## ", 1)[0]


_SECTION = _section()
_ROWS = tuple((m["convention"], m["module"]) for m in _ROW.finditer(_SECTION))


def test_the_table_is_not_empty() -> None:
    """A declaration that parsed to nothing is the failure that hides.

    Every assertion below quantifies over the rows, so a table this
    module's regex stopped matching -- a column added, the backticks
    dropped, the heading retitled -- would satisfy all of them silently.
    """
    assert _ROWS, f"{_README.name}'s {_HEADING} section parsed to no rows"


@pytest.mark.parametrize("convention, module", _ROWS, ids=lambda v: v)
def test_every_convention_named_is_one_of_section_sevens(
    convention: str, module: str
) -> None:
    """A convention invented here is not a convention the standard has."""
    assert convention in _CONVENTIONS, (
        f"{module} is declared against {convention!r}, which is not one of"
        f" section 7's: {', '.join(_CONVENTIONS)}"
    )


@pytest.mark.parametrize("convention, module", _ROWS, ids=lambda v: v)
def test_every_module_named_exists(convention: str, module: str) -> None:
    """A row outliving the file it names is the ordinary way this rots."""
    assert (_TESTS / module).is_file(), (
        f"{_README.name} declares {convention!r} tested in {module},"
        " which is not a file in this directory"
    )


@pytest.mark.parametrize("convention, module", _ROWS, ids=lambda v: v)
def test_every_module_named_holds_a_test(convention: str, module: str) -> None:
    """A file emptied of its tests still satisfies the check above.

    The source is parsed rather than the suite queried: an import would
    make this module's result depend on every other module's import
    side effects, and pytest's own collection is not available to a test
    it has already collected.
    """
    # no guard for a missing file: the test above is what reports that,
    # and a guard here would be a branch nothing can reach while it passes
    path = _TESTS / module
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found = any(
        isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        and node.name.startswith("test_")
        for node in ast.walk(tree)
    )
    assert found, (
        f"{module} is declared to test {convention!r} and defines no"
        " function whose name begins with test_"
    )


def test_the_two_halves_account_for_every_convention() -> None:
    """The table and the "Not tested here" line partition section 7's set.

    This is the assertion the declaration exists for. Either half alone
    is satisfiable by saying less: a table naming three conventions is
    true about those three and silent about the rest, and silence is
    exactly what section 7's escape clause makes unreadable. Together
    they have to name each convention once.
    """
    match = _NOT_TESTED.search(_SECTION)
    assert match, (
        f'{_README.name} has no "Not tested here: ...." line;'
        " the declaration is half of one"
    )
    listed = match[1].strip()
    absent = () if listed == "none" else tuple(s.strip() for s in listed.split(";"))
    tested = {convention for convention, _ in _ROWS}

    overlap = tested.intersection(absent)
    assert not overlap, (
        f"{', '.join(sorted(overlap))} is both declared tested and listed as not tested"
    )

    unknown = [name for name in absent if name not in _CONVENTIONS]
    assert not unknown, (
        f"{', '.join(unknown)} is listed as not tested and is not one of"
        f" section 7's: {', '.join(_CONVENTIONS)}"
    )

    unaccounted = [
        name for name in _CONVENTIONS if name not in tested and name not in absent
    ]
    assert not unaccounted, (
        f"{', '.join(unaccounted)} is neither declared tested nor listed as"
        " not tested; section 7's conventions are what the two halves"
        " must cover"
    )
