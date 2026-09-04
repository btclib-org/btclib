# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Every path:line citation in SECURITY.md answers for what it names.

SECURITY.md publishes what this library protects and what it does not,
and a reader who follows one of its pointers into the source is checking
a claim for themselves, which is the behaviour the file should reward.
An edit anywhere in a cited file shifts the line it cites, and no other
gate reads them, so the pointer rots with nothing red: the reader lands
on an unrelated line, or inside a function other than the one the
sentence names, and learns that the file's pointers cannot be followed.
That is worse than a file with no pointers (issue #1690).

The grammar read here is the file's own. A citation is a backticked
path, with or without a line number, and its anchor is the backticked
span in front of it -- the prose puts one there either way it writes a
citation:

- a dotted name, `dsa.Signer.__init__`, and then the definition holding
  the cited line must be the one named, read off the module's own `ast`;
- anything else is a fragment of the line itself, the way the musig2
  citation quotes the sum it points at, and then it must be on the line
  cited. Whitespace is flowed on both sides, the eighty-column wrap of
  the markdown being a fact of the margin and not of the code.

A path with no line number is held to naming a file that exists, which
is the whole of what it claims.

Two things this does not check. Which line inside a named definition is
the right one: a dotted name pins the function and leaves every line of
it equally acceptable, so a citation that drifts within its own function
passes here -- a citation wanting the stricter check quotes its line
instead of naming its function. And whether the sentence around a
citation is true of the line it points at, which no test can read; what
this keeps true is that the pointer still points at the code the
sentence was written about.

A test rather than a hook, for the reasons `docs_test.py` gives: no
environment the suite does not already have, every interpreter of the
matrix rather than one runner, and `tests-passed` gates it without a
line in any `needs` list.
"""

import ast
import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).parents[1]
_SECURITY = _ROOT / "SECURITY.md"

# a path in this repository, with the line number it may carry: the
# slash is what keeps `btclib.ecc.musig2` and the dotted names beside it
# from reading as citations
_CITATION = re.compile(r"^(?P<path>[\w.-]+(?:/[\w.-]+)+\.py)(?::(?P<line>\d+))?$")
# a dotted name, which is how the prose spells the definition a citation
# sits inside; an anchor that is not one is read as a fragment of the
# line, and a fragment of Python source carries a space or a bracket
_SYMBOL = re.compile(r"^[A-Za-z_]\w*(?:\.\w+)+$")
_SPAN = re.compile(r"`([^`]+)`")


def _flow(text: str) -> str:
    """Return the text with every run of whitespace collapsed to a space."""
    return " ".join(text.split())


def _prose() -> str:
    """Return SECURITY.md outside its fenced blocks, whitespace flowed.

    A fence is dropped rather than read: the shell inside one is not
    prose, and its own backticks would pair with the prose's and shift
    every anchor after it by one.
    """
    lines = []
    in_fence = False
    for line in _SECURITY.read_text(encoding="utf-8").splitlines():
        if line.strip().startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence:
            lines.append(line)
    return _flow("\n".join(lines))


_SPANS = _SPAN.findall(_prose())
# each span paired with the span in front of it, and the first with
# nothing: `strict=False` is what drops the head that has no span after
# it. A citation opening the file carries an empty anchor, and `_defect`
# refuses that rather than checking a line against nothing -- the empty
# string is in every line, so a fall-through here would pass a citation
# for free
_CITATIONS = tuple(
    (anchor, match["path"], match["line"] or "")
    for anchor, span in zip(["", *_SPANS], _SPANS, strict=False)
    if (match := _CITATION.match(span))
)


def _enclosing(source: Path, lineno: int) -> str:
    """Return the dotted name of the innermost definition holding the line.

    The module's own name opens it, so that the prose can write the
    citation the way it reads -- `taproot._tweaked_prvkey` rather than
    the bare function -- and a line inside no definition answers with
    that name alone. Parsed from the source rather than imported: the
    line numbers are the file's, and an import would run the module for
    them.
    """
    node: ast.AST = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    names = [source.stem]
    while True:
        for child in ast.iter_child_nodes(node):
            # the isinstance first, and not for tidiness: the children of
            # a definition include its `arguments`, which carries no line
            # number at all
            if isinstance(
                child, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef
            ) and child.lineno <= lineno <= (child.end_lineno or child.lineno):
                names.append(child.name)
                node = child
                break
        else:
            return ".".join(names)


def _named_defect(anchor: str, source: Path, lineno: int) -> str:
    """Report a name that is not the definition the cited line sits in.

    The anchor is matched against the tail of the definition's dotted
    name, so that `Signer.__init__` and `dsa.Signer.__init__` are both
    the same claim about the same line.
    """
    enclosing = _enclosing(source, lineno).split(".")
    named = anchor.split(".")
    if named != enclosing[-len(named) :]:
        return (
            f"names `{anchor}`, where line {lineno} of {source.name} is in"
            f" `{'.'.join(enclosing)}`"
        )
    return ""


def _quoted_defect(anchor: str, cited: str, lineno: int) -> str:
    """Report a quotation that is not on the line cited."""
    if _flow(anchor) not in _flow(cited):
        return f"quotes `{anchor}`, where line {lineno} reads `{_flow(cited)}`"
    return ""


def _defect(anchor: str, path: str, line: str, root: Path = _ROOT) -> str:
    """Return what the citation fails to answer for, empty where nothing."""
    source = root / path
    if not source.is_file():
        return f"cites {path}, which is not a file of this repository"
    if not line:
        return ""
    lines = source.read_text(encoding="utf-8").splitlines()
    lineno = int(line)
    if not 1 <= lineno <= len(lines):
        return f"cites line {lineno} of {path}, which has no such line"
    if not anchor.strip():
        return f"cites line {lineno} of {path} with nothing in front of it"
    if _SYMBOL.match(anchor):
        return _named_defect(anchor, source, lineno)
    return _quoted_defect(anchor, lines[lineno - 1], lineno)


# the module the controls below cite, written to a directory of their
# own: a control aimed at src/btclib would be measuring the tree it is
# meant to be independent of, and would stop tampering the day that tree
# moved under it
_CONTROL_SOURCE = '''\
"""A module the controls cite, one line of it inside no definition."""


class Klass:
    """A definition holding another."""

    def method(self) -> None:
        """The innermost definition, and the line below is its own."""
        answer = 1 + 1
'''

_SOUND = (
    pytest.param(
        "control.Klass.method", "control.py", "9", id="the name holds the line"
    ),
    pytest.param(
        "Klass.method", "control.py", "9", id="the name is a tail of the definition"
    ),
    pytest.param(
        "answer = 1 + 1", "control.py", "9", id="the quotation is on the line"
    ),
    pytest.param(
        "control.Klass.method", "control.py", "", id="a path claims only to exist"
    ),
)

_BROKEN = (
    pytest.param(
        "control.Klass.other", "control.py", "9", id="a name that does not hold it"
    ),
    pytest.param("control.Klass", "control.py", "1", id="a line in no definition"),
    pytest.param("answer = 2 + 2", "control.py", "9", id="a quotation not on the line"),
    pytest.param(
        "control.Klass.method", "control.py", "99", id="a line the file lacks"
    ),
    pytest.param(
        "control.Klass.method", "control.py", "0", id="a line below the first"
    ),
    pytest.param("control.Klass.method", "absent.py", "1", id="a file that is gone"),
    pytest.param("", "control.py", "9", id="a citation with nothing in front of it"),
)


@pytest.fixture
def control(tmp_path: Path) -> Path:
    """Write the module the controls cite, and answer its directory."""
    (tmp_path / "control.py").write_text(_CONTROL_SOURCE, encoding="utf-8")
    return tmp_path


def test_the_scan_still_finds_citations() -> None:
    """A guard that parsed no citation passes for free.

    Which is the failure mode of every assertion written in the
    negative: a citation respelled past `_CITATION`, or an anchor no
    longer in front of one, leaves the check below quantifying over
    nothing.
    """
    assert _CITATIONS, f"no path:line citation parsed out of {_SECURITY.name}"


@pytest.mark.parametrize("anchor, path, line", _CITATIONS, ids=lambda value: value)
def test_every_citation_answers_for_what_it_names(
    anchor: str, path: str, line: str
) -> None:
    """The citation and the line it points at say the same thing.

    A failure here is fixed in SECURITY.md, by re-deriving the line --
    `awk 'NR==N' <file>` against the anchor -- and never by editing the
    source to suit the number.
    """
    defect = _defect(anchor, path, line)
    assert not defect, f"{_SECURITY.name} {defect}"


@pytest.mark.parametrize("anchor, path, line", _SOUND)
def test_a_citation_that_answers_is_left_alone(
    anchor: str, path: str, line: str, control: Path
) -> None:
    """The check has to pass what it should pass, or it is a wall.

    The other half of the control below: a check that reported every
    citation broken would be as useless as one that reported none, and
    the two tests fail on opposite mistakes.
    """
    assert not _defect(anchor, path, line, control)


@pytest.mark.parametrize("anchor, path, line", _BROKEN)
def test_a_broken_citation_of_each_kind_is_named(
    anchor: str, path: str, line: str, control: Path
) -> None:
    """The check fires for each way a citation stops answering.

    Each of these is a shape the check exists to catch. Two of them are
    what issue #1690 measured in SECURITY.md itself: a function named
    beside a line that is inside a different one, and a line the prose
    quotes that has moved.
    """
    assert _defect(anchor, path, line, control)
