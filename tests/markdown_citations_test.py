# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Every path a markdown file cites of this tree is one this tree has.

A citation is what a reader follows to check a claim, so one resolving to
nothing sends whoever follows it looking for a file that is not there.
The population is every tracked `*.md`, citing being what these files do
rather than a property of any one of them: `tests/_data/README.md` and
`CHANGELOG.md` name the module a verdict's values sit in, `CONTRIBUTING.md`
and `REVIEWING.md` the file a rule lives in, and `CLAUDE.md` the module a
layer is drawn at.

Whose a cited path is, the tree decides. A list of the paths other
projects own is a list to keep, and the day a vendored file arrives
without an entry the red lands on a correct citation. So a cited path
this tree does not have, whose file name it does have, under a directory
it does have, is one of this tree's own files cited where it is not, and
another project's path fails one half or the other. Dropping either half
reddens citations that are correct:

- without the directory half a path written relative to `src/` or to
  `src/btclib/` is left to a file name this tree does have, which is
  `CLAUDE.md`'s `curves/curve_group.py` and `RELEASE_NOTES.md`'s
  `btclib/b58.py`;
- without the file name half another project's tests are left to
  `tests/`, the directory everyone puts them in, which is `REVIEWING.md`'s
  `tests/verbatim_test.py` -- named in that sentence as the organization
  standard's own module -- and `tests/_data/README.md`'s spesmilo/electrum
  vector sources.

A citation broken across the eighty-column wrap is not read at all: the
character class stops at the newline, so `tests/` ending one line and
`descriptors_test.py` opening the next is no match, and the sweep's
silence about such a path is not a verdict on it. Folding the wrap away
before matching is not the repair, the two foldings being exactly
complementary: joining the halves with nothing does see a wrapped path,
and also fuses a *command* wrapped at a space, which `CHANGELOG.md`
carries -- `pytest` and `tests/ecc/dsa_test.py` on either side of a break
become one path -- while joining them with a space fuses neither and sees
neither, a path having no space to be broken at. What keeps that fused
path from reddening a correct citation today is the directory half alone,
this tree having no `pytesttests/ecc`, which is luck and not the rule
(issue #1969). The rule is blind by construction in one more way, and
that one is deliberate: a cited path whose file name this tree does not
have anywhere is another project's as far as this reads, whether or not
it is. A `./` in front of one of this tree's own files is blind the same
way and for the same reason -- `.` is a directory no `git ls-files` path
carries, so the directory half excuses `` `./SECURITY.md` ``, which
CONTRIBUTING.md cites -- and a rename would go unflagged in that
spelling.

Both halves accept a path another repository owns whose file name *and*
whose directory this tree also has, and which this tree does not itself
have -- that last is what `cited - tracked` asks first, so one of our own
paths cited as somebody else's is not this class. REVIEWING.md cites the
organization standard's `tests/verbatim_test.py` one file name short of
it: `tests` is a directory here, so the day this tree gains a
`verbatim_test.py` anywhere but at `tests/verbatim_test.py` itself, that
landed citation begins to read as one of ours cited where it is not.
Landing at that path instead makes it disappear from the sweep rather than
reddening it, `cited - tracked` being asked first -- silence, and not this
class. `_EXEMPT` is where such a path goes, keyed on the path with what
makes it somebody else's beside it. A released `## v<version>` section of
`CHANGELOG.md` is the other way in: `changelog_immutability_test.py`
compares it byte for byte against its own tag, so a path renamed after an
entry cited it cannot be corrected where it is cited, and the exemption is
the only place that decision can be written down.

A file stating the convention its own citations are written to can be
held to more than this, and this rule does not stand in for that:
`tf2_ledger_test.py` resolves `TF2.md`'s paths against `src/btclib/` as
well as against the root, which is available to it because that ledger
says which of the two each path is written from.

The module asks `git ls-files` which paths this repository has, so
`source-exclude` keeps it out of the sdist: a tree stripped to its tracked
files has no index to ask.

A test rather than a hook, for the reasons `docs_test.py` gives: no
environment the suite does not already have, every interpreter of the
matrix rather than one runner, and `tests-passed` gates it without a line
in any `needs` list.
"""

import re
import shutil
import subprocess
from collections.abc import Mapping
from pathlib import Path

_ROOT = Path(__file__).parents[1]

# resolved once, for the reason `declared_version_test.py`'s own `_GIT`
# is: a bare "git" in a subprocess list is a partial executable path
_GIT = shutil.which("git") or "git"

# a backticked span of path characters, with a directory in it and a
# suffix on the name. What the character class leaves out is what makes
# the span a citation rather than something shaped like one:
# `bitcoin/bitcoin#15437` is an issue, `api/tx/<txid>` an endpoint, and
# `tests/tx/_data/*.bin` a set of files rather than one, so none of the
# three is a path `git ls-files` could answer for
_CITED_PATH = re.compile(r"`([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+\.[A-Za-z0-9]+)`")

# a path both halves of the rule accept and this tree does not own, with
# what makes it somebody else's beside it. Empty, the tree having no such
# path: an entry here records a decision about one citation, where
# widening the rule to excuse it would excuse the next real defect with it
_EXEMPT: dict[str, str] = {}


def _cited_paths(text: str) -> set[str]:
    """Every path `text` cites in backticks."""
    return {match.group(1) for match in _CITED_PATH.finditer(text)}


def _tracked() -> set[str]:
    """Every path this repository tracks."""
    listed = subprocess.run(  # noqa: S603
        [_GIT, "ls-files"],
        cwd=_ROOT,
        capture_output=True,
        encoding="utf-8",
        check=False,
    )
    return set(listed.stdout.splitlines())


def _misresolved(
    cited: set[str], tracked: set[str], exempt: Mapping[str, str]
) -> list[str]:
    """Return the cited paths naming a file `tracked` holds elsewhere.

    Both halves of a path are read, and each answers one of the two ways
    another project's path reads like one of ours. A vendored file keeps
    the name upstream publishes it under, so upstream's own path for it
    carries our file name and only the directory tells the two apart; and
    another project's tests sit under `tests/` as ours do, so there only
    the name does.
    """
    names = {path.rsplit("/", 1)[-1] for path in tracked}
    directories = {path.rsplit("/", 1)[0] for path in tracked if "/" in path}
    return sorted(
        path
        for path in cited - tracked - set(exempt)
        if path.rsplit("/", 1)[-1] in names and path.rsplit("/", 1)[0] in directories
    )


def _offenders(
    texts: Mapping[str, str], tracked: set[str], exempt: Mapping[str, str]
) -> dict[str, list[str]]:
    """Return what each markdown file of `texts` cites of this tree elsewhere.

    Keyed on the file, a path being followed from the paragraph carrying
    it: the same wrong path in two files is two corrections.
    """
    return {
        markdown: misresolved
        for markdown, text in texts.items()
        if (misresolved := _misresolved(_cited_paths(text), tracked, exempt))
    }


def test_every_path_a_markdown_file_cites_of_this_tree_is_one_this_tree_has() -> None:
    """A citation is what a reader follows to check a claim.

    A verdict is checked by opening the module holding the values, a rule
    by opening the file stating it, so a path resolving to nothing leaves
    the claim standing on nothing a reader can reach.
    """
    tracked = _tracked()
    texts = {
        path: (_ROOT / path).read_text(encoding="utf-8")
        for path in sorted(tracked)
        if path.endswith(".md")
    }
    # what a sweep answering zero has to be held to: `git ls-files` gives
    # an empty set where git is missing, and the pattern can stop matching
    # without anything else here changing
    assert "pyproject.toml" in tracked
    assert {path for text in texts.values() for path in _cited_paths(text)} & tracked

    offenders = _offenders(texts, tracked, _EXEMPT)
    assert not offenders, (
        "a markdown file cites a path this tree does not have, under a file"
        f" name and a directory it does have: {offenders!r}"
    )

    # an exemption outlives the citation it was written for, and a dead one
    # excuses nothing while reading as though it did. Set arithmetic rather
    # than a loop over `_EXEMPT`, which is empty: a loop body no run enters
    # is uncovered, and the floor is 100%
    unexempted = {
        path
        for text in texts.values()
        for path in _misresolved(_cited_paths(text), tracked, {})
    }
    stale = sorted(set(_EXEMPT) - unexempted)
    assert not stale, f"_EXEMPT names a path the rule would not flag: {stale}"


def test_a_citation_broken_across_the_wrap_is_not_read() -> None:
    """The limit above, executable rather than stated.

    A fold that made this answer with the path would also fuse the
    command `CHANGELOG.md` wraps at a space, so a change here is a
    decision about that trade and not a widening (issue #1969).
    """
    assert _cited_paths("the module is `tests/\ndescriptors_test.py`.") == set()
    assert _cited_paths("the module is `tests/descriptors_test.py`.") == {
        "tests/descriptors_test.py"
    }


def test_a_path_of_this_tree_is_told_from_a_path_of_another_project() -> None:
    """The sweep above passes for free if it cannot tell the two apart.

    One synthetic tracked set, and a citation for each arm the rule has:
    `tests/descriptors_test.py` is this tree's own module at a path this
    tree does not have and is caught; the same module at its own path is
    not; Core's `src/test/data/script_tests.json` carries the file name
    our vendored copy keeps and is left to its directory, which this tree
    does not have; and electrum's `tests/test_mnemonic.py` sits in a
    directory this tree does have and is left to its name.

    Two of those arms turn on `tests` being a directory the set has, so
    the set holds a file directly under it and says so before the sweep
    runs: without that the caught arm is excused for the wrong reason and
    the electrum arm proves nothing, neither of which an expectation of an
    empty list would show. The cited set is read back for the same reason,
    a pattern that stopped matching leaving nothing for the rule to
    disagree about.
    """
    tracked = {
        "tests/markdown_citations_test.py",
        "tests/descriptors/descriptors_test.py",
        "tests/script_engine/_data/script_tests.json",
    }
    assert "tests" in {path.rsplit("/", 1)[0] for path in tracked}
    cited = _cited_paths(
        "`tests/descriptors_test.py`, `tests/descriptors/descriptors_test.py`,"
        " Core's `src/test/data/script_tests.json` and electrum's"
        " `tests/test_mnemonic.py`."
    )
    assert cited == {
        "tests/descriptors_test.py",
        "tests/descriptors/descriptors_test.py",
        "src/test/data/script_tests.json",
        "tests/test_mnemonic.py",
    }

    assert _misresolved(cited, tracked, {}) == ["tests/descriptors_test.py"]


def test_an_exempt_path_is_excused_and_the_rule_is_left_as_it_is() -> None:
    """What the guard does with the path both halves accept.

    The tree carries no such path, so this is what says the exemption
    works on the day one arrives, and it is measured against the same
    citation unexempted rather than against an empty list, which an
    exemption that suppressed everything would also answer with.
    """
    tracked = {
        "tests/markdown_citations_test.py",
        "tests/descriptors/descriptors_test.py",
    }
    cited = {"tests/descriptors_test.py", "tests/script_engine/_data/script_tests.json"}

    assert _misresolved(cited, tracked, {}) == ["tests/descriptors_test.py"]
    assert _misresolved(cited, tracked, {"tests/descriptors_test.py": "why"}) == []


def test_a_misresolved_citation_is_reported_under_the_file_citing_it() -> None:
    """Which paragraph to correct is the file, not the path alone."""
    tracked = {
        "tests/markdown_citations_test.py",
        "tests/descriptors/descriptors_test.py",
    }
    texts = {
        "CONTRIBUTING.md": "the module is `tests/descriptors_test.py`.",
        "README.md": "the module is `tests/descriptors/descriptors_test.py`.",
    }

    assert _offenders(texts, tracked, {}) == {
        "CONTRIBUTING.md": ["tests/descriptors_test.py"]
    }
