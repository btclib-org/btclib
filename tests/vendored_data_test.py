# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What `tests/_data/README.md` must not say about itself.

The same claim `release_notes_test.py` forbids CHANGELOG.md, for the same
reason and one more. A stated count is a line every open branch has to
edit, so a pull request vendoring a vector file is guaranteed to conflict
on it -- measured: the summary read 46, 47, 48, 49 and 50 across the
branches open on one afternoon, and each of those numbers was a rebase
conflict for the others. Worse, two branches moving it to the *same* new
number merge with nothing to decide, into a number that is wrong.

The one more is that this file has no `merge=union` driver to fall back
on, and cannot have one: union keeps both sides' added lines, which is
right for a list of bullets and nonsense for the prose around them. So
the number goes, the lists stay -- they are the fact the number
summarized -- and the Summary carries the `git ls-files` command that
derives it on demand.

Which is what this module guards, the assertions running the other way
round: a count is a failure. Anchored on the two shapes a self-count
takes here, "N files." opening the Summary and a Summary bullet that
counts what it then lists, rather than on numbers in prose: the entries
say "eight files under tests/ecc/_data" of BIP327's fixed set and "45
quadruples" of a vector file's contents, which are facts about an
upstream and not claims about this file. The bullet pattern is applied to
the Summary alone for that same reason -- an entry describing 70 rows of
Core's `key_io_valid.json` is describing Core's file.

A test rather than a hook, for the reasons `docs_test.py` gives: no
environment the suite does not already have, every interpreter of the
matrix rather than one runner, and `tests-passed` gates it without a line
in any `needs` list.
"""

import re
from pathlib import Path

_README = Path(__file__).parents[1] / "tests" / "_data" / "README.md"

# "N files." as the Summary opened, in digits or spelled out; against the
# whole file, the shape being specific enough to occur nowhere else
_FORBIDDEN_ANYWHERE = r"(?im)^(?:\d+|[a-z-]+) files\."

# a Summary bullet that opens with a count of what it lists; against the
# Summary alone
_FORBIDDEN_IN_SUMMARY = r"(?m)^- \d+ [a-z]"


def _summary() -> str:
    """Return the Summary section, which ends at the next heading."""
    text = _README.read_text(encoding="utf-8")
    start = text.index("\n## Summary\n")
    end = text.index("\n### ", start)
    return text[start:end]


def test_the_readme_states_no_total() -> None:
    """No "N files.", written by hand or restored by a rebase.

    The number is a claim nothing derives; the command in the file's own
    Summary derives it.
    """
    match = re.search(_FORBIDDEN_ANYWHERE, _README.read_text(encoding="utf-8"))
    assert match is None, (
        f"tests/_data/README.md states a total again: {match[0]!r}."
        " Remove it -- the git ls-files command in its Summary answers on"
        " demand, and every open branch would have to edit the number."
    )


def test_no_summary_bullet_counts_what_it_lists() -> None:
    """The names are the fact; a number in front of them is a second one."""
    match = re.search(_FORBIDDEN_IN_SUMMARY, _summary())
    assert match is None, (
        f"a Summary bullet states a count again: {match[0]!r}."
        " The list that follows it is the count, and the two drift apart."
    )


def test_the_patterns_still_match() -> None:
    """The guards above pass for free if their patterns match nothing.

    Which is the failure mode of every assertion written in the negative,
    and the one the file they read cannot reveal: a pattern reworded past
    the text it forbids leaves a green test guarding an empty set. These
    are the lines as the file spelled them while it still stated a count.
    """
    assert re.search(_FORBIDDEN_ANYWHERE, "49 files. Against a pinned blob:")
    assert re.search(_FORBIDDEN_ANYWHERE, "Fifty files. Against a pinned blob:")
    assert re.search(_FORBIDDEN_IN_SUMMARY, "- 18 identical byte for byte: `en`")
    assert re.search(_FORBIDDEN_IN_SUMMARY, "- 3 not vendored: `rfc6979.json`")


def test_the_patterns_spare_the_numbers_that_are_facts() -> None:
    """A number in an entry is upstream's, not a claim about this file."""
    spared = (
        "### BIP327 (MuSig2): eight files under `tests/ecc/_data/`",
        "45 quadruples -- description, mnemonics, master secret, root xprv",
        "The 70 invalid strings are refused by all four entry points.",
    )
    for text in spared:
        assert not re.search(_FORBIDDEN_ANYWHERE, text), text
        assert not re.search(_FORBIDDEN_IN_SUMMARY, text), text
