# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What CHANGELOG.md and RELEASE_NOTES.md must not say about themselves.

A count is the one fact in either file nothing derives: prose can be
reviewed, a number cannot -- it is right or wrong, and which one is
invisible unless somebody counts the bullets. `f295aaaf` left CHANGELOG.md
at 115 entries under a header reading "a hundred and eleven", `1142e97b`
took it to 116 under the same header, and the drift survived both reviews
because there was nothing to notice.

Checking the number against the bullets is one answer, and it costs what
it fixes: the count is then a line every open branch has to edit, so it
becomes the one conflict a pull request is guaranteed to have -- and two
branches moving it to the same new number merge without a conflict into a
number that is wrong. So neither file states it, and
`grep -c '^- ' CHANGELOG.md` derives it whenever a release wants it.

Which is what this module guards, the assertions running the other way
round: a count anywhere in either file is a failure. Not only because one
could be written by hand. `.gitattributes` marks both files `merge=union`
so that two branches appending a bullet to the same group stop colliding,
and the price of that driver is silence -- these files cannot conflict any
more, so a branch still carrying an edit to one of the old count
paragraphs restores it on rebase with nothing in the merge output to say
so. Nothing but this.

A test rather than a hook, for the reasons `docs_test.py` gives: no
environment the suite does not already have, every interpreter of the
matrix rather than one runner, and `tests-passed` gates it without a line
in any `needs` list.
"""

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).parents[1]
_FILES = (_ROOT / "CHANGELOG.md", _ROOT / "RELEASE_NOTES.md")

# The three claims the two files used to make, keyed on the number word
# and not on the prose around it, `\s+` covering the 80-column wrap that
# falls in a different place each time a paragraph is reflowed:
# CHANGELOG.md's and RELEASE_NOTES.md's entry count, the size of
# RELEASE_NOTES.md's breaking-changes list, and CHANGELOG.md's
# cross-reference to it. Three patterns and not a general "no number
# words in prose": the entries
# themselves say "eighteen became issues" and "the twelve on-chain
# scripts of issue #123", which are facts about a change and not claims
# about the file.
_FORBIDDEN = (
    r"(?i)a hundred and [a-z-]+\s+entries",
    r"(?im)^[a-z-]+ changes break code",
    r"(?i)lists the\s+[a-z-]+ source-breaking changes",
)

# each of those patterns against the text it forbids, as the files spelled
# it while they still stated a count: what `test_the_patterns_still_match`
# compares them with.
_RESURRECTED = (
    "A hundred and eighty entries, grouped. The order runs from what breaks",
    "The first release since 2023, and the largest: a hundred and eighty\nentries",
    "Twenty-nine changes break code that worked on v2023.7.12.",
    "[HISTORY.md](./HISTORY.md) lists the\ntwenty-nine source-breaking changes",
)


@pytest.mark.parametrize("path", _FILES, ids=lambda p: p.name)
def test_neither_file_states_a_count(path: Path) -> None:
    """No entry count, and no size of the breaking-changes list.

    Written by hand or put back by a `union` merge that had nothing to
    decide: either way the number is a claim nothing derives, and the
    command in the header derives it instead.
    """
    text = path.read_text(encoding="utf-8")
    for pattern in _FORBIDDEN:
        match = re.search(pattern, text)
        assert match is None, (
            f"{path.name} states a count again: {match[0]!r}."
            " Remove it -- `grep -c '^- ' CHANGELOG.md` answers on demand,"
            " and a rebase restores such a paragraph in silence."
        )


def test_the_patterns_still_match() -> None:
    """The guard above passes for free if its patterns match nothing.

    Which is the failure mode of every assertion written in the negative,
    and the one the files it reads cannot reveal: a pattern reworded past
    the text it forbids leaves a green test guarding an empty set.
    """
    for text in _RESURRECTED:
        assert any(re.search(p, text) for p in _FORBIDDEN), text

    for pattern in _FORBIDDEN:
        assert any(re.search(pattern, t) for t in _RESURRECTED), pattern
