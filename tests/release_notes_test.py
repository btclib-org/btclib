#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""The four counts CHANGELOG.md and HISTORY.md state about themselves.

Both files open by saying how many entries they hold, and both name the
number in words. That is the one fact in either file nothing derives:
prose can be reviewed, a number cannot -- it is right or wrong, and which
one is invisible unless somebody counts the bullets. Nobody did, twice.
`f295aaaf` left the file at 115 entries under a header reading "a hundred
and eleven", `1142e97b` took it to 116 under the same header, and the
drift survived both reviews because there was nothing to notice.

CONTRIBUTING.md and CLAUDE.md both answer this with a command to run by
hand. Written as a habit it did not work, which is the whole argument for
this module: the count is checked by the same run that checks everything
else, and an entry added without moving the header is a red test rather
than a claim nobody rereads.

Four numbers, not two. The entry count appears in both files, and so does
the size of the breaking-changes list -- HISTORY.md states it above the
list and CHANGELOG.md cross-references it. A source-breaking change that
moves one and not the other leaves the same kind of false claim behind.

A test rather than a hook, for the reasons `docs_test.py` gives: no
environment the suite does not already have, every interpreter of the
matrix rather than one runner, and `tests-passed` gates it without a line
in any `needs` list.
"""

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).parents[1]
_CHANGELOG = _ROOT / "CHANGELOG.md"
_HISTORY = _ROOT / "HISTORY.md"

# a markdown bullet at the start of a line: what both files count as an
# entry, and what `grep -c '^- '` counts in the command this replaces
_BULLET = re.compile(r"^- ", re.MULTILINE)

_UNITS = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6,
    "seven": 7, "eight": 8, "nine": 9, "ten": 10, "eleven": 11,
    "twelve": 12, "thirteen": 13, "fourteen": 14, "fifteen": 15,
    "sixteen": 16, "seventeen": 17, "eighteen": 18, "nineteen": 19,
}  # fmt: skip
_TENS = {
    "twenty": 20, "thirty": 30, "forty": 40, "fifty": 50,
    "sixty": 60, "seventy": 70, "eighty": 80, "ninety": 90,
}  # fmt: skip


def int_from_words(words: str) -> int:
    """Return the integer a spelled-out English number names.

    Enough of the language for what these two files say and no more: an
    optional "a hundred and", then a ten and a unit joined by a hyphen.
    Anything outside that raises rather than guessing, because a header
    this cannot read is a header that stopped matching the pattern the
    tests below look it up by -- which is itself worth a failure.
    """
    total = 0
    text = words.strip().lower()
    if text.startswith("a hundred and "):
        total, text = 100, text[len("a hundred and ") :]
    for part in text.split("-"):
        if part in _TENS:
            total += _TENS[part]
        elif part in _UNITS:
            total += _UNITS[part]
        else:
            msg = f"not a number this knows how to read: {words!r}"
            raise ValueError(msg)
    return total


def stated(path: Path, pattern: str) -> int:
    """Return the number `pattern` captures in `path`, as an int."""
    match = re.search(pattern, path.read_text(encoding="utf-8"), re.MULTILINE)
    assert match is not None, f"{path.name} no longer states it: {pattern}"
    return int_from_words(match[1])


def test_entry_count_is_what_both_files_say() -> None:
    """The bullets of CHANGELOG.md, against the count in both headers."""
    entries = len(_BULLET.findall(_CHANGELOG.read_text(encoding="utf-8")))
    assert entries == stated(_CHANGELOG, r"^(A hundred and [a-z-]+) entries, grouped")
    assert entries == stated(_HISTORY, r"the largest: (a hundred and [a-z-]+)\nentries")


def test_breaking_change_count_is_what_both_files_say() -> None:
    """The breaking-changes list, against the count above and beside it.

    The list runs from its own heading to the paragraph that closes it,
    which names the two changes deliberately left off; the bullets in
    between are the changes it claims.
    """
    history = _HISTORY.read_text(encoding="utf-8")
    start = history.index("### Breaking changes")
    end = history.index("Two changes are deliberately", start)
    listed = len(_BULLET.findall(history[start:end]))

    assert listed == stated(_HISTORY, r"^([A-Z][a-z-]+) changes break code")
    assert listed == stated(_CHANGELOG, r"lists the\n([a-z-]+) source-breaking changes")


def test_int_from_words_refuses_what_it_cannot_read() -> None:
    """The parser above raises rather than guessing.

    `stated` calls it on whatever the header matched, so a header reworded
    past the patterns must fail loudly: a silent 0 would make every
    assertion above compare a real count against nothing.
    """
    for words in ("a hundred and umpteen", "several", "a thousand"):
        with pytest.raises(ValueError, match="not a number this knows how to read"):
            int_from_words(words)

    # and it reads the two shapes the files actually use
    assert int_from_words("sixteen") == 16
    assert int_from_words("a hundred and forty-five") == 145
