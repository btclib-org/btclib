#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Every example in the documentation is what the library answers.

A page of worked examples is a promise, and prose cannot keep it: an
output pasted by hand is true on the afternoon it was pasted and silently
false after the next rename. Written as doctests the examples are run --
here, by the suite -- so a drifted example is a red test rather than a
lie a reader discovers by typing it.

A test rather than `sphinx-build -b doctest`. It needs no environment the
suite does not already have, it runs on every interpreter of the matrix
instead of on one runner, `tests-passed` gates it without a line being
added to any `needs` list, and `uv run pytest` stays the whole command.
The docs build has its own job and asks a different question -- whether
the page renders -- so neither covers the other.

Which pages are examined is read off the pages: a doctest prompt is what
makes one an example page, and the api reference stanzas have none. That
way a page added under `docs/source/` is covered the moment it carries an
example, with nothing here to remember to update.
"""

import doctest
import io
from contextlib import redirect_stdout
from pathlib import Path

import pytest

_DOCS_DIR = Path(__file__).parents[1] / "docs" / "source"
_PROMPT = ">>> "


def _pages_with_examples() -> list[str]:
    """The names of the documentation pages that carry doctests."""
    return sorted(
        page.name
        for page in _DOCS_DIR.glob("*.rst")
        if _PROMPT in page.read_text(encoding="utf-8")
    )


@pytest.mark.parametrize("page_name", _pages_with_examples())
def test_the_examples_are_what_the_library_answers(page_name: str) -> None:
    # doctest reports a failure by writing a diff, and the diff is the
    # whole value of running it: captured here so that it reaches the
    # assertion message instead of pytest's captured-stdout section,
    # which xdist does not always show for a parametrized case
    report = io.StringIO()
    with redirect_stdout(report):
        results = doctest.testfile(
            str(_DOCS_DIR / page_name),
            module_relative=False,
            encoding="utf-8",
            # no optionflags: an example whose output is elided is an
            # example checked in part, and the point of this file is that
            # a reader can type the page in and get the page back. Where
            # a long exception message would make that unreasonable the
            # page carries an inline "# doctest:" directive, which is
            # visible in the rendered documentation and therefore
            # reviewable
        )
    assert results.attempted, f"no example ran in {page_name}"
    assert not results.failed, report.getvalue()


def test_the_pages_were_found_at_all() -> None:
    """Guard the test above against passing vacuously.

    An empty parameter set is a skip, which reads as green: a wrong
    `_DOCS_DIR`, or a page that stops being reST, would silently stop
    checking every example in the documentation. The wheel ships no
    tests, so this file only ever runs from a source tree or an sdist,
    and both carry `docs/`.
    """
    assert _DOCS_DIR.is_dir()
    assert _pages_with_examples()
