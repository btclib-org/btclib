#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""LICENSE, __copyright__ and pyproject.toml's author, checked together.

Issue #389: LICENSE named "Ferdinando M. Ametrano and btclib contributors"
while __copyright__ had already moved to "The btclib developers", each
edited on its own with nothing to notice the other had not moved too.
docs/source/conf.py reads __copyright__ back by regex instead of
declaring a value of its own, which is why that one file never drifted;
LICENSE and pyproject.toml's `authors` are both static text with nothing
deriving either from the other, so a change to one is silent everywhere
else until something reads the same sources this reads.

Regex rather than `tomllib` for the one line wanted out of
pyproject.toml: the floor here is 3.10, and `tomllib` is 3.11 -- the same
reason `release.yml` gives for reaching for it only from a `python -` a
workflow can pin to a newer interpreter, which a module in this package
cannot. Once 3.10 is dropped, `_pyproject_author` can read the file the
way `release.yml` already does.
"""

import re
from pathlib import Path

import btclib

_ROOT = Path(__file__).parents[1]
_HOLDER_RE = r"Copyright \([Cc]\) (\d{4})-(\d{4}) (.+)"
_AUTHOR_RE = r'authors\s*=\s*\[\{\s*name\s*=\s*"([^"]+)"'


def _license_holder() -> tuple[str, str, str]:
    text = (_ROOT / "LICENSE").read_text(encoding="utf-8")
    match = re.search(_HOLDER_RE, text)
    assert match, f"LICENSE has no 'Copyright (c) YYYY-YYYY holder' line: {text[:80]!r}"
    return match.group(1), match.group(2), match.group(3)


def _copyright_holder() -> tuple[str, str, str]:
    match = re.search(_HOLDER_RE, btclib.__copyright__)
    assert match, (
        f"btclib.__copyright__ does not match the expected shape: {btclib.__copyright__!r}"
    )
    return match.group(1), match.group(2), match.group(3)


def _pyproject_author() -> str:
    text = (_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(_AUTHOR_RE, text)
    assert match, "pyproject.toml has no 'authors = [{ name = ... }]' line"
    return match.group(1)


def test_license_and_copyright_name_the_same_holder_and_years() -> None:
    """The two places a human edits a year range must edit it together."""
    license_start, license_end, license_holder = _license_holder()
    copyright_start, copyright_end, copyright_holder = _copyright_holder()
    assert (license_start, license_end, license_holder) == (
        copyright_start,
        copyright_end,
        copyright_holder,
    ), (
        f"LICENSE says {license_start}-{license_end} {license_holder!r}, "
        f"btclib.__copyright__ says {copyright_start}-{copyright_end} "
        f"{copyright_holder!r}. Edit both together, or make one read the "
        "other -- docs/source/conf.py already does, for its own copyright "
        "line"
    )


def test_license_holder_matches_the_declared_author() -> None:
    """The wheel's `Author` metadata is the same holder LICENSE names."""
    _, _, license_holder = _license_holder()
    author = _pyproject_author()
    assert license_holder == author, (
        f"LICENSE names {license_holder!r}, pyproject.toml's author "
        f"{author!r}. A wheel built from one and read from the other "
        "would disagree about who holds the copyright"
    )
