#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Non-regression tests for btclib, and the vendored vectors they read.

The vector files are Bitcoin Core's, the BIPs' and a few other projects':
some thousands of cases in a couple of dozen files. Read them here and
hand them to `pytest.mark.parametrize`, so that a vector is a test rather
than one turn of a loop inside a single test function: xdist can then
spread them over the cores rather than serialize one indivisible function
per file, a failure names the vector instead of the loop that was running
it, and the vectors after the first failure still run -- a loop stops at
the first one and reports nothing about the rest.

Not a `pytest_generate_tests` hook, the other half of the suggestion in
issue 152: the hook lives in a conftest, away from the test it feeds, and
buys nothing here -- what each of these tests needs is a list built by a
few lines of Python, which parametrize takes directly.

Here rather than in a `tests/vectors.py`: name-tests-test runs at its
default, so every Python file under `tests/` is a test file except the
two basenames the hook exempts, `__init__.py` and `conftest.py`. A
`vectors_test.py` would name the one module here that holds no test as
though it held tests, so the loaders live in the package `__init__`,
beside the helpers of `tests/script/__init__.py` and
`tests/script_engine/__init__.py`: shared test code lives in the package
`__init__` at all three levels.
"""

import csv
import json
import re
from os import path
from typing import Any

_TESTS_DIR = path.dirname(__file__)


def load(*relative_path: str, encoding: str = "ascii") -> Any:
    """Read a vendored JSON vector file, named relative to `tests/`.

    Naming a vector file by its path from the test suite root, rather
    than from the test module that reads it, is what lets two packages
    share one file without the `dirname(dirname(__file__))` walk that
    breaks the moment a test module moves.
    """
    with open(path.join(_TESTS_DIR, *relative_path), encoding=encoding) as file_:
        return json.load(file_)


def load_csv(*relative_path: str, encoding: str = "ascii") -> list[list[str]]:
    """The same for a csv vector file, header row dropped."""
    with open(
        path.join(_TESTS_DIR, *relative_path), newline="", encoding=encoding
    ) as file_:
        return list(csv.reader(file_))[1:]


# what makes an id unreadable in a report and unusable in a -k expression:
# anything that is not a letter, a digit or a dash. Bitcoin Core comments
# hold spaces, quotes, parentheses and slashes; a descriptor holds a '#'
_NOT_IN_AN_ID = re.compile(r"[^0-9A-Za-z]+")


def vector_id(index: int, *description: object) -> str:
    """Name the vector at `index`: where it is, then what it is about.

    The position alone is what parametrize generates on its own, and it
    says where in the file to look but not what the case was testing;
    the description alone -- the comment of a Bitcoin Core vector, a
    script, an address -- reads well but is neither unique nor always
    there. Both, so that the red line of a report both identifies the
    vector in the file and says what it is, and `-k` can select it.

    Truncated, because a description is occasionally a whole script: an
    id is a name, and the vector file remains the place to read the
    case in full.
    """
    text = "-".join(str(d) for d in description if d)
    text = _NOT_IN_AN_ID.sub("-", text).strip("-")
    return f"{index}-{text[:60]}" if text else str(index)
