# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

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
import importlib
import json
import pkgutil
import re
from dataclasses import fields
from pathlib import Path
from typing import Any

import pytest

import btclib

_TESTS_DIR = Path(__file__).parent


def module_names() -> list[str]:
    """Return every module of the installed btclib, the top-level one included.

    Here rather than at each site that walks the package, for the reason
    `public_classes_with` below gives. What the walk covers -- a second
    package root, a different prefix, a module it has to skip -- is
    settled here for all of them, and a copy that disagreed would be red
    nowhere: each site asserts against whatever its own walk found.
    """
    return [
        "btclib",
        *(module.name for module in pkgutil.walk_packages(btclib.__path__, "btclib.")),
    ]


def public_classes_with(method_name: str) -> set[str]:
    """Return every public btclib class offering that method, module included.

    Found rather than listed, which is what makes an inventory a promise:
    a class added to the library has to appear in the test that holds the
    method to its contract, or be named an exclusion there. A class this
    walk cannot reach is one no caller can import either.

    The module is part of the name because three classes are called
    `Sig`. A private class is skipped, the contract being about what a
    caller can reach.

    Here rather than in the one test that first needed it: the files that
    call it hold the same classes to contracts of their own, and none of
    them owns the walk.
    """
    found = set()
    for module_name in module_names():
        module = importlib.import_module(module_name)
        for obj in vars(module).values():
            if not isinstance(obj, type):
                continue
            if not getattr(obj, "__module__", "").startswith("btclib"):
                continue
            if obj.__qualname__.startswith("_"):
                continue
            if callable(getattr(obj, method_name, None)):
                found.add(f"{obj.__module__}.{obj.__qualname__}")
    return found


def load(*relative_path: str, encoding: str = "ascii") -> Any:
    """Read a vendored JSON vector file, named relative to `tests/`.

    Naming a vector file by its path from the test suite root, rather
    than from the test module that reads it, is what lets two packages
    share one file without the `dirname(dirname(__file__))` walk that
    breaks the moment a test module moves.
    """
    with _TESTS_DIR.joinpath(*relative_path).open(encoding=encoding) as file_:
        return json.load(file_)


def load_csv(*relative_path: str, encoding: str = "ascii") -> list[list[str]]:
    """Read a vendored csv vector file, header row dropped."""
    with _TESTS_DIR.joinpath(*relative_path).open(
        newline="", encoding=encoding
    ) as file_:
        return list(csv.reader(file_))[1:]


def load_bin(*relative_path: str) -> bytes:
    """Read a vendored file of consensus bytes: a block, a transaction.

    Named from `tests/` for the same reason as the two above, and it is
    what a block is read by outside `tests/block`: the signed
    transactions of a block are the fixtures of more than one question
    about them.
    """
    with _TESTS_DIR.joinpath(*relative_path).open("rb") as file_:
        return file_.read()


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


def replace_unchecked(instance: Any, **changes: Any) -> Any:
    """Return `instance` with the given fields changed, validation skipped.

    `dataclasses.replace` always re-validates through `__init__` -- right
    for a modified copy meant to stay valid, wrong for a fixture built to
    fail its own `assert_valid` on purpose. Every frozen, validating
    dataclass in this project takes `check_validity` the same
    keyword-only way (`CONTRIBUTING.md`'s "The public surface"), so this
    is the one helper any of them can use in place of the direct field
    mutation a frozen instance now refuses.
    """
    current = {field.name: getattr(instance, field.name) for field in fields(instance)}
    current.update(changes)
    return type(instance)(**current, check_validity=False)


# What a test asking libsecp256k1 for the right answer is marked with.
#
# The suite validates btclib's Python arithmetic *against* the bindings,
# so a few tests hold both implementations and compare them. Those cannot
# run where only one exists, and marking them is what lets the rest of
# the suite -- twenty-two thousand tests that ask btclib a question and
# not libsecp256k1 -- run in the configuration issue #966 is about.
#
# A marker and not a `skipif`, with `conftest.py` turning it into a skip
# where the bindings are absent. One name then does both jobs: `pytest -m
# "not bindings"` names the same set the no-bindings job runs, which is
# what a contributor wants long before a second install, and the
# registration in pyproject.toml has something to be strict about. A
# `skipif` alone skips and selects nothing; `pytest.mark.bindings` around
# one does not compose -- a MarkDecorator is not a test function, so it
# is stored as an argument of the outer mark and the skip is lost, which
# a run with the bindings uninstalled reports as 503 failures.
#
# Here rather than in `conftest.py`: conftest is pytest's to import, and
# importing it by name as well is the shape that bites when an import
# mode or a rootdir changes. This package already holds the shared
# loaders these same modules import.
needs_bindings = pytest.mark.bindings
