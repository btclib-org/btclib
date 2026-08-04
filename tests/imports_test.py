#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the import graph of the `btclib` package.

Every module must be importable *first*, with no other btclib module in
sys.modules yet. Nothing else in the suite establishes that: a test
module reaches its subject through whatever the modules imported before
it have already pulled in, so a cycle that only bites the caller who
happens to arrive from the other side stays invisible.

The cycle this guards against is real: issue #147 found b58 ->
btclib.script -> script.script_pub_key -> b58, surviving only because
script_pub_key imported the modules rather than their names, so that the
partially initialized b58 was never asked for an attribute at import
time -- with nothing in that file to say so.
"""

from __future__ import annotations

import importlib
import pkgutil
import sys
from collections.abc import Iterator

import pytest

import btclib

MODULE_NAMES = [
    "btclib",
    *(module.name for module in pkgutil.walk_packages(btclib.__path__, "btclib.")),
]


def btclib_modules() -> list[str]:
    """Return the btclib modules in sys.modules, the bindings excluded."""
    # not startswith("btclib"), which would also catch the
    # btclib_libsecp256k1 bindings: they are not part of this package, and
    # reimporting a cffi extension module is another matter entirely
    return [
        name for name in sys.modules if name == "btclib" or name.startswith("btclib.")
    ]


@pytest.fixture
def unimported_btclib() -> Iterator[None]:
    """Hide every btclib module from sys.modules, then put it back.

    A subprocess per module would be the obvious way to get a virgin
    interpreter, and it is what issue #147 used to demonstrate the
    failure, but as a test it costs an interpreter start-up per module
    (~0.2 s, times some sixty of them) and buys nothing: the import
    machinery decides what to execute by consulting sys.modules and
    nothing else.

    What the modules imported inside the fixture must not do is outlive
    it. They are fresh objects, so a class reimported here is not the
    class the rest of the suite already holds a reference to, and an
    isinstance check across the two would fail.
    """
    saved = {name: sys.modules[name] for name in btclib_modules()}
    for name in saved:
        del sys.modules[name]
    try:
        yield
    finally:
        for name in btclib_modules():
            del sys.modules[name]
        sys.modules.update(saved)


@pytest.mark.parametrize("module_name", MODULE_NAMES)
def test_import_first(module_name: str, unimported_btclib: None) -> None:
    """Import each module first, with no other btclib module loaded."""
    assert importlib.import_module(module_name).__name__ == module_name


def test_address_encodings_stay_below_script(unimported_btclib: None) -> None:
    """b58 and b32 must not import btclib.script.

    script.script_pub_key imports both of them to render an address, so
    an import the other way is the cycle of issue #147 — and importing
    any script submodule is an import of btclib.script, whose __init__
    pulls script_pub_key in. p2sh-wrapped SegWit is the temptation: b58
    needs the [OP_0, witness program] redeem script, and spells it out
    instead of calling script.serialize.
    """
    importlib.import_module("btclib.b58")
    importlib.import_module("btclib.b32")
    assert not [name for name in btclib_modules() if name.startswith("btclib.script")]
