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

This package is imported by every test module, before that module's own
body runs. Whatever this file executes at import time therefore executes
inside every module's own measured reach: the suite's coverage floor and
the weekly no-bindings census both read what the import reaches, never
what a test body goes on to call. A literal is safe to share here at
module scope. Anything that calls into btclib's own arithmetic is shared
as a function instead, computed only when a caller invokes it.
"""

import importlib
import json
import pkgutil
import re
import sys
import types
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import fields
from pathlib import Path
from typing import Any, NamedTuple

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


def defined_by_ellipticcurves(obj: object) -> bool:
    """Whether a name btclib publishes is an object of ellipticcurves.

    The curve arithmetic and the schemes other than `bms` are that
    package's, and btclib re-exports them (issue #2282): a test walking
    btclib's surface for a property of every function or class meets them
    under btclib's spellings, and that package's own suite is what asks
    them the question. So such a walk leaves them out, by where the object
    was defined rather than by a list of names.
    """
    return (getattr(obj, "__module__", None) or "").split(".")[0] == "ellipticcurves"


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


def workflow_files(directory: Path) -> tuple[Path, ...]:
    """Return the workflow files in `directory`, `.yml` and `.yaml` alike.

    GitHub reads both extensions, so a glob matching one spelling drops
    a workflow written with the other and leaves it out of whatever the
    caller holds the set to (issue #1874).

    The two are named rather than globbed as `*.y*ml`, which is `y`,
    anything, `ml`: that matches `test.yXml` and `test.ymml` as well,
    which GitHub does not run, and a caller comparing this set with
    `CONTRIBUTING.md`'s *What runs when* table would ask for a row
    naming a file no run exists for (issue #1879).

    Here rather than in each caller: `what_runs_when_test.py` compares
    the set with that table, `interpreters_test.py` reads each file for
    the interpreters it names, and a rule stated at both sites is a rule
    that gets corrected at one.
    """
    return tuple(sorted((*directory.glob("*.yml"), *directory.glob("*.yaml"))))


def load(*relative_path: str, encoding: str = "ascii") -> Any:
    """Read a vendored JSON vector file, named relative to `tests/`.

    Naming a vector file by its path from the test suite root, rather
    than from the test module that reads it, is what lets two packages
    share one file without the `dirname(dirname(__file__))` walk that
    breaks the moment a test module moves.
    """
    with _TESTS_DIR.joinpath(*relative_path).open(encoding=encoding) as file_:
        return json.load(file_)


def load_bin(*relative_path: str) -> bytes:
    """Read a vendored file of consensus bytes: a block, a transaction.

    Named from `tests/` for the same reason as the one above, and it is
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


# --------------------------------------------------------------------------
# One key pair's spellings, shared by `ecc/dsa_test.py` and `hashes_test.py`.
#
# Built inside a function rather than at module scope: this package is
# imported by every test module before that module's own body runs, so a
# value computed here at import time would run inside every module's own
# measured reach. `key_pair_spellings` below is not called until
# `ecc/dsa_test.py` or `hashes_test.py` calls it, so a module that asks no
# question about a key pair never reaches the curve arithmetic that builds
# one (issue #2120).
# --------------------------------------------------------------------------


class KeyPairSpellings(NamedTuple):
    """One key pair, in every spelling ecc/dsa_test.py and hashes_test.py read.

    The WIF and the xprv are here for the refusals alone: `ecc` takes a
    scalar and a point, and a spelling that carries a network is read
    where its format is defined -- a WIF by `b58`, an xprv by
    `btclib_wallet.bip32` (issue #1188). The xprv is written out as the
    Base58Check of its BIP32 serialization, so building it asks nothing
    of the package that parses one.
    """

    q: int
    q_hexstring: str
    plain_prv_keys: list[bytes | str]
    wif_compressed_string: str
    wif_uncompressed_string: str
    xprv_string: str
    Q: tuple[int, int]
    Q_compressed: bytes
    net_unaware_compressed_pub_keys: list[bytes | str]
    net_unaware_uncompressed_pub_keys: list[bytes | str]


def key_pair_spellings() -> KeyPairSpellings:
    """Build one `KeyPairSpellings`, computed on call rather than at import.

    `btclib.base58` and `btclib.curves` are imported
    inside this function rather than at the top of the module, for the
    reason the block comment above gives: a top-level import would run at
    collection, the same moment `Q = mult(q)` would.
    """
    from btclib.base58 import encode as b58encode  # noqa: PLC0415
    from btclib.curves import mult  # noqa: PLC0415

    q = 12
    q_bytes = q.to_bytes(32, byteorder="big", signed=False)
    q_hexstring = q_bytes.hex()
    q_hexstring2 = " " + q_hexstring + " "

    # the private-key spellings a curve reads: the scalar's octets and
    # their hex, naming neither a network nor a compression
    plain_prv_keys: list[bytes | str] = [q_hexstring, q_hexstring2]

    wif_compressed_string = b58encode(b"\x80" + q_bytes + b"\x01").decode("ascii")
    wif_uncompressed_string = b58encode(b"\x80" + q_bytes).decode("ascii")

    # BIP32's serialization: version, depth, parent fingerprint, child
    # index, chain code, and the key behind a zero octet
    xprv_bytes = (
        bytes.fromhex("04 88 ad e4")
        + b"\x00"
        + 4 * b"\x00"
        + 4 * b"\x00"
        + 32 * b"\x00"
        + b"\x00"
        + q_bytes
    )
    xprv_string = b58encode(xprv_bytes).decode("ascii")

    Q = mult(q)
    x_Q_bytes = Q[0].to_bytes(32, byteorder="big", signed=False)
    Q_compressed = (b"\x03" if (Q[1] & 1) else b"\x02") + x_Q_bytes
    Q_compressed_hexstring = Q_compressed.hex()
    Q_compressed_hexstring2 = " " + Q_compressed_hexstring + " "
    Q_compressed_hexstring3 = ("03" if (Q[1] & 1) else "02") + " " + x_Q_bytes.hex()
    Q_uncompressed = (
        b"\x04" + x_Q_bytes + Q[1].to_bytes(32, byteorder="big", signed=False)
    )
    Q_uncompressed_hexstring = Q_uncompressed.hex()
    Q_uncompressed_hexstring2 = " " + Q_uncompressed_hexstring + " "
    Q_uncompressed_hexstring3 = (
        "04 "
        + x_Q_bytes.hex()
        + " "
        + Q[1].to_bytes(32, byteorder="big", signed=False).hex()
    )

    # an xpub is the only public spelling that names a network, and it is
    # `btclib_wallet.bip32.pub_keyinfo_from_xpub`'s to read (issue #1188),
    # so every family here is network-unaware
    net_unaware_compressed_pub_keys: list[bytes | str] = [
        Q_compressed_hexstring,
        Q_compressed_hexstring2,
        Q_compressed_hexstring3,
    ]
    net_unaware_uncompressed_pub_keys: list[bytes | str] = [
        Q_uncompressed_hexstring,
        Q_uncompressed_hexstring2,
        Q_uncompressed_hexstring3,
    ]

    return KeyPairSpellings(
        q=q,
        q_hexstring=q_hexstring,
        plain_prv_keys=plain_prv_keys,
        wif_compressed_string=wif_compressed_string,
        wif_uncompressed_string=wif_uncompressed_string,
        xprv_string=xprv_string,
        Q=Q,
        Q_compressed=Q_compressed,
        net_unaware_compressed_pub_keys=net_unaware_compressed_pub_keys,
        net_unaware_uncompressed_pub_keys=net_unaware_uncompressed_pub_keys,
    )


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


# --------------------------------------------------------------------------
# The libsecp256k1 dispatch switched off, for the tests that ask the Python
# arm of a btclib function a question. The dispatch is ellipticcurves', and
# `curves.set_libsecp256k1_serving` is its public switch; `conftest.py`
# puts it back after every test, the switch being process-wide where
# `monkeypatch` undoes only its own patches.
# --------------------------------------------------------------------------


@contextmanager
def python_arithmetic() -> Iterator[None]:
    """Switch the dispatch off for a block, and back to what it was after.

    For a test comparing the two arms within itself: `conftest.py`
    restores the switch after the test, and this restores it after the
    block, so that what follows in the same test is delegated again.
    """
    from btclib.curves import (  # noqa: PLC0415
        is_libsecp256k1_serving,
        set_libsecp256k1_serving,
    )

    serving = is_libsecp256k1_serving()
    set_libsecp256k1_serving(serving=False)
    try:
        yield
    finally:
        set_libsecp256k1_serving(serving=serving)


def no_bindings_anywhere(monkeypatch: pytest.MonkeyPatch) -> None:
    """Switch the dispatch off, and every bound bindings callable out of reach.

    An arm gated on the dispatch can hold a binding of its own --
    `script.engine.script` imports the bindings' `dsa.verify`,
    `script.taproot` their `xonly` -- and `from ... import x as y` copies
    the object rather than looking it up again, so a patch on the module
    the bindings live in does not reach a name already copied out of it.

    So this walks every module already loaded under `btclib`,
    `ellipticcurves` or `btclib_secp256k1` and replaces every callable there
    whose `__module__` traces back to the bindings with one that raises,
    whichever module holds the name; the dispatch is switched off
    alongside it, since a caller with the switch still on and every name
    unreachable is not the configuration a missing install produces. An
    arm this does not cover fails by calling through instead of passing
    by measuring the bindings against themselves.
    """
    from btclib.curves import set_libsecp256k1_serving  # noqa: PLC0415

    def refuse(what: str) -> Callable[..., Any]:
        def asked(*_args: object, **_kwargs: object) -> Any:
            # a green suite is one where this never runs, the dispatch
            # switched off ruling the call out
            raise AssertionError(  # pragma: no cover -- the dispatch switched off keeps this uncalled
                f"the Python arm reached libsecp256k1: {what}"
            )

        return asked

    for mod_name, mod in list(sys.modules.items()):
        if mod_name.split(".")[0] not in {
            "btclib",
            "btclib_secp256k1",
            "ellipticcurves",
        }:
            continue
        for attr, value in list(vars(mod).items()):
            if isinstance(value, types.ModuleType) or not callable(value):
                continue
            origin = getattr(value, "__module__", None) or ""
            if origin.split(".")[0] == "btclib_secp256k1":
                monkeypatch.setattr(mod, attr, refuse(f"{mod_name}.{attr}"))

    set_libsecp256k1_serving(serving=False)
