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

# --------------------------------------------------------------------------
# AES-128 and AES-256, shared by `ecc/ecies_test.py`'s CBC vectors and
# `bip38_test.py`'s ECB ones.
#
# **Why a test writes its own block cipher.** btclib takes no
# cryptographic dependency and ships no cipher: hashlib and the
# secp256k1 bindings are the whole of it, `ecc.ecies`'s module docstring
# has the argument in full, and `ecc.dsa`/`ecc.ssa` inherit it -- a
# table-driven AES leaks its key through cache timing, and a
# timing-vulnerable cipher is a worse thing to ship than none. None of
# that reaches this file: the wheel and the sdist carry no tests, so
# nothing here is installed on a user's machine, and the keys used
# against it below are fixed published test vectors, so there is no
# secret for a timing side channel to leak. A test-only dependency would
# buy the same vectors for the price of a package neither module
# otherwise needs, and would make this reasoning invisible, since a
# dependency does not explain itself.
#
# It is written for the vectors, not for use: correct, small enough to
# read against FIPS-197, and slow. Do not import it from anywhere but
# `ecc/ecies_test.py` and `bip38_test.py`.
# --------------------------------------------------------------------------

_AES_BLOCK_SIZE = 16
# FIPS-197 section 5.2, the round constants a 128- or 256-bit key
# schedule needs: the highest index either ever reads is `i // nk - 1`
# with `i < 4 * (nr + 1)`, which stays below 7 for both key lengths
_AES_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _aes_xtime(a: int) -> int:
    """Multiply by x in GF(2^8), modulo the AES polynomial x^8+x^4+x^3+x+1."""
    a <<= 1
    return a ^ 0x11B if a & 0x100 else a


def _aes_mul(a: int, b: int) -> int:
    """Multiply two elements of GF(2^8)."""
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = _aes_xtime(a)
        b >>= 1
    return result


def _aes_build_boxes() -> tuple[tuple[int, ...], tuple[int, ...]]:
    """Return the S-box and its inverse, derived rather than tabulated.

    A 256-entry table copied from somewhere is a table nobody can check;
    the definition is short enough to write instead. Each byte maps to its
    multiplicative inverse in GF(2^8) -- read off the exp/log tables of the
    generator 3, with zero mapping to itself -- under the AES affine
    transform, which is the byte xored with four rotations of itself and
    with 0x63.
    """
    exp = [0] * 255
    log = [0] * 256
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        x = _aes_mul(x, 3)

    sbox = []
    for i in range(256):
        inverse = 0 if i == 0 else exp[(255 - log[i]) % 255]
        rotated = inverse
        affine = inverse
        for _ in range(4):
            rotated = ((rotated << 1) | (rotated >> 7)) & 0xFF
            affine ^= rotated
        sbox.append(affine ^ 0x63)

    inv_sbox = [0] * 256
    for i, s in enumerate(sbox):
        inv_sbox[s] = i
    return tuple(sbox), tuple(inv_sbox)


_AES_SBOX, _AES_INV_SBOX = _aes_build_boxes()


def aes_expand_key(key: bytes) -> list[list[int]]:
    """Return the round keys of an AES-128 or AES-256 key, by its length.

    `nk` -- the key length in 32-bit words -- is 4 for AES-128 and 8 for
    AES-256; `nr`, the number of rounds, is `nk + 6` either way, FIPS-197
    table 1. The schedules differ in one place: AES-256's, alone among
    the three FIPS-197 defines, runs an extra SubWord with no rotation
    and no round constant every fourth word that RotWord does not
    already cover -- `i % nk == 4`, reachable only where `nk > 6`, so an
    AES-128 schedule never takes the branch and an AES-256 one always
    does at 6 of its 60 words.
    """
    nk = len(key) // 4
    nr = nk + 6
    words = [list(key[4 * i : 4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        word = list(words[i - 1])
        if i % nk == 0:
            word = [_AES_SBOX[b] for b in (*word[1:], word[0])]
            word[0] ^= _AES_RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            word = [_AES_SBOX[b] for b in word]
        words.append([a ^ b for a, b in zip(words[i - nk], word, strict=True)])
    return [
        [b for word in words[4 * r : 4 * r + 4] for b in word] for r in range(nr + 1)
    ]


# the state is 16 bytes in input order, so flat index 4*column+row: that is
# exactly how FIPS-197 fills its 4x4 array, column by column
def _aes_sub_bytes(state: list[int], box: tuple[int, ...]) -> list[int]:
    return [box[b] for b in state]


def _aes_shift_rows(state: list[int], *, inverse: bool = False) -> list[int]:
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            source = (c - r) % 4 if inverse else (c + r) % 4
            out[4 * c + r] = state[4 * source + r]
    return out


def _aes_mix_columns(state: list[int], *, inverse: bool = False) -> list[int]:
    coefficients = (14, 11, 13, 9) if inverse else (2, 3, 1, 1)
    out = [0] * 16
    for c in range(4):
        column = state[4 * c : 4 * c + 4]
        for r in range(4):
            acc = 0
            for k in range(4):
                acc ^= _aes_mul(column[k], coefficients[(k - r) % 4])
            out[4 * c + r] = acc
    return out


def _aes_add_round_key(state: list[int], round_key: list[int]) -> list[int]:
    return [a ^ b for a, b in zip(state, round_key, strict=True)]


def aes_encrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    """Encrypt one 16-byte block under an expanded key, no mode, no padding."""
    nr = len(round_keys) - 1
    state = _aes_add_round_key(list(block), round_keys[0])
    for rnd in range(1, nr):
        state = _aes_mix_columns(_aes_shift_rows(_aes_sub_bytes(state, _AES_SBOX)))
        state = _aes_add_round_key(state, round_keys[rnd])
    state = _aes_shift_rows(_aes_sub_bytes(state, _AES_SBOX))
    return bytes(_aes_add_round_key(state, round_keys[nr]))


def aes_decrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    """Decrypt one 16-byte block under an expanded key, no mode, no padding."""
    nr = len(round_keys) - 1
    state = _aes_add_round_key(list(block), round_keys[nr])
    for rnd in range(nr - 1, 0, -1):
        state = _aes_sub_bytes(_aes_shift_rows(state, inverse=True), _AES_INV_SBOX)
        state = _aes_mix_columns(
            _aes_add_round_key(state, round_keys[rnd]), inverse=True
        )
    state = _aes_sub_bytes(_aes_shift_rows(state, inverse=True), _AES_INV_SBOX)
    return bytes(_aes_add_round_key(state, round_keys[0]))


def aes_xor(a: bytes, b: bytes) -> bytes:
    """Return the byte-wise XOR of two equal-length buffers."""
    return bytes(x ^ y for x, y in zip(a, b, strict=True))
