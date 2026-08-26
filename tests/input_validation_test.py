# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The gate for the two rules about a public function's inputs.

> Every public function guarantees the validation of all its inputs,
> directly or indirectly. A malformed argument leaves as
> `BTClibTypeError` or `BTClibValueError`.

CONTRIBUTING.md's "Every public function validates its inputs" states it,
and which of the two classes comes out is not a coin toss -- it is the
distinction issue #814 settled, so this file drives the two separately:

- **a value of a type the signature does not declare** is the caller's
  own mistake, and leaves as a `BTClibTypeError`. Every function the walk
  can drive, without exception.
- **a value of a declared type that no valid input carries** is a fact
  about the input, and leaves as a `BTClibException` -- unless the
  function answers a `bool` about it, in which case the answer is
  `False`. `_ANSWERS_FALSE` is that family, and it is a family: nine
  script predicates, `b32.is_segwit_prefixed` and `ecc.dleq.verify_proof`.

Both are `BTClibException`, which is what makes the second rule one
predicate instead of a tuple that has to be kept in step with the
hierarchy -- the reason issue #743 landed that base class before this
test rather than after it.

## How it calls what it calls

The library's input types are few and well bounded, most of them named in
`src/btclib/alias.py` and the key and path ones beside their converters.
`_WRONG_TYPE` and `_WRONG_VALUE` give each of them values of the two
kinds, and the walk finds every public module-level function whose
*required* parameters are all of those types. Those it can call with no
fixture and no knowledge of what the function does.

Every argument is wrong at once, which is not weaker than one wrong
argument among valid ones: whichever the function refuses first, the rule
says how it must refuse it. And it needs no valid values, which is what
makes the walk automatic -- a valid `Octets` is 20 bytes for one
function, 32 for another and any length for a third, so the table of
those is the hand-written thing this avoids.

## What it does not reach, and why that is not a hole to plug here

A **parameter with a default** is never driven: to reach `hf` or
`network` the arguments before them would have to be valid, which is the
table this design is built to do without. Those two are gated by hand
where their own checks live, and the two families of them that are large
enough to be walked have a file each: `tests/curve_parameter_test.py` for
every parameter declaring a curve, `tests/bool_parameter_test.py` for
every `bool` one. Each carries the table this walk avoids, and a walk of
its own over the parameter it is about, so the table cannot go stale
quietly.

A **method**, and a function taking a `Tx`, a `Psbt` or a callback, needs
a valid instance the vocabulary cannot build. That is the part of issue
#744 that stays hand-read, and `tests/bool_contract_test.py` is where the
bool half of it is driven from fixtures instead.
`test_the_walk_reaches_what_it_claims` pins what the walk does find, so a
narrowing of it fails here rather than quietly running over less.

## The three lists, and which way each ratchets

- `_WRONG_TYPE` and `_WRONG_VALUE` are the vocabulary, and every name in
  them is a type this tree still declares: a rename would otherwise
  shrink the walk in silence, which
  `test_the_vocabulary_is_the_libraries_input_types` is against. Which
  dict a value belongs in is the only judgement in this file, and it is
  the annotation's to make: `1.5` is no `Octets`, `"not hex at all"` is
  one that will not decode.
- `_ANSWERS_FALSE` is what answers rather than refuses a wrong value,
  with the reason. It can only shrink:
  `test_what_answers_false_still_does` fails on an entry that has started
  refusing, as RUF100 fails an unused `noqa`, so a line cannot outlive
  the reason for it.

There was a fourth, `_OPEN`, holding what issue #744's census left, and
an `_EXCLUDED` that mixed the two kinds of wrong value into one
exemption. Both are gone: with the vocabularies split, nothing needs
excusing from the type rule, and what the old list held was the bool
contract, which `_ANSWERS_FALSE` now states as one. `pytest.raises` went
with them -- a hand-rolled verdict had a branch for a native exception
that no function of the library reaches any more, and naming the class
is what `pytest.raises` does without one.
"""

from __future__ import annotations

import ast
import importlib
from collections.abc import Callable, Iterator
from functools import partial
from pathlib import Path
from typing import Any

import pytest

from btclib.exceptions import BTClibException, BTClibTypeError

_LIBRARY = Path(__file__).parents[1] / "src" / "btclib"

# a value of no type the alias declares: the caller's own mistake, and a
# call mypy refuses. The tuples are read round-robin so that a function
# taking three parameters of one type is called with three different
# wrong values. Constants and not a strategy: what this gate reports has
# to be the same on two runs, the lists below being read as statements
# about the tree
_WRONG_TYPE: dict[str, tuple[Any, ...]] = {
    "BIP32Key": (None, 1.5),
    "BinaryData": (None, 1.5),
    "DerPath": (None, 1.5),
    "Integer": (None, 1.5),
    # an Octets, beside None and 1.5: every Octets is itself iterable, so
    # a signature reading Sequence[Octets] or Iterable[Octets] accepts
    # one as far as mypy goes, and a function that does not refuse it by
    # name zips through its bytes instead (issue #1405). All four Octets
    # spellings, a guard naming three of the four otherwise passing this
    # walk (issue #1434)
    "Iterable[Octets]": (
        None,
        1.5,
        b"\xaa\xbb\xcc\xdd",
        bytearray(b"\xaa\xbb\xcc\xdd"),
        memoryview(b"\xaa\xbb\xcc\xdd"),
    ),
    "Key": (None, 1.5),
    "Octets": (None, 1.5, tuple(range(4))),
    "Point": (None, 1.5, "not a point"),
    "PrvKey": (None, 1.5),
    "PubKey": (None, 1.5),
    "ScriptList": (None, 1.5, "not a list"),
    "Sequence[Octets]": (
        None,
        1.5,
        b"\xaa\xbb\xcc\xdd",
        bytearray(b"\xaa\xbb\xcc\xdd"),
        memoryview(b"\xaa\xbb\xcc\xdd"),
    ),
    "String": (None, 1.5, 1),
}

# a value of a declared type that no valid input carries: a fact about
# the input, and the half a bool function answers False about. Every one
# of these type checks -- that is what puts it in this dict rather than
# in the one above -- so a `# type: ignore` is never needed to build the
# call, which is the same line drawn twice
_WRONG_VALUE: dict[str, tuple[Any, ...]] = {
    "BIP32Key": ("not an xkey",),
    "BinaryData": ("not hex at all",),
    # a string no path spelling reads, an index below zero, and one above
    # the four bytes a BIP32 index has
    "DerPath": ("m/x", -1, [2**32]),
    "Integer": ("not hex at all",),
    "Key": ("not a key",),
    # a hex string that is not hex, and one of odd length
    "Octets": ("not hex at all", "9"),
    # a tuple of the wrong arity, and a pair of ints that is no point:
    # run time cannot tell tuple[int] from tuple[int, int], so the arity
    # is a value here and not a type
    "Iterable[Octets]": (["not hex at all"],),
    "Point": ((1,), (1, 2)),
    "PrvKey": ("not a key",),
    "PubKey": ("not a key",),
    "ScriptList": (["OP_NOT_AN_OP_CODE"],),
    "Sequence[Octets]": (["not hex at all"],),
    "String": ("not an address",),
}

# one reason for eleven functions, nine of which are
# `script_pub_key._is_funct`'s own: "these bool functions answer 'are
# these bytes a p2sh script', so bytes that are not are False". The other
# two answer the same shape of question one layer up -- does this string
# start as a bech32 address, does this proof hold -- and CONTRIBUTING.md
# states the rule for all of them beside the validation one.
#
# `taproot.check_output_pubkey` is deliberately *not* here, and is the
# reason `check_` keeps its prefix: it answers a bool and refuses a
# malformed control block, that being no proof rather than a disproof
_A_BOOL_ANSWERS_FALSE = (
    "a bool answers about a value of a declared type, so a value that is"
    " not one is False rather than a refusal: issue #814 settled it, and"
    " CONTRIBUTING.md's 'Every public function validates its inputs'"
    " states it"
)

_ANSWERS_FALSE: dict[str, str] = {
    "btclib.b32.is_segwit_prefixed": _A_BOOL_ANSWERS_FALSE,
    "btclib.ecc.dleq.verify_proof": _A_BOOL_ANSWERS_FALSE,
    "btclib.ecc.pedersen.verify": _A_BOOL_ANSWERS_FALSE,
    "btclib.script.script_pub_key.is_nulldata": _A_BOOL_ANSWERS_FALSE,
    "btclib.script.script_pub_key.is_p2ms": _A_BOOL_ANSWERS_FALSE,
    "btclib.script.script_pub_key.is_p2pk": _A_BOOL_ANSWERS_FALSE,
    "btclib.script.script_pub_key.is_p2pkh": _A_BOOL_ANSWERS_FALSE,
    "btclib.script.script_pub_key.is_p2sh": _A_BOOL_ANSWERS_FALSE,
    "btclib.script.script_pub_key.is_p2tr": _A_BOOL_ANSWERS_FALSE,
    "btclib.script.script_pub_key.is_p2wpkh": _A_BOOL_ANSWERS_FALSE,
    "btclib.script.script_pub_key.is_p2wsh": _A_BOOL_ANSWERS_FALSE,
    "btclib.script.script_pub_key.is_segwit": _A_BOOL_ANSWERS_FALSE,
}


def _alias_of(annotation: ast.expr) -> str | None:
    """Return the input type an annotation names, `X | None` included."""
    name = ast.unparse(annotation).replace(" | None", "").strip()
    return name if name in _WRONG_TYPE else None


def _drivable() -> dict[str, list[str]]:
    """Return every public function the vocabulary can call, by dotted name.

    Required parameters only: what carries a default is what a caller may
    leave out, so a function is driven on the arguments it insists on.
    All of them have to be in the vocabulary -- one `Tx` and the walk has
    nothing to pass.
    """
    found: dict[str, list[str]] = {}
    for path in sorted(_LIBRARY.rglob("*.py")):
        module = ".".join(path.relative_to(_LIBRARY.parent).with_suffix("").parts)
        for node in ast.parse(path.read_text(encoding="utf-8")).body:
            if not isinstance(node, ast.FunctionDef) or node.name.startswith("_"):
                continue
            positional = [*node.args.posonlyargs, *node.args.args]
            required = positional[: len(positional) - len(node.args.defaults)]
            # `is not None` narrows for mypy and never filters: mypy runs
            # strict over this package, so a parameter without an
            # annotation is a state the library does not reach
            annotations = [a.annotation for a in required if a.annotation is not None]
            aliases = [_alias_of(a) for a in annotations]
            if required and len(aliases) == len(required) and all(aliases):
                found[f"{module}.{node.name}"] = [a for a in aliases if a]
    return found


_DRIVABLE = _drivable()


def _calls(
    dotted: str, vocabulary: dict[str, tuple[Any, ...]]
) -> Iterator[Callable[[], Any]]:
    """Yield one prepared call per round, every argument wrong at once.

    The vocabulary is the parameter, and it is the whole of what tells the
    two rules apart: the same walk, the same function, two kinds of wrong
    value.
    """
    module_name, _, name = dotted.rpartition(".")
    function = getattr(importlib.import_module(module_name), name)
    aliases = _DRIVABLE[dotted]
    for round_ in range(max(len(vocabulary[a]) for a in aliases)):
        args = [vocabulary[a][round_ % len(vocabulary[a])] for a in aliases]
        # partial and not a lambda, which would close over the loop
        # variables and be read on a later round
        yield partial(function, *args)


_DRIVEN = sorted(_DRIVABLE)
_REFUSES_A_WRONG_VALUE = sorted(set(_DRIVABLE) - _ANSWERS_FALSE.keys())


@pytest.mark.parametrize("dotted", _DRIVEN)
def test_a_wrong_type_leaves_as_a_btclib_type_error(dotted: str) -> None:
    """The first rule, and it has no exceptions.

    Every public function the walk can drive, `_ANSWERS_FALSE` included:
    a bool is an answer about a value, so a type it does not declare is
    not something it answers about either.

    `BTClibTypeError` and not `BTClibException`: this is where the class
    is the point. A bare `TypeError` fails here as a `BTClibValueError`
    does -- the first is a leak from underneath the library, the second
    is the library calling a caller's mistake a fact about the input.
    """
    for call in _calls(dotted, _WRONG_TYPE):
        with pytest.raises(BTClibTypeError):
            call()


@pytest.mark.parametrize("dotted", _REFUSES_A_WRONG_VALUE)
def test_a_wrong_value_leaves_as_a_btclib_exception(dotted: str) -> None:
    """The second rule, over everything that does not answer False.

    `BTClibException` and not one of the three: which of them a malformed
    value deserves is the function's to decide -- a size is a
    `BTClibValueError`, a bool where a number belongs is a
    `BTClibTypeError` -- and the contract a caller is given is the base.
    """
    for call in _calls(dotted, _WRONG_VALUE):
        with pytest.raises(BTClibException):
            call()


@pytest.mark.parametrize("dotted", sorted(_ANSWERS_FALSE))
def test_what_answers_false_still_does(dotted: str) -> None:
    """A line of `_ANSWERS_FALSE` cannot outlive the reason for it.

    `is False` and not a falsy answer: these eleven return a bool, and an
    empty string or a None passing for one is the shape issue #776 found
    in `script_pub_key.address`, which answered "" for a None.
    """
    for call in _calls(dotted, _WRONG_VALUE):
        assert call() is False


def test_the_vocabulary_is_the_libraries_input_types() -> None:
    """A renamed type would narrow the walk without failing anything.

    Every name in the two vocabularies is still declared under
    `src/btclib/`, and
    every type `alias.py` declares and a public parameter is annotated
    with is either in the vocabulary or named below with the reason no
    wrong value can be built for it.
    """
    declared: set[str] = set()
    in_alias_py: set[str] = set()
    annotated: set[str] = set()
    for path in sorted(_LIBRARY.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names = {
            node.targets[0].id
            for node in tree.body
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id[0].isupper()
        }
        declared |= names
        if path.name == "alias.py":
            in_alias_py = names
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef) or node.name.startswith("_"):
                continue
            arguments = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
            annotated |= {
                ast.unparse(a.annotation).replace(" | None", "").strip()
                for a in arguments
                if a.annotation is not None
            }

    # `Sequence[Octets]` and `Iterable[Octets]` are not declarations of
    # their own -- `Octets` is -- so a renamed `Octets` is still caught
    # by unwrapping one level before checking
    def _is_declared(alias: str) -> bool:
        for wrapper in ("Sequence[", "Iterable["):
            if alias.startswith(wrapper) and alias.endswith("]"):
                return alias[len(wrapper) : -1] in declared
        return alias in declared

    assert set(_WRONG_TYPE) == set(_WRONG_VALUE)
    assert all(_is_declared(alias) for alias in _WRONG_TYPE)

    without_a_wrong_value = {
        # three Literals: a value outside them is what mypy refuses, and a
        # test passing one would be testing the type checker
        "BIP44ScriptType",
        "NetworkField",
        "ScriptType",
        # the two hash-function types are always behind a default -- `hf`
        # is the last parameter of everything that takes one -- so the
        # walk cannot reach them for the reason the module docstring
        # gives. `hashes._assert_valid_hf` is the check, and
        # tests/hashes_test.py, dsa_test.py and ssa_test.py are where it
        # is held to it
        "HashDigestF",
        "HashF",
        # a callable, and the same again: its wrong values are the
        # non-callables, and it is never a required parameter
        "CipherF",
        # the internal coordinates: no public parameter takes them from a
        # caller, `curves` converting to them and back
        "JacPoint",
        # a nested structure whose wrong values are its leaves', and its
        # leaves are Octets and int
        "TaprootScriptTree",
    }
    assert in_alias_py & annotated <= set(_WRONG_TYPE) | without_a_wrong_value


def test_the_walk_reaches_what_it_claims() -> None:
    """The shapes the walk must find, and two it must not.

    A walk that found nothing would pass every test above. One function
    per shape it has to reach -- a single parameter, two of different
    types, one behind a default it must ignore -- and the two kinds it
    must leave alone: a private name, and a function whose required
    parameters are not all in the vocabulary.
    """
    assert _DRIVABLE["btclib.hashes.sha256"] == ["Octets"]
    assert _DRIVABLE["btclib.bip32.bip32.derive"] == ["BIP32Key", "DerPath"]
    assert _DRIVABLE["btclib.to_pub_key.pub_keyinfo_from_key"] == ["Key"]
    # `network` and `compressed` carry defaults and are not driven
    assert _DRIVABLE["btclib.b58.p2pkh"] == ["Key"]

    assert "btclib.hashes._assert_valid_hf" not in _DRIVABLE
    # a required parameter the vocabulary cannot build: a Tx, a Psbt
    assert "btclib.script.sig_hash.legacy" not in _DRIVABLE
    assert "btclib.psbt.psbt.finalize" not in _DRIVABLE


def test_every_driven_function_is_under_both_rules() -> None:
    """No function leaves the run without a line saying why."""
    assert _ANSWERS_FALSE.keys() <= set(_DRIVABLE)
    assert set(_DRIVEN) == set(_DRIVABLE)
    assert set(_REFUSES_A_WRONG_VALUE) | _ANSWERS_FALSE.keys() == set(_DRIVABLE)
