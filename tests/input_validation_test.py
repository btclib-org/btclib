# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The gate for the one rule about a public function's inputs.

> Every public function guarantees the validation of all its inputs,
> directly or indirectly. A malformed argument leaves as
> `BTClibTypeError` or `BTClibValueError`.

Both are `BTClibException`, which is what makes this one predicate
instead of a tuple that has to be kept in step with the hierarchy -- the
reason issue #743 landed that base class before this test rather than
after it.

## How it calls what it calls

The library's input types are few and well bounded, most of them named in
`btclib/alias.py` and the key and path ones beside their converters.
`_MALFORMED` gives each of them values that are not of it, and the walk
finds every public module-level function whose *required* parameters are
all of those types. Those it can call with no fixture and no knowledge of
what the function does, and what it asserts is the rule as written:
something is raised, and it is a `BTClibException`.

Every argument is malformed at once, which is not weaker than one
malformed argument among valid ones: whichever the function refuses
first, the rule says it must refuse it as a btclib error. And it needs no
valid values, which is what makes the walk automatic -- a valid `Octets`
is 20 bytes for one function, 32 for another and any length for a third,
so the table of those is the hand-written thing this avoids.

## What it does not reach, and why that is not a hole to plug here

A **parameter with a default** is never driven: to reach `hf` or
`network` the arguments before them would have to be valid, which is the
table this design is built to do without. Those two are gated by hand
instead, where their own checks live.

A **method**, and a function taking a `Tx`, a `Psbt` or a callback, needs
a valid instance the vocabulary cannot build. That is the part of issue
#744 that stays hand-read. `test_the_walk_reaches_what_it_claims` pins
what the walk does find, so a narrowing of it fails here rather than
quietly running over less.

## The three lists, and which way each ratchets

- `_MALFORMED` is the vocabulary, and every name in it is a type this
  tree still declares: a rename would otherwise shrink the walk in
  silence, which `test_the_vocabulary_is_the_libraries_input_types` is
  against.
- `_EXCLUDED` is what must not be held to the rule this way, with the
  reason. What is in it is a family whose own comment states the design.
- `_OPEN` is what issue #744's census left, each entry naming the class
  that escapes. It can only shrink: `test_what_is_open_is_still_open`
  fails on an entry that has become compliant, as RUF100 fails an unused
  `noqa`, so a fix cannot land without deleting its line.
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path
from typing import Any

import pytest

from btclib.exceptions import BTClibException

_LIBRARY = Path(__file__).parents[1] / "btclib"

# a value of none of the library's input types is what each of these is,
# and the tuples are read round-robin so that a function taking three
# parameters of one type is called with three different wrong values.
# Constants and not a strategy: what this gate reports has to be the same
# on two runs, `_OPEN` below being read as a statement about the tree
_MALFORMED: dict[str, tuple[Any, ...]] = {
    "BIP32Key": (None, 1.5, "not an xkey"),
    "BinaryData": ("not hex at all", None, 1.5),
    "DerPath": (-1, [2**32], "m/x", 1.5),
    "Integer": ("not hex at all", None, 1.5),
    "Key": (None, 1.5, "not a key"),
    "Octets": ("not hex at all", "9", tuple(range(4)), None),
    "Point": ((1,), "not a point", None),
    "PrvKey": (None, 1.5, "not a key"),
    "PubKey": (None, 1.5, "not a key"),
    "ScriptList": (None, 1.5, "not a list"),
    "String": (1, None, 1.5),
}

# one reason for nine functions, and it is `script_pub_key._is_funct`'s
# own: "these bool functions answer 'are these bytes a p2sh script', so
# bytes that are not are False". A malformed hex string is bytes that are
# not, and what `bytes.fromhex` raises for it is a ValueError, which that
# `except ValueError` catches on purpose. A wrong *type* is not covered
# by it and does raise, which is the half of those nine the rule reaches
_A_PREDICATE_ANSWERS_FALSE = (
    "a bool function about a script answers False for bytes that are not"
    " one, and a malformed hex string is bytes that are not: the reason is"
    " in script_pub_key._is_funct, which catches ValueError alone"
)

_EXCLUDED: dict[str, str] = {
    "btclib.script.script_pub_key.is_nulldata": _A_PREDICATE_ANSWERS_FALSE,
    "btclib.script.script_pub_key.is_p2ms": _A_PREDICATE_ANSWERS_FALSE,
    "btclib.script.script_pub_key.is_p2pk": _A_PREDICATE_ANSWERS_FALSE,
    "btclib.script.script_pub_key.is_p2pkh": _A_PREDICATE_ANSWERS_FALSE,
    "btclib.script.script_pub_key.is_p2sh": _A_PREDICATE_ANSWERS_FALSE,
    "btclib.script.script_pub_key.is_p2tr": _A_PREDICATE_ANSWERS_FALSE,
    "btclib.script.script_pub_key.is_p2wpkh": _A_PREDICATE_ANSWERS_FALSE,
    "btclib.script.script_pub_key.is_p2wsh": _A_PREDICATE_ANSWERS_FALSE,
    "btclib.script.script_pub_key.is_segwit": _A_PREDICATE_ANSWERS_FALSE,
}

# what issue #744's census left, by the class that escapes. Deleting a
# line is how a fix lands, the test below failing on an entry that has
# stopped leaking, so this cannot go stale in either direction
_OPEN: dict[str, str] = {
    "btclib.b32.has_segwit_prefix": "AttributeError",
    "btclib.b32.p2wpkh": "TypeError",
    "btclib.b32.witness_from_address": "TypeError",
    "btclib.b58.h160_from_address": "TypeError",
    "btclib.b58.p2pkh": "TypeError",
    "btclib.b58.p2wpkh_p2sh": "TypeError",
    "btclib.b58.wif_from_prv_key": "TypeError",
    "btclib.base58.decode": "TypeError",
    "btclib.bech32.decode": "AttributeError",
    "btclib.bip32.bip32.crack_prv_key": "TypeError",
    "btclib.bip32.bip32.derive": "TypeError",
    "btclib.bip32.bip32.xpub_from_xprv": "TypeError",
    "btclib.bip32.der_path.bytes_from_der_path": "TypeError",
    "btclib.bip32.der_path.hardenings_from_der_path": "TypeError",
    "btclib.bip32.der_path.indexes_from_der_path": "TypeError",
    "btclib.bip32.der_path.str_from_der_path": "TypeError",
    "btclib.bip322.sign": "AttributeError",
    "btclib.bip322.to_sign_psbt": "AttributeError",
    "btclib.bip44.address_from_der_path": "TypeError",
    "btclib.bip85.bytes_entropy_from_root_key": "TypeError",
    "btclib.bip85.drng_from_der_path": "TypeError",
    "btclib.bip85.entropy_from_der_path": "TypeError",
    "btclib.bip85.mnemonic_from_root_key": "TypeError",
    "btclib.bip85.wif_from_root_key": "TypeError",
    "btclib.bip85.xprv_from_root_key": "TypeError",
    "btclib.curves.curve.double_mult": "TypeError",
    "btclib.curves.sec_point.bytes_from_point": "TypeError",
    "btclib.descriptors.descriptors.account_descriptors": "TypeError",
    "btclib.ecc.dleq.generate_proof": "TypeError",
    "btclib.ecc.dleq.verify_proof": "no exception",
    "btclib.ecc.ecies.derive_keys": "TypeError",
    "btclib.ecc.ellswift.create": "TypeError",
    "btclib.ecc.musig2.individual_pub_key": "TypeError",
    "btclib.ecc.musig2.nonce_gen": "TypeError",
    "btclib.psbt.psbt_utils.deserialize_map": "AttributeError",
    "btclib.script.script.parse": "AttributeError",
    "btclib.script.script_pub_key.address": "no exception",
    "btclib.script.sig_hash.redeem_script": "AttributeError",
    "btclib.script.taproot.output_prvkey": "TypeError",
    "btclib.script.taproot.output_prvkey_from_merkle_root": "TypeError",
    "btclib.script.taproot.parse": "AttributeError",
    "btclib.script.taproot.serialize": "TypeError",
    "btclib.silent_payments.keys_from_address": "TypeError",
    # the name of a BIP352 function, and detect-secrets reads any
    # "...secret": "..." as one
    "btclib.silent_payments.shared_secret": "TypeError",  # pragma: allowlist secret
    "btclib.slip132.address_from_xkey": "TypeError",
    "btclib.slip132.address_from_xpub": "TypeError",
    "btclib.slip132.p2pkh_xkey": "TypeError",
    "btclib.slip132.p2wpkh_p2sh_xkey": "TypeError",
    "btclib.slip132.p2wpkh_xkey": "TypeError",
    "btclib.to_prv_key.int_from_prv_key": "TypeError",
    "btclib.to_prv_key.prv_keyinfo_from_prv_key": "TypeError",
    "btclib.to_pub_key.fingerprint": "TypeError",
    "btclib.to_pub_key.point_from_key": "TypeError",
    "btclib.to_pub_key.pub_keyinfo_from_key": "TypeError",
    "btclib.to_pub_key.pub_keyinfo_from_prv_key": "TypeError",
    "btclib.tx_or_psbt.tx_or_psbt_from_any": "AttributeError",
    "btclib.utils.bytesio_from_binarydata": "no exception",
    "btclib.var_bytes.parse": "AttributeError",
    "btclib.var_int.parse": "AttributeError",
}


def _alias_of(annotation: ast.expr) -> str | None:
    """Return the input type an annotation names, `X | None` included."""
    name = ast.unparse(annotation).replace(" | None", "").strip()
    return name if name in _MALFORMED else None


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
        for node in ast.parse(path.read_text()).body:
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


def _leak(dotted: str) -> str | None:
    """Return the class of what escapes the rule, or None if it holds."""
    module_name, _, name = dotted.rpartition(".")
    function = getattr(importlib.import_module(module_name), name)
    aliases = _DRIVABLE[dotted]
    for round_ in range(max(len(_MALFORMED[a]) for a in aliases)):
        args = [_MALFORMED[a][round_ % len(_MALFORMED[a])] for a in aliases]
        try:
            function(*args)
        except BTClibException:
            continue
        # the class of what came out is the finding, so every one of them
        # is caught and named rather than let out of the walk
        except Exception as e:  # noqa: BLE001
            return type(e).__name__
        return "no exception"
    return None


_GATED = sorted(set(_DRIVABLE) - _EXCLUDED.keys() - _OPEN.keys())


@pytest.mark.parametrize("dotted", _GATED)
def test_a_malformed_argument_leaves_as_a_btclib_exception(dotted: str) -> None:
    """The rule, over every public function the vocabulary can drive."""
    leak = _leak(dotted)
    assert leak is None, f"{dotted} answers a malformed argument with {leak}"


@pytest.mark.parametrize("dotted", sorted(_OPEN))
def test_what_is_open_is_still_open(dotted: str) -> None:
    """A fix cannot land without deleting its line from `_OPEN`.

    The ratchet, and the reason the list is in the tree rather than in a
    report: an entry that has become compliant fails here, so what is
    left cannot drift the way a census read by hand did.
    """
    assert _leak(dotted) == _OPEN[dotted], (
        f"{dotted} no longer answers with {_OPEN[dotted]}: delete its line"
        " from _OPEN, or correct it to what it answers with now"
    )


def test_the_vocabulary_is_the_libraries_input_types() -> None:
    """A renamed type would narrow the walk without failing anything.

    Every name in `_MALFORMED` is still declared under `btclib/`, and
    every type `alias.py` declares and a public parameter is annotated
    with is either in the vocabulary or named below with the reason no
    wrong value can be built for it.
    """
    declared: set[str] = set()
    in_alias_py: set[str] = set()
    annotated: set[str] = set()
    for path in sorted(_LIBRARY.rglob("*.py")):
        tree = ast.parse(path.read_text())
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

    assert set(_MALFORMED) <= declared

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
    assert in_alias_py & annotated <= set(_MALFORMED) | without_a_wrong_value


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


def test_every_driven_function_is_gated_excluded_or_open() -> None:
    """No function leaves the run without a line saying why."""
    assert not _EXCLUDED.keys() & _OPEN.keys()
    assert _EXCLUDED.keys() <= set(_DRIVABLE)
    assert _OPEN.keys() <= set(_DRIVABLE)
    assert set(_GATED) | _EXCLUDED.keys() | _OPEN.keys() == set(_DRIVABLE)
