# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The gate for what a public function's name promises about its answer.

CONTRIBUTING.md's "Every public function validates its inputs" states the
vocabulary: `assert_*` refuses and returns None, `is_*` and `verify*`
answer a bool about a value of a declared type, and `check_*` answers a
bool *and* refuses what cannot be an answer -- the one prefix that warns
a caller it still needs an `except`.

This file is why the statement is worth making. `check_` had drifted to
four meanings at once -- nine refusals returning None, two verdicts, a
converter returning bytes and a query returning a pair of bools -- and a
prefix that says four things says nothing, which is what issue #814
found. Nothing in the tree noticed, because the vocabulary was a habit
and not a rule.

So it is a rule now, read off the annotations rather than off a list of
names somebody keeps in step. What it cannot see is the *contract*: that
`is_p2sh` is total over its values where `check_pub_key` is not is a
promise in prose, and only the return type is here.

`_OTHER_CONTRACT` is what the rule does not cover, one entry per reason.
It ratchets the way every list in `input_validation_test.py` does:
`test_what_is_excepted_still_needs_to_be` fails on an entry that has come
into line, so a name cannot keep an exemption it has stopped needing.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_LIBRARY = Path(__file__).parents[1] / "src" / "btclib"

# what each prefix promises the return type is. `verify` is matched
# anywhere in the name and not only at the front: `batch_verify_`,
# `partial_sig_verify` and `anti_exfil_host_verify` are verifications,
# and reading the front alone is what left them out of issue #814's first
# census
_PROMISED: dict[str, str] = {
    "assert_": "None",
    "check_": "bool",
    "is_": "bool",
    "verify": "bool",
}

# an op code implementation is named for the op code, and OP_VERIFY,
# OP_EQUALVERIFY and their kind carry the word: they answer with the
# stack, or with nothing, and are no more verifications in this sense
# than OP_CHECKSIG is a `check_`
_AN_OP_CODE = "op_"

_A_SCRIPT_FAILURE_SAYS_WHERE = (
    "the script engine refuses instead of answering: a ScriptError carries"
    " the command index and the stack depth, which is the whole of what an"
    " engine is asked for, and a bool would drop it"
)

_AN_ASSERT_WITH_A_PAYLOAD = (
    "it is the Signer's own question -- five conditions on the psbt, and"
    " the message they prove it commits to -- so refusing and handing back"
    " what was validated are one answer, not two"
)

_OTHER_CONTRACT: dict[str, str] = {
    "btclib.bip322.assert_signed_message": _AN_ASSERT_WITH_A_PAYLOAD,
    "btclib.script.engine.__init__.verify_amounts": _A_SCRIPT_FAILURE_SAYS_WHERE,
    "btclib.script.engine.__init__.verify_input": _A_SCRIPT_FAILURE_SAYS_WHERE,
    "btclib.script.engine.__init__.verify_transaction": _A_SCRIPT_FAILURE_SAYS_WHERE,
    "btclib.script.engine.script.verify_script": _A_SCRIPT_FAILURE_SAYS_WHERE,
    "btclib.script.engine.tapscript.verify_key_path": _A_SCRIPT_FAILURE_SAYS_WHERE,
    "btclib.script.engine.tapscript.verify_script_path_vc0": (
        _A_SCRIPT_FAILURE_SAYS_WHERE
    ),
}


# A bool need not carry one of the four prefixes: an English predicate is
# the same family and the same contract, and `is_` would cost the reading.
# Each entry carries the reason it keeps the name it has -- and the
# ratchet below is what closes the vocabulary all the same, an entry that
# has gained a prefix being one this list no longer excuses (issue #814)
_ITS_STANDARD_SPELLING = (
    "the name is the standard's: BIP379's malleability analysis says a"
    " miniscript mixes timelocks and has duplicate keys, and the three"
    " PSBT_GLOBAL_TX_MODIFIABLE bits are named after the field"
)

_A_PREDICATE_WITH_A_SUBJECT = (
    "`reads_back` is the round trip as a question, and the subject is the"
    " script: `is_read_back` would ask who reads it"
)

_THE_STANDARD_NAMES_THE_OPERATION = (
    "BIP158 queries a Golomb-coded set with `gcs_match`, and Core spells"
    " the pair `GCSFilter::Match` and `MatchAny`: an `is_` would rename"
    " the operation the standard defines, and the answer is not a"
    " property of the filter but of the element it is asked about"
)

_CAN_ADDRV1_ASKS_CAPACITY_NOT_VALIDITY = (
    "`is_addrv1` would name the encoding rather than the question asked of"
    " it -- whether an `addr` message, which has no field for the network"
    " id, has room for this peer at all. `can_` is issue #1581's own name"
    " for it and btclib-node's before that, and it is what `network_address`"
    " asks first before refusing on the same question"
)

_ENGLISH_PREDICATE: dict[str, str] = {
    "btclib.block.block_filter.match": _THE_STANDARD_NAMES_THE_OPERATION,
    "btclib.block.block_filter.match_any": _THE_STANDARD_NAMES_THE_OPERATION,
    "btclib.descriptors.miniscript.has_duplicate_keys": (_ITS_STANDARD_SPELLING),
    "btclib.descriptors.miniscript.mixes_timelocks": (_ITS_STANDARD_SPELLING),
    "btclib.descriptors.miniscript.reads_back": _A_PREDICATE_WITH_A_SUBJECT,
    "btclib.p2p.addrv2.can_addrv1": _CAN_ADDRV1_ASKS_CAPACITY_NOT_VALIDITY,
    "btclib.psbt.psbt.has_sig_hash_single": _ITS_STANDARD_SPELLING,
    "btclib.psbt.psbt.inputs_modifiable": _ITS_STANDARD_SPELLING,
    "btclib.psbt.psbt.outputs_modifiable": _ITS_STANDARD_SPELLING,
}


def _promised_by(name: str) -> str | None:
    """Return the type the name promises, or None if it promises nothing."""
    if name.startswith(_AN_OP_CODE):
        return None
    for prefix, promised in _PROMISED.items():
        if name.startswith(prefix) or (prefix == "verify" and prefix in name):
            return promised
    return None


def _return_type(returns: ast.expr) -> str:
    """Return what a function's annotation promises its caller, TypeIs as bool.

    `TypeIs[Octets]` narrows a caller's type checker and answers exactly
    `True` or `False` at runtime (PEP 742), the same as the `bool` it
    replaced on `utils.is_octets` -- so a name promising `bool` is kept
    to that promise by one, and this is the one place the annotation is
    read for both censuses below. The caller's own `node.returns is not
    None` already established what this takes, `ast.expr` rather than
    `ast.FunctionDef` so mypy narrows it there instead of losing the
    check across the call.
    """
    unparsed = ast.unparse(returns)
    if unparsed.startswith("TypeIs["):
        return "bool"
    return unparsed


def _named() -> dict[str, str]:
    """Return every public function whose name promises a return type.

    Methods included, a property being one: `BIP32KeyData.is_private`
    promises a bool as much as `script_pub_key.is_p2sh` does.

    The dotted name is the file's path and keeps the `__init__` of a
    package module, which is what `input_validation_test.py`'s walk does
    and is importable either way: one spelling across the two gates.
    """
    found: dict[str, str] = {}
    for path in sorted(_LIBRARY.rglob("*.py")):
        module = ".".join(path.relative_to(_LIBRARY.parent).with_suffix("").parts)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef) or node.name.startswith("_"):
                continue
            if _promised_by(node.name) is None:
                continue
            # every function of this package is annotated, mypy running
            # strict over it, so an unannotated one is a state the tree
            # does not reach
            assert node.returns is not None
            found[f"{module}.{node.name}"] = _return_type(node.returns)
    return found


def _argument_less_bools() -> dict[str, bool]:
    """Return every public argument-less bool, and whether it is a property.

    "No argument" means none besides `self`: a bool about the object it is
    read off, which is the family the question applies to. One that takes
    something is a function of it, and `@property` is not open to it.
    """
    found: dict[str, bool] = {}
    for path in sorted(_LIBRARY.rglob("*.py")):
        module = ".".join(path.relative_to(_LIBRARY.parent).with_suffix("").parts)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        # classes and what is in them, not `ast.walk(tree)`: a property is
        # a class thing, which is what `_class_members` below says in as
        # many words, so a module-level function is out of scope however
        # few arguments it takes and cannot be told to become one
        for cls in ast.walk(tree):
            if not isinstance(cls, ast.ClassDef):
                continue
            for node in ast.walk(cls):
                if not isinstance(node, ast.FunctionDef) or node.name.startswith("_"):
                    continue
                if node.returns is None or ast.unparse(node.returns) != "bool":
                    continue
                arguments = [
                    a.arg
                    for a in [
                        *node.args.posonlyargs,
                        *node.args.args,
                        *node.args.kwonlyargs,
                    ]
                    if a.arg != "self"
                ]
                if arguments:
                    continue
                decorated = {ast.unparse(d) for d in node.decorator_list}
                found[f"{module}.{node.name}"] = _is_a_read(decorated)
    return found


# an argument-less member of a public class is a read, and a read is a
# `@property`. These are the shapes that are not a read, by what they do
# rather than by a list of names -- which is what keeps the rule from
# needing one (issue #814):
#
# - `assert_*` refuses, and a property that refuses is a trap: reading
#   `obj.assert_valid` evaluates the method and throws it away
# - `get_*` talks to a node or an explorer, so it costs a round trip and
#   can fail; the prefix is the warning and a property would hide it
# - `to_*` converts, and hands back a new object rather than a read of
#   this one
# - `close`, `wipe` and `clear` are each an action with a side effect
_NOT_A_READ = ("assert_", "get_", "to_")
_AN_ACTION = frozenset({"clear", "close", "wipe"})

# hashlib's own API, mirrored in a Protocol, and hashlib draws the line
# itself: `digest()`, `hexdigest()` and `copy()` are calls where
# `block_size`, `digest_size` and `name` are attributes. So these three
# are named one by one rather than the class being exempt -- a property
# here would stop anything `hashlib.new` returns from satisfying
# HashObject, and the other three are reads and stay properties
_MIRRORS_HASHLIB = frozenset(
    {
        "btclib.alias.HashObject.copy",
        "btclib.alias.HashObject.digest",
        "btclib.alias.HashObject.hexdigest",
    }
)


def _is_a_read(decorated: set[str]) -> bool:
    """Return whether the decorators make this a read rather than a call.

    `functools.cached_property` is one as much as `property` is --
    `Script.asm` parses once and is read thereafter -- and testing the set
    for `"property"` alone missed it, which is what this function exists
    to stop being written twice.
    """
    return bool(
        decorated & {"property", "cached_property", "functools.cached_property"}
    )


def _class_members() -> dict[str, bool]:
    """Return every argument-less member of a public class, property or not.

    A property is a class thing, so a module-level function is out of
    scope however few arguments it takes -- `fetch.fetcher.client_errors`
    is a context manager and could not be one. Methods of a private class
    are out too: `_Decoder` is not API.
    """
    found: dict[str, bool] = {}
    for path in sorted(_LIBRARY.rglob("*.py")):
        module = ".".join(path.relative_to(_LIBRARY.parent).with_suffix("").parts)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for cls in ast.walk(tree):
            if not isinstance(cls, ast.ClassDef) or cls.name.startswith("_"):
                continue
            for node in cls.body:
                if not isinstance(node, ast.FunctionDef) or node.name.startswith("_"):
                    continue
                decorated = {ast.unparse(d) for d in node.decorator_list}
                if {"staticmethod", "classmethod"} & decorated:
                    continue
                # no filter for a `@x.setter`: one takes the value it
                # sets, so the argument count below excludes it already
                arguments = [
                    a.arg
                    for a in [
                        *node.args.posonlyargs,
                        *node.args.args,
                        *node.args.kwonlyargs,
                    ]
                    if a.arg != "self"
                ]
                if arguments or node.args.vararg or node.args.kwarg:
                    continue
                key = f"{module}.{cls.name}.{node.name}"
                found[key] = _is_a_read(decorated)
    return found


def _public_bools() -> list[str]:
    """Return every public function that answers a bool, however named.

    The dotted name drops the class, as `_named` above does: a method and
    a module function of one name are one entry, which is the spelling
    `input_validation_test.py` uses too.
    """
    found: list[str] = []
    for path in sorted(_LIBRARY.rglob("*.py")):
        module = ".".join(path.relative_to(_LIBRARY.parent).with_suffix("").parts)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef) or node.name.startswith("_"):
                continue
            if node.returns is not None and _return_type(node.returns) == "bool":
                found.append(f"{module}.{node.name}")
    return sorted(found)


_NAMED = _named()
_GATED = sorted(set(_NAMED) - _OTHER_CONTRACT.keys())
_PUBLIC_BOOLS = _public_bools()
_ARGUMENT_LESS_BOOLS = _argument_less_bools()
_CLASS_MEMBERS = _class_members()


@pytest.mark.parametrize("dotted", _GATED)
def test_the_name_says_what_the_answer_is(dotted: str) -> None:
    """The rule, over every public name that carries one of the prefixes."""
    promised = _promised_by(dotted.rpartition(".")[2])
    assert _NAMED[dotted] == promised, (
        f"{dotted} returns {_NAMED[dotted]} where its name promises {promised}"
    )


@pytest.mark.parametrize("dotted", sorted(_OTHER_CONTRACT))
def test_what_is_excepted_still_needs_to_be(dotted: str) -> None:
    """An entry of `_OTHER_CONTRACT` cannot outlive the reason for it."""
    promised = _promised_by(dotted.rpartition(".")[2])
    assert _NAMED[dotted] != promised, (
        f"{dotted} now returns {promised}: delete its line from _OTHER_CONTRACT"
    )


def test_the_walk_reaches_what_it_claims() -> None:
    """One name per prefix it must find, and the two kinds it must not.

    A walk that found nothing would pass the test above.
    """
    assert _NAMED["btclib.script.script_pub_key.is_p2sh"] == "bool"
    assert _NAMED["btclib.script.engine.script.check_pub_key"] == "bool"
    assert _NAMED["btclib.script.taproot.check_output_pubkey"] == "bool"
    assert _NAMED["btclib.ecc.dsa.verify_"] == "bool"
    assert _NAMED["btclib.ecc.ssa.batch_verify"] == "bool"
    assert _NAMED["btclib.ecc.dsa.assert_as_valid"] == "None"
    # a method, and a property among them
    assert _NAMED["btclib.bip32.bip32.is_private"] == "bool"

    # an op code is named for the op code
    assert "btclib.script.engine.script_op_codes.op_verify" not in _NAMED
    assert "btclib.script.engine.script_op_codes.op_equalverify" not in _NAMED
    # a private name, and a name that promises nothing
    assert "btclib.hashes._assert_valid_hf" not in _NAMED
    assert "btclib.utils.bytes_from_octets" not in _NAMED


def test_check_says_one_thing() -> None:
    """`check_` is two functions, and issue #814 is why they are named.

    The prefix meant four things at once. Pinning what is left keeps a
    tenth `check_` from being added without the question being asked
    again: a refusal is an `assert_`, a converter is named for what it
    returns, and a query for what it answers.
    """
    checks = {d for d in _NAMED if d.rpartition(".")[2].startswith("check_")}
    assert checks == {
        "btclib.script.engine.script.check_pub_key",
        "btclib.script.taproot.check_output_pubkey",
    }


@pytest.mark.parametrize("dotted", _PUBLIC_BOOLS)
def test_every_public_bool_is_named_by_the_vocabulary(dotted: str) -> None:
    """A bool carries one of the four prefixes, or is named in the list.

    What this closes is the gap the prefixes alone leave: they promise a
    shape to a caller who sees one, and say nothing about a bool that
    carries none. Seven did before issue #814 -- four were renamed and
    three more were, `Block.is_segwit` joining the `Tx.is_segwit` it is
    computed from -- and the six that are left keep their names for the
    reason each entry gives.

    So a bool added from here on either carries a prefix or is a decision
    somebody wrote down, which is what `check_` drifting for four
    meanings cost the tree.
    """
    name = dotted.rpartition(".")[2]
    assert (
        _promised_by(name) is not None
        or name.startswith(_AN_OP_CODE)
        or dotted in _ENGLISH_PREDICATE
    ), f"{dotted} answers a bool and its name promises nothing"


@pytest.mark.parametrize("dotted", sorted(_ENGLISH_PREDICATE))
def test_what_keeps_its_english_name_still_needs_to(dotted: str) -> None:
    """A line of `_ENGLISH_PREDICATE` cannot outlive the name it excuses."""
    assert dotted in _PUBLIC_BOOLS, f"{dotted} is no longer a public bool"
    name = dotted.rpartition(".")[2]
    assert _promised_by(name) is None, (
        f"{dotted} carries a prefix now: delete its line from _ENGLISH_PREDICATE"
    )


@pytest.mark.parametrize("dotted", sorted(_ARGUMENT_LESS_BOOLS))
def test_a_bool_about_the_object_is_a_property(dotted: str) -> None:
    """A bool taking nothing but `self` is read, not called.

    Thirty were properties and six were methods -- `Tx.is_segwit`,
    `Tx.is_coinbase` and their four siblings in `tx/` and `block/` -- so
    the six were the exception and are properties now (issue #814). The
    shape a reader has to remember is one shape.

    It also spends the one hazard `truthy-function` covers rather than
    relying on it: `if tx.is_segwit:` with the parentheses forgotten was a
    bound method, and every bound method is true. mypy names that, and
    mypy is a gate here; a property makes it unsayable, which is the
    stronger of the two.
    """
    assert _ARGUMENT_LESS_BOOLS[dotted], (
        f"{dotted} answers a bool about the object and takes nothing:"
        " it is a @property, not a method"
    )


def test_the_walk_reaches_both_shapes() -> None:
    """One of each shape, so the filter is doing work rather than nothing."""
    assert _ARGUMENT_LESS_BOOLS["btclib.tx.tx.is_segwit"] is True
    assert _ARGUMENT_LESS_BOOLS["btclib.bip32.bip32.is_private"] is True
    # a bool of an argument is a function of it, and no property can be
    assert "btclib.script.script_pub_key.is_p2sh" not in _ARGUMENT_LESS_BOOLS
    assert "btclib.ecc.dsa.verify" not in _ARGUMENT_LESS_BOOLS


@pytest.mark.parametrize("dotted", sorted(_CLASS_MEMBERS))
def test_an_argument_less_member_is_read_not_called(dotted: str) -> None:
    """Whatever it answers, a member that takes nothing is a `@property`.

    The bool rule above, generalised to every return type: `PsbtView.tx`
    was a property and `PsbtView.prevouts` a method, two reads of one
    lazy view spelled two ways, and `master_fingerprint` and
    `capabilities` were methods on the signer contract while every
    implementation of them returned a stored value.

    What is not a read is here by shape and not by a list of names, which
    is what keeps this rule from needing one.
    """
    name = dotted.rpartition(".")[2]
    if name.startswith(_NOT_A_READ) or name in _AN_ACTION or dotted in _MIRRORS_HASHLIB:
        assert not _CLASS_MEMBERS[dotted], (
            f"{dotted} is a @property and its name says it is not a read:"
            " rename it, or drop the decorator"
        )
        return
    assert _CLASS_MEMBERS[dotted], (
        f"{dotted} takes nothing but self: it is a @property, not a method"
    )


def test_the_walk_reaches_every_shape_of_member() -> None:
    """One of each, so neither branch above is running over nothing."""
    assert _CLASS_MEMBERS["btclib.psbt.psbt_view.PsbtView.prevouts"] is True
    assert _CLASS_MEMBERS["btclib.psbt_signer.PsbtSigner.master_fingerprint"] is True
    # a cached_property is a read too, which testing for "property" alone
    # would have missed
    assert _CLASS_MEMBERS["btclib.script.script.Script.asm"] is True
    # and the three of HashObject that hashlib spells as attributes
    assert _CLASS_MEMBERS["btclib.alias.HashObject.digest_size"] is True
    # and the four shapes that are not a read
    # OutPoint's and not Tx's, which takes an `unsigned_template` and so
    # is not argument-less at all
    assert _CLASS_MEMBERS["btclib.tx.out_point.OutPoint.assert_valid"] is False
    assert _CLASS_MEMBERS["btclib.psbt.psbt.Psbt.to_v2"] is False
    assert _CLASS_MEMBERS["btclib.hwi.HwiSigner.close"] is False
    assert _CLASS_MEMBERS["btclib.alias.HashObject.digest"] is False
    assert _CLASS_MEMBERS["btclib.fetch.fetcher.Fetcher.get_block_count"] is False
