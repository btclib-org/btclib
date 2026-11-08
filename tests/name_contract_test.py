# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The gate for what a public function's name promises about its answer.

CONTRIBUTING.md's "Every public function validates its inputs" states the
vocabulary: `assert_*` and `validate_*` refuse and return None, `is_*`
and `verify*` answer a bool about a value of a declared type, and
`check_*` answers a bool *and* refuses what cannot be an answer -- the
one prefix that warns a caller it still needs an `except`.

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
# census. The others are matched at the front only, the underscore
# included, so `validated_network_name`, a converter, promises nothing
_PROMISED: dict[str, str] = {
    "assert_": "None",
    "check_": "bool",
    "is_": "bool",
    "validate_": "None",
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

_A_MESSAGE_VERIFY_HAS_SIX_ANSWERS = (
    "answers as Bitcoin Core's MessageVerify, whose three refusals and two"
    " false answers a caller maps one by one: a bool would merge them"
)

_OTHER_CONTRACT: dict[str, str] = {
    "btclib.bms.message_verify": _A_MESSAGE_VERIFY_HAS_SIX_ANSWERS,
    "btclib.script.engine.__init__.verify_amounts": _A_SCRIPT_FAILURE_SAYS_WHERE,
    "btclib.script.engine.__init__.verify_input": _A_SCRIPT_FAILURE_SAYS_WHERE,
    "btclib.script.engine.__init__.verify_transaction": _A_SCRIPT_FAILURE_SAYS_WHERE,
    "btclib.script.engine.script.verify_script": _A_SCRIPT_FAILURE_SAYS_WHERE,
    "btclib.script.engine.tapscript.verify_key_path": _A_SCRIPT_FAILURE_SAYS_WHERE,
    "btclib.script.engine.tapscript.verify_script_path_vc0": (
        _A_SCRIPT_FAILURE_SAYS_WHERE
    ),
}


# A bool need not carry one of the prefixes: an English predicate is
# the same family and the same contract, and `is_` would cost the reading.
# Each entry carries the reason it keeps the name it has -- and the
# ratchet below is what closes the vocabulary all the same, an entry that
# has gained a prefix being one this list no longer excuses (issue #814)
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
    " for it, and it is what `network_address` asks first before refusing"
    " on the same question"
)

_PERMITTED_DIFFICULTY_TRANSITION_IS_CORES_OWN_NAME = (
    "Bitcoin Core spells this `PermittedDifficultyTransition`"
    " (`src/pow.cpp`, at bitcoin/bitcoin@f0de87f040): an `is_` would"
    " rename the check a headers presync (Core's `HeadersSyncState`)"
    " asks by that exact name (issue #2418)"
)

_POLICY_IS_CORES_OWN_NAME = (
    "Bitcoin Core spells this `SpendsNonAnchorWitnessProg`"
    " (`src/policy/policy.cpp`, at bitcoin/bitcoin@f0de87f040):"
    " `btclib.policy` keeps the name a reader of Core's mempool looks for"
)

_ENGLISH_PREDICATE: dict[str, str] = {
    "btclib.block.block_filter.match": _THE_STANDARD_NAMES_THE_OPERATION,
    "btclib.block.block_filter.match_any": _THE_STANDARD_NAMES_THE_OPERATION,
    "btclib.p2p.addrv2.can_addrv1": _CAN_ADDRV1_ASKS_CAPACITY_NOT_VALIDITY,
    "btclib.block.proof_of_work.permitted_difficulty_transition": (
        _PERMITTED_DIFFICULTY_TRANSITION_IS_CORES_OWN_NAME
    ),
    "btclib.policy.spends_non_anchor_witness_prog": _POLICY_IS_CORES_OWN_NAME,
}


def _promised_by(name: str) -> str | None:
    """Return the type the name promises, or None if it promises nothing."""
    if name.startswith(_AN_OP_CODE):
        return None
    return next(
        (
            promised
            for prefix, promised in _PROMISED.items()
            if name.startswith(prefix) or (prefix == "verify" and prefix in name)
        ),
        None,
    )


def _return_type(returns: ast.expr) -> str:
    """Return what a function's annotation promises its caller, TypeIs as bool.

    `TypeIs[Octets]` narrows a caller's type checker and answers exactly
    `True` or `False` at runtime (PEP 742), the same as the `bool` it
    replaced on `utils.is_octets` -- so a name promising `bool` is kept
    to that promise by one, and this is the one place the annotation is
    read for both censuses below. The walks' own `node.returns is not
    None` narrows `returns` before it is passed, here and to `_answer`.
    """
    unparsed = ast.unparse(returns)
    if unparsed.startswith("TypeIs["):
        return "bool"
    return unparsed


_Function = ast.FunctionDef | ast.AsyncFunctionDef


_COROUTINE = "Coroutine["


def _answer(node: _Function, returns: ast.expr) -> str:
    """Return what a call to the function answers, as `_return_type` reads it.

    An `async def` answers a coroutine, whatever its annotation, and a
    coroutine keeps no prefix's promise: CONTRIBUTING.md's "Every public
    function validates its inputs" says why.
    """
    answer = _return_type(returns)
    if isinstance(node, ast.AsyncFunctionDef):
        return f"{_COROUTINE}{answer}]"
    return answer


def _named_in(module: str, source: str) -> dict[str, list[str]]:
    """Map each public name of a module that promises a type to its answers.

    A name defined twice, in two classes or in two branches of an `if`,
    lists both answers, each as `_answer` reads it, so neither hides the
    other.
    """
    found: dict[str, list[str]] = {}
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, _Function) or node.name.startswith("_"):
            continue
        if _promised_by(node.name) is None:
            continue
        # every function of this package is annotated, mypy running
        # strict over it, so an unannotated one is a state the tree
        # does not reach
        assert node.returns is not None
        answer = _answer(node, node.returns)
        found.setdefault(f"{module}.{node.name}", []).append(answer)
    return found


def _named() -> dict[str, list[str]]:
    """Map every public function whose name promises a type, as `_named_in`.

    Methods included, a property being one: `BIP32KeyData.is_private`
    promises a bool as much as `script_pub_key.is_p2sh` does.

    The dotted name is the file's path and keeps the `__init__` of a
    package module, which is what `input_validation_test.py`'s walk does
    and is importable either way: one spelling across the two gates.
    """
    found: dict[str, list[str]] = {}
    for path in sorted(_LIBRARY.rglob("*.py")):
        module = ".".join(path.relative_to(_LIBRARY.parent).with_suffix("").parts)
        found |= _named_in(module, path.read_text(encoding="utf-8"))
    return found


def _breaks_its_promise(dotted: str, returns: list[str]) -> bool:
    """Return whether a definition under the name breaks its promise."""
    promised = _promised_by(dotted.rpartition(".")[2])
    return any(returned != promised for returned in returns)


def _outlives_its_exception(dotted: str, returns: list[str]) -> str | None:
    """Return why an `_OTHER_CONTRACT` entry no longer holds, or None."""
    if not _breaks_its_promise(dotted, returns):
        promised = _promised_by(dotted.rpartition(".")[2])
        return f"{dotted} now returns {promised}: delete its line from _OTHER_CONTRACT"
    if any(returned.startswith(_COROUTINE) for returned in returns):
        return f"{dotted} is an `async def`, which no line of _OTHER_CONTRACT excuses"
    return None


def _argument_less_bools_in(module: str, source: str) -> dict[str, list[bool]]:
    """Return each public argument-less bool of a module, property or not.

    "No argument" means none besides `self`: a bool about the object it is
    read off, which is the family the question applies to. One that takes
    something is a function of it, and `@property` is not open to it. An
    `async def` is not recorded, for the reason `_class_members` gives.

    The dotted name drops the class, as `_named` does, and the value lists
    each definition: a method is not hidden by a property of the same name
    in another class.
    """
    found: dict[str, list[bool]] = {}

    def record(node: ast.FunctionDef) -> None:
        if node.name.startswith("_"):
            return
        if node.returns is None or ast.unparse(node.returns) != "bool":
            return
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
            return
        decorated = {ast.unparse(d) for d in node.decorator_list}
        found.setdefault(f"{module}.{node.name}", []).append(_is_a_read(decorated))

    # every node is visited once, and a function only inside a class: a
    # property is a class thing, which is what `_class_members` below says
    # in as many words, so a module-level function is out of scope however
    # few arguments it takes and cannot be told to become one
    def visit(node: ast.AST, in_class: bool) -> None:
        for child in ast.iter_child_nodes(node):
            if in_class and isinstance(child, ast.FunctionDef):
                record(child)
            visit(child, in_class or isinstance(child, ast.ClassDef))

    visit(ast.parse(source), in_class=False)
    return found


def _is_called(reads: list[bool]) -> bool:
    """Return whether a definition under the name is a method, not a read."""
    return not all(reads)


def _argument_less_bools() -> dict[str, list[bool]]:
    """Map every public argument-less bool, as `_argument_less_bools_in`."""
    found: dict[str, list[bool]] = {}
    for path in sorted(_LIBRARY.rglob("*.py")):
        module = ".".join(path.relative_to(_LIBRARY.parent).with_suffix("").parts)
        found |= _argument_less_bools_in(module, path.read_text(encoding="utf-8"))
    return found


# an argument-less member of a public class is a read, and a read is a
# `@property`. These are the shapes that are not a read, by what they do
# rather than by a list of names -- which is what keeps the rule from
# needing one (issue #814):
#
# - `assert_*` and `validate_*` refuse, and a property that refuses is a
#   trap: reading `obj.assert_valid` evaluates the method and throws it
#   away
# - `get_*` talks to a node or an explorer, so it costs a round trip and
#   can fail; the prefix is the warning and a property would hide it
# - `to_*` converts, and hands back a new object rather than a read of
#   this one
# - `close`, `flip`, `wipe` and `clear` are each an action with a side effect
_NOT_A_READ = ("assert_", "get_", "to_", "validate_")
_AN_ACTION = frozenset({"clear", "close", "flip", "wipe"})


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


def _is_not_a_read(name: str) -> bool:
    """Return whether a member's name says it is not a read."""
    return name.startswith(_NOT_A_READ) or name in _AN_ACTION


def _class_members_in(module: str, source: str) -> dict[str, bool]:
    """Return every argument-less member of a public class of a module.

    The key is the member's dotted path, each enclosing class and function
    included, so two nested classes of one name are two keys.
    """
    found: dict[str, bool] = {}

    def record(cls: ast.ClassDef, prefix: str) -> None:
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
            found[f"{prefix}{cls.name}.{node.name}"] = _is_a_read(decorated)

    # every node is visited, with the dotted path of the classes and
    # functions around it, as `public_parameter_test.py`'s walk does
    def visit(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef) and not child.name.startswith("_"):
                record(child, prefix)
            if isinstance(child, ast.ClassDef | _Function):
                visit(child, f"{prefix}{child.name}.")
            else:
                visit(child, prefix)

    visit(ast.parse(source), f"{module}.")
    return found


def _class_members() -> dict[str, bool]:
    """Return every argument-less member of a public class, property or not.

    A property is a class thing, so a module-level function is out of
    scope however few arguments it takes. Methods of a private class
    are out too: `_Decoder` is not API. So is an `async def`: its caller
    awaits it, which makes it a call.
    """
    found: dict[str, bool] = {}
    for path in sorted(_LIBRARY.rglob("*.py")):
        module = ".".join(path.relative_to(_LIBRARY.parent).with_suffix("").parts)
        found |= _class_members_in(module, path.read_text(encoding="utf-8"))
    return found


def _public_bools_in(module: str, source: str) -> set[str]:
    """Return every public function of a module that answers a bool.

    The dotted name drops the class, as `_named` above does: a method and
    a module function of one name are one entry, which is the spelling
    `input_validation_test.py` uses too. The gate below reads the name
    alone, so one entry judges every definition under it.
    """
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, _Function) or node.name.startswith("_"):
            continue
        if node.returns is not None and _answer(node, node.returns) == "bool":
            found.add(f"{module}.{node.name}")
    return found


def _public_bools() -> list[str]:
    """Return every public function that answers a bool, however named."""
    found: set[str] = set()
    for path in sorted(_LIBRARY.rglob("*.py")):
        module = ".".join(path.relative_to(_LIBRARY.parent).with_suffix("").parts)
        found |= _public_bools_in(module, path.read_text(encoding="utf-8"))
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
    assert not _breaks_its_promise(dotted, _NAMED[dotted]), (
        f"{dotted} returns {_NAMED[dotted]} where its name promises {promised}"
    )


@pytest.mark.parametrize("dotted", sorted(_OTHER_CONTRACT))
def test_what_is_excepted_still_needs_to_be(dotted: str) -> None:
    """An entry of `_OTHER_CONTRACT` cannot outlive the reason for it.

    Its reason excuses the answer it gives, never a coroutine: an
    `async def` under an excepted name fails as one under any other does.
    """
    outlived = _outlives_its_exception(dotted, _NAMED[dotted])
    assert outlived is None, outlived


# names an `_OTHER_CONTRACT` line could excuse: one that still answers
# as its exception says, one that has come into line, and an `async def`
_EXCEPTED_CONTROL = """
def verify_script(a: int) -> None: ...
def verify_amounts(a: int) -> bool: ...
async def verify_key_path(a: int) -> None: ...
"""


def test_an_exception_outlived_or_awaited_fails() -> None:
    """The check above fails an entry that is in line, or an `async def`.

    Every entry of btclib's `_OTHER_CONTRACT` still needs its line, and
    none is an `async def`: this source holds the cases that must fail.
    """
    named = _named_in("control", _EXCEPTED_CONTROL)
    outlived = {
        d for d, returns in named.items() if _outlives_its_exception(d, returns)
    }
    assert outlived == {"control.verify_amounts", "control.verify_key_path"}


def test_the_walk_reaches_what_it_claims() -> None:
    """One name per prefix it must find, and the two kinds it must not.

    A walk that found nothing would pass the test above.
    """
    assert _NAMED["btclib.script.script_pub_key.is_p2sh"] == ["bool"]
    assert _NAMED["btclib.script.engine.script.check_pub_key"] == ["bool"]
    assert _NAMED["btclib.script.taproot.check_output_pubkey"] == ["bool"]
    assert _NAMED["btclib.script.engine.script.dsa_verify"] == ["bool"]
    assert _NAMED["btclib.block.merkle_proof.verify"] == ["bool"]
    assert _NAMED["btclib.bms.assert_as_valid"] == ["None"]
    assert _NAMED["btclib.policy.validate_inputs_standardness"] == ["None"]
    # a method, and a property among them
    assert _NAMED["btclib.key.is_compressed"] == ["bool"]

    # an op code is named for the op code
    assert "btclib.script.engine.script_op_codes.op_verify" not in _NAMED
    assert "btclib.script.engine.script_op_codes.op_checklocktimeverify" not in _NAMED
    # a private name, and a name that promises nothing
    assert "btclib.bms._assert_p2pkh" not in _NAMED
    assert "btclib.utils.bytes_from_octets" not in _NAMED


# a `validate_` that refuses, one that answers a bool, an `async def` one
# annotated as refusing, and two names that carry the word without the
# prefix: not followed by an underscore, and not at the front
_VALIDATE_CONTROL = """
def validate_refusal(a: int) -> None: ...
def validate_answer(a: int) -> bool: ...
async def validate_later(a: int) -> None: ...
def validated_name(a: str) -> str: ...
def revalidate_cache(a: str) -> str: ...
"""


def test_a_validate_answering_a_bool_breaks_its_promise() -> None:
    """The rule fails a `validate_` that answers a bool or a coroutine.

    btclib's own `validate_` functions all refuse, so the rule above never
    fails on one: this source holds the cases that must.
    """
    named = _named_in("control", _VALIDATE_CONTROL)
    assert named == {
        "control.validate_refusal": ["None"],
        "control.validate_answer": ["bool"],
        "control.validate_later": ["Coroutine[None]"],
    }
    broken = {d for d, returns in named.items() if _breaks_its_promise(d, returns)}
    assert broken == {"control.validate_answer", "control.validate_later"}


# a name defined twice, in two classes and in two branches of an `if`,
# the definition that breaks the rule first, where the second would
# overwrite it; a property of a nested class, defined once; two nested
# classes of one name under two outer classes; a class inside a function;
# an `async def` taking only `self`, which `_named_in` records as the
# coroutine it answers, and which `_public_bools_in`,
# `_argument_less_bools_in` and `_class_members_in` do not record; and an
# `async def` under each other prefix but `validate_`, which
# `_VALIDATE_CONTROL` holds, each annotated as its prefix promises
_REDEFINED_CONTROL = """
class Block:
    def is_final(self) -> bool: ...
    async def is_ready(self) -> bool: ...
class Tx:
    @property
    def is_final(self) -> bool: ...
class Outer:
    class Inner:
        @property
        def is_inner(self) -> bool: ...
class Left:
    class Node:
        @property
        def depth(self) -> int: ...
class Right:
    class Node:
        def depth(self) -> int: ...
def f() -> None:
    class K:
        @property
        def size(self) -> int: ...
if TYPE_CHECKING:
    def verify_tx(a: int) -> int: ...
else:
    def verify_tx(a: int) -> bool: ...
async def assert_later(a: int) -> None: ...
async def check_later(a: int) -> bool: ...
async def verify_later(a: int) -> bool: ...
"""


def test_a_second_definition_hides_no_first() -> None:
    """No definition of a name hides another one.

    `_named_in` and `_argument_less_bools_in` list each definition once,
    and `_public_bools_in` keeps the name, which is all it judges.
    `_named_in` records an `async def` as a coroutine, which breaks the
    promise of its prefix; the other walks do not record it. btclib holds
    no prefixed name whose definitions disagree, and no `async def`: this
    source holds both.
    """
    named = _named_in("control", _REDEFINED_CONTROL)
    assert named == {
        "control.is_final": ["bool", "bool"],
        "control.is_ready": ["Coroutine[bool]"],
        "control.is_inner": ["bool"],
        "control.verify_tx": ["int", "bool"],
        "control.assert_later": ["Coroutine[None]"],
        "control.check_later": ["Coroutine[bool]"],
        "control.verify_later": ["Coroutine[bool]"],
    }
    broken = {d for d, returns in named.items() if _breaks_its_promise(d, returns)}
    assert broken == {
        "control.is_ready",
        "control.verify_tx",
        "control.assert_later",
        "control.check_later",
        "control.verify_later",
    }

    assert _public_bools_in("control", _REDEFINED_CONTROL) == {
        "control.is_final",
        "control.is_inner",
        "control.verify_tx",
    }
    # the method of `Block` is not a property, whatever `Tx` holds, and the
    # nested property is listed once, not once per enclosing class
    argument_less = _argument_less_bools_in("control", _REDEFINED_CONTROL)
    assert argument_less == {
        "control.is_final": [False, True],
        "control.is_inner": [True],
    }
    assert _is_called(argument_less["control.is_final"])
    assert _class_members_in("control", _REDEFINED_CONTROL) == {
        "control.Block.is_final": False,
        "control.Tx.is_final": True,
        "control.Outer.Inner.is_inner": True,
        "control.Left.Node.depth": True,
        "control.Right.Node.depth": False,
        "control.f.K.size": True,
    }


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
    """A bool carries one of the prefixes, or is named in the list.

    What this closes is the gap the prefixes alone leave: they promise a
    shape to a caller who sees one, and say nothing about a bool that
    carries none. Those that keep their names keep them for the reason
    each entry gives.

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
    assert not _is_called(_ARGUMENT_LESS_BOOLS[dotted]), (
        f"{dotted} answers a bool about the object and takes nothing:"
        " it is a @property, not a method"
    )


def test_the_walk_reaches_both_shapes() -> None:
    """One of each shape, so the filter is doing work rather than nothing."""
    assert _ARGUMENT_LESS_BOOLS["btclib.tx.tx.is_segwit"] == [True]
    assert _ARGUMENT_LESS_BOOLS["btclib.key.is_compressed"] == [True]
    # a bool of an argument is a function of it, and no property can be
    assert "btclib.script.script_pub_key.is_p2sh" not in _ARGUMENT_LESS_BOOLS
    assert "btclib.bms.verify" not in _ARGUMENT_LESS_BOOLS


@pytest.mark.parametrize("dotted", sorted(_CLASS_MEMBERS))
def test_an_argument_less_member_is_read_not_called(dotted: str) -> None:
    """Whatever it answers, a member that takes nothing is a `@property`.

    The bool rule above, generalised to every return type: two reads of
    one object spelled two ways, one as an attribute and one as a call,
    are one shape more than a reader should have to remember.

    What is not a read is here by shape and not by a list of names, which
    is what keeps this rule from needing one.
    """
    if _is_not_a_read(dotted.rpartition(".")[2]):
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
    assert _CLASS_MEMBERS["btclib.tx.tx.Tx.vsize"] is True
    assert _CLASS_MEMBERS["btclib.key.PrvKeyData.pub"] is True
    # a cached_property is a read too, which testing for "property" alone
    # would have missed
    assert _CLASS_MEMBERS["btclib.script.script.Script.asm"] is True
    # and the shapes that are not a read
    # OutPoint's and not Tx's, which takes an `unsigned_template` and so
    # is not argument-less at all
    assert _CLASS_MEMBERS["btclib.tx.out_point.OutPoint.assert_valid"] is False
    assert _CLASS_MEMBERS["btclib.block.block.Block.assert_valid_weight"] is False


# a refusal that takes nothing but `self`, which btclib's own `validate_`
# functions do not, beside a read
_MEMBER_CONTROL = """
class Spend:
    def validate_inputs(self) -> None: ...
    @property
    def fee(self) -> int: ...
"""


def test_a_validate_member_is_not_a_read() -> None:
    """A self-only `validate_` member stays a method, as an `assert_` does."""
    members = _class_members_in("control", _MEMBER_CONTROL)
    assert members == {
        "control.Spend.validate_inputs": False,
        "control.Spend.fee": True,
    }
    # the gate above fails a member whose shape and name disagree
    broken = {d for d in members if _is_not_a_read(d.rpartition(".")[2]) == members[d]}
    assert not broken
