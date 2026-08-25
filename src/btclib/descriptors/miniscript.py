# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Miniscript: the expression, its type, its script, both ways, BIP379.

A miniscript is a bitcoin script written as a tree of *fragments*, which
is what makes a non-trivial spending condition something a wallet can
read rather than something it has to recognize. `parse` reads the text
BIP379 defines and `from_script` reads a script back into it; `str` and
`Miniscript.script` are the two ways out. The round trip is the point:
`from_script(node.script())` is `node` again, so a signer handed a witness
script can say what it means without being told. `reads_back` is that
round trip asked of a script instead of assumed of it -- whether the bytes
in hand are the expression they look like -- which is the question a
caller has about a script somebody else wrote.

`satisfy` is the third thing it does: the witness that spends the script,
which for a miniscript is a choice and not an assembly -- several branches
may be open at once, and which one to take is what BIP379's non-malleable
satisfaction algorithm decides. It reads the signatures a caller has and a
`SpendContext`: the hash preimages, and the lock times the transaction
being built will carry, because an ``older()`` or an ``after()`` is a
branch only the right transaction opens. Non-malleable or refused, which
is Bitcoin Core's default too: a witness a third party could rewrite is
worse than none.

The bounds are the same analysis read statically: `max_ops`,
`max_stack_items`, `max_exec_stack_items` and `max_witness_size` answer
what a spend may cost before there is a spend, and `is_sane` is the
conjunction Bitcoin Core requires of a miniscript before it accepts a
descriptor holding one. `max_witness_stack` is the last of those broken
into its elements, which is what an estimator needs: the largest witness
this can be satisfied by, element by element, with every signature assumed
and every lock time taken as met. Its bytes and `max_witness_size` are the
same number by two roads -- one over the type tables, one over the
satisfaction -- and the test that they agree on every vector is what says
neither transcription drifted.

The type system is why a fragment can be trusted to compose. Every
expression has one of four basic types -- "B" base, "V" verify, "K" key,
"W" wrapped -- and a set of properties saying how it consumes the stack,
whether it can be dissatisfied, and whether a third party can rewrite a
witness for it. `Miniscript.properties` is that set, one character per
BIP379 property, and an expression whose properties are empty is one the
rules refuse: `parse` refuses it too, naming the innermost fragment that
failed, because "which fragment" is the answer a caller wants.

Two contexts, `P2WSH` and `TAPSCRIPT`, because BIP379 has two: the
fragments are the same, but ``multi()`` belongs to the first and
``multi_a()`` to the second, a key is 33 bytes there and 32 here, the
``d:`` wrapper is "u" only under tapscript -- MINIMALIF being consensus
for taproot and policy for P2WSH -- and each context bounds its own
resources. The context is therefore a parameter of everything, and
`descriptors` passes the one the position gives: `P2WSH` inside ``wsh()``,
`TAPSCRIPT` for a leaf of a ``tr()`` script tree.

Above `key_expression`, whose KEY expressions the fragments hold, and
below `descriptors`, which reads a miniscript wherever a SCRIPT
expression may be one. This module imports the first and not the second.

BIP379: https://github.com/bitcoin/bips/blob/master/bip-0379.md
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import TypeVar

from typing_extensions import override

from btclib.alias import Octets, ScriptList
from btclib.descriptors.key_expression import (
    KeyExpression,
    PrvKeys,
    _offered_signature,
    _parse_key,
    _split_arguments,
)
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160
from btclib.script.limits import (
    MAX_OPS_PER_SCRIPT,
    MAX_PUBKEYS_PER_MULTISIG,
    MAX_STACK_SIZE,
)
from btclib.script.script import (
    BYTE_FROM_OP_CODE_NAME,
    op_code_spans,
    push_int,
    serialize,
)
from btclib.utils import assert_type, bytes_from_octets, decode_num, encode_num
from btclib.var_int import serialize as var_int_serialize

__all__ = [
    "P2WSH",
    "TAPSCRIPT",
    "Miniscript",
    "SpendContext",
    "from_script",
    "parse",
    "reads_back",
]

# the two contexts BIP379 is specified for, P2SH and bare scripts being
# excluded from it. Spelled as the BIP spells them, these being what an
# error message has to name
P2WSH = "P2WSH"
TAPSCRIPT = "tapscript"

# what a p2wsh witness script may hold and still be relayed: Bitcoin
# Core's MAX_STANDARD_P2WSH_SCRIPT_SIZE and MAX_STANDARD_P2WSH_STACK_ITEMS,
# both policy and not consensus, which is why they are here and not in
# `script.limits` beside the consensus caps
_MAX_STANDARD_P2WSH_SCRIPT_SIZE = 3600
_MAX_STANDARD_P2WSH_STACK_ITEMS = 100

# a tapscript has no size limit of its own, so what bounds one is the
# weight of a transaction that could spend it: Bitcoin Core's
# `MaxScriptSize` takes the standard transaction weight, less the body of a
# spending transaction and less a maximal witness. Derived here rather than
# copied, every term being a constant with a name -- a bound this loose is
# not one a real script runs into, so a wrong copy of it would go unnoticed
_MAX_STANDARD_TX_WEIGHT = 400000
_WITNESS_SCALE_FACTOR = 4
# version and nLockTime, the input count and one input's 41 bytes without
# its witness, the output count and one p2wsh output's 43 bytes, and the
# two bytes of the segwit marker, which are witness and not body
_TX_BODY_LEEWAY_WEIGHT = (8 + 1 + 41 + 1 + 43) * _WITNESS_SCALE_FACTOR + 2
# and the largest witness: a full stack of the largest element a tapscript
# miniscript puts on it -- a BIP340 signature and its sighash byte -- each
# with its length prefix, plus the largest control block, which is 33 bytes
# and 128 nodes of 32
_MAX_TAPSCRIPT_SAT_SIZE = (
    len(var_int_serialize(MAX_STACK_SIZE))
    + (1 + 65) * MAX_STACK_SIZE
    + len(var_int_serialize(33 + 32 * 128))
    + (33 + 32 * 128)
)
_TAPSCRIPT_WEIGHT_LEFT = (
    _MAX_STANDARD_TX_WEIGHT - _TX_BODY_LEEWAY_WEIGHT - _MAX_TAPSCRIPT_SAT_SIZE
)
# less what says how long the script itself is, that being part of the same
# witness
_MAX_TAPSCRIPT_SIZE = _TAPSCRIPT_WEIGHT_LEFT - len(
    var_int_serialize(_TAPSCRIPT_WEIGHT_LEFT)
)

# BIP342 puts no bound of its own on the keys of a multi_a(), so the bound
# is the stack: one element per key, and no more than 1000 elements
_MAX_PUBKEYS_PER_MULTI_A = 999

# the lock time that tells a block height from a unix timestamp, and the
# nSequence bit that tells a block count from a 512-second count: BIP65's
# and BIP68's own thresholds, which is what the timelock-mixing rules are
# about -- an expression may not need both kinds of one at once
_LOCKTIME_THRESHOLD = 500000000
_SEQUENCE_LOCKTIME_TYPE_FLAG = 1 << 22

# 1 <= n < 2**31 for older() and after(): a script number is signed, so
# 2**31 is the first value CHECKSEQUENCEVERIFY cannot be handed, and zero
# locks nothing
_MAX_TIMELOCK = 0x80000000

# the wrappers, which keep the colon they are written with: `str` writes a
# tag as it stands, and "v" alone would name a fragment that is not one
_WRAPPERS = ("a:", "s:", "c:", "d:", "v:", "j:", "n:")

# and the two-argument combinators, which is what makes them one case in
# every table below. andor() is the only three-argument fragment
_BINARY = ("and_v", "and_b", "or_b", "or_c", "or_d", "or_i")

# the hash fragments and the op code each commits with, and the size of
# the digest it holds
_HASH_OP_CODES = {
    "sha256": "OP_SHA256",
    "hash256": "OP_HASH256",
    "ripemd160": "OP_RIPEMD160",
    "hash160": "OP_HASH160",
}
_DATA_SIZE = {"sha256": 32, "hash256": 32, "ripemd160": 20, "hash160": 20}

# how many subexpressions each fragment takes. thresh() is not here: it
# takes one or more, which its threshold then bounds
_ARITY = {
    **dict.fromkeys(
        ("0", "1", "pk_k", "pk_h", "older", "after", "multi", "multi_a"), 0
    ),
    **dict.fromkeys(_HASH_OP_CODES, 0),
    **dict.fromkeys(_WRAPPERS, 1),
    **dict.fromkeys(_BINARY, 2),
    "andor": 3,
}

# a number, as the fragments that take one accept it: digits and nothing
# else, so that neither "-1" nor "+1" is read as a lock time
_NUMBER = re.compile(r"[0-9]+")


def _assert_valid_context(context: str) -> None:
    """Refuse a spend context that is not one of BIP379's two.

    Every rule below reads the context by asking whether it is
    `TAPSCRIPT`, so a third value is not an unknown context: it is the
    p2wsh one, silently, and the expression is type-checked and sized
    under rules it was not offered to. A function rather than two lines
    at the one caller, so that `parse` keeps the branch count ruff's
    C901 allows it.
    """
    assert_type(context, str, "context")
    if context not in {P2WSH, TAPSCRIPT}:
        err_msg = f"unknown spend context: '{context}'"
        err_msg += f"; it must be one of {sorted((P2WSH, TAPSCRIPT))}"
        raise BTClibValueError(err_msg)


def _t(properties: str) -> frozenset[str]:
    """Return a set of type properties, one character each."""
    return frozenset(properties)


_NONE: frozenset[str] = frozenset()


def _has(properties: frozenset[str], required: str) -> bool:
    """Answer whether every required property is among those held.

    Bitcoin Core's ``<<`` operator, and the subset rule it stands for: an
    expression that is "Bdu" is one wherever a "B", a "d", a "Bu" or a
    "Bdu" is asked for.
    """
    return _t(required) <= properties


def _if(condition: bool, properties: frozenset[str]) -> frozenset[str]:
    """Return the properties where the condition holds, none where it does not.

    Bitcoin Core's `Type::If`, which is what lets a table row be written as
    one expression.
    """
    return properties if condition else _NONE


def _mixed(x: frozenset[str], y: frozenset[str]) -> bool:
    """Answer whether two subexpressions need incompatible timelocks.

    Which is what the "g", "h", "i" and "j" properties are recorded for: a
    relative time lock ("g") and a relative height lock ("h") cannot both
    be met by one nSequence, an absolute time lock ("i") and an absolute
    height lock ("j") cannot both be met by one nLockTime, and the two
    pairs are independent of each other.
    """
    return (
        (_has(x, "g") and _has(y, "h"))
        or (_has(x, "h") and _has(y, "g"))
        or (_has(x, "i") and _has(y, "j"))
        or (_has(x, "j") and _has(y, "i"))
    )


# the leaf fragments whose type is the same wherever they appear. older()
# and after() are not among them, each carrying which kind of timelock it
# is, and neither is the "u" that only a tapscript ``d:`` has
_LEAF_PROPERTIES = {
    "0": "Bzudemsxk",
    "1": "Bzufmxk",
    "pk_k": "Konudemsxk",
    "pk_h": "Knudemsxk",
    "multi": "Bnudemsk",
    "multi_a": "Budemsk",
    **dict.fromkeys(_HASH_OP_CODES, "Bonudmk"),
}


def _leaf_properties(fragment: str, threshold: int) -> frozenset[str]:
    """Return the type of a fragment that has no subexpressions."""
    if fragment == "older":
        return (
            _if(bool(threshold & _SEQUENCE_LOCKTIME_TYPE_FLAG), _t("g"))
            | _if(not threshold & _SEQUENCE_LOCKTIME_TYPE_FLAG, _t("h"))
            | _t("Bzfmxk")
        )
    if fragment == "after":
        return (
            _if(threshold >= _LOCKTIME_THRESHOLD, _t("i"))
            | _if(threshold < _LOCKTIME_THRESHOLD, _t("j"))
            | _t("Bzfmxk")
        )
    return _t(_LEAF_PROPERTIES[fragment])


def _wrapper_properties(
    fragment: str, x: frozenset[str], context: str
) -> frozenset[str]:
    """Return the type of a wrapped expression, from its argument's."""
    if fragment == "a:":
        properties = _if(_has(x, "B"), _t("W")) | (x & _t("ghijkudfems")) | _t("x")
    elif fragment == "s:":
        properties = _if(_has(x, "Bo"), _t("W")) | (x & _t("ghijkudfemsx"))
    elif fragment == "c:":
        properties = _if(_has(x, "K"), _t("B")) | (x & _t("ghijkondfem")) | _t("us")
    elif fragment == "d:":
        properties = (
            _if(_has(x, "Vz"), _t("B"))
            | _if(_has(x, "z"), _t("o"))
            | _if(_has(x, "f"), _t("e"))
            | (x & _t("ghijkms"))
            # what ``d:`` leaves on the stack is what it duplicated, and
            # only MINIMALIF makes that an exact 1 rather than any nonzero
            # value: consensus under tapscript, policy under P2WSH
            | _if(context == TAPSCRIPT, _t("u"))
            | _t("ndx")
        )
    elif fragment == "v:":
        properties = _if(_has(x, "B"), _t("V")) | (x & _t("ghijkzonms")) | _t("fx")
    elif fragment == "j:":
        properties = (
            _if(_has(x, "Bn"), _t("B"))
            | _if(_has(x, "f"), _t("e"))
            | (x & _t("ghijkoums"))
            | _t("ndx")
        )
    else:
        properties = (x & _t("ghijkBzondfems")) | _t("ux")
    return properties


def _and_properties(
    fragment: str, x: frozenset[str], y: frozenset[str]
) -> frozenset[str]:
    """Return the type of and_v() or and_b(), the two conjunctions."""
    timelocks = ((x | y) & _t("ghij")) | _if(
        _has(x & y, "k") and not _mixed(x, y), _t("k")
    )
    if fragment == "and_v":
        return (
            _if(_has(x, "V"), y & _t("KVB"))
            | (x & _t("n"))
            | _if(_has(x, "z"), y & _t("n"))
            | _if(_has(x | y, "z"), (x | y) & _t("o"))
            | (x & y & _t("mz"))
            | ((x | y) & _t("s"))
            | _if(_has(y, "f") or _has(x, "s"), _t("f"))
            | (y & _t("ux"))
            | timelocks
        )
    return (
        _if(_has(y, "W"), x & _t("B"))
        | _if(_has(x | y, "z"), (x | y) & _t("o"))
        | (x & _t("n"))
        | _if(_has(x, "z"), y & _t("n"))
        | _if(_has(x & y, "s"), x & y & _t("e"))
        | (x & y & _t("dzm"))
        | _if(_has(x & y, "f") or _has(x, "sf") or _has(y, "sf"), _t("f"))
        | ((x | y) & _t("s"))
        | _t("ux")
        | timelocks
    )


def _or_properties(
    fragment: str, x: frozenset[str], y: frozenset[str]
) -> frozenset[str]:
    """Return the type of one of the four disjunctions.

    Every one of them may mix timelocks: the two branches are alternatives,
    so a satisfaction needs the locks of one of them and never of both.
    """
    timelocks = ((x | y) & _t("ghij")) | (x & y & _t("k"))
    if fragment == "or_b":
        return (
            _if(_has(x, "Bd") and _has(y, "Wd"), _t("B"))
            | _if(_has(x | y, "z"), (x | y) & _t("o"))
            | _if(_has(x | y, "s") and _has(x & y, "e"), x & y & _t("m"))
            | (x & y & _t("zse"))
            | _t("dux")
            | timelocks
        )
    if fragment == "or_c":
        return (
            _if(_has(x, "Bdu"), y & _t("V"))
            | _if(_has(y, "z"), x & _t("o"))
            | _if(_has(x, "e") and _has(x | y, "s"), x & y & _t("m"))
            | (x & y & _t("zs"))
            | _t("fx")
            | timelocks
        )
    if fragment == "or_d":
        return (
            _if(_has(x, "Bdu"), y & _t("B"))
            | _if(_has(y, "z"), x & _t("o"))
            | _if(_has(x, "e") and _has(x | y, "s"), x & y & _t("m"))
            | (x & y & _t("zs"))
            | (y & _t("ufde"))
            | _t("x")
            | timelocks
        )
    return (
        (x & y & _t("VBKufs"))
        | _if(_has(x & y, "z"), _t("o"))
        | _if(_has(x | y, "f"), (x | y) & _t("e"))
        | _if(_has(x | y, "s"), x & y & _t("m"))
        | ((x | y) & _t("d"))
        | _t("x")
        | timelocks
    )


def _andor_properties(
    x: frozenset[str], y: frozenset[str], z: frozenset[str]
) -> frozenset[str]:
    """Return the type of andor(X,Y,Z): X and Y, or else Z.

    The timelock rule is and_v()'s and applies to X and Y alone: Z is the
    branch taken when X is dissatisfied, so its locks are never needed
    together with X's.
    """
    return (
        _if(_has(x, "Bdu"), y & z & _t("BKV"))
        | (x & y & z & _t("z"))
        | _if(_has(x | (y & z), "z"), (x | (y & z)) & _t("o"))
        | (y & z & _t("u"))
        | _if(_has(x, "s") or _has(y, "f"), z & _t("fe"))
        | (z & _t("d"))
        | _if(_has(x, "e") and _has(x | y | z, "s"), x & y & z & _t("m"))
        | (z & (x | y) & _t("s"))
        | _t("x")
        | ((x | y | z) & _t("ghij"))
        | _if(_has(x & y & z, "k") and not _mixed(x, y), _t("k"))
    )


def _thresh_properties(
    subs: Sequence[frozenset[str]], threshold: int
) -> frozenset[str]:
    """Return the type of a thresh(), which has to walk its subexpressions.

    The first is "Bdu" and the rest "Wdu", the stack elements they consume
    are what tell "z" from "o", and the timelock accumulator carries the
    mixing rule: two branches with incompatible locks are a problem only
    where the threshold makes both of them necessary.
    """
    all_e = True
    all_m = True
    arguments = 0
    signed = 0
    timelocks = _t("k")
    for position, sub in enumerate(subs):
        if not _has(sub, "Wdu" if position else "Bdu"):
            return _NONE
        all_e = all_e and _has(sub, "e")
        all_m = all_m and _has(sub, "m")
        signed += _has(sub, "s")
        arguments += 0 if _has(sub, "z") else 1 if _has(sub, "o") else 2
        timelocks = ((timelocks | sub) & _t("ghij")) | _if(
            _has(timelocks & sub, "k")
            and (threshold <= 1 or not _mixed(timelocks, sub)),
            _t("k"),
        )
    return (
        _t("Bdu")
        | _if(arguments == 0, _t("z"))
        | _if(arguments == 1, _t("o"))
        | _if(all_e and signed == len(subs), _t("e"))
        | _if(all_e and all_m and signed >= len(subs) - threshold, _t("m"))
        | _if(signed >= len(subs) - threshold + 1, _t("s"))
        | timelocks
    )


def _computed_properties(node: Miniscript) -> frozenset[str]:
    """Return the type and properties of a node, from its subexpressions'.

    BIP379's three tables at once, as Bitcoin Core's `ComputeType` holds
    them: the correctness table, the timelock-mixing rule and the
    malleability table are computed by the same expressions, so they cannot
    be separated.

    Empty where the requirements are not met, which is what makes an
    ill-typed expression invalid rather than an error, and what propagates:
    a subexpression with no type gives its parent none either.
    """
    subs = [sub.properties for sub in node.subs]
    fragment = node.fragment
    if not subs:
        return _sanitized(_leaf_properties(fragment, node.threshold))
    if fragment in _WRAPPERS:
        return _sanitized(_wrapper_properties(fragment, subs[0], node.context))
    if fragment in {"and_v", "and_b"}:
        return _sanitized(_and_properties(fragment, subs[0], subs[1]))
    if fragment == "andor":
        return _sanitized(_andor_properties(subs[0], subs[1], subs[2]))
    if fragment == "thresh":
        return _sanitized(_thresh_properties(subs, node.threshold))
    return _sanitized(_or_properties(fragment, subs[0], subs[1]))


def _pushed_number(number: int) -> ScriptList:
    """Return the minimal push of a script number, as a command.

    `script.push_int`, which is that choice written once: an op code
    where one means the number -- OP_16 and not the byte 0x10, so that
    what is written is what `from_script` reads back -- and the
    CScriptNum encoding above it. A list, because the callers are
    building one.
    """
    return [push_int(number)]


def _pushed_size(number: int) -> int:
    """Return the length in bytes of the minimal push of a number."""
    return len(serialize(_pushed_number(number)))


# what each fragment adds around its subexpressions: its own op codes,
# one byte each -- which is why this is both the bytes it adds to the
# script and the ops it adds to a spend, the two being the same op codes
# counted twice. ``v:`` is not here, adding a byte only where the last op
# code of its argument has no VERIFY form, and neither is thresh(), which
# adds an OP_ADD per subexpression and a threshold to push
_OVERHEAD = {
    "and_v": 0,
    "s:": 1,
    "c:": 1,
    "n:": 1,
    "and_b": 1,
    "or_b": 1,
    "a:": 2,
    "or_c": 2,
    "d:": 3,
    "or_d": 3,
    "or_i": 3,
    "andor": 3,
    "j:": 4,
}


def _leaf_script_size(node: Miniscript) -> int:
    """Return the length of the script of a fragment with no subexpressions."""
    fragment = node.fragment
    keys = len(node.keys)
    if fragment in {"0", "1"}:
        size = 1
    elif fragment == "pk_k":
        size = 33 if node.context == TAPSCRIPT else 34
    elif fragment == "pk_h":
        # OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY
        size = 3 + 21
    elif fragment in {"older", "after"}:
        size = 1 + _pushed_size(node.threshold)
    elif fragment == "multi":
        size = 1 + _pushed_size(keys) + _pushed_size(node.threshold) + 34 * keys
    elif fragment == "multi_a":
        size = (1 + 32 + 1) * keys + _pushed_size(node.threshold) + 1
    else:
        # a hash fragment: OP_SIZE <32> OP_EQUALVERIFY, the hash op code,
        # the digest, and OP_EQUAL
        size = 4 + 2 + (33 if _DATA_SIZE[fragment] == 32 else 21)
    return size


def _computed_script_size(node: Miniscript) -> int:
    """Return the length of the script, without serializing it.

    Which is what the parser needs before it has an index to derive the
    keys at: the size of a key is the context's and not the key's, so
    every fragment's script has a length its subexpressions' determine.
    """
    if not node.subs:
        return _leaf_script_size(node)
    size = sum(sub.script_size for sub in node.subs)
    if node.fragment == "v:":
        return size + _has(node.subs[0].properties, "x")
    if node.fragment == "thresh":
        return size + len(node.subs) + _pushed_size(node.threshold)
    return size + _OVERHEAD[node.fragment]


def _add(first: int | None, second: int | None) -> int | None:
    """Add two bounds, None being "no such satisfaction"."""
    return None if first is None or second is None else first + second


def _worst(first: int | None, second: int | None) -> int | None:
    """Return the larger of two bounds, disregarding the absent ones."""
    if first is None:
        return second
    if second is None:
        return first
    return max(first, second)


@dataclass(frozen=True)
class _Bounds:
    """A bound on satisfying and one on dissatisfying, either may be absent."""

    sat: int | None
    dsat: int | None


@dataclass(frozen=True)
class _Trace:
    """What executing a script does to the stack, at worst.

    `net` is how many more elements the stack holds when execution starts
    than when it ends -- negative where the script leaves more than it was
    given -- and `peak` how many more it holds at its highest point than
    at the end. Two numbers because two limits are asked: a p2wsh witness
    may carry a hundred elements, and no script may reach a thousand on
    the stack while it runs.
    """

    net: int
    peak: int


def _union(first: _Trace | None, second: _Trace | None) -> _Trace | None:
    """Return the worse of two possible executions, either may be impossible."""
    if first is None:
        return second
    if second is None:
        return first
    return _Trace(max(first.net, second.net), max(first.peak, second.peak))


def _concat(first: _Trace | None, second: _Trace | None) -> _Trace | None:
    """Return the execution of one script followed by another.

    The nets add; the peak is the second script's own, or the first's once
    what the second consumes is accounted for. Not commutative, which is
    the whole reason this is a function and not a maximum: "OP_1 OP_DROP"
    reaches one element above where it ends and "OP_DROP OP_1" reaches
    none.
    """
    if first is None or second is None:
        return None
    return _Trace(first.net + second.net, max(second.peak, second.net + first.peak))


# the stack effect of the op codes a fragment's script is built from. A
# push is one element the stack did not hold before, hence a net of -1;
# OP_IF consumes one, hence 1; and what neither pushes nor pops -- the
# hash op codes, the two repurposed nops, OP_ELSE, OP_ENDIF -- is the
# identity of the concatenation
_EMPTY = _Trace(0, 0)
_PUSH = _Trace(-1, 0)
_NOP = _Trace(0, 0)
_IF = _Trace(1, 1)
_BINARY_OP = _Trace(1, 1)
_ONE_ARG_OP = _Trace(1, 1)
_EQUALVERIFY = _Trace(2, 2)


def _hash_trace() -> _Trace | None:
    """Return the execution of a hash fragment's script.

    OP_SIZE duplicates the element, the pushed 32 and OP_EQUALVERIFY
    consume both, the hash op code rewrites the element in place, and the
    pushed digest and OP_EQUAL consume it: one element in, one out.
    """
    return _concat(
        _concat(_concat(_PUSH, _PUSH), _concat(_EQUALVERIFY, _NOP)),
        _concat(_PUSH, _ONE_ARG_OP),
    )


def _leaf_ops(node: Miniscript) -> tuple[int, _Bounds]:
    """Return the op codes of a leaf's script, and what its spend adds.

    The count is the non-push op codes, and the two bounds the keys of an
    OP_CHECKMULTISIG that may be executed: BIP141 counts those against the
    201 of a p2wsh spend, and how many are counted depends on which branch
    runs.
    """
    fragment = node.fragment
    keys = len(node.keys)
    if fragment == "multi":
        # one op code, and the keys of the OP_CHECKMULTISIG that runs
        return 1, _Bounds(keys, keys)
    if fragment == "multi_a":
        # a CHECKSIG or a CHECKSIGADD per key, and the OP_NUMEQUAL
        return keys + 1, _Bounds(0, 0)
    count, sat, dsat = _LEAF_OPS[fragment]
    return count, _Bounds(sat, dsat)


# what each leaf costs: its non-push op codes, and the keys of an
# OP_CHECKMULTISIG its satisfaction and its dissatisfaction may execute --
# None where there is no such thing to do. multi() and multi_a() are not
# here, both counting their keys
_LEAF_OPS: dict[str, tuple[int, int | None, int | None]] = {
    "1": (0, 0, None),
    "0": (0, None, 0),
    "pk_k": (0, 0, 0),
    "pk_h": (3, 0, 0),
    "older": (1, 0, None),
    "after": (1, 0, None),
    **dict.fromkeys(_HASH_OP_CODES, (4, 0, None)),
}


def _wrapper_ops(node: Miniscript) -> tuple[int, _Bounds]:
    """Return the ops of a wrapped expression."""
    sub = node.subs[0]
    if node.fragment == "v:":
        return sub._static_ops + _has(sub.properties, "x"), _Bounds(sub._ops.sat, None)
    # ``d:`` and ``j:`` are dissatisfied by the element their OP_IF reads,
    # so nothing of the argument runs and nothing of it is counted
    dsat = 0 if node.fragment in {"d:", "j:"} else sub._ops.dsat
    static = _OVERHEAD[node.fragment] + sub._static_ops
    return static, _Bounds(sub._ops.sat, dsat)


def _binary_ops(node: Miniscript) -> tuple[int, _Bounds]:
    """Return the ops of a combinator, from its subexpressions'."""
    x, y = (sub._ops for sub in node.subs[:2])
    fragment = node.fragment
    if fragment == "and_v":
        bounds = _Bounds(_add(x.sat, y.sat), None)
    elif fragment == "and_b":
        bounds = _Bounds(_add(x.sat, y.sat), _add(x.dsat, y.dsat))
    elif fragment == "or_b":
        sat = _worst(_add(x.sat, y.dsat), _add(y.sat, x.dsat))
        bounds = _Bounds(sat, _add(x.dsat, y.dsat))
    elif fragment == "or_c":
        bounds = _Bounds(_worst(x.sat, _add(y.sat, x.dsat)), None)
    elif fragment == "or_d":
        bounds = _Bounds(_worst(x.sat, _add(y.sat, x.dsat)), _add(x.dsat, y.dsat))
    elif fragment == "or_i":
        bounds = _Bounds(_worst(x.sat, y.sat), _worst(x.dsat, y.dsat))
    else:
        z = node.subs[2]._ops
        sat = _worst(_add(y.sat, x.sat), _add(x.dsat, z.sat))
        bounds = _Bounds(sat, _add(x.dsat, z.dsat))
    static = sum(sub._static_ops for sub in node.subs)
    return static + _OVERHEAD[fragment], bounds


def _thresh_ops(node: Miniscript) -> tuple[int, _Bounds]:
    """Return the ops of a thresh(), over every way to reach its threshold.

    `reached[j]` is the worst cost of satisfying exactly j of the
    subexpressions read so far, which is the only way to bound this: the
    threshold says how many are satisfied and not which, and the
    expensive ones are not always the ones that count.
    """
    static = 0
    reached: list[int | None] = [0]
    for sub in node.subs:
        static += sub._static_ops + 1
        following: list[int | None] = [_add(reached[0], sub._ops.dsat)]
        following.extend(
            _worst(_add(reached[j], sub._ops.dsat), _add(reached[j - 1], sub._ops.sat))
            for j in range(1, len(reached))
        )
        following.append(_add(reached[-1], sub._ops.sat))
        reached = following
    return static, _Bounds(reached[node.threshold], reached[0])


def _computed_ops(node: Miniscript) -> tuple[int, _Bounds]:
    """Return the static op codes of the script and the ops a spend adds."""
    if not node.subs:
        return _leaf_ops(node)
    if node.fragment in _WRAPPERS:
        return _wrapper_ops(node)
    if node.fragment == "thresh":
        return _thresh_ops(node)
    return _binary_ops(node)


# what satisfying and dissatisfying each leaf does to the stack, None
# where there is no such thing to do. multi() and multi_a() are not here,
# both counting their keys; the pk_h() trace is OP_DUP, the hash, the
# pushed digest and the OP_EQUALVERIFY, which is one element in and one out
_LEAF_STACK: dict[str, tuple[_Trace | None, _Trace | None]] = {
    "0": (None, _PUSH),
    "1": (_PUSH, None),
    "older": (_concat(_PUSH, _NOP), None),
    "after": (_concat(_PUSH, _NOP), None),
    "pk_k": (_PUSH, _PUSH),
    "pk_h": (
        _concat(_concat(_PUSH, _NOP), _concat(_PUSH, _EQUALVERIFY)),
        _concat(_concat(_PUSH, _NOP), _concat(_PUSH, _EQUALVERIFY)),
    ),
    **dict.fromkeys(_HASH_OP_CODES, (_hash_trace(), None)),
}


def _leaf_stack(node: Miniscript) -> tuple[_Trace | None, _Trace | None]:
    """Return what satisfying and dissatisfying a leaf does to the stack."""
    fragment = node.fragment
    if fragment == "multi":
        # k+1 elements in -- a dummy and k signatures -- and one out,
        # having reached k+n+2 more than it ends with: the n keys, the two
        # thresholds, and what it started with
        return (_Trace(node.threshold, node.threshold + len(node.keys) + 2),) * 2
    if fragment == "multi_a":
        # one element per key in, one out, and one more than the keys at
        # its peak: the first key pushed on top of them all
        return (_Trace(len(node.keys) - 1, len(node.keys)),) * 2
    return _LEAF_STACK[fragment]


def _wrapper_stack(node: Miniscript) -> tuple[_Trace | None, _Trace | None]:
    """Return the stack effect of a wrapped expression."""
    fragment = node.fragment
    sat, dsat = node.subs[0]._stack
    if fragment in {"a:", "s:", "n:"}:
        return sat, dsat
    if fragment == "c:":
        return _concat(sat, _ONE_ARG_OP), _concat(dsat, _ONE_ARG_OP)
    if fragment == "d:":
        prefix = _concat(_PUSH, _IF)
        return _concat(prefix, sat), prefix
    if fragment == "v:":
        return _concat(sat, _ONE_ARG_OP), None
    prefix = _concat(_concat(_PUSH, _NOP), _IF)
    return _concat(prefix, sat), prefix


def _binary_stack(node: Miniscript) -> tuple[_Trace | None, _Trace | None]:
    """Return the stack effect of a combinator, from its subexpressions'."""
    fragment = node.fragment
    (x_sat, x_dsat), (y_sat, y_dsat) = (sub._stack for sub in node.subs[:2])
    traces: tuple[_Trace | None, _Trace | None]
    if fragment == "and_v":
        traces = _concat(x_sat, y_sat), None
    elif fragment == "and_b":
        traces = (
            _concat(_concat(x_sat, y_sat), _BINARY_OP),
            _concat(_concat(x_dsat, y_dsat), _BINARY_OP),
        )
    elif fragment == "or_b":
        sat = _union(_concat(x_sat, y_dsat), _concat(x_dsat, y_sat))
        traces = (
            _concat(sat, _BINARY_OP),
            _concat(_concat(x_dsat, y_dsat), _BINARY_OP),
        )
    elif fragment == "or_c":
        traces = _union(_concat(x_sat, _IF), _concat(_concat(x_dsat, _IF), y_sat)), None
    elif fragment == "or_d":
        # OP_IFDUP duplicates what it reads only where that is nonzero,
        # which is the branch taken when X was satisfied
        taken = _concat(_concat(x_sat, _PUSH), _IF)
        not_taken = _concat(_concat(x_dsat, _EMPTY), _IF)
        traces = _union(taken, _concat(not_taken, y_sat)), _concat(not_taken, y_dsat)
    elif fragment == "or_i":
        traces = (
            _concat(_IF, _union(x_sat, y_sat)),
            _concat(_IF, _union(x_dsat, y_dsat)),
        )
    else:
        z_sat, z_dsat = node.subs[2]._stack
        traces = (
            _union(
                _concat(_concat(x_sat, _IF), y_sat),
                _concat(_concat(x_dsat, _IF), z_sat),
            ),
            _concat(_concat(x_dsat, _IF), z_dsat),
        )
    return traces


def _thresh_stack(node: Miniscript) -> tuple[_Trace | None, _Trace | None]:
    """Return the stack effect of a thresh(), over every way to reach it."""
    reached: list[_Trace | None] = [_EMPTY]
    for position, sub in enumerate(node.subs):
        sat, dsat = sub._stack
        add = _BINARY_OP if position else _EMPTY
        following: list[_Trace | None] = [_concat(_concat(reached[0], dsat), add)]
        following.extend(
            _concat(
                _union(_concat(reached[j], dsat), _concat(reached[j - 1], sat)), add
            )
            for j in range(1, len(reached))
        )
        following.append(_concat(_concat(reached[-1], sat), add))
        reached = following
    equal = _concat(_PUSH, _ONE_ARG_OP)
    return (
        _concat(reached[node.threshold], equal),
        _concat(reached[0], equal),
    )


def _computed_stack(node: Miniscript) -> tuple[_Trace | None, _Trace | None]:
    """Return what satisfying and dissatisfying costs the stack."""
    if not node.subs:
        return _leaf_stack(node)
    if node.fragment in _WRAPPERS:
        return _wrapper_stack(node)
    if node.fragment == "thresh":
        return _thresh_stack(node)
    return _binary_stack(node)


def _signature_size(context: str) -> int:
    """Return the largest signature the context's CHECKSIG takes.

    A low-s DER signature and its sighash byte under P2WSH; a BIP340
    signature and its sighash byte under tapscript, that byte being what a
    non-default sighash type costs there.
    """
    return 65 if context == TAPSCRIPT else 72


def _pub_key_size(context: str) -> int:
    """Return the public key size the context writes: x-only, or SEC."""
    return 32 if context == TAPSCRIPT else 33


def _leaf_witness(node: Miniscript) -> _Bounds:
    """Return the witness bytes a leaf's satisfaction and dissatisfaction take.

    A signature is 72 bytes and a sighash byte under P2WSH -- the largest
    a low-s DER signature is -- and 64 bytes and a sighash byte under
    tapscript, plus in both cases the byte that says how long the element
    is. A dissatisfaction is the empty push, which is one byte.
    """
    signature = 1 + _signature_size(node.context)
    pub_key = 1 + _pub_key_size(node.context)
    fragment = node.fragment
    if fragment == "0":
        bounds = _Bounds(None, 0)
    elif fragment in {"1", "older", "after"}:
        bounds = _Bounds(0, None)
    elif fragment == "pk_k":
        bounds = _Bounds(signature, 1)
    elif fragment == "pk_h":
        bounds = _Bounds(signature + pub_key, 1 + pub_key)
    elif fragment == "multi":
        # the dummy element OP_CHECKMULTISIG pops, plus a signature per
        # key the threshold asks for
        bounds = _Bounds(node.threshold * signature + 1, node.threshold + 1)
    elif fragment == "multi_a":
        # one element per key: a signature for those that sign, and the
        # empty push for the rest
        bounds = _Bounds(
            node.threshold * signature + len(node.keys) - node.threshold,
            len(node.keys),
        )
    else:
        # a hash fragment is satisfied by its 32-byte preimage, and BIP379
        # allows no other size
        bounds = _Bounds(1 + 32, None)
    return bounds


def _wrapper_witness(node: Miniscript) -> _Bounds:
    """Return the witness bounds of a wrapped expression."""
    sub = node.subs[0]._witness
    fragment = node.fragment
    if fragment in {"a:", "s:", "n:", "c:"}:
        return sub
    if fragment == "d:":
        # the element ``d:`` duplicates is part of the witness: OP_1 to
        # satisfy, and the empty push to dissatisfy
        return _Bounds(_add(1 + 1, sub.sat), 1)
    if fragment == "v:":
        return _Bounds(sub.sat, None)
    return _Bounds(sub.sat, 1)


def _binary_witness(node: Miniscript) -> _Bounds:
    """Return the witness bounds of a combinator."""
    fragment = node.fragment
    x, y = (sub._witness for sub in node.subs[:2])
    if fragment == "and_v":
        bounds = _Bounds(_add(x.sat, y.sat), None)
    elif fragment == "and_b":
        bounds = _Bounds(_add(x.sat, y.sat), _add(x.dsat, y.dsat))
    elif fragment == "or_b":
        bounds = _Bounds(
            _worst(_add(x.dsat, y.sat), _add(x.sat, y.dsat)), _add(x.dsat, y.dsat)
        )
    elif fragment == "or_c":
        bounds = _Bounds(_worst(x.sat, _add(x.dsat, y.sat)), None)
    elif fragment == "or_d":
        bounds = _Bounds(_worst(x.sat, _add(x.dsat, y.sat)), _add(x.dsat, y.dsat))
    elif fragment == "or_i":
        # the branch selector, which is OP_1 or the empty push: two bytes
        # for the first branch and one for the second
        bounds = _Bounds(
            _worst(_add(x.sat, 2), _add(y.sat, 1)),
            _worst(_add(x.dsat, 2), _add(y.dsat, 1)),
        )
    else:
        z = node.subs[2]._witness
        bounds = _Bounds(
            _worst(_add(x.sat, y.sat), _add(x.dsat, z.sat)), _add(x.dsat, z.dsat)
        )
    return bounds


def _thresh_witness(node: Miniscript) -> _Bounds:
    """Return the witness bounds of a thresh(), over every way to reach it."""
    reached: list[int | None] = [0]
    for sub in node.subs:
        following: list[int | None] = [_add(reached[0], sub._witness.dsat)]
        following.extend(
            _worst(
                _add(reached[j], sub._witness.dsat),
                _add(reached[j - 1], sub._witness.sat),
            )
            for j in range(1, len(reached))
        )
        following.append(_add(reached[-1], sub._witness.sat))
        reached = following
    return _Bounds(reached[node.threshold], reached[0])


def _computed_witness(node: Miniscript) -> _Bounds:
    """Return the witness bytes satisfying and dissatisfying may take."""
    if not node.subs:
        return _leaf_witness(node)
    if node.fragment in _WRAPPERS:
        return _wrapper_witness(node)
    if node.fragment == "thresh":
        return _thresh_witness(node)
    return _binary_witness(node)


@dataclass(frozen=True)
class Miniscript:
    """A miniscript expression: a fragment, its arguments, its own type.

    The fragment is the name BIP379 gives it, a wrapper keeping the colon
    it is written with. `subs` are the subexpressions; `keys` the KEY
    expressions of ``pk_k()``, ``pk_h()``, ``multi()`` and ``multi_a()``;
    `threshold` the number of ``older()``, ``after()``, ``thresh()``,
    ``multi()`` and ``multi_a()``; and `data` the digest of a hash
    fragment. One field per kind of argument, no fragment using all four.

    What is derived is computed once, when the node is built: the type
    properties, the script's length, and the bounds on ops, stack and
    witness. Not for speed but for depth -- an expression nests as deep as
    its script is long, so a value computed on demand would be computed by
    a recursion the length of the tree, where a parser building the tree
    bottom-up has each subexpression's answer already.
    """

    fragment: str
    context: str = P2WSH
    subs: tuple[Miniscript, ...] = ()
    keys: tuple[KeyExpression, ...] = ()
    threshold: int = 0
    data: bytes = b""

    # BIP379's type properties, the script size, and the three bounds:
    # functions of the fields above, and therefore out of the comparison
    # and the repr
    properties: frozenset[str] = field(init=False, compare=False, repr=False)
    script_size: int = field(init=False, compare=False, repr=False)
    _static_ops: int = field(init=False, compare=False, repr=False)
    _ops: _Bounds = field(init=False, compare=False, repr=False)
    _stack: tuple[_Trace | None, _Trace | None] = field(
        init=False, compare=False, repr=False
    )
    _witness: _Bounds = field(init=False, compare=False, repr=False)

    def __post_init__(self) -> None:
        """Check the shape of the node, then compute what it determines."""
        self._assert_shape()
        static, ops = _computed_ops(self)
        for name, value in (
            ("properties", _computed_properties(self)),
            ("script_size", _computed_script_size(self)),
            ("_static_ops", static),
            ("_ops", ops),
            ("_stack", _computed_stack(self)),
            ("_witness", _computed_witness(self)),
        ):
            object.__setattr__(self, name, value)

    def _assert_shape(self) -> None:
        """Refuse a node no fragment has the shape of.

        The arity, the keys, the digest and the number, which neither
        `parse` nor `from_script` can get wrong and a caller building a
        node by hand can. Refused rather than typed empty: an
        ill-*shaped* node is not an expression the rules have anything to
        say about, where an ill-*typed* one is an expression they refuse.
        """
        fragment = self.fragment
        if fragment == "thresh":
            if not self.subs:
                raise BTClibValueError("thresh() takes at least one subexpression")
        elif fragment not in _ARITY:
            raise BTClibValueError(f"unknown miniscript fragment: {fragment}")
        elif len(self.subs) != _ARITY[fragment]:
            err_msg = (
                f"{fragment} takes {_ARITY[fragment]} subexpressions, "
                f"{len(self.subs)} given"
            )
            raise BTClibValueError(err_msg)
        self._assert_keys()
        if len(self.data) != _DATA_SIZE.get(fragment, 0):
            expected = _DATA_SIZE.get(fragment, 0)
            err_msg = (
                f"{fragment} takes {expected} bytes of data, {len(self.data)} given"
            )
            raise BTClibValueError(err_msg)
        self._assert_number()

    def _assert_keys(self) -> None:
        """Refuse the keys no fragment holds, and the ones a context forbids."""
        fragment = self.fragment
        keys = len(self.keys)
        if fragment == "multi" and self.context == TAPSCRIPT:
            raise BTClibValueError("multi() is not allowed in a tapscript")
        if fragment == "multi_a" and self.context != TAPSCRIPT:
            raise BTClibValueError("multi_a() is only allowed in a tapscript")
        if fragment in {"pk_k", "pk_h"}:
            allowed = keys == 1
        elif fragment == "multi":
            allowed = 1 <= keys <= MAX_PUBKEYS_PER_MULTISIG
        elif fragment == "multi_a":
            allowed = 1 <= keys <= _MAX_PUBKEYS_PER_MULTI_A
        else:
            allowed = keys == 0
        if not allowed:
            raise BTClibValueError(f"invalid number of keys in {fragment}: {keys}")

    def _assert_number(self) -> None:
        """Refuse a lock time or a threshold outside its bounds."""
        fragment = self.fragment
        threshold = self.threshold
        if fragment in {"older", "after"}:
            if not 1 <= threshold < _MAX_TIMELOCK:
                raise BTClibValueError(f"invalid {fragment}() value: {threshold}")
        elif fragment in {"multi", "multi_a"}:
            if not 1 <= threshold <= len(self.keys):
                err_msg = f"invalid k in k-of-n {fragment}: {threshold}"
                raise BTClibValueError(err_msg)
        elif fragment == "thresh":
            if not 1 <= threshold <= len(self.subs):
                err_msg = f"invalid thresh() threshold: {threshold} of {len(self.subs)}"
                raise BTClibValueError(err_msg)
        elif threshold:
            raise BTClibValueError(f"{fragment} takes no number: {threshold}")

    @property
    def is_valid(self) -> bool:
        """Answer whether the expression is typed and fits its context."""
        return bool(self.properties) and self.script_size <= _max_script_size(
            self.context
        )

    @property
    def is_valid_top_level(self) -> bool:
        """Answer whether the expression can be a script on its own.

        Which asks one thing beyond validity: the type must be "B", a
        script being satisfied by what it leaves on the stack.
        """
        return self.is_valid and _has(self.properties, "B")

    @property
    def is_non_malleable(self) -> bool:
        """Answer whether every satisfaction can be made non-malleable."""
        return _has(self.properties, "m")

    @property
    def is_signature_required(self) -> bool:
        """Answer whether every satisfaction requires a signature."""
        return _has(self.properties, "s")

    @property
    def mixes_timelocks(self) -> bool:
        """Answer whether a satisfaction needs incompatible timelocks.

        A height lock and a time lock of the same kind in one branch: the
        script is valid and that branch is unspendable, which is the
        expression saying something other than what it means.
        """
        return not _has(self.properties, "k")

    @property
    def key_expressions(self) -> tuple[KeyExpression, ...]:
        """Return every KEY expression of the tree, left to right."""
        keys: list[KeyExpression] = []
        stack = [self]
        while stack:
            node = stack.pop()
            keys.extend(node.keys)
            stack.extend(reversed(node.subs))
        return tuple(keys)

    @property
    def has_duplicate_keys(self) -> bool:
        """Answer whether one KEY expression appears more than once.

        Which BIP379's malleability analysis assumes away: a signature
        made for one check of a key satisfies every other check of it, so
        an expression naming a key twice has satisfactions the type system
        does not predict. Two KEY expressions are the same where they are
        equal -- the same text, in effect -- which is the comparison
        Bitcoin Core's descriptor layer makes too.
        """
        keys = self.key_expressions
        return len(set(keys)) != len(keys)

    @property
    def max_ops(self) -> int | None:
        """Return the ops a satisfaction may cost, None where none exists.

        The non-push op codes of the script plus the keys of every
        OP_CHECKMULTISIG that may be executed, which is what BIP141 counts
        against the 201 of a p2wsh spend.
        """
        return _add(self._static_ops, self._ops.sat)

    @property
    def max_stack_items(self) -> int | None:
        """Return the witness elements a satisfaction needs, None where none.

        The initial stack of the script, which is what a p2wsh witness
        carries and what standardness bounds at a hundred.
        """
        trace = self._stack[0]
        return None if trace is None else trace.net + self._leaves_a_value

    @property
    def max_exec_stack_items(self) -> int | None:
        """Return the elements the stack may hold while it runs, or None.

        The bound consensus puts at a thousand, and the one a tapscript
        can reach without reaching any other: nothing bounds the size of a
        tapscript witness, so the stack during execution is what bounds
        the script.
        """
        trace = self._stack[0]
        return None if trace is None else trace.peak + self._leaves_a_value

    @property
    def _leaves_a_value(self) -> bool:
        """Answer whether the expression leaves a value: anything but a "V"."""
        return bool(self.properties & _t("BKW"))

    @property
    def max_witness_size(self) -> int | None:
        """Return the bytes a satisfying witness may take, None where none.

        The stack elements alone: what pushes them is the witness script,
        and a caller counting a whole input adds it.
        """
        return self._witness.sat

    @property
    def max_witness_stack(self) -> tuple[int, ...] | None:
        """Return the size of every element of the largest satisfying witness.

        In witness order, the script excluded, and None where no
        satisfaction exists at all. What `max_witness_size` answers as one
        number, broken up: an estimator wants the elements, because it is
        the transaction's layout that turns them into bytes -- a count
        prefix and a length prefix each -- and only the transaction knows
        that.

        Estimated and not satisfied: every signature and preimage is
        assumed to turn up and every lock time to be met, so what comes
        back is the largest witness a signer could end up broadcasting
        rather than the one a particular caller can build now. That is what
        a fee wants to be computed from, and it is why this asks for
        nothing: a signature's size is the context's, not the key's.
        """

        def up(_state: None, node: Miniscript, subs: list[_Inputs]) -> _Inputs:
            return _computed_input(
                node, subs, SpendContext(), {}, 0, "mainnet", None, estimate=True
            )

        satisfaction = _tree_eval(self, None, lambda *_: None, up).sat
        if satisfaction.stack is None:
            return None
        return tuple(len(element) for element in satisfaction.stack)

    @property
    def is_satisfiable(self) -> bool:
        """Answer whether any satisfaction exists at all."""
        return self.max_stack_items is not None

    @property
    def is_within_resource_limits(self) -> bool:
        """Answer whether a satisfaction is guaranteed to be spendable.

        The limits that depend on the satisfaction rather than on the
        script: the ops of a p2wsh spend and its hundred witness elements,
        both standardness, and the thousand elements consensus allows on
        the stack of a tapscript while it runs.
        """
        if not self.is_valid:
            return False
        if self.context == TAPSCRIPT:
            items = self.max_exec_stack_items
            return items is None or items <= MAX_STACK_SIZE
        ops = self.max_ops
        elements = self.max_stack_items
        return (ops is None or ops <= MAX_OPS_PER_SCRIPT) and (
            elements is None or elements <= _MAX_STANDARD_P2WSH_STACK_ITEMS
        )

    @property
    def is_sane_subexpression(self) -> bool:
        """Answer whether the expression means what it says, as a part."""
        return (
            self.is_within_resource_limits
            and self.is_non_malleable
            and not self.mixes_timelocks
            and not self.has_duplicate_keys
        )

    @property
    def is_sane(self) -> bool:
        """Answer whether the expression is safe as a script on its own.

        Which adds to its parts being sane the two things only a whole
        script is asked: that it is a "B" of a size its context allows,
        and that it cannot be satisfied without a signature -- without
        one, an attacker is free to change the nSequence and the nLockTime
        the timelocks were checked against, and to rewrite the witness.
        """
        return (
            self.is_valid_top_level
            and self.is_sane_subexpression
            and self.is_signature_required
        )

    @property
    def insane_sub(self) -> Miniscript | None:
        """Return the deepest subexpression that is not sane, or None.

        The deepest, because that is the one to name: an expression is
        insane where one of its parts is, so the part is the answer and
        the whole is the symptom.
        """

        def up(
            _state: None, node: Miniscript, subs: list[Miniscript | None]
        ) -> Miniscript | None:
            for insane in subs:
                if insane is not None:
                    return insane
            return None if node.is_sane_subexpression else node

        return _tree_eval(self, None, lambda *_: None, up)

    def script(
        self,
        index: int = 0,
        network: str = "mainnet",
        prv_keys: PrvKeys | None = None,
    ) -> bytes:
        """Return the script of the expression, its keys derived at `index`.

        The three parameters are `KeyExpression.sec`'s: an index for a
        ranged key, a network for the extended keys, and the private
        material that a hardened step needs and an xpub cannot take.
        """
        if not self.is_valid:
            raise BTClibValueError(f"invalid miniscript: {self}")

        def up(verify: bool, node: Miniscript, subs: list[bytes]) -> bytes:
            return _fragment_script(
                node, subs, verify, index=index, network=network, prv_keys=prv_keys
            )

        return _tree_eval(self, False, _verify_state, up)

    def satisfy(
        self,
        signatures: Mapping[Octets, Octets] | None = None,
        spend: SpendContext | None = None,
        index: int = 0,
        network: str = "mainnet",
        prv_keys: PrvKeys | None = None,
    ) -> list[bytes]:
        """Return the witness elements that satisfy the expression.

        In witness order, the script itself excluded: what a p2wsh spend
        puts in front of the witness script, or a tapscript spend in front
        of the script and its control block.

        Non-malleable or refused, which is BIP379's algorithm and Bitcoin
        Core's default: of the stacks that would satisfy this script, the
        one reported is the one no third party could rewrite, and where
        every candidate is rewritable there is no answer -- a witness that
        is valid and malleable is worse than none, because it is one a
        relay can change under the transaction that carries it. A
        satisfaction with no signature in it is refused for the same
        reason: without one, the nLockTime and the nSequence the timelocks
        were checked against are a third party's to change too.

        `signatures` maps a public key to the signature made with it, as
        `Descriptor.satisfy` takes it; `spend` is the rest of what a
        satisfaction reads. The refusal says which of the two was short,
        because adding to either changes the answer: a preimage or a
        higher sequence can turn "none" into a satisfaction, and can also
        turn a non-malleable one malleable, which is why the two are
        separate messages.
        """
        offered = (
            {}
            if signatures is None
            else {
                bytes_from_octets(key): bytes_from_octets(signature)
                for key, signature in signatures.items()
            }
        )
        context = SpendContext() if spend is None else spend

        def up(_state: None, node: Miniscript, subs: list[_Inputs]) -> _Inputs:
            return _computed_input(
                node,
                subs,
                context,
                offered,
                index,
                network,
                prv_keys,
                estimate=False,
            )

        satisfaction = _tree_eval(self, None, lambda *_: None, up).sat
        if satisfaction.stack is None:
            err_msg = (
                f"no satisfaction of {self} with the signatures, preimages "
                "and lock times given"
            )
            raise BTClibValueError(err_msg)
        if satisfaction.malleable or not satisfaction.has_sig:
            err_msg = (
                f"no non-malleable satisfaction of {self}: every witness that "
                "would satisfy it is one a third party could rewrite"
            )
            raise BTClibValueError(err_msg)
        return list(satisfaction.stack)

    @override
    def __str__(self) -> str:
        """Return the expression as BIP379 writes it.

        Which is not always as it was read: the sugared fragments are
        written sugared -- ``pk()`` for ``c:pk_k()``, ``t:`` for
        ``and_v(X,1)``, ``l:`` and ``u:`` for the two ``or_i()`` with a
        ``0``, ``and_n()`` for ``andor(X,Y,0)`` -- so an expression built
        by hand or read from a script comes out in them too. Bitcoin
        Core's `ToString` writes the same, and the round trip through the
        script is what both keep.
        """
        return _tree_eval(self, False, _wrapper_state, _fragment_text)


def _max_script_size(context: str) -> int:
    """Return the largest script the context allows."""
    if context == TAPSCRIPT:
        return _MAX_TAPSCRIPT_SIZE
    return _MAX_STANDARD_P2WSH_SCRIPT_SIZE


_State = TypeVar("_State")
_Result = TypeVar("_Result")


def _tree_eval(
    root: Miniscript,
    root_state: _State,
    down: Callable[[_State, Miniscript, int], _State],
    up: Callable[[_State, Miniscript, list[_Result]], _Result],
) -> _Result:
    """Compute a value for every node bottom-up, with a state handed down.

    Bitcoin Core's `TreeEval`, and iterative for its reason: a miniscript
    nests as deep as its script is long -- a tapscript may hold a
    thousand nested fragments -- and CPython's frame limit is not a rule
    about scripts. `down` computes the state of a child from its parent's,
    `up` the value of a node from its children's values and its own state.
    """
    stack: list[tuple[Miniscript, int, _State]] = [(root, 0, root_state)]
    results: list[_Result] = []
    while stack:
        node, expanded, state = stack[-1]
        if expanded < len(node.subs):
            stack[-1] = (node, expanded + 1, state)
            stack.append((node.subs[expanded], 0, down(state, node, expanded)))
            continue
        stack.pop()
        cut = len(results) - len(node.subs)
        subs = results[cut:]
        del results[cut:]
        results.append(up(state, node, subs))
    return results[0]


def _verify_state(verify: bool, node: Miniscript, index: int) -> bool:
    """Answer whether a subexpression's script is followed by an OP_VERIFY.

    Which is what lets ``v:`` cost nothing: the last op code of the
    argument becomes its VERIFY form instead. The property is the
    argument's own for ``v:``, and inherited by the last subexpression of
    an ``and_v()`` and by the argument of an ``s:`` -- the two places
    where a subexpression's script ends where its parent's does.
    """
    if node.fragment == "v:":
        return True
    if node.fragment == "s:" or (node.fragment == "and_v" and index == 1):
        return verify
    return False


# every combinator's script as BIP379's translation table gives it: its
# own op codes, and an integer where a subexpression's script goes. The
# fragments left out are the ones whose last op code has a VERIFY form to
# take -- ``c:``, multi(), multi_a() and thresh() -- and ``v:``, which is
# that transformation
_SCRIPT_TEMPLATES: dict[str, tuple[str | int, ...]] = {
    "a:": ("OP_TOALTSTACK", 0, "OP_FROMALTSTACK"),
    "s:": ("OP_SWAP", 0),
    "d:": ("OP_DUP", "OP_IF", 0, "OP_ENDIF"),
    "j:": ("OP_SIZE", "OP_0NOTEQUAL", "OP_IF", 0, "OP_ENDIF"),
    "n:": (0, "OP_0NOTEQUAL"),
    "and_v": (0, 1),
    "and_b": (0, 1, "OP_BOOLAND"),
    "or_b": (0, 1, "OP_BOOLOR"),
    "or_c": (0, "OP_NOTIF", 1, "OP_ENDIF"),
    "or_d": (0, "OP_IFDUP", "OP_NOTIF", 1, "OP_ENDIF"),
    "or_i": ("OP_IF", 0, "OP_ELSE", 1, "OP_ENDIF"),
    "andor": (0, "OP_NOTIF", 2, "OP_ELSE", 1, "OP_ENDIF"),
}


def _sec(
    node: Miniscript,
    key: KeyExpression,
    index: int,
    network: str,
    prv_keys: PrvKeys | None,
) -> bytes:
    """Return the public key as the context writes it: x-only, or SEC."""
    sec = key.sec(index, network, prv_keys)
    return sec[1:] if node.context == TAPSCRIPT else sec


def _leaf_fragment_script(
    node: Miniscript,
    verify: bool,
    index: int,
    network: str,
    prv_keys: PrvKeys | None,
) -> ScriptList:
    """Return the commands of a fragment that has no subexpressions."""
    fragment = node.fragment
    commands: ScriptList
    if fragment in {"0", "1"}:
        commands = [f"OP_{fragment}"]
    elif fragment == "pk_k":
        commands = [_sec(node, node.keys[0], index, network, prv_keys)]
    elif fragment == "pk_h":
        key_hash = hash160(_sec(node, node.keys[0], index, network, prv_keys))
        commands = ["OP_DUP", "OP_HASH160", key_hash, "OP_EQUALVERIFY"]
    elif fragment == "older":
        commands = [*_pushed_number(node.threshold), "OP_CHECKSEQUENCEVERIFY"]
    elif fragment == "after":
        commands = [*_pushed_number(node.threshold), "OP_CHECKLOCKTIMEVERIFY"]
    elif fragment in _HASH_OP_CODES:
        commands = [
            "OP_SIZE",
            *_pushed_number(32),
            "OP_EQUALVERIFY",
            _HASH_OP_CODES[fragment],
            node.data,
            "OP_EQUALVERIFY" if verify else "OP_EQUAL",
        ]
    else:
        commands = _multi_fragment_script(node, verify, index, network, prv_keys)
    return commands


def _multi_fragment_script(
    node: Miniscript,
    verify: bool,
    index: int,
    network: str,
    prv_keys: PrvKeys | None,
) -> ScriptList:
    """Return the commands of a ``multi()`` or of a ``multi_a()``.

    The one op code of the first against one per key of the second, which
    is the whole difference between them: OP_CHECKMULTISIG pops the
    signatures it was built to pop, where OP_CHECKSIGADD counts every
    signature that verifies and the OP_NUMEQUAL compares the count.
    """
    keys = [_sec(node, key, index, network, prv_keys) for key in node.keys]
    if node.fragment == "multi":
        return [
            *_pushed_number(node.threshold),
            *keys,
            *_pushed_number(len(keys)),
            "OP_CHECKMULTISIGVERIFY" if verify else "OP_CHECKMULTISIG",
        ]
    commands: ScriptList = [keys[0], "OP_CHECKSIG"]
    for key in keys[1:]:
        commands += [key, "OP_CHECKSIGADD"]
    return [
        *commands,
        *_pushed_number(node.threshold),
        "OP_NUMEQUALVERIFY" if verify else "OP_NUMEQUAL",
    ]


def _fragment_script(
    node: Miniscript,
    subs: list[bytes],
    verify: bool,
    *,
    index: int,
    network: str,
    prv_keys: PrvKeys | None,
) -> bytes:
    """Return the script of one fragment, its subexpressions' being built."""
    fragment = node.fragment
    if not node.subs:
        return serialize(_leaf_fragment_script(node, verify, index, network, prv_keys))
    if fragment == "c:":
        return subs[0] + serialize(["OP_CHECKSIGVERIFY" if verify else "OP_CHECKSIG"])
    if fragment == "v:":
        # where the argument's last op code has a VERIFY form it has
        # already been written as that form, the argument having been told
        # it is verified; where it has none, "x", the OP_VERIFY goes here
        if _has(node.subs[0].properties, "x"):
            return subs[0] + serialize(["OP_VERIFY"])
        return subs[0]
    if fragment == "thresh":
        script = subs[0]
        for sub in subs[1:]:
            script += sub + serialize(["OP_ADD"])
        return script + serialize(
            [
                *_pushed_number(node.threshold),
                "OP_EQUALVERIFY" if verify else "OP_EQUAL",
            ]
        )
    return b"".join(
        subs[part] if isinstance(part, int) else serialize([part])
        for part in _SCRIPT_TEMPLATES[fragment]
    )


def _wrapper_state(state: bool, node: Miniscript, index: int) -> bool:
    """Answer whether a subexpression is written behind a wrapper.

    Which is what puts the colon in ``s:pk(K)``: the wrappers are written
    as a run of letters, and the colon separates that run from the
    fragment it wraps -- so it belongs to the innermost expression, and
    that expression is the one told it is wrapped. The three sugared
    fragments that stand for a wrapper are wrappers here too.
    """
    return _is_wrapper(node)


def _is_wrapper(node: Miniscript) -> bool:
    """Answer whether the node is written as a wrapper: a letter and a colon."""
    if node.fragment in _WRAPPERS:
        return True
    if node.fragment == "and_v":
        return node.subs[1].fragment == "1"
    return node.fragment == "or_i" and "0" in (
        node.subs[0].fragment,
        node.subs[1].fragment,
    )


def _sugared_text(node: Miniscript, subs: list[str], prefix: str) -> str | None:
    """Return the sugared spelling of a fragment, None where it has none.

    BIP379's five: ``pk()`` and ``pkh()`` for a ``c:`` over the two key
    fragments, ``t:`` for the ``and_v()`` that appends a ``1``, ``l:`` and
    ``u:`` for the ``or_i()`` that adds a ``0`` on either side, and
    ``and_n()`` for the ``andor()`` whose third branch is ``0``.

    Three of them are written as a function and take the colon a wrapped
    expression carries; the two written as a wrapper letter do not, that
    colon being the one their own letter shares with the letters in front
    of it.
    """
    fragment = node.fragment
    if fragment == "c:" and node.subs[0].fragment in {"pk_k", "pk_h"}:
        name = "pk" if node.subs[0].fragment == "pk_k" else "pkh"
        return f"{prefix}{name}({node.subs[0].keys[0]})"
    if fragment == "and_v" and node.subs[1].fragment == "1":
        return "t" + subs[0]
    if fragment == "or_i" and node.subs[0].fragment == "0":
        return "l" + subs[1]
    if fragment == "or_i" and node.subs[1].fragment == "0":
        return "u" + subs[0]
    if fragment == "andor" and node.subs[2].fragment == "0":
        return f"{prefix}and_n({subs[0]},{subs[1]})"
    return None


def _fragment_text(wrapped: bool, node: Miniscript, subs: list[str]) -> str:
    """Return one fragment as text, its subexpressions' being written."""
    fragment = node.fragment
    prefix = ":" if wrapped else ""
    sugared = _sugared_text(node, subs, prefix)
    if sugared is not None:
        return sugared
    if fragment in _WRAPPERS:
        return fragment[0] + subs[0]
    return prefix + _plain_text(node, subs)


def _plain_text(node: Miniscript, subs: list[str]) -> str:
    """Return a fragment written as its name and its arguments.

    Which arguments those are is the one thing that differs between the
    rows: a key, a number, a digest, a threshold and keys, a threshold and
    subexpressions, or subexpressions alone.
    """
    fragment = node.fragment
    if fragment in {"0", "1"}:
        text = fragment
    elif fragment in {"pk_k", "pk_h"}:
        text = f"{fragment}({node.keys[0]})"
    elif fragment in {"older", "after"}:
        text = f"{fragment}({node.threshold})"
    elif fragment in _HASH_OP_CODES:
        text = f"{fragment}({node.data.hex()})"
    elif fragment in {"multi", "multi_a"}:
        keys = ",".join(str(key) for key in node.keys)
        text = f"{fragment}({node.threshold},{keys})"
    elif fragment == "thresh":
        text = f"thresh({node.threshold},{','.join(subs)})"
    else:
        text = f"{fragment}({','.join(subs)})"
    return text


def _sanitized(properties: frozenset[str]) -> frozenset[str]:
    """Return the properties, or none where they name no one basic type.

    The four basic types conflict, so an expression is a "B", a "V", a "K"
    or a "W" and never two of them; what the tables above return where
    their requirements are not met is the properties without any, which is
    not a type. Bitcoin Core's `SanitizeType`, whose other checks are
    invariants of those tables rather than answers about an expression.
    """
    return properties if len(properties & _t("BVKW")) == 1 else _NONE


# how a fragment's arguments are written, for the parser to read: the two
# key fragments and their sugared forms, and the combinators that take
# subexpressions rather than data
_KEY_FRAGMENTS = ("pk", "pkh", "pk_k", "pk_h")
_COMBINATORS = ("andor", "and_n", *_BINARY)
# and every fragment whose arguments are not subexpressions, which is
# what makes the name of one either a leaf or a word the language has not
_LEAVES = (*_KEY_FRAGMENTS, *_HASH_OP_CODES, "older", "after", "multi", "multi_a")

# the states of `parse` and of `from_script`, both of which walk a stack
# of them rather than recursing: an expression nests as deep as its script
# is long. A state that builds a node is named by the fragment it builds,
# so that one function can build any of them; these are the rest
_WRAPPED_EXPR = "a wrapped expression"
_EXPR = "an expression"
_WRAP_T = "the t: wrapper"
_WRAP_U = "the u: wrapper"
_MORE_THRESH = "another thresh() argument"
_COMMA = ","
_CLOSE = ")"

_NAME_CHARACTERS = frozenset("abcdefghijklmnopqrstuvwxyz_0123456789")


def _expression_end(text: str, pos: int) -> int:
    """Return the index one past the expression starting at `pos`.

    Which ends at the comma or the close bracket that is not inside a
    bracket of its own: a KEY expression may hold a ``musig()`` with
    commas of its own, and a subexpression may hold anything.
    """
    depth = 0
    for i in range(pos, len(text)):
        char = text[i]
        if char == "(":
            depth += 1
        elif char == ")":
            if not depth:
                return i
            depth -= 1
        elif char == "," and not depth:
            return i
    return len(text)


def _assert_typed(node: Miniscript) -> Miniscript:
    """Return the node, refusing one the type system does not allow.

    Checked as each node is built rather than once at the end, so that
    what is named is the innermost fragment that failed: the type of an
    expression is a function of its arguments' types, so an argument
    without a type gives its parent none, and the outermost fragment is
    only where that is noticed.
    """
    if not node.properties:
        arguments = ", ".join("".join(sorted(sub.properties)) for sub in node.subs)
        err_msg = f"ill-typed miniscript: {node.fragment} over {arguments}"
        raise BTClibValueError(err_msg)
    if node.script_size > _max_script_size(node.context):
        err_msg = (
            f"miniscript too large for {node.context}: "
            f"{node.script_size} bytes of script"
        )
        raise BTClibValueError(err_msg)
    return node


def _built(fragment: str, built: list[Miniscript], context: str) -> None:
    """Build a node from the arguments already built, and check its type.

    The sugared wrappers are built as what they stand for: ``t:X`` is
    ``and_v(X,1)``, ``u:X`` is ``or_i(X,0)`` and ``and_n(X,Y)`` is
    ``andor(X,Y,0)``, so nothing downstream has to know they were written
    the short way -- `str` writes them short again by recognizing the
    shape.
    """
    arguments: tuple[Miniscript, ...]
    if fragment == _WRAP_T:
        arguments = (built.pop(), Miniscript("1", context))
        fragment = "and_v"
    elif fragment == _WRAP_U:
        arguments = (built.pop(), Miniscript("0", context))
        fragment = "or_i"
    elif fragment == "and_n":
        second = built.pop()
        arguments = (built.pop(), second, Miniscript("0", context))
        fragment = "andor"
    else:
        count = 1 if fragment in _WRAPPERS else _ARITY[fragment]
        arguments = tuple(built[len(built) - count :])
        del built[len(built) - count :]
    built.append(_assert_typed(Miniscript(fragment, context, arguments)))


def _read_wrappers(
    expression: str,
    pos: int,
    to_parse: list[tuple[str, int, int]],
    built: list[Miniscript],
    context: str,
) -> int:
    """Read the wrappers in front of an expression, and stack them.

    They are written as a run of letters ended by a colon, so what says
    there are none is the absence of that colon: `l:` and `u:` are the
    two that are not fragments of their own, and the first of them needs
    the ``0`` its ``or_i()`` puts on the left pushed before the argument
    is read.
    """
    colon = None
    for i in range(pos + 1, len(expression)):
        if expression[i] == ":":
            colon = i
            break
        if expression[i] not in _NAME_CHARACTERS:
            break
    for letter in expression[pos:colon] if colon else "":
        if letter == "l":
            built.append(Miniscript("0", context))
            to_parse.append(("or_i", 0, 0))
        elif letter == "u":
            to_parse.append((_WRAP_U, 0, 0))
        elif letter == "t":
            to_parse.append((_WRAP_T, 0, 0))
        elif f"{letter}:" in _WRAPPERS:
            to_parse.append((f"{letter}:", 0, 0))
        else:
            raise BTClibValueError(f"unknown miniscript wrapper: {letter}:")
    to_parse.append((_EXPR, 0, 0))
    return colon + 1 if colon else pos


def _read_name(expression: str, pos: int) -> tuple[str, int]:
    """Return the name of the fragment at `pos`, and where it ends."""
    end = pos
    while end < len(expression) and expression[end] in _NAME_CHARACTERS:
        end += 1
    if end == pos:
        raise BTClibValueError(f"not a miniscript fragment: {expression[pos:]}")
    return expression[pos:end], end


def _read_key_fragment(
    name: str,
    argument: str,
    context: str,
    prv_keys: dict[str, str],
) -> Miniscript:
    """Return the node of a fragment whose argument is a KEY expression.

    ``pk()`` and ``pkh()`` are BIP379's sugar for a ``c:`` over the other
    two, and are built as that. The key is read as BIP380 defines one,
    with the two restrictions the context puts on it: uncompressed keys
    are unspendable inside a witness program, so neither context allows
    one, and a tapscript holds the 32 bytes of an x-only key.
    """
    tapscript = context == TAPSCRIPT
    key = _parse_key(
        argument,
        prv_keys,
        x_only=tapscript,
        compressed=True,
        musig_allowed=tapscript,
    )
    fragment = "pk_h" if name in {"pkh", "pk_h"} else "pk_k"
    node = Miniscript(fragment, context, keys=(key,))
    return node if name.startswith("pk_") else Miniscript("c:", context, (node,))


def _read_multi(
    name: str,
    argument: str,
    context: str,
    prv_keys: dict[str, str],
) -> Miniscript:
    """Return the node of a ``multi()`` or a ``multi_a()``: a k and keys."""
    arguments = _split_arguments(argument)
    if len(arguments) < 2:
        err_msg = f"{name}() takes a threshold and at least one key"
        raise BTClibValueError(err_msg)
    threshold, *keys = arguments
    if not _NUMBER.fullmatch(threshold):
        raise BTClibValueError(f"invalid {name}() threshold: {threshold}")
    tapscript = context == TAPSCRIPT
    return Miniscript(
        name,
        context,
        keys=tuple(
            _parse_key(
                key,
                prv_keys,
                x_only=tapscript,
                compressed=True,
                musig_allowed=tapscript,
            )
            for key in keys
        ),
        threshold=int(threshold),
    )


def _read_number(name: str, argument: str) -> int:
    """Return the number a fragment's argument is, refusing anything else.

    Digits and nothing else, so that a sign is not read as one: Bitcoin
    Core refuses ``after(-1)`` and ``after(+1)`` for the same reason, an
    expression being text that has one spelling.
    """
    if not _NUMBER.fullmatch(argument):
        raise BTClibValueError(f"invalid {name}() number: {argument}")
    return int(argument)


def _read_leaf(
    name: str,
    argument: str,
    context: str,
    prv_keys: dict[str, str],
) -> Miniscript:
    """Return the node of a fragment whose arguments are not subexpressions."""
    if name in _KEY_FRAGMENTS:
        return _read_key_fragment(name, argument, context, prv_keys)
    if name in _HASH_OP_CODES:
        digest = bytes_from_octets(argument, _DATA_SIZE[name])
        return Miniscript(name, context, data=digest)
    if name in {"older", "after"}:
        return Miniscript(name, context, threshold=_read_number(name, argument))
    return _read_multi(name, argument, context, prv_keys)


def _read_fragment(
    expression: str,
    pos: int,
    to_parse: list[tuple[str, int, int]],
    built: list[Miniscript],
    context: str,
    prv_keys: dict[str, str],
) -> int:
    """Read one fragment, building it or stacking what its arguments need."""
    name, pos = _read_name(expression, pos)
    if name in {"0", "1"}:
        built.append(Miniscript(name, context))
        return pos
    if expression[pos : pos + 1] != "(":
        raise BTClibValueError(f"not a miniscript fragment: {name}")
    if name in _COMBINATORS:
        to_parse.append((name, 0, 0))
        to_parse.append((_CLOSE, 0, 0))
        for _ in range(2 if name == "andor" else 1):
            to_parse.append((_WRAPPED_EXPR, 0, 0))
            to_parse.append((_COMMA, 0, 0))
        to_parse.append((_WRAPPED_EXPR, 0, 0))
        return pos + 1
    if name == "thresh":
        end = _expression_end(expression, pos + 1)
        if expression[end : end + 1] != ",":
            raise BTClibValueError("thresh() takes a threshold and subexpressions")
        threshold = _read_number(name, expression[pos + 1 : end])
        # the first argument is read before the state that loops over the
        # rest, so the count starts at one
        to_parse.append((_MORE_THRESH, 1, threshold))
        to_parse.append((_WRAPPED_EXPR, 0, 0))
        return end + 1
    if name not in _LEAVES:
        raise BTClibValueError(f"unknown miniscript fragment: {name}()")
    end = _expression_end(expression, pos)
    if expression[end - 1 : end] != ")":
        raise BTClibValueError(f"unbalanced brackets: {name}{expression[pos:]}")
    built.append(
        _assert_typed(
            _read_leaf(name, expression[pos + 1 : end - 1], context, prv_keys)
        )
    )
    return end


def _read_more_thresh(
    expression: str,
    pos: int,
    to_parse: list[tuple[str, int, int]],
    built: list[Miniscript],
    context: str,
    count: int,
    threshold: int,
) -> int:
    """Read another thresh() argument, or close the thresh() and build it."""
    char = expression[pos : pos + 1]
    if char == ",":
        to_parse.append((_MORE_THRESH, count + 1, threshold))
        to_parse.append((_WRAPPED_EXPR, 0, 0))
        return pos + 1
    if char != ")":
        raise BTClibValueError(f"unbalanced brackets in thresh(): {expression[pos:]}")
    arguments = tuple(built[len(built) - count :])
    del built[len(built) - count :]
    built.append(
        _assert_typed(Miniscript("thresh", context, arguments, threshold=threshold))
    )
    return pos + 1


def parse(
    expression: str,
    context: str = P2WSH,
    prv_keys: dict[str, str] | None = None,
) -> Miniscript:
    """Return the Miniscript of a BIP379 expression, in its context.

    Refused where the type system refuses it, naming the innermost
    fragment that failed, and refused where the top-level expression is
    not a "B" of a size the context allows: a miniscript that is not both
    is not a script, and every caller of this wants a script.

    `prv_keys` is `descriptors.parse`'s: the mapping an extended private
    key is filed in, under the extended public key that replaces it, so
    that what a parsed expression holds is public.

    A `str`, a BIP379 expression being text, and refused as a type for
    the reason `descriptors.parse` gives: what was neither reached the
    slicing below and left as "object of type X has no len()".

    The context is one of the two BIP379 has, and `prv_keys` a mapping
    or `None`, as `descriptors.parse` asks for the same pair: a context
    no fragment table knows was compared against `TAPSCRIPT`, found
    unequal, and every rule then read as the p2wsh one, so an expression
    was type-checked under a context that does not exist.
    """
    assert_type(expression, str, "miniscript")
    _assert_valid_context(context)
    assert_type(prv_keys, (Mapping, type(None)), "prv_keys")

    if prv_keys is None:
        prv_keys = {}
    to_parse: list[tuple[str, int, int]] = [(_WRAPPED_EXPR, 0, 0)]
    built: list[Miniscript] = []
    pos = 0
    while to_parse:
        state, count, threshold = to_parse.pop()
        if state == _WRAPPED_EXPR:
            pos = _read_wrappers(expression, pos, to_parse, built, context)
        elif state == _EXPR:
            pos = _read_fragment(expression, pos, to_parse, built, context, prv_keys)
        elif state in {_COMMA, _CLOSE}:
            if expression[pos : pos + 1] != state:
                err_msg = f"expected {state!r} in the miniscript: {expression[pos:]}"
                raise BTClibValueError(err_msg)
            pos += 1
        elif state == _MORE_THRESH:
            pos = _read_more_thresh(
                expression, pos, to_parse, built, context, count, threshold
            )
        else:
            _built(state, built, context)
    if pos != len(expression):
        err_msg = f"trailing characters after the miniscript: {expression[pos:]}"
        raise BTClibValueError(err_msg)
    node = built[0]
    if not _has(node.properties, "B"):
        basic = "".join(sorted(node.properties & _t("BVKW")))
        err_msg = f"not a miniscript script: {node} is a {basic}, not a B"
        raise BTClibValueError(err_msg)
    return node


def _op(name: str) -> int:
    """Return the byte of an op code, by the name `script` knows it by."""
    return BYTE_FROM_OP_CODE_NAME[name][0]


_OP_0 = _op("OP_0")
_OP_1 = _op("OP_1")
_OP_16 = _op("OP_16")
_OP_PUSHDATA4 = _op("OP_PUSHDATA4")
_OP_IF = _op("OP_IF")
_OP_NOTIF = _op("OP_NOTIF")
_OP_ELSE = _op("OP_ELSE")
_OP_ENDIF = _op("OP_ENDIF")
_OP_VERIFY = _op("OP_VERIFY")
_OP_TOALTSTACK = _op("OP_TOALTSTACK")
_OP_FROMALTSTACK = _op("OP_FROMALTSTACK")
_OP_DUP = _op("OP_DUP")
_OP_IFDUP = _op("OP_IFDUP")
_OP_SWAP = _op("OP_SWAP")
_OP_SIZE = _op("OP_SIZE")
_OP_EQUAL = _op("OP_EQUAL")
_OP_0NOTEQUAL = _op("OP_0NOTEQUAL")
_OP_ADD = _op("OP_ADD")
_OP_BOOLAND = _op("OP_BOOLAND")
_OP_BOOLOR = _op("OP_BOOLOR")
_OP_NUMEQUAL = _op("OP_NUMEQUAL")
_OP_HASH160 = _op("OP_HASH160")
_OP_CHECKSIG = _op("OP_CHECKSIG")
_OP_CHECKSIGADD = _op("OP_CHECKSIGADD")
_OP_CHECKMULTISIG = _op("OP_CHECKMULTISIG")
_OP_CHECKLOCKTIMEVERIFY = _op("OP_CHECKLOCKTIMEVERIFY")
_OP_CHECKSEQUENCEVERIFY = _op("OP_CHECKSEQUENCEVERIFY")

# the fragment each hash op code belongs to, which is the table above read
# the other way: a script is decoded by its op codes
_HASH_FRAGMENTS = {_op(code): fragment for fragment, code in _HASH_OP_CODES.items()}

# the four op codes that have a VERIFY form, and the form each one takes.
# A script is decoded with them split apart -- the VERIFY becoming an op
# code of its own -- because that is what the ``v:`` wrapper writes, and
# what a fragment ending in one of these writes when it is verified
_VERIFY_FORMS = {
    _op("OP_CHECKSIGVERIFY"): _OP_CHECKSIG,
    _op("OP_CHECKMULTISIGVERIFY"): _OP_CHECKMULTISIG,
    _op("OP_EQUALVERIFY"): _OP_EQUAL,
    _op("OP_NUMEQUALVERIFY"): _OP_NUMEQUAL,
}

# the states of the decoder that are not the name of a fragment to build
_SINGLE = "one expression"
_MAYBE_AND_V = "another and_v() argument, if there is one"
_W_EXPR = "a W expression"
_THRESH_BRANCH = "another thresh() branch"
_THRESH_END = "the end of a thresh()"
_ENDIF = "what an OP_ENDIF closes"
_ENDIF_NOTIF = "an or_c() or an or_d()"
_ENDIF_ELSE = "an or_i() or an andor()"

# _SINGLE reads one B, V or K expression, and this reads a run of them:
# and_v() writes its arguments one after the other, so a script does not
# say where one ends and the next begins, and a run of them is what any
# one of them may be
_BKV = (_SINGLE, _MAYBE_AND_V)


def _assert_minimal_push(op_code: int, data: bytes, encoded: bytes) -> None:
    """Refuse a push that is not the shortest way to write itself.

    BIP62's rule, and the reason a script has one miniscript and not
    several: a non-minimal push would decode to the same fragment and
    serialize back to different bytes, so the round trip would not hold.
    The interpreter enforces the same rule under MINIMALDATA, on the
    scripts it executes rather than on the ones it reads.
    """
    if len(data) == 1 and (data[0] == 0x81 or 1 <= data[0] <= 16):
        err_msg = f"non-minimal push: an op code pushes {data.hex()}"
        raise BTClibValueError(err_msg)
    if serialize([data]) != encoded:
        err_msg = f"non-minimal push of {len(data)} bytes: op code {hex(op_code)}"
        raise BTClibValueError(err_msg)


def _decomposed(script: bytes) -> list[tuple[int, bytes]]:
    """Return the op codes of a script and their data, last one first.

    Last first because that is the end a script is read from: a fragment
    is recognized by the op code that closes it -- an OP_ENDIF, an
    OP_BOOLOR, a CHECKSIG -- and what precedes it is then read as its
    arguments.

    An OP_n is answered as the push of the number it pushes, so that a
    threshold written as an op code and one written as a byte read the
    same; the four VERIFY forms are split into the op code and an
    OP_VERIFY, which is how the ``v:`` wrapper writes them; and a script
    that writes one of those four *as* two op codes is refused, there
    being one spelling of it.
    """
    entries: list[tuple[int, bytes]] = []
    spans = list(op_code_spans(script))
    if not (spans and spans[-1][2] == len(script)) and script:
        raise BTClibValueError(f"not a script: {script.hex()}")
    for position, (op_code, start, stop) in enumerate(spans):
        if _OP_1 <= op_code <= _OP_16:
            entries.append((op_code, bytes([op_code - _OP_1 + 1])))
            continue
        if op_code in _VERIFY_FORMS:
            entries.append((_VERIFY_FORMS[op_code], b""))
            entries.append((_OP_VERIFY, b""))
            continue
        if _OP_0 < op_code <= _OP_PUSHDATA4:
            prefix = 1 if op_code <= 75 else 1 + 2 ** (op_code - 76)
            data = script[start + prefix : stop]
            _assert_minimal_push(op_code, data, script[start:stop])
            entries.append((op_code, data))
            continue
        if (
            op_code in {_OP_CHECKSIG, _OP_CHECKMULTISIG, _OP_EQUAL, _OP_NUMEQUAL}
            and position + 1 < len(spans)
            and spans[position + 1][0] == _OP_VERIFY
        ):
            err_msg = f"non-minimal VERIFY after op code {hex(op_code)}"
            raise BTClibValueError(err_msg)
        entries.append((op_code, b""))
    entries.reverse()
    return entries


def _script_number(entry: tuple[int, bytes]) -> int | None:
    """Return the number an entry pushes, None where it pushes none.

    The four-byte bound and the minimal encoding of Bitcoin Core's
    CScriptNum: a longer push is not a number a script can compare, and a
    number written with a byte to spare is a second spelling of itself.
    """
    op_code, data = entry
    if op_code == _OP_0:
        return 0
    if not data or len(data) > 4:
        return None
    number = decode_num(data)
    return number if encode_num(number) == data else None


def _key_from_sec(sec: bytes, context: str) -> KeyExpression:
    """Return the KEY expression of a public key read from a script."""
    if context == TAPSCRIPT:
        # the even-y lift of BIP340, which is what those 32 bytes mean
        return KeyExpression(pub_key=b"\x02" + sec, x_only=True)
    return KeyExpression(pub_key=sec)


@dataclass
class _Decoder:
    """The stack machine that reads a script back into an expression.

    Bitcoin Core's `DecodeScript`, and a machine rather than a recursion
    for `_tree_eval`'s reason. `entries` are the op codes last one first,
    `pos` how far into them the walk has come, `to_parse` what is still
    expected, and `built` the expressions completed so far -- the last of
    them being the leftmost, since the script is read from its end.
    """

    entries: list[tuple[int, bytes]]
    context: str
    key_hashes: dict[bytes, bytes]
    pos: int = 0
    to_parse: list[tuple[str, int, int]] = field(default_factory=list)
    built: list[Miniscript] = field(default_factory=list)

    def _remaining(self) -> int:
        return len(self.entries) - self.pos

    def _op_code(self, offset: int) -> int:
        return self.entries[self.pos + offset][0]

    def _data(self, offset: int) -> bytes:
        return self.entries[self.pos + offset][1]

    def _expect(self, *states: str) -> None:
        """Stack what is expected next, the first named being read first."""
        self.to_parse.extend((state, 0, 0) for state in reversed(states))

    def _constant(self) -> Miniscript | None:
        fragment = {_OP_1: "1", _OP_0: "0"}.get(self._op_code(0))
        if fragment is None:
            return None
        self.pos += 1
        return Miniscript(fragment, self.context)

    def _key(self) -> Miniscript | None:
        """Read a pk_k(), which is a key, or a pk_h(), which is its hash.

        The hash is all a ``pk_h()`` leaves in the script, so reading one
        back needs the key from somewhere else: `key_hashes` is that
        somewhere, and without the entry the script cannot be read --
        which is Bitcoin Core's answer too, its own inference asking a
        signing provider for the key behind the hash.
        """
        data = self._data(0)
        if len(data) in {32, 33}:
            expected = 32 if self.context == TAPSCRIPT else 33
            if len(data) != expected:
                err_msg = f"not a {self.context} public key: {len(data)} bytes"
                raise BTClibValueError(err_msg)
            self.pos += 1
            return Miniscript(
                "pk_k", self.context, keys=(_key_from_sec(data, self.context),)
            )
        if (
            self._remaining() >= 5
            and self._op_code(0) == _OP_VERIFY
            and self._op_code(1) == _OP_EQUAL
            and self._op_code(3) == _OP_HASH160
            and self._op_code(4) == _OP_DUP
            and len(self._data(2)) == 20
        ):
            key_hash = self._data(2)
            if key_hash not in self.key_hashes:
                err_msg = f"no public key for the hash160 {key_hash.hex()}"
                raise BTClibValueError(err_msg)
            sec = self.key_hashes[key_hash]
            # the answer is checked against the question, which is the one
            # thing the script itself cannot say: a mapping filing a key
            # under a hash that is not its own reads the script into an
            # expression writing a different script back, and the inverse
            # this module documents would hold for every input but that one
            if hash160(sec) != key_hash:
                err_msg = f"the key answered for the hash160 {key_hash.hex()}"
                err_msg += f" hashes to {hash160(sec).hex()}"
                raise BTClibValueError(err_msg)
            self.pos += 5
            key = _key_from_sec(sec, self.context)
            return Miniscript("pk_h", self.context, keys=(key,))
        return None

    def _timelock(self) -> Miniscript | None:
        locks = {
            _OP_CHECKSEQUENCEVERIFY: "older",
            _OP_CHECKLOCKTIMEVERIFY: "after",
        }
        fragment = locks.get(self._op_code(0))
        if fragment is None or self._remaining() < 2:
            return None
        number = _script_number(self.entries[self.pos + 1])
        if number is None:
            return None
        self.pos += 2
        return Miniscript(fragment, self.context, threshold=number)

    def _hash(self) -> Miniscript | None:
        """Read a hash fragment: the size check, the digest, the comparison."""
        if self._remaining() < 7 or self._op_code(0) != _OP_EQUAL:
            return None
        if not (
            self._op_code(3) == _OP_VERIFY
            and self._op_code(4) == _OP_EQUAL
            and _script_number(self.entries[self.pos + 5]) == 32
            and self._op_code(6) == _OP_SIZE
        ):
            return None
        fragment = _HASH_FRAGMENTS.get(self._op_code(2))
        if fragment is None or len(self._data(1)) != _DATA_SIZE[fragment]:
            return None
        digest = self._data(1)
        self.pos += 7
        return Miniscript(fragment, self.context, data=digest)

    def _multi(self) -> Miniscript | None:
        if self._remaining() < 3 or self._op_code(0) != _OP_CHECKMULTISIG:
            return None
        if self.context == TAPSCRIPT:
            raise BTClibValueError("multi() is not allowed in a tapscript")
        count = _script_number(self.entries[self.pos + 1])
        if count is None or self._remaining() < 3 + count:
            raise BTClibValueError("not a multi(): no number of keys")
        keys = []
        for i in range(count):
            sec = self._data(2 + i)
            if len(sec) != 33:
                raise BTClibValueError(f"not a multi() key: {len(sec)} bytes")
            keys.append(_key_from_sec(sec, self.context))
        threshold = _script_number(self.entries[self.pos + 2 + count])
        if threshold is None:
            raise BTClibValueError("not a multi(): no threshold")
        self.pos += 3 + count
        # the keys were read from the end of the script, so the last read
        # is the first the script pushes
        keys.reverse()
        return Miniscript("multi", self.context, keys=tuple(keys), threshold=threshold)

    def _multi_a(self) -> Miniscript | None:
        """Read a multi_a(): a CHECKSIG, then a CHECKSIGADD per further key."""
        if self._remaining() < 4 or self._op_code(0) != _OP_NUMEQUAL:
            return None
        if self.context != TAPSCRIPT:
            raise BTClibValueError("multi_a() is only allowed in a tapscript")
        threshold = _script_number(self.entries[self.pos + 1])
        if threshold is None:
            raise BTClibValueError("not a multi_a(): no threshold")
        keys = []
        offset = 2
        while True:
            if self._remaining() < offset + 2:
                raise BTClibValueError("not a multi_a(): the keys end the script")
            op_code = self._op_code(offset)
            if op_code not in {_OP_CHECKSIGADD, _OP_CHECKSIG}:
                raise BTClibValueError("not a multi_a(): no CHECKSIG for a key")
            sec = self._data(offset + 1)
            if len(sec) != 32:
                raise BTClibValueError(f"not a multi_a() key: {len(sec)} bytes")
            keys.append(_key_from_sec(sec, self.context))
            offset += 2
            if op_code == _OP_CHECKSIG:
                break
        self.pos += offset
        keys.reverse()
        return Miniscript(
            "multi_a", self.context, keys=tuple(keys), threshold=threshold
        )

    def _single(self) -> None:
        """Read one B, V or K expression, which is what every state expects."""
        if not self._remaining():
            raise BTClibValueError("the script ends where an expression is expected")
        for reader in (
            self._constant,
            self._key,
            self._timelock,
            self._hash,
            self._multi,
            self._multi_a,
        ):
            node = reader()
            if node is not None:
                self.built.append(node)
                return
        self._combinator()

    def _combinator(self) -> None:
        """Read the op code that closes a fragment, and expect its arguments.

        The wrappers ask for one expression and not a run of them, which is
        what and_v() commutes with: ``c:and_v(X,Y)`` and ``and_v(X,c:Y)``
        have the same script, and the second is the one that is valid.
        """
        op_code = self._op_code(0)
        wrappers = {_OP_CHECKSIG: "c:", _OP_VERIFY: "v:", _OP_0NOTEQUAL: "n:"}
        if op_code in wrappers:
            self.pos += 1
            self._expect(_SINGLE, wrappers[op_code])
            return
        if op_code == _OP_ENDIF:
            self.pos += 1
            self._expect(*_BKV, _ENDIF)
            return
        # and_b() and or_b() take a W as their second argument, and it is
        # the first one read: the script writes it last
        pairs = {_OP_BOOLAND: "and_b", _OP_BOOLOR: "or_b"}
        if op_code in pairs:
            self.pos += 1
            self._expect(_W_EXPR, _SINGLE, pairs[op_code])
            return
        number = (
            _script_number(self.entries[self.pos + 1])
            if self._remaining() >= 3
            else None
        )
        if op_code == _OP_EQUAL and number is not None:
            if number < 1:
                raise BTClibValueError(f"invalid thresh() threshold: {number}")
            self.pos += 2
            self.to_parse.append((_THRESH_BRANCH, 0, number))
            return
        err_msg = f"not a miniscript: op code {hex(op_code)} closes no fragment"
        raise BTClibValueError(err_msg)

    def _wrapped(self) -> None:
        """Read a W expression, which is an ``a:`` or an ``s:``."""
        if not self._remaining():
            raise BTClibValueError("the script ends where a W expression is expected")
        if self._op_code(0) == _OP_FROMALTSTACK:
            self.pos += 1
            self._expect(*_BKV, "a:")
        else:
            self._expect(*_BKV, "s:")

    def _maybe_and_v(self) -> None:
        """Expect another and_v() argument where the script could hold one.

        The op codes that cannot end a well-formed expression are the ones
        that begin something else: what follows them is not an argument of
        an and_v() but the branch or the wrapper they belong to.
        """
        ends = {_OP_IF, _OP_ELSE, _OP_NOTIF, _OP_TOALTSTACK, _OP_SWAP}
        if self._remaining() and self._op_code(0) not in ends:
            self._expect(*_BKV, "and_v")

    def _thresh_branch(self, count: int, threshold: int) -> None:
        if not self._remaining():
            raise BTClibValueError("the script ends inside a thresh()")
        if self._op_code(0) == _OP_ADD:
            self.pos += 1
            self.to_parse.append((_THRESH_BRANCH, count + 1, threshold))
            self.to_parse.append((_W_EXPR, 0, 0))
        else:
            self.to_parse.append((_THRESH_END, count + 1, threshold))
            # every argument of a thresh() is "d", so none is an and_v()
            self.to_parse.append((_SINGLE, 0, 0))

    def _thresh_end(self, count: int, threshold: int) -> None:
        if threshold > count:
            err_msg = f"invalid thresh() threshold: {threshold} of {count}"
            raise BTClibValueError(err_msg)
        # read backwards, so the last branch built is the first one written
        arguments = tuple(reversed(self.built[len(self.built) - count :]))
        del self.built[len(self.built) - count :]
        self.built.append(
            Miniscript("thresh", self.context, arguments, threshold=threshold)
        )

    def _endif(self) -> None:
        """Read what an OP_ENDIF closed, once its first argument is read."""
        if not self._remaining():
            raise BTClibValueError("the script ends inside an OP_IF")
        op_code = self._op_code(0)
        if op_code == _OP_ELSE:
            self.pos += 1
            self._expect(*_BKV, _ENDIF_ELSE)
            return
        if op_code == _OP_NOTIF:
            self.pos += 1
            self.to_parse.append((_ENDIF_NOTIF, 0, 0))
            return
        if op_code != _OP_IF:
            err_msg = f"not a miniscript: op code {hex(op_code)} before an OP_ENDIF"
            raise BTClibValueError(err_msg)
        if self._remaining() >= 2 and self._op_code(1) == _OP_DUP:
            self.pos += 2
            self.to_parse.append(("d:", 0, 0))
            return
        if (
            self._remaining() >= 3
            and self._op_code(1) == _OP_0NOTEQUAL
            and self._op_code(2) == _OP_SIZE
        ):
            self.pos += 3
            self.to_parse.append(("j:", 0, 0))
            return
        raise BTClibValueError("not a miniscript: an OP_IF wrapping nothing known")

    def _endif_notif(self) -> None:
        """Tell an or_d() from an or_c(): the first duplicates what it read."""
        if not self._remaining():
            raise BTClibValueError("the script ends inside an OP_NOTIF")
        if self._op_code(0) == _OP_IFDUP:
            self.pos += 1
            self.to_parse.append(("or_d", 0, 0))
        else:
            self.to_parse.append(("or_c", 0, 0))
        # both take a "d" as their first argument, so neither is an and_v()
        self.to_parse.append((_SINGLE, 0, 0))

    def _endif_else(self) -> None:
        """Tell an or_i() from an andor(), which tests its first argument."""
        if not self._remaining():
            raise BTClibValueError("the script ends inside an OP_ELSE")
        if self._op_code(0) == _OP_IF:
            self.pos += 1
            self._build("or_i", 2)
            return
        if self._op_code(0) != _OP_NOTIF:
            err_msg = (
                f"not a miniscript: op code {hex(self._op_code(0))} before OP_ELSE"
            )
            raise BTClibValueError(err_msg)
        self.pos += 1
        self.to_parse.append(("andor", 0, 0))
        self.to_parse.append((_SINGLE, 0, 0))

    def _wrap_stacked(self, fragment: str) -> None:
        """Consume the op code that moved the argument, then wrap it.

        A "W" expression is written around its argument -- ``a:`` puts it
        on the altstack and takes it back, ``s:`` swaps what is under it --
        so the op code in front of the argument is read after it, the
        script being read backwards.
        """
        expected = _OP_TOALTSTACK if fragment == "a:" else _OP_SWAP
        if not self._remaining() or self._op_code(0) != expected:
            err_msg = f"not a {fragment} wrapper: its first op code is missing"
            raise BTClibValueError(err_msg)
        self.pos += 1
        self._build(fragment, 1)

    def _build(self, fragment: str, count: int) -> None:
        """Build a node from the arguments read, which are in reverse order."""
        arguments = tuple(reversed(self.built[len(self.built) - count :]))
        del self.built[len(self.built) - count :]
        if fragment == "andor":
            # the script writes andor(X,Y,Z) as [X] NOTIF [Z] ELSE [Y]
            # ENDIF, so what is read last is X and what is read first is Y
            arguments = (arguments[0], arguments[2], arguments[1])
        self.built.append(Miniscript(fragment, self.context, arguments))

    def decode(self) -> Miniscript:
        """Read the whole script, and return the expression it is."""
        # the top level, so the type is B: a W expression cannot be one
        self._expect(*_BKV)
        # what each state that reads the script does; the rest build a node
        readers = {
            _SINGLE: self._single,
            _MAYBE_AND_V: self._maybe_and_v,
            _W_EXPR: self._wrapped,
            _ENDIF: self._endif,
            _ENDIF_NOTIF: self._endif_notif,
            _ENDIF_ELSE: self._endif_else,
        }
        while self.to_parse:
            if self.built and not self.built[-1].is_valid:
                _assert_typed(self.built[-1])
            state, count, threshold = self.to_parse.pop()
            reader = readers.get(state)
            if reader is not None:
                reader()
            elif state == _THRESH_BRANCH:
                self._thresh_branch(count, threshold)
            elif state == _THRESH_END:
                self._thresh_end(count, threshold)
            elif state in {"a:", "s:"}:
                self._wrap_stacked(state)
            elif state in _WRAPPERS:
                self._build(state, 1)
            else:
                self._build(state, _ARITY[state])
        return self.built[0]


def from_script(
    script: Octets,
    context: str = P2WSH,
    key_hashes: Mapping[Octets, Octets] | None = None,
) -> Miniscript:
    """Return the Miniscript a script is, refusing one that is not miniscript.

    The other direction of `Miniscript.script`, and its inverse: what this
    returns writes back the very bytes it was read from, so a wallet
    handed a witness script can say what spends it. Not every script is a
    miniscript, and this is what answers the question -- a caller asking
    it catches the refusal.

    `key_hashes` maps a hash160 to the public key behind it, for the one
    fragment that keeps no key in the script: ``pk_h()`` and its sugared
    ``pkh()`` write the hash alone, so a script holding one is readable
    only where the key is supplied. Bitcoin Core asks a signing provider
    the same question, and the answer is held to it: a key filed under a
    hash that is not its own is refused rather than read, that being the
    one input for which the inverse above did not hold.

    `reads_back` is this question asked without the refusal, for a caller
    that holds a script and wants to know whether any language reads it.
    """
    script = bytes_from_octets(script)
    if len(script) > _max_script_size(context):
        err_msg = f"script too large for {context}: {len(script)} bytes"
        raise BTClibValueError(err_msg)
    decoder = _Decoder(
        _decomposed(script),
        context,
        {
            bytes_from_octets(key_hash): bytes_from_octets(key)
            for key_hash, key in (key_hashes or {}).items()
        },
    )
    node = decoder.decode()
    if decoder.pos != len(decoder.entries):
        err_msg = "not a miniscript: the script holds more than one expression"
        raise BTClibValueError(err_msg)
    _assert_typed(node)
    if not _has(node.properties, "B"):
        basic = "".join(sorted(node.properties & _t("BVKW")))
        err_msg = f"not a miniscript script: {node} is a {basic}, not a B"
        raise BTClibValueError(err_msg)
    return node


def reads_back(
    script: Octets,
    context: str = P2WSH,
    key_hashes: Mapping[Octets, Octets] | None = None,
) -> bool:
    """Whether a script is the miniscript it reads as.

    The round trip as a question: the script is read back into an
    expression and the expression writes a script, and the answer is
    whether those are the same bytes. What it is asked about is a script
    somebody else wrote -- a witness script off a psbt, the pre-image a
    wallet computes -- where "this is a 2-of-3 with a timelock" is an
    intention, and reading it back is the only thing that says the bytes
    agree with it. A script that is well formed by accident hashes to a
    perfectly good address, and nothing else notices.

    False is the answer wherever no language reads the script: not every
    script is a miniscript -- an ``OP_DROP`` where nothing drops, a
    quorum whose count does not match its keys -- and a caller wanting to
    know *what* is wrong with it calls `from_script` and reads the
    refusal.

    Written as the round trip rather than as "`from_script` accepted it",
    which is what it comes to today: the decoder refuses every second
    spelling of one expression -- a non-minimal push, a number with a
    byte to spare, a VERIFY written as two op codes -- and a key answered
    for the wrong hash, so what it accepts writes itself back. That is
    the claim, and this is the proof of it rather than a restatement.
    """
    script = bytes_from_octets(script)
    try:
        node = from_script(script, context, key_hashes)
    except BTClibValueError:
        return False
    return node.script() == script


def _assert_sane(node: Miniscript) -> None:
    """Refuse a miniscript that does not mean what it says.

    What Bitcoin Core requires of a miniscript before it accepts a
    descriptor holding one, and the message it answers with: the
    subexpression at fault and the first thing wrong with it. A caller
    that wants the analysis rather than the refusal reads the properties
    themselves -- `is_sane` is this question without the message.

    Satisfiability is asked beside sanity and not inside it, which is
    Bitcoin Core's split too: an expression with no satisfaction at all is
    a script nobody can spend, and every *part* of a sane expression may
    be one -- the ``0`` of an ``or_i()`` among them.
    """
    if node.is_sane and node.is_satisfiable:
        return
    insane = node.insane_sub or node
    if not node.is_satisfiable:
        raise BTClibValueError(f"{node} is not satisfiable")
    if not insane.is_non_malleable:
        raise BTClibValueError(f"{insane} is not sane: malleable witnesses exist")
    if insane is node and not insane.is_signature_required:
        err_msg = f"{insane} is not sane: witnesses without signature exist"
        raise BTClibValueError(err_msg)
    if insane.mixes_timelocks:
        err_msg = (
            f"{insane} is not sane: it mixes timelocks "
            "expressed in blocks and in seconds"
        )
        raise BTClibValueError(err_msg)
    if insane.has_duplicate_keys:
        raise BTClibValueError(f"{insane} is not sane: it repeats a public key")
    err_msg = f"{insane} is not sane: satisfying it may exceed the resource limits"
    raise BTClibValueError(err_msg)


@dataclass(frozen=True)
class SpendContext:
    """What a miniscript satisfaction reads beside the signatures.

    The signatures are `Descriptor.satisfy`'s own parameter and are not
    here: one source of truth for them, and this is the rest of what a
    satisfaction may need -- the preimage of a hash fragment, and the
    lock times the transaction being built will carry, which say whether
    an ``older()`` or an ``after()`` can be met at all.

    The four preimage mappings are `PsbtIn`'s four, field for field, and
    keyed the same way: the digest to the bytes that hash to it -- bytes
    and not "bytes or hex", where the signatures of `satisfy` take either,
    because these come from a psbt rather than from a keyboard. A psbt
    carries them because BIP174 gave them fields, which is what lets
    `descriptors.miniscript_solver` build a context out of one.

    `sequence` is the input's own, `locktime` the transaction's, and
    `version` matters for the same reason it matters to the interpreter:
    BIP68's relative locks are enforced from version 2, so an ``older()``
    in a version-1 transaction is a branch nothing can spend.
    """

    sha256_preimages: Mapping[bytes, bytes] = field(default_factory=dict)
    hash256_preimages: Mapping[bytes, bytes] = field(default_factory=dict)
    ripemd160_preimages: Mapping[bytes, bytes] = field(default_factory=dict)
    hash160_preimages: Mapping[bytes, bytes] = field(default_factory=dict)
    locktime: int = 0
    sequence: int = 0
    version: int = 2

    def _preimage(self, fragment: str, digest: bytes) -> bytes | None:
        """Return the preimage of a digest, None where the caller has none."""
        preimage = {
            "sha256": self.sha256_preimages,
            "hash256": self.hash256_preimages,
            "ripemd160": self.ripemd160_preimages,
            "hash160": self.hash160_preimages,
        }[fragment].get(digest)
        # BIP379 allows a preimage of 32 bytes and no other size, which is
        # what makes the size of a satisfaction predictable; a mapping
        # holding another is a caller's mistake and not a missing preimage
        return None if preimage is None else bytes_from_octets(preimage, 32)

    def _after(self, value: int) -> bool:
        """Answer whether the transaction's lock time meets an ``after()``.

        BIP65's rule, which is what the interpreter enforces in
        `script.engine`: the two must be the same kind of lock time --
        both block heights or both timestamps, either side of the
        500000000 threshold -- and the transaction's must have reached
        the fragment's. The final sequence that would let a transaction
        ignore its own lock time is a refusal there and cannot be one
        here: `sequence` is what this context carries, and a caller that
        set it to 0xffffffff has asked for a transaction with no lock
        time at all.
        """
        if (value >= _LOCKTIME_THRESHOLD) != (self.locktime >= _LOCKTIME_THRESHOLD):
            return False
        return value <= self.locktime and self.sequence != 0xFFFFFFFF

    def _older(self, value: int) -> bool:
        """Answer whether the input's sequence meets an ``older()``.

        BIP112's rule, again the interpreter's: from version 2, with the
        disable bit clear, the same unit on bit 22 -- blocks against
        512-second intervals -- and a relative lock time at least the
        fragment's.
        """
        if self.version < 2 or self.sequence & (1 << 31):
            return False
        if value & _SEQUENCE_LOCKTIME_TYPE_FLAG != (
            self.sequence & _SEQUENCE_LOCKTIME_TYPE_FLAG
        ):
            return False
        return value & 0x0000FFFF <= self.sequence & 0x0000FFFF


@dataclass(frozen=True)
class _Input:
    """One witness stack that satisfies or dissatisfies an expression.

    `stack` is None where there is no such stack at all -- Bitcoin Core's
    Availability::NO, and BIP379's *(none)*. The three flags are what the
    non-malleable algorithm chooses by: whether the stack carries a
    signature, whether a third party could rewrite it, and whether it is
    one of the options BIP379 lists as unnecessary. `size` is the witness
    bytes it takes, which is what breaks a tie.
    """

    stack: tuple[bytes, ...] | None
    has_sig: bool = False
    malleable: bool = False
    non_canonical: bool = False
    size: int = 0


def _element(data: bytes) -> _Input:
    """Return a one-element stack, its length prefix counted."""
    return _Input((data,), size=len(data) + 1)


_NO_WITNESS = _Input(None)
_NO_PUSHES = _Input(())
_ZERO_PUSH = _element(b"")
_ONE_PUSH = _element(b"\x01")
# the dissatisfaction of a hash fragment: any 32 bytes that are not the
# preimage, and malleable by construction -- a third party can put other
# 32 bytes there, which is why BIP379 rules it out of a non-malleable
# satisfaction rather than merely listing it
_ZERO32_PUSH = _Input((bytes(32),), malleable=True, size=33)


def _both(first: _Input, second: _Input) -> _Input:
    """Return the stack that is the first followed by the second.

    Which is Bitcoin Core's ``+``: the elements of one and then of the
    other, and every flag of either. Absent where either is absent -- a
    satisfaction needing two things has neither if one is missing.
    """
    if first.stack is None or second.stack is None:
        return _NO_WITNESS
    return _Input(
        first.stack + second.stack,
        has_sig=first.has_sig or second.has_sig,
        malleable=first.malleable or second.malleable,
        non_canonical=first.non_canonical or second.non_canonical,
        size=first.size + second.size,
    )


def _better(first: _Input, second: _Input) -> _Input:
    """Return the one of two stacks a non-malleable satisfaction takes.

    BIP379's algorithm, as Bitcoin Core's ``|`` implements it: a stack
    without a signature is one an attacker can produce too, so where only
    one option carries a signature the other is what a malleator would
    use and is therefore the one to report; where neither does, both are
    malleable, because either could be swapped for the other; where both
    do, the non-malleable one wins, and between two of a kind the smaller
    witness does.
    """
    if first.stack is None:
        return second
    if second.stack is None:
        return first
    if first.has_sig != second.has_sig:
        return second if first.has_sig else first
    if not first.has_sig:
        return replace(first if first.size <= second.size else second, malleable=True)
    if first.malleable != second.malleable:
        return second if first.malleable else first
    return first if first.size <= second.size else second


# which of two candidate stacks a walk keeps: `_better` for the witness a
# signer will build, `_larger` for how large one can get
_Choice = Callable[["_Input", "_Input"], "_Input"]


def _larger(first: _Input, second: _Input) -> _Input:
    """Return the larger of two stacks, which is what an estimate keeps.

    Where `_better` answers "which of these will be built", this answers
    "how large can this get": the malleability rules of the first are
    about choosing a witness and say nothing about the size of the one a
    signer ends up with when the cheap branch is the one that is shut. It
    is what makes this the same number Bitcoin Core's `MaxSatSize` reports,
    which is the static bound of `max_witness_size` and not the
    satisfaction of any particular spend.
    """
    if first.stack is None:
        return second
    if second.stack is None:
        return first
    # a malleable option is one no satisfaction of this library builds, so
    # its size bounds nothing that will be broadcast: this is the one rule
    # of `_better` an estimate keeps, and it is what makes the answer agree
    # with `max_witness_size`, whose own tables count the canonical
    # satisfactions alone
    if first.malleable != second.malleable:
        return second if first.malleable else first
    return first if first.size >= second.size else second


@dataclass(frozen=True)
class _Inputs:
    """The best stack for satisfying an expression, and for dissatisfying it."""

    sat: _Input
    dsat: _Input


def _assumed_signature(node: Miniscript) -> _Input:
    """Return the stack of a signature the caller does not have yet.

    Which is what an estimate is made of: the largest signature the context
    takes, in bytes that are not a signature and never leave this module --
    only their length is read.

    Nothing marks them as assumed, and nothing has to: an estimate assumes
    every signature and a satisfaction assumes none, so the two never
    compare a real stack against a supposed one. That is the whole of what
    Bitcoin Core's Availability::MAYBE arbitrates, and why there is no
    third state here.
    """
    return replace(_element(bytes(_signature_size(node.context))), has_sig=True)


def _key_input(
    node: Miniscript,
    signatures: Mapping[bytes, bytes],
    index: int,
    network: str,
    prv_keys: PrvKeys | None,
    *,
    estimate: bool,
) -> _Inputs:
    """Return the stacks of a ``pk_k()`` or a ``pk_h()``.

    A ``pk_h()`` puts the key on the stack beside the signature, the
    script holding its hash alone; both are dissatisfied by the empty
    push where a signature belongs.
    """
    # the 33-byte form for the lookup, whatever the script writes: a
    # signer hands back a signature under either spelling of a taproot key,
    # which is what `_offered_signature` answers for
    sec = node.keys[0].sec(index, network, prv_keys)
    offered = _offered_signature(signatures, sec, x_only=node.context == TAPSCRIPT)
    if offered is not None:
        signature = replace(_element(offered), has_sig=True)
    else:
        signature = _assumed_signature(node) if estimate else _NO_WITNESS
    if node.fragment == "pk_k":
        return _Inputs(signature, _ZERO_PUSH)
    key = _element(sec[1:] if node.context == TAPSCRIPT else sec)
    return _Inputs(_both(signature, key), _both(_ZERO_PUSH, key))


def _multi_input(
    node: Miniscript,
    signatures: Mapping[bytes, bytes],
    index: int,
    network: str,
    prv_keys: PrvKeys | None,
    choose: _Choice,
    *,
    estimate: bool,
) -> _Inputs:
    """Return the stacks of a ``multi()`` or a ``multi_a()``.

    `reached[j]` is the best stack carrying j signatures of the keys read
    so far, which is the only way to choose: any k of the n keys satisfy,
    and which k are available is not known until they have been asked
    for. The two differ in what an unused key costs -- nothing to
    OP_CHECKMULTISIG, which pops only the signatures it is given, and an
    empty push to OP_CHECKSIGADD, which counts them all -- and in the
    order, the first key's signature being on top for one and at the
    bottom for the other.
    """
    multi_a = node.fragment == "multi_a"
    keys = list(reversed(node.keys)) if multi_a else list(node.keys)
    # OP_CHECKMULTISIG pops one element more than it was given, which is
    # the empty push every satisfaction of it starts with
    reached = [_NO_PUSHES if multi_a else _ZERO_PUSH]
    for key in keys:
        sec = key.sec(index, network, prv_keys)
        offered = _offered_signature(signatures, sec, x_only=node.context == TAPSCRIPT)
        if offered is not None:
            signature = replace(_element(offered), has_sig=True)
        else:
            signature = _assumed_signature(node) if estimate else _NO_WITNESS
        unused = _ZERO_PUSH if multi_a else _NO_PUSHES
        following = [_both(reached[0], unused)]
        following.extend(
            choose(_both(reached[j], unused), _both(reached[j - 1], signature))
            for j in range(1, len(reached))
        )
        following.append(_both(reached[-1], signature))
        reached = following
    if multi_a:
        # one element per key, so dissatisfying is satisfying none of them
        return _Inputs(reached[node.threshold], reached[0])
    # and k+1 empty pushes dissatisfy a multi(), the threshold being how
    # many signatures OP_CHECKMULTISIG will look for
    dissatisfaction = _ZERO_PUSH
    for _ in range(node.threshold):
        dissatisfaction = _both(dissatisfaction, _ZERO_PUSH)
    return _Inputs(reached[node.threshold], dissatisfaction)


def _leaf_input(
    node: Miniscript,
    spend: SpendContext,
    signatures: Mapping[bytes, bytes],
    index: int,
    network: str,
    prv_keys: PrvKeys | None,
    choose: _Choice,
    *,
    estimate: bool,
) -> _Inputs:
    """Return the stacks of a fragment with no subexpressions.

    Estimating, the three things a caller may not have are assumed: a
    signature, a preimage, and a transaction whose lock times meet the
    fragment. That is what makes the answer an upper bound over the
    branches rather than the spend of one of them.
    """
    fragment = node.fragment
    if fragment == "0":
        inputs = _Inputs(_NO_WITNESS, _NO_PUSHES)
    elif fragment == "1":
        inputs = _Inputs(_NO_PUSHES, _NO_WITNESS)
    elif fragment in {"pk_k", "pk_h"}:
        inputs = _key_input(
            node, signatures, index, network, prv_keys, estimate=estimate
        )
    elif fragment in {"older", "after"}:
        met = (
            spend._older(node.threshold)
            if fragment == "older"
            else spend._after(node.threshold)
        )
        # a lock time is met by the transaction or it is not: nothing goes
        # on the stack either way, and nothing dissatisfies one.
        # Estimating, it is taken as met *and* as unknown -- the branch may
        # be the one taken, and a caller is owed the larger of the two
        satisfaction = _NO_PUSHES if estimate or met else _NO_WITNESS
        inputs = _Inputs(satisfaction, _NO_WITNESS)
    elif fragment in _HASH_OP_CODES:
        preimage = spend._preimage(fragment, node.data)
        if preimage is not None:
            satisfaction = _element(preimage)
        elif estimate:
            # BIP379 allows a preimage of 32 bytes and no other size, so
            # its size is known without the preimage
            satisfaction = _element(bytes(32))
        else:
            satisfaction = _NO_WITNESS
        inputs = _Inputs(satisfaction, _ZERO32_PUSH)
    else:
        inputs = _multi_input(
            node, signatures, index, network, prv_keys, choose, estimate=estimate
        )
    return inputs


def _wrapper_input(node: Miniscript, x: _Inputs) -> _Inputs:
    """Return the stacks of a wrapped expression, from its argument's."""
    fragment = node.fragment
    if fragment in {"a:", "s:", "c:", "n:"}:
        return x
    if fragment == "d:":
        # the element the OP_IF reads is part of the witness
        return _Inputs(_both(x.sat, _ONE_PUSH), _ZERO_PUSH)
    if fragment == "v:":
        return _Inputs(x.sat, _NO_WITNESS)
    # ``j:`` is dissatisfied by the empty push its OP_SIZE reads; where the
    # argument can also be dissatisfied without a signature, a third party
    # has two ways to dissatisfy this and the choice is malleable
    dissatisfiable = x.dsat.stack is not None and not x.dsat.has_sig
    return _Inputs(x.sat, replace(_ZERO_PUSH, malleable=dissatisfiable))


def _and_input(node: Miniscript, x: _Inputs, y: _Inputs, choose: _Choice) -> _Inputs:
    """Return the stacks of and_v() or and_b().

    The arguments are written left to right and consume the stack from the
    top, so what satisfies the second is under what satisfies the first.
    """
    if node.fragment == "and_v":
        # dissatisfying a "V" is impossible, so this stack is listed for
        # completeness and never chosen
        return _Inputs(
            _both(y.sat, x.sat), replace(_both(y.dsat, x.sat), non_canonical=True)
        )
    overcomplete = choose(
        replace(_both(y.sat, x.dsat), malleable=True, non_canonical=True),
        replace(_both(y.dsat, x.sat), malleable=True, non_canonical=True),
    )
    return _Inputs(_both(y.sat, x.sat), choose(_both(y.dsat, x.dsat), overcomplete))


def _or_input(node: Miniscript, x: _Inputs, z: _Inputs, choose: _Choice) -> _Inputs:
    """Return the stacks of one of the four disjunctions."""
    fragment = node.fragment
    if fragment == "or_b":
        # satisfying both branches is overcomplete: either half can be
        # turned back into a dissatisfaction and the OP_BOOLOR still holds
        both = replace(_both(z.sat, x.sat), malleable=True, non_canonical=True)
        satisfaction = choose(choose(_both(z.dsat, x.sat), _both(z.sat, x.dsat)), both)
        return _Inputs(satisfaction, _both(z.dsat, x.dsat))
    satisfaction = choose(x.sat, _both(z.sat, x.dsat))
    if fragment == "or_c":
        return _Inputs(satisfaction, _NO_WITNESS)
    if fragment == "or_d":
        return _Inputs(satisfaction, _both(z.dsat, x.dsat))
    # or_i() carries the branch selector in the witness, which is what its
    # OP_IF reads: OP_1 for the first branch and the empty push for the
    # second
    return _Inputs(
        choose(_both(x.sat, _ONE_PUSH), _both(z.sat, _ZERO_PUSH)),
        choose(_both(x.dsat, _ONE_PUSH), _both(z.dsat, _ZERO_PUSH)),
    )


def _andor_input(x: _Inputs, y: _Inputs, z: _Inputs, choose: _Choice) -> _Inputs:
    """Return the stacks of andor(X,Y,Z): X and Y, or else Z."""
    return _Inputs(
        choose(_both(y.sat, x.sat), _both(z.sat, x.dsat)),
        choose(
            replace(_both(y.dsat, x.sat), non_canonical=True),
            _both(z.dsat, x.dsat),
        ),
    )


def _thresh_input(node: Miniscript, subs: list[_Inputs], choose: _Choice) -> _Inputs:
    """Return the stacks of a thresh(), over every way to reach its threshold.

    `reached[j]` is the best stack satisfying j of the branches read so
    far, read from the last one: the branches are written left to right
    and the last one's stack is at the bottom of the witness. Every count
    but the threshold dissatisfies, and every count but zero does it with
    more satisfactions than the OP_EQUAL wants -- overcomplete, so
    malleable and non-canonical, and never chosen while the all-zero
    dissatisfaction exists.
    """
    reached = [_NO_PUSHES]
    for sub in reversed(subs):
        following = [_both(reached[0], sub.dsat)]
        following.extend(
            choose(_both(reached[j], sub.dsat), _both(reached[j - 1], sub.sat))
            for j in range(1, len(reached))
        )
        following.append(_both(reached[-1], sub.sat))
        reached = following
    dissatisfaction = _NO_WITNESS
    for count, reaching in enumerate(reached):
        if count == node.threshold:
            continue
        # every count but zero satisfies more branches than the OP_EQUAL
        # asks for: overcomplete, so malleable, and never chosen while the
        # all-dissatisfied stack exists
        stack = (
            replace(reaching, malleable=True, non_canonical=True) if count else reaching
        )
        dissatisfaction = choose(dissatisfaction, stack)
    return _Inputs(reached[node.threshold], dissatisfaction)


def _computed_input(
    node: Miniscript,
    subs: list[_Inputs],
    spend: SpendContext,
    signatures: Mapping[bytes, bytes],
    index: int,
    network: str,
    prv_keys: PrvKeys | None,
    *,
    estimate: bool,
) -> _Inputs:
    """Return the best stacks of one fragment, from its subexpressions'."""
    choose = _larger if estimate else _better
    if not subs:
        return _leaf_input(
            node, spend, signatures, index, network, prv_keys, choose, estimate=estimate
        )
    if node.fragment in _WRAPPERS:
        return _wrapper_input(node, subs[0])
    if node.fragment in {"and_v", "and_b"}:
        return _and_input(node, subs[0], subs[1], choose)
    if node.fragment == "andor":
        return _andor_input(subs[0], subs[1], subs[2], choose)
    if node.fragment == "thresh":
        return _thresh_input(node, subs, choose)
    return _or_input(node, subs[0], subs[1], choose)
