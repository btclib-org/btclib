# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The gate for a function taking an object the caller already built.

CONTRIBUTING.md's "Every public function validates its inputs" is driven
automatically by `input_validation_test.py`, over the functions whose every
required parameter is a library input type, and by hand in
`bool_contract_test.py`, over the ones that answer a `bool`. Neither
reaches a function whose parameter is a `CmpctBlock`, a `PubKeyData`, a
taproot script tree or a sequence of transactions: no vocabulary of wrong
values builds one, so a fixture has to, and issue #856 is where that
ceiling is written down.

`check_validity=False` is why this family is worth a gate of its own.
CONTRIBUTING.md's "it says *do not check now*, not *this object is exempt
from here on*" makes an invalid object something a caller can legitimately
hold, so a public name accepting one is a name that has to ask -- and the
rules are the same two everywhere else obeys:

- a **wrong type** leaves as a `BTClibTypeError`
- a **wrong value** of a declared type leaves as a `BTClibValueError`,
  these functions answering no `bool` about their argument

The rest of the family -- a `Psbt`, a `PsbtIn`, a sequence of extended
keys -- is `btclib_wallet`'s, and so is its gate.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Any

import pytest

from btclib import b32, b58
from btclib.block import Block
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.key import PrvKeyData, PubKeyData
from btclib.p2p import CmpctBlock, PrefilledTransaction, reconstruct
from btclib.script import (
    ScriptPubKey,
    TaprootScriptTree,
    input_script_sig,
    output_pubkey,
)
from btclib.script.taproot import tree_helper

# the block after genesis, for the one case here whose argument is a p2p
# message: a `CmpctBlock` needs a header that is one, and a header cannot
# be invented -- the proof of work `BlockHeader` is checked against has
# to have been done
_BLOCK_1 = Block.parse(
    (Path(__file__).parent / "block" / "_data" / "block_1.bin").read_bytes()
)
# a compact block of two transactions: the coinbase prefilled, and one
# short id for a transaction a pool may or may not hold
_CMPCTBLOCK = CmpctBlock(
    _BLOCK_1.header, 0, [1], [PrefilledTransaction(0, _BLOCK_1.transactions[0])]
)
# a compact block of no transactions at all, which is a `CmpctBlock` of a
# perfectly good type and a value no block has: there is none without a
# coinbase, and Core's `InitData` refuses it too
_NO_TRANSACTIONS = CmpctBlock(_BLOCK_1.header, 0)

# a compressed public key, and octets of its size under a prefix no SEC key
# has: `check_validity=False` builds the second, which `assert_valid`
# refuses, and hashing it would answer an address nobody can spend from
_PUB_KEY = PrvKeyData(1).pub
_BAD_PREFIX = PubKeyData(b"\x05" + _PUB_KEY.sec[1:], check_validity=False)


# a taproot script tree of one leaf; an empty list is a list, the type a
# tree is, and no tree
_TREE: TaprootScriptTree = [(0xC0, ["OP_1"])]


def _p2ms_1_of_1(key: PubKeyData) -> ScriptPubKey:
    """`ScriptPubKey.p2ms` driven at one of its keys."""
    return ScriptPubKey.p2ms(1, [key])


# a value of no type any of these positions declares, None aside at a
# position whose case declares it
_WRONG_TYPES = (None, 1.5)


@dataclass(frozen=True)
class _Case:
    """A function, a call of it that works, and what to drive."""

    label: str
    function: Any
    args: tuple[Any, ...]
    # position -> a wrong value of the type that position declares
    wrong_values: dict[int, Any]
    # the positions where None is declared: an internal key or a tree
    # that is absent, and not a wrong type
    none_declared: frozenset[int] = frozenset()


_CASES = (
    _Case(
        "p2p.compact_blocks.reconstruct",
        reconstruct,
        (_CMPCTBLOCK, [_BLOCK_1.transactions[0]]),
        # the pool has no wrong value: every transaction is one a mempool
        # may hold, and a pool that answers no short id is the ordinary
        # case rather than a refusal
        {0: _NO_TRANSACTIONS},
    ),
    *(
        _Case(label, function, (_PUB_KEY,), {0: _BAD_PREFIX})
        for label, function in (
            ("b58.p2pkh", b58.p2pkh),
            ("b58.p2wpkh_p2sh", b58.p2wpkh_p2sh),
            ("b32.p2wpkh", b32.p2wpkh),
            ("script.ScriptPubKey.p2pk", ScriptPubKey.p2pk),
            ("script.ScriptPubKey.p2pkh", ScriptPubKey.p2pkh),
            ("script.ScriptPubKey.p2wpkh", ScriptPubKey.p2wpkh),
            ("script.ScriptPubKey.p2ms at a key", _p2ms_1_of_1),
        )
    ),
    _Case(
        "script.ScriptPubKey.p2ms",
        ScriptPubKey.p2ms,
        (1, [_PUB_KEY], True),
        # a threshold above the key count, and a sequence of no keys
        {0: 2, 1: []},
    ),
    _Case("script.taproot.tree_helper", tree_helper, (_TREE,), {0: []}),
    _Case(
        "script.taproot.output_pubkey",
        output_pubkey,
        (_PUB_KEY, _TREE),
        {0: _BAD_PREFIX, 1: []},
        frozenset({0, 1}),
    ),
    _Case(
        "script.taproot.input_script_sig",
        input_script_sig,
        (_PUB_KEY, _TREE, 0),
        # a leaf index past the tree's one leaf
        {0: _BAD_PREFIX, 1: [], 2: 1},
        frozenset({0}),
    ),
    _Case(
        "script.ScriptPubKey.p2tr",
        ScriptPubKey.p2tr,
        (_PUB_KEY, _TREE, "mainnet"),
        {0: _BAD_PREFIX, 1: [], 2: "no such network"},
        frozenset({0, 1}),
    ),
)

_IDS = tuple(case.label for case in _CASES)


def _driven(case: _Case, position: int, wrong: Any) -> Callable[[], Any]:
    """Return the call with one position replaced, the others left valid."""
    args = list(case.args)
    args[position] = wrong
    return partial(case.function, *args)


@pytest.mark.parametrize("case", _CASES, ids=_IDS)
def test_the_call_works(case: _Case) -> None:
    """The fixture is valid, which is what makes a refusal below a finding.

    Without this a case whose arguments had gone stale would pass every
    test in the file by refusing everything it is handed.
    """
    case.function(*case.args)


@pytest.mark.parametrize("case", _CASES, ids=_IDS)
def test_a_wrong_type_leaves_as_a_btclib_type_error(case: _Case) -> None:
    """The first rule, one position at a time, the others left valid."""
    for position in range(len(case.args)):
        for wrong in _WRONG_TYPES:
            if wrong is None and position in case.none_declared:
                continue
            with pytest.raises(BTClibTypeError):
                _driven(case, position, wrong)()


@pytest.mark.parametrize("case", _CASES, ids=_IDS)
def test_a_wrong_value_leaves_as_a_btclib_value_error(case: _Case) -> None:
    """The second rule: a value of a declared type is refused as a value.

    `BTClibValueError` and not `BTClibException`, which would be the
    contract read literally: a type error is one of those too, so the
    wider class would let the first rule's failures through as the
    second's answer.
    """
    for position, wrong in sorted(case.wrong_values.items()):
        with pytest.raises(BTClibValueError):
            _driven(case, position, wrong)()
