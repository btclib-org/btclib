# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests that a frozen dataclass's hashability sentence matches `hash()`.

A frozen dataclass here states whether a value of it is hashable, in a sentence
of one of two fixed shapes: "Frozen and hashable, ..." against "Frozen, and not
hashable: ...". Nothing re-derived that sentence before this file, so it could
disagree with the class and still pass a green suite at a 100% coverage floor
(issue #1692).

The claim is not decidable by reading the class alone. `@dataclass(
frozen=True)` gives every one of them a `__hash__`, so what raises is `hash()`
on a *value* whose field holds an object of a plain, non-frozen dataclass:
`eq=True` there sets that object's own `__hash__` to `None`, and a value
holding it cannot be hashed however frozen the outer class itself is.

The walk below covers only a frozen dataclass whose own docstring makes the
claim. `_HASHABLE_CLAIM` and `_NOT_HASHABLE_CLAIM` are the two shapes pinned
rather than parsed, and a docstring that mentions "hashable" without landing on
either is what `test_every_hashability_claim_is_pinned_and_covered` fails on by
name -- a drift from the two shapes, not a class that says nothing. A docstring
silent about hashability altogether is not asked at all: a class added later
with no sentence is covered by nothing here, the same blind spot issue #1692
opened one level up. Requiring the sentence of every frozen dataclass in the
tree, rather than of the ones that already carry it, is a wider change than
this file makes.

`_INSTANCES` is the table `test_every_hashability_claim_is_pinned_and_covered`
holds the live walk to, in the shape `tests/keyword_only_test.py` and
`tests/parse_contract_test.py` already use for the same problem: a dictionary
frozen at authoring time, checked against what the tree answers now. Each value
is built with the field its own docstring names populated -- a
`PrefilledTransaction`'s `Tx`, a `Headers`'s `BlockHeader` -- because an empty
tuple in that field would hash without error and prove nothing about the claim
it is supposed to exercise.
"""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Callable
from importlib import import_module
from pathlib import Path
from typing import Any

import pytest

from btclib.block import Block, BlockHeader, PartialMerkleTree
from btclib.consensus import CONSENSUS_PARAMS, ConsensusParams
from btclib.p2p import (
    BlockPayload,
    BlockTxn,
    CFCheckpt,
    CFHeaders,
    CFilter,
    CmpctBlock,
    Feature,
    FeeFilter,
    GetBlockTxn,
    GetCFCheckpt,
    Headers,
    Inventory,
    MerkleBlock,
    NetworkAddress,
    NetworkAddressV2,
    PartialBlock,
    PrefilledTransaction,
    Reject,
    SendCmpct,
    SendTxRcncl,
    TxPayload,
)
from btclib.script import ScriptPubKey
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from tests import module_names

_TX_ID = "01" * 32


def _block_1() -> bytes:
    """Return the consensus bytes of the block after genesis."""
    filename = Path(__file__).parent / "block" / "_data" / "block_1.bin"
    with filename.open("rb") as file_:
        return file_.read()


def _header() -> BlockHeader:
    """Return the header of the block after genesis."""
    return BlockHeader.parse(_block_1()[:80])


def _tx() -> Tx:
    """Return one signed-looking transaction, good enough to hold a field."""
    return Tx(
        1, 0x12345678, [TxIn(OutPoint(_TX_ID, 0), b"", 0xFFFFFFFF)], [TxOut(1, b"")]
    )


# the two shapes issue #1692 names, pinned literally rather than parsed:
# a docstring that says "hashable" some other way is a drift this file
# surfaces by name instead of reading as a claim of neither kind
_HASHABLE_CLAIM = re.compile(r"Frozen and hashable\b")
_NOT_HASHABLE_CLAIM = re.compile(r"Frozen, and not hashable\b")
_MENTIONS_HASHABILITY = re.compile(r"\bhashable\b", re.IGNORECASE)


def _frozen_dataclasses() -> dict[str, type]:
    """Return every public frozen dataclass reachable from a public module.

    Keyed by `module.qualname`, deduplicated the way `public_classes_with`
    dedupes a method: a class re-exported under a second `__all__` --
    `btclib.p2p.compact_blocks.PrefilledTransaction` under `btclib.p2p`'s
    own -- is one entry, not two.
    """
    found: dict[str, type] = {}
    for module_name in module_names():
        module = import_module(module_name)
        for obj in vars(module).values():
            if not isinstance(obj, type):
                continue
            if not getattr(obj, "__module__", "").startswith("btclib"):
                continue
            if obj.__qualname__.startswith("_"):
                continue
            if not dataclasses.is_dataclass(obj):
                continue
            # typeshed's DataclassInstance protocol has no
            # __dataclass_params__ of its own, this attribute being what
            # dataclasses.dataclass actually sets
            params = obj.__dataclass_params__  # type: ignore[attr-defined]
            if not params.frozen:
                continue
            found[f"{obj.__module__}.{obj.__qualname__}"] = obj
    return found


def _claim(cls: type) -> str | None:
    """Return what one class's own docstring claims about its hashability.

    `"hashable"` or `"not hashable"` for the two pinned shapes, `"drift"`
    for a docstring that mentions hashability without landing on either
    -- both matching, or neither matching where the word is present --
    and `None` for a docstring silent about it altogether.
    """
    doc = cls.__doc__ or ""
    hashable = bool(_HASHABLE_CLAIM.search(doc))
    not_hashable = bool(_NOT_HASHABLE_CLAIM.search(doc))
    if hashable and not not_hashable:
        return "hashable"
    if not_hashable and not hashable:
        return "not hashable"
    if _MENTIONS_HASHABILITY.search(doc):
        return "drift"
    return None


def test_claim_reads_the_two_shapes_and_flags_the_rest() -> None:
    """`_claim` on four built docstrings, one per outcome it can return.

    The tree's own classes may carry no drifted sentence at a given
    moment -- issue #1692's own census found none -- which would leave
    the walk elsewhere in this file untested on that outcome. Built here
    instead, independently of what the tree currently states.
    """

    class _Hashable:
        """Frozen and hashable, for the sake of this fixture."""

    class _NotHashable:
        """Frozen, and not hashable: for the sake of this fixture."""

    class _Drifted:
        """Frozen, and the one class here that is not hashable."""

    class _Silent:
        """Nothing here about hashability at all."""

    assert _claim(_Hashable) == "hashable"
    assert _claim(_NotHashable) == "not hashable"
    assert _claim(_Drifted) == "drift"
    assert _claim(_Silent) is None


# every frozen dataclass whose docstring makes the claim, and a value
# built to exercise it: (class, a callable returning one instance).
# Walked from `btclib`, on the commit this file is part of -- see this
# file's own docstring for why a class saying nothing is not here
_INSTANCES: dict[str, tuple[type, Callable[[], Any]]] = {
    "btclib.block.partial_merkle_tree.PartialMerkleTree": (
        PartialMerkleTree,
        lambda: PartialMerkleTree.from_txids([_tx().id], [True]),
    ),
    "btclib.consensus.ConsensusParams": (
        ConsensusParams,
        lambda: CONSENSUS_PARAMS["mainnet"],
    ),
    "btclib.p2p.address.NetworkAddress": (
        NetworkAddress,
        lambda: NetworkAddress(1, "10.0.0.1", 8333),
    ),
    "btclib.p2p.addrv2.NetworkAddressV2": (NetworkAddressV2, NetworkAddressV2),
    "btclib.p2p.block_filters.CFilter": (CFilter, CFilter),
    "btclib.p2p.block_filters.CFHeaders": (CFHeaders, CFHeaders),
    "btclib.p2p.block_filters.GetCFCheckpt": (GetCFCheckpt, GetCFCheckpt),
    "btclib.p2p.block_filters.CFCheckpt": (CFCheckpt, CFCheckpt),
    "btclib.p2p.compact_blocks.SendCmpct": (SendCmpct, SendCmpct),
    "btclib.p2p.compact_blocks.PrefilledTransaction": (
        PrefilledTransaction,
        lambda: PrefilledTransaction(0, _tx()),
    ),
    "btclib.p2p.compact_blocks.CmpctBlock": (
        CmpctBlock,
        lambda: CmpctBlock(_header(), prefilled_txns=[PrefilledTransaction(0, _tx())]),
    ),
    "btclib.p2p.compact_blocks.GetBlockTxn": (GetBlockTxn, GetBlockTxn),
    "btclib.p2p.compact_blocks.BlockTxn": (
        BlockTxn,
        lambda: BlockTxn(transactions=[_tx()]),
    ),
    "btclib.p2p.compact_blocks.PartialBlock": (
        PartialBlock,
        lambda: PartialBlock(_header(), [_tx()]),
    ),
    "btclib.p2p.data.TxPayload": (TxPayload, lambda: TxPayload(_tx(), True)),
    "btclib.p2p.data.BlockPayload": (
        BlockPayload,
        lambda: BlockPayload(Block.parse(_block_1()), True),
    ),
    "btclib.p2p.inventory.Inventory": (Inventory, Inventory),
    "btclib.p2p.inventory.Headers": (Headers, lambda: Headers([_header()])),
    "btclib.p2p.merkleblock.MerkleBlock": (
        MerkleBlock,
        lambda: MerkleBlock(
            _header(), PartialMerkleTree.from_txids([_tx().id], [True])
        ),
    ),
    "btclib.p2p.negotiation.FeeFilter": (FeeFilter, lambda: FeeFilter(1000)),
    "btclib.p2p.negotiation.SendTxRcncl": (SendTxRcncl, lambda: SendTxRcncl(1, 2)),
    "btclib.p2p.negotiation.Feature": (Feature, lambda: Feature(b"BIP434")),
    "btclib.p2p.reject.Reject": (Reject, Reject),
    "btclib.script.script_pub_key.ScriptPubKey": (
        ScriptPubKey,
        lambda: ScriptPubKey("51"),
    ),
    "btclib.tx.out_point.OutPoint": (OutPoint, lambda: OutPoint(_TX_ID, 0)),
}


def test_every_hashability_claim_is_pinned_and_covered() -> None:
    """Nothing claims hashability outside the two shapes, and nothing is missed.

    The half `test_a_frozen_dataclass_is_as_hashable_as_its_docstring_says`
    cannot ask: that test parametrizes over `_INSTANCES` itself, so a new
    claim added to the tree without a line here would run no test at all.
    This walks every public frozen dataclass, asks what each one's own
    docstring claims, and fails by name on a claim that matches neither
    pinned shape -- rather than reading it as silence -- before checking
    that the classes actually claiming something are exactly the ones
    `_INSTANCES` holds a value for.
    """
    claims = {name: _claim(cls) for name, cls in _frozen_dataclasses().items()}

    drifted = sorted(name for name, claim in claims.items() if claim == "drift")
    assert not drifted, f"hashability sentence matches neither shape: {drifted}"

    claimed = {name for name, claim in claims.items() if claim is not None}
    assert claimed == set(_INSTANCES)


@pytest.mark.parametrize("qualname", sorted(_INSTANCES))
def test_a_frozen_dataclass_is_as_hashable_as_its_docstring_says(
    qualname: str,
) -> None:
    """`hash()` on a built value agrees with what the class's docstring says.

    The docstring is read live, not from a frozen expectation, so a
    class whose sentence and behaviour drift apart -- either changing
    without the other -- fails here whichever one moved.
    """
    cls, build = _INSTANCES[qualname]
    value = build()
    if _claim(cls) == "not hashable":
        with pytest.raises(TypeError):
            hash(value)
    else:
        hash(value)
