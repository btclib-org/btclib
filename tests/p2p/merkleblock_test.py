# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `btclib.p2p.merkleblock`.

The tree's own hazard -- a malformed `CPartialMerkleTree` -- is
`tests/block/partial_merkle_tree_test.py`'s, driven directly against
`PartialMerkleTree` rather than through this wrapper: what this file
checks is what a `MerkleBlock` adds over its two fields, which is the
wire framing, the command, and that the two are validated independently
of each other, not the walk.
"""

from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

from btclib.block import Block, BlockHeader, PartialMerkleTree
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.p2p import MerkleBlock

_MAINNET = bytes.fromhex("f9beb4d9")


def _load(fname: str) -> Block:
    """Return a vendored block, parsed from tests/block/_data."""
    filename = Path(__file__).parents[1] / "block" / "_data" / fname
    with filename.open("rb") as file_:
        return Block.parse(file_.read())


def _tree_of(block: Block, *matched_indexes: int) -> PartialMerkleTree:
    txids = [tx.id for tx in block.transactions]
    matches = [index in matched_indexes for index in range(len(txids))]
    return PartialMerkleTree.from_txids(txids, matches)


def test_a_merkleblock_carries_the_command_bitcoin_core_spells() -> None:
    """The wire name, matched by the census test's regex."""
    assert MerkleBlock.command == "merkleblock"


def test_round_trips_a_real_block_s_header_and_tree() -> None:
    """The octets a message writes are the octets it reads back."""
    block = _load("block_200000.bin")
    tree = _tree_of(block, 0, 1, 387)
    merkle_block = MerkleBlock(block.header, tree)

    serialized = merkle_block.serialize()
    parsed = MerkleBlock.parse(serialized)

    assert parsed == merkle_block
    assert parsed.header == block.header
    assert parsed.tree == tree
    assert parsed.serialize() == serialized


def test_the_tree_it_carries_proves_the_header_s_root() -> None:
    """The property this format exists for, checked at the message level."""
    block = _load("block_481824_complete.bin")
    tree = _tree_of(block, 0, 5, 1865)
    merkle_block = MerkleBlock(block.header, tree)

    root = merkle_block.tree.merkle_root
    matches = merkle_block.tree.matches
    assert root == merkle_block.header.merkle_root
    assert matches == (
        (0, block.transactions[0].id),
        (5, block.transactions[5].id),
        (1865, block.transactions[1865].id),
    )


def test_to_message_writes_the_command_and_the_payload() -> None:
    """`to_message` frames the payload under the class's own command."""
    block = _load("block_1.bin")
    tree = _tree_of(block, 0)
    merkle_block = MerkleBlock(block.header, tree)

    message = merkle_block.to_message(_MAINNET)

    assert message.command == "merkleblock"
    assert message.magic == _MAINNET
    assert message.payload == merkle_block.serialize()
    assert MerkleBlock.parse(message.payload) == merkle_block


def test_the_header_and_the_tree_are_not_cross_checked() -> None:
    """A header for one block beside a tree built for another still parses.

    The module docstring is where this is argued: `assert_valid` asks
    that each field is independently valid and asks nothing of the pair
    together, which is what a caller comparing the recomputed root
    against `header.merkle_root` is for.
    """
    wrong_header = _load("block_1.bin").header
    other_block = _load("block_200000.bin")
    tree = _tree_of(other_block, 0)

    merkle_block = MerkleBlock(wrong_header, tree)
    root = merkle_block.tree.merkle_root
    assert root != merkle_block.header.merkle_root


def test_a_wrong_header_type_is_refused() -> None:
    """A `header` that is no `BlockHeader` is named, not stored."""
    block = _load("block_1.bin")
    tree = _tree_of(block, 0)
    with pytest.raises(BTClibTypeError, match="invalid header type"):
        MerkleBlock(b"not a header", tree)  # type: ignore[arg-type]


def test_a_wrong_tree_type_is_refused() -> None:
    """A `tree` that is no `PartialMerkleTree` is named, not stored."""
    block = _load("block_1.bin")
    with pytest.raises(BTClibTypeError, match="invalid tree type"):
        MerkleBlock(block.header, b"not a tree")  # type: ignore[arg-type]


def test_trailing_octets_are_refused() -> None:
    """A `merkleblock` payload is one whole object, as every payload is."""
    block = _load("block_1.bin")
    tree = _tree_of(block, 0)
    serialized = MerkleBlock(block.header, tree).serialize()

    with pytest.raises(BTClibValueError, match="bytes after the merkleblock"):
        MerkleBlock.parse(serialized + b"\x00")


def test_check_validity_reaches_both_fields_and_can_be_turned_off() -> None:
    """`check_validity=False` reaches both fields, and stays off on parse."""
    block = _load("block_1.bin")
    tree = _tree_of(block, 0)
    # version=0 is refused (must be > 0) without changing the header's
    # width, which is what lets the unchecked round trip below still hold
    bad_header = BlockHeader(
        0,
        block.header.previous_block_hash,
        block.header.merkle_root,
        block.header.time,
        block.header.bits,
        block.header.nonce,
        check_validity=False,
    )

    with pytest.raises(BTClibValueError, match="invalid version"):
        MerkleBlock(bad_header, tree, check_validity=True)

    # unchecked construction takes the fields as given, and still
    # round-trips: serialize/parse do not silently re-validate for it
    unchecked = MerkleBlock(bad_header, tree, check_validity=False)
    assert (
        MerkleBlock.parse(
            unchecked.serialize(check_validity=False), check_validity=False
        )
        == unchecked
    )


def test_the_message_is_frozen_and_not_hashable() -> None:
    """`dataclasses.replace` is what changes a vector, then."""
    block = _load("block_1.bin")
    tree = _tree_of(block, 0)
    merkle_block = MerkleBlock(block.header, tree)

    with pytest.raises(FrozenInstanceError):
        merkle_block.tree = tree  # type: ignore[misc]
    assert replace(merkle_block, tree=tree) == merkle_block

    # the tree is hashable, its own fields being immutable; the message
    # is not, `BlockHeader` being a mutable dataclass
    assert len({tree, _tree_of(block, 0)}) == 1
    with pytest.raises(TypeError, match="unhashable"):
        hash(merkle_block)
