# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.block.partial_merkle_tree` module.

The valid vectors are built with `PartialMerkleTree.from_txids` over the
`_data/block_*.bin` blocks `tests/block/merkle_proof_test.py` already
uses, and checked against the recomputed root and the real header's
`merkle_root` -- consensus data this library did not compute -- rather
than recorded by hand. The refusals are each Core's own, transliterated
from `src/merkleblock.cpp`'s `ExtractMatches`/`TraverseAndExtract`, and
each is asserted on its own message rather than merely on the exception
class.
"""

from pathlib import Path

import pytest

from btclib.block import Block, PartialMerkleTree
from btclib.exceptions import BTClibTypeError, BTClibValueError


def _load(fname: str) -> Block:
    """Return a vendored block, parsed from tests/block/_data."""
    filename = Path(__file__).parent / "_data" / fname
    with filename.open("rb") as file_:
        return Block.parse(file_.read())


@pytest.mark.parametrize(
    "fname, matched_indexes",
    [
        ("block_1.bin", [0]),
        ("block_170.bin", [0]),
        ("block_170.bin", [0, 1]),
        ("block_200000.bin", [0]),
        ("block_200000.bin", [0, 1, 2, 387]),
        ("block_481824_complete.bin", [0]),
        ("block_481824_complete.bin", [0, 5, 932, 933, 1865]),
    ],
)
def test_a_built_tree_recomputes_the_header_s_root(
    fname: str, matched_indexes: list[int]
) -> None:
    """A tree built over every txid proves the ones it was told to keep."""
    block = _load(fname)
    txids = [tx.id for tx in block.transactions]
    matches = [index in matched_indexes for index in range(len(txids))]

    tree = PartialMerkleTree.from_txids(txids, matches)
    root = tree.merkle_root
    found = tree.matches

    assert root == block.header.merkle_root
    assert found == tuple((index, txids[index]) for index in matched_indexes)


def test_no_match_still_proves_the_root() -> None:
    """A tree with nothing to keep still commits to the header's root.

    `TraverseAndBuild` stops at the very first node when nothing below it
    is a match, which for an all-false vector is the root itself: one
    flag bit, one hash, and no position handed back.
    """
    block = _load("block_200000.bin")
    txids = [tx.id for tx in block.transactions]
    matches = [False] * len(txids)

    tree = PartialMerkleTree.from_txids(txids, matches)
    assert len(tree.hashes) == 1
    root = tree.merkle_root
    found = tree.matches

    assert root == block.header.merkle_root
    assert found == ()


def test_a_single_transaction_block_is_its_own_root() -> None:
    """The coinbase of a one-transaction block needs no internal node."""
    block = _load("block_1.bin")
    txid = block.transactions[0].id
    tree = PartialMerkleTree.from_txids([txid], [True])

    assert tree.n_transactions == 1
    root = tree.merkle_root
    found = tree.matches
    assert root == block.header.merkle_root == txid
    assert found == ((0, txid),)


def test_round_trips_through_serialize_and_parse() -> None:
    """The octets a tree writes are the octets it reads back."""
    block = _load("block_200000.bin")
    txids = [tx.id for tx in block.transactions]
    matches = [index in (0, 1, 100, 387) for index in range(len(txids))]
    tree = PartialMerkleTree.from_txids(txids, matches)

    serialized = tree.serialize()
    parsed = PartialMerkleTree.parse(serialized)

    assert parsed == tree
    assert parsed.serialize() == serialized


def test_a_transaction_count_of_zero_is_refused() -> None:
    """Core's `nTransactions == 0` in `ExtractMatches`."""
    with pytest.raises(BTClibValueError, match="transaction count is zero"):
        PartialMerkleTree(0, [], b"")


def test_a_transaction_count_past_the_block_bound_is_refused() -> None:
    """Core's `nTransactions > MAX_BLOCK_WEIGHT / MIN_TRANSACTION_WEIGHT`."""
    with pytest.raises(BTClibValueError, match="transaction count too high"):
        PartialMerkleTree(10**9, [], b"", check_validity=False).assert_valid()


def test_a_hash_of_the_wrong_width_is_refused() -> None:
    """A hash the wire cannot hold is caught by the walk, not by `bytes()`."""
    tree = PartialMerkleTree(1, [bytes(31)], b"\x01", check_validity=False)
    with pytest.raises(BTClibValueError, match="invalid hash length"):
        _ = tree.merkle_root


def test_more_hashes_than_the_tree_can_hold_is_refused() -> None:
    """Core's `vHash.size() > nTransactions`."""
    with pytest.raises(BTClibValueError, match=r"2 hashes for 1 transactions"):
        PartialMerkleTree(1, [bytes(32), bytes(32)], b"\xff")


def test_fewer_flag_bits_than_hashes_is_refused() -> None:
    """Core's `vBits.size() < vHash.size()`."""
    with pytest.raises(BTClibValueError, match=r"0 flag bits for 2 hashes"):
        PartialMerkleTree(2, [bytes(32), bytes(32)], b"")


def test_a_short_bit_stream_is_refused_mid_walk() -> None:
    """Core's `nBitsUsed >= vBits.size()` inside `TraverseAndExtract`.

    A flag byte count that satisfies the pre-check above -- at least one
    bit per hash -- is not the same as enough bits for the walk itself:
    every visited node, expanded or not, consumes one bit, and a tree
    with many transactions but few real matches needs far more of them
    than it has hashes.
    """
    block = _load("block_481824_complete.bin")
    txids = [tx.id for tx in block.transactions]
    matches = [index == 0 for index in range(len(txids))]
    tree = PartialMerkleTree.from_txids(txids, matches)

    # every bit set forces a full descent at every node instead of the
    # early stop the real flags encode, which exhausts the bit stream
    # long before the walk reaches a leaf
    all_set_flags = bytes([0xFF]) * len(tree.flags)
    forced = PartialMerkleTree(
        tree.n_transactions, tree.hashes, all_set_flags, check_validity=False
    )
    with pytest.raises(BTClibValueError, match="flag bits exhausted"):
        _ = forced.merkle_root


def test_a_short_hash_vector_is_refused_mid_walk() -> None:
    """Core's `nHashUsed >= vHash.size()` inside `TraverseAndExtract`."""
    block = _load("block_200000.bin")
    txids = [tx.id for tx in block.transactions]
    matches = [index in (0, 1) for index in range(len(txids))]
    tree = PartialMerkleTree.from_txids(txids, matches)

    truncated = PartialMerkleTree(
        tree.n_transactions, tree.hashes[:-1], tree.flags, check_validity=False
    )
    with pytest.raises(BTClibValueError, match="hashes exhausted"):
        _ = truncated.merkle_root


def test_duplicate_child_hashes_are_refused() -> None:
    """Core's `TraverseAndExtract` malleability check: `right == left`.

    Two matched leaves that share one hash make the node above them a
    node whose two children are the same hash, which is the shorter list
    of one leaf's own CVE-2012-2459 mutation and is refused the same way
    `merkle_proof.py`'s verifier refuses it one level down.
    """
    txid = bytes(32)
    tree = PartialMerkleTree.from_txids(
        [txid, txid], [True, True], check_validity=False
    )
    with pytest.raises(BTClibValueError, match="same value"):
        _ = tree.merkle_root


def test_unused_hashes_after_the_walk_are_refused() -> None:
    """Core's `nHashUsed != vHash.size()` after `ExtractMatches`' walk.

    The extra hash has to stay under `n_transactions`, or the earlier
    "more hashes than the tree can hold" refusal fires first: a block
    with few real matches and many transactions leaves room for both to
    be tested apart.
    """
    block = _load("block_200000.bin")
    txids = [tx.id for tx in block.transactions]
    matches = [index in (0, 1) for index in range(len(txids))]
    tree = PartialMerkleTree.from_txids(txids, matches)
    assert len(tree.hashes) < len(txids) - 1

    extra = PartialMerkleTree(
        tree.n_transactions,
        [*tree.hashes, bytes(32)],
        tree.flags,
        check_validity=False,
    )
    with pytest.raises(BTClibValueError, match="unused hashes"):
        _ = extra.merkle_root


def test_unused_flag_bits_after_the_walk_are_refused() -> None:
    """Core's `CeilDiv(nBitsUsed, 8) != CeilDiv(vBits.size(), 8)`.

    A whole extra octet, not the zero padding every stream already
    carries up to the octet boundary -- that padding is what a valid
    tree's own `flags` already ends in and must not be refused.
    """
    block = _load("block_1.bin")
    txid = block.transactions[0].id
    tree = PartialMerkleTree.from_txids([txid], [True])

    extra = PartialMerkleTree(
        tree.n_transactions, tree.hashes, tree.flags + b"\x00", check_validity=False
    )
    with pytest.raises(BTClibValueError, match="unused flag bits"):
        _ = extra.merkle_root


def test_n_transactions_type_is_refused() -> None:
    """A bool would read as a transaction count of zero or one."""
    with pytest.raises(BTClibTypeError, match="invalid n_transactions type"):
        PartialMerkleTree(n_transactions=True)


def test_hashes_must_be_a_sequence_and_not_octets() -> None:
    """An `Octets` is a `Sequence` too: zipped, not read as a list of hashes."""
    with pytest.raises(BTClibTypeError, match="invalid hashes type"):
        PartialMerkleTree(1, b"\x00" * 32, b"\x01")  # type: ignore[arg-type]


def test_from_txids_refuses_a_bare_octets_for_either_sequence() -> None:
    """Same shape, on the two sequences `from_txids` takes."""
    with pytest.raises(BTClibTypeError, match="invalid txids type"):
        PartialMerkleTree.from_txids(b"\x00" * 32, [True])  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid matches type"):
        PartialMerkleTree.from_txids([bytes(32)], b"\x01")  # type: ignore[arg-type]


def test_from_txids_refuses_a_matches_count_mismatch() -> None:
    """One bool per txid, or the shape a caller meant is not the one sent."""
    with pytest.raises(BTClibValueError, match="invalid matches count"):
        PartialMerkleTree.from_txids([bytes(32), bytes(32)], [True])


def test_from_txids_refuses_no_transactions() -> None:
    """There is no block, and no tree, with zero transactions."""
    with pytest.raises(BTClibValueError, match="no transactions"):
        PartialMerkleTree.from_txids([], [])


def test_from_txids_refuses_a_non_bool_match_element() -> None:
    """`1` is an int, and is not read for its truth in place of a bool."""
    with pytest.raises(BTClibTypeError, match="invalid matches element type"):
        PartialMerkleTree.from_txids([bytes(32)], [1])  # type: ignore[list-item]
