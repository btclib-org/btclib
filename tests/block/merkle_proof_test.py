# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.block.merkle_proof` module.

The vectors are the `_data/block_*.bin` blocks the rest of tests/block
uses: a branch is built here from the transaction list, and what it is
checked against is the merkle_root of the real header, which is
consensus data and not something this library computed. Core's
gettxoutproof produces the same branches, and its verifytxoutproof is
the authority on the answer, but neither is needed to have the vectors:
the block carries the transactions and the root that commits to them.
"""

from pathlib import Path
from typing import Any, cast

import pytest

from btclib.block import Block, merkle_proof
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import hash256, merkle_root_from_branch
from btclib.tx import OutPoint, Tx, TxIn, TxOut


def _load(fname: str) -> Block:
    """Return a vendored block, parsed from tests/block/_data."""
    filename = Path(__file__).parent / "_data" / fname
    with filename.open("rb") as file_:
        return Block.parse(file_.read())


def _branch(hashes: list[bytes], index: int) -> list[bytes]:
    """Return the siblings met climbing to the root, bottom-up.

    The builder's side, written out here rather than imported so that
    the verifier is checked against something other than itself. An odd
    level is padded with a copy of its last hash before the sibling is
    read, which is what makes the last leaf its own sibling.
    """
    branch = []
    level = list(hashes)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        branch.append(level[index ^ 1])
        level = [hash256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
        index //= 2
    return branch


@pytest.mark.parametrize("fname", ["block_1.bin", "block_170.bin", "block_200000.bin"])
def test_every_transaction_of_a_real_block_is_proved(fname: str) -> None:
    """Every txid, with its branch, recomputes the header's merkle root."""
    block = _load(fname)
    txids = [tx.id for tx in block.transactions]
    hashes = [txid[::-1] for txid in txids]  # internal byte order
    root = block.header.merkle_root

    for index, txid in enumerate(txids):
        branch = [sibling[::-1] for sibling in _branch(hashes, index)]
        merkle_proof.assert_as_valid(txid, branch, index, root)
        assert merkle_proof.verify(txid, branch, index, root)
        # the same branch proves nothing about any other position
        if len(txids) > 1:
            assert not merkle_proof.verify(txid, branch, index ^ 1, root)


def test_a_segwit_block_is_proved_over_txids_not_wtxids() -> None:
    """The header's tree is the txid one, witnesses left out by design.

    Block 481824 is the first segwit block and every one of its 1866
    transactions carries a `hash` that differs from its `id`; the branch
    that proves one against the header is built from `id`. Sampled
    rather than exhaustive -- a proof per transaction here costs more
    than the rest of this file put together, and the positions below
    already cover both parities and both ends.
    """
    block = _load("block_481824_complete.bin")
    txids = [tx.id for tx in block.transactions]
    hashes = [txid[::-1] for txid in txids]
    root = block.header.merkle_root
    assert len(txids) == 1866
    assert any(tx.hash != tx.id for tx in block.transactions)

    witness_bearing = 0
    for index in (0, 1, 2, 3, 932, 933, len(txids) - 2, len(txids) - 1):
        transaction = block.transactions[index]
        branch = [sibling[::-1] for sibling in _branch(hashes, index)]
        merkle_proof.assert_as_valid(txids[index], branch, index, root)
        # where the two differ, it is the txid the header commits to: a
        # transaction with no witness has one hash and proves either way
        if transaction.hash != transaction.id:
            witness_bearing += 1
            assert not merkle_proof.verify(transaction.hash, branch, index, root)
    assert witness_bearing


def test_a_single_transaction_block_needs_no_branch() -> None:
    """The coinbase of a one-transaction block *is* the root."""
    block = _load("block_1.bin")
    txid = block.transactions[0].id
    assert txid == block.header.merkle_root
    merkle_proof.assert_as_valid(txid, [], 0, block.header.merkle_root)
    # and an index that no branch places is refused rather than ignored
    with pytest.raises(BTClibValueError, match="leaf index too high"):
        merkle_proof.assert_as_valid(txid, [], 1, block.header.merkle_root)


def test_the_odd_level_padding_is_not_a_mutation() -> None:
    """A leaf that is its own sibling is Bitcoin's padding, not CVE-2012-2459.

    Refusing every equal pair would refuse almost every block: an odd
    level is padded by hashing its last node with itself. The node is a
    *left* child there, which is what tells the padding apart from the
    duplicated subtree the verifier does refuse.
    """
    block = _load("block_200000.bin")
    hashes = [tx.id[::-1] for tx in block.transactions]
    # 388 leaves, so the padding is not at the bottom: the levels are
    # 388, 194, 97, 49, 25, 13, 7, 4, 2, 1, and five of them are odd
    assert len(hashes) == 388

    last = len(hashes) - 1
    branch = _branch(hashes, last)

    # walk the last leaf up and find the padded levels: the running hash
    # is its own sibling there, and it is a left child every time, which
    # is exactly what tells the padding from the mutation
    running, index, padded = hashes[last], last, 0
    for sibling in branch:
        if sibling == running:
            assert not index % 2, "padding duplicates a left child"
            padded += 1
        running = hash256(running + sibling if index % 2 == 0 else sibling + running)
        index //= 2
    assert padded == 5

    merkle_proof.assert_as_valid(
        block.transactions[last].id,
        [sibling[::-1] for sibling in branch],
        last,
        block.header.merkle_root,
    )


def test_cve_2012_2459_a_duplicated_sibling_is_refused() -> None:
    """A right child equal to its sibling proves a root of a shorter list."""
    leaf = hash256(b"btclib")
    root = hash256(leaf + leaf)

    # as a left child this is the padding above, and it is accepted
    assert merkle_root_from_branch(leaf, [leaf], 0, hash256) == root

    # as a right child it is the mutation, and it is not
    with pytest.raises(BTClibValueError, match="mutated merkle branch"):
        merkle_root_from_branch(leaf, [leaf], 1, hash256)

    with pytest.raises(BTClibValueError, match="mutated merkle branch"):
        merkle_proof.assert_as_valid(leaf[::-1], [leaf[::-1]], 1, root[::-1])


def _sixty_four_byte_tx() -> Tx:
    """Return a transaction whose serialization is exactly 64 bytes.

    4 version, 1 input count, 36 outpoint, 1 empty script_sig, 4
    sequence, 1 output count, 8 value, 1 script length, 4 script, 4
    lock_time.
    """
    tx_in = TxIn(OutPoint(b"\x11" * 32, 0), b"", 0xFFFFFFFF)
    tx = Tx(1, 0, [tx_in], [TxOut(0, b"\x51\x51\x51\x51")], check_validity=False)
    assert len(tx.serialize(include_witness=True, check_validity=False)) == 64
    return tx


def test_cve_2017_12842_an_inner_node_that_is_a_transaction_is_refused() -> None:
    """A 64-byte transaction can be presented as an inner node.

    Its two halves are then a leaf and its sibling, and the branch is one
    level shorter than the tree it claims to belong to: the arithmetic
    checks out, so only refusing the shape refuses the proof. Which is
    why the check cannot live beside the arithmetic -- it has to know
    what a transaction looks like.
    """
    raw = _sixty_four_byte_tx().serialize(include_witness=True, check_validity=False)
    leaf, sibling = raw[:32], raw[32:]
    root = hash256(raw)

    # the arithmetic alone is satisfied: this is a well-formed branch
    assert merkle_root_from_branch(leaf, [sibling], 0, hash256) == root

    # and the block-level verifier refuses it anyway
    with pytest.raises(BTClibValueError, match="is a valid transaction"):
        merkle_proof.assert_as_valid(leaf[::-1], [sibling[::-1]], 0, root[::-1])
    assert not merkle_proof.verify(leaf[::-1], [sibling[::-1]], 0, root[::-1])


def test_an_honest_block_has_no_inner_node_that_parses_as_a_transaction() -> None:
    """The check above refuses nothing in a real block, which is the point."""
    block = _load("block_200000.bin")
    hashes = [tx.id[::-1] for tx in block.transactions]
    root = block.header.merkle_root
    for index in (0, 1, 2, len(hashes) // 2, len(hashes) - 1):
        branch = [sibling[::-1] for sibling in _branch(hashes, index)]
        merkle_proof.assert_as_valid(block.transactions[index].id, branch, index, root)


def test_a_malformed_branch_is_refused() -> None:
    """Refuse a branch malformed in sibling size, index or length."""
    block = _load("block_200000.bin")
    txids = [tx.id for tx in block.transactions]
    hashes = [txid[::-1] for txid in txids]
    root = block.header.merkle_root
    index = 3
    branch = [sibling[::-1] for sibling in _branch(hashes, index)]

    merkle_proof.assert_as_valid(txids[index], branch, index, root)

    # a branch item that is not 32 bytes is not a sibling
    with pytest.raises(BTClibValueError, match="invalid size"):
        merkle_proof.assert_as_valid(
            txids[index], [*branch[:-1], b"\x00" * 31], index, root
        )

    # a negative position
    with pytest.raises(BTClibValueError, match="negative leaf index"):
        merkle_proof.assert_as_valid(txids[index], branch, -1, root)

    # a branch too short for the position it claims. Dropping the top
    # sibling is not enough to catch it -- index 3 spends its bits in the
    # first two steps and the root simply comes out wrong -- so the check
    # bites where the position needs more steps than the branch has
    assert not merkle_proof.verify(txids[index], branch[:-1], index, root)
    with pytest.raises(BTClibValueError, match="leaf index too high"):
        merkle_proof.assert_as_valid(txids[index], branch[:1], index, root)

    # a branch of the right shape, one sibling wrong
    wrong = [*branch]
    wrong[0] = bytes(32)
    assert not merkle_proof.verify(txids[index], wrong, index, root)

    # and the right branch for the wrong root
    assert not merkle_proof.verify(txids[index], branch, index, bytes(32))


def test_one_sibling_is_not_a_branch_of_them() -> None:
    """Octets are a Sequence too, and iterating one yields its octets.

    A caller passing the one sibling it has, rather than a branch holding
    it, would otherwise have `assert_type`'s own `Sequence` check let it
    through -- an `Octets` is one -- and be zipped through its bytes,
    each treated as its own sibling (issue #1405).
    """
    block = _load("block_200000.bin")
    txids = [tx.id for tx in block.transactions]
    hashes = [txid[::-1] for txid in txids]
    root = block.header.merkle_root
    index = 3
    branch = [sibling[::-1] for sibling in _branch(hashes, index)]
    sibling = branch[0]

    with pytest.raises(BTClibTypeError, match="invalid branch type"):
        merkle_proof.assert_as_valid(txids[index], cast("Any", sibling), index, root)
    with pytest.raises(BTClibTypeError, match="invalid branch type"):
        merkle_root_from_branch(sibling, cast("Any", sibling), index, hash256)
