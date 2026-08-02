#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Block validity vectors from python-bitcoinlib, byte for byte.

`bitcoin/tests/data/checkblock_valid.json` and `checkblock_invalid.json`
of petertodd/python-bitcoinlib, which feed its `CheckBlock`;
tests/_data/README.md pins the revision. They are the only vendored
negative block vectors: what `block_test.py` rejects, it rejects from
blocks it mutates itself, so an independent hand is worth the two files.

A vector is `[comment, is_header, check_pow, cur_time, serialization]`.
The last two fields are contextual and btclib takes neither: `cur_time`
answers "is this block's timestamp too far in the future", which needs a
clock, and `check_pow` switches off a check `Block.assert_valid` always
makes. Both are read here anyway -- `check_pow` because it says which
rule the vector was written to reach, and the invalid table below records
where btclib's answer is the proof-of-work instead.
"""

from __future__ import annotations

from typing import Any

import pytest

from btclib.block import Block
from btclib.exceptions import BTClibValueError
from tests import load, vector_id

# btclib's own expectation, not upstream's: the vectors carry a comment
# and nothing else about the failure, so what a rejection must *say* is
# recorded here, keyed by that comment. Three of the seven name the
# proof-of-work, and upstream asks for it to be skipped (check_pow is
# false): btclib has no such switch, so the work is what answers first
# and the rule the vector aims at is out of reach through assert_valid.
# Each of those three rules is covered by block_test.py instead, from a
# block it mutates; the test at the end of this module is why the third
# of them cannot be covered from its own vector
_INVALID = {
    # the one contextual vector: two hours and one second ahead of the
    # cur_time it carries. btclib has no clock and no cur_time, so it
    # accepts -- marked xfail rather than dropped, and it turns red the
    # day a contextual check lands
    "Genesis block with time set to two hours + 1 second behind": None,
    "Genesis with one byte changed": "invalid proof-of-work: ",
    # the intended rule is "vtx empty"; this header carries a timestamp of
    # zero, so the header is refused before the transaction count is read
    "Empty vtx": r"invalid timestamp \(before genesis\)",
    # intended: first tx is not coinbase. block_test.py reaches that rule
    # from block 200,000 with its coinbase dropped
    "One tx, but not a coinbase": "invalid proof-of-work: ",
    # intended: bad-cb-multiple, which btclib does check (issue #250) but
    # only after the work, and this vector has none left to check --
    # test_the_bad_cb_multiple_vector_is_answered_by_the_work below
    "More than one coinbase (different coinbases)": "invalid proof-of-work: ",
    # upstream calls it a duplicate transaction, and the two copies do not
    # collide in the merkle tree -- [A, B, B] pads to [A, B, B, B] and its
    # root is not the one of [A, B]. So the root of the header, block
    # 170's, is simply not the root of these three transactions, which is
    # what Core answers too: bad-txnmrklroot is checked before the
    # duplicate flag it computes alongside
    "Duplicate transaction": "invalid merkle root: ",
    "Merkle root mismatch": "invalid merkle root: ",
}


def check_block_vectors(file_name: str) -> list[tuple[int, str, bool, str]]:
    """One tuple per vector, the single-string comment entries dropped.

    The index kept beside each is the position in the file, comments
    counted, so an id names the line to go and read.
    """
    vectors = []
    for index, vector in enumerate(load("block", "_data", file_name)):
        if len(vector) == 1:  # a comment, which upstream's loader skips too
            continue
        comment, is_header, check_pow, _cur_time, serialization = vector
        # no vector in either file is a bare 80-byte header, so there is
        # no header branch here to leave untested; a refreshed file that
        # grows one says so instead of being silently read as a block
        assert not is_header, comment
        vectors.append((index, comment, check_pow, serialization))
    return vectors


def params(file_name: str) -> list[Any]:
    """`check_block_vectors`, as parametrize takes it."""
    return [
        pytest.param(comment, check_pow, serialization, id=vector_id(index, comment))
        for index, comment, check_pow, serialization in check_block_vectors(file_name)
    ]


@pytest.mark.parametrize(
    ("comment", "check_pow", "serialization"),
    params("checkblock_valid.json"),
)
def test_checkblock_valid(comment: str, check_pow: bool, serialization: str) -> None:
    """Four real mainnet blocks, genesis among them.

    Genesis is the block btclib had no vector for, and it is the shape
    the merkle tree has nowhere else: one leaf, so the root is the txid
    of the coinbase and no hashing happens at all.
    """
    # every one of the four carries its proof-of-work, so parse() with
    # the default check_validity is the whole assertion
    assert check_pow, comment
    block = Block.parse(serialization)
    assert block.serialize().hex() == serialization
    assert block == Block.parse(block.serialize())


@pytest.mark.parametrize(
    ("comment", "check_pow", "serialization"),
    params("checkblock_invalid.json"),
)
def test_checkblock_invalid(comment: str, check_pow: bool, serialization: str) -> None:
    err_msg = _INVALID[comment]
    if err_msg is None:
        pytest.xfail("btclib takes no cur_time: no contextual timestamp check")
    # the serialization still has to parse: these are well-formed blocks
    # that consensus refuses, not truncated bytes
    block = Block.parse(serialization, check_validity=False)
    with pytest.raises(BTClibValueError, match=err_msg):
        block.assert_valid()


def test_the_bad_cb_multiple_vector_is_answered_by_the_work() -> None:
    """Why the table above records the work for a coinbase vector.

    Core's bad-cb-multiple is a rule btclib has (issue #250), and
    `block_test.py`'s `test_a_block_carries_one_coinbase` is where it is
    asserted, from a block mutated for the purpose. This vector cannot
    assert it: its header was re-rooted to commit to both coinbases, so
    the work no longer holds, and `assert_valid` checks the work first
    with no `fCheckPoW` switch to turn off. Everything else about the
    block is in order -- two coinbases, correct merkle root -- which is
    what makes the work, and only the work, the answer.

    Measured here rather than asserted in a comment: the entry in
    `_INVALID` is a claim about btclib's order of checks, and this is
    what turns it red if that order changes.
    """
    two_coinbases = next(
        serialization
        for _, comment, _, serialization in check_block_vectors(
            "checkblock_invalid.json"
        )
        if comment.startswith("More than one coinbase")
    )
    block = Block.parse(two_coinbases, check_validity=False)
    assert [tx.is_coinbase() for tx in block.transactions] == [True, True]
    block.assert_valid_merkle_root()

    with pytest.raises(BTClibValueError, match="invalid proof-of-work: "):
        block.header.assert_valid_pow()
