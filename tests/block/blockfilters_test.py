# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The ten testnet blocks Bitcoin Core carries in `blockfilters.json`.

`src/test/data/blockfilters.json` is Core's BIP158 vector file, and each
of its rows opens with a height, a block hash and a whole serialized
block before the filter columns begin; tests/_data/README.md pins the
revision. btclib implements no block filter, so those columns are unread
here -- the file is vendored whole under its own name anyway, which is
what the naming convention asks for and what leaves the filters there
for whenever BIP158 arrives.

The three columns read are the vector: Core chose the rows for the
shapes their scripts have, and they are shapes nothing else in this
suite holds. The four blocks of `_data/block_*.bin` are mainnet and
ordinary; these are testnet and deliberately odd -- a coinbase output
script no parser can read, two empty output scripts, duplicate pushdata.
What the file does not add is an *invalid* block: every row is a block
the chain accepted, and the negative vectors remain the seven of
`checkblock_test.py`.

The `Notes` column is Core's own and describes the filter case rather
than the block: 15007's "non-standard OP_RETURN output" is in a script
this block spends from, not in the block, whose single transaction is a
coinbase paying to p2pk.
"""

from __future__ import annotations

from typing import Any

import pytest

from btclib.block import Block, BlockContext
from btclib.exceptions import BTClibValueError
from tests import load, vector_id

_HEADER_ROW = 1  # "Block Height,Block Hash,Block,[Prev Output Scripts ..."

# Core's chainparams for testnet3, which these ten blocks are from: the
# four rows below it predate the rule, and are the reason the gate exists
# -- checking bad-cb-height at every height would refuse four blocks the
# chain accepted
_TESTNET_BIP34_HEIGHT = 21_111

# the legacy sigop count of each row, which is the arithmetic and not the
# limit: 21 in all, against a cost cap of 20,000 checks. 987,876 is the
# zero, its coinbase output script ending in an OP_CHECKSIG inside a push
# that runs past the end of the script -- an op code no implementation
# reaches
_SIG_OP_COUNT = {
    0: 1,
    2: 1,
    3: 1,
    15007: 1,
    49291: 2,
    180480: 8,
    926485: 6,
    987876: 0,
    1263442: 1,
    1414221: 0,
}


def _rows() -> list[Any]:
    """Return the vector rows, the header row of column names dropped."""
    rows: list[Any] = load("block", "_data", "blockfilters.json")
    return rows[_HEADER_ROW:]


def params() -> list[Any]:
    """Return one pytest.param per row, labelled by height and notes."""
    return [
        pytest.param(height, block_hash, serialization, id=vector_id(height, notes))
        for height, block_hash, serialization, _, _, _, _, notes in _rows()
    ]


def block_at(height: int) -> Block:
    """Return the row of that height, parsed under the full validity check."""
    return next(Block.parse(row[2]) for row in _rows() if row[0] == height)


@pytest.mark.parametrize("height, block_hash, serialization", params())
def test_blockfilters_block(height: int, block_hash: str, serialization: str) -> None:
    """Parse each row's block, round-trip it, and check its two claims.

    The hash the row states is what the parsed header must hash to, and
    the height is the second independent claim in the file: from BIP34
    on, a block commits its own height into the coinbase script_sig, so
    `Block.height` can be held to a number btclib did not compute. The
    four version 1 rows -- genesis, 2, 3 and 15007 -- predate BIP34 and
    commit nothing, which is `None` here.
    """
    block = Block.parse(serialization)
    assert block.serialize().hex() == serialization
    assert block == Block.parse(block.serialize())
    assert block.header.hash.hex() == block_hash

    expected_height = None if block.header.version == 1 else height
    assert block.height == expected_height

    assert block.sig_op_count == _SIG_OP_COUNT[height]


@pytest.mark.parametrize("height, block_hash, serialization", params())
def test_blockfilters_coinbase_height(
    height: int, block_hash: str, serialization: str
) -> None:
    """Core's bad-cb-height over ten real testnet blocks.

    Six of the rows are at or above testnet3's activation height and
    commit their own height in the bytes Core builds; the four below it
    are version 1 blocks that commit nothing, and they are what says the
    activation height has to be part of the context. Asked through
    `assert_valid_contextual`, so that the gate is what decides and not
    the test: the same call over the same block passes below the
    activation height and asks the question above it.
    """
    block = Block.parse(serialization)
    context = BlockContext(
        height=height,
        now=block.header.time,
        bip34_height=_TESTNET_BIP34_HEIGHT,
    )
    assert context.is_bip34_active == (height >= _TESTNET_BIP34_HEIGHT)
    block.assert_valid_contextual(context)

    if not context.is_bip34_active:
        # the commitment is absent, so asking for it directly is what
        # measures that the gate above is doing the work
        with pytest.raises(BTClibValueError, match="invalid coinbase height: "):
            block.assert_valid_coinbase_height(height)
        return

    # and above it, the block is refused for any other height
    with pytest.raises(BTClibValueError, match="invalid coinbase height: "):
        block.assert_valid_coinbase_height(height + 1)


def test_an_output_script_can_be_empty() -> None:
    """Core's "pays to empty output script", and the "empty data" row.

    A zero-length script_pub_key is a var_bytes of zero and nothing
    else, so it is the shape a length-driven parser is most likely to
    mishandle -- and it is spendable by anyone, which is why the chain
    holds so few of them.
    """
    empty = [
        (out.value, out.script_pub_key.script)
        for height in (49291, 1414221)
        for tx in block_at(height).transactions
        for out in tx.vout
        if not out.script_pub_key.script
    ]
    assert empty == [(50000000, b""), (78125000, b"")]


def test_a_coinbase_output_script_need_not_parse() -> None:
    """Core's row for a coinbase output script no parser can read.

    A script_pub_key is bytes the consensus rules never execute unless
    something spends it, so a block carrying one that no parser can read
    is valid: the block-level checks are over the bytes. btclib says so
    twice -- `assert_valid` accepts the block, and the rendering marks
    where the opcodes stop making sense rather than raising.
    """
    coinbase = block_at(987876).transactions[0]
    assert coinbase.is_coinbase
    script_pub_key = coinbase.vout[0].script_pub_key
    assert script_pub_key.asm[-2:] == ["UNKNOWN_OP_CODE_216", "[error]"]
    assert script_pub_key.type == "unknown"


def test_the_witness_row_commits_to_its_witnesses() -> None:
    """Core's "includes witness data", the one segwit row of the file.

    `Block.parse` above already asserted it, `assert_valid` checking the
    BIP141 commitment for any block with a witness; naming it here is
    what says the row was chosen for that and would be missed if it went.
    """
    block = block_at(1263442)
    assert block.is_segwit
    assert block.witness_commitment is not None
