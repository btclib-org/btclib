# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The strategies draw valid values, and reach the shapes they are for."""

import pytest
from hypothesis import find, given

from btclib.alias import ScriptType
from btclib.block import Block, BlockHeader
from btclib.block.proof_of_work import REGTEST_POW_LIMIT_BITS
from btclib.script import ScriptPubKey, Witness, parse
from btclib.script.script import ERROR_COMMAND
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from tests.strategies import (
    BLOCK_HEADERS,
    BLOCKS,
    OUT_POINTS,
    SCRIPT_PUB_KEYS,
    SCRIPTS,
    TX_INS,
    TX_OUTS,
    TXS,
    WITNESSES,
)


@given(out_point=OUT_POINTS, witness=WITNESSES, tx_out=TX_OUTS, tx_in=TX_INS)
def test_strategies_draw_valid_values(
    out_point: OutPoint, witness: Witness, tx_out: TxOut, tx_in: TxIn
) -> None:
    """Every value a strategy draws passes its type's `assert_valid`."""
    out_point.assert_valid()
    witness.assert_valid()
    tx_out.assert_valid()
    tx_in.assert_valid()


@given(tx=TXS)
def test_strategy_draws_valid_transactions(tx: Tx) -> None:
    """Every transaction the strategy draws passes `assert_valid`."""
    tx.assert_valid()


def test_scripts_include_a_push_cut_short() -> None:
    """A script that parse ends with ERROR_COMMAND is among the draws."""
    find(SCRIPTS, lambda script: ERROR_COMMAND in parse(script))


def test_scripts_include_a_push_of_over_255_bytes() -> None:
    """A push with a two-byte length, OP_PUSHDATA2, is among the draws."""
    find(
        SCRIPTS,
        lambda script: any(isinstance(c, str) and len(c) > 510 for c in parse(script)),
    )


@given(script_pub_key=SCRIPT_PUB_KEYS)
def test_strategy_draws_valid_script_pub_keys(script_pub_key: ScriptPubKey) -> None:
    """Every output script the strategy draws passes `assert_valid`."""
    script_pub_key.assert_valid()


@pytest.mark.parametrize(
    "script_type",
    [
        "nulldata",
        "p2ms",
        "p2pk",
        "p2pkh",
        "p2sh",
        "p2tr",
        "p2wpkh",
        "p2wsh",
        "unknown",
        "witness_unknown",
    ],
)
def test_script_pub_keys_include_each_type(script_type: ScriptType) -> None:
    """Each type `type_and_payload` names is among the draws."""
    find(SCRIPT_PUB_KEYS, lambda script_pub_key: script_pub_key.type == script_type)


@given(header=BLOCK_HEADERS)
def test_strategy_draws_valid_block_headers(header: BlockHeader) -> None:
    """Every header the strategy draws passes `assert_valid`."""
    header.assert_valid()


@given(block=BLOCKS)
def test_strategy_draws_valid_blocks(block: Block) -> None:
    """Every block drawn passes `assert_valid` with regtest's limit."""
    block.assert_valid(REGTEST_POW_LIMIT_BITS)


def test_blocks_include_a_witness_commitment() -> None:
    """A block carrying a BIP141 commitment is among the draws."""
    find(BLOCKS, lambda block: block.witness_commitment is not None)


def test_blocks_include_a_coinbase_alone_and_several_transactions() -> None:
    """A block of the coinbase alone, and one of three or more transactions."""
    find(BLOCKS, lambda block: len(block.transactions) == 1)
    find(BLOCKS, lambda block: len(block.transactions) >= 3)
