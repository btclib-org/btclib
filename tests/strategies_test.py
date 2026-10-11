# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The transaction strategies draw valid values; SCRIPTS reaches the edges."""

from hypothesis import find, given

from btclib.script import Witness, parse
from btclib.script.script import ERROR_COMMAND
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from tests.strategies import (
    OUT_POINTS,
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
