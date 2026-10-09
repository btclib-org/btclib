# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The shared strategies draw only valid values."""

from hypothesis import given

from btclib.script import Witness
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from tests.strategies import OUT_POINTS, TX_INS, TX_OUTS, TXS, WITNESSES


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
