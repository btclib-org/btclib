# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Transactions: OutPoint, TxIn, TxOut, Tx, Coin, join, and input_weight."""

from btclib.tx.coin import Coin
from btclib.tx.out_point import OutPoint
from btclib.tx.tx import Tx, join
from btclib.tx.tx_context import (
    AncestorMedianTimePast,
    assert_coinbase_maturity,
    assert_coinbase_value,
    assert_sequence_locks,
    is_final,
)
from btclib.tx.tx_in import TxIn, input_weight
from btclib.tx.tx_out import TxOut

# AncestorMedianTimePast, assert_coinbase_maturity, assert_coinbase_value,
# assert_sequence_locks and is_final are flattened out of tx_context the
# same way btclib.block flattens header_context: each is the one
# operation a caller reaches for, not a namespace of related constants
__all__ = [
    "AncestorMedianTimePast",
    "Coin",
    "OutPoint",
    "Tx",
    "TxIn",
    "TxOut",
    "assert_coinbase_maturity",
    "assert_coinbase_value",
    "assert_sequence_locks",
    "input_weight",
    "is_final",
    "join",
]
