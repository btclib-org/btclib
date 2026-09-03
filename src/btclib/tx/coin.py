# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The Coin dataclass: a prevout, and what a rule about spending it needs.

Bitcoin Core's `Coin` (`src/coins.h`, at bitcoin/bitcoin@9be056a8a7) is
the shape matched -- an output, the height of the block that created it,
and whether that block's own coinbase created it -- and not matched in
full: Core's `Coin` also runs the output through `TxOutCompression`, a
storage optimization no caller of `btclib.tx.tx_context` needs, and
issue #1123 already declined it. How a node keeps one
on disk is that node's decision and not this class's: no `parse` and no
`serialize`, `to_dict` and `from_dict` included, since there is no wire
or json shape to round-trip.

A caller checking a mempool acceptance rather than a block connecting
builds a `Coin` at one past the active chain's tip -- Core's own
`MEMPOOL_HEIGHT` reading -- rather than this module special-casing the
mempool: the rules in `btclib.tx.tx_context` read `Coin.height` and
nothing about where it came from.
"""

from __future__ import annotations

from dataclasses import dataclass

from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.tx.tx_out import TxOut
from btclib.utils import assert_type, is_integer

__all__ = [
    "Coin",
]


# frozen, as OutPoint and TxOut are: a Coin is a value read off a chain at
# one instant, not something a caller mutates in place, and the generated
# __hash__ needs every field hashable -- TxOut already is (issue 416)
@dataclass(frozen=True)
class Coin:
    """One prevout: an output, the height it was created at, a coinbase bit.

    Everything `btclib.tx.tx_context`'s rules need about an output that
    the output's own bytes do not carry -- `Consensus::CheckTxInputs`'s
    coinbase maturity check and the BIP68 sequence lock both read a
    prevout's creation height, which is chain state and not part of the
    spending transaction.
    """

    tx_out: TxOut
    height: int
    is_coinbase: bool

    def __init__(
        self,
        tx_out: TxOut,
        height: int,
        is_coinbase: bool,
        *,
        check_validity: bool = True,
    ) -> None:
        object.__setattr__(self, "tx_out", tx_out)
        object.__setattr__(self, "height", height)
        object.__setattr__(self, "is_coinbase", is_coinbase)

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Refuse a wrong-typed tx_out, a bad height, or a non-bool bit."""
        assert_type(self.tx_out, TxOut, "tx_out")
        self.tx_out.assert_valid()

        if not is_integer(self.height):
            err_msg = f"invalid height type: {type(self.height).__name__}"
            raise BTClibTypeError(err_msg)
        if self.height < 0:
            raise BTClibValueError(f"invalid height: {self.height}")

        assert_type(self.is_coinbase, bool, "is_coinbase")
