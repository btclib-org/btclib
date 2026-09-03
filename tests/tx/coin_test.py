# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.tx.coin` module."""

from dataclasses import FrozenInstanceError

import pytest

from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.script import ScriptPubKey
from btclib.tx import Coin, TxOut

A_TX_OUT = TxOut(1_000, ScriptPubKey(b""))


def test_coin() -> None:
    """Check the three fields, one coinbase and one not."""
    coin = Coin(A_TX_OUT, 100, is_coinbase=True)
    assert coin.tx_out == A_TX_OUT
    assert coin.height == 100
    assert coin.is_coinbase

    coin = Coin(A_TX_OUT, 0, is_coinbase=False)
    assert coin.height == 0
    assert not coin.is_coinbase


def test_frozen() -> None:
    """Refuse assignment to any field: a frozen Coin is hashable."""
    coin = Coin(A_TX_OUT, 100, is_coinbase=True)

    with pytest.raises(FrozenInstanceError):
        coin.height = 101  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        coin.is_coinbase = False  # type: ignore[misc]

    assert hash(coin) == hash(Coin(A_TX_OUT, 100, is_coinbase=True))
    assert len({coin, Coin(A_TX_OUT, 100, is_coinbase=True)}) == 1


def test_invalid_tx_out() -> None:
    """Refuse a tx_out of the wrong type."""
    with pytest.raises(BTClibTypeError, match="invalid tx_out type"):
        Coin("not a tx_out", 100, is_coinbase=True)  # type: ignore[arg-type]


def test_invalid_height() -> None:
    """Refuse a non-integer or negative height."""
    with pytest.raises(BTClibTypeError, match="invalid height type"):
        Coin(A_TX_OUT, "100", is_coinbase=True)  # type: ignore[arg-type]

    with pytest.raises(BTClibValueError, match="invalid height"):
        Coin(A_TX_OUT, -1, is_coinbase=True)

    with pytest.raises(BTClibTypeError, match="invalid height type"):
        Coin(A_TX_OUT, True, is_coinbase=True)  # bool is not a height


def test_invalid_is_coinbase() -> None:
    """Refuse an is_coinbase of the wrong type."""
    with pytest.raises(BTClibTypeError, match="invalid is_coinbase type"):
        Coin(A_TX_OUT, 100, is_coinbase=1)  # type: ignore[arg-type]


def test_invalid_tx_out_content() -> None:
    """A malformed tx_out is refused through TxOut.assert_valid."""
    bad = TxOut(1_000, ScriptPubKey(b""), check_validity=False)
    object.__setattr__(bad, "value", -1)
    with pytest.raises(BTClibValueError):
        Coin(bad, 100, is_coinbase=True)


def test_check_validity_false_skips_the_check() -> None:
    """check_validity=False builds a Coin nothing here has judged yet."""
    coin = Coin(A_TX_OUT, -1, is_coinbase=True, check_validity=False)
    assert coin.height == -1
    with pytest.raises(BTClibValueError, match="invalid height"):
        coin.assert_valid()
