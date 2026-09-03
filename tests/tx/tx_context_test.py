# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.tx.tx_context` module.

Every case is synthetic and hand-computed against Bitcoin Core v31.1's
own `src/consensus/tx_verify.cpp` (bitcoin/bitcoin@9be056a8a7): the four
rules under test each need a chain around the transaction that no vector
file carries, and Core's own coverage of them lives in the functional
suite (`feature_cltv.py`, `feature_csv_activation.py`), which drives a
running node rather than a table of inputs and outputs.
"""

import pytest

from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.script import ScriptPubKey
from btclib.tx import Coin, OutPoint, Tx, TxIn, TxOut
from btclib.tx.limits import (
    LOCKTIME_THRESHOLD,
    SEQUENCE_FINAL,
    SEQUENCE_LOCKTIME_DISABLE_FLAG,
    SEQUENCE_LOCKTIME_TYPE_FLAG,
)
from btclib.tx.tx_context import (
    assert_coinbase_maturity,
    assert_coinbase_value,
    assert_sequence_locks,
    is_final,
)

A_SCRIPT_PUB_KEY = ScriptPubKey(b"")
A_PREV_OUT = OutPoint(b"\x11" * 32, 0)


def _tx_out(value: int = 1_000) -> TxOut:
    """Return a TxOut of the given value, script_pub_key held fixed."""
    return TxOut(value, A_SCRIPT_PUB_KEY)


def _tx(version: int = 2, lock_time: int = 0, sequence: int = 0) -> Tx:
    """Return a one-input, one-output Tx over the given fields."""
    return Tx(
        version,
        lock_time,
        [TxIn(A_PREV_OUT, sequence=sequence)],
        [_tx_out()],
    )


def _coinbase(script_sig: bytes = b"\x02\x00\x00", value: int = 50 * 100_000_000) -> Tx:
    """Return a coinbase Tx paying `value`."""
    return Tx(
        2,
        0,
        [TxIn(OutPoint(), script_sig=script_sig)],
        [_tx_out(value)],
    )


# --- is_final --------------------------------------------------------


def test_a_zero_lock_time_is_always_final() -> None:
    """Core's IsFinalTx: lock_time 0 is final regardless of height or time."""
    tx = _tx(lock_time=0, sequence=0)
    assert is_final(tx, height=0, block_time=0)


def test_a_height_lock_time_is_read_against_height() -> None:
    """lock_time is the last invalid height: not final at or below it.

    Final once `height` has passed it, Core's own nLockTime semantics.
    """
    tx = _tx(lock_time=500, sequence=0)
    assert not is_final(tx, height=500, block_time=10**9)
    assert is_final(tx, height=501, block_time=0)


def test_a_timestamp_lock_time_is_read_against_block_time() -> None:
    """A lock_time at or above LOCKTIME_THRESHOLD is read as a timestamp."""
    tx = _tx(lock_time=LOCKTIME_THRESHOLD + 100, sequence=0)
    assert not is_final(tx, height=10**9, block_time=LOCKTIME_THRESHOLD + 100)
    assert is_final(tx, height=0, block_time=LOCKTIME_THRESHOLD + 101)


def test_every_input_final_overrides_an_unmet_lock_time() -> None:
    """SEQUENCE_FINAL on every input makes lock_time irrelevant."""
    tx = _tx(lock_time=500, sequence=SEQUENCE_FINAL)
    assert is_final(tx, height=0, block_time=0)


def test_is_final_refuses_a_non_integer_height_or_block_time() -> None:
    """A malformed height or block_time is refused, not silently coerced."""
    tx = _tx()
    with pytest.raises(BTClibTypeError, match="invalid height type"):
        is_final(tx, height="0", block_time=0)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid block_time type"):
        is_final(tx, height=0, block_time="0")  # type: ignore[arg-type]


# --- assert_coinbase_maturity -----------------------------------------


def test_a_coinbase_below_the_maturity_depth_is_refused() -> None:
    """bad-txns-premature-spend-of-coinbase, below and at the boundary."""
    coin = Coin(_tx_out(), height=100, is_coinbase=True)
    with pytest.raises(BTClibValueError, match="bad-txns-premature-spend-of-coinbase"):
        assert_coinbase_maturity([coin], spend_height=199)
    assert_coinbase_maturity([coin], spend_height=200)


def test_a_non_coinbase_prevout_is_never_refused_on_maturity() -> None:
    """A prevout that is not a coinbase has no maturity rule at all."""
    coin = Coin(_tx_out(), height=100, is_coinbase=False)
    assert_coinbase_maturity([coin], spend_height=100)


def test_assert_coinbase_maturity_refuses_a_non_integer_spend_height() -> None:
    """A malformed spend_height is refused, not silently coerced."""
    coin = Coin(_tx_out(), height=100, is_coinbase=True)
    with pytest.raises(BTClibTypeError, match="invalid spend_height type"):
        assert_coinbase_maturity([coin], spend_height="200")  # type: ignore[arg-type]


# --- assert_coinbase_value ---------------------------------------------


def test_a_coinbase_at_or_below_subsidy_plus_fees_is_accepted() -> None:
    """A coinbase paying exactly the ceiling, or under it, is accepted."""
    coinbase = _coinbase(value=100)
    assert_coinbase_value(coinbase, subsidy=90, fees=10)
    assert_coinbase_value(coinbase, subsidy=100, fees=0)


def test_a_coinbase_above_subsidy_plus_fees_is_refused() -> None:
    """bad-cb-amount: a coinbase paying more than subsidy plus fees."""
    coinbase = _coinbase(value=101)
    with pytest.raises(BTClibValueError, match="bad-cb-amount"):
        assert_coinbase_value(coinbase, subsidy=90, fees=10)


def test_assert_coinbase_value_refuses_a_non_integer_subsidy_or_fees() -> None:
    """A malformed subsidy or fees is refused, not silently coerced."""
    coinbase = _coinbase()
    with pytest.raises(BTClibTypeError, match="invalid subsidy type"):
        assert_coinbase_value(coinbase, subsidy="90", fees=0)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid fees type"):
        assert_coinbase_value(coinbase, subsidy=90, fees="0")  # type: ignore[arg-type]


# --- assert_sequence_locks ----------------------------------------------


def test_a_version_1_transaction_is_never_sequence_locked() -> None:
    """BIP68 does not apply below version 2, whatever the sequence is."""
    tx = _tx(version=1, sequence=5)
    coin = Coin(_tx_out(), height=100, is_coinbase=False)
    assert_sequence_locks(
        tx,
        [coin],
        height=0,
        tip_median_time_past=0,
        ancestor_median_time_past=lambda h: 0,
    )


def test_a_disabled_sequence_is_never_sequence_locked() -> None:
    """SEQUENCE_LOCKTIME_DISABLE_FLAG opts a single input out of BIP68."""
    tx = _tx(sequence=SEQUENCE_LOCKTIME_DISABLE_FLAG | 5)
    coin = Coin(_tx_out(), height=100, is_coinbase=False)
    assert_sequence_locks(
        tx,
        [coin],
        height=0,
        tip_median_time_past=0,
        ancestor_median_time_past=lambda h: 0,
    )


def test_a_height_based_lock_is_read_against_height() -> None:
    """A height-based lock of 5 over a coin at height 100 matures at 105."""
    tx = _tx(sequence=5)
    coin = Coin(_tx_out(), height=100, is_coinbase=False)
    with pytest.raises(BTClibValueError, match="bad-txns-nonfinal"):
        assert_sequence_locks(
            tx,
            [coin],
            height=104,
            tip_median_time_past=0,
            ancestor_median_time_past=lambda h: 0,
        )
    assert_sequence_locks(
        tx,
        [coin],
        height=105,
        tip_median_time_past=0,
        ancestor_median_time_past=lambda h: 0,
    )


def test_a_time_based_lock_is_read_against_tip_median_time_past() -> None:
    """A time-based lock of 5 units (2560s) over a 1_000s ancestor."""
    coin = Coin(_tx_out(), height=100, is_coinbase=False)
    tx = _tx(sequence=SEQUENCE_LOCKTIME_TYPE_FLAG | 5)

    def ancestor_median_time_past(height: int) -> int:
        assert height == coin.height - 1
        return 1_000

    with pytest.raises(BTClibValueError, match="bad-txns-nonfinal"):
        assert_sequence_locks(
            tx,
            [coin],
            height=0,
            tip_median_time_past=1_000 + 2_560 - 1,
            ancestor_median_time_past=ancestor_median_time_past,
        )
    assert_sequence_locks(
        tx,
        [coin],
        height=0,
        tip_median_time_past=1_000 + 2_560,
        ancestor_median_time_past=ancestor_median_time_past,
    )


def test_assert_sequence_locks_refuses_a_prevouts_count_mismatch() -> None:
    """Prevouts must align with tx.vin one for one."""
    tx = _tx(sequence=5)
    with pytest.raises(BTClibValueError, match="prevouts for"):
        assert_sequence_locks(
            tx,
            [],
            height=0,
            tip_median_time_past=0,
            ancestor_median_time_past=lambda h: 0,
        )


def test_assert_sequence_locks_refuses_a_non_integer_height_or_time() -> None:
    """A malformed height or tip_median_time_past is refused."""
    tx = _tx(sequence=5)
    coin = Coin(_tx_out(), height=100, is_coinbase=False)
    with pytest.raises(BTClibTypeError, match="invalid height type"):
        assert_sequence_locks(
            tx,
            [coin],
            height="0",  # type: ignore[arg-type]
            tip_median_time_past=0,
            ancestor_median_time_past=lambda h: 0,
        )
    with pytest.raises(BTClibTypeError, match="invalid tip_median_time_past type"):
        assert_sequence_locks(
            tx,
            [coin],
            height=0,
            tip_median_time_past="0",  # type: ignore[arg-type]
            ancestor_median_time_past=lambda h: 0,
        )
