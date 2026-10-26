# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.tx.tx_context` module.

The cases of the rules Core v31.1 enforces are synthetic and
hand-computed against its own `src/consensus/tx_verify.cpp`
(bitcoin/bitcoin@9be056a8a7): each needs a chain around the transaction
that no vector file carries, and Core's own coverage of them lives in the
functional suite (`feature_cltv.py`, `feature_csv_activation.py`), which
drives a running node rather than a table of inputs and outputs.

The BIP54 rules are held to bip-0054's own vectors, `sigops.json`,
`txsize.json` and `coinbases.json` under `tests/tx/_data/`, which
`tests/_data/README.md` pins; the synthetic cases beside them are the
edges the vectors do not reach.
"""

import re
from typing import Any

import pytest

from btclib.block import Block
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.script import ScriptPubKey
from btclib.tx import Coin, OutPoint, Tx, TxIn, TxOut
from btclib.tx.limits import (
    INVALID_TX_NONWITNESS_SIZE,
    LOCKTIME_THRESHOLD,
    MAX_TX_LEGACY_SIGOPS,
    SEQUENCE_FINAL,
    SEQUENCE_LOCKTIME_DISABLE_FLAG,
    SEQUENCE_LOCKTIME_TYPE_FLAG,
)
from btclib.tx.tx_context import (
    assert_bip54_coinbase,
    assert_bip54_sig_ops,
    assert_bip54_tx_size,
    assert_coinbase_maturity,
    assert_coinbase_value,
    assert_sequence_locks,
    is_final,
)
from tests import load, vector_id

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


def _bip54_vectors(name: str) -> list[Any]:
    """Return one parameter per case of a bip-0054 vector file."""
    cases: list[dict[str, Any]] = load("tx", "_data", name)
    return [
        pytest.param(case, id=vector_id(i, case["comment"]))
        for i, case in enumerate(cases)
    ]


@pytest.mark.parametrize("case", _bip54_vectors("sigops.json"))
def test_bip54_sig_ops_vectors(case: dict[str, Any]) -> None:
    """Each bip-0054 sigops case is refused exactly where it is invalid.

    Some of upstream's pathological cases break `CheckTransaction` as
    well, so the transaction is parsed without that check: the rule
    asked here is the sigop limit alone.
    """
    tx = Tx.parse(case["tx"], check_validity=False)
    prevouts = [TxOut.parse(spent) for spent in case["spent_outputs"]]
    if case["valid"]:
        assert_bip54_sig_ops(tx, prevouts)
    else:
        with pytest.raises(BTClibValueError, match="bad-txns-legacy-sigops"):
            assert_bip54_sig_ops(tx, prevouts)


def _bare_checksigs(count: int) -> ScriptPubKey:
    """Return a script_pub_key of `count` OP_CHECKSIG, one legacy check each."""
    return ScriptPubKey(b"\xac" * count)


def test_bip54_sig_ops_limit_is_inclusive() -> None:
    """`MAX_TX_LEGACY_SIGOPS` checks pass and one more is refused."""
    prevouts = [TxOut(1_000, _bare_checksigs(MAX_TX_LEGACY_SIGOPS - 1))]
    script_sig = b"\xac"  # one more check, counted in the spending input
    tx = Tx(2, 0, [TxIn(A_PREV_OUT, script_sig=script_sig)], [_tx_out()])
    assert_bip54_sig_ops(tx, prevouts)
    prevouts = [TxOut(1_000, _bare_checksigs(MAX_TX_LEGACY_SIGOPS))]
    with pytest.raises(BTClibValueError, match="bad-txns-legacy-sigops"):
        assert_bip54_sig_ops(tx, prevouts)


def test_bip54_sig_ops_skips_a_coinbase() -> None:
    """A coinbase is not limited, and its prevouts are not counted.

    Built unchecked: a coinbase script_sig this long is refused by
    `CheckTransaction`, which this rule does not ask.
    """
    script_sig = b"\xac" * (MAX_TX_LEGACY_SIGOPS + 1)
    coinbase = Tx(
        2,
        0,
        [TxIn(OutPoint(), script_sig=script_sig, check_validity=False)],
        [_tx_out()],
        check_validity=False,
    )
    assert coinbase.is_coinbase
    assert_bip54_sig_ops(coinbase, [])


def test_assert_bip54_sig_ops_refuses_what_cannot_be_checked() -> None:
    """A wrong type, or a prevout count that is not the input count."""
    tx = _tx()
    with pytest.raises(BTClibTypeError, match="tx"):
        assert_bip54_sig_ops("tx", [_tx_out()])  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="prevouts"):
        assert_bip54_sig_ops(tx, 1)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="prevout"):
        assert_bip54_sig_ops(tx, ["a"])  # type: ignore[list-item]
    with pytest.raises(BTClibValueError, match="prevouts for"):
        assert_bip54_sig_ops(tx, [])


@pytest.mark.parametrize("case", _bip54_vectors("txsize.json"))
def test_bip54_tx_size_vectors(case: dict[str, Any]) -> None:
    """Each bip-0054 txsize case is refused exactly where it is invalid."""
    tx = Tx.parse(case["tx"])
    if case["valid"]:
        assert_bip54_tx_size(tx)
    else:
        assert len(tx.serialize(include_witness=False)) == INVALID_TX_NONWITNESS_SIZE
        with pytest.raises(BTClibValueError, match="bad-txns-size"):
            assert_bip54_tx_size(tx)


def test_assert_bip54_tx_size_refuses_a_non_tx() -> None:
    """Anything but a Tx is a type error."""
    with pytest.raises(BTClibTypeError, match="tx"):
        assert_bip54_tx_size(b"")  # type: ignore[arg-type]


def _bip54_coinbase_chains() -> list[Any]:
    """Return one parameter per chain of `coinbases.json`."""
    cases: list[dict[str, Any]] = load("tx", "_data", "coinbases.json")
    return [
        pytest.param(case, id=vector_id(i, case["comment"]))
        for i, case in enumerate(cases)
    ]


def _expected_coinbase_refusal(comment: str) -> tuple[int, str]:
    """Read the height and the reason an invalid case's comment states.

    Each comment names the block's height, and a final sequence where
    that is what breaks the rule; any other invalid case breaks the lock.
    """
    match = re.match(r"Block at height (\d+) ", comment)
    assert match, comment
    reason = "bad-cb-locktime"
    if " final nSequence" in comment and "non-final nSequence" not in comment:
        reason = "bad-cb-sequence"
    return int(match[1]), reason


@pytest.mark.parametrize("case", _bip54_coinbase_chains())
def test_bip54_coinbase_vectors(case: dict[str, Any]) -> None:
    """A chain is valid exactly where every coinbase of it passes.

    The chain starts at genesis, so a block's position is its height. An
    invalid chain is refused once, at the height and for the reason its
    comment states.
    """
    refused = []
    for height, serialized in enumerate(case["block_chain"]):
        coinbase = Block.parse(serialized).transactions[0]
        try:
            assert_bip54_coinbase(coinbase, height)
        except BTClibValueError as e:
            refused.append((height, str(e).split(":")[0]))
    if case["valid"]:
        assert not refused
    else:
        assert refused == [_expected_coinbase_refusal(case["comment"])]


def _coinbase_at(lock_time: int, sequence: int) -> Tx:
    """Return a coinbase with the given lock_time and input sequence."""
    tx_in = TxIn(OutPoint(), script_sig=b"\x02\x00\x00", sequence=sequence)
    return Tx(2, lock_time, [tx_in], [_tx_out()])


def test_bip54_coinbase_locks_to_the_height_before() -> None:
    """lock_time must be height - 1, and the sequence must not be final."""
    assert_bip54_coinbase(_coinbase_at(lock_time=9, sequence=0), 10)
    with pytest.raises(BTClibValueError, match="bad-cb-locktime"):
        assert_bip54_coinbase(_coinbase_at(lock_time=10, sequence=0), 10)
    with pytest.raises(BTClibValueError, match="bad-cb-sequence"):
        assert_bip54_coinbase(_coinbase_at(lock_time=9, sequence=SEQUENCE_FINAL), 10)
    # the genesis block is not checked
    assert_bip54_coinbase(_coinbase_at(lock_time=0, sequence=SEQUENCE_FINAL), 0)


def test_assert_bip54_coinbase_refuses_what_cannot_be_checked() -> None:
    """A wrong type, a negative height, or a transaction that is no coinbase."""
    coinbase = _coinbase_at(lock_time=0, sequence=0)
    with pytest.raises(BTClibTypeError, match="coinbase"):
        assert_bip54_coinbase("tx", 1)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid height type"):
        assert_bip54_coinbase(coinbase, "1")  # type: ignore[arg-type]
    with pytest.raises(BTClibValueError, match="invalid height"):
        assert_bip54_coinbase(coinbase, -1)
    with pytest.raises(BTClibValueError, match="not a coinbase"):
        assert_bip54_coinbase(_tx(), 1)
