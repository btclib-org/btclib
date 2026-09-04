# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.coinstats` module.

The oracle is a Bitcoin Core node and nothing else: `bogo_size` and
`tx_out_ser` reproduce no wire size and no storage format, so an
assertion written from this tree's own answer would say only that the
answer has not changed. `tests/_data/gettxoutsetinfo_regtest.json` is
one regtest chain's unspent outputs beside what `gettxoutsetinfo`
reported about it, and that file's entry in `tests/_data/README.md` says
which call each field came from and how to record another.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest

from btclib import var_int
from btclib.amount import sats_from_btc
from btclib.coinstats import CoinStats, bogo_size, tx_out_ser
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.muhash import MuHash3072
from btclib.script import is_unspendable
from btclib.tx.coin import Coin
from btclib.tx.out_point import OutPoint
from btclib.tx.tx_out import TxOut
from tests import load

_RECORDED = load("_data", "gettxoutsetinfo_regtest.json")


def _out_point_and_coin(recorded: dict[str, Any]) -> tuple[bytes, Coin]:
    """Return the outpoint bytes and the `Coin` one recorded output is."""
    out_point = OutPoint(bytes.fromhex(recorded["txid"]), recorded["vout"])
    tx_out = TxOut(
        sats_from_btc(Decimal(recorded["value"])), recorded["script_pub_key"]
    )
    return out_point.serialize(), Coin(tx_out, recorded["height"], recorded["coinbase"])


def _counters(stats: CoinStats) -> tuple[int, int, int]:
    """Return the three running counters, the accumulator left aside."""
    return (stats.transaction_output_count, stats.total_amount, stats.bogo_size)


def _every_recorded_output() -> list[tuple[bytes, Coin]]:
    """Return every unspent output of the recorded chain, in block order."""
    return [
        _out_point_and_coin(recorded)
        for recorded in _RECORDED["utxos"] + _RECORDED["unspendable_outputs"]
    ]


def test_the_recorded_chain_reproduces_what_the_node_reported() -> None:
    """Every number `gettxoutsetinfo` answered, from the outputs alone.

    The one assertion that says `tx_out_ser` and `bogo_size` are Core's:
    a wrong byte anywhere in what is committed to gives a digest that is
    a plausible 32 bytes, and a wrong fixed part gives a plausible
    integer.

    The digest is compared reversed, `gettxoutsetinfo` printing a
    `uint256` in display order -- `btclib.coinstats`' own "Reading a
    digest against a node" is where that is argued.
    """
    stats = CoinStats()
    for out_point_bytes, coin in _every_recorded_output():
        stats.insert(out_point_bytes, coin)

    reported = _RECORDED["gettxoutsetinfo"]
    assert stats.digest[::-1].hex() == reported["muhash"]
    assert stats.transaction_output_count == reported["txouts"]
    assert stats.bogo_size == reported["bogosize"]
    assert stats.total_amount == sats_from_btc(Decimal(reported["total_amount"]))


def test_the_recorded_chain_carries_what_it_is_read_for() -> None:
    """Guard the oracle above against passing on a file that lost its point.

    It reads a file, and a file that had lost its unspendable outputs, or
    every script but one shape, would still make every assertion up
    there true -- of a chain that no longer exercises the gate or the
    script-length term of the bogo size.
    """
    assert _RECORDED["unspendable_outputs"]
    scripts = {utxo["script_pub_key"][:4] for utxo in _RECORDED["utxos"]}
    assert scripts == {"0014", "0020", "5120", "76a9", "a914"}
    coinbase_bits = {utxo["coinbase"] for utxo in _RECORDED["utxos"]}
    assert coinbase_bits == {True, False}


def test_remove_undoes_insert_whatever_the_order() -> None:
    """`insert` and `remove` are exact inverses, as the accumulator is.

    Removed in the reverse of the order they went in, and the counters
    come back to the empty set as well as the digest does -- which is
    what lets a caller undo a staged block without recording what any of
    them held before it.
    """
    empty = CoinStats()
    stats = CoinStats()
    outputs = _every_recorded_output()
    for out_point_bytes, coin in outputs:
        stats.insert(out_point_bytes, coin)
    for out_point_bytes, coin in reversed(outputs):
        stats.remove(out_point_bytes, coin)

    assert stats.digest == empty.digest
    assert stats.transaction_output_count == 0
    assert stats.total_amount == 0
    assert stats.bogo_size == 0


def test_an_unspendable_output_moves_nothing() -> None:
    """What Core's own UTXO set never carries, this never counts.

    `CCoinsViewCache::AddCoin` returns before adding such an output, so
    the answer is not that the arithmetic cancels: nothing is asked of
    the accumulator at all, which is what the assertion after the
    `insert` alone says. `remove` is checked beside it because a gate on
    one of the two and not the other is an accumulator that stops
    cancelling.
    """
    empty = CoinStats()
    stats = CoinStats()
    op_return = _RECORDED["unspendable_outputs"][0]
    out_point_bytes, coin = _out_point_and_coin(op_return)
    assert is_unspendable(coin.tx_out.script_pub_key.script)

    # the accumulator is compared by digest and not by identity, two
    # MuHash3072 of the same multiset being different objects
    stats.insert(out_point_bytes, coin)
    assert _counters(stats) == _counters(empty)
    assert stats.digest == empty.digest
    stats.remove(out_point_bytes, coin)
    assert _counters(stats) == _counters(empty)
    assert stats.digest == empty.digest


def test_the_packed_height_is_four_bytes_wide_and_not_a_var_int() -> None:
    """The fixed width is what a storage format is free to disagree on.

    A height under 253 is one byte as a `var_int` and four here, so the
    two encodings of the same number are not interchangeable and the
    digests they lead to are different.
    """
    out_point = OutPoint(bytes.fromhex(f"{7:064x}"), 3)
    tx_out = TxOut(1000, "0014" + "11" * 20)
    coin = Coin(tx_out, 12, is_coinbase=True)

    serialized = tx_out_ser(out_point.serialize(), coin)
    packed = serialized[36:40]
    assert packed == b"\x19\x00\x00\x00"  # (12 << 1) | 1
    assert serialized == out_point.serialize() + packed + tx_out.serialize()
    assert len(var_int.serialize((12 << 1) | 1)) == 1


def test_the_coinbase_bit_is_the_low_bit_of_the_packed_field() -> None:
    """The same height with and without it differ in one bit, and only there."""
    out_point_bytes = OutPoint(bytes.fromhex(f"{7:064x}"), 3).serialize()
    tx_out = TxOut(1000, "0014" + "11" * 20)

    mined = tx_out_ser(out_point_bytes, Coin(tx_out, 12, is_coinbase=True))
    spent_from = tx_out_ser(out_point_bytes, Coin(tx_out, 12, is_coinbase=False))
    assert int.from_bytes(mined[36:40], "little") ^ 1 == int.from_bytes(
        spent_from[36:40], "little"
    )


def test_a_height_wider_than_the_packed_field_is_refused() -> None:
    """The `uint32` Core packs into is what bounds the height.

    One bit is the coinbase flag, so the highest height the field holds
    is one below 2**31 -- and a height above it would otherwise leave as
    an OverflowError, from outside the library's exception contract.
    """
    out_point_bytes = OutPoint(bytes.fromhex(f"{7:064x}"), 3).serialize()
    tx_out = TxOut(1000, "0014" + "11" * 20)

    highest = (1 << 31) - 1
    at_the_bound = tx_out_ser(out_point_bytes, Coin(tx_out, highest, True))
    assert len(at_the_bound) == 36 + 4 + len(tx_out.serialize())
    assert at_the_bound[36:40] == b"\xff\xff\xff\xff"

    coin = Coin(tx_out, highest + 1, is_coinbase=True)
    with pytest.raises(BTClibValueError, match="invalid height"):
        tx_out_ser(out_point_bytes, coin)
    with pytest.raises(BTClibValueError, match="invalid height"):
        CoinStats().insert(out_point_bytes, coin)


def test_a_wrong_argument_is_refused_as_btclib_refuses_one() -> None:
    """Both arguments are checked, the outpoint by its size."""
    out_point_bytes = OutPoint(bytes.fromhex(f"{7:064x}"), 3).serialize()
    coin = Coin(TxOut(1000, "0014" + "11" * 20), 12, is_coinbase=False)

    with pytest.raises(BTClibValueError, match="invalid size"):
        tx_out_ser(out_point_bytes[:-1], coin)
    with pytest.raises(BTClibTypeError, match="invalid coin type"):
        tx_out_ser(out_point_bytes, coin.tx_out)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid coin type"):
        CoinStats().remove(out_point_bytes, "not a coin")  # type: ignore[arg-type]


def test_the_bogo_size_is_not_a_serialized_size() -> None:
    """Core's own "database-independent metric", and what it is not.

    A script long enough to need a three-byte `var_int` length prefix
    still counts two for it, so the bogo size of an output and the bytes
    a transaction writes it as move apart as the script grows.
    """
    short = bytes.fromhex("0014" + "11" * 20)
    long = b"\x51" * 300

    assert bogo_size(short) == 50 + len(short)
    assert bogo_size(long) == 50 + len(long)
    assert bogo_size(short.hex()) == bogo_size(short)

    wire = TxOut(1000, long).serialize()
    assert len(wire) == 8 + 3 + len(long)
    assert bogo_size(long) != len(wire) + 32 + 4 + 4


def test_the_accumulator_is_the_module_it_comes_from() -> None:
    """`CoinStats` wraps `MuHash3072` and adds no arithmetic of its own.

    A caller resuming from a store hands back an accumulator that module
    deserialized, and the digest read here is that module's own bytes.
    """
    stats = CoinStats()
    out_point_bytes, coin = _out_point_and_coin(_RECORDED["utxos"][0])
    stats.insert(out_point_bytes, coin)

    expected = MuHash3072()
    expected.insert(tx_out_ser(out_point_bytes, coin))
    assert stats.digest == expected.digest
    assert CoinStats(MuHash3072.deserialize(stats.muhash.serialize)).digest == (
        stats.digest
    )
