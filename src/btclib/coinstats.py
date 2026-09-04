# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What `gettxoutsetinfo` reports about a UTXO set, as arithmetic.

Bitcoin Core's `CoinStatsIndex` (`src/index/coinstatsindex.cpp`, at
bitcoin/bitcoin@9be056a8a7, tag v31.1) maintains a MuHash commitment
to the unspent output set incrementally, and beside it the running
counters `m_transaction_output_count`, `m_total_amount` and
`m_bogo_size` the same way. `CoinStats` below is the commitment and
those counters together, and each of `insert` and `remove` is one
output's contribution to every one of them.

`btclib.muhash` is the accumulator and knows nothing about outputs;
what this module adds is the bitcoin on top of it -- which bytes an
output is committed to as, which outputs are committed to at all, and
what a counter counts. That split is why this is a module of its own:
`btclib.muhash` is the general construction, RFC 8439's own ChaCha20
block function included, and it would have to import the transaction
package to carry any of what is here.

The seam runs where `btclib.tx.coin` already put it for `Coin`: what is
here is a function of its arguments alone, and how a node keeps a
running total on disk is that node's own decision. So there is no
`serialize` and no `parse` for `CoinStats`, no walk of a chain, and no
undo log -- `insert` and `remove` are exact inverses on the same
arguments, in either order and regardless of what else went through
either meanwhile, which is what lets a caller undo a staged block
without having recorded what the accumulator and the counters held
before it.

## Reading a digest against a node

`gettxoutsetinfo`'s own `muhash` field is `digest` below with its bytes
reversed. `FinalizeHash` (`kernel/coinstats.cpp`) writes what
`MuHash3072::Finalize` gives into a `uint256`, and the rpc prints that
through `uint256::GetHex`, which is `uint256`'s display order and the
reverse of its serialization; `digest` is the serialization.

## What is committed to, and what is not

`btclib.script.is_unspendable` gates both `insert` and `remove`:
`CCoinsViewCache::AddCoin` (`coins.cpp:91`) returns without adding such
an output to Core's own set at all, so `ApplyCoinHash` never sees one
and no counter here ever counts one. The gate is here rather than left
to the caller because it is the difference between reproducing
`gettxoutsetinfo` and not, and because a caller that skips such an
output on the way in and not on the way out has an accumulator that no
longer cancels.

Two exclusions Core's own set makes are the caller's and not this
module's, both being facts about a chain rather than about an output:
the genesis block's coinbase, which is spendable-looking and
unspendable, and the coinbase of either mainnet block
`IsBIP30Unspendable` (`validation.cpp:6230-6234`) names by height and
hash, each duplicated verbatim by a later one.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from btclib.alias import Octets
from btclib.exceptions import BTClibValueError
from btclib.muhash import MuHash3072
from btclib.script.spendability import is_unspendable
from btclib.tx.coin import Coin
from btclib.utils import assert_type, bytes_from_octets

__all__ = [
    "CoinStats",
    "bogo_size",
    "tx_out_ser",
]

# what OutPoint.serialize writes: a 32-byte tx id and a 4-byte vout
_OUT_POINT_SIZE = 36

# GetBogoSize's own fixed part (kernel/coinstats.cpp:36-44), with Core's
# own labels: 32 txid, 4 vout index, 4 height and coinbase bit, 8 amount,
# 2 scriptPubKey length
_BOGO_FIXED = 32 + 4 + 4 + 8 + 2

# TxOutSer packs the height and the coinbase bit into one uint32, so the
# height it can carry stops one bit short of that width
_MAX_PACKED_HEIGHT = (1 << 31) - 1


def bogo_size(script_pub_key: Octets) -> int:
    """Return Core's `GetBogoSize` for an output with such a script.

    A fixed part plus the script's own length, and no output's actual
    size: Core's own comment over it reads "Database-independent metric
    indicating the UTXO set size". The fixed part allows a constant for
    the script's length marker rather than measuring the `var_int` the
    wire writes it behind, and allows nothing at all for what a store
    compresses an output down to. It is what `gettxoutsetinfo` answers
    as `bogosize`, and nothing else reproduces it.
    """
    return _bogo_size(bytes_from_octets(script_pub_key))


def _bogo_size(script_pub_key: bytes) -> int:
    """Return `GetBogoSize`, on a script already read as bytes."""
    return _BOGO_FIXED + len(script_pub_key)


def tx_out_ser(out_point_bytes: Octets, coin: Coin) -> bytes:
    """Return the bytes a coin is committed to as -- Core's `TxOutSer`.

    `TxOutSer` (`kernel/coinstats.cpp:46-52`) writes the outpoint, then
    `(height << 1) | coinbase` as a fixed 4-byte little-endian `uint32`,
    then the output. The fixed width is the whole of what a caller
    cannot guess: an outpoint, that packed number and an output are
    also what a UTXO store keeps, and a store is free to write the
    packed number as a `var_int` for density -- the same number, a
    different encoding, and a different digest.

    `out_point_bytes` rather than an `OutPoint`, because a caller with a
    UTXO set already holds the outpoint in exactly this form -- it is
    what keys the set -- and `OutPoint.serialize` is what writes it.
    """
    return _tx_out_ser(_checked_out_point(out_point_bytes, coin), coin)


def _tx_out_ser(out_point_bytes: bytes, coin: Coin) -> bytes:
    """Return `TxOutSer`, on arguments already checked."""
    packed = (coin.height << 1) | int(coin.is_coinbase)
    return (
        out_point_bytes
        + packed.to_bytes(4, "little")
        + coin.tx_out.serialize(check_validity=False)
    )


def _checked_out_point(out_point_bytes: Octets, coin: Coin) -> bytes:
    """Return the outpoint as bytes, both arguments having been checked."""
    out_point_bytes = bytes_from_octets(out_point_bytes, _OUT_POINT_SIZE)
    assert_type(coin, Coin, "coin")
    coin.assert_valid()
    # a height the uint32 above cannot hold would leave as an
    # OverflowError, from outside the library's exception contract
    if coin.height > _MAX_PACKED_HEIGHT:
        raise BTClibValueError(f"invalid height: {coin.height}")
    return out_point_bytes


@dataclass
class CoinStats:
    """The MuHash commitment to a UTXO set, and the counters beside it.

    The defaults are the empty set, which is what a caller starting from
    the genesis block wants; a caller resuming from a store hands back
    what it kept.
    """

    muhash: MuHash3072 = field(default_factory=MuHash3072)
    transaction_output_count: int = 0
    total_amount: int = 0  # denominated in satoshi
    bogo_size: int = 0

    def insert(self, out_point_bytes: Octets, coin: Coin) -> None:
        """Count one coin everywhere; skip an unspendable output.

        Nothing is returned and nothing has to be kept: `remove` skips
        exactly what this skips, so undoing a staged block is the same
        walk the other way round, and a caller that wants to know asks
        `btclib.script.is_unspendable` itself.
        """
        checked = _checked_out_point(out_point_bytes, coin)
        script = coin.tx_out.script_pub_key.script
        if is_unspendable(script):
            return
        self.muhash.insert(_tx_out_ser(checked, coin))
        self.transaction_output_count += 1
        self.total_amount += coin.tx_out.value
        self.bogo_size += _bogo_size(script)

    def remove(self, out_point_bytes: Octets, coin: Coin) -> None:
        """Uncount one coin everywhere -- `insert`'s exact inverse."""
        checked = _checked_out_point(out_point_bytes, coin)
        script = coin.tx_out.script_pub_key.script
        if is_unspendable(script):
            return
        self.muhash.remove(_tx_out_ser(checked, coin))
        self.transaction_output_count -= 1
        self.total_amount -= coin.tx_out.value
        self.bogo_size -= _bogo_size(script)

    @property
    def digest(self) -> bytes:
        """Return the 32-byte commitment, `MuHash3072.digest`'s own bytes.

        A property and not a call, as on the accumulator it reads, and
        in its byte order: the module docstring's "Reading a digest
        against a node" is what a `gettxoutsetinfo` reply has to be
        reversed against.
        """
        return self.muhash.digest
