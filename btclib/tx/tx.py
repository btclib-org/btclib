#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Transaction (Tx) class.

Dataclass encapsulating version, lock_time,
vin (list[TxIn]), and vout (list[TxOut]).

- https://en.bitcoin.it/wiki/Transaction
- https://learnmeabitcoin.com/guide/coinbase-transaction
- https://bitcoin.stackexchange.com/questions/20721/what-is-the-format-of-the-coinbase-transaction

For TxIn.sequence and TX.lock_time see:
- https://developer.bitcoin.org/devguide/transactions.html
- https://medium.com/summa-technology/bitcoins-time-locks-27e0c362d7a1
- https://bitcoin.stackexchange.com/questions/40764/is-my-understanding-of-locktime-correct
- https://en.bitcoin.it/wiki/Timelock
"""

from __future__ import annotations

import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from io import SEEK_CUR
from math import ceil
from typing import Any

from btclib import var_int
from btclib.alias import BinaryData
from btclib.amount import _MAX_SATOSHI
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash256
from btclib.script.sig_ops import sig_op_count as script_sig_op_count
from btclib.script.witness import Witness
from btclib.tx.tx_in import TX_IN_COMPARES_WITNESS, TxIn
from btclib.tx.tx_out import TxOut
from btclib.utils import bytesio_from_binarydata

_SEGWIT_MARKER = b"\x00\x01"


def _assert_valid_coinbase(vin: Sequence[TxIn], *, is_coinbase: bool) -> None:
    """Raise an exception if the inputs disagree with the coinbase rule.

    The two cases are one check because a coinbase input -- the null
    outpoint -- is what makes a transaction a coinbase: either the
    transaction is one, and then its single input carries the block's
    script_sig, whose size consensus bounds; or it is not, and then no
    input may be a coinbase one.

    is_coinbase is passed rather than recomputed: `Tx.is_coinbase` is
    where "one input, and it is the null outpoint" is spelled, and a
    second spelling here is one that can drift from it.
    """
    if is_coinbase:
        if not 2 <= len(vin[0].script_sig) <= 100:
            raise BTClibValueError("Invalid coinbase script size")
        return

    for tx_in in vin:
        if tx_in.is_coinbase():
            raise BTClibValueError("coinbase input in a non-coinbase transaction")


@dataclass
class Tx:
    # 4 bytes, _signed_ little endian
    version: int
    # 0	Not locked
    #  < 500000000	Block number at which this transaction is unlocked
    # >= 500000000	UNIX timestamp at which this transaction is unlocked
    # If all TxIns have final (0xffffffff) sequence numbers then lock_time
    # is irrelevant. Otherwise, the transaction may not be added to a
    # block until after lock_time.
    # Set to the current block to prevent fee sniping.
    lock_time: int
    vin: list[TxIn]
    vout: list[TxOut]

    @property
    def nVersion(self) -> int:
        """Return the nVersion int for compatibility with CTransaction."""
        return self.version

    @property
    def nLockTime(self) -> int:
        """Return the nLockTime int for compatibility with CTransaction."""
        return self.lock_time

    @property
    def id(self) -> bytes:
        """Return the transaction id."""
        serialized_ = self.serialize(include_witness=False, check_validity=False)
        hash256_ = hash256(serialized_)
        return hash256_[::-1]

    @property
    def hash(self) -> bytes:
        """Return the transaction hash.

        It differs from tx_id for witness transactions.
        """
        serialized_ = self.serialize(include_witness=True, check_validity=False)
        hash256_ = hash256(serialized_)
        return hash256_[::-1]

    @property
    def size(self) -> int:
        """Return the transaction size."""
        return len(self.serialize(include_witness=True, check_validity=False))

    @property
    def vsize(self) -> int:
        """Return the virtual transaction size.

        It differs from size for witness transactions.
        """
        return ceil(self.weight / 4)

    @property
    def weight(self) -> int:
        no_wit = len(self.serialize(include_witness=False, check_validity=False)) * 3
        wit = len(self.serialize(include_witness=True, check_validity=False))
        return no_wit + wit

    @property
    def sig_op_count(self) -> int:
        """Return the legacy sigop count, Core's GetLegacySigOpCount.

        Every input's script_sig and every output's script_pub_key,
        counted from the bytes by `script.sig_ops.sig_op_count`: the P2SH
        and witness sigops Core adds in ConnectBlock need the outputs
        being spent, which a transaction does not carry. That module's
        docstring has what the shortfall is; the block rule this feeds,
        `Block.assert_valid_sig_op_count`, is the one it is enough for.
        """
        return sum(script_sig_op_count(tx_in.script_sig) for tx_in in self.vin) + sum(
            script_sig_op_count(tx_out.script_pub_key.script) for tx_out in self.vout
        )

    @property
    def vwitness(self) -> list[Witness]:
        return [tx_in.script_witness for tx_in in self.vin]

    def is_segwit(self) -> bool:
        # refer to tx_in, not tx_out
        return any(tx_in.is_segwit() for tx_in in self.vin)

    def is_coinbase(self) -> bool:
        return len(self.vin) == 1 and self.vin[0].is_coinbase()

    def __init__(
        self,
        version: int = 1,
        lock_time: int = 0,
        vin: Sequence[TxIn] | None = None,
        vout: Sequence[TxOut] | None = None,
        *,
        check_validity: bool = True,
    ) -> None:
        self.version = version
        self.lock_time = lock_time
        # https://docs.python.org/3/tutorial/controlflow.html#default-argument-values
        self.vin = list(vin) if vin else []
        self.vout = list(vout) if vout else []

        if check_validity:
            self.assert_valid()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Tx):
            return NotImplemented

        if not TX_IN_COMPARES_WITNESS and self.vwitness != other.vwitness:
            return False

        return (self.version, self.lock_time, self.vin, self.vout) == (
            other.version,
            other.lock_time,
            other.vin,
            other.vout,
        )

    def to_dict(
        self, *, check_validity: bool = True
    ) -> dict[str, str | int | list[Any]]:
        if check_validity:
            self.assert_valid()

        return {
            "txid": self.id.hex(),
            "hash": self.hash.hex(),
            "version": self.version,
            "size": self.size,
            "vsize": self.vsize,
            "weight": self.weight,
            "locktime": self.lock_time,
            "vin": [tx_in.to_dict(check_validity=False) for tx_in in self.vin],
            "vout": [tx_out.to_dict(check_validity=False) for tx_out in self.vout],
        }

    @classmethod
    def from_dict(
        cls: type[Tx], dict_: Mapping[str, Any], *, check_validity: bool = True
    ) -> Tx:
        return cls(
            dict_["version"],
            dict_["locktime"],
            [TxIn.from_dict(tx_in, check_validity=False) for tx_in in dict_["vin"]],
            [TxOut.from_dict(tx_out, check_validity=False) for tx_out in dict_["vout"]],
            check_validity=check_validity,
        )

    def assert_standard(self) -> None:
        self.assert_valid()

        # should be a 4-bytes __signed__ integer
        if not 0 < self.version <= 0x7FFFFFFF:
            raise BTClibValueError(f"invalid version: {self.version}")

    def assert_valid(self, *, unsigned_template: bool = False) -> None:
        """Assert that this is a valid transaction.

        unsigned_template=True drops the two rules a PSBT's global unsigned
        transaction cannot satisfy, and only those: at least one input and
        at least one output. Everything else still applies -- the version
        and lock time ranges, each input and output on its own, the
        MAX_MONEY bound on their sum.

        Those two rules are right for a transaction, Core's
        CheckTransaction rejecting an empty vin or vout, and wrong for a
        PSBT's: that one is incomplete by construction, which is the whole
        point of the format. BIP174 lists two zero-input PSBTs as valid
        and btclib refused both (issue 170).
        """
        _assert_valid_coinbase(self.vin, is_coinbase=self.is_coinbase())

        # must be a 4-bytes integer
        if not 0 <= self.version <= 0xFFFFFFFF:
            raise BTClibValueError(f"invalid version: {self.version}")

        # must be a 4-bytes int
        if not 0 <= self.lock_time <= 0xFFFFFFFF:
            raise BTClibValueError(f"invalid lock time: {self.lock_time}")

        if not unsigned_template and not self.vin:
            raise BTClibValueError("Missing inputs")
        for tx_in in self.vin:
            tx_in.assert_valid()

        if not unsigned_template and not self.vout:
            raise BTClibValueError("Missing outputs")
        for tx_out in self.vout:
            tx_out.assert_valid()

        # CheckTransaction bounds the outputs one by one and then their
        # sum, and the second check is not implied by the first: every
        # output can be within MoneyRange while the total is above it.
        # Only the sum of the outputs, as there, and not the fee: what
        # the inputs are worth is not in the transaction, and comparing
        # the two is verify_amounts' job, with the prevouts in hand
        total = sum(tx_out.value for tx_out in self.vout)
        if total > _MAX_SATOSHI:
            raise BTClibValueError(f"invalid total output amount: {total}")

    def serialize(self, include_witness: bool, *, check_validity: bool = True) -> bytes:
        if check_validity:
            self.assert_valid()

        segwit = include_witness and self.is_segwit()

        return b"".join(
            [
                self.version.to_bytes(4, byteorder="little", signed=False),
                _SEGWIT_MARKER if segwit else b"",
                var_int.serialize(len(self.vin)),
                b"".join(
                    tx_in.serialize(check_validity=check_validity) for tx_in in self.vin
                ),
                var_int.serialize(len(self.vout)),
                b"".join(
                    tx_out.serialize(check_validity=check_validity)
                    for tx_out in self.vout
                ),
                b"".join(
                    tx_in.script_witness.serialize(check_validity=check_validity)
                    for tx_in in self.vin
                )
                if segwit
                else b"",
                self.lock_time.to_bytes(4, byteorder="little", signed=False),
            ]
        )

    @classmethod
    def parse(
        cls: type[Tx],
        data: BinaryData,
        *,
        check_validity: bool = True,
    ) -> Tx:
        """Return a Tx by parsing binary data."""
        stream = bytesio_from_binarydata(data)

        # version is a signed int (int32_t) in bitcoin_core
        # However there are at least two transactions:
        # 35e79ee733fad376e76d16d1f10088273c2f4c2eaba1374a837378a88e530005
        # c659729a7fea5071361c2c1a68551ca2bf77679b27086cc415adeeb03852e369
        # where the version number is negative if it is considered as a signed
        # integer. As such in btclib the version is an UNSIGNED integer.
        # This has been discussed in: https://github.com/bitcoin/bitcoin/pull/16525
        version = int.from_bytes(stream.read(4), byteorder="little", signed=False)

        segwit = stream.read(2) == _SEGWIT_MARKER
        if not segwit:
            # Change stream position: seek to byte offset relative to position
            stream.seek(-2, SEEK_CUR)  # current position

        n = var_int.parse(stream)
        vin = [TxIn.parse(stream, check_validity=check_validity) for _ in range(n)]

        n = var_int.parse(stream)
        vout = [TxOut.parse(stream, check_validity=check_validity) for _ in range(n)]

        if segwit:
            for tx_in in vin:
                tx_in.script_witness = Witness.parse(
                    stream, check_validity=check_validity
                )

        lock_time = int.from_bytes(stream.read(4), byteorder="little", signed=False)

        return cls(version, lock_time, vin, vout, check_validity=check_validity)


def join_txs(
    txs: Sequence[Tx],
    enforce_same_version: bool,
    enforce_same_lock_time: bool,
    shuffle_inp: bool,
    shuffle_out: bool,
) -> Tx:
    """Join transactions into one, concatenating inputs and outputs.

    Outputs are concatenated and never merged, and no parameter asks for
    it: coalescing two outputs that pay the same script changes the
    output set, so it invalidates every signature already made over the
    old one -- and with the shuffle below the result would depend on the
    order the merge ran in. Summing two payments into one output is the
    caller's to do before signing.
    """
    version = max(tx.version for tx in txs)
    if enforce_same_version and any(tx.version != version for tx in txs):
        raise BTClibValueError("Version numbers are not the same")

    lock_time = max(tx.lock_time for tx in txs)
    if enforce_same_lock_time and any(tx.lock_time != lock_time for tx in txs):
        raise BTClibValueError("Lock times are not the same")

    if sum(len(tx.vin) for tx in txs) != len(
        {vin.serialize() for tx in txs for vin in tx.vin}
    ):
        raise BTClibValueError("common inputs")
    vin = [vin for tx in txs for vin in tx.vin]

    vout = [vout for tx in txs for vout in tx.vout]

    # avoid leaking matches between inputs and outputs
    if shuffle_inp:
        secrets.SystemRandom().shuffle(vin)
    if shuffle_out:
        secrets.SystemRandom().shuffle(vout)

    tx = Tx(version, lock_time, vin, vout)
    tx.assert_valid()
    return tx
