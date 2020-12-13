#!/usr/bin/env python3

# Copyright (C) 2020-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Bitcoin Transaction.

https://en.bitcoin.it/wiki/Transaction
https://learnmeabitcoin.com/guide/coinbase-transaction
https://bitcoin.stackexchange.com/questions/20721/what-is-the-format-of-the-coinbase-transaction

For TxIn.sequence and TX.lock_time see:
https://developer.bitcoin.org/devguide/transactions.html
https://medium.com/summa-technology/bitcoins-time-locks-27e0c362d7a1
https://bitcoin.stackexchange.com/questions/40764/is-my-understanding-of-locktime-correct
https://en.bitcoin.it/wiki/Timelock

"""

from dataclasses import InitVar, dataclass, field
from io import SEEK_CUR
from math import ceil
from typing import Dict, List, Type, TypeVar

from dataclasses_json import DataClassJsonMixin, config
from dataclasses_json.core import Json

from . import var_int
from .alias import BinaryData
from .exceptions import BTClibValueError
from .tx_in import _TX_IN_COMPARES_WITNESS, TxIn
from .tx_out import TxOut
from .utils import bytesio_from_binarydata, hash256
from .witness import Witness

_SEGWIT_MARKER = b"\x00\x01"

_Tx = TypeVar("_Tx", bound="Tx")


@dataclass
class Tx(DataClassJsonMixin):
    # private data members are used only for to_dict
    # use the corresponding public properties instead
    _tx_id: bytes = field(
        default=b"",
        init=False,
        repr=False,
        compare=False,
        metadata=config(
            encoder=lambda v: v.hex(), decoder=bytes.fromhex, field_name="txid"
        ),
    )
    _hash: bytes = field(
        default=b"",
        init=False,
        repr=False,
        compare=False,
        metadata=config(
            encoder=lambda v: v.hex(), decoder=bytes.fromhex, field_name="hash"
        ),
    )
    # 4 bytes, unsigned little endian
    version: int = 1
    _size: int = field(
        default=-1,
        init=False,
        repr=False,
        compare=False,
        metadata=config(field_name="size"),
    )
    _vsize: int = field(
        default=-1,
        init=False,
        repr=False,
        compare=False,
        metadata=config(field_name="vsize"),
    )
    _weight: int = field(
        default=-1,
        init=False,
        repr=False,
        compare=False,
        metadata=config(field_name="weight"),
    )
    # 0	Not locked
    #  < 500000000	Block number at which this transaction is unlocked
    # >= 500000000	UNIX timestamp at which this transaction is unlocked
    # If all TxIns have final (0xffffffff) sequence numbers then lock_time is irrelevant.
    # Otherwise, the transaction may not be added to a block until after lock_time.
    # Set to the current block to prevent fee sniping.
    lock_time: int = field(
        default=0,
        metadata=config(field_name="locktime"),
    )
    vin: List[TxIn] = field(default_factory=list)
    vout: List[TxOut] = field(default_factory=list)
    # TODO: add fee when a tx fetcher will be available
    check_validity: InitVar[bool] = True

    def __post_init__(self, check_validity: bool) -> None:
        if check_validity:
            self.assert_valid()

    def __eq__(self, other) -> bool:
        if not isinstance(other, Tx):
            return NotImplemented  # pragma: no cover

        if not _TX_IN_COMPARES_WITNESS and self.vwitness != other.vwitness:
            return False  # pragma: no cover

        return (self.version, self.lock_time, self.vin, self.vout) == (
            other.version,
            other.lock_time,
            other.vin,
            other.vout,
        )

    def _set_properties(self) -> None:
        self._tx_id = self.tx_id
        self._hash = self.hash
        self._size = self.size
        self._vsize = self.vsize
        self._weight = self.weight

    def to_dict(self, encode_json=False) -> Dict[str, Json]:
        self._set_properties()
        return super().to_dict(encode_json)

    @property
    def nVersion(self) -> int:  # pylint: disable=invalid-name
        "Return the nVersion int for compatibility with CTransaction."
        return self.version

    @property
    def nLockTime(self) -> int:  # pylint: disable=invalid-name
        "Return the nLockTime int for compatibility with CTransaction."
        return self.lock_time

    @property
    def tx_id(self) -> bytes:
        serialized_ = self.serialize(include_witness=False, check_validity=False)
        hash256_ = hash256(serialized_)
        return hash256_[::-1]

    @property
    def hash(self) -> bytes:
        serialized_ = self.serialize(include_witness=True, check_validity=False)
        hash256_ = hash256(serialized_)
        return hash256_[::-1]

    @property
    def size(self) -> int:
        return len(self.serialize(include_witness=True, check_validity=False))

    @property
    def vsize(self) -> int:
        return ceil(self.weight / 4)

    @property
    def weight(self) -> int:
        no_wit = len(self.serialize(include_witness=False, check_validity=False)) * 3
        wit = len(self.serialize(include_witness=True, check_validity=False))
        return no_wit + wit

    @property
    def vwitness(self) -> List[Witness]:
        return [tx_in.script_witness for tx_in in self.vin]

    def is_segwit(self) -> bool:
        # refer to tx_in, not tx_out
        return any(tx_in.is_segwit() for tx_in in self.vin)

    def is_coinbase(self) -> bool:
        return len(self.vin) == 1 and self.vin[0].is_coinbase()

    def assert_valid(self) -> None:

        # must be a 4-bytes int
        if not 0 < self.version <= 0xFFFFFFFF:
            raise BTClibValueError(f"invalid version: {self.version}")

        # must be a 4-bytes int
        if not 0 <= self.lock_time <= 0xFFFFFFFF:
            raise BTClibValueError(f"invalid lock time: {self.lock_time}")

        for tx_in in self.vin:
            tx_in.assert_valid()

        for tx_out in self.vout:
            tx_out.assert_valid()

        self._set_properties()

    def serialize(self, include_witness: bool, check_validity: bool = True) -> bytes:

        if check_validity:
            self.assert_valid()

        segwit = include_witness and self.is_segwit()

        out = self.version.to_bytes(4, byteorder="little", signed=False)
        out += _SEGWIT_MARKER if segwit else b""
        out += var_int.serialize(len(self.vin))
        out += b"".join(tx_in.serialize(check_validity) for tx_in in self.vin)
        out += var_int.serialize(len(self.vout))
        out += b"".join(tx_out.serialize(check_validity) for tx_out in self.vout)
        if segwit:
            out += b"".join(
                tx_in.script_witness.serialize(check_validity) for tx_in in self.vin
            )
        out += self.lock_time.to_bytes(4, byteorder="little", signed=False)

        return out

    @classmethod
    def deserialize(
        cls: Type[_Tx], data: BinaryData, check_validity: bool = True
    ) -> _Tx:
        "Return a Tx by parsing binary data."

        stream = bytesio_from_binarydata(data)

        version = int.from_bytes(stream.read(4), byteorder="little", signed=False)

        segwit = stream.read(2) == _SEGWIT_MARKER
        if not segwit:
            # Change stream position: seek to byte offset relative to position
            stream.seek(-2, SEEK_CUR)  # current position

        n = var_int.deserialize(stream)
        vin = [TxIn.deserialize(stream) for _ in range(n)]

        n = var_int.deserialize(stream)
        vout = [TxOut.deserialize(stream) for _ in range(n)]

        if segwit:
            for tx_in in vin:
                tx_in.script_witness = Witness.deserialize(stream, check_validity)

        lock_time = int.from_bytes(stream.read(4), byteorder="little", signed=False)

        return cls(version, lock_time, vin, vout, check_validity)
