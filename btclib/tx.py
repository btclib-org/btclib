#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
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
"""

from dataclasses import dataclass, field
from math import ceil
from typing import Dict, List, Type, TypeVar

from dataclasses_json import DataClassJsonMixin, config
from dataclasses_json.core import Json

from . import varint
from .alias import BinaryData
from .exceptions import BTClibValueError
from .tx_in import TxIn
from .tx_out import TxOut
from .utils import bytesio_from_binarydata, hash256
from .witness import Witness

_SEGWIT_MARKER = b"\x00\x01"

_Tx = TypeVar("_Tx", bound="Tx")


@dataclass
class Tx(DataClassJsonMixin):
    # 4 bytes, unsigned little endian
    version: int = 0
    vin: List[TxIn] = field(default_factory=list)
    vout: List[TxOut] = field(default_factory=list)
    # 4 bytes, unsigned little endian
    locktime: int = 0
    # private data member used only for to_dict
    # use the corresponding public properties instead
    _txid: bytes = field(
        default=b"",
        init=False,
        repr=False,
        compare=False,
        metadata=config(
            encoder=lambda v: v.hex(), decoder=bytes.fromhex, field_name="txid"
        ),
    )
    _size: int = field(
        default=-1,
        init=False,
        repr=False,
        compare=False,
        metadata=config(field_name="size"),
    )
    _weight: int = field(
        default=-1,
        init=False,
        repr=False,
        compare=False,
        metadata=config(field_name="weight"),
    )
    _vsize: int = field(
        default=-1,
        init=False,
        repr=False,
        compare=False,
        metadata=config(field_name="vsize"),
    )
    # TODO: add fee when a tx fecther will be available

    def _set_properties(self) -> None:
        self._txid = self.txid
        self._size = self.size
        self._weight = self.weight
        self._vsize = self.vsize

    def to_dict(self, encode_json=False) -> Dict[str, Json]:
        self._set_properties()
        return super().to_dict(encode_json)

    @property
    def txid(self) -> bytes:
        serialized_ = self.serialize(include_witness=False, assert_valid=False)
        hash256_ = hash256(serialized_)
        return hash256_[::-1]

    @property
    def size(self) -> int:
        return len(self.serialize(include_witness=True, assert_valid=False))

    @property
    def weight(self) -> int:
        a = len(self.serialize(include_witness=False, assert_valid=False)) * 3
        b = len(self.serialize(include_witness=True, assert_valid=False))
        return a + b

    @property
    def vsize(self) -> int:
        return ceil(self.weight / 4)

    def hash(self) -> bytes:
        serialized_ = self.serialize(include_witness=True, assert_valid=False)
        hash256_ = hash256(serialized_)
        return hash256_[::-1]

    def segwit(self) -> bool:
        return any(tx_in.witness for tx_in in self.vin)

    def is_coinbase(self) -> bool:
        return len(self.vin) == 1 and self.vin[0].is_coinbase()

    def assert_valid(self) -> None:

        # TODO check version

        if not self.vin:
            raise BTClibValueError("transaction must have at least one input")
        for tx_in in self.vin:
            tx_in.assert_valid()
        if not self.vout:
            raise BTClibValueError("transaction must have at least one output")
        for tx_out in self.vout:
            tx_out.assert_valid()

        # TODO check locktime

        self._set_properties()

    def serialize(self, include_witness: bool, assert_valid: bool = True) -> bytes:

        if assert_valid:
            self.assert_valid()

        segwit = include_witness and self.segwit()

        out = self.version.to_bytes(4, byteorder="little", signed=False)
        out += _SEGWIT_MARKER if segwit else b""
        out += varint.encode(len(self.vin))
        out += b"".join(tx_in.serialize(assert_valid) for tx_in in self.vin)
        out += varint.encode(len(self.vout))
        out += b"".join(tx_out.serialize(assert_valid) for tx_out in self.vout)
        if segwit:
            out += b"".join(tx_in.witness.serialize(assert_valid) for tx_in in self.vin)
        out += self.locktime.to_bytes(4, byteorder="little", signed=False)

        return out

    @classmethod
    def deserialize(cls: Type[_Tx], data: BinaryData, assert_valid: bool = True) -> _Tx:

        stream = bytesio_from_binarydata(data)

        tx = cls()

        tx.version = int.from_bytes(stream.read(4), byteorder="little", signed=False)

        segwit = stream.read(2) == _SEGWIT_MARKER
        if not segwit:
            # Change stream position
            # Seek to byte offset relative to position indicated by whence
            whence = 1  # current position
            stream.seek(-2, whence)

        n = varint.decode(stream)
        tx.vin = [TxIn.deserialize(stream) for _ in range(n)]

        n = varint.decode(stream)
        tx.vout = [TxOut.deserialize(stream) for _ in range(n)]

        if segwit:
            for tx_in in tx.vin:
                tx_in.witness = Witness().deserialize(stream)

        tx.locktime = int.from_bytes(stream.read(4), byteorder="little", signed=False)

        if assert_valid:
            tx.assert_valid()
        return tx
