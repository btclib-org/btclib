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
from typing import List, Type, TypeVar

from dataclasses_json import DataClassJsonMixin

from . import varint
from .alias import BinaryData
from .exceptions import BTClibValueError
from .tx_in import TxIn, witness_deserialize, witness_serialize
from .tx_out import TxOut
from .utils import bytesio_from_binarydata, hash256

_Tx = TypeVar("_Tx", bound="Tx")


@dataclass
class Tx(DataClassJsonMixin):
    version: int = 0
    locktime: int = 0
    vin: List[TxIn] = field(default_factory=list)
    vout: List[TxOut] = field(default_factory=list)

    @classmethod
    def deserialize(cls: Type[_Tx], data: BinaryData, assert_valid: bool = True) -> _Tx:
        stream = bytesio_from_binarydata(data)

        tx = cls()
        tx.version = int.from_bytes(stream.read(4), "little")
        view: bytes = stream.getvalue()
        witness_flag = False
        if view[stream.tell() : stream.tell() + 2] == b"\x00\x01":
            witness_flag = True
            stream.read(2)

        input_count = varint.decode(stream)
        tx.vin = [TxIn.deserialize(stream) for _ in range(input_count)]

        output_count = varint.decode(stream)
        tx.vout = [TxOut.deserialize(stream) for _ in range(output_count)]

        if witness_flag:
            for tx_input in tx.vin:
                tx_input.txinwitness = witness_deserialize(stream)

        tx.locktime = int.from_bytes(stream.read(4), "little")

        if assert_valid:
            tx.assert_valid()
        return tx

    def serialize(
        self, include_witness: bool = True, assert_valid: bool = True
    ) -> bytes:

        if assert_valid:
            self.assert_valid()

        out = self.version.to_bytes(4, "little")
        witness_flag = False
        out += varint.encode(len(self.vin))
        for tx_input in self.vin:
            out += tx_input.serialize(assert_valid=assert_valid)
            if tx_input.txinwitness != []:
                witness_flag = True
        out += varint.encode(len(self.vout))
        for tx_output in self.vout:
            out += tx_output.serialize(assert_valid=assert_valid)
        if witness_flag and include_witness:
            for tx_input in self.vin:
                out += witness_serialize(tx_input.txinwitness)
        out += self.locktime.to_bytes(4, "little")
        if witness_flag and include_witness:
            out = out[:4] + b"\x00\x01" + out[4:]
        return out

    @property
    def txid(self) -> bytes:
        return hash256(self.serialize(False))[::-1]

    @property
    def hash(self) -> bytes:
        return hash256(self.serialize())[::-1]

    @property
    def size(self) -> int:
        return len(self.serialize())

    @property
    def weight(self) -> int:
        # check for assert_valid only once
        a = len(self.serialize(include_witness=False, assert_valid=True)) * 3
        b = len(self.serialize(include_witness=True, assert_valid=False))
        return a + b

    @property
    def vsize(self) -> int:
        self.assert_valid()
        return ceil(self.weight / 4)

    def assert_valid(self) -> None:
        if not self.vin:
            raise BTClibValueError("A transaction must have at least one input")
        for tx_in in self.vin:
            tx_in.assert_valid()
        if not self.vout:
            raise BTClibValueError("A transaction must have at least one output")
        for tx_out in self.vout:
            tx_out.assert_valid()

        # TODO check version and locktime
