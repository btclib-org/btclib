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

from dataclasses import dataclass
from math import ceil
from typing import List, Type, TypeVar

from . import varint
from .alias import BinaryData
from .tx_in import TxIn, witness_deserialize, witness_serialize
from .tx_out import TxOut
from .utils import bytesio_from_binarydata, hash256

_Tx = TypeVar("_Tx", bound="Tx")


@dataclass
class Tx:
    nVersion: int
    nLockTime: int
    vin: List[TxIn]
    vout: List[TxOut]

    @classmethod
    def deserialize(cls: Type[_Tx], data: BinaryData) -> _Tx:
        stream = bytesio_from_binarydata(data)
        nVersion = int.from_bytes(stream.read(4), "little")
        view: bytes = stream.getvalue()
        witness_flag = False
        if view[stream.tell() : stream.tell() + 2] == b"\x00\x01":
            witness_flag = True
            stream.read(2)
        input_count = varint.decode(stream)
        vin: List[TxIn] = []
        for _ in range(input_count):
            tx_input = TxIn.deserialize(stream)
            vin.append(tx_input)
        output_count = varint.decode(stream)
        vout: List[TxOut] = []
        for _ in range(output_count):
            tx_output = TxOut.deserialize(stream)
            vout.append(tx_output)
        if witness_flag:
            for tx_input in vin:
                witness = witness_deserialize(stream)
                tx_input.txinwitness = witness
        nLockTime = int.from_bytes(stream.read(4), "little")
        tx = cls(nVersion=nVersion, nLockTime=nLockTime, vin=vin, vout=vout)
        tx.assert_valid()
        return tx

    def serialize(self, include_witness: bool = True) -> bytes:
        out = self.nVersion.to_bytes(4, "little")
        witness_flag = False
        out += varint.encode(len(self.vin))
        for tx_input in self.vin:
            out += tx_input.serialize()
            if tx_input.txinwitness != []:
                witness_flag = True
        out += varint.encode(len(self.vout))
        for tx_output in self.vout:
            out += tx_output.serialize()
        if witness_flag and include_witness:
            for tx_input in self.vin:
                out += witness_serialize(tx_input.txinwitness)
        out += self.nLockTime.to_bytes(4, "little")
        if witness_flag and include_witness:
            out = out[:4] + b"\x00\x01" + out[4:]
        return out

    @property
    def txid(self) -> str:
        return hash256(self.serialize(False))[::-1].hex()

    @property
    def hash(self) -> str:
        return hash256(self.serialize())[::-1].hex()

    @property
    def size(self) -> int:
        return len(self.serialize())

    @property
    def weight(self) -> int:
        return len(self.serialize(False)) * 3 + len(self.serialize())

    @property
    def vsize(self) -> int:
        return ceil(self.weight / 4)

    def assert_valid(self) -> None:
        if not self.vin:
            raise ValueError("A transaction must have at least one input")
        for tx_in in self.vin:
            tx_in.assert_valid()
        if not self.vout:
            raise ValueError("A transaction must have at least one output")
        for tx_out in self.vout:
            tx_out.assert_valid()
