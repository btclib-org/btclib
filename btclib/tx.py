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

from typing import List, TypeVar, Type
from dataclasses import dataclass
from math import ceil

from . import varint
from .alias import Octets
from .tx_in import TxIn, witness_serialize, witness_deserialize
from .tx_out import TxOut
from .utils import binaryio_from_binarydata, bytes_from_octets, hash256

_Tx = TypeVar("_Tx", bound="Tx")


@dataclass
class Tx:
    nVersion: int
    nLockTime: int
    vin: List[TxIn]
    vout: List[TxOut]

    @classmethod
    def deserialize(cls: Type[_Tx], data: Octets) -> _Tx:
        data = bytes_from_octets(data)
        nVersion = int.from_bytes(data[:4], "little")
        data = data[4:]
        witness_flag = False
        if data[:2] == b"\x00\x01":
            witness_flag = True
            data = data[2:]
        stream = binaryio_from_binarydata(data)
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
        assert self.vin
        for tx_in in self.vin:
            tx_in.assert_valid()
        assert self.vout
        for tx_out in self.vout:
            tx_out.assert_valid()
