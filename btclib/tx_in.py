#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from typing import List, TypeVar, Type
from dataclasses import dataclass

from . import script, varint
from .alias import Octets, Token
from .utils import bytes_from_octets

_OutPoint = TypeVar("_OutPoint", bound="OutPoint")


@dataclass
class OutPoint:
    hash: str
    n: int

    @classmethod
    def deserialize(cls: Type[_OutPoint], data: Octets) -> _OutPoint:
        data = bytes_from_octets(data)
        hash = data[:32][::-1].hex()
        n = int.from_bytes(data[32:36], "little")
        point = cls(hash, n)
        return point

    def serialize(self) -> bytes:
        out = bytes.fromhex(self.hash)[::-1]
        out += self.n.to_bytes(4, "little")
        return out

    def assert_valid(self) -> None:
        null_txid = "00" * 32
        null_vout = 256 ** 4 - 1
        if (self.hash == null_txid) ^ (self.n == null_vout):
            raise ValueError("invalid tx_in")


_TxIn = TypeVar("_TxIn", bound="TxIn")


@dataclass
class TxIn:
    prevout: OutPoint
    scriptSig: List[Token]
    scriptSigHex: str
    nSequence: int
    txinwitness: List[str]

    @classmethod
    def deserialize(cls: Type[_TxIn], data: Octets) -> _TxIn:

        data = bytes_from_octets(data)

        prevout = OutPoint.deserialize(data)

        is_coinbase = False
        if prevout.hash == "00" * 32 and prevout.n == 256 ** 4 - 1:
            is_coinbase = True

        script_length = varint.decode(data[36:])
        data = data[36 + len(varint.encode(script_length)) :]

        scriptSig: List[Token] = []
        scriptSigHex = ""
        if is_coinbase:
            scriptSigHex = data[:script_length].hex()
        else:
            scriptSig = script.decode(data[:script_length])

        nSequence = int.from_bytes(data[script_length : script_length + 4], "little")
        txinwitness: List[str] = []

        tx_in = cls(
            prevout=prevout,
            scriptSig=scriptSig,
            scriptSigHex=scriptSigHex,
            nSequence=nSequence,
            txinwitness=txinwitness,
        )

        tx_in.assert_valid()
        return tx_in

    def serialize(self) -> bytes:
        out = self.prevout.serialize()
        if self.prevout.hash == "00" * 32 and self.prevout.n == 256 ** 4 - 1:
            script_bytes = bytes.fromhex(self.scriptSigHex)
        else:
            script_bytes = script.encode(self.scriptSig)
        out += varint.encode(len(script_bytes))
        out += script_bytes
        out += self.nSequence.to_bytes(4, "little")
        return out

    def assert_valid(self) -> None:
        self.prevout.assert_valid()


def witness_deserialize(data: Octets) -> List[str]:

    data = bytes_from_octets(data)

    witness: List[str] = []

    witness_count = varint.decode(data)
    data = data[len(varint.encode(witness_count)) :]
    for _ in range(witness_count):
        witness_len = varint.decode(data)
        data = data[len(varint.encode(witness_len)) :]
        witness.append(data[:witness_len].hex())
        data = data[witness_len:]

    return witness


def witness_serialize(witness: List[str]) -> bytes:

    out = b""

    witness_count = len(witness)
    out += varint.encode(witness_count)
    for i in range(witness_count):
        witness_bytes = bytes.fromhex(witness[i])
        out += varint.encode(len(witness_bytes))
        out += witness_bytes

    return out
