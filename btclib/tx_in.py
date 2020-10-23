#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from dataclasses import dataclass, field
from typing import List, Type, TypeVar

from dataclasses_json import config, dataclass_json

from . import script, varint
from .alias import BinaryData, String, Token
from .utils import bytesio_from_binarydata, token_or_string_to_printable

_OutPoint = TypeVar("_OutPoint", bound="OutPoint")


@dataclass_json
@dataclass
class OutPoint:
    hash: str
    n: int

    @classmethod
    def deserialize(cls: Type[_OutPoint], data: BinaryData) -> _OutPoint:
        data = bytesio_from_binarydata(data)
        hash = data.read(32)[::-1].hex()
        n = int.from_bytes(data.read(4), "little")
        return cls(hash, n)

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


@dataclass_json
@dataclass
class TxIn:
    prevout: OutPoint
    scriptSig: List[Token] = field(
        metadata=config(encoder=token_or_string_to_printable)
    )
    scriptSigHex: str
    nSequence: int
    txinwitness: List[String] = field(
        metadata=config(encoder=token_or_string_to_printable)
    )

    @classmethod
    def deserialize(cls: Type[_TxIn], data: BinaryData) -> _TxIn:
        stream = bytesio_from_binarydata(data)
        prevout = OutPoint.deserialize(stream)
        is_coinbase = False
        if prevout.hash == "00" * 32 and prevout.n == 256 ** 4 - 1:
            is_coinbase = True
        script_length = varint.decode(stream)
        scriptSig: List[Token] = []
        scriptSigHex = ""
        if is_coinbase:
            scriptSigHex = stream.read(script_length).hex()
        else:
            scriptSig = script.decode(stream.read(script_length))
        nSequence = int.from_bytes(stream.read(4), "little")
        txinwitness: List[String] = []
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
            out += varint.encode(len(self.scriptSigHex) // 2)
            out += bytes.fromhex(self.scriptSigHex)
        else:
            out += script.serialize(self.scriptSig)
        out += self.nSequence.to_bytes(4, "little")
        return out

    def assert_valid(self) -> None:
        self.prevout.assert_valid()


def witness_deserialize(data: BinaryData) -> List[String]:
    stream = bytesio_from_binarydata(data)
    witness: List[String] = []
    witness_count = varint.decode(stream)
    for _ in range(witness_count):
        witness_len = varint.decode(stream)
        witness.append(stream.read(witness_len).hex())
    return witness


def witness_serialize(witness: List[String]) -> bytes:
    witness_str = []
    for token in witness:
        if isinstance(token, bytes):
            witness_str.append(token.hex())
        else:
            witness_str.append(token)

    out = b""
    witness_count = len(witness_str)
    out += varint.encode(witness_count)
    for i in range(witness_count):
        witness_bytes = bytes.fromhex(witness_str[i])
        out += varint.encode(len(witness_bytes))
        out += witness_bytes
    return out
