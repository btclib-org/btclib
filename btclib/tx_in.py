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

from dataclasses_json import DataClassJsonMixin, config

from . import script, varint
from .alias import BinaryData, ScriptToken, String
from .utils import bytesio_from_binarydata, token_or_string_to_printable

_OutPoint = TypeVar("_OutPoint", bound="OutPoint")


@dataclass
class OutPoint(DataClassJsonMixin):
    hash: bytes = field(
        metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex)
    )
    n: int

    @classmethod
    def deserialize(
        cls: Type[_OutPoint], data: BinaryData, assert_valid: bool = True
    ) -> _OutPoint:
        "Return an OutPoint from the first 36 bytes of the provided data."

        data = bytesio_from_binarydata(data)
        # 32 bytes, little endian
        hash = data.read(32)[::-1]
        # 4 bytes, little endian, interpreted as int
        n = int.from_bytes(data.read(4), "little")

        result = cls(hash, n)
        if assert_valid:
            result.assert_valid()
        return result

    def serialize(self, assert_valid: bool = True) -> bytes:
        "Return the 36 bytes serialization of the OutPoint."

        if assert_valid:
            self.assert_valid()

        # 32 bytes, little endian
        out = self.hash[::-1]
        # 4 bytes, little endian
        out += self.n.to_bytes(4, "little")
        return out

    @property
    def is_coinbase(self) -> bool:
        return (self.hash == b"\x00" * 32) and (self.n == 0xFFFFFFFF)

    def assert_valid(self) -> None:
        # must be a 32 bytes
        if len(self.hash) != 32:
            m = f"invalid OutPoint hash: {len(self.hash)}"
            m += " instead of 32 bytes"
            raise ValueError(m)
        # must be a 4-bytes int
        if self.n < 0 or self.n > 0xFFFFFFFF:
            raise ValueError(f"invalid OutPoint n: {self.n}")
        #
        if (self.hash == b"\x00" * 32) ^ (self.n == 0xFFFFFFFF):
            raise ValueError("invalid OutPoint")


_TxIn = TypeVar("_TxIn", bound="TxIn")


@dataclass
class TxIn(DataClassJsonMixin):
    prevout: OutPoint
    scriptSig: List[ScriptToken] = field(
        metadata=config(encoder=token_or_string_to_printable)
    )
    scriptSigHex: str
    nSequence: int
    txinwitness: List[String] = field(
        metadata=config(encoder=token_or_string_to_printable)
    )

    @classmethod
    def deserialize(
        cls: Type[_TxIn], data: BinaryData, assert_valid: bool = True
    ) -> _TxIn:
        stream = bytesio_from_binarydata(data)
        prevout = OutPoint.deserialize(stream)
        script_length = varint.decode(stream)
        scriptSig: List[ScriptToken] = []
        scriptSigHex = ""
        if prevout.is_coinbase:
            scriptSigHex = stream.read(script_length).hex()
        else:
            scriptSig = script.decode(stream.read(script_length))
        # 4 bytes, little endian, interpreted as int
        nSequence = int.from_bytes(stream.read(4), "little")
        txinwitness: List[String] = []

        tx_in = cls(
            prevout=prevout,
            scriptSig=scriptSig,
            scriptSigHex=scriptSigHex,
            nSequence=nSequence,
            txinwitness=txinwitness,
        )
        if assert_valid:
            tx_in.assert_valid()
        return tx_in

    def serialize(self, assert_valid: bool = True) -> bytes:

        if assert_valid:
            self.assert_valid()

        out = self.prevout.serialize()
        if self.prevout.is_coinbase:
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
