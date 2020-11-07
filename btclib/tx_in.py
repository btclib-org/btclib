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

from . import varint
from .alias import BinaryData
from .utils import bytesio_from_binarydata

_OutPoint = TypeVar("_OutPoint", bound="OutPoint")


@dataclass
class OutPoint(DataClassJsonMixin):
    hash: bytes = field(
        default=b"\x00" * 32,
        metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex),
    )
    n: int = 0xFFFFFFFF

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
        if self.n < 0:
            raise ValueError(f"negative OutPoint n: {self.n}")
        if self.n > 0xFFFFFFFF:
            raise ValueError(f"OutPoint n too high: {hex(self.n)}")
        # not a coinbase, not a regular OutPoint
        if (self.hash == b"\x00" * 32) ^ (self.n == 0xFFFFFFFF):
            raise ValueError("invalid OutPoint")


_TxIn = TypeVar("_TxIn", bound="TxIn")


@dataclass
class TxIn(DataClassJsonMixin):
    prevout: OutPoint
    scriptSig: bytes = field(
        metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex)
    )
    nSequence: int
    txinwitness: List[bytes] = field(
        metadata=config(encoder=lambda val: [v.hex() for v in val])
    )

    @classmethod
    def deserialize(
        cls: Type[_TxIn], data: BinaryData, assert_valid: bool = True
    ) -> _TxIn:

        stream = bytesio_from_binarydata(data)

        prevout = OutPoint.deserialize(stream)

        scriptSig = stream.read(varint.decode(stream))

        # 4 bytes, little endian, interpreted as int
        nSequence = int.from_bytes(stream.read(4), "little")

        tx_in = cls(
            prevout=prevout,
            scriptSig=scriptSig,
            nSequence=nSequence,
            txinwitness=[],
        )
        if assert_valid:
            tx_in.assert_valid()
        return tx_in

    def serialize(self, assert_valid: bool = True) -> bytes:

        if assert_valid:
            self.assert_valid()

        out = self.prevout.serialize()
        out += varint.encode(len(self.scriptSig)) + self.scriptSig
        out += self.nSequence.to_bytes(4, "little")
        return out

    def assert_valid(self) -> None:
        self.prevout.assert_valid()
        # TODO: empty scriptSig is valid (add non-regression test)


def witness_deserialize(data: BinaryData) -> List[bytes]:
    stream = bytesio_from_binarydata(data)
    n = varint.decode(stream)
    return [stream.read(varint.decode(stream)) for _ in range(n)]


def witness_serialize(witness: List[bytes]) -> bytes:
    out = varint.encode(len(witness))
    return out + b"".join([(varint.encode(len(w)) + w) for w in witness])
