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

from . import varbytes, varint
from .alias import BinaryData
from .exceptions import BTClibValueError
from .utils import bytesio_from_binarydata

_OutPoint = TypeVar("_OutPoint", bound="OutPoint")


@dataclass
class OutPoint(DataClassJsonMixin):
    txid: bytes = field(
        default=b"\x00" * 32,
        metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex),
    )
    vout: int = 0xFFFFFFFF

    @classmethod
    def deserialize(
        cls: Type[_OutPoint], data: BinaryData, assert_valid: bool = True
    ) -> _OutPoint:
        "Return an OutPoint from the first 36 bytes of the provided data."

        data = bytesio_from_binarydata(data)
        # 32 bytes, little endian
        txid = data.read(32)[::-1]
        # 4 bytes, little endian, interpreted as int
        vout = int.from_bytes(data.read(4), "little")

        result = cls(txid, vout)
        if assert_valid:
            result.assert_valid()
        return result

    def serialize(self, assert_valid: bool = True) -> bytes:
        "Return the 36 bytes serialization of the OutPoint."

        if assert_valid:
            self.assert_valid()

        # 32 bytes, little endian
        out = self.txid[::-1]
        # 4 bytes, little endian
        out += self.vout.to_bytes(4, "little")
        return out

    @property
    def is_coinbase(self) -> bool:
        self.assert_valid()
        return (self.txid == b"\x00" * 32) and (self.vout == 0xFFFFFFFF)

    def assert_valid(self) -> None:
        # must be a 32 bytes
        if len(self.txid) != 32:
            m = f"invalid OutPoint txid: {len(self.txid)}"
            m += " instead of 32 bytes"
            raise BTClibValueError(m)
        # must be a 4-bytes int
        if self.vout < 0:
            raise BTClibValueError(f"negative OutPoint vout: {self.vout}")
        if self.vout > 0xFFFFFFFF:
            raise BTClibValueError(f"OutPoint vout too high: {hex(self.vout)}")
        # not a coinbase, not a regular OutPoint
        if (self.txid == b"\x00" * 32) ^ (self.vout == 0xFFFFFFFF):
            raise BTClibValueError("invalid OutPoint")


_TxIn = TypeVar("_TxIn", bound="TxIn")


@dataclass
class TxIn(DataClassJsonMixin):
    prevout: OutPoint
    # TODO make it { "asm": "", "hex": "" }
    script_sig: bytes = field(
        metadata=config(
            field_name="scriptSig", encoder=lambda v: v.hex(), decoder=bytes.fromhex
        )
    )
    sequence: int
    txinwitness: List[bytes] = field(
        metadata=config(
            encoder=lambda val: [v.hex() for v in val],
            decoder=lambda val: [bytes.fromhex(v) for v in val],
        )
    )

    @classmethod
    def deserialize(
        cls: Type[_TxIn], data: BinaryData, assert_valid: bool = True
    ) -> _TxIn:

        stream = bytesio_from_binarydata(data)

        prevout = OutPoint.deserialize(stream)

        script_sig = varbytes.decode(stream)

        # 4 bytes, little endian, interpreted as int
        sequence = int.from_bytes(stream.read(4), "little")

        tx_in = cls(
            prevout=prevout,
            script_sig=script_sig,
            sequence=sequence,
            txinwitness=[],
        )
        if assert_valid:
            tx_in.assert_valid()
        return tx_in

    def serialize(self, assert_valid: bool = True) -> bytes:

        if assert_valid:
            self.assert_valid()

        out = self.prevout.serialize()
        out += varbytes.encode(self.script_sig)
        out += self.sequence.to_bytes(4, "little")
        return out

    def assert_valid(self) -> None:
        self.prevout.assert_valid()
        # TODO: empty script_sig is valid (add non-regression test)


def witness_deserialize(data: BinaryData) -> List[bytes]:
    stream = bytesio_from_binarydata(data)
    n = varint.decode(stream)
    return [varbytes.decode(stream) for _ in range(n)]


def witness_serialize(witness: List[bytes]) -> bytes:
    out = varint.encode(len(witness))
    return out + b"".join([varbytes.encode(w) for w in witness])
