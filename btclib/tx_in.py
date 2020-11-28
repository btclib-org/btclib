#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from dataclasses import dataclass, field
from typing import Type, TypeVar

from dataclasses_json import DataClassJsonMixin, config

from . import varbytes
from .alias import BinaryData
from .exceptions import BTClibValueError
from .utils import bytesio_from_binarydata
from .witness import Witness

_OutPoint = TypeVar("_OutPoint", bound="OutPoint")


@dataclass
class OutPoint(DataClassJsonMixin):
    txid: bytes = field(
        default=b"\x00" * 32,
        metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex),
    )
    # 4 bytes, unsigned little endian
    vout: int = -1
    # add value and script_pubkey when tx fetcher will be available

    def is_coinbase(self) -> bool:
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

    def serialize(self, assert_valid: bool = True) -> bytes:
        "Return the 36 bytes serialization of the OutPoint."

        if assert_valid:
            self.assert_valid()

        # 32 bytes, little endian
        out = self.txid[::-1]
        # 4 bytes, little endian
        out += self.vout.to_bytes(4, "little")
        return out

    @classmethod
    def deserialize(
        cls: Type[_OutPoint], data: BinaryData, assert_valid: bool = True
    ) -> _OutPoint:
        "Return an OutPoint from the first 36 bytes of the provided data."

        data = bytesio_from_binarydata(data)

        outpoint = cls()
        # 32 bytes, little endian
        outpoint.txid = data.read(32)[::-1]
        # 4 bytes, little endian, interpreted as int
        outpoint.vout = int.from_bytes(data.read(4), "little")

        if assert_valid:
            outpoint.assert_valid()
        return outpoint


_TxIn = TypeVar("_TxIn", bound="TxIn")


@dataclass
class TxIn(DataClassJsonMixin):
    prevout: OutPoint = field(default=OutPoint())
    # TODO make it { "asm": "", "hex": "" }
    script_sig: bytes = field(
        default=b"",
        metadata=config(
            field_name="scriptSig", encoder=lambda v: v.hex(), decoder=bytes.fromhex
        ),
    )
    # 4 bytes, unsigned little endian
    sequence: int = -1
    witness: Witness = Witness()

    def assert_valid(self) -> None:
        self.prevout.assert_valid()
        # TODO: empty script_sig is valid (add non-regression test)
        # TODO: test sequence
        self.witness.assert_valid()

    def serialize(self, assert_valid: bool = True) -> bytes:

        if assert_valid:
            self.assert_valid()

        out = self.prevout.serialize()
        out += varbytes.encode(self.script_sig)
        out += self.sequence.to_bytes(4, "little")
        return out

    @classmethod
    def deserialize(
        cls: Type[_TxIn], data: BinaryData, assert_valid: bool = True
    ) -> _TxIn:

        stream = bytesio_from_binarydata(data)

        tx_in = cls()
        tx_in.prevout = OutPoint.deserialize(stream)
        tx_in.script_sig = varbytes.decode(stream)
        # 4 bytes, little endian, interpreted as int
        tx_in.sequence = int.from_bytes(stream.read(4), "little")

        if assert_valid:
            tx_in.assert_valid()
        return tx_in
