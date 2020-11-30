#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from dataclasses import InitVar, dataclass, field
from typing import Type, TypeVar

from dataclasses_json import DataClassJsonMixin, config

from . import varbytes
from .alias import BinaryData
from .exceptions import BTClibValueError
from .utils import bytesio_from_binarydata

MAX_SATOSHI = 2_099_999_997_690_000
SAT_PER_COIN = 100_000_000

_TxOut = TypeVar("_TxOut", bound="TxOut")


@dataclass
class TxOut(DataClassJsonMixin):
    # FIXME make it BTC, not sat
    # value: int = field(
    #    metadata=config(
    #        encoder=lambda v: str(v / SAT_PER_COIN),
    #        decoder=lambda v: int(float(v) * SAT_PER_COIN),
    #    )
    # )
    # 8 bytes, unsigned little endian
    value: int = -1  # satoshis
    # FIXME: make it
    # "script_pubkey": {
    #    "asm": "0 d85c2b71d0060b09c9886aeb815e50991dda124d",
    #    "hex": "0014d85c2b71d0060b09c9886aeb815e50991dda124d",
    #    "reqSigs": 1,
    #    "type": "witness_v0_keyhash",
    #    "addresses": [
    #        "bc1qmpwzkuwsqc9snjvgdt4czhjsnywa5yjdgwyw6k"
    #    ]
    # }
    script_pubkey: bytes = field(
        default=b"",
        metadata=config(
            field_name="scriptPubKey",
            encoder=lambda v: v.hex(),
            decoder=bytes.fromhex,
        ),
    )
    check_validity: InitVar[bool] = True

    def __post_init__(self, check_validity: bool) -> None:
        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        if self.value < 0:
            raise BTClibValueError(f"negative value: {self.value}")
        if self.value > MAX_SATOSHI:
            raise BTClibValueError(f"value too high: {hex(self.value)}")

    def serialize(self, assert_valid: bool = True) -> bytes:

        if assert_valid:
            self.assert_valid()

        out = self.value.to_bytes(8, byteorder="little", signed=False)
        out += varbytes.serialize(self.script_pubkey)
        return out

    @classmethod
    def deserialize(
        cls: Type[_TxOut], data: BinaryData, assert_valid: bool = True
    ) -> _TxOut:
        stream = bytesio_from_binarydata(data)
        tx_out = cls(check_validity=False)
        tx_out.value = int.from_bytes(stream.read(8), byteorder="little", signed=False)
        tx_out.script_pubkey = varbytes.deserialize(stream)

        if assert_valid:
            tx_out.assert_valid()
        return tx_out
