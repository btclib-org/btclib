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
    value: int  # satoshis
    # FIXME: make it
    # "scriptPubKey": {
    #    "asm": "0 d85c2b71d0060b09c9886aeb815e50991dda124d",
    #    "hex": "0014d85c2b71d0060b09c9886aeb815e50991dda124d",
    #    "reqSigs": 1,
    #    "type": "witness_v0_keyhash",
    #    "addresses": [
    #        "bc1qmpwzkuwsqc9snjvgdt4czhjsnywa5yjdgwyw6k"
    #    ]
    # }
    scriptPubKey: bytes = field(
        metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex)
    )

    @classmethod
    def deserialize(
        cls: Type[_TxOut], data: BinaryData, assert_valid: bool = True
    ) -> _TxOut:
        stream = bytesio_from_binarydata(data)
        # 8 bytes, little endian, interpreted as int
        value = int.from_bytes(stream.read(8), "little")

        scriptPubKey = varbytes.decode(stream)

        tx_out = cls(value=value, scriptPubKey=scriptPubKey)
        if assert_valid:
            tx_out.assert_valid()
        return tx_out

    def serialize(self, assert_valid: bool = True) -> bytes:

        if assert_valid:
            self.assert_valid()

        out = self.value.to_bytes(8, "little")
        out += varbytes.encode(self.scriptPubKey)
        return out

    def assert_valid(self) -> None:
        # must be a 8-bytes int
        if self.value < 0:
            raise BTClibValueError(f"negative value: {self.value}")
        if self.value > MAX_SATOSHI:
            raise BTClibValueError(f"value too high: {hex(self.value)}")
