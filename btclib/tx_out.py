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

from . import script
from .alias import BinaryData, ScriptToken
from .utils import bytesio_from_binarydata, token_or_string_to_printable

MAX_SATOSHI = 2_099_999_997_690_000

_TxOut = TypeVar("_TxOut", bound="TxOut")


@dataclass
class TxOut(DataClassJsonMixin):
    nValue: int  # satoshis
    scriptPubKey: List[ScriptToken] = field(
        metadata=config(encoder=token_or_string_to_printable)
    )

    @classmethod
    def deserialize(
        cls: Type[_TxOut], data: BinaryData, assert_valid: bool = True
    ) -> _TxOut:
        stream = bytesio_from_binarydata(data)
        # 8 bytes, little endian, interpreted as int
        nValue = int.from_bytes(stream.read(8), "little")

        scriptPubKey = script.deserialize(stream)

        tx_out = cls(nValue=nValue, scriptPubKey=scriptPubKey)
        if assert_valid:
            tx_out.assert_valid()
        return tx_out

    def serialize(self, assert_valid: bool = True) -> bytes:

        if assert_valid:
            self.assert_valid()

        out = self.nValue.to_bytes(8, "little")
        out += script.serialize(self.scriptPubKey)
        return out

    def assert_valid(self) -> None:
        # must be a 8-bytes int
        if self.nValue < 0:
            raise ValueError(f"negative nValue: {self.nValue}")
        if self.nValue > MAX_SATOSHI:
            raise ValueError(f"nValue too high: {hex(self.nValue)}")
        if len(self.scriptPubKey) == 0:
            raise ValueError("empty scriptPubKey")
