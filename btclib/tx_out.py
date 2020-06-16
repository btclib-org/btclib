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

_TxOut = TypeVar("_TxOut", bound="TxOut")


@dataclass
class TxOut:
    value: int  # satoshis
    scriptPubKey: List[Token]

    @classmethod
    def deserialize(cls: Type[_TxOut], data: Octets) -> _TxOut:

        data = bytes_from_octets(data)

        value = int.from_bytes(data[:8], "little")
        script_length = varint.decode(data[8:])
        data = data[8 + len(varint.encode(script_length)) :]
        scriptPubKey = script.decode(data[:script_length])

        tx_out = cls(value=value, scriptPubKey=scriptPubKey)

        tx_out.assert_valid()
        return tx_out

    def serialize(self) -> bytes:
        out = self.value.to_bytes(8, "little")
        script_bytes = script.encode(self.scriptPubKey)
        out += varint.encode(len(script_bytes))
        out += script_bytes
        return out

    def assert_valid(self) -> None:
        if self.value < 0:
            raise ValueError(f"negative value: {self.value}")

        if 2099999997690000 < self.value:
            raise ValueError(f"value too high: {self.value}")

        if len(self.scriptPubKey) == 0:
            raise ValueError(f"empty scriptPubKey: {self.scriptPubKey}")
