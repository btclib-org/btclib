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
from .alias import BinaryData, Octets
from .exceptions import BTClibTypeError
from .utils import bytes_from_octets, bytesio_from_binarydata

_Witness = TypeVar("_Witness", bound="Witness")


@dataclass
class Witness(DataClassJsonMixin):
    items: List[Octets] = field(
        default_factory=list,
        metadata=config(
            encoder=lambda val: [bytes_from_octets(v).hex() for v in val],
            decoder=lambda val: [bytes.fromhex(v).hex() for v in val],
        ),
    )

    def __len__(self):
        return len(self.items)

    def assert_valid(self) -> None:
        if not isinstance(self.items, list):
            raise BTClibTypeError("invalid witness")
        self.items = [bytes_from_octets(octets).hex() for octets in self.items]

    def serialize(self, assert_valid: bool = True) -> bytes:
        "Return the 36 bytes serialization of the Witness."

        if assert_valid:
            self.assert_valid()

        out = varint.serialize(len(self.items))
        return out + b"".join([varbytes.serialize(w) for w in self.items])

    @classmethod
    def deserialize(
        cls: Type[_Witness], data: BinaryData, assert_valid: bool = True
    ) -> _Witness:
        "Return a Witness by parsing binary data."

        data = bytesio_from_binarydata(data)
        witness = cls()

        n = varint.deserialize(data)
        witness.items = [varbytes.deserialize(data) for _ in range(n)]

        if assert_valid:
            witness.assert_valid()
        return witness
