#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from dataclasses import InitVar, dataclass, field
from typing import List, Type, TypeVar

from dataclasses_json import DataClassJsonMixin, config

from . import var_bytes, var_int
from .alias import BinaryData
from .exceptions import BTClibTypeError
from .utils import bytesio_from_binarydata

_TxInWitness = TypeVar("_TxInWitness", bound="TxInWitness")


@dataclass
class TxInWitness(DataClassJsonMixin):
    stack: List[bytes] = field(
        default_factory=list,
        metadata=config(
            encoder=lambda val: [v.hex() for v in val],
            decoder=lambda val: [bytes.fromhex(v) for v in val],
        ),
    )
    check_validity: InitVar[bool] = True

    def __post_init__(self, check_validity: bool) -> None:
        if check_validity:
            self.assert_valid()

    def __len__(self):
        return len(self.stack)

    def assert_valid(self) -> None:
        if not isinstance(self.stack, list):
            raise BTClibTypeError("invalid witness")
        if not all(isinstance(v, bytes) for v in self.stack):
            raise BTClibTypeError("invalid witness")

    def serialize(self, assert_valid: bool = True) -> bytes:
        "Return the serialization of the TxInWitness."

        if assert_valid:
            self.assert_valid()

        out = var_int.serialize(len(self.stack))
        return out + b"".join([var_bytes.serialize(w) for w in self.stack])

    @classmethod
    def deserialize(
        cls: Type[_TxInWitness], data: BinaryData, assert_valid: bool = True
    ) -> _TxInWitness:
        "Return a TxInWitness by parsing binary data."

        data = bytesio_from_binarydata(data)
        witness = cls(check_validity=False)

        n = var_int.deserialize(data)
        witness.stack = [var_bytes.deserialize(data) for _ in range(n)]

        if assert_valid:
            witness.assert_valid()
        return witness
