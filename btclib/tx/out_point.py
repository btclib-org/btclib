#!/usr/bin/env python3

# Copyright (C) 2020-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from dataclasses import InitVar, dataclass, field
from typing import Type, TypeVar

from dataclasses_json import DataClassJsonMixin, config

from btclib.alias import BinaryData
from btclib.exceptions import BTClibValueError
from btclib.utils import bytesio_from_binarydata

_OutPoint = TypeVar("_OutPoint", bound="OutPoint")


@dataclass
class OutPoint(DataClassJsonMixin):
    tx_id: bytes = field(
        default=b"\x00" * 32,
        metadata=config(
            field_name="txid", encoder=lambda v: v.hex(), decoder=bytes.fromhex
        ),
    )
    vout: int = 0xFFFFFFFF
    # TODO add value and script_pub_key when tx fetcher will be available
    check_validity: InitVar[bool] = True

    @property
    def hash(self) -> int:
        "Return the hash int for compatibility with COutPoint."
        return int.from_bytes(self.tx_id, "big", signed=False)

    @property
    def n(self) -> int:
        "Return the n int for compatibility with COutPoint."
        return self.vout

    def __post_init__(self, check_validity: bool) -> None:
        if check_validity:
            self.assert_valid()

    def is_coinbase(self) -> bool:
        return self.tx_id == b"\x00" * 32 and self.vout == 0xFFFFFFFF

    def assert_valid(self) -> None:
        if len(self.tx_id) != 32:
            err_msg = f"invalid OutPoint tx_id: {len(self.tx_id)}"
            err_msg += " instead of 32 bytes"
            raise BTClibValueError(err_msg)
        # must be a 4-bytes int
        if not 0 <= self.vout <= 0xFFFFFFFF:
            raise BTClibValueError(f"invalid vout: {self.vout}")
        # not a coinbase, not a regular OutPoint
        if (self.tx_id == b"\x00" * 32) ^ (self.vout == 0xFFFFFFFF):
            raise BTClibValueError("invalid OutPoint")

    def serialize(self, check_validity: bool = True) -> bytes:
        "Return the 36 bytes serialization of the OutPoint."

        if check_validity:
            self.assert_valid()

        out = self.tx_id[::-1]
        out += self.vout.to_bytes(4, byteorder="little", signed=False)
        return out

    @classmethod
    def parse(
        cls: Type[_OutPoint], data: BinaryData, check_validity: bool = True
    ) -> _OutPoint:
        "Return an OutPoint from the first 36 bytes of the provided data."

        data = bytesio_from_binarydata(data)
        tx_id = data.read(32)[::-1]
        vout = int.from_bytes(data.read(4), "little", signed=False)

        return cls(tx_id, vout, check_validity)
