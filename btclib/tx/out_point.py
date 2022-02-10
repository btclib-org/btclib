#!/usr/bin/env python3

# Copyright (C) 2020-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""OutPoint dataclass.

Dataclass encapsulating tx_id and vout.
"""


from dataclasses import dataclass
from typing import Any, Dict, Mapping, Type, Union

from btclib.alias import BinaryData, Octets
from btclib.exceptions import BTClibValueError
from btclib.utils import bytes_from_octets, bytesio_from_binarydata


# FIXME make it frozen
@dataclass
class OutPoint:
    tx_id: bytes
    vout: int

    # TODO add value and script_pub_key proprties when tx fetcher will be available

    @property
    def hash(self) -> int:
        "Return the hash int for compatibility with COutPoint."
        return int.from_bytes(self.tx_id, "big", signed=False)

    @property
    def n(self) -> int:
        "Return the n int for compatibility with COutPoint."
        return self.vout

    def __init__(
        self,
        tx_id: Octets = b"\x00" * 32,
        vout: int = 0xFFFFFFFF,
        check_validity: bool = True,
    ) -> None:

        object.__setattr__(self, "tx_id", bytes_from_octets(tx_id))
        object.__setattr__(self, "vout", vout)

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

    def to_dict(self, check_validity: bool = True) -> Dict[str, Union[str, int]]:

        if check_validity:
            self.assert_valid()

        return {"txid": self.tx_id.hex(), "vout": self.vout}

    @classmethod
    def from_dict(
        cls: Type["OutPoint"], dict_: Mapping[str, Any], check_validity: bool = True
    ) -> "OutPoint":

        return cls(dict_["txid"], dict_["vout"], check_validity)

    def serialize(self, check_validity: bool = True) -> bytes:
        "Return the 36 bytes serialization of the OutPoint."

        if check_validity:
            self.assert_valid()

        out = self.tx_id[::-1]
        out += self.vout.to_bytes(4, byteorder="little", signed=False)
        return out

    @classmethod
    def parse(
        cls: Type["OutPoint"], data: BinaryData, check_validity: bool = True
    ) -> "OutPoint":
        "Return an OutPoint from the first 36 bytes of the provided data."

        data = bytesio_from_binarydata(data)
        tx_id = data.read(32)[::-1]
        vout = int.from_bytes(data.read(4), "little", signed=False)

        return cls(tx_id, vout, check_validity)
