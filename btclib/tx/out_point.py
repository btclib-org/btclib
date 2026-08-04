#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""The OutPoint dataclass; the class docstring has the contract."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from btclib.alias import BinaryData, Octets
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.utils import (
    assert_no_trailing,
    bytes_from_octets,
    bytesio_from_binarydata,
    is_integer,
    read_exactly,
)

__all__ = [
    "OutPoint",
]


# frozen: both fields are immutable, so this one
# is frozen all the way down, and the generated __hash__ makes an OutPoint
# usable as the dict key or set member an utxo set wants it to be.
# __init__ already went through object.__setattr__, in wait for this
@dataclass(frozen=True)
class OutPoint:
    """The output a transaction input spends: (tx_id, vout).

    tx_id is held in the byte order hex explorers print, reversed on
    the wire by serialize and back by parse. Frozen and hashable, so
    an OutPoint can key the dict a utxo set is; the default instance
    is the coinbase marker, all-zero tx_id and 0xFFFFFFFF vout, and
    assert_valid refuses a half-coinbase mix of the two.
    """

    tx_id: bytes
    vout: int

    @property
    def hash(self) -> int:
        """Return the hash int for compatibility with COutPoint."""
        return int.from_bytes(self.tx_id, "big", signed=False)

    @property
    def n(self) -> int:
        """Return the n int for compatibility with COutPoint."""
        return self.vout

    def __init__(
        self,
        tx_id: Octets = b"\x00" * 32,
        vout: int = 0xFFFFFFFF,
        *,
        check_validity: bool = True,
    ) -> None:
        object.__setattr__(self, "tx_id", bytes_from_octets(tx_id))
        object.__setattr__(self, "vout", vout)

        if check_validity:
            self.assert_valid()

    def is_coinbase(self) -> bool:
        """Answer whether this is the coinbase marker, spending nothing."""
        return self.tx_id == b"\x00" * 32 and self.vout == 0xFFFFFFFF

    def assert_valid(self) -> None:
        """Refuse a tx_id not of 32 bytes, a vout no 4 bytes hold, a mix.

        The mix is an all-zero tx_id with a real vout or the reverse:
        the coinbase marker is both fields at their sentinel or
        neither.
        """
        if len(self.tx_id) != 32:
            err_msg = f"invalid OutPoint tx_id: {len(self.tx_id)}"
            err_msg += " instead of 32 bytes"
            raise BTClibValueError(err_msg)
        # a bool is an int and would read as vout 0 or 1, which the range
        # check below cannot tell from an index: `from_dict` reads json
        if not is_integer(self.vout):
            err_msg = f"invalid vout type: {type(self.vout).__name__}"
            raise BTClibTypeError(err_msg)
        # must be a 4-bytes int
        if not 0 <= self.vout <= 0xFFFFFFFF:
            raise BTClibValueError(f"invalid vout: {self.vout}")
        # not a coinbase, not a regular OutPoint
        if (self.tx_id == b"\x00" * 32) ^ (self.vout == 0xFFFFFFFF):
            raise BTClibValueError("invalid OutPoint")

    def to_dict(self, *, check_validity: bool = True) -> dict[str, str | int]:
        """Return {"txid", "vout"}, the keys Bitcoin Core's RPC uses.

        The txid is hex in display order; from_dict reads the same
        shape back and the round trip is exact.
        """
        if check_validity:
            self.assert_valid()

        return {"txid": self.tx_id.hex(), "vout": self.vout}

    @classmethod
    def from_dict(
        cls: type[OutPoint], dict_: Mapping[str, Any], *, check_validity: bool = True
    ) -> OutPoint:
        """Build an OutPoint from the dict shape to_dict writes."""
        return cls(dict_["txid"], dict_["vout"], check_validity=check_validity)

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the 36 bytes serialization of the OutPoint."""
        if check_validity:
            self.assert_valid()

        out = self.tx_id[::-1]
        out += self.vout.to_bytes(4, byteorder="little", signed=False)
        return out

    @classmethod
    def parse(
        cls: type[OutPoint], data: BinaryData, *, check_validity: bool = True
    ) -> OutPoint:
        """Return an OutPoint from the first 36 bytes of the provided data."""
        stream = bytesio_from_binarydata(data)
        tx_id = read_exactly(stream, 32, "outpoint tx_id")[::-1]
        vout = int.from_bytes(
            read_exactly(stream, 4, "outpoint vout"), "little", signed=False
        )
        assert_no_trailing(data, stream, "outpoint")

        return cls(tx_id, vout, check_validity=check_validity)
