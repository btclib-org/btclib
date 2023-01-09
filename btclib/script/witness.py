#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Witness (list[bytes]) class."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from btclib import var_bytes, var_int
from btclib.alias import BinaryData, Octets
from btclib.utils import bytes_from_octets, bytesio_from_binarydata


@dataclass
class Witness:
    stack: list[bytes]

    def __init__(
        self, stack: Sequence[Octets] | None = None, check_validity: bool = True
    ) -> None:
        # https://docs.python.org/3/tutorial/controlflow.html#default-argument-values
        self.stack = [bytes_from_octets(element) for element in stack] if stack else []

        if check_validity:
            self.assert_valid()

    def __len__(self) -> int:
        return len(self.stack)

    def assert_valid(self) -> None:
        for stack_element in self.stack:
            bytes(stack_element)

    def to_dict(self, check_validity: bool = True) -> dict[str, list[str]]:
        if check_validity:
            self.assert_valid()

        return {"stack": [v.hex() for v in self.stack]}

    @classmethod
    def from_dict(
        cls: type[Witness],
        dict_: Mapping[str, Sequence[Octets]],
        check_validity: bool = True,
    ) -> Witness:
        return cls(dict_["stack"], check_validity)

    def serialize(self, check_validity: bool = True) -> bytes:
        """Return the serialization of the Witness."""
        if check_validity:
            self.assert_valid()

        out = var_int.serialize(len(self.stack))
        return out + b"".join([var_bytes.serialize(w) for w in self.stack])

    @classmethod
    def parse(
        cls: type[Witness], data: BinaryData, check_validity: bool = True
    ) -> Witness:
        """Return a Witness by parsing binary data."""
        data = bytesio_from_binarydata(data)
        n = var_int.parse(data)
        stack = [var_bytes.parse(data) for _ in range(n)]
        return cls(stack, check_validity)
