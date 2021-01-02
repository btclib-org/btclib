#!/usr/bin/env python3

# Copyright (C) 2017-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Varint encoding and decoding functions.

A var_int (variable integer) is variable-length quantity that uses an
arbitrary number of binary octets (eight-bit bytes) to represent an
arbitrarily large integer.
It is usually a base-128 (7 bits) representation of an unsigned integer
with the addition of the eighth bit to mark continuation of bytes;
it is used to save additional space for a resource constrained system.

This is the slightly different Bitcoin implementation, used in transaction
data to indicate the number of upcoming fields or the length of the
upcoming field.

Up to 0xfc, a var_int is just 1 byte; however, if the integer is greater than
0xfc, then it is expanded as [1 byte prefix][number]:

* prefix 0xfd markes the next two bytes as the number;
* prefix 0xfe markes the next four bytes as the number;
* prefix 0xff markes the next eight bytes as the number.
"""

from btclib.alias import BinaryData
from btclib.exceptions import BTClibValueError
from btclib.utils import bytesio_from_binarydata, hex_string


def parse(stream: BinaryData) -> int:
    """Return the variable-length integer read from a stream."""

    stream = bytesio_from_binarydata(stream)

    i = stream.read(1)[0]
    if i < 0xFD:
        # one byte integer
        return i
    if i == 0xFD:
        # 0xfd marks the next two bytes as the number
        return int.from_bytes(stream.read(2), byteorder="little", signed=False)
    if i == 0xFE:
        # 0xfe marks the next four bytes as the number
        return int.from_bytes(stream.read(4), byteorder="little", signed=False)
    # 0xff marks the next eight bytes as the number
    return int.from_bytes(stream.read(8), byteorder="little", signed=False)


def serialize(i: int) -> bytes:
    "Return the var_int bytes encoding of an integer."

    if i < 0x00:
        raise BTClibValueError(f"negative integer: {i}")
    if i < 0xFD:  # 1 byte
        return bytes([i])
    if i <= 0xFFFF:  # 2 bytes
        return b"\xFD" + i.to_bytes(2, byteorder="little", signed=False)
    if i <= 0xFFFFFFFF:  # 4 bytes
        return b"\xFE" + i.to_bytes(4, byteorder="little", signed=False)
    if i <= 0xFFFFFFFFFFFFFFFF:  # 8 bytes
        return b"\xFF" + i.to_bytes(8, byteorder="little", signed=False)
    raise BTClibValueError(f"integer too big for var_int encoding: '{hex_string(i)}'")
