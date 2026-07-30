#!/usr/bin/env python3

# Copyright (C) The btclib developers
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

Only the shortest encoding of a given number is valid: Bitcoin Core
rejects the others as "non-canonical ReadCompactSize()". Were they
accepted, the same transaction would have two serializations, hence two
txids.
"""

from io import BytesIO

from btclib.alias import BinaryData
from btclib.exceptions import BTClibValueError
from btclib.utils import bytesio_from_binarydata, hex_string

# The MAX_SIZE of Bitcoin Core (serialize.h), i.e. the range check its
# ReadCompactSize applies by default. Every var_int btclib parses is a
# length or a count, so it cannot legitimately exceed it; without a cap,
# nine hostile bytes ask a parser to allocate up to 2^64-1 elements.
MAX_SIZE = 0x02000000


def _parse_number(stream: BytesIO, size: int, minimum: int) -> int:
    """Return the little-endian number the prefix announced."""
    data = stream.read(size)
    if len(data) != size:
        raise BTClibValueError("not enough binary data for var_int")
    i = int.from_bytes(data, byteorder="little", signed=False)
    if i < minimum:
        err_msg = f"non-canonical var_int: {i} encoded in {size + 1} bytes"
        raise BTClibValueError(err_msg)
    return i


def parse(stream: BinaryData, max_size: int = MAX_SIZE) -> int:
    """Return the variable-length integer read from a stream.

    max_size is the range check of Bitcoin Core's ReadCompactSize; raise
    it only for a var_int that is neither a length nor a count.
    """
    stream = bytesio_from_binarydata(stream)

    data = stream.read(1)
    if not data:
        raise BTClibValueError("not enough binary data for var_int")
    i = data[0]
    if i == 0xFD:
        # 0xfd marks the next two bytes as the number
        i = _parse_number(stream, 2, 0xFD)
    elif i == 0xFE:
        # 0xfe marks the next four bytes as the number
        i = _parse_number(stream, 4, 0x0001_0000)
    elif i == 0xFF:
        # 0xff marks the next eight bytes as the number
        i = _parse_number(stream, 8, 0x0001_0000_0000)
    # else it is a one byte integer, which is canonical by construction

    if i > max_size:
        err_msg = f"var_int too big: {hex_string(i)}, max is {hex_string(max_size)}"
        raise BTClibValueError(err_msg)
    return i


def serialize(i: int) -> bytes:
    """Return the var_int bytes encoding of an integer."""
    if i < 0x00:
        raise BTClibValueError(f"negative integer: {i}")
    if i < 0xFD:  # 1 byte
        return bytes([i])
    if i <= 0xFFFF:  # 2 bytes
        return b"\xfd" + i.to_bytes(2, byteorder="little", signed=False)
    if i <= 0xFFFFFFFF:  # 4 bytes
        return b"\xfe" + i.to_bytes(4, byteorder="little", signed=False)
    if i <= 0xFFFFFFFFFFFFFFFF:  # 8 bytes
        return b"\xff" + i.to_bytes(8, byteorder="little", signed=False)
    raise BTClibValueError(f"integer too big for var_int encoding: '{hex_string(i)}'")
