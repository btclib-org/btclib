# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Varint encoding and decoding functions.

Bitcoin's variable-length integer, Core's CompactSize: what the wire
uses to say how many fields follow or how long the next field is.
Not the base-128 varint of other protocols -- the encoding is its
own.

Up to 0xfc, a var_int is 1 byte; a greater integer is expanded as
[1 byte prefix][number]:

* prefix 0xfd marks the next two bytes as the number;
* prefix 0xfe marks the next four bytes as the number;
* prefix 0xff marks the next eight bytes as the number.

Only the shortest encoding of a given number is valid: Bitcoin Core
rejects the others as "non-canonical ReadCompactSize()". Were they
accepted, the same transaction would have two serializations, hence two
txids.
"""

from io import BytesIO

from btclib.alias import BinaryData
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.utils import bytesio_from_binarydata, hex_string, is_integer

__all__ = [
    "MAX_SIZE",
    "parse",
    "serialize",
]

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
    it only for a var_int that is neither a length nor a count. It is an
    integer and a bool is not one, `is_integer` being the same predicate
    every integer field of the library is held to: `max_size=True` is a cap
    of one, so a caller who meant "no cap" would get a `var_int too big`
    for every count above one -- and `true` is what a json configuration
    decodes to.
    """
    if not is_integer(max_size):
        raise BTClibTypeError(f"non-integer max_size: {max_size}")

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


def _size(i: int) -> int:
    """Return the width `serialize` writes for i, without writing it.

    The four thresholds below are `serialize`'s own, and a test asserts
    the two agree on both sides of each: a size and a serialization that
    disagree are a consensus answer that is wrong by a byte.

    Private, and unvalidated as a private twin is: every caller hands it
    the length of a list or of a byte string, which is the non-negative
    integer `serialize` checks for. The range `serialize` refuses is
    unreachable from there -- a count that large counts more items than
    the block holding them could carry.
    """
    if i < 0xFD:
        return 1
    if i <= 0xFFFF:
        return 3
    if i <= 0xFFFFFFFF:
        return 5
    return 9


def serialize(i: int) -> bytes:
    """Return the var_int bytes encoding of an integer.

    An integer, and a bool is not one: `bytes([True])` is the single octet
    one, so a boolean would encode as the count one or the length zero --
    the number saying how many of something there are, taken from a value
    that says whether. A float or a string leaves through the `TypeError`
    of `bytes()` or of a comparison, from underneath the library rather
    than through its exception contract, which is what `is_integer` is
    here to answer instead.
    """
    if not is_integer(i):
        raise BTClibTypeError(f"non-integer var_int: {i}")
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
