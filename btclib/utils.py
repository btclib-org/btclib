#!/usr/bin/env python3

# Copyright (C) 2017-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Assorted conversion utilities.

Most conversions from SEC 1 v.2 2.3 are included.

https://www.secg.org/sec1-v2.pdf
"""

from collections.abc import Iterable as IterableCollection
from io import BytesIO
from typing import Iterable, Optional, Union

from btclib.alias import BinaryData, Integer, Octets
from btclib.exceptions import BTClibValueError

# hexstr_from_bytes is not needed!!
# def hexstr_from_bytes(byte_str: bytes) -> str:
#    return byte_str.hex()


NoneOneOrMoreInt = Optional[Union[int, Iterable[int]]]


def bytes_from_octets(octets: Octets, out_size: NoneOneOrMoreInt = None) -> bytes:
    """Return bytes from a hex-string, stripping leading/trailing spaces.

    If the input is not a string, then it goes untouched.
    Optionally, it also ensures required output size.
    """

    if isinstance(octets, str):  # hex string
        octets = bytes.fromhex(octets)

    if (
        out_size is None
        or isinstance(out_size, int)
        and len(octets) == out_size
        or isinstance(out_size, IterableCollection)
        and len(octets) in out_size
    ):
        return octets

    err_msg = f"invalid size: {len(octets)} bytes instead of {out_size}"
    raise BTClibValueError(err_msg)


def bytesio_from_binarydata(stream: BinaryData) -> BytesIO:
    """Return a BytesIO stream object from BinaryIO or Octets.

    If the input is not Octets (i.e. str or bytes),
    then it goes untouched.
    """

    if isinstance(stream, str):  # hex string
        stream = bytes_from_octets(stream)

    if isinstance(stream, bytes):
        stream = BytesIO(stream)

    return stream


def int_from_bits(octets: Octets, nlen: int) -> int:
    """Return the leftmost nlen bits.

    Take as input a sequence of blen bits and calculate a
    non-negative integer i that is less than 2^nlen according to
    SEC 1 v.2 section 4.1.3 (5).
    Note that an additional reduction modulo n would be required
    to ensure that 0 < i < n.

    int_from_bits is not the reverse of i.to_bytes, even
    for input sequences of length nlen: i.to_bytes will add some
    bits on the left, while int_from_bits will discard some bits on the
    right. i.to_bytes is the reverse of int_from_bits only when
    nlen is a multiple of 8 and bit sequences already have length nlen.
    See https://tools.ietf.org/html/rfc6979#section-2.3.5.
    """

    octets = bytes_from_octets(octets)
    i = int.from_bytes(octets, byteorder="big", signed=False)

    blen = len(octets) * 8  # bits
    n = (blen - nlen) if blen >= nlen else 0
    return i >> n


def int_from_integer(i: Integer) -> int:
    """Return an int from many possible integer representations.

    Allowed integer representations are:

    * 3735928559
    * -3735928559
    * "0xdeadbeef"
    * "-0xdeadbeef"
    * "deadbeef"
    * b'\xde\xad\xbe\xef'

    The binary representation is not allowed because there is no way to
    discriminate it from a valid hex-string
    (e.g. "0b11011110101011011011111011101111").
    """

    if isinstance(i, int):
        return i

    if isinstance(i, str):
        i = i.strip().lower()
        if i.startswith("0x") or i.startswith("-0x"):
            return int(i, 16)
        i = bytes.fromhex(i)

    # must be bytes
    return int.from_bytes(i, "big", signed=False)


def hex_string(i: Integer) -> str:
    """Return a hex-string from many positive integer representations.

    Negative integers are not allowed.

    The resulting hex-string has an even number of hex-digits and
    includes a space every four bytes (i.e. every eight hex-digits).
    """

    int_ = int_from_integer(i)
    if int_ < 0:
        raise BTClibValueError(f"negative integer: {int_}")
    a_str = hex(int_)[2:]
    if len(a_str) % 2 != 0:
        a_str = "0" + a_str

    indx = list(reversed(range(len(a_str), 0, -8)))
    lresult = [(a_str[max(0, i - 8) : i]) for i in indx]
    result = " ".join(lresult)
    return result.upper()


def decode_num(data: bytes) -> int:
    """Decode a number to the bitcoin-specific little endian format.

    A number is encoded as little-endian variable-length byte vector
    with the most significant bit (MSB) determining the sign.

    * 0x01 is 1
    * 0x81 is -1

    Therefore, there are two representations of zero:

    * 0x00 is "positive" zero
    * 0x80 is "negative" zero

    Positive zero is also represented by a null-length byte vector,
    which is considered the canonical one.
    """

    length = len(data)
    if length == 0:
        raise BTClibValueError("empty byte string")
    i = int.from_bytes(data, byteorder="little", signed=False)
    if data[-1] >= 0x80:  # negative number
        # mask for all but the highest bit
        mask = (2 ** (length * 8) - 1) >> 1
        i &= mask
        i *= -1
    return i


def encode_num(i: int) -> bytes:
    """Encode a number to the bitcoin-specific little endian format.

    A number is encoded as little-endian variable-length byte vector
    with the most significant bit (MSB) determining the sign.

    * 0x01 is 1
    * 0x81 is -1

    Therefore, there are two representations of zero:

    * 0x00 is "positive" zero
    * 0x80 is "negative" zero

    Positive zero is also represented by a null-length byte vector,
    which is considered the canonical one.
    """

    # i.bit_length() bits, plus a sign bit
    n_bits = i.bit_length() + 1
    # The number of bytes necessary to accomodate n_bits
    n_bytes = (n_bits + 7) // 8
    # Convert the input number to absolute value + sign in top bit
    encoded_i = abs(i) | ((i < 0) << (n_bytes * 8 - 1))
    # Serialize to bytes
    return encoded_i.to_bytes(n_bytes, byteorder="little", signed=False)
