#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
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

import hashlib
from io import BytesIO
from typing import BinaryIO, Iterable, Optional, Union

from .alias import BinaryData, Integer, Octets

# hexstr_from_bytes is not needed!!
# def hexstr_from_bytes(byte_str: bytes) -> str:
#    return byte_str.hex()


def sha256(o: Octets) -> bytes:
    "Return the SHA256(*) of the input octet sequence."

    o = bytes_from_octets(o)
    return hashlib.sha256(o).digest()


def hash160(o: Octets) -> bytes:
    "Return the HASH160=RIPEMD160(SHA256) of the input octet sequence."

    t = sha256(o)
    return hashlib.new("ripemd160", t).digest()


def hash256(o: Octets) -> bytes:
    "Return the SHA256(SHA256(*)) of the input octet sequence."

    t = sha256(o)
    return hashlib.sha256(t).digest()


NoneOneOrMoreInt = Optional[Union[int, Iterable[int]]]


def bytes_from_octets(o: Octets, out_size: NoneOneOrMoreInt = None) -> bytes:
    """Return bytes from a hex-string, stripping leading/trailing spaces.

    If the input is not a string, then it goes untouched.
    Optionally, it also ensures required output size.
    """

    if isinstance(o, str):  # hex string
        o = bytes.fromhex(o)

    if (
        out_size is None
        or isinstance(out_size, int)
        and len(o) == out_size
        or isinstance(out_size, Iterable)
        and len(o) in out_size
    ):
        return o

    m = f"invalid size: {len(o)} bytes instead of {out_size}"
    raise ValueError(m)


def bytesio_from_binarydata(stream: BinaryData) -> BytesIO:
    """Return a BinaryIO stream object Octets.

    If the input is not Octets (i.e. string or bytes),
    then it goes untouched.
    """

    if isinstance(stream, str):  # hex string
        stream = bytes_from_octets(stream)
    if isinstance(stream, bytes):
        stream = BytesIO(stream)
    elif isinstance(stream, BinaryIO):
        stream = BytesIO(stream.read())
    return stream


def int_from_bits(o: Octets, nlen: int) -> int:
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

    o = bytes_from_octets(o)
    i = int.from_bytes(o, byteorder="big")

    blen = len(o) * 8  # bits
    n = (blen - nlen) if blen >= nlen else 0
    return i >> n


def int_from_integer(i: Integer) -> int:

    if isinstance(i, int):
        return i
    if isinstance(i, str):
        i = i.lower()
        if i.startswith("0x"):
            return int(i, 16)
        i = bytes.fromhex(i)
    if not isinstance(i, bytes):
        raise TypeError("not an Integer=Union[int, str, bytes]")
    return int.from_bytes(i, "big")


def hex_string(i: Integer) -> str:

    if isinstance(i, int):
        if i < 0:
            raise ValueError(f"negative integer: {i}")
        a_str = hex(i)[2:]
    elif isinstance(i, bytes):
        a_str = i.hex()
    else:  # must be string
        i = i.upper()
        if i.startswith("0X"):
            a_str = i[2:]
        elif i.startswith("0B"):
            a_str = hex(int(i, 2))[2:]
        else:
            # check valid hex-string, remove any whitespace
            a_str = bytes.fromhex(i).hex()

    if len(a_str) % 2 != 0:
        a_str = "0" + a_str

    indx = list(reversed(range(len(a_str), 0, -8)))
    lresult = [(a_str[max(0, i - 8) : i]) for i in indx]
    result = " ".join(lresult)
    return result.upper()


def ensure_is_power_of_two(n: int, var_name: str = None) -> None:
    # http://www.graphics.stanford.edu/~seander/bithacks.html
    if n & (n - 1) != 0:
        raise ValueError(f"{var_name}: {n} (must be a power of two)")
