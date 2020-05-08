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
from typing import Iterable, Optional, Union

from .alias import Integer, Octets

# hexstr_from_bytes is not needed!!
# def hexstr_from_bytes(byte_str: bytes) -> str:
#    return byte_str.hex()


NoneOneOrMoreInt = Optional[Union[int, Iterable[int]]]


def bytes_from_octets(o: Octets, out_size: NoneOneOrMoreInt = None) -> bytes:
    """Return bytes from a hex-string, stripping leading/trailing spaces.

    If the input is not a string, then it goes untouched.
    Optionally, it also ensures required output size.
    """

    if isinstance(o, str):  # hex string
        o = bytes.fromhex(o)

    if (out_size is None or
            isinstance(out_size, int) and len(o) == out_size or
            isinstance(out_size, Iterable) and len(o) in out_size):
        return o

    m = f"Invalid size: {len(o)} bytes instead of {out_size}"
    raise ValueError(m)


def int_from_integer(i: Integer) -> int:
    if isinstance(i, int):
        return i
    elif isinstance(i, bytes):
        return int.from_bytes(i, 'big')
    return int(i, 16)


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
    i = int.from_bytes(o, byteorder='big')

    blen = len(o) * 8  # bits
    n = (blen - nlen) if blen >= nlen else 0
    return i >> n


def sha256(o: Octets) -> bytes:
    """Return SHA256(*) of the input octet sequence."""

    o = bytes_from_octets(o)
    return hashlib.sha256(o).digest()


def hash160(o: Octets) -> bytes:
    """Return RIPEMD160(SHA256(*)) of the input octet sequence."""

    t = sha256(o)
    return hashlib.new('ripemd160', t).digest()


def hash256(o: Octets) -> bytes:
    """Return SHA256(SHA256(*)) of the input octet sequence."""

    t = sha256(o)
    return hashlib.sha256(t).digest()


def ensure_is_power_of_two(n: int, var_name: str = None) -> None:
    # http://www.graphics.stanford.edu/~seander/bithacks.html
    if n & (n - 1) != 0:
        raise ValueError(f"{var_name} ({n}) must be a power of two")
