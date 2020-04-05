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
from typing import Optional, Union

from .alias import HashF, Octets, Point, PubKey, String
from .curve import Curve
from .curves import secp256k1


# TODO rename as bytes_from_octets
def bytes_from_hexstring(o: Octets, out_size: Optional[int] = None) -> bytes:
    """Return bytes from a hex-string, stripping leading/trailing spaces.

    If the input is not a string, then it goes untouched.
    Optionally, it also ensures required output size.
    """

    if isinstance(o, str):  # hex string
        o = bytes.fromhex(o)

    if (out_size is None) or (len(o) == out_size):
       return o

    m = f"Invalid size: {len(o)} bytes instead of {out_size}"
    raise ValueError(m)

# TODO rename as bytes_from_point
def octets_from_point(Q: Point, compressed: bool, ec: Curve = secp256k1) -> bytes:
    """Return a point as compressed/uncompressed octet sequence.

    Return a point as compressed (0x02, 0x03) or uncompressed (0x04)
    octet sequence, according to SEC 1 v.2, section 2.3.3.
    """

    # check that Q is a point and that is on curve
    ec.require_on_curve(Q)

    if Q[1] == 0:  # infinity point in affine coordinates
        return b'\x00'

    bPx = Q[0].to_bytes(ec.psize, byteorder='big')
    if compressed:
        return (b'\x03' if (Q[1] & 1) else b'\x02') + bPx

    return b'\x04' + bPx + Q[1].to_bytes(ec.psize, byteorder='big')


def point_from_octets(pubkey: Octets, ec: Curve = secp256k1) -> Point:
    """Return a tuple (Px, Py) that belongs to the curve.

    Return a tuple (Px, Py) that belongs to the curve according to
    SEC 1 v.2, section 2.3.4.
    """

    pubkey = bytes_from_hexstring(pubkey)

    # TODO: remove support for infinity point?
    bsize = len(pubkey)  # bytes
    if bsize == 1 and pubkey[0] == 0x00:      # infinity point
        return 1, 0

    if bsize == ec.psize + 1:                 # compressed point
        if pubkey[0] not in (0x02, 0x03):
            msg = f"{ec.psize+1} bytes, but not a compressed point"
            raise ValueError(msg)
        Px = int.from_bytes(pubkey[1:], byteorder='big')
        try:
            Py = ec.y_odd(Px, pubkey[0] % 2)  # also check Px validity
            return Px, Py
        except:
            msg = f"{ec.psize+1} bytes, but not a valid x coordinate {Px}"
            raise ValueError(msg)
    else:                                     # uncompressed point
        if bsize != 2*ec.psize + 1:
            msg = f"wrong byte-size ({bsize}) for a point: it "
            msg += f"should have be {ec.psize+1} or {2*ec.psize+1}"
            raise ValueError(msg)
        if pubkey[0] != 0x04:
            raise ValueError("not an uncompressed point")
        Px = int.from_bytes(pubkey[1:ec.psize+1], byteorder='big')
        P = Px, int.from_bytes(pubkey[ec.psize+1:], byteorder='big')
        if ec.is_on_curve(P):
            return P
        else:
            raise ValueError(f"point {P} not on curve")


def int_from_prvkey(prvkey: Union[int, Octets], ec: Curve = secp256k1) -> int:
    """Return a verified-as-valid private key integer."""

    if not isinstance(prvkey, int):
        prvkey = bytes_from_hexstring(prvkey, ec.nsize)
        prvkey = int.from_bytes(prvkey, 'big')

    if not 0 < prvkey < ec.n:
        raise ValueError(f"private key {hex(prvkey)} not in [1, n-1]")

    return prvkey


def int_from_bits(o: Octets, ec: Curve = secp256k1) -> int:
    """Return the leftmost nlen bits reduced modulo n.

    Take as input a sequence of blen bits and calculate a
    non-negative integer i that is less than 2^nlen according to
    SEC 1 v.2 section 4.1.3 (5). Further,
    reduce i module n to ensure that 0 < i < n.

    int_from_bits is used during signature generation and verification
    in ECDSA and ECSSA to transform a hash value (computed over the
    input message) into an integer modulo n.

    Note that int_from_bits is not the reverse of i.to_bytes, even
    for input sequences of length nlen: i.to_bytes will add some
    bits on the left, while int_from_bits will discard some bits on the
    right. i.to_bytes is the reverse of int_from_bits only when
    nlen is a multiple of 8 and bit sequences already have length nlen.
    See https://tools.ietf.org/html/rfc6979#section-2.3.5.
    """
    i = _int_from_bits(o, ec)
    return i % ec.n  # might be implemented as difference


def _int_from_bits(o: Octets, ec: Curve) -> int:
    """Return the leftmost nlen bits.

    Take as input a sequence of blen bits and calculate a
    non-negative integer i that is less than 2^nlen according to
    SEC 1 v.2 section 4.1.3 (5).
    
    Note that an additional reduction modulo n would be required
    to ensure that 0 < i < n.
    """

    o = bytes_from_hexstring(o)
    i = int.from_bytes(o, byteorder='big')

    blen = len(o) * 8  # bits
    n = (blen - ec.nlen) if blen >= ec.nlen else 0
    return i >> n


def sha256(o: Octets) -> bytes:
    """Return SHA256(*) of the input octet sequence."""

    o = bytes_from_hexstring(o)
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
