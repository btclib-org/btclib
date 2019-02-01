#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""
Assorted conversion utilities
"""

from typing import Union

from btclib.ec import EC, Point

octets = Union[str, bytes]


def point_from_octets(ec: EC, o: octets) -> Point:
    """Return a tuple (Px, Py) that belongs to the curve

       SEC 1 v.2, section 2.3.4
    """
    if isinstance(o, str):
        o = bytes.fromhex(o)

    bsize = len(o) # bytes
    if bsize == 1 and o[0] == 0x00:     # infinity point
        return Point()

    if bsize == ec.psize+1:             # compressed point
        if o[0] not in (0x02, 0x03):
            m = f"{ec.psize+1} bytes, but not a compressed point"
            raise ValueError(m)
        Px = int.from_bytes(o[1:], 'big')
        try:
            Py = ec.y_odd(Px, o[0] % 2)  # also check Px validity
            return Point(Px, Py)
        except:
            raise ValueError("point not on curve")
    else:                               # uncompressed point
        if bsize != 2*ec.psize+1:
            m = f"wrong byte-size ({bsize}) for a point: it "
            m += f"should have be {ec.psize+1} or {2*ec.psize+1}"
            raise ValueError(m)
        if o[0] != 0x04:
            raise ValueError("not an uncompressed point")
        Px = int.from_bytes(o[1:ec.psize+1], 'big')
        P = Point(Px, int.from_bytes(o[ec.psize+1:], 'big'))
        if ec.is_on_curve(P):
            return P
        else:
            raise ValueError("point not on curve")


def octets_from_point(ec: EC, Q: Point, compressed: bool) -> bytes:
    """Return a compressed (0x02, 0x03) or uncompressed (0x04) point as octets

       SEC 1 v.2, section 2.3.3
    """
    # check that Q is a point and that is on curve
    ec.require_on_curve(Q)

    if Q[1] == 0:  # infinity point in affine coordinates
        return b'\x00'

    bPx = Q[0].to_bytes(ec.psize, byteorder='big')
    if compressed:
        return (b'\x03' if (Q[1] & 1) else b'\x02') + bPx

    return b'\x04' + bPx + Q[1].to_bytes(ec.psize, byteorder='big')


def int_from_octets(o: octets) -> int:
    """SEC 1 v.2, section 2.3.8"""
    if isinstance(o, str):  # hex string
        o = bytes.fromhex(o)
    return int.from_bytes(o, 'big')


def octets_from_int(i: int, bytesize: int) -> bytes:
    """SEC 1 v.2, section 2.3.7"""
    return i.to_bytes(bytesize, 'big')

# https://tools.ietf.org/html/rfc6979#section-2.3.5
# Note that octets_from_int is not the reverse of int_from_bits, even for input
# sequences of length nlen: octets_from_int will add some bits on the left,
# while int_from_bits will discard some bits on the right.
# octets_from_int is the reverse of int_from_bits only when nlen is a multiple of
# 8 and bit sequences already have length nlen.

def int_from_bits(ec: EC, o: octets) -> int:
    """ Return the leftmost ec.nlen bits reduced modulo ec.n
    
        It takes as input a sequence of blen bits and calculate a non-negative
        integer 'i' that is less than 2^nlen. Further, it reduces 'i'
        modulo ec.n to ensure that 0 < i < ec.n.

        int_from_bits is used during signature generation and verification in
        ECDSA and ECSSA to transform a hash value (computed over the input
        message) into an integer modulo ec.n.
    """
    i = _int_from_bits(ec, o)
    return i % ec.n  # might be just a difference


def _int_from_bits(ec: EC, o: octets) -> int:
    """ Return the leftmost ec.nlen bits

        It takes as input a sequence of blen bits and outputs a non-negative
        integer 'o' that is less than 2^nlen. Note that an additional reduction
        modulo ec.n would be required to ensure that 0 < i < ec.n.

        http://www.secg.org/sec1-v2.pdf
        SEC 1 v.2 section 4.1.3 (5)
    """
    i = int_from_octets(o)

    blen = len(o) * 8  # bits
    n = (blen - ec.nlen) if blen >= ec.nlen else 0
    return i >> n
