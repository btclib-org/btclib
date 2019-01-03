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


def octets2point(ec: EC, o: octets) -> Point:
    """Return a tuple (Px, Py) that belongs to the curve

       SEC 1 v.2, section 2.3.4
    """
    if isinstance(o, str):
        o = bytes.fromhex(o)

    bsize = len(o) # bytes
    if bsize == 1 and o[0] == 0x00:     # infinity point
        return 1, 0

    if bsize == ec.psize+1:             # compressed point
        if o[0] not in (0x02, 0x03):
            m = "%s bytes, but not a compressed point" % (ec.psize+1)
            raise ValueError(m)
        Px = int.from_bytes(o[1:], 'big')
        try:
            Py = ec.yOdd(Px, o[0] % 2)  # also check Px validity
            return Px, Py
        except:
            raise ValueError("point not on curve")
    else:                               # uncompressed point
        if bsize != 2*ec.psize+1:
            m = "wrong byte-size (%s) for a point: it " % bsize
            m += "should be %s or %s" % (ec.psize+1, 2*ec.psize+1)
            raise ValueError(m)
        if o[0] != 0x04:
            raise ValueError("not an uncompressed point")
        Px = int.from_bytes(o[1:ec.psize+1], 'big')
        P = Px, int.from_bytes(o[ec.psize+1:], 'big')
        if ec.isOnCurve(P):
            return P
        else:
            raise ValueError("point not on curve")


def point2octets(ec: EC, Q: Point, compressed: bool) -> bytes:
    """Return a compressed (0x02, 0x03) or uncompressed (0x04) point as octets

       SEC 1 v.2, section 2.3.3
    """
    # check that Q is a point and that is on curve
    ec.requireOnCurve(Q)

    if Q[1] == 0:  # infinity point in affine coordinates
        return b'\x00'

    bPx = Q[0].to_bytes(ec.psize, byteorder='big')
    if compressed:
        return (b'\x03' if (Q[1] & 1) else b'\x02') + bPx

    return b'\x04' + bPx + Q[1].to_bytes(ec.psize, byteorder='big')


def octets2int(o: octets) -> int:
    """SEC 1 v.2, section 2.3.8"""
    if isinstance(o, str):  # hex string
        o = bytes.fromhex(o)
    return int.from_bytes(o, 'big')


def int2octets(i: int, bytesize: int) -> bytes:
    """SEC 1 v.2, section 2.3.7"""
    return i.to_bytes(bytesize, 'big')

# https://tools.ietf.org/html/rfc6979#section-2.3.5
# Note that int2octets is not the reverse of bits2int, even for input
# sequences of length nlen: int2octets will add some bits on the left,
# while bits2int will discard some bits on the right.
# int2octets is the reverse of bits2int only when nlen is a multiple of
# 8 and bit sequences already have length nlen.

def bits2int(ec: EC, o: octets) -> int:
    """ Return the leftmost ec.nlen bits reduced modulo ec.n
    
        It takes as input a sequence of blen bits and calculate a non-negative
        integer 'i' that is less than 2^nlen. Further, it reduces 'i'
        modulo ec.n to ensure that 0 < i < ec.n.

        bits2int is used during signature generation and verification in
        ECDSA and ECSSA to transform a hash value (computed over the input
        message) into an integer modulo ec.n.
    """
    i = _bits2int(ec, o)
    return i % ec.n  # might be just a difference


def _bits2int(ec: EC, o: octets) -> int:
    """ Return the leftmost ec.nlen bits

        It takes as input a sequence of blen bits and outputs a non-negative
        integer 'o' that is less than 2^nlen. Note that an additional reduction
        modulo ec.n would be required to ensure that 0 < i < ec.n.

        http://www.secg.org/sec1-v2.pdf
        SEC 1 v.2 section 4.1.3 (5)
    """
    i = octets2int(o)

    blen = len(o) * 8  # bits
    n = (blen - ec.nlen) if blen >= ec.nlen else 0
    return i >> n
