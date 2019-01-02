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

    if len(o) == 1 and o[0] == 0x00:  # infinity point
        return 1, 0

    if len(o) == ec.bytesize+1:       # compressed point
        if o[0] not in (0x02, 0x03):
            m = "%s bytes, but not a compressed point" % (ec.bytesize+1)
            raise ValueError(m)
        Px = int.from_bytes(o[1:], 'big')
        try:
            Py = ec.yOdd(Px, o[0] % 2)    # also check Px validity
            return Px, Py
        except:
            raise ValueError("point not on curve")
    else:                             # uncompressed point
        if len(o) != 2*ec.bytesize+1:
            m = "wrong byte-size (%s) for a point: it " % len(o)
            m += "should be %s or %s" % (ec.bytesize+1, 2*ec.bytesize+1)
            raise ValueError(m)
        if o[0] != 0x04:
            raise ValueError("not an uncompressed point")
        Px = int.from_bytes(o[1:ec.bytesize+1], 'big')
        P = Px, int.from_bytes(o[ec.bytesize+1:], 'big')
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

    bPx = Q[0].to_bytes(ec.bytesize, byteorder='big')
    if compressed:
        return (b'\x03' if (Q[1] & 1) else b'\x02') + bPx

    return b'\x04' + bPx + Q[1].to_bytes(ec.bytesize, byteorder='big')


def octets2int(o: octets) -> int:
    """SEC 1 v.2, section 2.3.8"""
    if isinstance(o, str):  # hex string
        o = bytes.fromhex(o)

    return int.from_bytes(o, 'big')


def int2octets(q: int, bytesize: int) -> bytes:
    """SEC 1 v.2, section 2.3.7"""
    return q.to_bytes(bytesize, 'big')


def bits2int(ec: EC, o: octets) -> int:
    """Return the leftmost ec.n.bitlength() bits only % ec.n"""

    i = _bits2int(ec, o)
    return i % ec.n


def _bits2int(ec: EC, o: octets) -> int:
    """Return the leftmost ec.n.bitlength() bits only

       http://www.secg.org/sec1-v2.pdf
       SEC 1 v.2 section 4.1.3 (5)
       
       Note that an additional mod ec.n is required to ensure that 0 < i < ec.n
    """

    i = octets2int(o)

    hlen = i.bit_length()
    qlen = ec.n.bit_length()
    n = (hlen - qlen) if hlen >= qlen else 0
    return i >> n


def bits2octets(ec: EC, b: bytes) -> bytes:
    z1 = bits2int(ec, b)
    return int2octets(z1, ec.bytesize)
