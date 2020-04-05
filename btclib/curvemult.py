#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Elliptic curve point multiplication functions."""

import heapq
from typing import List, Sequence

from .alias import INFJ, JacPoint, Point
from .curve import Curve, _jac_from_aff
from .curves import secp256k1


def mult(m: int, Q: Point = None, ec: Curve = secp256k1) -> Point:
    """Point multiplication, implemented using 'double and add'.

    Computations use Jacobian coordinates and binary decomposition of m.
    """
    if Q is None:
        QJ = ec.GJ
    else:
        ec.require_on_curve(Q)
        QJ = _jac_from_aff(Q)

    R = _mult_jac(m, QJ, ec)
    return ec._aff_from_jac(R)


def _mult_jac(m: int, Q: JacPoint, ec: Curve) -> JacPoint:
    # double & add in Jacobian coordinates, using binary decomposition of m
    # Point is assumed to be on curve

    m %= ec.n
    if m == 0 or Q[2] == 0:        # Infinity point in affine coordinates
        return INFJ                # return Infinity point
    R = INFJ                       # initialize as infinity point
    while m > 0:                   # use binary representation of m
        if m & 1:                  # if least significant bit is 1
            R = ec._add_jac(R, Q)  # then add current Q
        m = m >> 1                 # remove the bit just accounted for
        Q = ec._add_jac(Q, Q)      # double Q for next step
    return R


def double_mult(u: int, H: Point, v: int, Q: Point = None,
                ec: Curve = secp256k1) -> Point:
    """Shamir trick for efficient computation of u*H + v*Q"""

    ec.require_on_curve(H)
    HJ = _jac_from_aff(H)

    if Q is None:
        QJ = ec.GJ
    else:
        ec.require_on_curve(Q)
        QJ = _jac_from_aff(Q)

    R = _double_mult(u, HJ, v, QJ, ec)

    return ec._aff_from_jac(R)


def _double_mult(u: int, HJ: JacPoint, v: int, QJ: JacPoint,
                 ec: Curve) -> JacPoint:

    u %= ec.n
    if u == 0 or HJ[2] == 0:
        return _mult_jac(v, QJ, ec)

    v %= ec.n
    if v == 0 or QJ[2] == 0:
        return _mult_jac(u, HJ, ec)

    R = INFJ  # initialize as infinity point
    msb = max(u.bit_length(), v.bit_length())
    while msb > 0:
        if u >> (msb - 1):  # checking msb
            R = ec._add_jac(R, HJ)
            u -= pow(2, u.bit_length() - 1)
        if v >> (msb - 1):  # checking msb
            R = ec._add_jac(R, QJ)
            v -= pow(2, v.bit_length() - 1)
        if msb > 1:
            R = ec._add_jac(R, R)
        msb -= 1

    return R


def multi_mult(scalars: Sequence[int], Points: Sequence[Point],
               ec: Curve = secp256k1) -> Point:
    """Return the multi scalar multiplication u1*Q1 + ... + un*Qn.

    Use Bos-Coster's algorithm for efficient computation;
    the input points must be on the curve.
    """

    if len(scalars) != len(Points):
        errMsg = f"mismatch between scalar length ({len(scalars)}) and "
        errMsg += f"Points length ({len(Points)})"
        raise ValueError(errMsg)

    JPoints: List[JacPoint] = list()
    for P in Points:
        ec.require_on_curve(P)
        JPoints.append(_jac_from_aff(P))

    R = _multi_mult(scalars, JPoints, ec)

    return ec._aff_from_jac(R)


def _multi_mult(scalars: Sequence[int], JPoints: Sequence[JacPoint],
                ec: Curve) -> JacPoint:
    # source: https://cr.yp.to/badbatch/boscoster2.py

    x = list(zip([-n for n in scalars], JPoints))
    heapq.heapify(x)
    while len(x) > 1:
        np1 = heapq.heappop(x)
        np2 = heapq.heappop(x)
        n1, p1 = -np1[0], np1[1]
        n2, p2 = -np2[0], np2[1]
        p2 = ec._add_jac(p1, p2)
        n1 -= n2
        if n1 > 0:
            heapq.heappush(x, (-n1, p1))
        heapq.heappush(x, (-n2, p2))
    np1 = heapq.heappop(x)
    n1, p1 = -np1[0], np1[1]
    return _mult_jac(n1, p1, ec)
