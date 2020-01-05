#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Elliptic curve class and functions."""

import heapq
from typing import Sequence, List

from .curve import Curve, Point, _JacPoint, _jac_from_aff

def mult(ec: Curve, m: int, Q: Point = None) -> Point:
    # this function is used by the Curve class; it might be a method...
    # but it does not need to
    if Q is None:
        QJ = ec.GJ
    else:
        ec.require_on_curve(Q)
        QJ = _jac_from_aff(Q)
    R = _mult_jac(ec, m, QJ)
    return ec._aff_from_jac(R)

def _mult_jac(ec: Curve, m: int, Q: _JacPoint) -> _JacPoint:
    # double & add in Jacobian coordinates, using binary decomposition of m
    # Point is assumed to be on curve

    m %= ec.n
    if m == 0 or Q[2] == 0:        # Infinity point in affine coordinates
        return 1, 1, 0             # return Infinity point
    R = 1, 1, 0                    # initialize as infinity point
    while m > 0:                   # use binary representation of m
        if m & 1:                  # if least significant bit is 1
            R = ec._add_jac(R, Q)  # then add current Q
        m = m >> 1                 # remove the bit just accounted for
        Q = ec._add_jac(Q, Q)      # double Q for next step
    return R


def double_mult(ec: Curve, u: int, H: Point, v: int, Q: Point = None) -> Point:
    """Shamir trick for efficient computation of u*H + v*Q"""

    ec.require_on_curve(H)
    HJ = _jac_from_aff(H)

    if Q is None:
        QJ = ec.GJ
    else:
        ec.require_on_curve(Q)
        QJ = _jac_from_aff(Q)

    R = _double_mult(ec, u, HJ, v, QJ)

    return ec._aff_from_jac(R)


def _double_mult(ec: Curve, u: int, HJ: _JacPoint,
                            v: int, QJ: _JacPoint) -> _JacPoint:

    u %= ec.n
    if u == 0 or HJ[2] == 0:
        return _mult_jac(ec, v, QJ)

    v %= ec.n
    if v == 0 or QJ[2] == 0:
        return _mult_jac(ec, u, HJ)

    R = 1, 1, 0  # initialize as infinity point
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


def multi_mult(ec: Curve,
               scalars: Sequence[int],
               Points: Sequence[Point]) -> Point:
    """Return the multi scalar multiplication u1*Q1 + ... + un*Qn.

    Use Bos-Coster's algorithm for efficient computation;
    the input points must be on the curve.
    """

    if len(scalars) != len(Points):
        errMsg = f"mismatch between scalar length ({len(scalars)}) and "
        errMsg += f"Points length ({len(Points)})"
        raise ValueError(errMsg)

    JPoints: List[_JacPoint] = list()
    for P in Points:
        ec.require_on_curve(P)
        JPoints.append(_jac_from_aff(P))

    R = _multi_mult(ec, scalars, JPoints)

    return ec._aff_from_jac(R)


def _multi_mult(ec: Curve,
                scalars: Sequence[int],
                JPoints: Sequence[_JacPoint]) -> _JacPoint:
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
    return _mult_jac(ec, n1, p1)
