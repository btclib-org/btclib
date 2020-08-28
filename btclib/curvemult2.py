#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Elliptic curve point multiplication functions.

The implemented algorithms are:
    - Montgomery Ladder
    - Scalar multiplication on basis 3
    - Fixed window
    - Sliding window
    - w-ary non-adjacent form (wNAF)

References:
    - https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication
    - https://cryptojedi.org/peter/data/eccss-20130911b.pdf
    - https://ecc2017.cs.ru.nl/slides/ecc2017school-castryck.pdf

TODO:
    - Computational cost of the different multiplications
    - New alghoritms at the state-of-art:
        -https://hal.archives-ouvertes.fr/hal-00932199/document
        -https://iacr.org/workshops/ches/ches2006/presentations/Douglas%20Stebila.pdf
        -1-s2.0-S1071579704000395-main
    - Elegance in the code
    - Solve problem with wNAF and w=1
    - Multi_mult algorithm: why does it work?
    - Check _double_jac function
"""


from typing import List

from .alias import INFJ, Integer, JacPoint, Point
from .curve import Curve, CurveGroup, _jac_from_aff
from .curves import secp256k1
from .utils import int_from_integer


def _double_jac(Q: JacPoint, ec: CurveGroup) -> JacPoint:

    QZ2 = Q[2] * Q[2]
    QY2 = Q[1] * Q[1]
    W = (3 * Q[0] * Q[0] + ec._a * QZ2 * QZ2) % ec.p
    V = (4 * Q[0] * QY2) % ec.p
    X = (W * W - 2 * V) % ec.p
    Y = (W * (V - X) - 8 * QY2 * QY2) % ec.p
    Z = (2 * Q[1] * Q[2]) % ec.p
    return X, Y, Z


def _mult_mont_ladder(m: int, Q: JacPoint, ec: CurveGroup) -> JacPoint:
    """Scalar multiplication in Jacobian coordinates using "montgomery ladder"

    Scalar multiplication of a curve point in Jacobian coordinates.
    This implementation uses "montgomery ladder" algorithm,
    It is constant-time if the binary size of Q remains the same.

    The input point is assumed to be on curve,
    the m coefficient is assumed to have been reduced mod n
    if appropriate (e.g. cyclic groups of order n).
    """

    if m < 0:
        raise ValueError(f"negative m: {hex(m)}")

    R = INFJ  # initialize as infinity point
    for m in [int(i) for i in bin(m)[2:]]:  # goes through binary digits
        if m == 0:
            Q = ec._add_jac(R, Q)
            R = _double_jac(R, ec)
        else:
            R = ec._add_jac(R, Q)
            Q = _double_jac(Q, ec)
    return R


def mult_mont_ladder(m: Integer, Q: Point = None, ec: Curve = secp256k1) -> Point:
    """Point multiplication, implemented using "montgomery ladder" algorithm to run in constant time.

    This can be beneficial when timing measurements are exposed to an attacker performing a side-channel attack.
    This algorithm has the same speed as the double-and-add approach except that it computes the same number
    of point additions and doubles regardless of the value of the multiplicand m.

    Computations use Jacobian coordinates and binary decomposition of m.
    """
    if Q is None:
        QJ = ec.GJ
    else:
        ec.require_on_curve(Q)
        QJ = _jac_from_aff(Q)

    m = int_from_integer(m) % ec.n
    R = _mult_mont_ladder(m, QJ, ec)
    return ec._aff_from_jac(R)


def convert_number_to_base(n: int, b: int) -> List[int]:
    """Returns the list of the digits of n written in basis b"""

    if n == 0:
        return [0]
    digits = []
    while n:
        digits.append(int(n % b))
        n //= b
    return digits[::-1]


def _mult_base_3(m: int, Q: JacPoint, ec: CurveGroup) -> JacPoint:
    """Scalar multiplication in Jacobian coordinates using base 3.

    This implementation uses the same idea of "double and add" algorithm, but with scalar radix 3.
    It is not constant time.

    The input point is assumed to be on curve,
    the m coefficient is assumed to have been reduced mod n
    if appropriate (e.g. cyclic groups of order n).
    """

    if m < 0:
        raise ValueError(f"negative m: {hex(m)}")

    T: List[JacPoint] = []
    T.append(INFJ)
    for i in range(1, 3):
        T.append(ec._add_jac(T[i - 1], Q))

    M = convert_number_to_base(m, 3)

    R = T[M[0]]

    for i in range(1, len(M)):
        R2 = _double_jac(R, ec)
        R = ec._add_jac(R2, R)
        R = ec._add_jac(R, T[M[i]])

    return R


def mult_base_3(m: Integer, Q: Point = None, ec: Curve = secp256k1) -> Point:
    """Point multiplication, implemented using "double and add" but changing the scalar radix to 3.

    Computations use Jacobian coordinates and decomposition of m basis 3.
    """
    if Q is None:
        QJ = ec.GJ
    else:
        ec.require_on_curve(Q)
        QJ = _jac_from_aff(Q)

    m = int_from_integer(m) % ec.n
    R = _mult_base_3(m, QJ, ec)
    return ec._aff_from_jac(R)


def _mult_fixed_window(m: int, w: int, Q: JacPoint, ec: CurveGroup) -> JacPoint:
    """Scalar multiplication in Jacobian coordinates using "fixed window".

    This implementation uses the method called "fixed window"
    It is not constant time.
    For 256-bit scalars choose w=4 or w=5

    The input point is assumed to be on curve,
    the m coefficient is assumed to have been reduced mod n
    if appropriate (e.g. cyclic groups of order n).
    """
    if m < 0:
        raise ValueError(f"negative m: {hex(m)}")

    # a number cannot be written in basis 1 (ie w=0)
    if w <= 0:
        raise ValueError(f"non positive w: {w}")

    b = pow(2, w)

    T: List[JacPoint] = []
    T.append(INFJ)
    for i in range(1, b):
        T.append(ec._add_jac(T[i - 1], Q))

    M = convert_number_to_base(m, b)

    R = T[M[0]]

    for i in range(1, len(M)):
        for _ in range(w):
            R = _double_jac(R, ec)
        R = ec._add_jac(R, T[M[i]])

    return R


def mult_fixed_window(
    m: Integer, w: Integer, Q: Point = None, ec: Curve = secp256k1
) -> Point:
    """Point multiplication, implemented using "fixed window" method.

    Computations use Jacobian coordinates and decomposition of m on basis 2^w.
    """

    if Q is None:
        QJ = ec.GJ
    else:
        ec.require_on_curve(Q)
        QJ = _jac_from_aff(Q)

    m = int_from_integer(m) % ec.n
    w = int_from_integer(w)
    R = _mult_fixed_window(m, w, QJ, ec)
    return ec._aff_from_jac(R)


# Need some modifies to make it more elegant
def _mult_sliding_window(m: int, w: int, Q: JacPoint, ec: CurveGroup) -> JacPoint:
    """Scalar multiplication in Jacobian coordinates using "sliding window".

    This implementation uses the method called "sliding window".
    It has the benefit that the pre-computation stage is roughly half as complex as the normal windowed method .
    It is not constant time.
    For 256-bit scalars choose w=4 or w=5

    The input point is assumed to be on curve,
    the m coefficient is assumed to have been reduced mod n
    if appropriate (e.g. cyclic groups of order n).
    """

    if m < 0:
        raise ValueError(f"negative m: {hex(m)}")

    if w <= 0:
        raise ValueError(f"non positive w: {w}")

    k = w - 1
    p = pow(2, k)

    P = Q
    for _ in range(k):
        P = _double_jac(P, ec)

    T: List[JacPoint] = []
    T.append(P)
    for i in range(1, p):
        T.append(ec._add_jac(T[i - 1], Q))

    M = convert_number_to_base(m, 2)

    R = INFJ

    i = 0
    while i < len(M):
        if M[i] == 0:
            R = _double_jac(R, ec)
            i += 1
        else:
            if (len(M) - i) < w:
                j = len(M) - i
            else:
                j = w

            t = M[i]
            for a in range(1, j):
                t = 2 * t + M[i + a]

            if j < w:
                for b in range(i, (i + j)):
                    R = _double_jac(R, ec)
                    if M[b] == 1:
                        R = ec._add_jac(R, Q)
                return R

            else:
                for _ in range(w):
                    R = _double_jac(R, ec)
                R = ec._add_jac(R, T[t - p])
                i += j
    return R


def mult_sliding_window(
    m: Integer, w: Integer, Q: Point = None, ec: Curve = secp256k1
) -> Point:
    """Point multiplication, implemented using "sliding window" method.

    Computations use Jacobian coordinates and decomposition of m on basis 2.
    """

    if Q is None:
        QJ = ec.GJ
    else:
        ec.require_on_curve(Q)
        QJ = _jac_from_aff(Q)

    m = int_from_integer(m) % ec.n
    w = int_from_integer(w)
    R = _mult_sliding_window(m, w, QJ, ec)
    return ec._aff_from_jac(R)


def mods(m: int, w: int) -> int:
    """Signed modulo function

    FIXME:
    mods does NOT work for w=1. However the function in NOT really meant to be used for w=1
    For w=1 it always gives back -1 and enters an infinte loop
    """

    w2 = pow(2, w)
    M = m % w2
    if M >= (w2 / 2):
        return M - w2
    else:
        return M


def _mult_w_NAF(m: int, w: int, Q: JacPoint, ec: CurveGroup) -> JacPoint:
    """Scalar multiplication in Jacobian coordinates using wNAF.

    This implementation uses the same method called "w-ary non-adjacent form" (wNAF)
    we make use of the fact that point subtraction is as easy as point addition to perform fewer operations compared to sliding-window
    In fact, on Weierstrass curves, known P, -P can be computed on the fly.

    The input point is assumed to be on curve,
    the m coefficient is assumed to have been reduced mod n
    if appropriate (e.g. cyclic groups of order n).
    """
    if m < 0:
        raise ValueError(f"negative m: {hex(m)}")

    if w <= 0:
        raise ValueError(f"non positive w: {w}")

    # This exception must be kept to satisfy while loop on line 344
    if m == 0:
        return INFJ

    i = 0

    M: List[int] = []
    while m > 0:
        if (m % 2) == 1:
            M.append(mods(m, w))
            m = m - M[i]
        else:
            M.append(0)
        m = m // 2
        i = i + 1

    p = i

    b = pow(2, w)

    Q2 = _double_jac(Q, ec)

    T: List[JacPoint] = []
    T.append(Q)
    for i in range(1, (b // 2)):
        T.append(ec._add_jac(T[i - 1], Q2))
    for i in range((b // 2), b):
        T.append(ec.negate_jac(T[i - (b // 2)]))

    R = INFJ

    for j in range(p - 1, -1, -1):
        R = _double_jac(R, ec)
        if M[j] != 0:
            if M[j] > 0:
                # It adds the element jQ
                R = ec._add_jac(R, T[(M[j] - 1) // 2])
            else:
                # In this case it adds the opposite, ie -jQ
                R = ec._add_jac(R, T[(b // 2) - ((M[j] + 1) // 2)])

    return R


def mult_w_NAF(m: Integer, w: Integer, Q: Point = None, ec: Curve = secp256k1) -> Point:
    """Point multiplication, implemented using "w-NAF" method.

    Computations use Jacobian coordinates and decomposition of m on basis 2^w.
    """

    if Q is None:
        QJ = ec.GJ
    else:
        ec.require_on_curve(Q)
        QJ = _jac_from_aff(Q)

    m = int_from_integer(m) % ec.n
    w = int_from_integer(w)
    R = _mult_w_NAF(m, w, QJ, ec)
    return ec._aff_from_jac(R)
