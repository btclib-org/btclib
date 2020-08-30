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
"""


from typing import List

from .alias import INFJ, JacPoint
from .curvegroup import CurveGroup


def convert_number_to_base(i: int, base: int) -> List[int]:
    "Return the digits of an integer in the requested base."

    digits: List[int] = []
    while i or not digits:
        i, idx = divmod(i, base)
        digits.append(idx)
    return digits[::-1]


def mods(m: int, w: int) -> int:
    """Signed modulo function.

    FIXME:
    mods does NOT work for w=1. However the function in NOT really meant to be used for w=1
    For w=1 it always gives back -1 and enters an infinte loop
    """

    w2 = pow(2, w)
    M = m % w2
    return M - w2 if M >= (w2 / 2) else M


def _mult_mont_ladder(m: int, Q: JacPoint, ec: CurveGroup) -> JacPoint:
    """Scalar multiplication using 'Montgomery ladder' algorithm.

    This implementation uses
    'Montgomery ladder' algorithm,
    'left-to-right' binary decomposition of the m coefficient,
    Jacobian coordinates.

    It is constant-time and resistant to the FLUSH+RELOAD attack,
    as it prevents branch prediction avoiding any if.

    The input point is assumed to be on curve and
    the m coefficient is assumed to have been reduced mod n
    if appropriate (e.g. cyclic groups of order n).
    """

    if m < 0:
        raise ValueError(f"negative m: {hex(m)}")

    # R[0] is the running result, R[1] = R[0] + Q is an ancillary variable
    R = [INFJ, Q]
    for i in [int(i) for i in bin(m)[2:]]:
        R[not i] = ec._add_jac(R[i], R[not i])
        R[i] = ec._double_jac(R[i])
    return R[0]


def _mult_base_3(m: int, Q: JacPoint, ec: CurveGroup) -> JacPoint:
    """Scalar multiplication using ternary decomposition of the scalar.

    This implementation uses
    'double & add' algorithm,
    'left-to-right' biternaryary decomposition of the m coefficient,
    Jacobian coordinates.

    TODO: make it constant-time.

    The input point is assumed to be on curve and
    the m coefficient is assumed to have been reduced mod n
    if appropriate (e.g. cyclic groups of order n).
    """

    if m < 0:
        raise ValueError(f"negative m: {hex(m)}")

    base = 3
    M = convert_number_to_base(m, base)

    T = [INFJ]
    for i in range(1, base):
        T.append(ec._add_jac(T[i - 1], Q))

    R = T[M[0]]
    for i in range(1, len(M)):
        R2 = ec._double_jac(R)
        R = ec._add_jac(R2, R)
        R = ec._add_jac(R, T[M[i]])
    return R


def _mult_fixed_window(m: int, Q: JacPoint, w: int, ec: CurveGroup) -> JacPoint:
    """Scalar multiplication using "fixed window".

    It is not constant time.
    For 256-bit scalars choose w=4 or w=5.

    The input point is assumed to be on curve and
    the m coefficient is assumed to have been reduced mod n
    if appropriate (e.g. cyclic groups of order n).
    """

    if m < 0:
        raise ValueError(f"negative m: {hex(m)}")

    # a number cannot be written in basis 1 (ie w=0)
    if w <= 0:
        raise ValueError(f"non positive w: {w}")

    base = pow(2, w)
    M = convert_number_to_base(m, base)

    T = [INFJ]
    for i in range(1, base):
        T.append(ec._add_jac(T[i - 1], Q))

    R = T[M[0]]
    for i in range(1, len(M)):
        for _ in range(w):
            R = ec._double_jac(R)
        R = ec._add_jac(R, T[M[i]])
    return R


def _mult_sliding_window(m: int, Q: JacPoint, w: int, ec: CurveGroup) -> JacPoint:
    """Scalar multiplication using "sliding window".

    It has the benefit that the pre-computation stage
    is roughly half as complex as the normal windowed method.
    It is not constant time.
    For 256-bit scalars choose w=4 or w=5.

    The input point is assumed to be on curve and
    the m coefficient is assumed to have been reduced mod n
    if appropriate (e.g. cyclic groups of order n).
    """

    if m < 0:
        raise ValueError(f"negative m: {hex(m)}")

    # a number cannot be written in basis 1 (ie w=0)
    if w <= 0:
        raise ValueError(f"non positive w: {w}")

    k = w - 1
    p = pow(2, k)

    P = Q
    for _ in range(k):
        P = ec._double_jac(P)

    T = [P]
    for i in range(1, p):
        T.append(ec._add_jac(T[i - 1], Q))

    M = convert_number_to_base(m, 2)

    R = INFJ
    i = 0
    while i < len(M):
        if M[i] == 0:
            R = ec._double_jac(R)
            i += 1
        else:
            j = len(M) - i if (len(M) - i) < w else w

            t = M[i]
            for a in range(1, j):
                t = 2 * t + M[i + a]

            if j < w:
                for b in range(i, (i + j)):
                    R = ec._double_jac(R)
                    if M[b] == 1:
                        R = ec._add_jac(R, Q)
                return R
            else:
                for _ in range(w):
                    R = ec._double_jac(R)
                R = ec._add_jac(R, T[t - p])
                i += j
    return R


def _mult_w_NAF(m: int, Q: JacPoint, w: int, ec: CurveGroup) -> JacPoint:
    """Scalar multiplication in Jacobian coordinates using wNAF.

    This implementation uses the same method called "w-ary non-adjacent form" (wNAF)
    we make use of the fact that point subtraction is as easy as point addition to perform fewer operations compared to sliding-window
    In fact, on Weierstrass curves, known P, -P can be computed on the fly.

    The input point is assumed to be on curve and
    the m coefficient is assumed to have been reduced mod n
    if appropriate (e.g. cyclic groups of order n).
    """
    if m < 0:
        raise ValueError(f"negative m: {hex(m)}")

    # a number cannot be written in basis 1 (ie w=0)
    if w <= 0:
        raise ValueError(f"non positive w: {w}")

    # This exception must be kept to satisfy the following while loop
    if m == 0:
        return INFJ

    i = 0

    M: List[int] = []
    while m > 0:
        if (m % 2) == 1:
            M.append(mods(m, w))
            m -= M[i]
        else:
            M.append(0)
        m //= 2
        i += 1

    p = i

    b = pow(2, w)

    Q2 = ec._double_jac(Q)
    T = [Q]
    for i in range(1, (b // 2)):
        T.append(ec._add_jac(T[i - 1], Q2))
    for i in range((b // 2), b):
        T.append(ec.negate_jac(T[i - (b // 2)]))

    R = INFJ
    for j in range(p - 1, -1, -1):
        R = ec._double_jac(R)
        if M[j] != 0:
            if M[j] > 0:
                # It adds the element jQ
                R = ec._add_jac(R, T[(M[j] - 1) // 2])
            else:
                # In this case it adds the opposite, ie -jQ
                R = ec._add_jac(R, T[(b // 2) - ((M[j] + 1) // 2)])
    return R
