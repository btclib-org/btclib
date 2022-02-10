#!/usr/bin/env python3

# Copyright (C) 2020-2022 The btclib developers
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
    - https://cr.yp.to/bib/2003/joye-ladder.pdf
    - D. Hankerson, 'Guide to Elliptic Curve Cryptography' chapter 3
    - https://bitcointalk.org/index.php?topic=3238.msg45565#msg45565
    - https://medium.com/@CoinExChain/acceleration-of-ecdsa-verification-with-endomorphism-mapping-of-secp256k1-126e77a51dba

TODO:
    - Computational cost of the different multiplications
    - New alghoritms at the state-of-art:
        -https://hal.archives-ouvertes.fr/hal-00932199/document
        -https://iacr.org/workshops/ches/ches2006/presentations/Douglas%20Stebila.pdf
        -1-s_2.0-S1071579704000395-main
        -https://crypto.stackexchange.com/questions/58506/what-is-the-curve-type-of-secp256k1
    - Multi_mult algorithm: why does it work?
    - Peter Dettman's field inverses and square roots using a sliding window over blocks of 1s
        -https://briansmith.org/ecc-inversion-addition-chains-01
    - Joint sparse form (JSF) for double mult
    -  Interleaving with NAFs
"""


from math import ceil
from typing import List, Tuple

from btclib.alias import INFJ, JacPoint
from btclib.ecc.curve_group import CurveGroup, _double_mult, convert_number_to_base
from btclib.exceptions import BTClibValueError


def mods(m: int, w: int) -> int:
    "Signed modulo function."

    w2 = pow(2, w)
    M = m % w2
    return M - w2 if M >= (w2 / 2) else M


def wNAF_of_m(m: int, w: int) -> List[int]:
    """wNAF (width-w Non-adjacent form) of number m

    Given an integer m, wNAF is a method of rapresentation
    with powers of 2, where the coefficients are odd or 0,
    and where at most one of any w consecutive digits is nonzero.
    It has the following propreties:
    - m has a unique width-w NAF.
    -The length of wNAF(m) is at most one more than the length of the binary
    representation of k.
    -The average density of nonzero digits is approximately 1/(w + 1).

    For complete reference see:
    D. Hankerson, 'Guide to Elliptic Curve Cryptography' chapter 3
    """

    i = 0

    M: List[int] = []
    while m > 0:
        if (m % 2) == 1:
            if w == 1:
                # Computing binary NAF of m
                M.append(2 - (m % 4))
            else:
                # Computing wNAF of m
                M.append(mods(m, w))
            m -= M[i]
        else:
            M.append(0)
        m //= 2
        i += 1

    return M


def mult_sliding_window(m: int, Q: JacPoint, ec: CurveGroup, w: int = 4) -> JacPoint:
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
        raise BTClibValueError(f"negative m: {hex(m)}")

    # a number cannot be written in basis 1 (ie w=0)
    if w <= 0:
        raise BTClibValueError(f"non positive w: {w}")

    k = w - 1
    p = pow(2, k)

    # at each step one of the points in T will be added
    P = Q
    for _ in range(k):
        P = ec.double_jac(P)
    T = [P]
    for i in range(1, p):
        T.append(ec.add_jac(T[i - 1], Q))

    digits = convert_number_to_base(m, 2)

    R = INFJ
    i = 0
    while i < len(digits):
        if digits[i] == 0:
            R = ec.double_jac(R)
            i += 1
        else:
            j = len(digits) - i if (len(digits) - i) < w else w
            t = digits[i]
            for a in range(1, j):
                t = 2 * t + digits[i + a]

            if j < w:
                for b in range(i, (i + j)):
                    R = ec.double_jac(R)
                    if digits[b] == 1:
                        R = ec.add_jac(R, Q)
                return R
            for _ in range(w):
                R = ec.double_jac(R)
            R = ec.add_jac(R, T[t - p])
            i += j

    return R


def mult_w_NAF(m: int, Q: JacPoint, ec: CurveGroup, w: int = 4) -> JacPoint:
    """Scalar multiplication in Jacobian coordinates using wNAF.

    This implementation uses the same method called "w-ary non-adjacent form" (wNAF)
    we make use of the fact that point subtraction is as easy as point addition to perform fewer operations compared to sliding-window
    In fact, on Weierstrass curves, known P, -P can be computed on the fly.

    The input point is assumed to be on curve and
    the m coefficient is assumed to have been reduced mod n
    if appropriate (e.g. cyclic groups of order n).
    'right-to-left' method.

    FIXME:
    - Make it constant time (if necessary)
    - Try to avoid exception in negation for w=1
    """

    if m < 0:
        raise BTClibValueError(f"negative m: {hex(m)}")

    # a number cannot be written in basis 1 (ie w=0)
    if w <= 0:
        raise BTClibValueError(f"non positive w: {w}")

    M = wNAF_of_m(m, w)

    p = len(M)

    b = pow(2, w)

    Q2 = ec.double_jac(Q)
    T = [Q]
    for i in range(1, (b // 4)):
        T.append(ec.add_jac(T[i - 1], Q2))
    for i in range((b // 4), (b // 2)):
        T.append(ec.negate_jac(T[i - (b // 4)]))

    R = INFJ
    for j in range(p - 1, -1, -1):
        R = ec.double_jac(R)
        if M[j] != 0:
            if M[j] > 0:
                # It adds the element jQ
                R = ec.add_jac(R, T[(M[j] - 1) // 2])
            else:
                # In this case it adds the opposite, ie -jQ
                if w != 1:
                    R = ec.add_jac(R, T[(b // 4) - ((M[j] + 1) // 2)])
                else:
                    # Case w=1 must be studied on its own for now
                    R = R = ec.add_jac(R, T[1])
    return R


def multiplier_decomposer(m: int, ec: CurveGroup) -> Tuple[int, int]:
    """Decompose m in two integers m1 e m2 so that mP = m1*P + m2*lambda*P.

    Used for point multiplication with efficiently computable endomorphisms.

    Based on alghoritm 3.74 of
    D. Hankerson, 'Guide to Elliptic Curve Cryptography'.
    Values computed for secp256k1.
    """

    if m < 0:
        raise ValueError(f"negative m: {hex(m)}")

    m %= ec.p

    # balanced length-two representation of a multiplier m.
    # values for secp256k1.
    # https://medium.com/@CoinExChain/acceleration-of-ecdsa-verification-with-endomorphism-mapping-of-secp256k1-126e77a51dba
    a1 = 0x3086D221A7D46BCDE86C90E49284EB15 % ec.p
    b1 = -0xE4437ED6010E88286F547FA90ABFE4C3 % ec.p
    a2 = 0x114CA50F7A8E2F3F657C1108D9D44CFD8 % ec.p
    b2 = 0x3086D221A7D46BCDE86C90E49284EB15 % ec.p

    c1 = ceil(b2 * m / ec.p)
    c2 = ceil((-1) * b1 * m / ec.p)

    m1 = m - (a1 * c1) - (a2 * c2)
    m2 = -(c1 * b1) - (c2 * b2)

    return m1 % ec.p, m2 % ec.p


def mult_endomorphism_secp256k1(m: int, Q: JacPoint, ec: CurveGroup) -> JacPoint:
    "Scalar multiplication in Jacobian coordinates using efficient endomorphism."

    m1, m2 = multiplier_decomposer(m, ec)

    # Values for the efficient endomorphism multiplication
    # see D. Hankerson, 'Guide to Elliptic Curve Cryptography' chapter 3.5
    # lam = 0x5363AD4CC05C30E0A5261C028812645A122E22EA20816678DF02967C1B23BD72
    beta = 0x7AE96A2B657C07106E64479EAC3434E99CF0497512F58995C1396C28719501EE

    K = ((Q[0] * beta) % ec.p), Q[1], Q[2]  # K = lambda*Q, direct calculation

    # FIXME: Change double mult (?) with alghoritm 3.77
    return _double_mult(m1, Q, m2, K, ec)
