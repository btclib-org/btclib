#!/usr/bin/env python3

# Copyright (C) The btclib developers
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
    - Interleaved-wNAF double multiplication (HMV algorithm 3.51)
    - GLV endomorphism multiplication for secp256k1 (HMV algorithm 3.77)

References:
    - https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication
    - https://cryptojedi.org/peter/data/eccss-20130911b.pdf
    - https://ecc2017.cs.ru.nl/slides/ecc2017school-castryck.pdf
    - https://cr.yp.to/bib/2003/joye-ladder.pdf
    - D. Hankerson, 'Guide to Elliptic Curve Cryptography' chapter 3
    - https://bitcointalk.org/index.php?topic=3238.msg45565#msg45565
    - https://medium.com/@CoinExChain/acceleration-of-ecdsa-verification-with-endomorphism-mapping-of-secp256k1-126e77a51dba

Further improvements, and the material for them. These are not
bibliography: each is an improvement this module could take, with what
would be needed to take it, kept here rather than in TODO.md so that it
sits next to the code it is about. The point-addition special cases are
settled where they live, in `curve_group`'s own comments, and issue 183
tracks the smaller follow-ups; what is here is the rest:

    - Computational cost of the different multiplications, measured rather
      than assumed: which of the six is fastest, and at what scalar size
    - New algorithms at the state of the art:

        - https://hal.archives-ouvertes.fr/hal-00932199/document
        - https://iacr.org/workshops/ches/ches2006/presentations/Douglas%20Stebila.pdf
        - https://arxiv.org/abs/1801.08589
        - https://eprint.iacr.org/2005/419
        - https://www.esat.kuleuven.be/cosic/publications/article-2293.pdf
        - https://crypto.stackexchange.com/questions/58506/what-is-the-curve-type-of-secp256k1
        - 1-s_2.0-S1071579704000395-main (the file name it was saved as; the
          paper it refers to has not been identified)
    - Strauss-wNAF, and Pippenger above a measured threshold, as the
      multi_mult libsecp256k1 dispatches between: issue 212. Bos-Coster
      stays whichever of them lands, the library being didactic as well --
      it is the one of the three that can be read in twenty lines
    - Peter Dettman's field inverses and square roots, a sliding window over
      blocks of 1s:

        - https://briansmith.org/ecc-inversion-addition-chains-01
    - Joint sparse form (JSF, HMV algorithm 3.50) for double mult: the
      alternative to the interleaving double_mult_w_NAF implements --
      one joint recoding of both scalars instead of one NAF each, fewer
      total additions in exchange for digit pairs that do not index a
      per-point table of odd multiples
"""

from __future__ import annotations

from btclib.alias import INFJ, JacPoint
from btclib.curves.curve_group import CurveGroup, convert_number_to_base
from btclib.exceptions import BTClibValueError


def mods(m: int, w: int) -> int:
    """Signed modulo function."""
    w2: int = pow(2, w)
    M = m % w2
    return M - w2 if M >= (w2 / 2) else M


def wNAF_of_m(m: int, w: int) -> list[int]:
    """WNAF (width-w Non-adjacent form) of number m.

    Given an integer m, wNAF is a method of representation
    with powers of 2, where the coefficients are odd or 0,
    and where at most one of any w consecutive digits is nonzero.
    It has the following properties:
    - m has a unique width-w NAF.
    -The length of wNAF(m) is at most one more than the length of the binary
    representation of k.
    -The average density of nonzero digits is approximately 1/(w + 1).

    For complete reference see:
    D. Hankerson, 'Guide to Elliptic Curve Cryptography' chapter 3
    """
    i = 0

    M: list[int] = []
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


def _sliding_window_table(Q: JacPoint, ec: CurveGroup, w: int) -> list[JacPoint]:
    """Return the multiples a full window can name, 2^(w-1)*Q to (2^w - 1)*Q.

    Half the table the fixed window needs, which is where "roughly half
    as complex a pre-computation" comes from: a window is only ever
    opened on a nonzero digit, so its value has its top bit set and no
    multiple below 2^(w-1) is ever indexed.
    """
    P = Q
    for _ in range(w - 1):
        P = ec.double_jac(P)
    T = [P]
    for _ in range(1, pow(2, w - 1)):
        T.append(ec.add_jac(T[-1], Q))
    return T


def _double_and_add(
    R: JacPoint, Q: JacPoint, digits: list[int], ec: CurveGroup
) -> JacPoint:
    """Fold digits into R by the plain binary method, one bit at a time."""
    for digit in digits:
        R = ec.double_jac(R)
        if digit == 1:
            R = ec.add_jac(R, Q)
    return R


def mult_sliding_window(m: int, Q: JacPoint, ec: CurveGroup, w: int = 4) -> JacPoint:
    """Scalar multiplication using "sliding window".

    It has the benefit that the pre-computation stage is roughly half as
    complex as the normal windowed method. It is not constant time. For
    256-bit scalars choose w=4 or w=5.

    The input point is assumed to be on curve and the m coefficient is
    assumed to have been reduced mod n if appropriate (e.g. cyclic
    groups of order n).
    """
    if m < 0:
        raise BTClibValueError(f"negative m: {hex(m)}")

    # a number cannot be written in basis 1 (ie w=0)
    if w <= 0:
        raise BTClibValueError(f"non positive w: {w}")

    # at each step one of the points in T will be added
    T = _sliding_window_table(Q, ec, w)
    p = pow(2, w - 1)

    digits = convert_number_to_base(m, 2)

    R = INFJ
    i = 0
    while i < len(digits):
        if digits[i] == 0:
            R = ec.double_jac(R)
            i += 1
            continue
        # a window opens here, and only a whole one indexes the table:
        # with fewer than w digits left the remainder is folded in bit by
        # bit instead, which is where the multiplication ends
        if len(digits) - i < w:
            return _double_and_add(R, Q, digits[i:], ec)
        # the w digits as a binary number; its top digit being 1, it is at
        # least 2^(w-1) and below 2^w, so entry t - 2^(w-1) of the table is
        # the multiple t*Q to be added
        t = 0
        for a in range(w):
            t = 2 * t + digits[i + a]
        for _ in range(w):
            R = ec.double_jac(R)
        R = ec.add_jac(R, T[t - p])
        i += w

    return R


def mult_w_NAF(m: int, Q: JacPoint, ec: CurveGroup, w: int = 4) -> JacPoint:
    """Scalar multiplication in Jacobian coordinates using wNAF.

    This implementation uses the same method called "w-ary non-adjacent
    form" (wNAF). We make use of the fact that point subtraction is as
    easy as point addition to perform fewer operations compared to
    sliding-window. In fact, on Weierstrass curves, known P, -P can be
    computed on the fly.

    The input point is assumed to be on curve and
    the m coefficient is assumed to have been reduced mod n
    if appropriate (e.g. cyclic groups of order n).
    'right-to-left' method.

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
    T.extend(ec.add_jac(T[i - 1], Q2) for i in range(1, (b // 4)))
    T.extend(ec.negate_jac(T[i - (b // 4)]) for i in range((b // 4), (b // 2)))
    R = INFJ
    for j in range(p - 1, -1, -1):
        R = ec.double_jac(R)
        if M[j] != 0:
            if M[j] > 0:
                # It adds the element jQ
                R = ec.add_jac(R, T[(M[j] - 1) // 2])
            elif w == 1:
                # Case w=1 must be studied on its own for now
                R = ec.add_jac(R, T[1])
            else:
                # In this case it adds the opposite, ie -jQ
                R = ec.add_jac(R, T[(b // 4) - ((M[j] + 1) // 2)])
    return R


def double_mult_w_NAF(
    u: int, HJ: JacPoint, v: int, QJ: JacPoint, ec: CurveGroup, w: int = 4
) -> JacPoint:
    """Double scalar multiplication (u*H + v*Q), interleaved wNAFs.

    Algorithm 3.51 of D. Hankerson, 'Guide to Elliptic Curve
    Cryptography': each coefficient gets its own width-w NAF and its own
    table of odd multiples, and one left-to-right loop shares the
    doublings, adding a (possibly negated) table entry wherever either
    NAF has a nonzero digit. Against curve_group's _double_mult -- the
    Shamir-Strauss binary loop -- the doublings are the same and the
    additions drop from one per bit to ~2/(w+1) per bit, the negative
    digits costing only an on-the-fly negation.

    This is the one the library calls: `curves.double_mult`, `dsa` and
    `ssa` verification and public key recovery all reach it, which on
    secp256k1 means every signature the bindings do not answer -- another
    curve, another hash function, a caller-supplied nonce, or the test
    suite holding the python path against them. Measured over random
    256-bit coefficients, best of seven: 1.03 ms against the 1.53 ms of
    curve_group's _double_mult, which stays as the reference the tests
    compare this against. w=5 measures 0.99 ms and w=3 1.10, so the
    default is within 4% of the best window and the table is half the
    size of w=5's.

    The gap over _double_mult is the wider since add_jac stopped
    shortcutting infinity: fewer additions is worth the more when an
    addition of infinity costs what any other costs, and the
    Shamir-Strauss loop makes one for a quarter of its digit pairs.

    The tables are also why it is not faster everywhere: they are built
    per call and per point, so a coefficient too short to amortize them
    pays for them. Against _double_mult, by coefficient size on
    secp256k1: 8 bits 1.37x *slower*, 16 bits 0.98, 24 bits 0.85, 32 bits
    0.81, 64 bits 0.72, 128 bits 0.68, 256 bits 0.67. The crossover is
    around 16 bits, so every curve with a real order is on the winning
    side and the toy curves of the test suite -- n = 11, n = 31 -- are
    the ones paying, about 3 us a call. Taken as it is rather than
    guarded by a size test: the guard would buy back a fraction of a
    second of the suite and put a branch in the middle of signature
    verification.

    The input points are assumed to be on curve, and the u and v
    coefficients are assumed to have been reduced mod n if appropriate
    (e.g. cyclic groups of order n).
    """
    if u < 0:
        raise BTClibValueError(f"negative first coefficient: {hex(u)}")
    if v < 0:
        raise BTClibValueError(f"negative second coefficient: {hex(v)}")
    # a number cannot be written in basis 1 (ie w=0)
    if w <= 0:
        raise BTClibValueError(f"non positive w: {w}")

    us = wNAF_of_m(u, w)
    vs = wNAF_of_m(v, w)

    # the odd multiples 1*P, 3*P, ..., (2^(w-1) - 1)*P of each point; a
    # digit d of a width-w NAF is odd with |d| < 2^(w-1), so d*P is
    # T[(|d| - 1) // 2], negated on the fly when d < 0. For w of 1 or 2
    # the digits are only +-1 and the tables are the points themselves
    H2 = ec.double_jac(HJ)
    TH = [HJ]
    for _ in range(2 ** (w - 2) - 1 if w > 2 else 0):
        TH.append(ec.add_jac(TH[-1], H2))
    Q2 = ec.double_jac(QJ)
    TQ = [QJ]
    for _ in range(2 ** (w - 2) - 1 if w > 2 else 0):
        TQ.append(ec.add_jac(TQ[-1], Q2))

    R = INFJ
    for j in range(max(len(us), len(vs)) - 1, -1, -1):
        R = ec.double_jac(R)
        if j < len(us) and us[j] != 0:
            d = us[j]
            T = TH[(d - 1) // 2] if d > 0 else ec.negate_jac(TH[(-d - 1) // 2])
            R = ec.add_jac(R, T)
        if j < len(vs) and vs[j] != 0:
            d = vs[j]
            T = TQ[(d - 1) // 2] if d > 0 else ec.negate_jac(TQ[(-d - 1) // 2])
            R = ec.add_jac(R, T)
    return R


# secp256k1 constants for the GLV endomorphism, all four functions of
# them below being specific to that curve:
# the group order,
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
# a cube root of 1 mod _N -- lam*(k1*G + k2*G) is (k1*lam)*G + (k2*lam)*G,
# which is what makes m1 + m2*lam a decomposition of a multiplier --
_LAM = 0x5363AD4CC05C30E0A5261C028812645A122E22EA20816678DF02967C1B23BD72
# the matching cube root of 1 mod p: lam*(x, y) = (beta*x, y), one field
# multiplication where a scalar multiplication by lam would be the very
# cost being avoided,
_BETA = 0x7AE96A2B657C07106E64479EAC3434E99CF0497512F58995C1396C28719501EE
# and the lattice basis of algorithm 3.74, satisfying
# a1 + b1*lam = a2 + b2*lam = 0 mod _N with all four ~ sqrt(_N)
_A1 = 0x3086D221A7D46BCDE86C90E49284EB15
_B1 = -0xE4437ED6010E88286F547FA90ABFE4C3
_A2 = 0x114CA50F7A8E2F3F657C1108D9D44CFD8
_B2 = 0x3086D221A7D46BCDE86C90E49284EB15


def multiplier_decomposer(m: int) -> tuple[int, int]:
    """Decompose m into m1, m2 with m1 + m2*lambda = m mod n.

    Balanced length-two representation, algorithm 3.74 of D. Hankerson,
    'Guide to Elliptic Curve Cryptography', with the constants of
    secp256k1: both m1 and m2 are signed and at most 128 bits, so the
    double multiplication they feed costs half the doublings of the
    single one it replaces. Any integer decomposes, a negative or
    oversized m being reduced mod n first.

    Signed and mod n are the whole of the algorithm (issue #215): the
    congruence only holds mod the group order, and secp256k1's p and n
    share their top 128 bits, so reducing mod ec.p instead would send
    every scalar above ~2^127 to a wrong answer. Rounding is to nearest,
    not with ceil, whose bias costs the balance: round-to-nearest is
    what makes c1, c2 the closest lattice point and m1, m2 short. The
    results stay signed, since a final mod-p reduction would throw away
    the sign that point negation is there to absorb, and hand
    _double_mult two 256-bit multipliers for an 8-bit m.
    """
    m %= _N

    # round-to-nearest as (2*x + n) // (2*n), spelled with the shared
    # n // 2 offset: python floor division makes (x + n//2) // n exact,
    # where round(b2 * m / _N) would go through a float
    c1 = (_B2 * m + _N // 2) // _N
    c2 = (-_B1 * m + _N // 2) // _N

    m1 = m - c1 * _A1 - c2 * _A2
    m2 = -c1 * _B1 - c2 * _B2

    return m1, m2


def mult_endomorphism_secp256k1(m: int, Q: JacPoint, ec: CurveGroup) -> JacPoint:
    """Scalar multiplication in Jacobian coordinates using endomorphism.

    Algorithm 3.77 of D. Hankerson, 'Guide to Elliptic Curve
    Cryptography': m*Q as m1*Q + m2*(lambda*Q), the halves coming from
    multiplier_decomposer and the double multiplication interleaving
    their wNAFs. Measured over 30 random 256-bit scalars: 0.53 ms at the
    default w=4, against 0.80 ms feeding the same halves to curve_group's
    _double_mult and 0.84 ms for the _mult this exists to beat -- the
    fastest python multiplication in the package, and the w=4 default is
    that measurement, the same halves interleaved at w=3 giving 0.57 ms
    and at w=5 0.52, which is the default's own noise.
    """
    if m < 0:
        raise BTClibValueError(f"negative m: {hex(m)}")

    m1, m2 = multiplier_decomposer(m)

    K = ((Q[0] * _BETA) % ec.p), Q[1], Q[2]  # K = lambda*Q, direct calculation

    # the decomposition is signed on purpose -- balance is what makes the
    # halves short -- and the sign belongs to the point: -m1*Q is m1*(-Q),
    # one modular negation of a y-coordinate
    P = Q
    if m1 < 0:
        m1, P = -m1, ec.negate_jac(P)
    if m2 < 0:
        m2, K = -m2, ec.negate_jac(K)

    return double_mult_w_NAF(m1, P, m2, K, ec)
