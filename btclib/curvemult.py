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
from typing import List, Sequence, Tuple

from .alias import INFJ, Integer, JacPoint, Point
from .curve import Curve, CurveGroup, _jac_from_aff, _mult_jac
from .curves import secp256k1
from .utils import int_from_integer


def mult(m: Integer, Q: Point = None, ec: Curve = secp256k1) -> Point:
    "Elliptic curve scalar multiplication."
    if Q is None:
        QJ = ec.GJ
    else:
        ec.require_on_curve(Q)
        QJ = _jac_from_aff(Q)

    m = int_from_integer(m) % ec.n
    R = _mult_jac(m, QJ, ec)
    return ec._aff_from_jac(R)


def _double_mult(
    u: int, HJ: JacPoint, v: int, QJ: JacPoint, ec: CurveGroup
) -> JacPoint:
    """Double scalar multiplication (u*H + v*Q).
     
    This implementation uses the Shamir-Strauss algorithm,
    'left-to-right' binary decomposition of the u and v coefficients,
    Jacobian coordinates.

    Strauss algorithm consists of a single 'double & add' loop
    for the parallel calculation of u*H and v*Q,
    efficiently using a single 'doubling' for both scalar multiplication.

    The Shamir trick adds the precomputation of H+Q,
    which is to be added in the loop when the binary digits
    of u and v are both equal to 1 (on average 1/4 of the cases).

    The input points are assumed to be on curve,
    the u and v coefficients are assumed to have been reduced mod n
    if appropriate (e.g. cyclic groups of order n).
    """

    if u < 0:
        raise ValueError(f"negative first coefficient: {hex(u)}")
    if v < 0:
        raise ValueError(f"negative second coefficient: {hex(v)}")

    # at each step one of the following points will be added
    t = [INFJ, HJ, QJ, ec._add_jac(HJ, QJ)]
    # which one depends on index
    ui = bin(u)[2:]
    vi = bin(v)[2:].zfill(len(ui))
    ui = ui.zfill(len(vi))
    index = [int(j) + 2 * int(k) for j, k in zip(ui, vi)]
    # R[0] is the running result, R[1] = R[0] + t[*] is an ancillary variable
    R = [t[index[0]], INFJ]
    # change t[0] to any value ≠ INFJ,
    # to avoid any _add_jac optimization for INFJ:
    # in any case t[0] will never be added to R[0]
    t[0] = HJ
    for i in index[1:]:
        # the doubling part of 'double & add'
        R[0] = ec._add_jac(R[0], R[0])
        # always perform the 'add', even if useless, to be constant-time
        # 'add' it to R[0] only if appropriate
        R[i==0] = ec._add_jac(R[0], t[i])
    return R[0]


def double_mult(
    u: Integer, H: Point, v: Integer, Q: Point, ec: Curve = secp256k1
) -> Point:
    "Shamir trick for efficient computation of u*H + v*Q."

    ec.require_on_curve(H)
    HJ = _jac_from_aff(H)

    ec.require_on_curve(Q)
    QJ = _jac_from_aff(Q)

    u = int_from_integer(u) % ec.n
    v = int_from_integer(v) % ec.n
    R = _double_mult(u, HJ, v, QJ, ec)
    return ec._aff_from_jac(R)


def _multi_mult(
    scalars: Sequence[int], JPoints: Sequence[JacPoint], ec: CurveGroup
) -> JacPoint:
    """Return the multi scalar multiplication u1*Q1 + ... + un*Qn.

    Use Bos-Coster's algorithm for efficient computation.

    The input points are assumed to be on curve,
    the scalar coefficients are assumed to have been reduced mod n
    if appropriate (e.g. cyclic groups of order n).
    """
    # source: https://cr.yp.to/badbatch/boscoster2.py

    if len(scalars) != len(JPoints):
        errMsg = "mismatch between number of scalars and points: "
        errMsg += f"{len(scalars)} vs {len(JPoints)}"
        raise ValueError(errMsg)

    # x = list(zip([-n for n in scalars], JPoints))
    x: List[Tuple[int, JacPoint]] = []
    for n, PJ in zip(scalars, JPoints):
        if n == 0:  # mandatory check to avoid infinite loop
            continue
        if n < 0:
            raise ValueError(f"negative coefficient: {hex(n)}")
        x.append((-n, PJ))

    if not x:
        return INFJ

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
    # assert n1 < ec.n, "better to take the mod n"
    # n1 %= ec.n
    return _mult_jac(n1, p1, ec)


def multi_mult(
    scalars: Sequence[Integer], Points: Sequence[Point], ec: Curve = secp256k1
) -> Point:
    """Return the multi scalar multiplication u1*Q1 + ... + un*Qn.

    Use Bos-Coster's algorithm for efficient computation.
    """

    if len(scalars) != len(Points):
        errMsg = "mismatch between number of scalars and points: "
        errMsg += f"{len(scalars)} vs {len(Points)}"
        raise ValueError(errMsg)

    JPoints: List[JacPoint] = list()
    ints: List[int] = list()
    for P, i in zip(Points, scalars):
        i = int_from_integer(i) % ec.n
        if i == 0:  # early optimization, even if not strictly necessary
            continue
        ints.append(i)
        ec.require_on_curve(P)
        JPoints.append(_jac_from_aff(P))

    R = _multi_mult(ints, JPoints, ec)
    return ec._aff_from_jac(R)
