#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Elliptic curve point multiplication functions."""

from typing import List, Sequence

from .alias import Integer, JacPoint, Point
from .curve import Curve
from .curvegroup import (
    _double_mult,
    _jac_from_aff,
    _mult_fixed_window,
    _multi_mult,
)
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
    R = _mult_fixed_window(m, QJ, ec)
    return ec._aff_from_jac(R)


def double_mult(
    u: Integer, H: Point, v: Integer, Q: Point, ec: Curve = secp256k1
) -> Point:
    "Double scalar multiplication (u*H + v*Q)."

    ec.require_on_curve(H)
    HJ = _jac_from_aff(H)

    ec.require_on_curve(Q)
    QJ = _jac_from_aff(Q)

    u = int_from_integer(u) % ec.n
    v = int_from_integer(v) % ec.n
    R = _double_mult(u, HJ, v, QJ, ec)
    return ec._aff_from_jac(R)


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
