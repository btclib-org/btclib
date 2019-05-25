#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Pedersen commitment functions.

In a commitment scheme the committer:

* decides (or is given) a secret message v
* decides a random secret r
* *commits* to v by applying the public commitment
  scheme algorithm and producing a commitment C=Commit(r,v)
* makes C public

Later, when he reveals r and v, the verifier *opens* the 
commitment checking if indeed C=Commit(r,v).

Pedersen commitment uses a public group of large order n
in which the discrete logarithm is hard.
In the case of an elliptic curve group, the generator G is
supplemented with a second random generator H and
the commitment algorithm is Commit(r,v)=rG+vH.
It is crucial for H to be Nothing-Up-My-Sleeve (NUMS), i.e.
the discrete logarithm of H with respect to G must be unknown.
"""

from .utils import int_from_octets, octets_from_point, \
    int_from_bits, HashF
from .curve import Point, Curve, double_mult

def second_generator(ec: Curve, hf: HashF) -> Point:
    """Second (with respect to G) elliptic curve generator.

    Second (with respect to G) Nothing-Up-My-Sleeve (NUMS)
    elliptic curve generator.

    The hash of G is coerced it to a point (hx, hy).
    If the resulting point is not on the curve, keep on
    incrementing hx until a valid curve point (hx, hy) is obtained.

    idea: https://crypto.stackexchange.com/questions/25581/second-generator-for-secp256k1-curve

    source: https://github.com/ElementsProject/secp256k1-zkp/blob/secp256k1-zkp/src/modules/rangeproof/main_impl.h
    """

    G_bytes = octets_from_point(ec, ec.G, False)
    hd = hf(G_bytes).digest()
    hx = int_from_bits(ec, hd)
    isCurvePoint = False
    while not isCurvePoint:
        try:
            hy = ec.y_odd(hx, False)
            isCurvePoint = True
        except:
            hx += 1
    return Point(hx, hy)


def commit(r: int, v: int, ec: Curve, hf: HashF) -> Point:
    """Commit to r, returning rG+vH.

    Commit to r, returning rG+vH. H is the second Nothing-Up-My-Sleeve
    (NUMS) generator of the curve.
    """

    H = second_generator(ec, hf)
    Q = double_mult(ec, v, H, r)
    assert Q[1] != 0, "how did you do that?!?"
    return Q


def open(r: int, v: int, C: Point, ec: Curve,
         hf: HashF) -> bool:
    """Open the commitment C and return True if valid."""

    # try/except wrapper for the Errors raised by commit
    try:
        P = commit(r, v, ec, hf)
    except:
        return False
    return C == P
