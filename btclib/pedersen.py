#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
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

from hashlib import sha256

from .alias import HashF, Point
from .curve import Curve, double_mult, secp256k1
from .exceptions import BTClibValueError
from .secpoint import bytes_from_point
from .utils import int_from_bits


def second_generator(ec: Curve = secp256k1, hf: HashF = sha256) -> Point:
    """Second (with respect to G) elliptic curve generator.

    Second (with respect to G) Nothing-Up-My-Sleeve (NUMS)
    elliptic curve generator.

    The hash of G is coerced it to a point (hx, hy).
    If the resulting point is not on the curve, keep on
    incrementing hx until a valid curve point (hx, hy) is obtained.

    idea:
    https://crypto.stackexchange.com/questions/25581/second-generator-for-secp256k1-curve

    source:
    https://github.com/ElementsProject/secp256k1-zkp/blob/secp256k1-zkp/src/modules/rangeproof/main_impl.h
    """

    compressed = False
    G_bytes = bytes_from_point(ec.G, ec, compressed)
    h = hf()
    h.update(G_bytes)
    hd = h.digest()
    hx = int_from_bits(hd, ec.nlen) % ec.n
    isCurvePoint = False
    while not isCurvePoint:
        try:
            hy = ec.y_even(hx)
            isCurvePoint = True
        except BTClibValueError:
            hx += 1
            hx %= ec.p
    return hx, hy


def commit(r: int, v: int, ec: Curve = secp256k1, hf: HashF = sha256) -> Point:
    """Commit to r, returning rG+vH.

    Commit to r, returning rG+vH. H is the second Nothing-Up-My-Sleeve
    (NUMS) generator of the curve.
    """

    H = second_generator(ec, hf)
    Q = double_mult(v, H, r, ec.G, ec)
    # edge case that cannot be reproduced in the test suite
    assert Q[1] != 0, "invalid (INF) key"
    return Q


def verify(r: int, v: int, C: Point, ec: Curve = secp256k1, hf: HashF = sha256) -> bool:
    """Open the commitment C and return True if valid."""

    # all kind of Exceptions are catched because
    # verify must always return a bool
    try:
        P = commit(r, v, ec, hf)
    except Exception:  # pylint: disable=broad-except
        return False
    return C == P
