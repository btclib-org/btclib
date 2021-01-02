#!/usr/bin/env python3

# Copyright (C) 2017-2021 The btclib developers
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

from btclib.alias import HashF, Point
from btclib.ecc.curve import Curve, double_mult, secp256k1
from btclib.ecc.sec_point import bytes_from_point
from btclib.exceptions import BTClibRuntimeError, BTClibValueError
from btclib.utils import int_from_bits


def second_generator(ec: Curve = secp256k1, hf: HashF = sha256) -> Point:
    """Second (with respect to G) elliptic curve generator.

    Second (with respect to G) Nothing-Up-My-Sleeve (NUMS)
    elliptic curve generator.

    The hash of G is coerced it to a point (x_H, y_H).
    If the resulting point is not on the curve, keep on
    incrementing x_H until a valid curve point (x_H, y_H) is obtained.

    idea:
    https://crypto.stackexchange.com/questions/25581/second-generator-for-secp256k1-curve

    source:
    https://github.com/ElementsProject/secp256k1-zkp/blob/secp256k1-zkp/src/modules/rangeproof/main_impl.h
    """

    G_bytes = bytes_from_point(ec.G, ec, compressed=False)
    hash_ = hf()
    hash_.update(G_bytes)
    hash_digest = hash_.digest()
    x_H = int_from_bits(hash_digest, ec.nlen) % ec.n
    while True:
        try:
            y_H = ec.y_even(x_H)
            return x_H, y_H
        except BTClibValueError:
            x_H += 1
            x_H %= ec.p


def commit(r: int, v: int, ec: Curve = secp256k1, hf: HashF = sha256) -> Point:
    """Commit to r, returning rG+vH.

    Commit to r, returning rG+vH. H is the second Nothing-Up-My-Sleeve
    (NUMS) generator of the curve.
    """

    H = second_generator(ec, hf)
    Q = double_mult(v, H, r, ec.G, ec)
    # edge case that cannot be reproduced in the test suite
    if Q[1] == 0:
        err_msg = "invalid (INF) key"  # pragma: no cover
        raise BTClibRuntimeError(err_msg)  # pragma: no cover
    return Q


def verify(
    r: int, v: int, commitment: Point, ec: Curve = secp256k1, hf: HashF = sha256
) -> bool:
    """Open the commitment and return True if valid."""

    # all kind of Exceptions are catched because
    # verify must always return a bool
    try:
        Q = commit(r, v, ec, hf)
    except Exception:  # pylint: disable=broad-except
        return False
    return commitment == Q
