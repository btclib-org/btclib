#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from .curve import Point, Curve, double_mult
from .utils import int_from_octets, octets_from_point, int_from_bits

def second_generator(ec: Curve, hf) -> Point:
    """Nothing-Up-My-Sleeve (NUMS) second generator H wrt ec.G 

       source: https://github.com/ElementsProject/secp256k1-zkp/blob/secp256k1-zkp/src/modules/rangeproof/main_impl.h
       idea: https://crypto.stackexchange.com/questions/25581/second-generator-for-secp256k1-curve
       Get the hash of G, then coerce it to a point (hx, hy).
       The resulting point could not be a curvepoint: in this case keep on
       incrementing hx until a valid curve point (hx, hy) is obtained.
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


def commit(r: int, v: int, ec: Curve, hf) -> Point:
    """Return rG + vH, with H being second (NUMS) generator of the curve"""
    H = second_generator(ec, hf)
    Q = double_mult(ec, v, H, r)
    assert Q[1] != 0, "how did you do that?!?"
    return Q


def open(r: int, v: int, C: Point, ec: Curve, hf) -> bool:
    # try/except wrapper for the Errors raised by commit
    try:
        P = commit(r, v, ec, hf)
    except:
        return False
    return C == P
