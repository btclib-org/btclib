#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from btclib.ec import Scalar, Point, int_from_Scalar, bytes_from_Point, EC, \
    DblScalarMult

def secondGenerator(ec: EC, hf) -> Point:
    """Nothing-Up-My-Sleeve (NUMS) second generator H wrt ec.G 

       source: https://github.com/ElementsProject/secp256k1-zkp/blob/secp256k1-zkp/src/modules/rangeproof/main_impl.h
       idea: (https://crypto.stackexchange.com/questions/25581/second-generator-for-secp256k1-curve)
       Get the hash of G, then coerce it to a point (hx, hy).
       The resulting point could not be a curvepoint: in this case keep on
       incrementing hx until a valid curve point (hx, hy) is obtained.
    """
    G_bytes = bytes_from_Point(ec, ec.G, False)
    hd = hf(G_bytes).digest()
    hx = int_from_Scalar(ec, hd)
    isCurvePoint = False
    while not isCurvePoint:
        try:
            hy = ec.yOdd(hx, False)
            isCurvePoint = True
        except:
            hx += 1
    return hx, hy


def pedersen_commit(r: Scalar, v: Scalar, ec: EC, hf) -> Point:
    """Return rG + vH, with H being second (NUMS) generator of the curve"""
    H = secondGenerator(ec, hf)
    Q = DblScalarMult(ec, r, ec.G, v, H)
    if Q[1] == 0:
        raise ValueError("failed")
    return Q


def pedersen_open(r: Scalar, v: Scalar, C: Point, ec: EC, hf) -> bool:
    try:
        P = pedersen_commit(r, v, ec, hf)
    except:
        return False
    return C == P
