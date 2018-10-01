#!/usr/bin/env python3

from btclib.ellipticcurves import EllipticCurve, Point, Scalar, \
                                  pointAdd, pointMultiply, secondGenerator

def pedersen_commit(ec: EllipticCurve, r: Scalar, v: Scalar) -> Point:
    rG = pointMultiply(ec, r, ec.G)
    vH = pointMultiply(ec, v, secondGenerator(ec))
    return pointAdd(ec, rG, vH)

def pedersen_open(ec: EllipticCurve, r: Scalar, v: Scalar, C: Point) -> bool:
    return C == pedersen_commit(ec, r, v)