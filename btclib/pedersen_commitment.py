#!/usr/bin/env python3

from btclib.ellipticcurves import EllipticCurve, Point, Scalar, \
                                  DoubleScalarMultiplication, secondGenerator

def pedersen_commit(ec: EllipticCurve, r: Scalar, v: Scalar) -> Point:
    # rG + vH
    Q = DoubleScalarMultiplication(ec, r, v, ec.G, secondGenerator(ec))
    assert Q is not None, "failed"
    return Q

def pedersen_open(ec: EllipticCurve, r: Scalar, v: Scalar, C: Point) -> bool:
    return C == pedersen_commit(ec, r, v)
