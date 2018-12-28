#!/usr/bin/env python3

from btclib.ellipticcurves import sha256, EllipticCurve, secp256k1, Point, \
    Scalar, DoubleScalarMultiplication, secondGenerator


def pedersen_commit(r: Scalar,
                    v: Scalar,
                    ec: EllipticCurve = secp256k1,
                    Hash=sha256) -> Point:
    # rG + vH
    H = secondGenerator(ec, Hash)
    Q = DoubleScalarMultiplication(ec, r, ec.G, v, H)
    assert Q is not None, "failed"
    return Q


def pedersen_open(r: Scalar,
                  v: Scalar,
                  C: Point,
                  ec: EllipticCurve = secp256k1,
                  Hash=sha256) -> bool:
    return C == pedersen_commit(r, v, ec, Hash)
