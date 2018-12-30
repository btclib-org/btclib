#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from btclib.ec import sha256, Scalar, Point, EC, secp256k1, \
    DblScalarMult, secondGenerator


def pedersen_commit(r: Scalar, v: Scalar, ec: EC, hf) -> Point:
    # rG + vH
    H = secondGenerator(ec, hf)
    Q = DblScalarMult(ec, r, ec.G, v, H)
    if Q[1] == 0:
        raise ValueError("failed")
    return Q


def pedersen_open(r: Scalar, v: Scalar, C: Point, ec: EC, hf) -> bool:
    return C == pedersen_commit(r, v, ec, hf)
