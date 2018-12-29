#!/usr/bin/env python3

# Copyright (C) 2017-2019 The bbtlib developers
#
# This file is part of bbtlib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of bbtlib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import os
import time

from btclib.ellipticcurves import secp256k1 as ec, \
                                  _pointMultiplyAffine, \
                                  _pointMultiplyJacobian, \
                                  _jac_from_affine, \
                                  int_from_Scalar

# setup
qs = []
for _ in range(0, 100):
    q = int_from_Scalar(ec, os.urandom(ec.bytesize))
    qs.append(q)

start = time.time()
for q in qs:
    Q = _pointMultiplyAffine(ec, q, ec.G)
elapsed1 = time.time() - start

GJ = _jac_from_affine(ec.G)
start = time.time()
for q in qs:
    QJ = _pointMultiplyJacobian(ec, q, GJ)
    Q = ec._affine_from_jac(QJ)
elapsed2 = time.time() - start

print(elapsed2 / elapsed1)
