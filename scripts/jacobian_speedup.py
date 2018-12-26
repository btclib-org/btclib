#!/usr/bin/env python3

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
