#!/usr/bin/env python3

import os
import time

from btclib.ellipticcurves import Point, secp256k1 as ec, \
                                  pointMultiply, DoubleScalarMultiplication, \
                                  int_from_Scalar

# setup
k1s = []
k2s = []
Qs = []
for _ in range(0, 100):
    k1 = int_from_Scalar(ec, os.urandom(ec.bytesize))
    k1s.append(k1)
    k2 = int_from_Scalar(ec, os.urandom(ec.bytesize))
    k2s.append(k2)
    q = int_from_Scalar(ec, os.urandom(ec.bytesize))
    Qs.append(pointMultiply(ec, q, ec.G))

start = time.time()
for i in range(0, 100):
    ec.add(pointMultiply(ec, k1s[i], ec.G),
           pointMultiply(ec, k2s[i], Qs[i]))
elapsed1 = time.time() - start

start = time.time()
for i in range(0, 100):
    DoubleScalarMultiplication(ec, k1s[i], ec.G, k2s[i], Qs[i])
elapsed2 = time.time() - start

print(elapsed2 / elapsed1)
