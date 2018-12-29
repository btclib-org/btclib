#!/usr/bin/env python3

# Copyright (C) 2017-2019 The bbtlib developers
#
# This file is part of bbtlib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of bbtlib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import random
import time

from btclib.ellipticcurves import secp256k1, pointMultiply, DoubleScalarMultiplication

random.seed(42)

ec = secp256k1
bits = ec.bytesize * 8

# setup
k1 = []
k2 = []
Q = []
for _ in range(50):
    k1.append(random.getrandbits(bits) % ec.n)
    k2.append(random.getrandbits(bits) % ec.n)
    q = random.getrandbits(bits) % ec.n
    Q.append(pointMultiply(ec, q, ec.G))

start = time.time()
for i in range(len(Q)):
    ec.add(pointMultiply(ec, k1[i], ec.G),
           pointMultiply(ec, k2[i], Q[i]))
elapsed1 = time.time() - start

start = time.time()
for i in range(len(Q)):
    DoubleScalarMultiplication(ec, k1[i], ec.G, k2[i], Q[i])
elapsed2 = time.time() - start

print(elapsed2 / elapsed1)
