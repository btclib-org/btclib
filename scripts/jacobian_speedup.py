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

from btclib.ellipticcurves import secp256k1, _jac_from_affine, \
    _pointMultiplyAffine, _pointMultiplyJacobian

random.seed(42)

ec = secp256k1
bits = ec.bytesize * 8

# setup
qs = []
for _ in range(0, 50):
    qs.append(random.getrandbits(bits) % ec.n)

start = time.time()
for q in qs:
    _pointMultiplyAffine(ec, q, ec.G)
elapsed1 = time.time() - start

start = time.time()
for q in qs:
    # starts from affine coordinates, ends with affine coordinates
    GJ = _jac_from_affine(ec.G)
    ec._affine_from_jac(_pointMultiplyJacobian(ec, q, GJ))
elapsed2 = time.time() - start

print(elapsed2 / elapsed1)
