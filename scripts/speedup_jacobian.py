#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import random
import time

from btclib.ec import _jac_from_aff, _pointMultAffine, _pointMultJacobian
from btclib.ecurves import secp256k1

random.seed(42)

ec = secp256k1

# setup
qs = []
for _ in range(50):
    qs.append(random.getrandbits(ec.nlen) % ec.n)

start = time.time()
for q in qs:
    _pointMultAffine(ec, q, ec.G)
elapsed1 = time.time() - start

start = time.time()
for q in qs:
    # starts from affine coordinates, ends with affine coordinates
    GJ = _jac_from_aff(ec.G)
    ec._affine_from_jac(_pointMultJacobian(ec, q, GJ))
elapsed2 = time.time() - start

print(elapsed2 / elapsed1)
