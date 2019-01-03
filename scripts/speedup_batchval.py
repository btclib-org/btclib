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
from hashlib import sha256

from btclib.ec import pointMult
from btclib.ecurves import secp256k1
from btclib.ecssa import ecssa_sign, ecssa_verify, ecssa_batch_validation

random.seed(42)

ec = secp256k1
hf = sha256
hsize =hf().digest_size
hlen = hsize * 8

n_sig = [2, 4, 8, 16, 32, 64, 128]
m = []
sig = []
Q = []
a = []
for j in range(max(n_sig)):
    m.append(random.getrandbits(hlen).to_bytes(hsize, 'big'))
    q = random.getrandbits(ec.nlen) % ec.n
    sig.append(ecssa_sign(ec, hf, m[j], q))
    Q.append(pointMult(ec, q, ec.G))
    if j != 0:
        a.append(random.getrandbits(ec.nlen) % ec.n)
    else:
        a.append(1) # FIXME: ?

for n in n_sig:

    # no batch
    start = time.time()
    for j in range(n):
        assert ecssa_verify(ec, hf, m[j], Q[j], sig[j])
    elapsed1 = time.time() - start

    # batch
    start = time.time()
    assert ecssa_batch_validation(ec, hf, m, Q, a, sig)
    elapsed2 = time.time() - start

    print(n, elapsed2 / elapsed1)
