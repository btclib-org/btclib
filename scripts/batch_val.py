#!/usr/bin/env python3

import os
import time

from btclib.ellipticcurves import secp256k1 as ec, \
                                  int_from_Scalar, pointMultiply
from btclib.ecssa import ecssa_sign, ecssa_verify, ecssa_batch_validation

n_sig = [1, 2, 5, 10, 50, 100, 500]
m = []
sig = []
q = []
Q = []
a = []
for j in range(0, max(n_sig)):
    m.append(os.urandom(ec.bytesize))
    q.append(int_from_Scalar(ec, os.urandom(ec.bytesize)))
    sig.append(ecssa_sign(m[j], q[j]))
    Q.append(pointMultiply(ec, q[j], ec.G))
    if j != 0:
        a.append(int.from_bytes(os.urandom(ec.bytesize), 'big'))
    else:
        a.append(1)

for n in n_sig:

    # no batch
    start = time.time()
    for j in range(0, n):
        assert ecssa_verify(sig[j], m[j], Q[j])
    elapsed = time.time() - start
    print(elapsed, )

    # batch
    start = time.time()
    assert ecssa_batch_validation(sig, m, Q, a)
    batch_end = time.time()
    elapsed = time.time() - start
    print(elapsed)
