#!/usr/bin/env python3

import os
import time
from btclib.ecssa import ecssa_sign, ecssa_verify, ecssa_batch_validation
from btclib.ellipticcurves import pointMultiply, pointMultiplyJacobian, \
                                  secp256k1 as ec

n_sig = [1, 2, 5, 10, 50, 100, 500]
l = len(n_sig)

no_batch_time = []
batch_time = []

for i in range(0, l):
    q = []
    Q = []
    m = []
    sigma = []
    a = []
    for j in range(0, n_sig[i]):
        q.append(int.from_bytes(os.urandom(ec.bytesize), 'big'))
        Q.append(pointMultiplyJacobian(ec, q[j], ec.G))
        m.append(os.urandom(ec.bytesize))
        sigma.append(ecssa_sign(ec, m[j], q[j]))
        if j != 0:
            a.append(int.from_bytes(os.urandom(ec.bytesize), 'big'))
        else:
            a.append(1)

    # no batch
    no_batch_check = []
    no_batch_start = time.time()
    for j in range(0, n_sig[i]):
        no_batch_check.append(ecssa_verify(ec, m[j], sigma[j], Q[j]))
    no_batch_end = time.time()

    no_batch_time.append(no_batch_end - no_batch_start)
    for j in range(0, n_sig[i]):
        assert no_batch_check[j] == True

    # batch
    batch_start = time.time()
    batch_check = ecssa_batch_validation(n_sig[i], Q, m, sigma, a)
    batch_end = time.time()

    batch_time.append(batch_end - batch_start)
    assert batch_check == True

print(no_batch_time)
print(batch_time)