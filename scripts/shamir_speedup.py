#!/usr/bin/env python3
from btclib.ellipticcurves import DoubleScalarMultiplication, pointAdd, \
                                  pointMultiply, pointMultiplyJacobian, \
                                  secp256k1 as ec
import os
import time

k1 = int.from_bytes(os.urandom(32), 'big')
k2 = int.from_bytes(os.urandom(32), 'big')

q = int.from_bytes(os.urandom(32), 'big')
Q = pointMultiplyJacobian(ec, q, ec.G)

start = time.time()
res1 = pointAdd(ec, pointMultiply(ec, k1, ec.G), pointMultiply(ec, k2, Q))
end = time.time()

t1 = end - start

start = time.time()
res2 = pointAdd(ec, pointMultiplyJacobian(ec, k1, ec.G), pointMultiplyJacobian(ec, k2, Q))
end = time.time()

t2 = end - start

start = time.time()
res3 = DoubleScalarMultiplication(ec, k1, ec.G, k2, Q)
end = time.time()

t3 = end - start

assert res1 == res2
assert res2 == res3

print(t1)
print(t2)
print(t3)