#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from hashlib import sha256 as hf

from btclib.numbertheory import mod_inv
from btclib.ec import pointMult
from btclib.ecurves import secp256k1 as ec

print("\n*** EC:")
print(ec)

q = 0x18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725
q = q % ec.n
print("\n*** Keys:")
print("prvkey:   ", hex(q))

Q = pointMult(ec, q, ec.G)
print("PubKey:", "02" if (Q[1] % 2 == 0) else "03", hex(Q[0]))

print("\n*** Message to be signed")
msg1 = "Paolo is afraid of ephemeral random numbers"
print(msg1)

print("*** Hash digest of the message")
h_bytes = hf(msg1.encode()).digest()
# hash(msg) must be transformed into an integer modulo ec.n:
h1 = int.from_bytes(h_bytes, 'big') % ec.n
assert h1 != 0
print("    h1:", hex(h1))

print("\n*** Signature")
# ephemeral key k must be kept secret and never reused !!!!!
# good choice: k = hf(msg|q)
# different for each msg, private because of q
temp = msg1+hex(q)
k_bytes = hf(temp.encode()).digest()
k1 = int.from_bytes(k_bytes, 'big') % ec.n
assert k1 != 0
print("eph k1:", hex(k1))

K1 = pointMult(ec, k1, ec.G)

r = K1[0] % ec.n
# if r == 0 (extremely unlikely for large ec.n) go back to a different ephemeral key
assert r != 0

s1 = ((h1 + r*q)*mod_inv(k1, ec.n)) % ec.n
# if s1 == 0 (extremely unlikely for large ec.n) go back to a different ephemeral key
assert s1 != 0

print("     r:", hex(r))
print("    s1:", hex(s1))

print("*** Signature Verification")
w = mod_inv(s1, ec.n)
u = (h1*w) %ec.n
v = (r*w) %ec.n
assert u != 0
assert v != 0
U = pointMult(ec, u, ec.G)
V = pointMult(ec, v, Q)
x, y = ec.add(U, V)
print(r == x %ec.n)

print("\n*** Malleated Signature")
s1m = ec.n - s1
print("     r:", hex(r))
print("   *s1:", hex(s1m))

print("*** Malleated Signature Verification")
w = mod_inv(s1m, ec.n)
u = (h1*w) %ec.n
v = (r*w) %ec.n
assert u != 0
assert v != 0
U = pointMult(ec, u, ec.G)
V = pointMult(ec, v, Q)
x, y = ec.add(U, V)
print(r == x %ec.n)

print("\n*** Another message")
msg2 = "and Paolo is right to be afraid"
print(msg2)

print("*** Hash digest of the message")
h_bytes = hf(msg2.encode()).digest()
# hash(msg) must be transformed into an integer modulo ec.n:
h2 = int.from_bytes(h_bytes, 'big') % ec.n
assert h2 != 0
print("    h2:", hex(h2))

print("\n*** Signature")
k2 = k1 #very bad! Never reuse the same ephemeral key!!!
print("eph k2:", hex(k2))

K2 = pointMult(ec, k2, ec.G)

r = K2[0] % ec.n
# if r == 0 (extremely unlikely for large ec.n) go back to a different ephemeral key
assert r != 0

s2 = ((h2 + r*q)*mod_inv(k2, ec.n)) %ec.n
# if s2 == 0 (extremely unlikely for large ec.n) go back to a different ephemeral key
assert s2 != 0

print("     r:", hex(r))
print("    s2:", hex(s2))

print("*** Signature Verification")
w = mod_inv(s2, ec.n)
u = (h2*w) %ec.n
v = (r*w) %ec.n
assert u != 0
assert v != 0
U = pointMult(ec, u, ec.G)
V = pointMult(ec, v, Q)
x, y = ec.add(U, V)
print(r == x %ec.n)
