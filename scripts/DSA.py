#!/usr/bin/env python3

from hashlib import sha256
from btclib.ellipticcurves import secp256k1 as ec
from btclib.numbertheory import mod_inv

print("\n*** EC:")
print(ec)

prv = 0x18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725
prv = prv % ec.n
print("\n*** Keys:")
print("prvkey:   ", hex(prv))

Pub = ec.pointMultiply(prv, ec.G)
print("PubKey:", "02" if (Pub[1] % 2 == 0) else "03", hex(Pub[0]))

print("\n*** Message to be signed")
msg1 = "Paolo is afraid of ephemeral random numbers"
print(msg1)

print("*** Hash of the message")
h_bytes = sha256(msg1.encode()).digest()
# hash(msg) must be transformed into an integer modulo ec.n:
h1 = int.from_bytes(h_bytes, 'big') % ec.n
assert h1 != 0
print("    h1:", hex(h1))

print("\n*** Signature")
# ephemeral key k must be kept secret and never reused !!!!!
# good choice: k = sha256(msg|prv)
# different for each msg, private because of prv
temp = msg1+hex(prv)
k_bytes = sha256(temp.encode()).digest()
k1 = int.from_bytes(k_bytes, 'big') % ec.n
assert k1 != 0
print("eph k1:", hex(k1))

K1 = ec.pointMultiply(k1, ec.G)

r = K1[0] % ec.n
# if r == 0 (extremely unlikely for large ec.n) go back to a different ephemeral key
assert r != 0

s1 = ((h1 + r*prv)*mod_inv(k1, ec.n)) % ec.n
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
U = ec.pointMultiply(u, ec.G)
V = ec.pointMultiply(v, Pub)
x, y = ec.pointAdd(U, V)
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
U = ec.pointMultiply(u, ec.G)
V = ec.pointMultiply(v, Pub)
x, y = ec.pointAdd(U, V)
print(r == x %ec.n)

print("\n*** Another message")
msg2 = "and Paolo is right to be afraid"
print(msg2)

print("*** Hash of the message")
h_bytes = sha256(msg2.encode()).digest()
# hash(msg) must be transformed into an integer modulo ec.n:
h2 = int.from_bytes(h_bytes, 'big') % ec.n
assert h2 != 0
print("    h2:", hex(h2))

print("\n*** Signature")
k2 = k1 #very bad! Never reuse the same ephemeral key!!!
print("eph k2:", hex(k2))

K2 = ec.pointMultiply(k2, ec.G)

r = K2[0] % ec.n
# if r == 0 (extremely unlikely for large ec.n) go back to a different ephemeral key
assert r != 0

s2 = ((h2 + r*prv)*mod_inv(k2, ec.n)) %ec.n
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
U = ec.pointMultiply(u, ec.G)
V = ec.pointMultiply(v, Pub)
x, y = ec.pointAdd(U, V)
print(r == x %ec.n)
