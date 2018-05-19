#!/usr/bin/python3

from hashlib import sha256
from ECsecp256k1 import G, order, modInv, pointAdd, pointMultiply

p = 0x18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725
# 0 < p < order
assert 0 < p        , "Invalid Private Key"
assert     p < order, "Invalid Private Key"
print("\n*** EC Private Key:")
print(hex(p).upper())

P = pointMultiply(p, G)
print("*** EC Public Key:")
print("02" if (P[1] % 2 == 0) else "03")
print(hex(P[0]).upper())

print("\n*** The message to be signed")
msg1 = "Paolo is afraid of ephemeral random numbers"
print(msg1)

print("*** The hash of the message")
hstring1 = sha256(msg1.encode()).hexdigest()
# Hash(msg) must be transformed into an integer modulo order:
h1 = int(hstring1, 16) % order
assert h1 != 0
print(" h1:", hex(h1).upper())

print("\n*** Signature")
# ephemeral key k must be kept secret and never reused !!!!!
# good choice: k = sha256(msg, p)
# different for each msg, private because of p
temp = msg1+hex(p)
k1 = int(sha256(temp.encode()).hexdigest(), 16) % order
# 0 < k1 < order
assert 0 < k1
assert     k1 < order

K1 = pointMultiply(k1, G)

r = K1[0] % order
# if r == 0 (extremely unlikely for large order) go back to a different ephemeral key
assert r != 0

s1 = ((h1 + r*p)*modInv(k1, order)) % order
# if s1 == 0 (extremely unlikely for large order) go back to a different ephemeral key
assert s1 != 0

print("  r:", hex(r).upper())
print(" s1:", hex(s1).upper())

print("*** Signature Verification")
w = modInv(s1, order)
u = (h1*w) %order
v = (r*w) %order
assert u != 0
assert v != 0
U = pointMultiply(u, G)
V = pointMultiply(v, P)
x, y = pointAdd(U, V)
print(r == x %order)

print("\n*** Malleated Signature")
s1m = order - s1
print("  r:", hex(r).upper())
print("*s1:", hex(s1m).upper())

print("*** Malleated Signature Verification")
w = modInv(s1m, order)
u = (h1*w) %order
v = (r*w) %order
assert u != 0
assert v != 0
U = pointMultiply(u, G)
V = pointMultiply(v, P)
x, y = pointAdd(U, V)
print(r == x %order)

print("\n*** Another message")
msg2 = "and Paolo is right to be afraid"
print(msg2)

print("*** The hash of the message")
hstring2 = sha256(msg2.encode()).hexdigest()
# Hash(msg) must be transformed into an integer modulo order:
h2 = int(hstring2, 16) % order
assert h2 != 0
print(" h2:", hex(h2).upper())

print("\n*** Signature")
k2 = k1 #very bad! Never reuse the same ephemeral key!!!
# 0 < k2 < order
assert 0 < k2
assert     k2 < order

K2 = pointMultiply(k2, G)

r = K2[0] % order
# if r == 0 (extremely unlikely for large order) go back to a different ephemeral key
assert r != 0

s2 = ((h2 + r*p)*modInv(k2, order)) %order
# if s2 == 0 (extremely unlikely for large order) go back to a different ephemeral key
assert s2 != 0

print("  r:", hex(r).upper())
print(" s2:", hex(s2).upper())

print("*** Signature Verification")
w = modInv(s2, order)
u = (h2*w) %order
v = (r*w) %order
assert u != 0
assert v != 0
U = pointMultiply(u, G)
V = pointMultiply(v, P)
x, y = pointAdd(U, V)
print(r == x %order)
