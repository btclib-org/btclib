#!/usr/bin/python3

from hashlib import sha256
from ECsecp256k1 import G, order, pointAdd, pointMultiply

p = 0x18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725
# 0 < p < order
assert 0 < p        , "Invalid Private Key"
assert     p < order, "Invalid Private Key"
print("\n*** EC Private Key: ")
print(hex(p).upper())

P = pointMultiply(p, G)
print("*** EC Public Key (uncompressed): ")
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
print("    h1:", hex(h1).upper())

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

s1 = (k1-h1*p) % order
# if s1 == 0 (extremely unlikely for large order) go back to a different ephemeral key
assert s1 != 0

print(" K1[0]:", hex(K1[0]).upper())
print(" K1[1]:", hex(K1[1]).upper())
print("    s1:", hex(s1))

print("*** Signature Verification")
minush1 = -h1 %order
V = pointMultiply(minush1, P)
V = pointAdd(K1, V)
print(V == pointMultiply(s1, G))

print("\n*** Another message")
msg2 = "and Paolo is right to be afraid"
print(msg2)

print("*** The hash of the message")
hstring2 = sha256(msg2.encode()).hexdigest()
# Hash(msg) must be transformed into an integer modulo order:
h2 = int(hstring2, 16) % order
assert h2 != 0
print("    h2:", hex(h2).upper())

print("\n*** Signature")
k2 = k1 #very bad! Never reuse the same ephemeral key!!!
# 0 < k < order
assert 0 < k2
assert     k2 < order

K2 = pointMultiply(k2, G)

s2 = (k2-h2*p) %order
# if s2 == 0 (extremely unlikely) go back to a different ephemeral key
assert s2 != 0

print(" K2[0]:", hex(K2[0]).upper())
print(" K2[1]:", hex(K2[1]).upper())
print("    s2:", hex(s2).upper())

print("*** Signature Verification")
minush2 = -h2 %order
V = pointMultiply(minush2, P)
V = pointAdd(K2, V)
print(V == pointMultiply(s2, G))
