#!/usr/bin/python3

from ECsecp256k1 import ec, modInv, pointAdd, pointMultiply
from hashlib import sha256

print("\n*** EC:")
print(ec)

p = 0x18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725
assert 0 < p           , "Invalid Private Key"
assert     p < ec.order, "Invalid Private Key"
print("\n*** EC Private Key: ")
print(hex(p).upper())

P = pointMultiply(p, ec.G, ec)
print("*** EC Public Key (uncompressed): ")
print("02" if (P[1] % 2 == 0) else "03")
print(hex(P[0]).upper())

print("\n*** The message to be signed")
msg1 = "Paolo is afraid of ephemeral random numbers"
print(msg1)

print("*** The hash of the message")
hstring1 = sha256(msg1.encode()).hexdigest()
# Hash(msg) must be transformed into an integer modulo ec.order:
h1 = int(hstring1, 16) % ec.order
assert h1 != 0
print("    h1:", hex(h1).upper())

print("\n*** Signature")
# ephemeral key k must be kept secret and never reused !!!!!
# good choice: k = sha256(msg, p)
# different for each msg, private because of p
temp = msg1+hex(p)
k1 = int(sha256(temp.encode()).hexdigest(), 16) % ec.order
assert 0 < k1
assert     k1 < ec.order

K1 = pointMultiply(k1, ec.G, ec)

s1 = (k1-h1*p) % ec.order
# if s1 == 0 (extremely unlikely for large ec.order) go back to a different ephemeral key
assert s1 != 0

print(" K1[0]:", hex(K1[0]).upper())
print(" K1[1]:", hex(K1[1]).upper())
print("    s1:", hex(s1))

print("*** Signature Verification")
minush1 = -h1 %ec.order
V = pointMultiply(minush1, P, ec)
V = pointAdd(K1, V, ec)
print(V == pointMultiply(s1, ec.G, ec))

print("\n*** Another message")
msg2 = "and Paolo is right to be afraid"
print(msg2)

print("*** The hash of the message")
hstring2 = sha256(msg2.encode()).hexdigest()
# Hash(msg) must be transformed into an integer modulo ec.order:
h2 = int(hstring2, 16) % ec.order
assert h2 != 0
print("    h2:", hex(h2).upper())

print("\n*** Signature")
k2 = k1 #very bad! Never reuse the same ephemeral key!!!
assert 0 < k2
assert     k2 < ec.order

K2 = pointMultiply(k2, ec.G, ec)

s2 = (k2-h2*p) %ec.order
# if s2 == 0 (extremely unlikely) go back to a different ephemeral key
assert s2 != 0

print(" K2[0]:", hex(K2[0]).upper())
print(" K2[1]:", hex(K2[1]).upper())
print("    s2:", hex(s2).upper())

print("*** Signature Verification")
minush2 = -h2 %ec.order
V = pointMultiply(minush2, P, ec)
V = pointAdd(K2, V, ec)
print(V == pointMultiply(s2, ec.G, ec))
