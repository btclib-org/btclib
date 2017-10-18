#!/usr/bin/python3

from F29_EC4_20_G8_10_N37 import prime, a, b, G, order, modInv, pointAdd, pointMultiply
from hashlib import sha256

print("\n*** EC:")
print("prime:", prime)
print("    a:", a)
print("    b:", b)
print("    G:", G)
print("order:", order)

p = 1
assert 0 < p
assert     p < order
print("\n*** EC Private Key:")
print(hex(p))

P = pointMultiply(p, G)
print("*** EC Public Key (uncompressed):")
print("04", P)

import hashlib

print("\n*** The message/transaction to be signed")
msg1 = "Paolo is afraid of ephemeral random numbers"
print(msg1)

print("*** The hash of the message/transaction")
hstring1 = hashlib.sha256(msg1.encode()).hexdigest()
#Hash(msg) must be converted to an integer
h1 = int(hstring1, 16)
assert (h1 % order) != 0
print(" h1:", hex(h1))

print("\n*** Signature")
# k must be kept secret and it must never be reused !!!!!
# good choice: k = sha256(msg, privKey)
# different for each msg, private because of privKey
temp = msg1+hex(p)
k1 = int(hashlib.sha256(temp.encode()).hexdigest(), 16) % order
# 0 < k1 < order
assert 0 < k1
assert     k1 < order

K1 = pointMultiply(k1, G)

xk = K1[0]
# if xk == 0 (extremely unlikely) go back to a different random number
assert xk != 0

s1 = ((h1 + xk*p) * modInv(k1, order)) %order
# if s == 0 (extremely unlikely) go back to a different random number
assert s1 != 0

print(" xk:", hex(xk))
print(" s1:", hex(s1))

print("*** Signature Verification")
w = modInv(s1, order)
u = (h1*w) %order
v = (xk*w) %order
assert u != 0
assert v != 0
U = pointMultiply(u, G)
V = pointMultiply(v, P)
x, y = pointAdd(U, V)
print(x == xk %order)

print("\n*** Malleated Signature")
s1m = order - s1
print(" xk:", hex(xk))
print("*s1:", hex(s1m))

print("*** Malleated Signature Verification")
w = modInv(s1m, order)
u = (h1*w) %order
v = (xk*w) %order
assert u != 0
assert v != 0
U = pointMultiply(u, G)
V = pointMultiply(v, P)
x, y = pointAdd(U, V)
print(x == xk %order)

print("\n*** Another message")
msg2 = "and Paolo is right to be afraid"
print(msg2)

print("*** The hash of the message/transaction")
hstring2 = hashlib.sha256(msg2.encode()).hexdigest()
#Hash(msg) must be converted to an integer
h2 = int(hstring2, 16)
assert (h2 % order) != 0
print(" h2:", hex(h2))

print("\n*** Signature")
k2 = k1 #very bad! Never reuse the same ephemeral key!!!
# 0 < k2 < order
assert 0 < k2
assert     k2 < order

K2 = pointMultiply(k2, G)

xk = K2[0]
# if xk == 0 (extremely unlikely) go back to a different random number
assert xk != 0

s2 = ((h2 + xk*p) * modInv(k2, order)) %order
# if s == 0 (extremely unlikely) go back to a different random number
assert s2 != 0

print(" xk:", hex(xk))
print(" s2:", hex(s2))

print("*** Signature Verification")
w = modInv(s2, order)
u = (h2*w) %order
v = (xk*w) %order
assert u != 0
assert v != 0
U = pointMultiply(u, G)
V = pointMultiply(v, P)
x, y = pointAdd(U, V)
print(x == xk %order)
