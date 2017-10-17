#!/usr/bin/python3

from secp256k1 import order, G, modInv, pointAdd, pointMultiply
from hashlib import sha256

privKey = 0x18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725
# 0 < privKey < order
assert 0 < privKey        , "Invalid Private Key"
assert     privKey < order, "Invalid Private Key"
print("\n*** EC Private Key:")
print(hex(privKey))

PubKey = pointMultiply(privKey, G)
print("*** EC Public Key (uncompressed):")
print("04")
print(hex(PubKey[0]))
print(hex(PubKey[1]))

print("\n*** The message/transaction to be signed")
msg1 = "Paolo is afraid of ephemeral random numbers"
print(msg1)

print("*** The hash of the message/transaction")
hstring1 = sha256(msg1.encode()).hexdigest()
#Hash(msg) must be converted to an integer
h1 = int(hstring1, 16)
assert (h1 % order) != 0
print(" h1:", hex(h1))

print("\n*** Signature")
# ephemeral k must be kept secret and it must never be reused !!!!!
# good choice: k = sha256(msg, privKey)
# different for each msg, private because of privKey
temp = msg1+hex(privKey)
k1 = int(sha256(temp.encode()).hexdigest(), 16) % order
# 0 < k < order
assert 0 < k1
assert     k1 < order

K1 = pointMultiply(k1, G)

xk = K1[0]
# if xk == 0 (extremely unlikely) go back to a different ephemeral key
assert xk != 0

s1 = ((h1 + xk*privKey)*modInv(k1, order)) %order
# if s == 0 (extremely unlikely) go back to a different ephemeral key
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
V = pointMultiply(v, PubKey)
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
V = pointMultiply(v, PubKey)
x, y = pointAdd(U, V)
print(x == xk %order)

print("\n*** Another message")
msg2 = "and Paolo is right to be afraid"
print(msg2)

print("*** The hash of the message/transaction")
hstring2 = sha256(msg2.encode()).hexdigest()
#Hash(msg) must be converted to an integer
h2 = int(hstring2, 16)
assert (h2 % order) != 0
print(" h2:", hex(h2))

print("\n*** Signature")
k2 = k1 #very bad! Never reuse the same ephemeral key!!!
# 0 < k < order
assert 0 < k2
assert     k2 < order

K2 = pointMultiply(k2, G)

xk = K2[0]
# if xk == 0 (extremely unlikely) go back to a different ephemeral key
assert xk != 0

s2 = ((h2 + xk*privKey)*modInv(k2, order)) %order
# if s == 0 (extremely unlikely) go back to a different ephemeral key
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
V = pointMultiply(v, PubKey)
x, y = pointAdd(U, V)
print(x == xk %order)
