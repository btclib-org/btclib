#!/usr/bin/python3

from secp256k1 import order, G, modInv, pointAdd, pointMultiply
from hashlib import sha256

privKey = 0x18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725
# 0 < privKey < order
assert 0 < privKey        , "Invalid Private Key"
assert     privKey < order, "Invalid Private Key"
print("\n*** EC Private Key: ")
print(hex(privKey))

PubKey = pointMultiply(privKey, G)
print("*** EC Public Key (uncompressed): ")
print("04")
print(hex(PubKey[0]))
print(hex(PubKey[1]))

import hashlib

print("\n*** The message/transaction to be signed")
msg1 = "Paolo is afraid of ephemeral random numbers"
print(msg1)

print("*** The hash of the message/transaction")
hstring1 = hashlib.sha256(msg1.encode()).hexdigest()
#Hash(msg) must be converted to an integer
h1 = int(hstring1, 16)
assert (h1 % order) != 0
print("    H1:", hex(h1))

print("\n*** Signature")
# ephemeral k must be kept secret and it must never be reused !!!!!
# good choice: k = sha256(msg, privKey)
# different for each msg, private because of privKey
temp = msg1+hex(privKey)
k1 = int(hashlib.sha256(temp.encode()).hexdigest(), 16) % order
# 0 < k < order
assert 0 < k1
assert     k1 < order

K1 = pointMultiply(k1, G)

s1 = (k1-h1*privKey) %order;
# if s == 0 (extremely unlikely) go back to a different ephemeral key
assert s1 != 0

print(" K1[0]:", hex(K1[0]))
print(" K1[1]:", hex(K1[1]))
print("    s1:", hex(s1))

print("*** Signature Verification")
minush1 = -h1 %order
V = pointMultiply(minush1, PubKey)
V = pointAdd(K1, V)
print(V == pointMultiply(s1, G))

print("\n*** Malleated Signature (K, *s)")
print(" K1[0]:", hex(K1[0]))
print(" K1[1]:", hex(K1[1]))
s1m = order - s1
print("   *s1:", hex(s1m))        #malleated

print("*** Malleated Signature (K, *s) Verification")
minush1 = -h1 %order
V = pointMultiply(minush1, PubKey)
V = pointAdd(K1, V)
print(V == pointMultiply(s1m, G)) #malleated

print("\n*** Malleated Signature (*K, s)")
K1m = (K1[0], -K1[1] %order)
print(" K1[0]:", hex(K1m[0]))
print("*K1[1]:", hex(K1m[1]))     #malleated
print("    s1:", hex(s1))

print("*** Malleated Signature (*K, s) Verification")
minush1 = -h1 %order
V = pointMultiply(minush1, PubKey)
V = pointAdd(K1m, V)              #malleated
print(V == pointMultiply(s1, G))

print("\n*** Malleated Signature (*K, *s)")
K1m = (K1[0], -K1[1] %order)
print(" K1[0]:", hex(K1m[0]))   
print("*K1[1]:", hex(K1m[1]))     #malleated
s1m = order-s1
print("   *s1:", hex(s1m))        #malleated

print("*** Malleated Signature Verification")
minush1 = -h1 %order
V = pointMultiply(minush1, PubKey)
V = pointAdd(K1m, V)              #malleated
print(V == pointMultiply(s1m, G)) #malleated

print("\n*** Another message")
msg2 = "and Paolo is right to be afraid"
print(msg2)

print("*** The hash of the message/transaction")
hstring2 = hashlib.sha256(msg2.encode()).hexdigest()
#Hash(msg) must be converted to an integer
h2 = int(hstring2, 16)
print(hex(h2))
assert (h2 % order) != 0

print("\n*** Signature")
k2 = k1 #very bad! Never reuse the same ephemeral key!!!
# 0 < k < order
assert 0 < k2
assert     k2 < order

K2 = pointMultiply(k2, G)

s2 = (k2-h2*privKey) %order;
# if s == 0 (extremely unlikely) go back to a different ephemeral key
assert s2 != 0

print(" K2[0]:", hex(K2[0]))
print(" K2[1]:", hex(K2[1]))
print("    s2:", hex(s2))

print("*** Signature Verification")
minush2 = -h2 %order
V = pointMultiply(minush2, PubKey)
V = pointAdd(K2, V)
print(V == pointMultiply(s2, G))
