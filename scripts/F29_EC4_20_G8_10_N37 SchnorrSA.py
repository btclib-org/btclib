#!/usr/bin/python3

from F29_EC4_20_G8_10_N37 import prime, a, b, G, order, modInv, pointAdd, pointMultiply
from hashlib import sha256

print("\n*** EC:")
print("prime:", prime)
print("    a:", a)
print("    b:", b)
print("    G:", G)
print("order:", order)

p = 18
assert 0 < p
assert     p < order
print("\n*** EC Private Key:")
print(hex(p))

P = pointMultiply(p, G)
print("*** EC Public Key (uncompressed):")
print("04", P)

print("\n*** The message to be signed")
msg1 = "Paolo is afraid of ephemeral random numbers"
print(msg1)

print("*** The hash of the message")
hstring1 = sha256(msg1.encode()).hexdigest()
#Hash(msg) must be converted to an integer
h1 = int(hstring1, 16)
print(hex(h1))
assert (h1 % order) != 0

print("\n*** Signature")
# the ephemeral key k must be kept secret and never reused !!!!!
# good choice: k = sha256(msg, p)
# different for each msg, private because of p
temp = msg1+hex(p)
k1 = int(sha256(temp.encode()).hexdigest(), 16) % order
print("     k:", hex(k1).upper())
# 0 < k1 < order
assert 0 < k1
assert     k1 < order

K1 = pointMultiply(k1, G)

s1 = (k1-h1*p) %order;
# if s == 0 (extremely unlikely) go back to a different ephemeral key
assert s1 != 0

print(" K1:", K1)
print(" s1:", hex(s1))

print("*** Signature Verification")
minush = -h1 %order
U = pointMultiply(minush, P)
V = pointAdd(K1, U)
print(V == pointMultiply(s1, G))

print("\n*** Malleated Signature (K, *s)")
print(" K1:", K1)
s1m = order - s1
print("*s1:", s1m)                #malleated

print("*** Malleated Signature (K, *s) Verification")
V = pointAdd(K1, U)
print(V == pointMultiply(s1m, G)) #malleated

print("\n*** Malleated Signature (*K, s)")
K1m = (K1[0], -K1[1] %order)
print("*K1:", K1m)                #malleated
print(" s1:", s1)

print("*** Malleated Signature (*K, s) Verification")
V = pointAdd(K1m, U)              #malleated
print(V == pointMultiply(s1, G))

print("\n*** Malleated Signature (*K, *s)")
print("*K1:", K1m)                #malleated
print("*s1:", s1m)                #malleated

print("*** Malleated Signature Verification")
V = pointAdd(K1m, U)              #malleated
print(V == pointMultiply(s1m, G)) #malleated

print("\n*** Another message")
msg2 = "and Paolo is right to be afraid"
print(msg2)

print("*** The hash of the message")
hstring2 = sha256(msg2.encode()).hexdigest()
#Hash(msg) must be converted to an integer
h2 = int(hstring2, 16)
print(hex(h2))
assert (h2 % order) != 0

print("\n*** Signature")
k2 = k1 #very bad! Never reuse the same ephemeral key!!!
# 0 < k2 < order
assert 0 < k2
assert     k2 < order

K2 = pointMultiply(k2, G)

s2 = (k2-h2*p) %order;
# if s == 0 (extremely unlikely) go back to a different ephemeral key
assert s2 != 0

print(" K2:", K2)
print(" s2:", hex(s2))

print("*** Signature Verification")
minush = -h2 %order
U = pointMultiply(minush, P)
V = pointAdd(K2, U)
print(V == pointMultiply(s2, G))
