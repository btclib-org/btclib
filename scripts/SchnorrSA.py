#!/usr/bin/python3

#from EC_1_1_F79_G0_1_N43 import ec
#from EC_7_10_F263_G3_4_N280 import ec
#from EC1_6_F11_G5_9_N13 import ec
#from EC2_3_F263_G200_39_N270 import ec
#from EC6_9_F263_G0_3_N269 import ec
from ECsecp256k1 import ec
from FiniteFields import modInv
from hashlib import sha256

print("\n*** EC:")
print(ec)

p = 0x18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725
print("\n*** EC Private Key: ")
print(hex(p))

P = ec.pointMultiply(p)
print("*** EC Public Key: ")
print("02" if (P[1] % 2 == 0) else "03")
print(hex(P[0]))

print("\n*** The message to be signed")
msg1 = "Paolo is afraid of ephemeral random numbers"
print(msg1)

print("*** The hash of the message")
hstring1 = sha256(msg1.encode()).hexdigest()
# Hash(msg) must be transformed into an integer modulo ec.order:
h1 = int(hstring1, 16) % ec.order
assert h1 != 0
print("    h1:", hex(h1))

print("\n*** Signature")
# ephemeral key k must be kept secret and never reused !!!!!
# good choice: k = sha256(msg, p)
# different for each msg, private because of p
temp = msg1+hex(p)
k1 = int(sha256(temp.encode()).hexdigest(), 16) % ec.order

K1 = ec.pointMultiply(k1)

s1 = (k1-h1*p) % ec.order
# if s1 == 0 (extremely unlikely for large ec.order) go back to a different ephemeral key
assert s1 != 0

print(" K1[0]:", hex(K1[0]))
print(" K1[1]:", hex(K1[1]))
print("    s1:", hex(s1))

print("*** Signature Verification")
minush1 = -h1 %ec.order
V = ec.pointMultiply(minush1, P)
V = ec.pointAdd(K1, V)
print(V == ec.pointMultiply(s1))

print("\n*** Another message")
msg2 = "and Paolo is right to be afraid"
print(msg2)

print("*** The hash of the message")
hstring2 = sha256(msg2.encode()).hexdigest()
# Hash(msg) must be transformed into an integer modulo ec.order:
h2 = int(hstring2, 16) % ec.order
assert h2 != 0
print("    h2:", hex(h2))

print("\n*** Signature")
k2 = k1 #very bad! Never reuse the same ephemeral key!!!

K2 = ec.pointMultiply(k2)

s2 = (k2-h2*p) %ec.order
# if s2 == 0 (extremely unlikely) go back to a different ephemeral key
assert s2 != 0

print(" K2[0]:", hex(K2[0]))
print(" K2[1]:", hex(K2[1]))
print("    s2:", hex(s2))

print("*** Signature Verification")
minush2 = -h2 %ec.order
V = ec.pointMultiply(minush2, P)
V = ec.pointAdd(K2, V)
print(V == ec.pointMultiply(s2))
