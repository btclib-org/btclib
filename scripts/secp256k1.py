#!/usr/bin/python3

# secp256k1 specs

# elliptic curve y^2 = x^3 + a * x + b over prime field
prime = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 -1
prime = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
a = 0; b = 7

from FiniteFields import modInv

def checkPoint(P):
  assert (P[0]*P[0]*P[0]+a*P[0]+b) % prime == (P[1]*P[1]) % prime
  
def pointDouble(P):
  lam = ((3*P[0]*P[0]+a) * modInv(2*P[1], prime)) % prime
  x = (lam*lam-2*P[0]) % prime
  y = (lam*(P[0]-x)-P[1]) % prime
  return (x,y)

def pointAdd(P, Q):
  if P == Q:
    return pointDouble(P)
  lam = ((Q[1]-P[1]) * modInv(Q[0]-P[0], prime)) % prime
  x = (lam*lam-P[0]-Q[0]) % prime
  y = (lam*(P[0]-x)-P[1]) % prime
  return (x,y)

# double & add
def pointMultiply(n, P):
  assert n!=0
  if n == 1:
    return P
  elif n % 2 == 1: # addition when n is odd
    return pointAdd(P, pointMultiply(n - 1, P))
  else:            # doubling when n is even
    return pointMultiply(n//2, pointDouble(P))

# A given generator specifies the group order
gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
G = (gx, gy)
order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
