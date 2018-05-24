#!/usr/bin/python3

# secp256k1 specs

# elliptic curve y^2 = x^3 + a * x + b
a = 0; b = 7
assert 4*a*a*a+27*b*b !=0, "zero discriminant"

# over prime finite field
prime = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 -1
prime = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f

def checkPoint(P):
  assert P[0] is None or (P[0]*P[0]*P[0]+a*P[0]+b) % prime == (P[1]*P[1]) % prime
  
# a given generator specifies the group order
gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
G = (gx, gy)
checkPoint(G)

# must be a prime for the cyclic group not to have subgroups
order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

from FiniteFields import modInv

def pointDouble(P):
  if P[1] == 0 or P[0] is None:
    return (None, None)
  lam = ((3*P[0]*P[0]+a) * modInv(2*P[1], prime)) % prime
  x = (lam*lam-2*P[0]) % prime
  y = (lam*(P[0]-x)-P[1]) % prime
  return (x, y)

def pointAdd(P, Q):
  if Q[0] is None:
    return P
  if P[0] is None:
    return Q
  if Q[0] == P[0]:
    if Q[1] == P[1]:
      return pointDouble(P)
    else:
      return (None, None)
  lam = ((Q[1]-P[1]) * modInv(Q[0]-P[0], prime)) % prime
  x = (lam*lam-P[0]-Q[0]) % prime
  y = (lam*(P[0]-x)-P[1]) % prime
  return (x, y)

# efficient double & add, using binary decomposition
def pointMultiply(n, P):
  n = n % order         # the group is cyclic
  result = (None, None) # initialized to infinity point
  powerOfP = P          # initialized as 2^0 P
  while n > 0:          # use binary representation of n
    if n & 1:           # if least significant bit is 1 add current power of P
      result = pointAdd(result, powerOfP)
    n = n>>1            # right shift to remove the bit just accounted for
    powerOfP = pointDouble(powerOfP) # update power of P for next step
  return result
