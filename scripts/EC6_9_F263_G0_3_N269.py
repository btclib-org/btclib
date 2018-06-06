#!/usr/bin/python3

# elliptic curve y^2 = x^3 + a * x + b
a = 6; b = 9
assert 4*a*a*a+27*b*b !=0, "zero discriminant"

# over prime finite field
prime = 263;

def checkPoint(P):
  assert P[0] is None or (P[0]*P[0]*P[0]+a*P[0]+b) % prime == (P[1]*P[1]) % prime
  
# a given generator specifies the group order
G = (0, 3)
checkPoint(G)

# must be a prime for the cyclic group not to have subgroups
order = 269

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

# double & add, using binary decomposition
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

i = 1
P = G
checkPoint(P)
print(i, P)
assert P == pointMultiply(i, G)

i = 2
P = pointDouble(G)
checkPoint(P)
print(i, P)
assert P == pointMultiply(i, G)

for i in range(3, order+2):
  P = pointAdd(P, G)
  checkPoint(P)
  print(i, P)
  assert P == pointMultiply(i, G), pointMultiply(i, G)
