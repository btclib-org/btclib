#!/usr/bin/python3

# elliptic curve y^2 = x^3 + a * x + b
a = -7; b = 10
assert 4*a*a*a+27*b*b !=0, "zero discriminant"

# over prime finite field
prime = 263;

def checkPoint(P):
  assert P[0] is None or (P[0]*P[0]*P[0]+a*P[0]+b) % prime == (P[1]*P[1]) % prime
  
# a given generator specifies the group order
G = (3, 4)
checkPoint(G)

# must be a prime for the cyclic group not to have subgroups
order = 280

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

# double & add
def pointMultiply(n, P):
  n = n % order
  if n == 0 or P[0] is None:
    return (None, None)
  if n == 1:
    return P
  if n % 2 == 1: # addition when n is odd
    return pointAdd(P, pointMultiply(n - 1, P))
  else:          # doubling when n is even
    return pointMultiply(n//2, pointDouble(P))

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
  
