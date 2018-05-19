#!/usr/bin/python3

# elliptic curve y^2 = x^3 + a * x + b
a = -1; b = 1
assert 4*a*a*a+27*b*b !=0, "zero discriminant"

# over prime field
prime = 79;

def checkPoint(P):
  assert (P[0]*P[0]*P[0]+a*P[0]+b) % prime == (P[1]*P[1]) % prime
  
# A given generator specifies the group order
G = (0, 1)
checkPoint(G)

# must be a prime for the cyclic field not to have subgroups
order = 43

from FiniteFields import modInv

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

i = 1
print(i, G)
checkPoint(G)

i = 2
P = pointDouble(G)
checkPoint(P)
print(i, P)

for i in range(3, order):
  P = pointAdd(P, G)
  checkPoint(P)
  print(i, P)
