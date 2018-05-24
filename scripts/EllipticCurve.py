#!/usr/bin/python3

# elliptic curve y^2 = x^3 + a * x + b
class EllipticCurve:
  """ Elliptic Curve class, encapsulating the curve parameters"""

  def __init__(self, a, b, prime, G, order):
    assert 4*a*a*a+27*b*b !=0, "zero discriminant"
    self.a = a
    self.b = b
    self.prime = prime
    self.checkPoint(G)
    self.G = G
    # must be a prime for the cyclic group not to have subgroups
    self.order = order

  def __str__(self):
   return "EllipticCurve(a=%s, b=%s) \nover F prime=%032x" % (self.a, self.b, self.prime)

  def __repr__(self):
    return 'EllipticCurve(%s,%s,0x%032x)' % (self.a, self.b, self.prime)
      
  def checkPoint(self, P):
    assert P[0] is None or (P[0]*P[0]*P[0]+self.a*P[0]+self.b) % self.prime == (P[1]*P[1]) % self.prime

from FiniteFields import modInv

def pointDouble(P, ec):
  ec.checkPoint(P)
  if P[1] == 0 or P[0] is None:
    return (None, None)
  lam = ((3*P[0]*P[0]+ec.a) * modInv(2*P[1], ec.prime)) % ec.prime
  x = (lam*lam-2*P[0]) % ec.prime
  y = (lam*(P[0]-x)-P[1]) % ec.prime
  return (x, y)

def pointAdd(P, Q, ec):
  ec.checkPoint(P)
  ec.checkPoint(Q)
  if Q[0] is None:
    return P
  if P[0] is None:
    return Q
  if Q[0] == P[0]:
    if Q[1] == P[1]:
      return pointDouble(P, ec)
    else:
      return (None, None)
  lam = ((Q[1]-P[1]) * modInv(Q[0]-P[0], ec.prime)) % ec.prime
  x = (lam*lam-P[0]-Q[0]) % ec.prime
  y = (lam*(P[0]-x)-P[1]) % ec.prime
  return (x, y)

# efficient double & add, using binary decomposition
def pointMultiply(n, P, ec):
  n = n % ec.order      # the group is cyclic
  result = (None, None) # initialized to infinity point
  powerOfP = P          # initialized as 2^0 P
  while n > 0:          # use binary representation of n
    if n & 1:           # if least significant bit is 1 add current power of P
      result = pointAdd(result, powerOfP, ec)
    n = n>>1            # right shift to remove the bit just accounted for
    powerOfP = pointDouble(powerOfP, ec) # update power of P for next step
  return result
