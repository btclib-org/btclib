#!/usr/bin/python3

from FiniteFields import modular_sqrt, modInv

# elliptic curve y^2 = x^3 + a * x + b
class EllipticCurve:
  """ Elliptic curve over Fp group """

  def __init__(self, a, b, prime, G, order):
    assert 4*a*a*a+27*b*b !=0, "zero discriminant"
    self.__a = a
    self.__b = b
    self.__prime = prime

    self.checkPoint(G)
    self.G = G
    self.order = order

  def checkPoint(self, P):
    assert P[0] is None or (P[0]*P[0]*P[0]+self.__a*P[0]+self.__b) % self.__prime == (P[1]*P[1]) % self.__prime

  def y(self, x, even=True):
    assert 0 <= x
    assert x < self.__prime
    temp = (x*x*x+self.__a*x+self.__b) % self.__prime
    root = modular_sqrt(temp, self.__prime)
    return root if (root % 2 == 0 and even) else self.__prime - root

  def __str__(self):
   return "Elliptic Curve Group(a=%s, b=%s) \nover F __prime=0x%032x \nGenerator: %s \norder: %s" % (self.__a, self.__b, self.__prime, self.G, self.order)

  def __repr__(self):
    return 'EllipticCurve(%s, %s, 0x%032x, %s, %s)' % (self.__a, self.__b, self.__prime, self.G, self.order)
      
  def pointDouble(self, P):
    self.checkPoint(P)
    if P[1] == 0 or P[0] is None:
      return (None, None)
    lam = ((3*P[0]*P[0]+ self.__a) * modInv(2*P[1], self.__prime)) % self.__prime
    x = (lam*lam-2*P[0]) % self.__prime
    y = (lam*(P[0]-x)-P[1]) % self.__prime
    return (x, y)

  def pointAdd(self, P, Q):
    self.checkPoint(P)
    self.checkPoint(Q)
    if Q[0] is None:
      return P
    if P[0] is None:
      return Q
    if Q[0] == P[0]:
      if Q[1] == P[1]:
        return self.pointDouble(P)
      else:
        return (None, None)
    lam = ((Q[1]-P[1]) * modInv(Q[0]-P[0], self.__prime)) % self.__prime
    x = (lam*lam-P[0]-Q[0]) % self.__prime
    y = (lam*(P[0]-x)-P[1]) % self.__prime
    return (x, y)

  # efficient double & add, using binary decomposition of n
  def pointMultiply(self, n, P):
    n = n % self.order    # the group is cyclic
    result = (None, None) # initialized to infinity point
    addendum = P          # initialized as 2^0 P
    while n > 0:          # use binary representation of n
      if n & 1:           # if least significant bit is 1 add current addendum
        result = self.pointAdd(result, addendum)
      n = n>>1            # right shift to remove the bit just accounted for
      addendum = self.pointDouble(addendum) # update addendum for next step
    return result

def main():
  G = (0, 3)
  order = 269
  ecg = EllipticCurve(6, 9, 263, G, order)
  print(ecg.y(0, False))
  print(ecg)
  print(ecg.checkPoint(G))
  print(ecg.pointDouble(G))
  print(ecg.pointAdd(G, G))
  print(ecg.pointMultiply(2, G))
  print(ecg.pointMultiply(order, G))
  print(ecg.pointMultiply(order+1, G))
  print(ecg.pointMultiply(order+2, G))

if __name__ == "__main__":
  # execute only if run as a script
  main()
