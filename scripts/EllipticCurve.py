#!/usr/bin/python3

from FiniteFields import mod_inv, mod_sqrt

# elliptic curve y^2 = x^3 + a * x + b
class EllipticCurve:
  """ Elliptic curve over Fp group"""

  def __init__(self, a, b, prime, G, order):
    assert 4*a*a*a+27*b*b !=0, "zero discriminant"
    self.__a = a
    self.__b = b
    self.__prime = prime

    self.__G = self.scrub_point(G)
    self.order = order

  def y2(self, x):
    assert 0 <= x
    assert x < self.__prime
    return (x*x*x + self.__a*x + self.__b) % self.__prime

  def y(self, x, even=True):
    y2 = self.y2(x)
    root = mod_sqrt(y2, self.__prime)
    if (root % 2 == 0 and even) or (root % 2 == 1 and not even):
      return root
    else:
      return self.__prime - root

  def __str__(self):
    result  = "EllipticCurve(a=%s, b=%s)" % (self.__a, self.__b)
    result += "\n prime = 0x%032x" % (self.__prime)
    result += "\n     G =(0x%032x,\n         0x%032x)" % (self.__G)
    result += "\n order = 0x%032x" % (self.order)
    return result

  def __repr__(self):
    result  = "EllipticCurve(%s, %s" % (self.__a, self.__b)
    result += ", 0x%032x" % (self.__prime)
    result += ", (0x%032x,0x%032x)" % (self.__G)
    result += ", 0x%032x)" % (self.order)
    return result
      
  def scrub_point(self, P):
    """ Return a tuple (Px, Py) having ensured it belongs to the curve """
    if isinstance(P, bytes):
      if len(P) == 33: # compressed point
        assert P[0] == 0x02 or P[0] == 0x03, "not a compressed point"
        Px = int.from_bytes(P[1:33], 'big')
        assert Px < self.__prime
        Py = self.y(Px, True)
        if (P[0] == 0x02):
          return (Px, Py)
        else:
          return (Px, self.__prime - Py)
      else:            # uncompressed point
        assert len(P) == 65, "not a point"
        assert P[0] == 0x04, "not an uncompressed point"
        Px = int.from_bytes(P[1:33], 'big')
        assert Px < self.__prime
        Py = int.from_bytes(P[34:], 'big')
        assert Py < self.__prime
        P = (Px, Py)

    assert (P[0] is None) or (self.y2(P[0]) == P[1]*P[1] % self.__prime)
    return P

  def bytes_from_point(self, P, compressed = True):
    """ Return a 33 bytes compressed (0x02, 0x03) or 65 bytes uncompressed (0x04) point ensuring it belongs to the curve """

    # if it is already byte, just check that it belongs to the curve
    if isinstance(P, bytes):
      if len(P) == 33: # compressed point
        assert P[0] == 0x02 or P[0] == 0x03, "not a compressed point"
        Px = int.from_bytes(P[1:33], 'big')
        assert Px < self.__prime
        return P
      else:            # uncompressed point
        assert len(P) == 65, "not a point"
        assert P[0] == 0x04, "not an uncompressed point"
        Px = int.from_bytes(P[1:33], 'big')
        assert Px < self.__prime
        Py = int.from_bytes(P[33:], 'big')
        assert Py < self.__prime
        assert self.y2(Px) == Py*Py % self.__prime
        return P

    assert P[0] is not None, "infinity point cannot be expressed as bytes"
    assert self.y2(P[0]) == P[1]*P[1] % self.__prime
    if compressed:
      prefix = b'\x02' if (P[1] % 2 == 0) else b'\x03'
      return prefix + P[0].to_bytes(32, byteorder='big')

    Pbytes = b'\x04' + P[0].to_bytes(32, byteorder='big')
    Pbytes += P[1].to_bytes(32, byteorder='big')
    return Pbytes


  def pointDouble(self, P):
    P = self.scrub_point(P)
    if P[1] == 0 or P[0] is None:
      return (None, None)
    lam = ((3*P[0]*P[0]+self.__a) * mod_inv(2*P[1], self.__prime)) % self.__prime
    x = (lam*lam-2*P[0]) % self.__prime
    y = (lam*(P[0]-x)-P[1]) % self.__prime
    return (x, y)

  def pointAdd(self, P, Q):
    P = self.scrub_point(P)
    Q = self.scrub_point(Q)
    if Q[0] is None:
      return P
    if P[0] is None:
      return Q
    if Q[0] == P[0]:
      if Q[1] == P[1]:
        return self.pointDouble(P)
      else:
        return (None, None)
    lam = ((Q[1]-P[1]) * mod_inv(Q[0]-P[0], self.__prime)) % self.__prime
    x = (lam*lam-P[0]-Q[0]) % self.__prime
    y = (lam*(P[0]-x)-P[1]) % self.__prime
    return (x, y)

  # efficient double & add, using binary decomposition of n
  def pointMultiply(self, n, P = None):
    if P is None: P = self.__G

    if isinstance(n, bytes) or isinstance(n, bytearray):
      assert len(n) == 32
      n = int.from_bytes(n, 'big')
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
  ec = EllipticCurve(6, 9, 263, G, 269)
  assert ec.y(G[0], True)  != G[1]
  assert ec.y(G[0], False) == G[1]
  print(ec)
  ec.scrub_point(G)
  print(G)
  print(ec.pointAdd(G, G))
  print(ec.pointDouble(G))
  print(ec.pointMultiply(2))
  print(ec.pointMultiply(ec.order))
  print(ec.pointMultiply(ec.order+1))
  print(ec.pointMultiply(ec.order+2))

if __name__ == "__main__":
  # execute only if run as a script
  main()
