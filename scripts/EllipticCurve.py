#!/usr/bin/python3

from FiniteFields import mod_inv, mod_sqrt
from math import sqrt

# elliptic curve y^2 = x^3 + a * x + b
class EllipticCurve:
  """ Elliptic curve over Fp group"""

  def __init__(self, a, b, prime, G, order):
    assert 4*a*a*a+27*b*b !=0, "zero discriminant"
    self.__a = a
    self.__b = b
    self.__prime = prime

    self.__G = self.tuple_from_point(G)
    # Hasse Theorem
    t = int(2 * sqrt(prime))
    assert order <= prime + 1 + t, "order too high"
    assert prime + 1 - t <= order, "order too low"
    self.order = order

  def __y2(self, x):
    assert 0 <= x
    assert x < self.__prime
    # skipping key check: x is not valid if sqrt(y*y) does not exists
    return (x*x*x + self.__a*x + self.__b) % self.__prime

  def y(self, x, odd):
    assert type(odd) == bool or odd in (0, 1), "must be bool or 0/1"
    y2 = self.__y2(x)
    # if root does not exist, mod_sqrt will raise a ValueError
    root = mod_sqrt(y2, self.__prime)
    # switch even/odd root when needed
    return root if (root % 2 + odd) != 1 else self.__prime - root

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
      
  def tuple_from_point(self, P):
    """ Return a tuple (Px, Py) having ensured it belongs to the curve """
    if isinstance(P, str):
      P = bytes.fromhex(P)

    if isinstance(P, bytes) or isinstance(P, bytearray):
      if len(P) == 33: # compressed point
        assert P[0] == 0x02 or P[0] == 0x03, "not a compressed point"
        Px = int.from_bytes(P[1:33], 'big')
        assert Px < self.__prime
        Py = self.y(Px, True)
        if (P[0] == 0x03):
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
        assert self.__y2(Px) == Py*Py % self.__prime, "point is not on the ec"
        return (Px, Py)
    elif isinstance(P, tuple):
      assert len(P) == 2, "invalid tuple point length"
      if (P[0] == None and P[1] == None):
        return P
      assert (type(P[0]) == int and type(P[1]) == int) , "invalid non-int tuple point"
      assert P[0] < self.__prime
      assert P[1] < self.__prime
      assert self.__y2(P[0]) == P[1]*P[1] % self.__prime, "point is not on the ec"
      return P
    else:
      raise ValueError("not an elliptic curve point")


  def bytes_from_point(self, P, compressed = True):
    """ Return a 33 bytes compressed (0x02, 0x03) or 65 bytes uncompressed
        (0x04) point ensuring it belongs to the curve
    """
    if isinstance(P, str):
      P = bytes.fromhex(P)

    if isinstance(P, bytes) or isinstance(P, bytearray):
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
        assert self.__y2(Px) == Py*Py % self.__prime
        return P
    elif isinstance(P, tuple):
      assert len(P) == 2, "invalid tuple point length"
      assert P[0] is not None, "infinity point cannot be expressed as bytes"
      assert P[1] is not None, "infinity point cannot be expressed as bytes"
      assert type(P[0]) == int and type(P[1]) == int, "invalid non-int tuple point"
      assert self.__y2(P[0]) == P[1]*P[1] % self.__prime
      if compressed:
        prefix = b'\x02' if (P[1] % 2 == 0) else b'\x03'
        return prefix + P[0].to_bytes(32, byteorder='big')

      Pbytes = b'\x04' + P[0].to_bytes(32, byteorder='big')
      Pbytes += P[1].to_bytes(32, byteorder='big')
      return Pbytes
    else:
      raise ValueError("not an elliptic curve point")

  def pointDouble(self, P):
    P = self.tuple_from_point(P)
    return self.pointDouble_raw(P)

  def pointDouble_raw(self, P):
    if P[1] == 0 or P[0] is None:
      return (None, None)
    lam = ((3*P[0]*P[0]+self.__a) * mod_inv(2*P[1], self.__prime)) % self.__prime
    x = (lam*lam-2*P[0]) % self.__prime
    y = (lam*(P[0]-x)-P[1]) % self.__prime
    return (x, y)

  def pointAdd(self, P, Q):
    P = self.tuple_from_point(P)
    Q = self.tuple_from_point(Q)
    return self.pointAdd_raw(P, Q)

  def pointAdd_raw(self, P, Q):
    if Q[0] is None:
      return P
    if P[0] is None:
      return Q
    if Q[0] == P[0]:
      if Q[1] == P[1]:
        return self.pointDouble_raw(P)
      else:
        return (None, None)
    lam = ((Q[1]-P[1]) * mod_inv(Q[0]-P[0], self.__prime)) % self.__prime
    x = (lam*lam-P[0]-Q[0]) % self.__prime
    y = (lam*(P[0]-x)-P[1]) % self.__prime
    return (x, y)

  # efficient double & add, using binary decomposition of n
  def pointMultiply(self, n, P = None):
    if isinstance(n, bytes) or isinstance(n, bytearray):
      assert len(n) == 32
      n = int.from_bytes(n, 'big')
    n = n % self.order    # the group is cyclic

    if P is None: P = self.__G
    else: P = self.tuple_from_point(P)

    return self.pointMultiply_raw(n, P)

  def pointMultiply_raw(self, n, P = None):
    if P is None: P = self.__G

    result = (None, None) # initialized to infinity point
    addendum = P          # initialized as 2^0 P
    while n > 0:          # use binary representation of n
      if n & 1:           # if least significant bit is 1 add current addendum
        result = self.pointAdd_raw(result, addendum)
      n = n>>1            # right shift to remove the bit just accounted for
      addendum = self.pointDouble_raw(addendum) # update addendum for next step
    return result


def main():
  G = (0, 3)
  ec = EllipticCurve(6, 9, 263, G, 269)
  assert ec.y(G[0], False) != G[1]
  assert ec.y(G[0], True) == G[1]
  print(ec)
  ec.tuple_from_point(G)
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
