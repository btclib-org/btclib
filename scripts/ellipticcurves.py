#!/usr/bin/python3

from FiniteFields import mod_inv, mod_sqrt
from math import sqrt

# elliptic curve y^2 = x^3 + a * x + b
class EllipticCurve:
  """Elliptic curve over Fp group"""

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
    assert self.pointMultiply_raw(order) == (None, None)

  def __y2(self, x):
    assert 0 <= x
    assert x < self.__prime
    # skipping a crucial check here:
    # x is not valid if sqrt(y*y) does not exists.
    # This is a good reason to heve this method as private
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
      # FIXME: xpub is not considered here
      # which is right as it is a bitcoin convention,
      # not an elliptic curve one 
      P = bytes.fromhex(P)

    if isinstance(P, bytes) or isinstance(P, bytearray):
      # FIXME: xpub should be dealt with here
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
        Py = int.from_bytes(P[33:], 'big')
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

# bitcoin curve
__Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
__Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
__prime = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
secp256k1 = EllipticCurve(0, 7, 2**256 - 2**32 - 977, (__Gx, __Gy), __prime)

# toy curves
ec11_13   = EllipticCurve( 1,  6,  11, (  5,  9),  13)
# FIXME: Hasse condition fails
#ec79_43   = EllipticCurve(-1,  1,  79, (  0,  1),  43)
ec263_269 = EllipticCurve( 6,  9, 263, (  0,  3), 269)
ec263_270 = EllipticCurve( 2,  3, 263, (200, 39), 270)
ec263_280 = EllipticCurve(-7, 10, 263, (  3,  4), 280)

import unittest

class Testsecp256k1(unittest.TestCase):
    def test_all_curves(self):
        for ec in (secp256k1, ec11_13, ec263_269, ec263_270, ec263_280):
            infinity = (None, None)
            inf_tuple = ec.tuple_from_point(infinity)
            self.assertEqual(inf_tuple, infinity)

            self.assertEqual(ec.pointMultiply(0), infinity)

            G = ec.pointMultiply(1)
            Gy = ec.y(G[0], True)
            self.assertEqual(Gy % 2, 1)
            Gy = ec.y(G[0], False)
            self.assertEqual(Gy % 2, 0)

            P = ec.pointAdd(infinity, G)
            self.assertEqual(P, G)
            P = ec.pointAdd(G, infinity)
            self.assertEqual(P, G)

            P = ec.pointDouble(G)
            self.assertEqual(P, ec.pointMultiply(2))

            P = ec.pointAdd(G, G)
            self.assertEqual(P, ec.pointMultiply(2))

            P = ec.pointMultiply(ec.order-1)
            self.assertEqual(ec.pointAdd(P, G), infinity)
            self.assertEqual(ec.pointMultiply(ec.order), infinity)

            if (ec.order % 2 == 0):
                P = ec.pointMultiply(ec.order//2)
                self.assertEqual(P[1], 0)
                self.assertEqual(ec.pointDouble(P), infinity)

    def test_tuple_from_point(self):
        prv = 0xc28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d
        Pub = secp256k1.pointMultiply(prv)
        
        Pub_bytes = b'\x02' + Pub[0].to_bytes(32, "big")
        p2 = secp256k1.tuple_from_point(Pub_bytes)
        self.assertEqual(p2, Pub)

        Pub_hex_str = Pub_bytes.hex()
        p2 = secp256k1.tuple_from_point(Pub_hex_str)
        self.assertEqual(p2, Pub)

        Pub_bytes = b'\x04' + Pub[0].to_bytes(32, "big") + Pub[1].to_bytes(32, "big")
        p2 = secp256k1.tuple_from_point(Pub_bytes)
        self.assertEqual(p2, Pub)

        Pub_hex_str = Pub_bytes.hex()
        p2 = secp256k1.tuple_from_point(Pub_hex_str)
        self.assertEqual(p2, Pub)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
