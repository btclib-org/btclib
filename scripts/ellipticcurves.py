#!/usr/bin/env python3

"""
Elliptic curve class and instances
"""

from math import sqrt
from typing import Tuple
from numbertheory import mod_inv, mod_sqrt

# elliptic curve y^2 = x^3 + a * x + b
class EllipticCurve:
  """Elliptic curve over Fp group"""

  def __init__(self,
               a: int,
               b: int,
               prime: int,
               G,
               order: int):
    assert 4*a*a*a+27*b*b !=0, "zero discriminant"
    self.__a = a
    self.__b = b
    self.__prime = prime

    self.__G = self.tuple_from_point(G)
    # Hasse Theorem
    t = int(2 * sqrt(prime))
    assert order <= prime + 1 + t, "order too high"
    # false for subgroups
    # assert prime + 1 - t <= order, "order too low"
    self.order = order
    assert self.pointMultiply_raw(order, G) == (None, None), "wrong order"

  def __y2(self, x: int) -> int:
    assert 0 <= x, "x < 0"
    assert x < self.__prime, "x >= prima"
    # skipping a crucial check here:
    # x is not valid if sqrt(y*y) does not exists.
    # This is a good reason to heve this method as private
    return (x*x*x + self.__a*x + self.__b) % self.__prime

  def y(self, x: int, odd: bool) -> int:
    assert type(odd) == bool or odd in (0, 1), "must be bool or 0/1"
    y2 = self.__y2(x)
    # if root does not exist, mod_sqrt will raise a ValueError
    root = mod_sqrt(y2, self.__prime)
    # switch even/odd root when needed
    return root if (root % 2 + odd) != 1 else self.__prime - root

  def __str__(self) -> str:
    result  = "EllipticCurve(a=%s, b=%s)" % (self.__a, self.__b)
    result += "\n prime = 0x%032x" % (self.__prime)
    result += "\n     G =(0x%032x,\n         0x%032x)" % (self.__G)
    result += "\n order = 0x%032x" % (self.order)
    return result

  def __repr__(self) -> str:
    result  = "EllipticCurve(%s, %s" % (self.__a, self.__b)
    result += ", 0x%032x" % (self.__prime)
    result += ", (0x%032x,0x%032x)" % (self.__G)
    result += ", 0x%032x)" % (self.order)
    return result
      
  def tuple_from_point(self, P) -> Tuple[int, int]:
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
        assert Px < self.__prime, "Px >= prime"
        Py = self.y(Px, True)
        if (P[0] == 0x03):
          return (Px, Py)
        else:
          return (Px, self.__prime - Py)
      else:            # uncompressed point
        assert len(P) == 65, "not a point"
        assert P[0] == 0x04, "not an uncompressed point"
        Px = int.from_bytes(P[1:33], 'big')
        assert Px < self.__prime, "Px >= prime"
        Py = int.from_bytes(P[33:], 'big')
        assert Py < self.__prime, "Py >= prime"
        assert self.__y2(Px) == Py*Py % self.__prime, "point is not on the ec"
        return (Px, Py)
    elif isinstance(P, tuple):
      assert len(P) == 2, "invalid tuple point length"
      if (P[0] == None and P[1] == None):
        return P
      assert (type(P[0]) == int and type(P[1]) == int) , "invalid non-int tuple point"
      assert P[0] < self.__prime, "Px >= prime"
      assert P[1] < self.__prime, "Py >= prime"
      assert self.__y2(P[0]) == P[1]*P[1] % self.__prime, "point is not on the ec"
      return P
    else:
      raise ValueError("not an elliptic curve point")


  def bytes_from_point(self, P, compressed: bool = True) -> bytes:
    """ Return a 33 bytes compressed (0x02, 0x03) or 65 bytes uncompressed
        (0x04) point ensuring it belongs to the curve
    """
    if isinstance(P, str):
      P = bytes.fromhex(P)

    if isinstance(P, bytes) or isinstance(P, bytearray):
      if len(P) == 33: # compressed point
        assert P[0] == 0x02 or P[0] == 0x03, "not a compressed point"
        Px = int.from_bytes(P[1:33], 'big')
        assert Px < self.__prime, "Px >= prime"
        return P
      else:            # uncompressed point
        assert len(P) == 65, "not a point"
        assert P[0] == 0x04, "not an uncompressed point"
        Px = int.from_bytes(P[1:33], 'big')
        assert Px < self.__prime, "Px >= prime"
        Py = int.from_bytes(P[33:], 'big')
        assert Py < self.__prime, "Py >= prime"
        assert self.__y2(Px) == Py*Py % self.__prime, "point is not on the ec"
        return P
    elif isinstance(P, tuple):
      assert len(P) == 2, "invalid tuple point length"
      assert P[0] is not None, "infinity point cannot be expressed as bytes"
      assert P[1] is not None, "infinity point cannot be expressed as bytes"
      assert type(P[0]) == int and type(P[1]) == int, "invalid non-int tuple point"
      assert self.__y2(P[0]) == P[1]*P[1] % self.__prime, "point is not on the ec"
      if compressed:
        prefix = b'\x02' if (P[1] % 2 == 0) else b'\x03'
        return prefix + P[0].to_bytes(32, byteorder='big')

      Pbytes = b'\x04' + P[0].to_bytes(32, byteorder='big')
      Pbytes += P[1].to_bytes(32, byteorder='big')
      return Pbytes
    else:
      raise ValueError("not an elliptic curve point")

  def pointDouble(self, P) -> Tuple[int, int]:
    P = self.tuple_from_point(P)
    return self.pointDouble_raw(P)

  def pointDouble_raw(self, P: Tuple[int, int]) -> Tuple[int, int]:
    if P[1] == 0 or P[0] is None:
      return (None, None)
    f = ((3*P[0]*P[0]+self.__a)*mod_inv(2*P[1], self.__prime)) % self.__prime
    x = (f*f-2*P[0]) % self.__prime
    y = (f*(P[0]-x)-P[1]) % self.__prime
    return (x, y)

  def pointAdd(self, P, Q) -> Tuple[int, int]:
    P = self.tuple_from_point(P)
    Q = self.tuple_from_point(Q)
    return self.pointAdd_raw(P, Q)

  def pointAdd_raw(self,
                   P: Tuple[int, int], Q: Tuple[int, int]) -> Tuple[int, int]:
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
  def pointMultiply(self, n: int, P = None) -> Tuple[int, int]:
    if isinstance(n, bytes) or isinstance(n, bytearray):
      n = int.from_bytes(n, 'big')
    n = n % self.order    # the group is cyclic

    if P is None: P = self.__G
    else: P = self.tuple_from_point(P)

    return self.pointMultiply_raw(n, P)

  def pointMultiply_raw(self, n: int, P: Tuple[int, int]) -> Tuple[int, int]:
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
ec79_43   = EllipticCurve(-1,  1,  79, (  0,  1),  43)
ec263_269 = EllipticCurve( 6,  9, 263, (  0,  3), 269)
ec263_270 = EllipticCurve( 2,  3, 263, (200, 39), 270)
ec263_280 = EllipticCurve(-7, 10, 263, (  3,  4), 280)
