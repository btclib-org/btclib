#!/usr/bin/env python3

"""
Elliptic curve class and instances
"""

from math import sqrt
from typing import Tuple, NewType, Union, Optional
from btclib.numbertheory import mod_inv, mod_sqrt

Point = Tuple[int, int]
GenericPoint = Union[str, bytes, bytearray, Point]
# infinity point being represented by None,
# Optional[Point] and Optional[GenericPoint] do include the infinity point

# elliptic curve y^2 = x^3 + a * x + b
class EllipticCurve:
    """Elliptic curve over Fp group"""

    def __init__(self,
                 a: int,
                 b: int,
                 prime: int,
                 G: GenericPoint,
                 order: int) -> None:
        assert 4*a*a*a+27*b*b !=0, "zero discriminant"
        self.__a = a
        self.__b = b
        self.__prime = prime

        self.G = self.tuple_from_point(G)

        # check order with Hasse Theorem
        t = int(2 * sqrt(prime))
        assert order <= prime + 1 + t, "order too high"
        # the following assertion would fail for subgroups
        # assert prime + 1 - t <= order, "order too low"
        self.order = order

        # check (order-1)*G + G = Inf
        T = self.pointMultiply_raw(order-1, self.G)
        Inf = self.pointAdd_raw(T, self.G)
        assert Inf is None, "wrong order"

    def __y2(self, x: int) -> int:
        assert type(x) == int,  "non-int x-coordinate"
        assert 0 <= x, "x-coordinate < 0"
        assert x < self.__prime, "x-coordinate >= prime"
        # skipping a crucial check here:
        # if sqrt(y*y) does not exist, then x is not valid.
        # This is a good reason to have this method as private
        return ((x*x + self.__a)*x + self.__b) % self.__prime

    # use this method also to check x-coordinate validity
    def y(self, x: int, odd1even0: int) -> int:
        assert odd1even0 in (0, 1), "must be bool or 0/1"
        y2 = self.__y2(x)
        # if root does not exist, mod_sqrt will raise a ValueError
        root = mod_sqrt(y2, self.__prime)
        # switch even/odd root when needed
        return root if (root % 2 + odd1even0) != 1 else self.__prime - root

    def checkSecondCoordinate(self, y: int) -> None:
        assert type(y) == int,  "non-int y-coordinate"
        assert 0 <= y, "y-coordinate < 0"
        assert y < self.__prime, "y-coordinate >= prime"

    def checkCoordinates(self, Px: int, Py: int) -> None:
        self.checkSecondCoordinate(Py)
        y = self.y(Px, Py % 2)
        assert Py == y, "point is not on the ec"
  
    def __str__(self) -> str:
        result  = "EllipticCurve(a=%s, b=%s)" % (self.__a, self.__b)
        result += "\n prime = 0x%032x" % (self.__prime)
        result += "\n     G =(0x%032x,\n         0x%032x)" % (self.G)
        result += "\n order = 0x%032x" % (self.order)
        return result

    def __repr__(self) -> str:
        result  = "EllipticCurve(%s, %s" % (self.__a, self.__b)
        result += ", 0x%032x" % (self.__prime)
        result += ", (0x%032x,0x%032x)" % (self.G)
        result += ", 0x%032x)" % (self.order)
        return result
        
    def tuple_from_point(self, P: Optional[GenericPoint]) -> Point:
        """ Return a tuple (Px, Py) having ensured it belongs to the curve """

        if isinstance(P, str):
            # FIXME: xpub is not considered here
            # which is right as it is a bitcoin convention only,
            # not an elliptic curve one 
            P = bytes.fromhex(P)

        if isinstance(P, bytes) or isinstance(P, bytearray):
            # FIXME: xpub might be dealt with here?
            if len(P) == 33: # compressed point
                assert P[0] == 0x02 or P[0] == 0x03, "not a compressed point"
                Px = int.from_bytes(P[1:33], 'big')
                Py = self.y(Px, P[0] % 2) # also check Px validity
            else:            # uncompressed point
                assert len(P) == 65, "not a point"
                assert P[0] == 0x04, "not an uncompressed point"
                Px = int.from_bytes(P[ 1:33], 'big')
                Py = int.from_bytes(P[33:  ], 'big')
                self.checkCoordinates(Px, Py)
            return Px, Py
        elif isinstance(P, tuple):
            assert len(P) == 2, "invalid tuple point length"
            self.checkCoordinates(P[0], P[1])
            return P
        elif P is None:
            raise ValueError("infinity point cannot be expressed as tuple")
        else:
            raise ValueError("not an elliptic curve point")


    def bytes_from_point(self, P: Optional[GenericPoint], compressed: bool) -> bytes:
        """ Return a 33 bytes compressed (0x02, 0x03) or 65 bytes uncompressed
            (0x04) point ensuring it belongs to the curve
        """
        if isinstance(P, str):
            P = bytes.fromhex(P)

        if isinstance(P, bytes) or isinstance(P, bytearray):
            if len(P) == 33: # compressed point
                assert P[0] == 0x02 or P[0] == 0x03, "not a compressed point"
                Px = int.from_bytes(P[1:33], 'big')
                self.y(Px, True) # check Px validity
                return P
            else:            # uncompressed point
                assert len(P) == 65, "not a point"
                assert P[0] == 0x04, "not an uncompressed point"
                Px = int.from_bytes(P[ 1:33], 'big')
                Py = int.from_bytes(P[33:  ], 'big')
                self.checkCoordinates(Px, Py)
                return P
        elif isinstance(P, tuple):
            assert len(P) == 2, "invalid tuple point length"
            self.checkCoordinates(P[0], P[1])
            if compressed:
                prefix = b'\x02' if (P[1] % 2 == 0) else b'\x03'
                return prefix + P[0].to_bytes(32, byteorder='big')
            Pbytes = b'\x04' + P[0].to_bytes(32, byteorder='big')
            Pbytes += P[1].to_bytes(32, byteorder='big')
            return Pbytes
        elif P is None:
            raise ValueError("infinity point cannot be expressed as bytes")
        else:
            raise ValueError("not an elliptic curve point")

    def pointDouble(self, P: Optional[GenericPoint]) -> Optional[Point]:
        if P is not None: P = self.tuple_from_point(P)
        return self.pointDouble_raw(P)

    def pointDouble_raw(self, P: Optional[Point]) -> Optional[Point]:
        if P is None or P[1] == 0: return None

        f = ((3*P[0]*P[0]+self.__a)*mod_inv(2*P[1], self.__prime)) % self.__prime
        x = (f*f-2*P[0]) % self.__prime
        y = (f*(P[0]-x)-P[1]) % self.__prime
        return x, y

    def pointAdd(self, P: Optional[GenericPoint], Q: Optional[GenericPoint]) -> Optional[Point]:
        if P is not None: P = self.tuple_from_point(P)
        if Q is not None: Q = self.tuple_from_point(Q)
        return self.pointAdd_raw(P, Q)

    def pointAdd_raw(self, P: Optional[Point], Q: Optional[Point]) -> Optional[Point]:
        if Q is None: return P
        if P is None: return Q

        if Q[0] == P[0]:
            if Q[1] == P[1]: return self.pointDouble_raw(P)
            else:            return None

        lam = ((Q[1]-P[1]) * mod_inv(Q[0]-P[0], self.__prime)) % self.__prime
        x = (lam*lam-P[0]-Q[0]) % self.__prime
        y = (lam*(P[0]-x)-P[1]) % self.__prime
        return x, y

    def pointMultiply(self, n: int, P: Optional[GenericPoint]) -> Optional[Point]:
        if isinstance(n, bytes) or isinstance(n, bytearray):
            n = int.from_bytes(n, 'big')
        if P is not None: P = self.tuple_from_point(P)
        return self.pointMultiply_raw(n, P)

    # efficient double & add, using binary decomposition of n
    def pointMultiply_raw(self, n: int, P: Optional[Point]) -> Optional[Point]:
        n = n % self.order # the group is cyclic
        result = None      # initialized to infinity point
        addendum = P       # initialized as 2^0 P
        while n > 0:       # use binary representation of n
            if n & 1:      # if least significant bit is 1 add current addendum
                result = self.pointAdd_raw(result, addendum)
            n = n>>1       # right shift to remove the bit just accounted for
                           # then update addendum for next step:
            addendum = self.pointDouble_raw(addendum)
        return result

# bitcoin curve
__Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
__Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
__order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
secp256k1 = EllipticCurve(0, 7, 2**256 - 2**32 - 977, (__Gx, __Gy), __order)

# toy curves
ec11_13   = EllipticCurve( 1,  6,  11, (  5,  9),  13)
ec79_43   = EllipticCurve(-1,  1,  79, (  0,  1),  43)
ec263_269 = EllipticCurve( 6,  9, 263, (  0,  3), 269)
ec263_270 = EllipticCurve( 2,  3, 263, (200, 39), 270)
ec263_280 = EllipticCurve(-7, 10, 263, (  3,  4), 280)
