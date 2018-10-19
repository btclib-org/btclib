#!/usr/bin/env python3

"""
Elliptic curve class, associated functions, and instances of SEC2 curves
"""

from math import sqrt
from hashlib import sha256
from typing import Tuple, NewType, Union, Optional
from btclib.numbertheory import mod_inv, mod_sqrt

Point = Tuple[int, int]
# infinity point being represented by None,
# Optional[Point] does include the infinity point

# elliptic curve y^2 = x^3 + a * x + b
class EllipticCurve:
    """Elliptic curve over Fp group"""

    def __init__(self,
                 a: int,
                 b: int,
                 p: int,
                 G: Point,
                 n: int) -> None:
        assert 4*a*a*a+27*b*b !=0, "zero discriminant"
        self.__a = a
        self.__b = b

        self.__p = p
        self.bytesize = (p.bit_length() + 7) // 8

        self.pIsThreeModFour = (self.__p % 4 == 3)

        # check n with Hasse Theorem
        t = int(2 * sqrt(p))
        assert n <= p + 1 + t, "order %s too high for prime %s" % (n, p)
        # the following assertion would fail for subgroups
        assert p + 1 - t <= n, "order %s too low for prime %s" % (n, p)
        self.n = n

        assert isOnCurve(self, G), "G is not on curve"
        self.G = G

        # check (n-1)*G + G = Inf
        T = self.pointMultiply(n-1, self.G)
        Inf = self.pointAdd(T, self.G)
        assert Inf is None, "wrong order"

    def return_prime(self) -> int:
        return self.__p

    def assertPointCoordinate(self, c: int) -> None:
        assert type(c) == int,  "non-int point coordinate"
        assert 0 <= c, "point coordinate %s < 0" % c
        assert c < self.__p, "point coordinate %s >= prime" % c

    def __y2(self, x: int) -> int:
        self.assertPointCoordinate(x)
        # skipping a crucial check here:
        # if sqrt(y*y) does not exist, then x is not valid.
        # This is a good reason to keep this method private
        return ((x*x + self.__a)*x + self.__b) % self.__p

    def areOnCurve(self, x: int, y: int) -> bool:
        self.assertPointCoordinate(y)
        return self.__y2(x) == (y*y % self.__p)

    def jacobi(self, y: int) -> int:
        self.assertPointCoordinate(y)
        return pow(y, (self.__p - 1) // 2, self.__p)

    # break the y simmetry: even/odd, low/high, or quadratic residue criteria

    def yOdd(self, x: int, odd1even0: int) -> int:
        assert odd1even0 in (0, 1), "must be bool or 0/1"
        y2 = self.__y2(x)
        if y2 == 0: return 0
        # if root does not exist, mod_sqrt will raise a ValueError
        root = mod_sqrt(y2, self.__p)
        # switch even/odd root when needed
        return root if (root % 2 + odd1even0) != 1 else self.__p - root

    def yLow(self, x: int, low1high0: int) -> int:
        assert low1high0 in (0, 1), "must be bool or 0/1"
        y2 = self.__y2(x)
        if y2 == 0: return 0
        # if root does not exist, mod_sqrt will raise a ValueError
        root = mod_sqrt(y2, self.__p)
        # switch low/high root when needed
        return root if (root < self.__p/2) else self.__p - root

    def yQuadraticResidue(self, x: int, quadRes: int) -> int:
        assert self.pIsThreeModFour, "this method works only when p = 3 (mod 4)"
        assert quadRes in (0, 1), "must be bool or 0/1"
        y2 = self.__y2(x)
        if y2 == 0: return 0
        # if root does not exist, mod_sqrt will raise a ValueError
        root = mod_sqrt(y2, self.__p)
        # switch to the quadratic residue root when needed
        if quadRes:
            return self.__p - root if (self.jacobi(root) != 1) else root
        else:
            return root if (self.jacobi(root) != 1) else self.__p - root

    def __str__(self) -> str:
        result  = "EllipticCurve(a=%s, b=%s)" % (self.__a, self.__b)
        result += "\n p = 0x%032x" % (self.__p)
        result += "\n G =(0x%032x,\n         0x%032x)" % (self.G)
        result += "\n n = 0x%032x" % (self.n)
        return result

    def __repr__(self) -> str:
        result  = "EllipticCurve(%s, %s" % (self.__a, self.__b)
        result += ", 0x%032x" % (self.__p)
        result += ", (0x%032x,0x%032x)" % (self.G)
        result += ", 0x%032x)" % (self.n)
        return result
        
    def pointAdd(self, Q: Optional[Point], R: Optional[Point]) -> Optional[Point]:
        if R is None:
            return Q
        if Q is None:
            return R
        if R[0] == Q[0]:
            if R[1] != Q[1] or Q[1] == 0: # opposite points
                return None
            else: # point doubling
                lam = ((3*Q[0]*Q[0]+self.__a)*mod_inv(2*Q[1], self.__p)) % self.__p
        else:
            lam = ((R[1]-Q[1]) * mod_inv(R[0]-Q[0], self.__p)) % self.__p
        x = (lam*lam-Q[0]-R[0]) % self.__p
        y = (lam*(Q[0]-x)-Q[1]) % self.__p
        return x, y

    # double & add, using binary decomposition of n
    def pointMultiply(self, n: int, Q: Optional[Point]) -> Optional[Point]:
        if Q is None:
            return Q
        n = n % self.n # the group is cyclic
        r = None       # initialized to infinity point
        while n > 0:   # use binary representation of n
            if n & 1:  # if least significant bit is 1 then add current Q
                r = self.pointAdd(r, Q)
            n = n>>1   # right shift removes the bit just accounted for
                       # double Q for next step
            Q = self.pointAdd(Q, Q)
        return r


### Functions using EllipticCurve ####

def isOnCurve(ec: EllipticCurve, Q: Point) -> bool:
    assert isinstance(Q, tuple), "not a tuple point"
    assert len(Q) == 2, "invalid tuple point length %s" % len(Q)
    return ec.areOnCurve(Q[0], Q[1])

GenericPoint = Union[str, bytes, bytearray, Point]
# infinity point being represented by None,
# Optional[GenericPoint] do include the infinity point

def tuple_from_Point(ec: EllipticCurve, Q: Optional[GenericPoint]) -> Point:
    """Return a tuple (Px, Py) having ensured it belongs to the curve"""

    if Q is None:
        raise ValueError("infinity point cannot be expressed as tuple")

    if isinstance(Q, str):
        # BIP32 xpub is not considered here,
        # as it is a bitcoin convention only
        Q = bytes.fromhex(Q)

    if isinstance(Q, bytes) or isinstance(Q, bytearray):
        if len(Q) == ec.bytesize+1: # compressed point
            assert Q[0] == 0x02 or Q[0] == 0x03, "not a compressed point"
            Px = int.from_bytes(Q[1:ec.bytesize+1], 'big')
            Py = ec.yOdd(Px, Q[0] % 2) # also check Px validity
        else:                          # uncompressed point
            assert len(Q) == 2*ec.bytesize+1, \
                "wrong byte-size (%s) for a point: it should be %s or %s" % \
                                    (len(Q), ec.bytesize+1, 2*ec.bytesize+1)
            assert Q[0] == 0x04, "not an uncompressed point"
            Px = int.from_bytes(Q[1:ec.bytesize+1], 'big')
            Py = int.from_bytes(Q[ec.bytesize+1:], 'big')
            assert ec.areOnCurve(Px, Py), "not on curve"
        return Px, Py

    # must be a tuple
    assert isOnCurve(ec, Q), "not on curve"
    return Q


def bytes_from_Point(ec: EllipticCurve, Q: Optional[GenericPoint], compressed: bool) -> bytes:
    """
    Return a compressed (0x02, 0x03) or uncompressed (0x04)
    point ensuring it belongs to the curve
    """
    # enforce self-consistency with whatever
    # policy is implemented by tuple_from_Point
    Q = tuple_from_Point(ec, Q)

    bPx = Q[0].to_bytes(ec.bytesize, byteorder='big')
    if compressed:
        return (b'\x03' if (Q[1] & 1) else b'\x02') + bPx

    return b'\x04' + bPx + Q[1].to_bytes(ec.bytesize, byteorder='big')


def pointAdd(ec: EllipticCurve, Q: Optional[GenericPoint], R: Optional[GenericPoint]) -> Optional[Point]:
    if Q is not None: Q = tuple_from_Point(ec, Q)
    if R is not None: R = tuple_from_Point(ec, R)
    return ec.pointAdd(Q, R)


Scalar = Union[str, bytes, bytearray, int]


def int_from_Scalar(ec: EllipticCurve, n: Scalar) -> int:
    if isinstance(n, str): # hex string
        n = bytes.fromhex(n)

    if isinstance(n, bytes) or isinstance(n, bytearray):
        # FIXME: asses if must be <= or ec.bytesize should be rivised
        assert len(n) <= ec.bytesize, "wrong lenght"
        n = int.from_bytes(n, 'big')

    if not isinstance(n, int):
        raise TypeError("a bytes-like object is required (also str or int)")
    return n % ec.n
        

def bytes_from_Scalar(ec: EllipticCurve, n: Scalar) -> bytes:
    # enforce self-consistency with whatever
    # policy is implemented by int_from_Scalar
    n = int_from_Scalar(ec, n)
    return n.to_bytes(ec.bytesize, 'big')


def pointMultiply(ec: EllipticCurve, n: Scalar, Q: Optional[GenericPoint]) -> Optional[Point]:
    n = int_from_Scalar(ec, n)
    if Q is not None: Q = tuple_from_Point(ec, Q)
    return ec.pointMultiply(n, Q)

def secondGenerator(ec: EllipticCurve) -> Point:
    """ Function needed to construct a suitable Nothing-Up-My-Sleeve (NUMS) 
    generator H wrt G. 

    source: https://github.com/ElementsProject/secp256k1-zkp/blob/secp256k1-zkp/src/modules/rangeproof/main_impl.h
    idea: (https://crypto.stackexchange.com/questions/25581/second-generator-for-secp256k1-curve)
    Possible to accomplish it by using the cryptographic hash of G 
    to pick H. Then coerce the hash to a point:
    as just hashing the point could possibly result not in obtaining 
    a curvepoint, keep on incrementing the hash of the x-coordinate 
    until you get a valid curve point H = (hx,hy).
    """
    G_bytes = bytes_from_Point(ec, ec.G, False)
    h = sha256(G_bytes).digest() 
    hx = int_from_Scalar(ec, h)
    isCurvePoint = False
    while not isCurvePoint:
        try:
            hy = ec.yOdd(hx, False)
            isCurvePoint = True
        except:
            hx += 1
    return hx, hy



# http://www.secg.org/sec2-v2.pdf
__a = 0
__b = 3
__p = 2**192 - 2**32 - 2**12 - 2**8 - 2**7 - 2**6 - 2**3 - 1
__Gx = 0xDB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D
__Gy = 0x9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D
__n = 0xFFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D
secp192k1 = EllipticCurve(__a, __b, __p, (__Gx, __Gy), __n)

__a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC
__b = 0X64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1
__p = 2**192 - 2**64 - 1
__Gx = 0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012
__Gy = 0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811
__n = 0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831
secp192r1 = EllipticCurve(__a, __b, __p, (__Gx, __Gy), __n)

__a = 0
__b = 5
__p = 2**224 - 2**32 - 2**12 - 2**11 - 2**9 - 2**7 - 2**4 - 2 - 1
__Gx    = 0xA1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C
__Gy    = 0x7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5
__n = 0x010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7
secp224k1 = EllipticCurve(__a, __b, __p, (__Gx, __Gy), __n)

__a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE
__b = 0XB4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4
__p = 2**224 - 2**96 + 1
__Gx    = 0xB70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21
__Gy    = 0xBD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34
__n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D
secp224r1 = EllipticCurve(__a, __b, __p, (__Gx, __Gy), __n)

# bitcoin curve
#
__a = 0
__b = 7
__p = 2**256 - 2**32 - 977
__Gx    = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
__Gy    = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
__n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
secp256k1 = EllipticCurve(__a, __b, __p, (__Gx, __Gy), __n)

__a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
__b = 0X5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
__p = 2**256 - 2**224 + 2**192 + 2**96 - 1
__Gx    = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
__Gy    = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
__n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
secp256r1 = EllipticCurve(__a, __b, __p, (__Gx, __Gy), __n)

__a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC
__b = 0XB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF
__p = 2**384 - 2**128 - 2**96 + 2**32 - 1
__Gx    = 0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7
__Gy    = 0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F
__n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
secp384r1 = EllipticCurve(__a, __b, __p, (__Gx, __Gy), __n)

__a = 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC
__b = 0x0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00
__p = 2**521 - 1
__Gx    = 0x00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66
__Gy    = 0x011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650
__n = 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409
secp521r1 = EllipticCurve(__a, __b, __p, (__Gx, __Gy), __n)
