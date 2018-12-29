#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""
EllipticCurve class, functions, and instances of SEC2 elliptic curves

TODO: document duck-typing and static typing design choices
"""

from hashlib import sha256
from math import sqrt
from typing import Tuple, NewType, Union

from btclib.numbertheory import mod_inv, mod_sqrt, legendre_symbol

Point = Tuple[int, int]
# infinity point is (int, 0), checked with 'Inf[1] == 0'
GenericPoint = Union[str, bytes, Point]
# str must be a hex-string

JacPoint = Tuple[int, int, int]
# infinity point is (int, int, 0), checked with 'Inf[2] == 0'

# elliptic curve y^2 = x^3 + a*x + b


class EllipticCurve:
    """Elliptic curve over Fp group"""

    def __init__(self,
                 p: int,
                 a: int,
                 b: int,
                 G: Point,
                 n: int,
                 checkWeakness=True) -> None:
        """EllipticCurve instantiation

        Parameters are checked according to SEC2 3.1.1.2.1
        """

        # 1) check that p is an odd prime
        if p % 2 == 0:
            raise ValueError("p (%s) is not odd" % p)
        # Fermat test will do as _probabilistic_ primality test...
        if not pow(2, p-1, p) == 1:
            raise ValueError("p (%s) is not prime" % p)
        self._p = p
        self.bytesize = (p.bit_length() + 7) // 8  # FIXME: p or n

        # 1. check that security level is as required
        # missing for the time being

        # must be true to break simmetry using quadratic residue
        self.pIsThreeModFour = (self._p % 4 == 3)

        # 2. check that a and b are integers in the interval [0, p−1]
        self.checkCoordinate(a)
        self.checkCoordinate(b)

        # 3. Check that 4*a^3 + 27*b^2 ≠ 0 (mod p).
        d = 4*a*a*a+27*b*b
        if d % p == 0:
            raise ValueError("zero discriminant")
        self._a = a
        self._b = b

        # 2. check that xG and yG are integers in the interval [0, p−1]
        if len(G) != 2:
            raise ValueError("Generator must a be a Tuple[int, int]")
        if not self.areValidCoordinates(G[0], G[1]):
            raise ValueError("Generator is not on the 'x^3 + a*x + b' curve")
        self.G = int(G[0]), int(G[1])

        # 4. Check that n is prime.
        if n < 2 or (n > 2 and not pow(2, n-1, n) == 1):
            raise ValueError("n (%s) is not prime" % n)
        # also check n with Hasse Theorem
        t = int(2 * sqrt(p))
        if not (p+1 - t <= n <= p+1 + t):
            raise ValueError("n (%s) not in [p+1 - t, p+1 + t]" % n)

        # 7. Check that nG = Inf.
        self.n = n
        # the following one would be tautologically true
        # Inf = pointMultiply(self, n, self.G)
        InfMinusG = pointMultiply(self, n-1, self.G)
        Inf = self.add(InfMinusG, self.G)
        if Inf[1] != 0:
            raise ValueError("n (%s) is not the group order" % n)

        # 6. Check cofactor
        # missing for the time being

        # 8. Check that n ≠ p
        if n == p:
            raise UserWarning("n=p -> weak curve")
        # 8. Check that p^i % n ≠ 1 for all 1≤i<100
        if checkWeakness:
            for i in (1, 100):
                if pow(p, i, n) == 1:
                    raise UserWarning("weak curve")

    def __str__(self) -> str:
        result = "EllipticCurve"
        result += "\n p = 0x%032x" % (self._p)
        result += "\n a = %s, b = %s" % (self._a, self._b)
        result += "\n G = (0x%032x,\n          0x%032x)" % (self.G)
        result += "\n n = 0x%032x" % (self.n)
        return result

    def __repr__(self) -> str:
        result = "EllipticCurve("
        result += "0x%032x" % (self._p)
        result += ", %s, %s" % (self._a, self._b)
        result += ", (0x%032x,0x%032x)" % (self.G)
        result += ", 0x%032x)" % (self.n)
        return result

    # methods using _p: they would become functions if _p goes public

    def checkCoordinate(self, c: int) -> None:  # FIXME: jac / affine ?
        """check that coordinate is in [0, p-1]"""
        if not (0 <= c < self._p):
            raise ValueError("coordinate %s not in [0, p-1]" % c)

    def opposite(self, Q: GenericPoint) -> Point:
        Q = to_Point(self, Q)
        if Q[1] == 0:  # Infinity point in affine coordinates
            return Q
        else:
            return Q[0], self._p - Q[1]

    def _affine_from_jac(self, Q: JacPoint) -> Point:
        if len(Q) != 3:
            raise ValueError("input point not in Jacobian coordinates")
        if Q[2] == 0:  # Infinity point in Jacobian coordinates
            return 1, 0
        else:
            Z2 = Q[2]*Q[2]
            x = (Q[0]*mod_inv(Z2, self._p)) % self._p
            y = (Q[1]*mod_inv(Z2*Q[2], self._p)) % self._p
            return x, y

    # methods using _a, _b, _p

    def _addJacobian(self, Q: JacPoint, R: JacPoint) -> JacPoint:
        # points are assumed to be on curve

        if Q[2] == 0:  # Infinity point in Jacobian coordinates
            return R
        if R[2] == 0:  # Infinity point in Jacobian coordinates
            return Q

        RZ2 = R[2] * R[2]
        RZ3 = RZ2 * R[2]
        QZ2 = Q[2] * Q[2]
        QZ3 = QZ2 * Q[2]
        if Q[0]*RZ2 % self._p == R[0]*QZ2 % self._p:     # same affine x
            if Q[1]*RZ3 % self._p == R[1]*QZ3 % self._p:  # point doubling
                QY2 = Q[1]*Q[1]
                W = (3*Q[0]*Q[0] + self._a*QZ2*QZ2) % self._p
                V = (4*Q[0]*QY2) % self._p
                X = (W*W - 2*V) % self._p
                Y = (W*(V - X) - 8*QY2*QY2) % self._p
                Z = (2*Q[1]*Q[2]) % self._p
                return X, Y, Z
            else:                                        # opposite points
                return 1, 1, 0
        else:
            T = (Q[1]*RZ3) % self._p
            U = (R[1]*QZ3) % self._p
            W = (U - T) % self._p

            M = (Q[0]*RZ2) % self._p
            N = (R[0]*QZ2) % self._p
            V = (N - M) % self._p

            V2 = V * V
            V3 = V2 * V
            MV2 = M * V2
            X = (W*W - V3 - 2*MV2) % self._p
            Y = (W*(MV2 - X) - T*V3) % self._p
            Z = (V*Q[2]*R[2]) % self._p
            return X, Y, Z

    def _addAffine(self, Q: GenericPoint, R: GenericPoint) -> Point:
        Q = to_Point(self, Q)  # also check that is on curve
        R = to_Point(self, R)  # also check that is on curve
        if R[1] == 0:  # Infinity point in affine coordinates
            return Q
        if Q[1] == 0:  # Infinity point in affine coordinates
            return R
        if R[0] == Q[0]:
            if R[1] == Q[1]:  # point doubling
                lam = ((3*Q[0]*Q[0]+self._a) *
                       mod_inv(2*Q[1], self._p)) % self._p
            else:  # must be opposite (points already checked to be on curve)
                # elif R[1] == self._p - Q[1]: # opposite points
                return 1, 0
            # else:
            #    raise ValueError("points are not on the same curve")
        else:
            lam = ((R[1]-Q[1]) * mod_inv(R[0]-Q[0], self._p)) % self._p
        x = (lam*lam-Q[0]-R[0]) % self._p
        y = (lam*(Q[0]-x)-Q[1]) % self._p
        return x, y

    def add(self, Q1: GenericPoint, Q2: GenericPoint) -> Point:
        Q1 = to_Point(self, Q1)
        Q2 = to_Point(self, Q2)
        QJ1 = _jac_from_affine(Q1)
        QJ2 = _jac_from_affine(Q2)
        R = self._addJacobian(QJ1, QJ2)
        return self._affine_from_jac(R)

    def _y2(self, x: int) -> int:
        self.checkCoordinate(x)
        # skipping a crucial check here:
        # if sqrt(y*y) does not exist, then x is not valid.
        # This is a good reason to keep this method private
        return ((x*x + self._a)*x + self._b) % self._p

    def y(self, x: int) -> int:
        y2 = self._y2(x)
        # mod_sqrt will raise a ValueError if root does not exist
        return mod_sqrt(y2, self._p)

    def areValidCoordinates(self, x: int, y: int) -> bool:
        if y == 0:  # Infinity point in affine coordinates
            return True
        self.checkCoordinate(y)
        return self._y2(x) == (y*y % self._p)

    # break the y simmetry: even/odd, low/high, or quadratic residue criteria

    def yOdd(self, x: int, odd1even0: int) -> int:
        """return the odd (even) y coordinate associated to x"""
        if odd1even0 not in (0, 1):
            raise ValueError("odd1even0 must be bool or 0/1")
        root = self.y(x)
        # switch even/odd root as needed (XORing the conditions)
        return root if root % 2 == odd1even0 else self._p - root

    def yHigh(self, x: int, high1low0: int) -> int:
        """return the high (low) y coordinate associated to x"""
        if high1low0 not in (0, 1):
            raise ValueError("high1low0 must be bool or 0/1")
        root = self.y(x)
        # switch low/high root as needed (XORing the conditions)
        return root if (self._p//2 < root) == high1low0 else self._p - root

    def yQuadraticResidue(self, x: int, quadRes: int) -> int:
        """return the quadratic residue y coordinate associated to x"""
        if quadRes not in (0, 1):
            raise ValueError("quadRes must be bool or 0/1")
        if not self.pIsThreeModFour:
            raise ValueError("this method works only when p = 3 (mod 4)")
        root = self.y(x)
        # switch to quadratic residue root as needed (XORing the conditions)
        legendre1 = legendre_symbol(root, self._p)
        return root if legendre1 == quadRes else self._p - root


def to_Point(ec: EllipticCurve, Q: GenericPoint) -> Point:
    """Return a tuple (Px, Py) according to SEC2 2.3.4

    It ensures the point belongs to the curve
    """

    if isinstance(Q, str):
        # BIP32 xpub is not considered here,
        # as it is a bitcoin convention only
        Q = bytes.fromhex(Q)

    if isinstance(Q, bytes):
        if len(Q) == 1 and Q[0] == 0x00:  # infinity point
            return 1, 0
        if len(Q) == ec.bytesize+1:  # compressed point
            if Q[0] not in (0x02, 0x03):
                m = "%s bytes, but not a compressed point" % (ec.bytesize+1)
                raise ValueError(m)
            Px = int.from_bytes(Q[1:], 'big')
            Py = ec.yOdd(Px, Q[0] % 2)  # also check Px validity
        else:                          # uncompressed point
            if len(Q) != 2*ec.bytesize+1:
                m = "wrong byte-size (%s) for a point: it " % len(Q)
                m += "should be %s or %s" % (ec.bytesize+1, 2*ec.bytesize+1)
                raise ValueError(m)
            if Q[0] != 0x04:
                raise ValueError("not an uncompressed point")
            Px = int.from_bytes(Q[1:ec.bytesize+1], 'big')
            Py = int.from_bytes(Q[ec.bytesize+1:], 'big')
            if not ec.areValidCoordinates(Px, Py):
                raise ValueError("point not on curve")
        return Px, Py

    # input is already a Point
    if not ec.areValidCoordinates(Q[0], Q[1]):
        raise ValueError("point not on curve")
    return Q

# this function is used by the EllipticCurve class; it might be a method...


def _jac_from_affine(Q: Point) -> JacPoint:
    if len(Q) != 2:
        raise ValueError("input point not in affine coordinates")
    if Q[1] == 0:  # Infinity point in affine coordinates
        return 1, 1, 0
    return Q[0], Q[1], 1

# this function is used by the EllipticCurve class; it might be a method...


def bytes_from_Point(ec: EllipticCurve,
                     Q: GenericPoint,
                     compressed: bool) -> bytes:
    """
    Return a compressed (0x02, 0x03) or uncompressed (0x04)
    point ensuring it belongs to the curve
    """
    # enforce self-consistency with whatever
    # policy is implemented by to_Point
    Q = to_Point(ec, Q)

    if Q[1] == 0:  # infinity point in affine coordinates
        return b'\x00'

    bPx = Q[0].to_bytes(ec.bytesize, byteorder='big')
    if compressed:
        return (b'\x03' if (Q[1] & 1) else b'\x02') + bPx

    return b'\x04' + bPx + Q[1].to_bytes(ec.bytesize, byteorder='big')


Scalar = Union[str, bytes, int]


def int_from_Scalar(ec: EllipticCurve, q: Scalar) -> int:
    """Integer for Point multiplication (i.e. private key), not coordinate"""
    if isinstance(q, str):  # hex string
        q = bytes.fromhex(q)

    if isinstance(q, bytes):
        if len(q) > ec.bytesize:  # FIXME: might be unnecessary
            errmsg = 'scalar size %s > %s' % (len(q), ec.bytesize)
            raise ValueError(errmsg)
        q = int.from_bytes(q, 'big')

    return q % ec.n  # fails if q is not int-like FIXME no % ec.n


def bytes_from_Scalar(ec: EllipticCurve, n: Scalar) -> bytes:
    # enforce self-consistency with whatever
    # policy is implemented by int_from_Scalar
    n = int_from_Scalar(ec, n)
    return n.to_bytes(ec.bytesize, 'big')

# this function is used by the EllipticCurve class; it might be a method...


def pointMultiply(ec: EllipticCurve,
                  n: Scalar,
                  Q: GenericPoint) -> Point:
    Q = to_Point(ec, Q)
    QJ = _jac_from_affine(Q)
    R = _pointMultiplyJacobian(ec, n, QJ)
    return ec._affine_from_jac(R)


def _pointMultiplyAffine(ec: EllipticCurve,
                         n: Scalar,
                         Q: GenericPoint) -> Point:
    """double & add in affine coordinates, using binary decomposition of n"""
    n = int_from_Scalar(ec, n)
    Q = to_Point(ec, Q)

    if Q[1] == 0:  # Infinity point in affine coordinates
        return Q
    R = 1, 0      # initialize as infinity point
    while n > 0:  # use binary representation of n
        if n & 1:  # if least significant bit is 1 then add current Q
            R = ec.add(R, Q)
        n = n >> 1  # right shift removes the bit just accounted for
        # double Q for next step
        Q = ec.add(Q, Q)
    return R


def _pointMultiplyJacobian(ec: EllipticCurve,
                           n: Scalar,
                           Q: JacPoint) -> JacPoint:
    """double & add in jacobian coordinates, using binary decomposition of n"""
    n = int_from_Scalar(ec, n)
    if len(Q) != 3:
        raise ValueError("input point not in Jacobian coordinates")

    if Q[2] == 0:  # Infinity point in Jacobian coordinates
        return 1, 1, 0
    R = 1, 1, 0   # initialize as infinity point
    while n > 0:  # use binary representation of n
        if n & 1:  # if least significant bit is 1 then add current Q
            R = ec._addJacobian(R, Q)
        n = n >> 1  # right shift removes the bit just accounted for
        # double Q for next step:
        Q = ec._addJacobian(Q, Q)
    return R


def DoubleScalarMultiplication(ec: EllipticCurve,
                               k1: Scalar,
                               Q1: GenericPoint,
                               k2: Scalar,
                               Q2: GenericPoint) -> Point:
    """Shamir trick for efficient computation of k1*Q1 + k2*Q2"""

    r1 = int_from_Scalar(ec, k1)
    if r1 == 0:
        Q2 = to_Point(ec, Q2)
        R2 = _jac_from_affine(Q2)
        R = _pointMultiplyJacobian(ec, k2, R2)
        return ec._affine_from_jac(R)

    Q1 = to_Point(ec, Q1)
    if Q1[1] == 0:
        Q2 = to_Point(ec, Q2)
        R2 = _jac_from_affine(Q2)
        R = _pointMultiplyJacobian(ec, k2, R2)
        return ec._affine_from_jac(R)

    R1 = _jac_from_affine(Q1)

    r2 = int_from_Scalar(ec, k2)
    if r2 == 0:
        R = _pointMultiplyJacobian(ec, r1, R1)
        return ec._affine_from_jac(R)

    Q2 = to_Point(ec, Q2)
    if Q2[1] == 0:
        R = _pointMultiplyJacobian(ec, r1, R1)
        return ec._affine_from_jac(R)

    R2 = _jac_from_affine(Q2)

    R = 1, 1, 0  # initialize as infinity point
    msb = max(r1.bit_length(), r2.bit_length())
    while msb > 0:
        if r1 >> (msb - 1):  # checking msb
            R = ec._addJacobian(R, R1)
            r1 -= pow(2, r1.bit_length() - 1)
        if r2 >> (msb - 1):  # checking msb
            R = ec._addJacobian(R, R2)
            r2 -= pow(2, r2.bit_length() - 1)
        if msb > 1:
            R = ec._addJacobian(R, R)
        msb -= 1

    return ec._affine_from_jac(R)


def secondGenerator(ec: EllipticCurve,
                    Hash=sha256) -> Point:
    """ Function needed to construct a suitable Nothing-Up-My-Sleeve (NUMS) 
    generator H wrt G. 

    source: https://github.com/ElementsProject/secp256k1-zkp/blob/secp256k1-zkp/src/modules/rangeproof/main_impl.h
    idea: (https://crypto.stackexchange.com/questions/25581/second-generator-for-secp256k1-curve)
    Possible to accomplish it by using the cryptographic hash of G 
    to pick H. Then coerce the hash to a point:
    as just hashing the point could possibly result not in obtaining 
    a curvepoint, keep on incrementing the hash of the x-coordinate 
    until you get a valid curve point H = (hx, hy).
    """
    G_bytes = bytes_from_Point(ec, ec.G, False)
    h = Hash(G_bytes).digest()
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
__p = 2**160 - 2**31 - 1
__a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC
__b = 0x1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45
__Gx = 0x4A96B5688EF573284664698968C38BB913CBFC82
__Gy = 0x23A628553168947D59DCC912042351377AC5FB32
__n = 0x0100000000000000000001F4C8F927AED3CA752257
secp160r1 = EllipticCurve(__p, __a, __b, (__Gx, __Gy), __n)

__p = 2**192 - 2**32 - 2**12 - 2**8 - 2**7 - 2**6 - 2**3 - 1
__a = 0
__b = 3
__Gx = 0xDB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D
__Gy = 0x9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D
__n = 0xFFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D
secp192k1 = EllipticCurve(__p, __a, __b, (__Gx, __Gy), __n)

__p = 2**192 - 2**64 - 1
__a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC
__b = 0X64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1
__Gx = 0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012
__Gy = 0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811
__n = 0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831
secp192r1 = EllipticCurve(__p, __a, __b, (__Gx, __Gy), __n)

__p = 2**224 - 2**32 - 2**12 - 2**11 - 2**9 - 2**7 - 2**4 - 2 - 1
__a = 0
__b = 5
__Gx = 0xA1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C
__Gy = 0x7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5
__n = 0x010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7
secp224k1 = EllipticCurve(__p, __a, __b, (__Gx, __Gy), __n)

__p = 2**224 - 2**96 + 1
__a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE
__b = 0XB4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4
__Gx = 0xB70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21
__Gy = 0xBD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34
__n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D
secp224r1 = EllipticCurve(__p, __a, __b, (__Gx, __Gy), __n)

# bitcoin curve
__p = 2**256 - 2**32 - 977
__a = 0
__b = 7
__Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
__Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
__n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
secp256k1 = EllipticCurve(__p, __a, __b, (__Gx, __Gy), __n)

__p = 2**256 - 2**224 + 2**192 + 2**96 - 1
__a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
__b = 0X5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
__Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
__Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
__n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
secp256r1 = EllipticCurve(__p, __a, __b, (__Gx, __Gy), __n)

__p = 2**384 - 2**128 - 2**96 + 2**32 - 1
__a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC
__b = 0XB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF
__Gx = 0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7
__Gy = 0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F
__n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
secp384r1 = EllipticCurve(__p, __a, __b, (__Gx, __Gy), __n)

__p = 2**521 - 1
__a = 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC
__b = 0x0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00
__Gx = 0x00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66
__Gy = 0x011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650
__n = 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409
secp521r1 = EllipticCurve(__p, __a, __b, (__Gx, __Gy), __n)

SEC_curves = [
    secp160r1,
    secp192k1, secp192r1, secp224k1, secp224r1,
    secp256k1, secp256r1, secp384r1, secp521r1
]
