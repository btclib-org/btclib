#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""
Elliptic curve class, functions, and instances of SEC2 elliptic curves

TODO: document duck-typing and static typing design choices
"""

from hashlib import sha256
from math import sqrt
from typing import Tuple

from btclib.numbertheory import mod_inv, mod_sqrt, legendre_symbol

# infinity point is (int, 0), checked with 'Inf[1] == 0'
Point = Tuple[int, int]

# infinity point is (int, int, 0), checked with 'Inf[2] == 0'
_JacPoint = Tuple[int, int, int]


# elliptic curve y^2 = x^3 + a*x + b


class EC:
    """Elliptic curve over Fp group"""

    def __init__(self, p: int, a: int, b: int, G: Point, n: int,
                 all_checks = True) -> None:
        """EC instantiation

        Parameters are checked according to SEC2 3.1.1.2.1
        """

        # 1) check that p is an odd prime
        if p % 2 == 0:
            raise ValueError("p (%s) is not odd" % p)
        # Fermat test will do as _probabilistic_ primality test...
        if not pow(2, p-1, p) == 1:
            raise ValueError("p (%s) is not prime" % p)

        if all_checks:
            # the security level in bits 't' should be an input
            # and required_bits should be checked accordingly
            #
            # for the time being just check bits are in required standards
            #           t = { 80, 112, 128, 192, 256}
            required_bits = [192, 224, 256, 384, 521]
            nbits = p.bit_length()
            if all_checks and not (nbits in required_bits):
                raise UserWarning("wrong number of bits (%s)" % nbits)

        self._p = p
        self.bytesize = (p.bit_length() + 7) // 8  # FIXME: p or n
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
        # 4. Check that yG^2 = xG^3 + a*xG + b (mod p).
        if len(G) != 2:
            raise ValueError("Generator must a be a Tuple[int, int]")
        if not self.isOnCurve(G):
            raise ValueError("Generator is not on the 'x^3 + a*x + b' curve")
        self.G = int(G[0]), int(G[1])

        # 5. Check that n is prime.
        if n < 2 or (n > 2 and not pow(2, n-1, n) == 1):
            raise ValueError("n (%s) is not prime" % n)
        # also check n with Hasse Theorem
        if all_checks:
            t = int(2 * sqrt(p))
            if not (p+1 - t <= n <= p+1 + t):
                raise ValueError("n (%s) not in [p+1 - t, p+1 + t]" % n)
        self.n = n

        # 6. Check cofactor
        # missing for the time being

        # 7. Check that nG = Inf.
        # it cannot be chacked as
        # Inf = pointMult(self, n, self.G)
        # the above would be tautologically true
        InfMinusG = pointMult(self, n-1, self.G)
        Inf = self.add(InfMinusG, self.G)
        if Inf[1] != 0:
            raise ValueError("n (%s) is not the group order" % n)

        # 8. Check that n ≠ p
        if n == p:
            raise UserWarning("n=p -> weak curve")
        if all_checks:
            # 8. Check that p^i % n ≠ 1 for all 1≤i<100
            for i in (1, 100):
                if pow(p, i, n) == 1:
                    raise UserWarning("weak curve")

    def __str__(self) -> str:
        result = "EC"
        result += "\n p = 0x%032x" % (self._p)
        result += "\n a = %s, b = %s" % (self._a, self._b)
        result += "\n G = (0x%032x,\n          0x%032x)" % (self.G)
        result += "\n n = 0x%032x" % (self.n)
        return result

    def __repr__(self) -> str:
        result = "EC("
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

    def opposite(self, Q: Point) -> Point:
        self.requireOnCurve(Q)
        if Q[1] == 0:  # Infinity point in affine coordinates
            return Q
        else:
            return Q[0], self._p - Q[1]

    def _affine_from_jac(self, Q: _JacPoint) -> Point:
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

    def _addJacobian(self, Q: _JacPoint, R: _JacPoint) -> _JacPoint:
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

    def _addAffine(self, Q: Point, R: Point) -> Point:
        # private method does not check for Q, R on curve
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

    def add(self, Q1: Point, Q2: Point) -> Point:
        self.requireOnCurve(Q1)
        self.requireOnCurve(Q2)
        QJ1 = _jac_from_aff(Q1)
        QJ2 = _jac_from_aff(Q2)
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

    def requireOnCurve(self, Q: Point) -> None:
        if not self.isOnCurve(Q):
            raise ValueError("Point not on curve")

    def isOnCurve(self, Q: Point) -> bool:
        if not isinstance(Q, tuple):
            raise ValueError("Point must be a tuple[int, int]")
        if len(Q) != 2:
            raise ValueError("Point must be a tuple[int, int]")
        if Q[1] == 0:  # Infinity point in affine coordinates
            return True
        self.checkCoordinate(Q[1])
        return self._y2(Q[0]) == (Q[1]*Q[1] % self._p)

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



# this function is used by the EC class; it might be a method...


def _jac_from_aff(Q: Point) -> _JacPoint:
    # private method does not check for Q on curve
    if Q[1] == 0:  # Infinity point in affine coordinates
        return 1, 1, 0
    return Q[0], Q[1], 1


# this function is used by the EC class; it might be a method...


def pointMult(ec: EC, n: int, Q: Point) -> Point:
    ec.requireOnCurve(Q)
    QJ = _jac_from_aff(Q)
    R = _pointMultJacobian(ec, n, QJ)
    return ec._affine_from_jac(R)


def _pointMultAffine(ec: EC, n: int, Q: Point) -> Point:
    """double & add in affine coordinates, using binary decomposition of n"""
    # private method does not check input
    n %= ec.n #FIXME: remove
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


def _pointMultJacobian(ec: EC, n: int, Q: _JacPoint) -> _JacPoint:
    """double & add in jacobian coordinates, using binary decomposition of n"""
    # private method does not check input
    n %= ec.n #FIXME: remove
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


def DblScalarMult(ec: EC, u: int, Q: Point, v: int, P: Point) -> Point:
    """Shamir trick for efficient computation of u*Q + v*P"""

    if u == 0:
        if v == 0:
            return 1, 0
        ec.requireOnCurve(P)
        PJ = _jac_from_aff(P)
        v %= ec.n
        R = _pointMultJacobian(ec, v, PJ)
        return ec._affine_from_jac(R)

    ec.requireOnCurve(Q)
    if Q[1] == 0:
        ec.requireOnCurve(P)
        PJ = _jac_from_aff(P)
        v %= ec.n
        R = _pointMultJacobian(ec, v, PJ)
        return ec._affine_from_jac(R)

    u %= ec.n
    QJ = _jac_from_aff(Q)

    if v == 0:
        R = _pointMultJacobian(ec, u, QJ)
        return ec._affine_from_jac(R)

    ec.requireOnCurve(P)
    if P[1] == 0:
        R = _pointMultJacobian(ec, u, QJ)
        return ec._affine_from_jac(R)

    v %= ec.n
    PJ = _jac_from_aff(P)

    R = 1, 1, 0  # initialize as infinity point
    msb = max(u.bit_length(), v.bit_length())
    while msb > 0:
        if u >> (msb - 1):  # checking msb
            R = ec._addJacobian(R, QJ)
            u -= pow(2, u.bit_length() - 1)
        if v >> (msb - 1):  # checking msb
            R = ec._addJacobian(R, PJ)
            v -= pow(2, v.bit_length() - 1)
        if msb > 1:
            R = ec._addJacobian(R, R)
        msb -= 1

    return ec._affine_from_jac(R)
