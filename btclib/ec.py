#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""
Elliptic curve class and functions

TODO: document duck-typing and static typing design choices
"""

from hashlib import sha256
from math import sqrt
import heapq
from typing import NamedTuple, Tuple, Sequence, List

from btclib.numbertheory import mod_inv, mod_sqrt, legendre_symbol

class Point(NamedTuple):
    """ Elliptic curve point
        
        Infinity point in affine coordinates is Inf = Point() and
        it can be checked with 'Inf[1] == 0' or 'Inf.y == 0'
    """
    x: int = 1
    y: int = 0

# infinity point in Jacobian coordinates is Inf = (int, int, 0)
# it can be checked with 'Inf[2] == 0'
_JacPoint = Tuple[int, int, int]

def _jac_from_aff(Q: Point) -> _JacPoint:
    # point is assumed to be on curve
    if Q[1] == 0:  # Infinity point in affine coordinates
        return 1, 1, 0
    return Q[0], Q[1], 1


class EC:
    """Elliptic curve y^2 = x^3 + a*x + b over Fp group"""

    def __init__(self, p: int, a: int, b: int, G: Point, n: int,
                       h: int, t: int, weakness_check: bool = True) -> None:
        """EC instantiation

        Parameters are checked according to SEC 1 v.2 3.1.1.2.1
        """

        # first off discriminate invalid (..., Gx, Gy, ...) input
        if len(G) != 2:
            raise ValueError("Generator must a be a Tuple[int, int]")

        # 1) check that p is an odd prime
        if p % 2 == 0:
            raise ValueError(f"p ({hex(p)}) is not odd")
        # Fermat test will do as _probabilistic_ primality test...
        if not pow(2, p-1, p) == 1:
            raise ValueError(f"p ({hex(p)}) is not prime")

        # 1) check that p has enough bits
        plen = p.bit_length()
        self.t = t
        if t != 0:
            t_range = [56, 64, 80, 96, 112, 128, 160, 192, 256]
            if t not in t_range:
                m = f"required security level ({t}) "
                m += f"not in the allowed range {t_range}"
                raise UserWarning(m)
            if plen < t*2:
                m = f"not enough bits ({plen}) for required security level {t}"
                raise UserWarning(m)

        self._p = p
        self.psize = (plen + 7) // 8
        # must be true to break simmetry using quadratic residue
        self.pIsThreeModFour = (self._p % 4 == 3)

        # 2. check that a and b are integers in the interval [0, p−1]
        if not 0 <= a < p:
            raise ValueError(f"invalid a ({hex(a)}) for given p ({hex(p)})")
        if not 0 <= b < p:
            raise ValueError(f"invalid b ({hex(b)}) for given p ({hex(p)})")

        # 3. Check that 4*a^3 + 27*b^2 ≠ 0 (mod p).
        d = 4*a*a*a+27*b*b
        if d % p == 0:
            raise ValueError("zero discriminant")
        self._a = a
        self._b = b

        # 2. check that xG and yG are integers in the interval [0, p−1]
        # 4. Check that yG^2 = xG^3 + a*xG + b (mod p).
        if not self.isOnCurve(G):
            raise ValueError("Generator is not on the 'x^3 + a*x + b' curve")
        self.G = Point(int(G[0]), int(G[1]))
        self.GJ = self.G[0], self.G[1], 1  # Jacobian coordinates

        # 5. Check that n is prime.
        if n < 2 or (n > 2 and not pow(2, n-1, n) == 1):
            raise ValueError(f"n ({hex(n)}) is not prime")
        delta = int(2 * sqrt(p))
        # also check n with Hasse Theorem
        if h < 2:
            if not (p + 1 - delta <= n <= p + 1 + delta):
                m = f"n ({hex(n)}) not in [p + 1 - delta, p + 1 + delta]"
                raise ValueError(m)
        self.n = n
        self.nlen = n.bit_length()
        self.nsize = (self.nlen + 7) // 8

        # 6. Check cofactor
        exp_h = int(1/n + delta/n + p/n)
        if h != exp_h:
            raise ValueError(f"h ({h}) not as expected ({exp_h})")
        assert t == 0 or h <= pow(2, t/8), f"h ({h}) too big for t ({t})"
        self.h = h

        # 7. Check that nG = Inf.
        # it cannot be simply checked with:
        # Inf = pointMult(self, n, self.G)
        # as the above would be tautologically true
        InfMinusG = pointMult(self, n-1, self.G)
        Inf = self.add(InfMinusG, self.G)
        if Inf[1] != 0:
            raise ValueError(f"n ({hex(n)}) is not the group order")

        # 8. Check that n ≠ p
        assert n != p, f"n=p ({hex(n)}) -> weak curve"
        #    raise UserWarning("n=p -> weak curve")
        if weakness_check:
            # 8. Check that p^i % n ≠ 1 for all 1≤i<100
            for i in range(1, 100):
                if pow(p, i, n) == 1:
                    raise UserWarning("weak curve")

    def __str__(self) -> str:
        result = "EC"
        result += f"\n p   = {hex(self._p)}"
        result += f"\n a   = {hex(self._a)}"
        result += f"\n b   = {hex(self._b)}"
        result += f"\n G.x = {hex(self.G[0])}"
        result += f"\n G.y = {hex(self.G[1])}"
        result += f"\n n   = {hex(self.n)}"
        result += f"\n h = {self.h}"
        result += f"\n t = {self.t}"
        return result

    def __repr__(self) -> str:
        result = "EC("
        result += f"{hex(self._p)}"
        result += f", {hex(self._a)}, {hex(self._b)}"
        result += f", ({hex(self.G[0])}, {hex(self.G[1])})"
        result += f", {hex(self.n)}"
        result += f", {self.h}"
        result += f", {self.t})"
        return result

    # methods using _p: they would become functions if _p goes public

    def opposite(self, Q: Point) -> Point:
        self.requireOnCurve(Q)
        # % self._p is required to account for infinity point, i.e. Q[1]==0
        return Point(Q[0], (self._p - Q[1]) % self._p)

    def _affine_from_jac(self, Q: _JacPoint) -> Point:
        # point is assumed to be on curve
        if Q[2] == 0:  # Infinity point in Jacobian coordinates
            return Point()
        else:
            Z2 = Q[2]*Q[2]
            x = (Q[0]*mod_inv(Z2, self._p)) % self._p
            y = (Q[1]*mod_inv(Z2*Q[2], self._p)) % self._p
            return Point(x, y)

    # methods using _a, _b, _p

    def add(self, Q1: Point, Q2: Point) -> Point:
        self.requireOnCurve(Q1)
        QJ1 = _jac_from_aff(Q1)
        self.requireOnCurve(Q2)
        QJ2 = _jac_from_aff(Q2)
        R = self._addJacobian(QJ1, QJ2)
        return self._affine_from_jac(R)

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
        if Q[0]*RZ2 % self._p == R[0]*QZ2 % self._p:      # same affine x
            if Q[1]*RZ3 % self._p == R[1]*QZ3 % self._p:  # point doubling
                QY2 = Q[1]*Q[1]
                W = (3*Q[0]*Q[0] + self._a*QZ2*QZ2) % self._p
                V = (4*Q[0]*QY2) % self._p
                X = (W*W - 2*V) % self._p
                Y = (W*(V - X) - 8*QY2*QY2) % self._p
                Z = (2*Q[1]*Q[2]) % self._p
                return X, Y, Z
            else:                                         # opposite points
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
        # points are assumed to be on curve
        if R[1] == 0:  # Infinity point in affine coordinates
            return Q
        if Q[1] == 0:  # Infinity point in affine coordinates
            return R

        if R[0] == Q[0]:
            if R[1] == Q[1]:  # point doubling
                lam = (3 * Q[0] * Q[0] + self._a) * mod_inv(2 * Q[1], self._p)
                lam %= self._p
            else:             # opposite points
                return Point()
        else:
            lam = ((R[1]-Q[1]) * mod_inv(R[0]-Q[0], self._p)) % self._p
        x = (lam * lam - Q[0] - R[0]) % self._p
        y = (lam * (Q[0] - x) - Q[1]) % self._p
        return Point(x, y)

    def _y2(self, x: int) -> int:
        # skipping a crucial check here:
        # if sqrt(y*y) does not exist, then x is not valid.
        # This is a good reason to keep this method private
        return ((x*x + self._a)*x + self._b) % self._p

    def y(self, x: int) -> int:
        if not 0 <= x < self._p:
            raise ValueError(f"x-coordinate {hex(x)} not in [0, p-1]")
        y2 = self._y2(x)
        # mod_sqrt will raise a ValueError if root does not exist
        return mod_sqrt(y2, self._p)

    def requireOnCurve(self, Q: Point) -> None:
        if not self.isOnCurve(Q):
            raise ValueError("Point not on curve")

    def isOnCurve(self, Q: Point) -> bool:
        if len(Q) != 2:
            raise ValueError("Point must be a tuple[int, int]")
        if Q[1] == 0:  # Infinity point in affine coordinates
            return True
        if not 0 < Q[1] < self._p: # y cannot be zero
            raise ValueError(f"y-coordinate {hex(Q[1])} not in (0, p)")
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
        # switch to quadratic residue root as needed
        legendre1 = legendre_symbol(root, self._p)
        return root if legendre1 == quadRes else self._p - root


def pointMult(ec: EC, n: int, Q: Point) -> Point:
    # this function is used by the EC class; it might be a method...
    # but it does not need to
    ec.requireOnCurve(Q)
    QJ = _jac_from_aff(Q)
    R = _pointMultJacobian(ec, n, QJ)
    return ec._affine_from_jac(R)


def _pointMultAffine(ec: EC, n: int, Q: Point) -> Point:
    # double & add in affine coordinates, using binary decomposition of n
    # Point is assumed to be on curve

    n %= ec.n
    if Q[1] == 0:                    # Infinity point in affine coordinates
        return Q
    R = Point()                      # initialize as infinity point
    while n > 0:                     # use binary representation of n
        if n & 1:                    # if least significant bit is 1
            R = ec._addAffine(R, Q)  # then add current Q
        n = n >> 1                   # remove the bit just accounted for
        Q = ec._addAffine(Q, Q)      # double Q for next step
    return R


def _pointMultJacobian(ec: EC, n: int, Q: _JacPoint) -> _JacPoint:
    # double & add in Jacobian coordinates, using binary decomposition of n
    # Point is assumed to be on curve

    n %= ec.n
    if Q[2] == 0:                      # Infinity point in Jacobian coordinates
        return 1, 1, 0
    R = 1, 1, 0                        # initialize as infinity point
    while n > 0:                       # use binary representation of n
        if n & 1:                      # if least significant bit is 1
            R = ec._addJacobian(R, Q)  # then add current Q
        n = n >> 1                     # remove the bit just accounted for
        Q = ec._addJacobian(Q, Q)      # double Q for next step
    return R


def DblScalarMult(ec: EC, u: int, Q: Point, v: int, P: Point) -> Point:
    """Shamir trick for efficient computation of u*Q + v*P"""

    ec.requireOnCurve(Q)
    QJ = _jac_from_aff(Q)

    ec.requireOnCurve(P)
    PJ = _jac_from_aff(P)

    R = _DblScalarMult(ec, u, QJ, v, PJ)

    return ec._affine_from_jac(R)


def _DblScalarMult(ec: EC, u: int, QJ: _JacPoint,
                           v: int, PJ: _JacPoint) -> _JacPoint:

    u %= ec.n
    if u == 0 or QJ[2] == 0:
        return _pointMultJacobian(ec, v, PJ)

    v %= ec.n
    if v == 0 or PJ[2] == 0:
        return _pointMultJacobian(ec, u, QJ)

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

    return R


def multiScalarMult(ec: EC, scalars: Sequence[int],
                            Points: Sequence[Point]) -> Point:
    """ Bos-Coster's algorithm """

    if len(scalars) != len(Points):
        errMsg = f"mismatch between scalar length ({len(scalars)}) and "
        errMsg += f"Points length ({len(Points)})"
        raise ValueError(errMsg)
        
    JPoints: List[_JacPoint] = list()
    for P in Points:
        ec.requireOnCurve(P)
        JPoints.append(_jac_from_aff(P))

    R = _multiScalarMult(ec, scalars, JPoints)

    return ec._affine_from_jac(R)


def _multiScalarMult(ec: EC, scalars: Sequence[int],
                             JPoints: Sequence[_JacPoint]) -> _JacPoint:
    # source: https://cr.yp.to/badbatch/boscoster2.py

    x = list(zip([-n for n in scalars], JPoints))
    heapq.heapify(x)
    while len(x) > 1:
        np1 = heapq.heappop(x)
        np2 = heapq.heappop(x)
        n1, p1 = -np1[0], np1[1]
        n2, p2 = -np2[0], np2[1]
        p2 = ec._addJacobian(p1, p2)
        n1 -= n2
        if n1 > 0:
            heapq.heappush(x, (-n1, p1))
        heapq.heappush(x, (-n2, p2))
    np1 = heapq.heappop(x)
    n1, p1 = -np1[0], np1[1]
    return _pointMultJacobian(ec, n1, p1)
