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

from math import sqrt
import heapq
from typing import NamedTuple, Tuple, Sequence, List

from btclib.numbertheory import mod_inv, mod_sqrt, legendre_symbol

class Point(NamedTuple):
    """ Elliptic curve point
        
    Infinity point in affine coordinates is Point() and
    it can be checked with 'Inf[1] == 0' or 'Inf.y == 0'
    """
    x: int = 1
    y: int = 0 # no affine point has y=0 coordinate

# infinity point in Jacobian coordinates is Inf = (int, int, 0)
# it can be checked with 'Inf[2] == 0'
_JacPoint = Tuple[int, int, int]

def _jac_from_aff(Q: Point) -> _JacPoint:
    # point is assumed to be on curve
    if Q[1] == 0:  # Infinity point in affine coordinates
        return 1, 1, 0
    return Q[0], Q[1], 1


class Curve:
    """ Elliptic curve y^2 = x^3 + a*x + b over Fp group """

    def __init__(self, p: int, a: int, b: int, G: Point, n: int,
                       h: int, t: int, weakness_check: bool = True) -> None:
        """Curve instantiation

        Parameters are checked according to SEC 1 v.2 3.1.1.2.1
        """

        # 1) check that p is an odd prime
        if p % 2 == 0:
            raise ValueError(f"p ({hex(p)}) is not odd")
        # Fermat test will do as _probabilistic_ primality test...
        if not pow(2, p-1, p) == 1:
            raise ValueError(f"p ({hex(p)}) is not prime")

        # 1) check that p has enough bits
        plen = p.bit_length()
        if t != 0:
            t_range = [56, 64, 80, 96, 112, 128, 160, 192, 256]
            if t not in t_range:
                m = f"required security level ({t}) "
                m += f"not in the allowed range {t_range}"
                raise UserWarning(m)
            if plen < t*2:
                m = f"not enough bits ({plen}) for required security level {t}"
                raise UserWarning(m)
        self.t = t

        self.psize = (plen + 7) // 8
        # must be true to break simmetry using quadratic residue
        self.pIsThreeModFour = (p % 4 == 3)
        self._p = p

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
        if len(G) != 2:
            raise ValueError("Generator must a be a tuple[int, int]")
        if not self.is_on_curve(G):
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
        # Inf = mult(self, n, self.G)
        # as the above would be tautologically true
        InfMinusG = mult(self, n-1, self.G)
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
        result = "Curve"
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
        result = "Curve("
        result += f"{hex(self._p)}"
        result += f", {hex(self._a)}, {hex(self._b)}"
        result += f", ({hex(self.G[0])}, {hex(self.G[1])})"
        result += f", {hex(self.n)}"
        result += f", {self.h}"
        result += f", {self.t})"
        return result

    # methods using _p: they would become functions if _p goes public

    def opposite(self, Q: Point) -> Point:
        self.require_on_curve(Q)
        # % self._p is required to account for infinity point, i.e. Q[1]==0
        return Point(Q[0], (self._p - Q[1]) % self._p)

    def _aff_from_jac(self, Q: _JacPoint) -> Point:
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
        self.require_on_curve(Q1)
        self.require_on_curve(Q2)
        # no Jacobian coordinates here as _aff_from_jac would cost 2 mod_inv
        # while _add_aff costs only one mod_inv
        return self._add_aff(Q1, Q2)

    def _add_jac(self, Q: _JacPoint, R: _JacPoint) -> _JacPoint:
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

    def _add_aff(self, Q: Point, R: Point) -> Point:
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

    def require_on_curve(self, Q: Point) -> None:
        if not self.is_on_curve(Q):
            raise ValueError("Point not on curve")

    def is_on_curve(self, Q: Point) -> bool:
        if len(Q) != 2:
            raise ValueError("Point must be a tuple[int, int]")
        if Q[1] == 0:  # Infinity point in affine coordinates
            return True
        if not 0 < Q[1] < self._p: # y cannot be zero
            raise ValueError(f"y-coordinate {hex(Q[1])} not in (0, p)")
        return self._y2(Q[0]) == (Q[1]*Q[1] % self._p)

    # break the y simmetry: even/odd, low/high, or quadratic residue criteria

    def y_odd(self, x: int, odd1even0: int = 1) -> int:
        """return the odd (even) y coordinate associated to x"""
        if odd1even0 not in (0, 1):
            raise ValueError("odd1even0 must be bool or 1/0")
        root = self.y(x)
        # switch even/odd root as needed (XORing the conditions)
        return root if root % 2 == odd1even0 else self._p - root

    def y_low(self, x: int, low1high0: int = 1) -> int:
        """return the low (high) y coordinate associated to x"""
        if low1high0 not in (0, 1):
            raise ValueError("low1high0 must be bool or 1/0")
        root = self.y(x)
        # switch low/high root as needed (XORing the conditions)
        return root if (self._p//2 >= root) == low1high0 else self._p - root

    def y_quadratic_residue(self, x: int, quad_res: int = 1) -> int:
        """return the quadratic residue y coordinate associated to x"""
        if quad_res not in (0, 1):
            raise ValueError("quad_res must be bool or 1/0")
        if not self.pIsThreeModFour:
            raise ValueError("this method works only when p = 3 (mod 4)")
        root = self.y(x)
        # switch to quadratic residue root as needed
        legendre = legendre_symbol(root, self._p)
        return root if legendre == quad_res else self._p - root


def mult(ec: Curve, n: int, Q: Point = None) -> Point:
    # this function is used by the Curve class; it might be a method...
    # but it does not need to
    if Q is None:
        QJ = ec.GJ
    else:
        ec.require_on_curve(Q)
        QJ = _jac_from_aff(Q)
    R = _mult_jac(ec, n, QJ)
    return ec._aff_from_jac(R)


def _mult_aff(ec: Curve, m: int, Q: Point) -> Point:
    # double & add in affine coordinates, using binary decomposition of m
    # Point is assumed to be on curve

    m %= ec.n
    if m == 0 or Q[1] == 0:        # Infinity point in affine coordinates
        return 1, 0                # return Infinity point
    R = 1, 0                       # initialize as infinity point
    while m > 0:                   # use binary representation of m
        if m & 1:                  # if least significant bit is 1
            R = ec._add_aff(R, Q)  # then add current Q
        m = m >> 1                 # remove the bit just accounted for
        Q = ec._add_aff(Q, Q)      # double Q for next step
    return R


def _mult_jac(ec: Curve, m: int, Q: _JacPoint) -> _JacPoint:
    # double & add in Jacobian coordinates, using binary decomposition of m
    # Point is assumed to be on curve

    m %= ec.n
    if m == 0 or Q[2] == 0:        # Infinity point in affine coordinates
        return 1, 1, 0             # return Infinity point
    R = 1, 1, 0                    # initialize as infinity point
    while m > 0:                   # use binary representation of m
        if m & 1:                  # if least significant bit is 1
            R = ec._add_jac(R, Q)  # then add current Q
        m = m >> 1                 # remove the bit just accounted for
        Q = ec._add_jac(Q, Q)      # double Q for next step
    return R


def double_mult(ec: Curve, u: int, H: Point, v: int, Q: Point = None) -> Point:
    """Shamir trick for efficient computation of u*H + v*Q"""

    ec.require_on_curve(H)
    HJ = _jac_from_aff(H)

    if Q is None:
        QJ = ec.GJ
    else:
        ec.require_on_curve(Q)
        QJ = _jac_from_aff(Q)

    R = _double_mult(ec, u, HJ, v, QJ)

    return ec._aff_from_jac(R)


def _double_mult(ec: Curve, u: int, HJ: _JacPoint,
                            v: int, QJ: _JacPoint) -> _JacPoint:

    u %= ec.n
    if u == 0 or HJ[2] == 0:
        return _mult_jac(ec, v, QJ)

    v %= ec.n
    if v == 0 or QJ[2] == 0:
        return _mult_jac(ec, u, HJ)

    R = 1, 1, 0  # initialize as infinity point
    msb = max(u.bit_length(), v.bit_length())
    while msb > 0:
        if u >> (msb - 1):  # checking msb
            R = ec._add_jac(R, HJ)
            u -= pow(2, u.bit_length() - 1)
        if v >> (msb - 1):  # checking msb
            R = ec._add_jac(R, QJ)
            v -= pow(2, v.bit_length() - 1)
        if msb > 1:
            R = ec._add_jac(R, R)
        msb -= 1

    return R


def multi_mult(ec: Curve,
               scalars: Sequence[int],
               Points: Sequence[Point]) -> Point:
    """ Bos-Coster's algorithm """

    if len(scalars) != len(Points):
        errMsg = f"mismatch between scalar length ({len(scalars)}) and "
        errMsg += f"Points length ({len(Points)})"
        raise ValueError(errMsg)
        
    JPoints: List[_JacPoint] = list()
    for P in Points:
        ec.require_on_curve(P)
        JPoints.append(_jac_from_aff(P))

    R = _multi_mult(ec, scalars, JPoints)

    return ec._aff_from_jac(R)


def _multi_mult(ec: Curve,
                scalars: Sequence[int],
                JPoints: Sequence[_JacPoint]) -> _JacPoint:
    # source: https://cr.yp.to/badbatch/boscoster2.py

    x = list(zip([-n for n in scalars], JPoints))
    heapq.heapify(x)
    while len(x) > 1:
        np1 = heapq.heappop(x)
        np2 = heapq.heappop(x)
        n1, p1 = -np1[0], np1[1]
        n2, p2 = -np2[0], np2[1]
        p2 = ec._add_jac(p1, p2)
        n1 -= n2
        if n1 > 0:
            heapq.heappush(x, (-n1, p1))
        heapq.heappush(x, (-n2, p2))
    np1 = heapq.heappop(x)
    n1, p1 = -np1[0], np1[1]
    return _mult_jac(ec, n1, p1)
