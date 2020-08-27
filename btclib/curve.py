#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Elliptic curve classes."""

from math import ceil, sqrt
from typing import Union

from .alias import INF, INFJ, Integer, JacPoint, Point
from .numbertheory import legendre_symbol, mod_inv, mod_sqrt
from .utils import hex_string, int_from_integer

_HEXTHRESHOLD = 0xFFFFFFFF


def _jac_from_aff(Q: Point) -> JacPoint:
    """Return the Jacobian representation of the affine point.

    The input point is assumed to be on curve.
    """
    return Q[0], Q[1], 1 if Q[1] else 0


class CurveGroup:
    """Finite group of the points of an elliptic curve over Fp.

    The elliptic curve is the set of points (x, y)
    that are solutions to a Weierstrass equation y^2 = x^3 + a*x + b,
    with x, y, a, and b in Fp (p being a prime),
    together with a point at infinity INF.
    The constants a, b must satisfy the relationship
    4 a^3 + 27 b^2 ≠ 0.

    The group is defined by the point addition group law.
    """

    def __init__(self, p: Integer, a: Integer, b: Integer) -> None:
        # Parameters are checked according to SEC 1 v.2 3.1.1.2.1

        p = int_from_integer(p)
        a = int_from_integer(a)
        b = int_from_integer(b)

        # 1) check that p is a prime
        # Fermat test will do as _probabilistic_ primality test...
        if p < 2 or p % 2 == 0 or pow(2, p - 1, p) != 1:
            err_msg = "p is not prime: "
            err_msg += f"'{hex_string(p)}'" if p > _HEXTHRESHOLD else f"{p}"
            raise ValueError(err_msg)

        plen = p.bit_length()
        # byte-lenght
        self.psize = ceil(plen / 8)
        # must be true to break simmetry using quadratic residue
        self.pIsThreeModFour = p % 4 == 3
        self.p = p

        # 2. check that a and b are integers in the interval [0, p−1]
        if a < 0:
            raise ValueError(f"negative a: {a}")
        if p <= a:
            err_msg = "p <= a: " + (
                f"'{hex_string(p)}' <= '{hex_string(a)}'"
                if p > _HEXTHRESHOLD
                else f"{p} <= {a}"
            )
            raise ValueError(err_msg)
        if b < 0:
            raise ValueError(f"negative b: {b}")
        if p <= b:
            err_msg = "p <= b: " + (
                f"'{hex_string(p)}' <= '{hex_string(b)}'"
                if p > _HEXTHRESHOLD
                else f"{p} <= {b}"
            )
            raise ValueError(err_msg)

        # 3. Check that 4*a^3 + 27*b^2 ≠ 0 (mod p)
        d = 4 * a * a * a + 27 * b * b
        if d % p == 0:
            raise ValueError("zero discriminant")
        self._a = a
        self._b = b

    def __str__(self) -> str:
        result = "Curve"
        if self.p > _HEXTHRESHOLD:
            result += f"\n p   = {hex_string(self.p)}"
        else:
            result += f"\n p   = {self.p}"

        if self._a > _HEXTHRESHOLD or self._b > _HEXTHRESHOLD:
            result += f"\n a   = {hex_string(self._a)}"
            result += f"\n b   = {hex_string(self._b)}"
        else:
            result += f"\n a   = {self._a}"
            result += f"\n b   = {self._b}"

        return result

    def __repr__(self) -> str:
        result = "Curve("
        result += f"'{hex_string(self.p)}'" if self.p > _HEXTHRESHOLD else f"{self.p}"
        if self._a > _HEXTHRESHOLD or self._b > _HEXTHRESHOLD:
            result += f", '{hex_string(self._a)}', '{hex_string(self._b)}'"
        else:
            result += f", {self._a}, {self._b}"

        result += ")"
        return result

    # methods using p: they could become functions

    def negate(self, Q: Point) -> Point:
        """Return the opposite point.

        The input point is not checked to be on the curve.
        """
        # % self.p is required to account for INF (i.e. Q[1]==0)
        # so that negate(INF) = INF
        if len(Q) == 2:
            return Q[0], (self.p - Q[1]) % self.p
        raise TypeError("not a point")

    def negate_jac(self, Q: JacPoint) -> JacPoint:
        """Return the opposite Jacobian point.

        The input point is not checked to be on the curve.
        """
        # % self.p is required to account for INF (i.e. Q[1]==0)
        # so that negate(INF) = INF
        if len(Q) == 3:
            return Q[0], (self.p - Q[1]) % self.p, Q[2]
        raise TypeError("not a Jacobian point")

    def _aff_from_jac(self, Q: JacPoint) -> Point:
        # point is assumed to be on curve
        if Q[2] == 0:  # Infinity point in Jacobian coordinates
            return INF
        else:
            Z2 = Q[2] * Q[2]
            x = (Q[0] * mod_inv(Z2, self.p)) % self.p
            y = (Q[1] * mod_inv(Z2 * Q[2], self.p)) % self.p
            return x, y

    def _x_aff_from_jac(self, Q: JacPoint) -> int:
        # point is assumed to be on curve
        if Q[2] == 0:  # Infinity point in Jacobian coordinates
            raise ValueError("infinity point has no x-coordinate")
        else:
            Z2 = Q[2] * Q[2]
            return (Q[0] * mod_inv(Z2, self.p)) % self.p

    def _jac_equality(self, QJ: JacPoint, PJ: JacPoint) -> bool:
        """Return True if Jacobian points are equal in affine coordinates.

        The input points are assumed to be on curve.
        """
        PJ2 = PJ[2] * PJ[2]
        QJ2 = QJ[2] * QJ[2]
        if QJ[0] * PJ2 % self.p != PJ[0] * QJ2 % self.p:
            return False
        PJ3 = PJ2 * PJ[2]
        QJ3 = QJ2 * QJ[2]
        return QJ[1] * PJ3 % self.p == PJ[1] * QJ3 % self.p

    # methods using _a, _b, _p

    def add(self, Q1: Point, Q2: Point) -> Point:
        """Return the sum of two points.

        The input points must be on the curve.
        """

        self.require_on_curve(Q1)
        self.require_on_curve(Q2)
        # no Jacobian coordinates here as _aff_from_jac would cost 2 mod_inv
        # while _add_aff costs only one mod_inv
        return self._add_aff(Q1, Q2)

    def _add_jac(self, Q: JacPoint, R: JacPoint) -> JacPoint:
        # points are assumed to be on curve

        if Q[2] == 0:  # Infinity point in Jacobian coordinates
            return R
        if R[2] == 0:  # Infinity point in Jacobian coordinates
            return Q

        RZ2 = R[2] * R[2]
        RZ3 = RZ2 * R[2]
        QZ2 = Q[2] * Q[2]
        QZ3 = QZ2 * Q[2]
        if Q[0] * RZ2 % self.p == R[0] * QZ2 % self.p:  # same affine x
            if Q[1] * RZ3 % self.p == R[1] * QZ3 % self.p:  # point doubling
                QY2 = Q[1] * Q[1]
                W = (3 * Q[0] * Q[0] + self._a * QZ2 * QZ2) % self.p
                V = (4 * Q[0] * QY2) % self.p
                X = (W * W - 2 * V) % self.p
                Y = (W * (V - X) - 8 * QY2 * QY2) % self.p
                Z = (2 * Q[1] * Q[2]) % self.p
                return X, Y, Z
            else:  # opposite points
                return INFJ
        else:
            T = (Q[1] * RZ3) % self.p
            U = (R[1] * QZ3) % self.p
            W = (U - T) % self.p

            M = (Q[0] * RZ2) % self.p
            N = (R[0] * QZ2) % self.p
            V = (N - M) % self.p

            V2 = V * V
            V3 = V2 * V
            MV2 = M * V2
            X = (W * W - V3 - 2 * MV2) % self.p
            Y = (W * (MV2 - X) - T * V3) % self.p
            Z = (V * Q[2] * R[2]) % self.p
            return X, Y, Z

    def _add_aff(self, Q: Point, R: Point) -> Point:
        # points are assumed to be on curve
        if R[1] == 0:  # Infinity point in affine coordinates
            return Q
        if Q[1] == 0:  # Infinity point in affine coordinates
            return R

        if R[0] == Q[0]:
            if R[1] == Q[1]:  # point doubling
                lam = (3 * Q[0] * Q[0] + self._a) * mod_inv(2 * Q[1], self.p)
                lam %= self.p
            else:  # opposite points
                return INF
        else:
            lam = ((R[1] - Q[1]) * mod_inv(R[0] - Q[0], self.p)) % self.p
        x = (lam * lam - Q[0] - R[0]) % self.p
        y = (lam * (Q[0] - x) - Q[1]) % self.p
        return x, y

    def _y2(self, x: int) -> int:
        # skipping a crucial check here:
        # if sqrt(y*y) does not exist, then x is not valid.
        # This is a good reason to keep this method private
        return ((x ** 2 + self._a) * x + self._b) % self.p

    def y(self, x: int) -> int:
        """Return the y coordinate from x, as in (x, y)."""
        if not 0 <= x < self.p:
            err_msg = "x-coordinate not in 0..p-1: "
            err_msg += f"{hex_string(x)}" if x > _HEXTHRESHOLD else f"{x}"
            raise ValueError(err_msg)
        try:
            y2 = self._y2(x)
            return mod_sqrt(y2, self.p)
        except Exception:
            raise ValueError("invalid x-coordinate")

    def require_on_curve(self, Q: Point) -> None:
        """Require the input curve Point to be on the curve.

        An Error is raised if not.
        """
        if not self.is_on_curve(Q):
            raise ValueError("point not on curve")

    def is_on_curve(self, Q: Point) -> bool:
        """Return True if the point is on the curve."""
        if len(Q) != 2:
            raise ValueError("point must be a tuple[int, int]")
        if Q[1] == 0:  # Infinity point in affine coordinates
            return True
        if not 0 < Q[1] < self.p:  # y cannot be zero
            raise ValueError(f"y-coordinate not in 1..p-1: '{hex_string(Q[1])}'")
        return self._y2(Q[0]) == (Q[1] * Q[1] % self.p)

    def has_square_y(self, Q: Union[Point, JacPoint]) -> bool:
        """Return True if the affine y-coordinate is a square.

        The input point is not checked to be on the curve.
        """
        if len(Q) == 2:
            return legendre_symbol(Q[1], self.p) == 1
        if len(Q) == 3:
            # FIXME: do not ignore
            return legendre_symbol(Q[1] * Q[2] % self.p, self.p) == 1  # type: ignore
        raise TypeError("not a point")

    def require_p_ThreeModFour(self) -> None:
        """Require the field prime p to be equal to 3 mod 4.

        An Error is raised if not.
        """
        if not self.pIsThreeModFour:
            m = "field prime is not equal to 3 mod 4: "
            m += f"'{hex_string(self.p)}'" if self.p > _HEXTHRESHOLD else f"{self.p}"
            raise ValueError(m)

    # break the y simmetry: even/odd, low/high, or quadratic residue criteria

    def y_odd(self, x: int, odd1even0: int = 1) -> int:
        """Return the odd/even affine y-coordinate associated to x."""
        if odd1even0 not in (0, 1):
            raise ValueError("odd1even0 must be bool or 1/0")
        root = self.y(x)
        # switch even/odd root as needed (XORing the conditions)
        return root if root % 2 == odd1even0 else self.p - root

    def y_low(self, x: int, low1high0: int = 1) -> int:
        """Return the low/high affine y-coordinate associated to x."""
        if low1high0 not in (0, 1):
            raise ValueError("low1high0 must be bool or 1/0")
        root = self.y(x)
        # switch low/high root as needed (XORing the conditions)
        return root if (self.p // 2 >= root) == low1high0 else self.p - root

    def y_quadratic_residue(self, x: int, quad_res: int = 1) -> int:
        """Return the quadratic residue affine y-coordinate."""
        if quad_res not in (0, 1):
            raise ValueError("quad_res must be bool or 1/0")
        self.require_p_ThreeModFour()
        root = self.y(x)
        # switch to quadratic residue root as needed
        legendre = legendre_symbol(root, self.p)
        return root if legendre == quad_res else self.p - root


def _mult_aff(m: int, Q: Point, ec: CurveGroup) -> Point:
    """Scalar multiplication of a curve point in affine coordinates.

    This implementation uses 'double & add' algorithm,
    binary decomposition of m,
    affine coordinates.
    It is not constant-time.

    The input point is assumed to be on curve,
    m is assumed to have been reduced mod n if appropriate
    (e.g. cyclic groups of order n).
    """

    if m < 0:
        raise ValueError(f"negative m: {hex(m)}")

    # there is not a compelling reason to optimize for INF, even if possible
    # if Q[1] == 0 or m == 0:  # Infinity point, affine coordinates
    #    return INF  # return Infinity point
    R = INF  # initialize as infinity point
    while m > 0:  # use binary representation of m
        if m & 1:  # if least significant bit is 1
            R = ec._add_aff(R, Q)  # then add current Q
        m = m >> 1  # remove the bit just accounted for
        Q = ec._add_aff(Q, Q)  # double Q for next step
    return R


def _mult_jac(m: int, Q: JacPoint, ec: CurveGroup) -> JacPoint:
    """Scalar multiplication of a curve point in Jacobian coordinates.

    This implementation uses 'double & add' algorithm,
    binary decomposition of m,
    affine coordinates.
    It is not constant-time.

    The input point is assumed to be on curve,
    m is assumed to have been reduced mod n if appropriate
    (e.g. cyclic groups of order n).
    """

    if m < 0:
        raise ValueError(f"negative m: {hex(m)}")

    # there is not a compelling reason to optimize for INFJ, even if possible
    # if Q[2] == 1:  # Infinity point, Jacobian coordinates
    #     return INFJ  # return Infinity point
    R = INFJ  # initialize as infinity point
    while m > 0:  # use binary representation of m
        if m & 1:  # if least significant bit is 1
            R = ec._add_jac(R, Q)  # then add current Q
        m = m >> 1  # remove the bit just accounted for
        Q = ec._add_jac(Q, Q)  # double Q for next step
    return R


class CurveSubGroup(CurveGroup):
    "Subgroup of the points of an elliptic curve over Fp generated by G."

    def __init__(self, p: Integer, a: Integer, b: Integer, G: Point) -> None:

        super().__init__(p, a, b)

        # 2. check that xG and yG are integers in the interval [0, p−1]
        # 4. Check that yG^2 = xG^3 + a*xG + b (mod p)
        if len(G) != 2:
            raise ValueError("Generator must a be a sequence[int, int]")
        self.G = (int_from_integer(G[0]), int_from_integer(G[1]))
        if not self.is_on_curve(self.G):
            raise ValueError("Generator is not on the curve")
        self.GJ = self.G[0], self.G[1], 1  # Jacobian coordinates

    def __str__(self) -> str:
        result = super().__str__()
        if self.p > _HEXTHRESHOLD:
            result += f"\n x_G = {hex_string(self.G[0])}"
            result += f"\n y_G = {hex_string(self.G[1])}"
        else:
            result += f"\n x_G = {self.G[0]}"
            result += f"\n y_G = {self.G[1]}"
        return result

    def __repr__(self) -> str:
        result = super().__repr__()[:-1]
        if self.p > _HEXTHRESHOLD:
            result += f", ('{hex_string(self.G[0])}', '{hex_string(self.G[1])}')"
        else:
            result += f", ({self.G[0]}, {self.G[1]})"
        result += ")"
        return result


class Curve(CurveSubGroup):
    "Prime order subgroup of the points of an elliptic curve over Fp."

    def __init__(
        self,
        p: Integer,
        a: Integer,
        b: Integer,
        G: Point,
        n: Integer,
        h: int,
        weakness_check: bool = True,
    ) -> None:

        super().__init__(p, a, b, G)
        n = int_from_integer(n)

        # Security level is expressed in bits, where n-bit security
        # means that the attacker would have to perform 2^n operations
        # to break it. Security bits are half the key size for asymmetric
        # elliptic curve cryptography, i.e. half of the number of bits
        # required to express the group order n or, holding Hasse theorem,
        # to express the field prime p

        self.n = n
        self.nlen = n.bit_length()
        self.nsize = (self.nlen + 7) // 8

        # 5. Check that n is prime.
        if n < 2 or n % 2 == 0 or pow(2, n - 1, n) != 1:
            err_msg = "n is not prime: "
            err_msg += f"{hex_string(n)}" if n > _HEXTHRESHOLD else f"{n}"
            raise ValueError(err_msg)
        delta = int(2 * sqrt(self.p))
        # also check n with Hasse Theorem
        if h < 2:
            if not (self.p + 1 - delta <= n <= self.p + 1 + delta):
                err_msg = "n not in p+1-delta..p+1+delta: "
                err_msg += f"{hex_string(n)}" if n > _HEXTHRESHOLD else f"{n}"
                raise ValueError(err_msg)

        # 7. Check that G ≠ INF, nG = INF
        if self.G[1] == 0:
            m = "INF point cannot be a generator"
            raise ValueError(m)
        Inf = _mult_aff(n, self.G, self)
        if Inf[1] != 0:
            err_msg = "n is not the group order: "
            err_msg += f"{hex_string(n)}" if n > _HEXTHRESHOLD else f"{n}"
            raise ValueError(err_msg)

        # 6. Check cofactor
        exp_h = int(1 / n + delta / n + self.p / n)
        if h != exp_h:
            raise ValueError(f"invalid h: {h}, expected {exp_h}")
        self.h = h

        # 8. Check that n ≠ p
        assert n != p, f"n=p weak curve: {hex_string(n)}"
        #    raise UserWarning("n=p -> weak curve")

        if weakness_check:
            # 8. Check that p^i % n ≠ 1 for all 1≤i<100
            for i in range(1, 100):
                if pow(self.p, i, n) == 1:
                    raise UserWarning("weak curve")

    def __str__(self) -> str:
        result = super().__str__()
        if self.n > _HEXTHRESHOLD:
            result += f"\n n   = {hex_string(self.n)}"
        else:
            result += f"\n n   = {self.n}"
        result += f"\n h = {self.h}"
        return result

    def __repr__(self) -> str:
        result = super().__repr__()[:-1]
        if self.n > _HEXTHRESHOLD:
            result += f", '{hex_string(self.n)}'"
        else:
            result += f", {self.n}"
        result += f", {self.h}"
        result += ")"
        return result
