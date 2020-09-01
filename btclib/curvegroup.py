#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Elliptic CurveGroup class and functions.

Note that CurveGroup does not have to be a cyclic subgroup.
For the cyclic subgroup class CurveSubGroup and
the cyclic subgroup class of prime order Curve,
see the btclib.curve module.
"""

import heapq
from math import ceil
from typing import List, Sequence, Tuple, Union

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
            x = Q[0] * mod_inv(Z2, self.p)
            y = Q[1] * mod_inv(Z2 * Q[2], self.p)
            return x % self.p, y % self.p

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

        # to have this funtion constant time,
        # Q or R equal to INFJ is not handled has a special case here
        # but it taken care of at the end,
        # after having performed all calculation, even if useless

        RZ2 = R[2] * R[2]
        RZ3 = RZ2 * R[2]
        QZ2 = Q[2] * Q[2]
        QZ3 = QZ2 * Q[2]

        M = Q[0] * RZ2
        N = R[0] * QZ2

        T = Q[1] * RZ3
        U = R[1] * QZ3

        # FIXME: it would be better if doubling was not a special case
        if M % self.p == N % self.p:  # same affine x
            if T % self.p == U % self.p:  # point doubling
                QY2 = Q[1] * Q[1]
                W = 3 * Q[0] * Q[0] + self._a * QZ2 * QZ2
                V = 4 * Q[0] * QY2
                X = W * W - 2 * V
                Y = W * (V - X) - 8 * QY2 * QY2
                Z = 2 * Q[1] * Q[2]
                return X % self.p, Y % self.p, Z % self.p

        W = U - T
        V = N - M

        V2 = V * V
        V3 = V2 * V
        MV2 = M * V2

        X = (W * W - V3 - 2 * MV2) % self.p
        Y = (W * (MV2 - X) - T * V3) % self.p
        Z = (V * Q[2] * R[2]) % self.p

        # Z is zero if Q or R are equal to INFJ,
        # so (X, Y, Z) is INFJ instead of being R or Q (respectively)
        # let's fix it

        # possible return values are:
        ret_values = [(X, Y, Z), R, Q, INFJ]
        #      Q==INFJ  +    R==INFJ  * 2
        #            0  +          0  * 2 = 0 → (X, Y, Z)
        #            1  +          0  * 2 = 1 → R
        #            0  +          1  * 2 = 2 → Q
        #            1  +          1  * 2 = 3 → INFJ
        i = (Q[2] == 0) + (R[2] == 0) * 2
        return ret_values[i]

    def _double_jac(self, Q: JacPoint) -> JacPoint:
        # point is assumed to be on curve

        QZ2 = Q[2] * Q[2]
        QY2 = Q[1] * Q[1]
        W = 3 * Q[0] * Q[0] + self._a * QZ2 * QZ2
        V = 4 * Q[0] * QY2
        X = W * W - 2 * V
        Y = W * (V - X) - 8 * QY2 * QY2
        Z = 2 * Q[1] * Q[2]
        return X % self.p, Y % self.p, Z % self.p

    def _add_aff(self, Q: Point, R: Point) -> Point:
        # points are assumed to be on curve

        # FIXME: it would be better if INF handling was not a special case
        if R[1] == 0:  # Infinity point in affine coordinates
            return Q
        if Q[1] == 0:  # Infinity point in affine coordinates
            return R

        # FIXME: it would be better if doubling was checked before INF handling
        if R[0] == Q[0]:
            if R[1] == Q[1]:  # point doubling
                return self._double_aff(R)
            else:  # opposite points
                return INF

        lam = (R[1] - Q[1]) * mod_inv(R[0] - Q[0], self.p)
        x = lam * lam - Q[0] - R[0]
        y = lam * (Q[0] - x) - Q[1]
        return x % self.p, y % self.p

    def _double_aff(self, Q: Point) -> Point:
        # point is assumed to be on curve

        if Q[1] == 0:  # Infinity point in affine coordinates
            return INF

        lam = (3 * Q[0] * Q[0] + self._a) * mod_inv(2 * Q[1], self.p)
        x = lam * lam - Q[0] - Q[0]
        y = lam * (Q[0] - x) - Q[1]
        return x % self.p, y % self.p

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

    This implementation uses
    'double & add' algorithm,
    'right-to-left' binary decomposition of the m coefficient,
    affine coordinates.

    The input point is assumed to be on curve and
    the m coefficient is assumed to have been reduced mod n
    if appropriate (e.g. cyclic groups of order n).
    """

    if m < 0:
        raise ValueError(f"negative m: {hex(m)}")

    # R[0] is the running result, R[1] = R[0] + Q is an ancillary variable
    R = [INF, Q]
    # if least significant bit of m is 1, then add Q to R[0]
    R[0] = R[m & 1]
    # remove the bit just accounted for
    m >>= 1
    while m > 0:
        # the doubling part of 'double & add'
        Q = ec._double_aff(Q)
        # always perform the 'add', even if useless, to be constant-time
        R[1] = ec._add_aff(R[0], Q)
        # if least significant bit of m is 1, then add Q to R[0]
        R[0] = R[m & 1]
        m >>= 1
    return R[0]


def _mult_jac(m: int, Q: JacPoint, ec: CurveGroup) -> JacPoint:
    """Scalar multiplication of a curve point in Jacobian coordinates.

    This implementation uses
    'double & add' algorithm,
    'right-to-left' binary decomposition of the m coefficient,
    Jacobian coordinates.

    The input point is assumed to be on curve and
    the m coefficient is assumed to have been reduced mod n
    if appropriate (e.g. cyclic groups of order n).
    """

    if m < 0:
        raise ValueError(f"negative m: {hex(m)}")

    # R[0] is the running result, R[1] = R[0] + Q is an ancillary variable
    R = [INFJ, Q]
    # if least significant bit of m is 1, then add Q to R[0]
    R[not (m & 1)] = Q
    # remove the bit just accounted for
    m >>= 1
    while m > 0:
        # the doubling part of 'double & add'
        Q = ec._double_jac(Q)
        # always perform the 'add', even if useless, to be constant-time
        # if least significant bit of m is 1, then add Q to R[0]
        R[not (m & 1)] = ec._add_jac(R[0], Q)
        m >>= 1
    return R[0]


_mult = _mult_jac


def _double_mult(
    u: int, HJ: JacPoint, v: int, QJ: JacPoint, ec: CurveGroup
) -> JacPoint:
    """Double scalar multiplication (u*H + v*Q).

    This implementation uses the Shamir-Strauss algorithm,
    'left-to-right' binary decomposition of the u and v coefficients,
    Jacobian coordinates.

    Strauss algorithm consists of a single 'double & add' loop
    for the parallel calculation of u*H and v*Q, efficiently
    using a single 'doubling' for both scalar multiplications (see
    https://stackoverflow.com/questions/50993471/ec-scalar-multiplication-with-strauss-shamir-method).

    The Shamir trick adds the precomputation of H+Q,
    which is to be added in the loop when the binary digits
    of u and v are both equal to 1 (on average 1/4 of the cases).

    The input points are assumed to be on curve,
    the u and v coefficients are assumed to have been reduced mod n
    if appropriate (e.g. cyclic groups of order n).
    """

    if u < 0:
        raise ValueError(f"negative first coefficient: {hex(u)}")
    if v < 0:
        raise ValueError(f"negative second coefficient: {hex(v)}")

    # at each step one of the following points will be added
    T = [INFJ, HJ, QJ, ec._add_jac(HJ, QJ)]
    # which one depends on binary digit for that step
    ui = bin(u)[2:]
    vi = bin(v)[2:].zfill(len(ui))
    ui = ui.zfill(len(vi))
    digits = [int(j) + 2 * int(k) for j, k in zip(ui, vi)]
    # R[0] is the running result, R[1] = R[0] + T[*] is an ancillary variable
    R = T[digits[0]]
    for i in digits[1:]:
        # the doubling part of 'double & add'
        R = ec._double_jac(R)
        # always perform the 'add', even if useless, to be constant-time
        # 'add' it to R[0] only if appropriate
        R = ec._add_jac(R, T[i])
    return R


def _multi_mult(
    scalars: Sequence[int], JPoints: Sequence[JacPoint], ec: CurveGroup
) -> JacPoint:
    """Return the multi scalar multiplication u1*Q1 + ... + un*Qn.

    Use Bos-Coster's algorithm for efficient computation.

    The input points are assumed to be on curve,
    the scalar coefficients are assumed to have been reduced mod n
    if appropriate (e.g. cyclic groups of order n).
    """
    # source: https://cr.yp.to/badbatch/boscoster2.py

    if len(scalars) != len(JPoints):
        errMsg = "mismatch between number of scalars and points: "
        errMsg += f"{len(scalars)} vs {len(JPoints)}"
        raise ValueError(errMsg)

    # x = list(zip([-n for n in scalars], JPoints))
    x: List[Tuple[int, JacPoint]] = []
    for n, PJ in zip(scalars, JPoints):
        if n == 0:  # mandatory check to avoid infinite loop
            continue
        if n < 0:
            raise ValueError(f"negative coefficient: {hex(n)}")
        x.append((-n, PJ))

    if not x:
        return INFJ

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
    # assert n1 < ec.n, "better to take the mod n"
    # n1 %= ec.n
    return _mult(n1, p1, ec)
