#!/usr/bin/env python3

# Copyright (C) 2017-2021 The btclib developers
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

import functools
import heapq
from math import ceil
from typing import List, Sequence, Tuple

from btclib.alias import INF, INFJ, Integer, JacPoint, Point
from btclib.ecc.number_theory import legendre_symbol, mod_inv, mod_sqrt
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.utils import hex_string, int_from_integer

HEX_THRESHOLD = 0xFFFFFFFF


def jac_from_aff(Q: Point) -> JacPoint:
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
            err_msg += f"'{hex_string(p)}'" if p > HEX_THRESHOLD else f"{p}"
            raise BTClibValueError(err_msg)

        plen = p.bit_length()
        # byte-length
        self.p_size = ceil(plen / 8)
        # must be true to break simmetry using quadratic residue
        self.p_is_3_mod_4 = p % 4 == 3
        self.p = p

        # 2. check that a and b are integers in the interval [0, p−1]
        if a < 0:
            raise BTClibValueError(f"negative a: {a}")
        if p <= a:
            err_msg = "p <= a: " + (
                f"'{hex_string(p)}' <= '{hex_string(a)}'"
                if p > HEX_THRESHOLD
                else f"{p} <= {a}"
            )
            raise BTClibValueError(err_msg)
        if b < 0:
            raise BTClibValueError(f"negative b: {b}")
        if p <= b:
            err_msg = "p <= b: " + (
                f"'{hex_string(p)}' <= '{hex_string(b)}'"
                if p > HEX_THRESHOLD
                else f"{p} <= {b}"
            )
            raise BTClibValueError(err_msg)

        # 3. Check that 4*a^3 + 27*b^2 ≠ 0 (mod p)
        d = 4 * a * a * a + 27 * b * b
        if d % p == 0:
            raise BTClibValueError("zero discriminant")
        self._a = a
        self._b = b

    def __str__(self) -> str:
        result = "Curve"
        if self.p > HEX_THRESHOLD:
            result += f"\n p   = {hex_string(self.p)}"
        else:
            result += f"\n p   = {self.p}"

        if self._a > HEX_THRESHOLD or self._b > HEX_THRESHOLD:
            result += f"\n a   = {hex_string(self._a)}"
            result += f"\n b   = {hex_string(self._b)}"
        else:
            result += f"\n a   = {self._a}"
            result += f"\n b   = {self._b}"

        return result

    def __repr__(self) -> str:
        result = "Curve("
        result += f"'{hex_string(self.p)}'" if self.p > HEX_THRESHOLD else f"{self.p}"
        if self._a > HEX_THRESHOLD or self._b > HEX_THRESHOLD:
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
        raise BTClibTypeError("not a point")

    def negate_jac(self, Q: JacPoint) -> JacPoint:
        """Return the opposite Jacobian point.

        The input point is not checked to be on the curve.
        """
        # % self.p is required to account for INF (i.e. Q[1]==0)
        # so that negate(INF) = INF
        if len(Q) == 3:
            return Q[0], (self.p - Q[1]) % self.p, Q[2]
        raise BTClibTypeError("not a Jacobian point")

    def aff_from_jac(self, Q: JacPoint) -> Point:
        # point is assumed to be on curve
        if Q[2] == 0:  # Infinity point in Jacobian coordinates
            return INF

        Z2 = Q[2] * Q[2]
        x = Q[0] * mod_inv(Z2, self.p)
        y = Q[1] * mod_inv(Z2 * Q[2], self.p)
        return x % self.p, y % self.p

    def x_aff_from_jac(self, Q: JacPoint) -> int:
        # point is assumed to be on curve
        if Q[2] == 0:  # Infinity point in Jacobian coordinates
            raise BTClibValueError("INF has no x-coordinate")

        Z2 = Q[2] * Q[2]
        return (Q[0] * mod_inv(Z2, self.p)) % self.p

    def y_aff_from_jac(self, Q: JacPoint) -> int:
        # point is assumed to be on curve
        if Q[2] == 0:  # Infinity point in Jacobian coordinates
            raise BTClibValueError("INF has no y-coordinate")

        Z2 = Q[2] * Q[2]
        return (Q[1] * mod_inv(Z2 * Q[2], self.p)) % self.p

    def jac_equality(self, QJ: JacPoint, PJ: JacPoint) -> bool:
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

    # methods using _a, _b, p

    def add(self, Q1: Point, Q2: Point) -> Point:
        """Return the sum of two points.

        The input points must be on the curve.
        """

        self.require_on_curve(Q1)
        self.require_on_curve(Q2)
        # no Jacobian coordinates here as aff_from_jac would cost 2 mod_inv
        # while add_aff costs only one mod_inv
        return self.add_aff(Q1, Q2)

    def add_jac(self, Q: JacPoint, R: JacPoint) -> JacPoint:
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

    def double_jac(self, Q: JacPoint) -> JacPoint:
        # point is assumed to be on curve

        QZ2 = Q[2] * Q[2]
        QY2 = Q[1] * Q[1]
        W = 3 * Q[0] * Q[0] + self._a * QZ2 * QZ2
        V = 4 * Q[0] * QY2
        X = W * W - 2 * V
        Y = W * (V - X) - 8 * QY2 * QY2
        Z = 2 * Q[1] * Q[2]
        return X % self.p, Y % self.p, Z % self.p

    def add_aff(self, Q: Point, R: Point) -> Point:
        # points are assumed to be on curve

        # FIXME: it would be better if INF handling was not a special case
        if R[1] == 0:  # Infinity point in affine coordinates
            return Q
        if Q[1] == 0:  # Infinity point in affine coordinates
            return R

        # FIXME: it would be better if doubling was checked before INF handling
        if R[0] == Q[0]:
            if R[1] == Q[1]:  # point doubling
                return self.double_aff(R)
            # opposite points
            return INF

        lam = (R[1] - Q[1]) * mod_inv(R[0] - Q[0], self.p)
        x = lam * lam - Q[0] - R[0]
        y = lam * (Q[0] - x) - Q[1]
        return x % self.p, y % self.p

    def double_aff(self, Q: Point) -> Point:
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
            err_msg += f"{hex_string(x)}" if x > HEX_THRESHOLD else f"{x}"
            raise BTClibValueError(err_msg)
        y2 = self._y2(x)
        try:
            return mod_sqrt(y2, self.p)
        except BTClibValueError as e:
            err_msg = "invalid x-coordinate: "
            err_msg += f"{hex_string(x)}" if x > HEX_THRESHOLD else f"{x}"
            raise BTClibValueError(err_msg) from e

    def require_on_curve(self, Q: Point) -> None:
        """Require the input curve Point to be on the curve.

        An Error is raised if not.
        """
        if not self.is_on_curve(Q):
            raise BTClibValueError("point not on curve")

    def is_on_curve(self, Q: Point) -> bool:
        """Return True if the point is on the curve."""
        if len(Q) != 2:
            raise BTClibValueError("point must be a tuple[int, int]")
        if Q[1] == 0:  # Infinity point in affine coordinates
            return True
        if not 0 < Q[1] < self.p:  # y cannot be zero
            raise BTClibValueError(f"y-coordinate not in 1..p-1: '{hex_string(Q[1])}'")
        return self._y2(Q[0]) == (Q[1] * Q[1] % self.p)

    #  y-simmetry tiebreaker criteria: even/odd, low/high, or quadratic residue

    def y_even(self, x: int) -> int:
        """Return the odd/even affine y-coordinate associated to x."""
        root = self.y(x)
        # switch even/odd root as needed (XORing the conditions)
        return self.p - root if root % 2 else root

    def y_low(self, x: int) -> int:
        """Return the low/high affine y-coordinate associated to x."""
        root = self.y(x)
        return root if root <= self.p // 2 else self.p - root

    def y_quadratic_residue(self, x: int) -> int:
        """Return the quadratic residue affine y-coordinate."""

        if not self.p_is_3_mod_4:
            err_msg = "field prime is not equal to 3 mod 4: "
            err_msg += (
                f"'{hex_string(self.p)}'" if self.p > HEX_THRESHOLD else f"{self.p}"
            )
            raise BTClibValueError(err_msg)
        root = self.y(x)
        legendre = legendre_symbol(root, self.p)
        return root if legendre else self.p - root


def mult_recursive_aff(m: int, Q: Point, ec: CurveGroup) -> Point:
    """Scalar multiplication of a curve point in affine coordinates.

    This implementation uses
    a recursive version of 'double & add',
    affine coordinates.

    The input point is assumed to be on curve and
    the m coefficient is assumed to have been reduced mod n
    if appropriate (e.g. cyclic groups of order n).
    """

    if m < 0:
        raise BTClibValueError(f"negative m: {hex(m)}")

    if m == 0:
        return INF

    if m % 2 == 1:
        return ec.add_aff(Q, mult_recursive_aff((m - 1), Q, ec))

    return mult_recursive_aff((m // 2), ec.double_aff(Q), ec)


def mult_recursive_jac(m: int, Q: JacPoint, ec: CurveGroup) -> JacPoint:
    """Scalar multiplication of a curve point in affine coordinates.

    This implementation uses
    a recursive version of 'double & add',
    jacobian coordinates.

    The input point is assumed to be on curve and
    the m coefficient is assumed to have been reduced mod n
    if appropriate (e.g. cyclic groups of order n).
    """

    if m < 0:
        raise BTClibValueError(f"negative m: {hex(m)}")

    if m == 0:
        return INFJ

    if m % 2 == 1:
        return ec.add_jac(Q, mult_recursive_jac((m - 1), Q, ec))

    return mult_recursive_jac((m // 2), ec.double_jac(Q), ec)


def mult_aff(m: int, Q: Point, ec: CurveGroup) -> Point:
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
        raise BTClibValueError(f"negative m: {hex(m)}")

    # R[0] is the running result, R[1] = R[0] + Q is an ancillary variable
    R = [INF, Q]
    # if least significant bit of m is 1, then add Q to R[0]
    R[0] = R[m & 1]
    # remove the bit just accounted for
    m >>= 1
    while m > 0:
        # the doubling part of 'double & add'
        Q = ec.double_aff(Q)
        # always perform the 'add', even if useless, to be constant-time
        R[1] = ec.add_aff(R[0], Q)
        # if least significant bit of m is 1, then add Q to R[0]
        R[0] = R[m & 1]
        m >>= 1
    return R[0]


def mult_jac(m: int, Q: JacPoint, ec: CurveGroup) -> JacPoint:
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
        raise BTClibValueError(f"negative m: {hex(m)}")

    # R[0] is the running result, R[1] = R[0] + Q is an ancillary variable
    R = [INFJ, Q]
    # if least significant bit of m is 1, then add Q to R[0]
    R[not m & 1] = Q
    # remove the bit just accounted for
    m >>= 1
    while m > 0:
        # the doubling part of 'double & add'
        Q = ec.double_jac(Q)
        # always perform the addition, even if useless, to be constant-time
        # but use it as R[0] only if least significant bit of m is 1
        R[not m & 1] = ec.add_jac(R[0], Q)
        m >>= 1
    return R[0]


def multiples(Q: JacPoint, size: int, ec: CurveGroup) -> List[JacPoint]:
    "Return {k_i * Q} for k_i in {0, ..., size-1)"

    if size < 2:
        raise BTClibValueError(f"size too low: {size}")

    k, odd = divmod(size, 2)
    T = [INFJ, Q]
    for i in range(3, k * 2, 2):
        T.append(ec.double_jac(T[(i - 1) // 2]))
        T.append(ec.add_jac(T[-1], Q))

    if odd:
        T.append(ec.double_jac(T[(size - 1) // 2]))

    return T


MAX_W = 5


@functools.lru_cache()  # least recently used cache
def cached_multiples(Q: JacPoint, ec: CurveGroup) -> List[JacPoint]:

    T = [INFJ, Q]
    for i in range(3, 2 ** MAX_W, 2):
        T.append(ec.double_jac(T[(i - 1) // 2]))
        T.append(ec.add_jac(T[-1], Q))
    return T


@functools.lru_cache()
def cached_multiples_fixwind(
    Q: JacPoint, ec: CurveGroup, w: int = 4
) -> List[List[JacPoint]]:
    """Made to precompute values for mult_fixed_window_cached.
    Do not use it for other functions.
    Made to be used for w=4, do not use w.
    """

    T = []
    K = Q
    for _ in range((ec.p_size * 8) // w + 1):
        sublist = [INFJ, K]
        for j in range(3, 2 ** w, 2):
            sublist.append(ec.double_jac(sublist[(j - 1) // 2]))
            sublist.append(ec.add_jac(sublist[-1], K))
        K = ec.double_jac(sublist[2 ** (w - 1)])
        T.append(sublist)

    return T


def convert_number_to_base(i: int, base: int) -> List[int]:
    "Return the digits of an integer in the requested base."

    digits: List[int] = []
    while i or not digits:
        i, idx = divmod(i, base)
        digits.append(idx)
    return digits[::-1]


def mult_mont_ladder(m: int, Q: JacPoint, ec: CurveGroup) -> JacPoint:
    """Scalar multiplication using 'Montgomery ladder' algorithm.

    This implementation uses
    'Montgomery ladder' algorithm,
    'left-to-right' binary decomposition of the m coefficient,
    Jacobian coordinates.

    It is constant-time and resistant to the FLUSH+RELOAD attack,
    (see https://eprint.iacr.org/2014/140.pdf)
    as it prevents branch prediction avoiding any if.

    The input point is assumed to be on curve and
    the m coefficient is assumed to have been reduced mod n
    if appropriate (e.g. cyclic groups of order n).
    """

    if m < 0:
        raise BTClibValueError(f"negative m: {hex(m)}")

    # R[0] is the running resultR[1] = R[0] + Q is an ancillary variable
    R = [INFJ, Q]
    for i in [int(i) for i in bin(m)[2:]]:
        R[not i] = ec.add_jac(R[i], R[not i])
        R[i] = ec.double_jac(R[i])
    return R[0]


def mult_base_3(m: int, Q: JacPoint, ec: CurveGroup) -> JacPoint:
    """Scalar multiplication using ternary decomposition of the scalar.

    This implementation uses
    'triple & add' algorithm,
    'left-to-right' ternary decomposition of the m coefficient,
    Jacobian coordinates.

    The input point is assumed to be on curve and
    the m coefficient is assumed to have been reduced mod n
    if appropriate (e.g. cyclic groups of order n).
    """

    if m < 0:
        raise BTClibValueError(f"negative m: {hex(m)}")

    # at each step one of the points in T will be added
    T = [INFJ, Q, ec.double_jac(Q)]
    # T = multiples(Q, 3, ec)
    # T = cached_multiples(Q, ec)

    digits = convert_number_to_base(m, 3)

    R = T[digits[0]]
    for i in digits[1:]:
        # 'triple'
        R2 = ec.double_jac(R)
        R3 = ec.add_jac(R2, R)
        # and 'add'
        R = ec.add_jac(R3, T[i])
    return R


def mult_fixed_window(
    m: int, Q: JacPoint, ec: CurveGroup, w: int = 4, cached: bool = False
) -> JacPoint:
    """Scalar multiplication using "fixed window".

    This implementation uses
    'multiple-double & add' algorithm,
    'left-to-right' window decomposition of the m coefficient,
    Jacobian coordinates.

    For 256-bit scalars it is suggested to choose w=4 or w=5.

    The input point is assumed to be on curve and
    the m coefficient is assumed to have been reduced mod n
    if appropriate (e.g. cyclic groups of order n).
    """

    if m < 0:
        raise BTClibValueError(f"negative m: {hex(m)}")

    # a number cannot be written in basis 1 (ie w=0)
    if w <= 0:
        raise BTClibValueError(f"non positive w: {w}")

    # at each step one of the points in T will be added
    # T = cached_multiples(Q, ec)
    # T = multiples(Q, 2 ** w, ec)

    T = cached_multiples(Q, ec) if cached else multiples(Q, 2 ** w, ec)

    digits = convert_number_to_base(m, 2 ** w)

    R = T[digits[0]]
    for i in digits[1:]:
        # multiple 'double'
        for _ in range(w):
            R = ec.double_jac(R)
        # and 'add'
        R = ec.add_jac(R, T[i])
    return R


def mult_fixed_window_cached(
    m: int, Q: JacPoint, ec: CurveGroup, w: int = 4
) -> JacPoint:
    """Scalar multiplication using "fixed window" & cached values.

    This implementation uses
    'multiple-double & add' algorithm,
    'left-to-right' window decomposition of the m coefficient,
    Jacobian coordinates.

    For 256-bit scalars it is suggested to choose w=4.
    Thanks to the pre-computed values, it just needs addictions.

    The input point is assumed to be on curve and
    the m coefficient is assumed to have been reduced mod n
    if appropriate (e.g. cyclic groups of order n).
    """

    if m < 0:
        raise BTClibValueError(f"negative m: {hex(m)}")

    # a number cannot be written in basis 1 (ie w=0)
    if w <= 0:
        raise BTClibValueError(f"non positive w: {w}")

    T = cached_multiples_fixwind(Q, ec, w)

    digits = convert_number_to_base(m, 2 ** w)

    k = len(digits) - 1

    R = T[k][digits[0]]

    for i in range(1, len(digits)):
        k -= 1
        # only 'add'
        R = ec.add_jac(R, T[k][digits[i]])
    return R


_mult = mult_fixed_window


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
        raise BTClibValueError(f"negative first coefficient: {hex(u)}")
    if v < 0:
        raise BTClibValueError(f"negative second coefficient: {hex(v)}")

    # at each step one of the following points will be added
    T = [INFJ, HJ, QJ, ec.add_jac(HJ, QJ)]
    # which one depends on binary digit for that step
    ui = bin(u)[2:]
    vi = bin(v)[2:].zfill(len(ui))
    ui = ui.zfill(len(vi))
    digits = [int(j) + 2 * int(k) for j, k in zip(ui, vi)]
    # R[0] is the running result, R[1] = R[0] + T[*] is an ancillary variable
    R = T[digits[0]]
    for i in digits[1:]:
        # the doubling part of 'double & add'
        R = ec.double_jac(R)
        # always perform the 'add', even if useless, to be constant-time
        # 'add' it to R[0] only if appropriate
        R = ec.add_jac(R, T[i])
    return R


def _multi_mult(
    scalars: Sequence[int], jac_points: Sequence[JacPoint], ec: CurveGroup
) -> JacPoint:
    """Return the multi scalar multiplication u1*Q1 + ... + un*Qn.

    Use Bos-Coster's algorithm for efficient computation.

    The input points are assumed to be on curve,
    the scalar coefficients are assumed to have been reduced mod n
    if appropriate (e.g. cyclic groups of order n).
    """
    # source: https://cr.yp.to/badbatch/boscoster2.py

    if len(scalars) != len(jac_points):
        err_msg = "mismatch between number of scalars and points: "
        err_msg += f"{len(scalars)} vs {len(jac_points)}"
        raise BTClibValueError(err_msg)

    # x = list(zip([-n for n in scalars], jac_points))
    x: List[Tuple[int, JacPoint]] = []
    for n, PJ in zip(scalars, jac_points):
        if n == 0:  # mandatory check to avoid infinite loop
            continue
        if n < 0:
            raise BTClibValueError(f"negative coefficient: {hex(n)}")
        x.append((-n, PJ))

    if not x:
        return INFJ

    heapq.heapify(x)
    while len(x) > 1:
        np1 = heapq.heappop(x)
        np2 = heapq.heappop(x)
        n_1, p_1 = -np1[0], np1[1]
        n_2, p_2 = -np2[0], np2[1]
        p_2 = ec.add_jac(p_1, p_2)
        n_1 -= n_2
        if n_1 > 0:
            heapq.heappush(x, (-n_1, p_1))
        heapq.heappush(x, (-n_2, p_2))
    np1 = heapq.heappop(x)
    n_1, p_1 = -np1[0], np1[1]
    # assert n_1 < ec.n, "better to take the mod n"
    # n_1 %= ec.n
    return _mult(n_1, p_1, ec)
