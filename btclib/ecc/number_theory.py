#!/usr/bin/env python3

# Copyright (C) 2017-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Number theory and modular arithmetic functions.

Implementations originally from
https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
and
https://codereview.stackexchange.com/questions/43210/tonelli-shanks-algorithm-implementation-of-prime-modular-square-root/43267
with the following modifications:

* type annotated python3
* minor improvements
* added extensive unit test
"""

from typing import Tuple

from btclib.exceptions import BTClibValueError
from btclib.utils import hex_string


def xgcd(a: int, b: int) -> Tuple[int, int, int]:
    """Return (g, x, y) such that a*x + b*y = g = gcd(x, y).

    based on Extended Euclidean Algorithm, see
    https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
    """

    x0, x1, y0, y1 = 0, 1, 1, 0
    while a != 0:
        q, b, a = b // a, a, b % a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
    return b, x0, y0


def mod_inv(a: int, m: int) -> int:
    """Return the inverse of a (mod m). m does not have to be a prime.

    Based on Extended Euclidean Algorithm, see:
    https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
    """

    a %= m
    g, x, _ = xgcd(a, m)
    if g == 1:
        return x % m
    err_msg = "No inverse for "
    err_msg += f"{hex_string(a)}" if a > 0xFFFFFFFF else f"{a}"
    err_msg += " mod "
    err_msg += f"{hex_string(m)}" if m > 0xFFFFFFFF else f"{m}"
    raise BTClibValueError(err_msg)


def legendre_symbol(a: int, p: int) -> int:
    """Compute the Legendre symbol a|p using Euler's criterion.

    p is a prime, a is relatively prime to p (if p divides a,
    then a|p = 0).
    It returns 1 if a has a square root modulo p, -1 otherwise.

    https://codereview.stackexchange.com/questions/43210/tonelli-shanks-algorithm-implementation-of-prime-modular-square-root/43267
    """

    ls = pow(a, p >> 1, p)
    return -1 if ls == p - 1 else ls


def mod_sqrt(a: int, p: int) -> int:
    """Return a quadratic residue (mod p) of a; p must be a prime.

    Solve the equation:
        x^2 = a mod p

    and return x. Note that p - x is also a root.

    If a simple solution is not available for p,
    then the Tonelli-Shanks algorithm is used.

    https://codereview.stackexchange.com/questions/43210/tonelli-shanks-algorithm-implementation-of-prime-modular-square-root/43267
    """

    a %= p

    if p % 4 == 3:  # secp256k1 case
        # inverse candidate is pow(a, (p + 1) // 4, p)
        r = pow(a, (p >> 2) + 1, p)
    elif p % 8 == 5:
        # inverse candidate is pow(a, (p + 3) // 8, p)
        r = pow(a, (p >> 3) + 1, p)
        if r * r % p == a:
            return r
        # another inverse candidate
        r = r * pow(2, p >> 2, p) % p
    else:
        return tonelli(a, p)

    if r * r % p != a:
        err_msg = "no root for "
        err_msg += f"'{hex_string(a)}'" if a > 0xFFFFFFFF else f"{a}"
        err_msg += " mod "
        err_msg += f"'{hex_string(p)}'" if p > 0xFFFFFFFF else f"{p}"
        raise BTClibValueError(err_msg)
    return r


def tonelli(a: int, p: int) -> int:
    """Return a quadratic residue (mod p) of a; p must be a prime.

    The Tonelli-Shanks algorithm is used.

    https://codereview.stackexchange.com/questions/43210/tonelli-shanks-algorithm-implementation-of-prime-modular-square-root/43267
    """

    a %= p
    if a == 0 or p == 2:
        return a

    # Check solution existence for an odd prime p
    if legendre_symbol(a, p) != 1:
        err_msg = "no root for "
        err_msg += f"'{hex_string(a)}'" if a > 0xFFFFFFFF else f"{a}"
        err_msg += " mod "
        err_msg += f"'{hex_string(p)}'" if p > 0xFFFFFFFF else f"{p}"
        raise BTClibValueError(err_msg)

    # Factor p-1 on the form q * 2^s (with q odd)
    q, s = p - 1, 0
    while q & 1 == 0:
        s += 1
        q >>= 1
    if s == 1:
        return pow(a, (p + 1) // 4, p)

    # Select a z which is a quadratic non residue modulo p
    z = 1
    while legendre_symbol(z, p) != -1:
        z += 1
    c = pow(z, q, p)
    r = pow(a, (q + 1) // 2, p)
    t = pow(a, q, p)
    while t != 1:
        # Find the lowest i such that t^(2^i) = 1
        t2i = t
        for i in range(1, s):
            t2i = t2i * t2i % p
            if t2i == 1:
                # Update next value to iterate
                b = pow(c, 1 << (s - i - 1), p)
                r = (r * b) % p
                c = (b * b) % p
                t = (t * c) % p
                s = i
                break

    return r
