#!/usr/bin/env python3

"""Modular algebra functions

   Implementations originally from
   https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
   and
   https://codereview.stackexchange.com/questions/43210/tonelli-shanks-algorithm-implementation-of-prime-modular-square-root/43267
   with the following modifications:
   - type annotated python3
   - minor improvements
   - added extensive unit test
"""

from typing import Tuple


def xgcd(a: int, b: int) -> Tuple[int, int, int]:
    """Return (g, x, y) such that a*x + b*y = g = gcd(x, y)

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
    """ Return the inverse of 'a' (mod m). m does not have to be a prime.

       based on Extended Euclidean Algorithm, see
       https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
    """
    a %= m
    g, x, _ = xgcd(a, m)
    if g == 1:
        return x % m
    raise ValueError(f"{hex(a)} has no inverse (mod {hex(m)})")


def legendre_symbol(a, p):
    """ Compute the Legendre symbol a|p using Euler's criterion.

        p is a prime, a is relatively prime to p (if p divides a, then a|p = 0)
        Returns 1 if a has a square root modulo p, -1 otherwise.

       https://codereview.stackexchange.com/questions/43210/tonelli-shanks-algorithm-implementation-of-prime-modular-square-root/43267
    """
    ls = pow(a, p >> 1, p)
    return -1 if ls == p - 1 else ls


def mod_sqrt(a: int, p: int) -> int:
    """ Return a quadratic residue (mod p) of 'a'; p must be a prime.
        Solve the equation
        x^2 = a mod p
        And returns x. Note that p - x is also a root.
        The Tonelli-Shanks algorithm is used (except for some simple
        cases in which the solution is known from an identity).

        https://codereview.stackexchange.com/questions/43210/tonelli-shanks-algorithm-implementation-of-prime-modular-square-root/43267
    """

    a %= p

    # Simple cases
    if p % 4 == 3:  # secp256k1 case
        x = pow(a, (p >> 2) + 1, p)  # inverse candidate
        if x * x % p == a:
            return x
        raise ValueError(f"{hex(a)} has no root (mod {hex(p)})")
    elif p % 8 == 5:
        x = pow(a, (p >> 3) + 1, p)
        if x * x % p == a:
            return x
        else:
            x = x * pow(2, p >> 2, p) % p
            if x * x % p == a:
                return x
        raise ValueError(f"{hex(a)} has no root (mod {hex(p)})")
    elif a == 0 or p == 2:
        return a

    # Check solution existence on odd prime
    if legendre_symbol(a, p) != 1:
        raise ValueError(f"{hex(a)} has no root (mod {hex(p)})")

    # Factor p-1 on the form q * 2^s (with Q odd)
    q, s = p - 1, 0
    while q & 1 == 0:
        s += 1
        q >>= 1

    # Select a z which is a quadratic non resudue modulo p
    z = 1
    while legendre_symbol(z, p) != -1:
        z += 1
    c = pow(z, q, p)

    # Search for a solution
    x = pow(a, (q + 1) // 2, p)
    t = pow(a, q, p)
    m = s
    while t != 1:
        # Find the lowest i such that t^(2^i) = 1
        t2i = t
        for i in range(1, m):
            t2i = t2i * t2i % p
            if t2i == 1:
                break

        # Update next value to iterate
        b = pow(c, 1 << (m - i - 1), p)
        x = (x * b) % p
        c = (b * b) % p
        t = (t * c) % p
        m = i

    return x
