# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Number theory and modular arithmetic functions.

Implementations originally from
https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
and
https://codereview.stackexchange.com/questions/43210/tonelli-shanks-algorithm-implementation-of-prime-modular-square-root/43267
with the following modifications:

* type annotated Python3
* minor improvements
* added extensive unit test
"""

from __future__ import annotations

from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.utils import hex_string, is_integer

__all__ = [
    "legendre_symbol",
    "mod_inv",
    "mod_sqrt",
    "tonelli",
    "xgcd",
]


def _assert_valid_operand(a: int) -> None:
    """Refuse an operand that is not an integer, a bool not being one.

    A float goes through every function here without complaint --
    `//`, `%` and `*` are all defined for it -- and comes back out of a
    signature that says `int`: `mod_inv(3.0, 7)` answers `5.0`, which is
    not a residue and not an error either. `var_int.serialize` checks the
    same way and its docstring says why a bool is excluded.
    """
    if not is_integer(a):
        raise BTClibTypeError(f"not an integer: {a!r}")


def _assert_valid_modulus(m: int) -> None:
    """Refuse a modulus nothing is a residue of.

    Positive, not merely non-zero: zero is the `ZeroDivisionError` of
    `a %= m` and the `ValueError` `pow` raises for a third argument of
    zero, neither of which a caller writing `except BTClibValueError`
    catches, and a negative modulus would answer with a negative residue
    class that no caller of this module has a use for.
    """
    _assert_valid_operand(m)
    if m < 1:
        raise BTClibValueError(f"non-positive modulus: {m}")


# every public function here checks its own arguments, rather than five
# private twins doing the work unchecked for the ones that call each
# other: a pair of isinstance calls is a fraction of a percent of the
# arithmetic it stands in front of, an inverse modulo a 256-bit prime
# being an extended Euclid, so the re-checking mod_sqrt does through
# tonelli and legendre_symbol costs less than five more names would


def xgcd(a: int, b: int) -> tuple[int, int, int]:
    """Return (g, x, y) such that a*x + b*y = g = gcd(x, y).

    based on Extended Euclidean Algorithm, see
    https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
    """
    _assert_valid_operand(a)
    _assert_valid_operand(b)
    x0, x1, y0, y1 = 0, 1, 1, 0
    while a != 0:
        q, b, a = b // a, a, b % a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
    return b, x0, y0


def mod_inv(a: int, m: int) -> int:
    """Return the inverse of a (mod m).

    m does not have to be a prime.

    Based on Extended Euclidean Algorithm, see:
    - https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
    """
    _assert_valid_operand(a)
    _assert_valid_modulus(m)
    a %= m
    g, x, _ = xgcd(a, m)
    if g == 1:
        return x % m
    err_msg = "no inverse for "
    err_msg += f"{hex_string(a)}" if a > 0xFFFFFFFF else f"{a}"
    err_msg += " mod "
    err_msg += f"{hex_string(m)}" if m > 0xFFFFFFFF else f"{m}"
    raise BTClibValueError(err_msg)


def legendre_symbol(a: int, p: int) -> int:
    """Compute the Legendre symbol a|p using Euler's criterion.

    p is a prime, a is relatively prime to p (if p divides a, then a|p =
    0). It returns 1 if a has a square root modulo p, -1 otherwise.

    https://codereview.stackexchange.com/questions/43210/tonelli-shanks-algorithm-implementation-of-prime-modular-square-root/43267
    """
    _assert_valid_operand(a)
    _assert_valid_modulus(p)
    ls = pow(a, p >> 1, p)
    return -1 if ls == p - 1 else ls


def mod_sqrt(a: int, p: int) -> int:
    """Return a quadratic residue (mod p) of a; p must be a prime.

    Solve the equation:
        x^2 = a mod p

    and return x; p - x is also a root.

    If a simple solution is not available for p,
    then the Tonelli-Shanks algorithm is used.

    https://codereview.stackexchange.com/questions/43210/tonelli-shanks-algorithm-implementation-of-prime-modular-square-root/43267
    """
    _assert_valid_operand(a)
    _assert_valid_modulus(p)
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
    _assert_valid_operand(a)
    _assert_valid_modulus(p)
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
