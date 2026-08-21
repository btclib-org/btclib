# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Number theory and modular arithmetic functions.

Implementations originally from
https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
and
https://codereview.stackexchange.com/questions/43210/tonelli_var-shanks-algorithm-implementation-of-prime-modular-square-root/43267
with the following modifications:

* type annotated Python3
* minor improvements
* added extensive unit test
"""

from __future__ import annotations

import secrets
from collections.abc import Sequence

from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.utils import hex_string, is_integer

__all__ = [
    "legendre_symbol_var",
    "mod_inv",
    "mod_inv_batch",
    "mod_inv_batch_var",
    "mod_inv_var",
    "mod_sqrt_var",
    "tonelli_var",
    "xgcd_var",
]


def _assert_valid_operand(a: int) -> None:
    """Refuse an operand that is not an integer, a bool not being one.

    A float goes through every function here without complaint --
    `//`, `%` and `*` are all defined for it -- and comes back out of a
    signature that says `int`: `mod_inv_var(3.0, 7)` answers `5.0`, which is
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
# other: a pair of isinstance calls is a small fraction of the arithmetic
# it stands in front of, an inverse modulo a 256-bit prime being an
# extended Euclid even when C runs it, so the re-checking mod_sqrt_var does
# through tonelli_var and legendre_symbol_var costs less than five more names
# would


def xgcd_var(a: int, b: int) -> tuple[int, int, int]:
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


def mod_inv_var(a: int, m: int) -> int:
    """Return the inverse of a (mod m).

    m does not have to be a prime.

    `pow(a, -1, m)` is an Extended Euclidean Algorithm too -- CPython's
    `long_invmod`, which is the loop `xgcd_var` runs with the second cofactor
    dropped -- so this delegates the same algorithm to C rather than
    interpreting it, and that is the whole of why it is called. It is not
    a constant-time inverse and neither was the bytecode one; SECURITY.md
    publishes the Python path as variable-time.

    Its duration follows the operand, so a secret one goes to
    `mod_inv` instead: what that duration carries is measured
    there, and it is enough to recover a private key from a signature.

    What `pow` does not carry is this module's contract, so the checks
    stay above it and the message below it: a non-invertible operand
    leaves `pow` as a bare `ValueError` naming neither operand, and
    rebuilding the message says more than chaining that one would.
    """
    _assert_valid_operand(a)
    _assert_valid_modulus(m)
    try:
        return pow(a, -1, m)
    except ValueError:
        a %= m
        err_msg = "no inverse for "
        err_msg += f"{hex_string(a)}" if a > 0xFFFFFFFF else f"{a}"
        err_msg += " mod "
        err_msg += f"{hex_string(m)}" if m > 0xFFFFFFFF else f"{m}"
        raise BTClibValueError(err_msg) from None


def mod_inv(a: int, m: int) -> int:
    """Return the inverse of a (mod m), timed on a random value instead.

    What `mod_inv_var` is for an operand that is public, this is for one
    that is secret. The extended Euclid under that one takes the
    iterations its input asks for, and for an operand drawn uniformly
    below m what its duration carries is the operand's bit-length: on
    secp256k1's order, 8.8 us for a 256-bit scalar against 4.3 for a
    128-bit one, falling at every step between them. That
    correlation is what the Minerva attack collects -- an ECDSA nonce is
    such a scalar, and a few thousand signing times sorted by it are a
    lattice away from the private key.

    (b*a)^-1 * b is a^-1 for every b invertible mod m, so drawing b at
    random leaves an inverse whose iteration count follows b and tells an
    observer nothing about a: 1.02x across the same range of operands,
    where `mod_inv_var` is 2.06x. Two multiplications, two reductions
    and a draw from `secrets`, which is 1.11x on a 256-bit operand and
    1.5% of the whole Python signature it sits in. Fermat's
    `pow(a, m - 2, m)` is the alternative and is flat for a different
    reason, its ladder running on the fixed exponent rather than on a
    random operand; it is not the one chosen, at 8.38x.

    The draw is what costs, so a small modulus pays proportionally more
    -- 4.8x on an order of 11, where the Euclid is a few iterations and
    `secrets` is the same syscall. Nothing signs with such an order
    outside the test suite.

    Not a constant-time inverse, and no more claiming to be one than
    `curve_group._blinded_jac` does: the duration is still an extended
    Euclid's and still visible, and what the blinding changes is whose it
    is. SECURITY.md publishes the Python path as variable-time, and
    CONTRIBUTING.md has what a name in this library does and does not
    promise about duration.
    """
    _assert_valid_operand(a)
    _assert_valid_modulus(m)

    # a nonzero b, and one the modulus leaves room to draw: m == 1 has
    # only b = 1, every integer being zero modulo it
    b = 1 + secrets.randbelow(m - 1) if m > 1 else 1
    try:
        return mod_inv_var(a * b % m, m) * b % m
    except BTClibValueError:
        # a product is invertible only if both factors are, so this is
        # either the caller's own non-invertible a -- and the call below
        # raises about the operand they passed, where the one above would
        # name a product they never formed -- or a b that is a zero
        # divisor, which only a composite m has. The blinding is lost in
        # that second case and the answer is not; every modulus this is
        # asked about in the library is the order of a group, which
        # `curves.Curve` requires prime
        return mod_inv_var(a, m)


def mod_inv_batch(a: Sequence[int], m: int) -> list[int]:
    """Return every inverse, each timed on a random value instead.

    What `mod_inv` is to `mod_inv_var`, this is to `mod_inv_batch_var`:
    the twin a secret may be handed. Montgomery's trick inverts one
    running product for the whole sequence, so the single extended Euclid
    it spends is timed on a value every element went into -- which is the
    channel, the same one and no smaller for being shared.

    Each element is blinded with a factor of its own rather than the
    sequence with one: `inv(a_i * b_i) * b_i` is `inv(a_i)`, and the
    product the batch forms is then a product of blinded values. One
    factor for all of them would blind that product and leave the ratios
    `a_i / a_j` in the peeled-back inverses, which is what the running
    products are made of.

    So it costs `n` draws from `secrets` and 2n multiplications on top of
    the trick, and the draws are the whole of it: measured on secp256k1's
    `p` over 16 random elements, best of nine alternating rounds, 43.7 us
    against the 20.9 of `mod_inv_batch_var` -- 2.1x, and 22.8 us of
    difference for 16 draws of 1.6.

    It is still the trick, which is the point of it being a batch at all:
    16 separate `mod_inv` calls are 155.9 us over the same elements, so
    blinding the batch is 3.6x cheaper than blinding one at a time, where
    the unblinded batch is 6.3x cheaper than the unblinded singles' 131.3.
    The saving shrinks as the draws grow with n and the one Euclid does
    not; the trick still wins at every size worth batching.

    Not constant-time, for the reasons `mod_inv` gives at length. The
    empty sequence is not an error here either.
    """
    _assert_valid_modulus(m)
    for x in a:
        _assert_valid_operand(x)

    if not a:
        return []

    # a nonzero factor each, as `mod_inv` draws its one; m == 1 leaves
    # only the factor 1, every integer being zero modulo it
    factors = [1 + secrets.randbelow(m - 1) if m > 1 else 1 for _ in a]
    blinded = [x * b % m for x, b in zip(a, factors, strict=True)]
    try:
        inverses = mod_inv_batch_var(blinded, m)
    except BTClibValueError:
        # a product is invertible only if every factor is, so an element
        # with no inverse is the caller's own error and is named as such
        # -- and a factor that a composite m made a zero divisor lands
        # here too, where `mod_inv` says what is lost and what is not
        return [mod_inv(x, m) for x in a]
    return [i * b % m for i, b in zip(inverses, factors, strict=True)]


def mod_inv_batch_var(a: Sequence[int], m: int) -> list[int]:
    """Return the inverse of every element of a (mod m), in its order.

    m does not have to be a prime, and every element has to be invertible
    modulo it, as `mod_inv_var` requires of its one operand.

    Montgomery's trick, which libsecp256k1 spells `secp256k1_fe_inv_all_var`:
    the running products a[0], a[0]*a[1], ..., a[0]*...*a[n-1] are formed,
    the last of them is inverted once, and the individual inverses are
    peeled back off it. So n inverses cost one inverse and 3(n-1)
    products, where n calls to `mod_inv_var` are n extended Euclids -- an
    inverse modulo a 256-bit prime being some thirty times a product.

    An empty sequence has no inverses and is not an error: it is what a
    caller that filtered its own input is left with.
    """
    _assert_valid_modulus(m)
    for x in a:
        _assert_valid_operand(x)

    if not a:
        return []

    # the running products, the last of which is the one to invert
    acc: list[int] = []
    product = 1
    for x in a:
        product = product * x % m
        acc.append(product)

    try:
        inv = pow(product, -1, m)
    except ValueError:
        # a product is invertible only if every factor is, so at least one
        # element is not: inverting them one at a time reaches it and
        # answers `mod_inv_var`'s own message, naming the operand rather than
        # the product a caller never formed
        return [mod_inv_var(x, m) for x in a]

    # and peeled back off it, from the last element to the first: the
    # inverse of the whole product times the product of everything before
    # element i is the inverse of element i
    inverses = [0] * len(a)
    for i in range(len(a) - 1, 0, -1):
        inverses[i] = inv * acc[i - 1] % m
        inv = inv * a[i] % m
    inverses[0] = inv
    return inverses


def legendre_symbol_var(a: int, p: int) -> int:
    """Compute the Legendre symbol a|p, as a binary Jacobi symbol.

    p is a prime, a is relatively prime to p (if p divides a, then a|p =
    0). It returns 1 if a has a square root modulo p, -1 otherwise. The
    Jacobi symbol is what is computed, and for a prime modulus the two
    are the same number.

    By the reciprocity recursion rather than by Euler's criterion, which
    is `pow(a, (p - 1) // 2, p)` -- an exponentiation the size of the
    square root the caller is asking about, where this is a gcd: 13.3 us
    against 74.7 on secp256k1's p, over 3000 calls, best of seven. The
    factors of two come out all at once, `a & -a` being the lowest set
    bit, which is libsecp256k1's `secp256k1_ctz64_var`; asking a gcd
    rather than an exponent is what its `secp256k1_fe_is_square_var`
    does, through `secp256k1_jacobi64_maybe_var` and never through a
    power. Its own recursion is the safegcd one, which in bytecode loses
    as every safegcd does -- `curves.curve_group_2` keeps the list.

    The loop's length follows `a`, where an exponentiation's did not.
    SECURITY.md publishes the Python path as variable-time, and nothing
    in the tree asks this about a value that has to stay hidden:
    `curves.curve._is_x_coordinate_var` is the one caller, and what reaches
    it is a signature's r, the x-coordinate of a serialized xpub, or a
    candidate x of an ElligatorSwift encoding -- each of them public, and
    on secp256k1 each answered by the bindings before this is reached.
    """
    _assert_valid_operand(a)
    _assert_valid_modulus(p)

    a %= p
    result = 1
    while a:
        # every factor of two at once, and the symbol 2|p is -1 for a p
        # of 3 or 5 mod 8, so only an odd count of them turns the sign
        twos = (a & -a).bit_length() - 1
        a >>= twos
        if twos & 1 and p & 7 in {3, 5}:
            result = -result
        # quadratic reciprocity: the operands swap, and the sign turns
        # when both of them are 3 mod 4
        if a & 3 == 3 and p & 3 == 3:
            result = -result
        a, p = p % a, a
    # what is left is the gcd, and a symbol is zero when it is not one:
    # for a prime p that is a multiple of p, which has no square root
    # and is not a non-residue either
    return result if p == 1 else 0


def mod_sqrt_var(a: int, p: int) -> int:
    """Return a quadratic residue (mod p) of a; p must be a prime.

    Solve the equation:
        x^2 = a mod p

    and return x; p - x is also a root.

    If a simple solution is not available for p,
    then the Tonelli-Shanks algorithm is used.

    https://codereview.stackexchange.com/questions/43210/tonelli_var-shanks-algorithm-implementation-of-prime-modular-square-root/43267
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
        return tonelli_var(a, p)

    if r * r % p != a:
        err_msg = "no root for "
        err_msg += f"'{hex_string(a)}'" if a > 0xFFFFFFFF else f"{a}"
        err_msg += " mod "
        err_msg += f"'{hex_string(p)}'" if p > 0xFFFFFFFF else f"{p}"
        raise BTClibValueError(err_msg)
    return r


def tonelli_var(a: int, p: int) -> int:
    """Return a quadratic residue (mod p) of a; p must be a prime.

    The Tonelli-Shanks algorithm is used.

    https://codereview.stackexchange.com/questions/43210/tonelli_var-shanks-algorithm-implementation-of-prime-modular-square-root/43267
    """
    _assert_valid_operand(a)
    _assert_valid_modulus(p)
    a %= p
    if a == 0 or p == 2:
        return a

    # Check solution existence for an odd prime p
    if legendre_symbol_var(a, p) != 1:
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

    # Select a z which is a quadratic non residue modulo p, from the
    # first value that can be one: 1 is a square modulo every prime, so
    # its symbol is known before the loop asks for it
    z = 2
    while legendre_symbol_var(z, p) != -1:
        z += 1
    c = pow(z, q, p)
    r = pow(a, (q + 1) // 2, p)
    t = pow(a, q, p)
    while t != 1:
        # Find the lowest i such that t^(2^i) = 1
        t2i = t
        # `no branch` on the exhausted loop, which cannot happen: the
        # legendre symbol above is what rules it out, `a` being a
        # quadratic residue making `t = a**q` an element of the subgroup
        # of order 2**(s-1), so squaring it reaches 1 at some i < s. The
        # bound is the loop's termination and not a fallback -- there is
        # no value of i to take past it -- which is why nothing follows
        # the loop but the `while` that reads the new t
        for i in range(1, s):  # pragma: no branch
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
