# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.number_theory` module."""

import math
import secrets

import pytest
from hypothesis import given
from hypothesis import strategies as st

from btclib import number_theory
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.number_theory import (
    legendre_symbol_var,
    mod_inv,
    mod_inv_batch_var,
    mod_inv_var,
    mod_sqrt_var,
    tonelli_var,
    xgcd_var,
)

primes = [
    2,
    3,
    5,
    7,
    11,
    13,
    17,
    19,
    23,
    29,
    31,
    37,
    41,
    43,
    47,
    53,
    59,
    61,
    67,
    71,
    73,
    79,
    83,
    89,
    97,
    101,
    103,
    107,
    109,
    113,
    2**160 - 2**31 - 1,
    2**192 - 2**32 - 2**12 - 2**8 - 2**7 - 2**6 - 2**3 - 1,
    2**192 - 2**64 - 1,
    2**224 - 2**32 - 2**12 - 2**11 - 2**9 - 2**7 - 2**4 - 2 - 1,
    2**224 - 2**96 + 1,
    2**256 - 2**32 - 977,
    2**256 - 2**224 + 2**192 + 2**96 - 1,
    2**384 - 2**128 - 2**96 + 2**32 - 1,
    2**521 - 1,
]


def test_a_float_is_no_operand_and_zero_is_no_modulus() -> None:
    """Modular arithmetic over what is not an integer answered anyway.

    Python defines `//`, `%` and `*` for a float, so every function here
    ran to completion on one and returned it: `mod_inv_var(3.0, 7)` answered
    `5.0` out of a signature that says `int`, and `xgcd_var(3.0, 7)` a
    triple of floats -- no exception, and a residue that is not one.
    `legendre_symbol_var` and its two callers reached `pow`'s own TypeError
    instead, which is no better for a caller filtering bad input.

    A modulus of zero is the other half: the `ZeroDivisionError` of
    `a %= m` and the `ValueError` `pow` raises for a third argument of
    zero. The first is an `ArithmeticError`, so `except ValueError` does
    not catch it.
    """
    for a, m in ((3.0, 7), (3, 7.0), ("3", 7), (3, None)):
        with pytest.raises(BTClibTypeError, match="not an integer: "):
            xgcd_var(a, m)  # type: ignore[arg-type]
        for call in (mod_inv_var, legendre_symbol_var, mod_sqrt_var, tonelli_var):
            with pytest.raises(BTClibTypeError, match="not an integer: "):
                call(a, m)  # type: ignore[arg-type]

    # a bool is not a number either, `isinstance(True, int)` being what
    # would otherwise make it the modulus one
    for value in (True, False):
        with pytest.raises(BTClibTypeError, match="not an integer: "):
            mod_inv_var(value, 7)
        with pytest.raises(BTClibTypeError, match="not an integer: "):
            mod_inv_var(3, value)

    for m in (0, -7):
        for call in (mod_inv_var, legendre_symbol_var, mod_sqrt_var, tonelli_var):
            with pytest.raises(BTClibValueError, match="non-positive modulus: "):
                call(3, m)
    # xgcd_var takes no modulus: zero is a legitimate operand there, whose
    # greatest common divisor with three is three
    assert xgcd_var(3, 0)[0] == 3


def test_mod_inv_prime() -> None:
    """Verify the inverse mod a prime, and refuse the zero residue."""
    for p in primes:
        with pytest.raises(BTClibValueError, match="no inverse for 0 mod"):
            mod_inv_var(0, p)
        for a in range(1, min(p, 500)):  # exhausted only for small p
            inv = mod_inv_var(a, p)
            assert a * inv % p == 1
            inv = mod_inv_var(a + p, p)
            assert a * inv % p == 1


def test_mod_inv() -> None:
    """Verify mod_inv_var over every residue of every modulus up to 100."""
    max_m = 100
    for m in range(2, max_m):
        nums = list(range(m))
        for a in nums:
            mult = [a * i % m for i in nums]
            if 1 in mult:
                inv = mod_inv_var(a, m)
                assert a * inv % m == 1
                inv = mod_inv_var(a + m, m)
                assert a * inv % m == 1
            else:
                err_msg = "no inverse for "
                with pytest.raises(BTClibValueError, match=err_msg):
                    mod_inv_var(a, m)


def test_legendre_symbol_is_the_squares_of_the_field() -> None:
    """The symbol against the squares themselves, exhaustively.

    For a prime p the residues are exactly the squares of 1..p-1 and zero
    is neither, so brute force is the oracle: the symbol is 1 on a square,
    -1 on anything else, 0 on a multiple of p, and it reads a negative or
    oversized operand as its residue.

    p = 2 is the case worth naming: every residue there is a square, so
    the symbol of 1 is 1.
    """
    for p in primes[:30]:  # exhaustable only for small p
        squares = {a * a % p for a in range(1, p)}
        for a in range(p):
            expected = 0 if a == 0 else 1 if a in squares else -1
            assert legendre_symbol_var(a, p) == expected, (a, p)
            assert legendre_symbol_var(a + p, p) == expected, (a, p)
            assert legendre_symbol_var(a - p, p) == expected, (a, p)


def test_mod_sqrt() -> None:
    """Verify both roots of every residue, exhaustively on small primes."""
    for p in primes[:30]:  # exhaustable only for small p
        has_root = {0, 1}
        has_root.update(i * i % p for i in range(2, p))
        for i in range(p):
            if i in has_root:
                root1 = mod_sqrt_var(i, p)
                assert i == (root1 * root1) % p
                root2 = p - root1
                assert i == (root2 * root2) % p
                root = mod_sqrt_var(i + p, p)
                assert i == (root * root) % p
                if p % 4 == 3 or p % 8 == 5:
                    assert tonelli_var(i, p) in {root1, root2}
            else:
                with pytest.raises(BTClibValueError, match="no root for "):
                    mod_sqrt_var(i, p)


def test_mod_sqrt2() -> None:
    """Reproduce Rosetta Code's Tonelli-Shanks vectors."""
    # https://rosettacode.org/wiki/Tonelli-Shanks_algorithm#Python
    test_vectors = [
        (10, 13),
        (56, 101),
        (1030, 10009),
        (44402, 100049),
        (665820697, 1000000009),
        (881398088036, 1000000000039),
        (41660815127637347468140745042827704103445750172002, 10**50 + 577),
    ]
    for i, p in test_vectors:
        root = tonelli_var(i, p)
        assert i == (root * root) % p


def test_minus_one_quadr_res() -> None:
    """Ensure that if p = 3 (mod 4) then p - 1 is not a quadratic residue."""
    for p in primes:
        if (p % 4) == 3:
            with pytest.raises(BTClibValueError, match="no root for "):
                mod_sqrt_var(p - 1, p)
        else:
            assert p == 2 or p % 4 == 1, "something is badly broken"
            root = mod_sqrt_var(p - 1, p)
            assert p - 1 == root * root % p


# the primes above are small enough to be exhaustive over, which is what
# the vector tests already do; these are the fields the library actually
# computes in, where only a generated argument reaches anything
FIELD_PRIMES = st.sampled_from(
    [
        7,
        97,
        (1 << 31) - 1,
        (1 << 61) - 1,
        # secp256k1's p and n, the two the whole library runs on
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
    ]
)


@given(a=st.integers(), p=FIELD_PRIMES)
def test_legendre_symbol_agrees_with_euler(a: int, p: int) -> None:
    """Euler's criterion is the definition, the recursion is what runs.

    Over the fields the library computes in, which are too large to
    enumerate. p = 2 is not among them and could not be: the criterion is
    `pow(a, (p - 1) // 2, p)` compared with p - 1, and at p = 2 that is a
    comparison with 1, which reads every residue as a non-residue.
    """
    euler = pow(a, p >> 1, p)
    expected = 0 if euler == 0 else 1 if euler == 1 else -1
    assert legendre_symbol_var(a, p) == expected


@given(a=st.integers(), b=st.integers())
def test_xgcd_is_bezout(a: int, b: int) -> None:
    """What xgcd_var returns is the identity it is named after."""
    g, x, y = xgcd_var(a, b)
    assert a * x + b * y == g
    assert g == math.gcd(a, b) or -g == math.gcd(a, b)


@given(a=st.integers(), m=st.integers(min_value=2))
def test_mod_inv_inverts(a: int, m: int) -> None:
    """The inverse multiplies back to one, or there is no inverse.

    m is not required to be prime, so the second outcome is reachable
    and is half of what the function promises.
    """
    if math.gcd(a % m, m) != 1:
        with pytest.raises(BTClibValueError, match="no inverse"):
            mod_inv_var(a, m)
        return
    inverse = mod_inv_var(a, m)
    assert 0 <= inverse < m
    assert a * inverse % m == 1


@given(a=st.integers(), p=FIELD_PRIMES)
def test_mod_sqrt_squares_back(a: int, p: int) -> None:
    """A root squares back to what it is the root of, when there is one.

    legendre_symbol_var is what says whether there is: 1 for a residue, -1
    for a non-residue, 0 for a multiple of p. The three cases together
    are the whole domain, which is the point of generating a.
    """
    symbol = legendre_symbol_var(a, p)
    assert symbol in {-1, 0, 1}
    if symbol == -1:
        with pytest.raises(BTClibValueError, match="no root for "):
            mod_sqrt_var(a, p)
        return
    root = mod_sqrt_var(a, p)
    assert root * root % p == a % p
    # the other root, p - root, is a root too: a square has two
    assert (p - root) * (p - root) % p == a % p


def test_mod_inv_batch_is_mod_inv_over_a_sequence() -> None:
    """The batch answers what the inverses one at a time answer.

    The first and last elements included, which is where the peeling
    back off the running products stops and starts, and the empty
    sequence, which has no inverses and is not an error.
    """
    for m in (7, 97, 2**521 - 1):
        values = [1, 2, m - 1, 3, m - 2]
        assert mod_inv_batch_var(values, m) == [mod_inv_var(v, m) for v in values]
        assert mod_inv_batch_var([2], m) == [mod_inv_var(2, m)]
    assert mod_inv_batch_var([], 7) == []


def test_mod_inv_batch_names_the_element_that_has_no_inverse() -> None:
    """A product is invertible only if every factor is.

    So the batch fails whenever one element does, and names that element
    as `mod_inv_var` does rather than the product a caller never formed.
    """
    with pytest.raises(BTClibValueError, match="no inverse for 0 mod 7"):
        mod_inv_batch_var([1, 2, 0, 3], 7)
    with pytest.raises(BTClibValueError, match="no inverse for 3 mod 9"):
        mod_inv_batch_var([2, 3], 9)

    # the arguments are checked as every other function of the module
    # checks its own, a bool being no integer and zero no modulus
    for value in (2.0, True, None):
        with pytest.raises(BTClibTypeError, match="not an integer: "):
            mod_inv_batch_var([1, value], 7)  # type: ignore[list-item]
    for m in (0, -7, 3.0, False):
        with pytest.raises((BTClibTypeError, BTClibValueError)):
            mod_inv_batch_var([1], m)  # type: ignore[arg-type]


@given(values=st.lists(st.integers(), max_size=8), m=st.integers(min_value=2))
def test_mod_inv_batch_inverts(values: list[int], m: int) -> None:
    """Every inverse multiplies its element back to one, or none does."""
    if any(math.gcd(v % m, m) != 1 for v in values):
        with pytest.raises(BTClibValueError, match="no inverse"):
            mod_inv_batch_var(values, m)
        return
    inverses = mod_inv_batch_var(values, m)
    assert len(inverses) == len(values)
    for v, inverse in zip(values, inverses, strict=True):
        assert 0 <= inverse < m
        assert v * inverse % m == 1


def test_mod_inv_blinded_is_mod_inv() -> None:
    """The blinding changes what is timed and not what is answered.

    Over the primes above, which is what it is asked about in the
    library -- a group order -- and over composite moduli, where an
    element with no inverse still has none and is named as `mod_inv_var`
    names it. A modulus of one is the degenerate case: every integer is
    zero modulo it, so the only factor to draw with is one.
    """
    for m in primes:
        for a in range(1, min(m, 200)):
            assert mod_inv(a, m) == mod_inv_var(a, m)
            assert mod_inv(a + m, m) == mod_inv_var(a, m)

    for m in range(2, 60):
        for a in range(m):
            if math.gcd(a, m) == 1:
                assert mod_inv(a, m) == mod_inv_var(a, m)
            else:
                with pytest.raises(BTClibValueError, match="no inverse for "):
                    mod_inv(a, m)

    assert mod_inv(7, 1) == mod_inv_var(7, 1) == 0

    # the arguments are checked here rather than one call deeper: the
    # factor is drawn before `mod_inv_var` is reached, and a modulus that is
    # not an integer would fail in the draw instead
    for value in (2.0, True, None):
        with pytest.raises(BTClibTypeError, match="not an integer: "):
            mod_inv(value, 7)  # type: ignore[arg-type]
        with pytest.raises(BTClibTypeError, match="not an integer: "):
            mod_inv(3, value)  # type: ignore[arg-type]
    for m in (0, -7):
        with pytest.raises(BTClibValueError, match="non-positive modulus: "):
            mod_inv(3, m)


def test_mod_inv_blinded_never_hands_the_operand_to_the_euclid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """What the extended Euclid is timed on is a fresh random value.

    Which is the whole of what the blinding buys, `mod_inv_var`'s duration
    following what it is handed: the same secret inverted twice reaches
    it as two unrelated values, so the duration carries the factor and
    not the caller's operand.
    """
    seen: list[int] = []
    real_mod_inv = number_theory.mod_inv_var

    def recording_mod_inv(a: int, m: int) -> int:
        seen.append(a)
        return real_mod_inv(a, m)

    monkeypatch.setattr(number_theory, "mod_inv_var", recording_mod_inv)

    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    secret = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
    for _ in range(32):
        assert number_theory.mod_inv(secret, n) == real_mod_inv(secret, n)

    assert secret not in seen
    # every call drew its own factor: a repeat would be a factor that is
    # not fresh, and 32 draws below n repeat with probability 2^-246
    assert len(set(seen)) == len(seen)


def test_mod_inv_blinded_answers_a_factor_that_is_a_zero_divisor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A composite modulus can make the drawn factor non-invertible.

    The product is then non-invertible while the operand is not, and the
    answer still has to be the operand's inverse -- reached by inverting
    it unblinded, which is the one case where the protection is lost and
    the result is not. A prime modulus cannot take this path, and every
    modulus the library blinds against is one: `curves.Curve` requires
    the group order prime.
    """
    # 1 + randbelow(m - 1) == 2, a zero divisor mod 8
    monkeypatch.setattr(secrets, "randbelow", lambda _: 1)
    assert mod_inv(3, 8) == mod_inv_var(3, 8) == 3

    # and an operand that has no inverse of its own still reports one,
    # naming itself rather than the product the caller never formed
    with pytest.raises(BTClibValueError, match="no inverse for 2 mod 8"):
        mod_inv(2, 8)


@given(a=st.integers(), m=st.integers(min_value=1))
def test_mod_inv_blinded_inverts(a: int, m: int) -> None:
    """`test_mod_inv_inverts`, of the blinded spelling.

    m from one rather than from two: the degenerate modulus is a branch
    here, where `mod_inv_var` has none.
    """
    if math.gcd(a % m, m) != 1 and m != 1:
        with pytest.raises(BTClibValueError, match="no inverse"):
            mod_inv(a, m)
        return
    inverse = mod_inv(a, m)
    assert 0 <= inverse < m
    assert a * inverse % m == 1 % m
