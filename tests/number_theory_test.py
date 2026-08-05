# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.number_theory` module."""

import math

import pytest
from hypothesis import given
from hypothesis import strategies as st

from btclib.exceptions import BTClibValueError
from btclib.number_theory import legendre_symbol, mod_inv, mod_sqrt, tonelli, xgcd

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


def test_mod_inv_prime() -> None:
    """Verify the inverse mod a prime, and refuse the zero residue."""
    for p in primes:
        with pytest.raises(BTClibValueError, match="no inverse for 0 mod"):
            mod_inv(0, p)
        for a in range(1, min(p, 500)):  # exhausted only for small p
            inv = mod_inv(a, p)
            assert a * inv % p == 1
            inv = mod_inv(a + p, p)
            assert a * inv % p == 1


def test_mod_inv() -> None:
    """Verify mod_inv over every residue of every modulus up to 100."""
    max_m = 100
    for m in range(2, max_m):
        nums = list(range(m))
        for a in nums:
            mult = [a * i % m for i in nums]
            if 1 in mult:
                inv = mod_inv(a, m)
                assert a * inv % m == 1
                inv = mod_inv(a + m, m)
                assert a * inv % m == 1
            else:
                err_msg = "no inverse for "
                with pytest.raises(BTClibValueError, match=err_msg):
                    mod_inv(a, m)


def test_mod_sqrt() -> None:
    """Verify both roots of every residue, exhaustively on small primes."""
    for p in primes[:30]:  # exhaustable only for small p
        has_root = {0, 1}
        for i in range(2, p):
            has_root.add(i * i % p)
        for i in range(p):
            if i in has_root:
                root1 = mod_sqrt(i, p)
                assert i == (root1 * root1) % p
                root2 = p - root1
                assert i == (root2 * root2) % p
                root = mod_sqrt(i + p, p)
                assert i == (root * root) % p
                if p % 4 == 3 or p % 8 == 5:
                    assert tonelli(i, p) in (root1, root2)
            else:
                with pytest.raises(BTClibValueError, match="no root for "):
                    mod_sqrt(i, p)


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
        root = tonelli(i, p)
        assert i == (root * root) % p


def test_minus_one_quadr_res() -> None:
    """Ensure that if p = 3 (mod 4) then p - 1 is not a quadratic residue."""
    for p in primes:
        if (p % 4) == 3:
            with pytest.raises(BTClibValueError, match="no root for "):
                mod_sqrt(p - 1, p)
        else:
            assert p == 2 or p % 4 == 1, "something is badly broken"
            root = mod_sqrt(p - 1, p)
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


@given(a=st.integers(), b=st.integers())
def test_xgcd_is_bezout(a: int, b: int) -> None:
    """What xgcd returns is the identity it is named after."""
    g, x, y = xgcd(a, b)
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
            mod_inv(a, m)
        return
    inverse = mod_inv(a, m)
    assert 0 <= inverse < m
    assert a * inverse % m == 1


@given(a=st.integers(), p=FIELD_PRIMES)
def test_mod_sqrt_squares_back(a: int, p: int) -> None:
    """A root squares back to what it is the root of, when there is one.

    legendre_symbol is what says whether there is: 1 for a residue, -1
    for a non-residue, 0 for a multiple of p. The three cases together
    are the whole domain, which is the point of generating a.
    """
    symbol = legendre_symbol(a, p)
    assert symbol in (-1, 0, 1)
    if symbol == -1:
        with pytest.raises(BTClibValueError, match="no root for "):
            mod_sqrt(a, p)
        return
    root = mod_sqrt(a, p)
    assert root * root % p == a % p
    # the other root, p - root, is a root too: a square has two
    assert (p - root) * (p - root) % p == a % p
