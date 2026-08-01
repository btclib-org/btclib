#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the `btclib.curve_group_2` module."""

import secrets

import pytest

from btclib.alias import INFJ
from btclib.curves import secp256k1
from btclib.curves.curve_group import _double_mult, _mult

# from the module that defines them: btclib.curves no longer exports the
# individual multiplication implementations
from btclib.curves.curve_group_2 import (
    _LAM,
    _N,
    double_mult_w_NAF,
    mult_endomorphism_secp256k1,
    mult_sliding_window,
    mult_w_NAF,
    multiplier_decomposer,
)
from btclib.exceptions import BTClibValueError
from tests.curves.curve_test import low_card_curves

ec23_31 = low_card_curves["ec23_31"]


def test_mult_sliding_window() -> None:
    for w in range(1, 6):
        for ec in low_card_curves.values():
            assert ec.jac_equality(mult_sliding_window(0, ec.GJ, ec, w), INFJ)
            assert ec.jac_equality(mult_sliding_window(0, INFJ, ec, w), INFJ)

            assert ec.jac_equality(mult_sliding_window(1, INFJ, ec, w), INFJ)
            assert ec.jac_equality(mult_sliding_window(1, ec.GJ, ec, w), ec.GJ)

            PJ = mult_sliding_window(2, ec.GJ, ec, w)
            assert ec.jac_equality(PJ, ec.add_jac(ec.GJ, ec.GJ))

            PJ = mult_sliding_window(ec.n - 1, ec.GJ, ec, w)
            assert ec.jac_equality(ec.negate_jac(ec.GJ), PJ)

            assert ec.jac_equality(mult_sliding_window(ec.n - 1, INFJ, ec, w), INFJ)
            assert ec.jac_equality(ec.add_jac(PJ, ec.GJ), INFJ)
            assert ec.jac_equality(mult_sliding_window(ec.n, ec.GJ, ec, w), INFJ)

            with pytest.raises(BTClibValueError, match="negative m: "):
                mult_sliding_window(-1, ec.GJ, ec, w)

            with pytest.raises(BTClibValueError, match="non positive w: "):
                mult_sliding_window(1, ec.GJ, ec, -w)

    ec = ec23_31
    for w in range(1, 10):
        for k1 in range(ec.n):
            K1 = mult_sliding_window(k1, ec.GJ, ec, w)
            assert ec.jac_equality(K1, _mult(k1, ec.GJ, ec))


def test_mult_w_NAF() -> None:
    for w in range(1, 6):
        for ec in low_card_curves.values():
            assert ec.jac_equality(mult_w_NAF(0, ec.GJ, ec, w), INFJ)
            assert ec.jac_equality(mult_w_NAF(0, INFJ, ec, w), INFJ)

            assert ec.jac_equality(mult_w_NAF(1, INFJ, ec, w), INFJ)
            assert ec.jac_equality(mult_w_NAF(1, ec.GJ, ec, w), ec.GJ)

            PJ = mult_w_NAF(2, ec.GJ, ec, w)
            assert ec.jac_equality(PJ, ec.add_jac(ec.GJ, ec.GJ))

            PJ = mult_w_NAF(ec.n - 1, ec.GJ, ec, w)
            assert ec.jac_equality(ec.negate_jac(ec.GJ), PJ)

            assert ec.jac_equality(mult_w_NAF(ec.n - 1, INFJ, ec, w), INFJ)
            assert ec.jac_equality(ec.add_jac(PJ, ec.GJ), INFJ)
            assert ec.jac_equality(mult_w_NAF(ec.n, ec.GJ, ec, w), INFJ)

            with pytest.raises(BTClibValueError, match="negative m: "):
                mult_w_NAF(-1, ec.GJ, ec, w)

            with pytest.raises(BTClibValueError, match="non positive w: "):
                mult_w_NAF(1, ec.GJ, ec, -w)

    ec = ec23_31
    for w in range(1, 10):
        for k1 in range(ec.n):
            K1 = mult_w_NAF(k1, ec.GJ, ec, w)
            assert ec.jac_equality(K1, _mult(k1, ec.GJ, ec))


def test_mult_endomorphism_secp256k1() -> None:
    ec = secp256k1
    assert ec.jac_equality(mult_endomorphism_secp256k1(0, ec.GJ, ec), INFJ)
    assert ec.jac_equality(mult_endomorphism_secp256k1(0, INFJ, ec), INFJ)

    assert ec.jac_equality(mult_endomorphism_secp256k1(1, INFJ, ec), INFJ)
    assert ec.jac_equality(mult_endomorphism_secp256k1(1, ec.GJ, ec), ec.GJ)

    PJ = mult_endomorphism_secp256k1(2, ec.GJ, ec)
    assert ec.jac_equality(PJ, ec.add_jac(ec.GJ, ec.GJ))

    PJ = mult_endomorphism_secp256k1(ec.n - 1, ec.GJ, ec)
    assert ec.jac_equality(ec.negate_jac(ec.GJ), PJ)

    assert ec.jac_equality(mult_endomorphism_secp256k1(ec.n - 1, INFJ, ec), INFJ)
    assert ec.jac_equality(ec.add_jac(PJ, ec.GJ), INFJ)
    assert ec.jac_equality(mult_endomorphism_secp256k1(ec.n, ec.GJ, ec), INFJ)

    with pytest.raises(BTClibValueError, match="negative m: "):
        mult_endomorphism_secp256k1(-1, ec.GJ, ec)


def test_mult_endomorphism_agrees_with_mult_above_2_127() -> None:
    """The scalars the broken decomposition got wrong (issue #215).

    Every value the older test pinned -- 0, 1, 2, n-1, n -- decomposes
    correctly even mod p, because p and n share their top 128 bits and a
    scalar below ~2^127 never reaches the bits where they differ. So the
    test to have is agreement with _mult across that line: the fixed
    scalars stepping over it, the two cube roots whose decompositions are
    the identity ones, and a spread of full-size scalars. Before the fix
    every scalar of this test above 2^127 failed.
    """
    ec = secp256k1
    scalars = [
        (1 << 127) - 1,  # the last scalar the mod-p decomposition survived
        1 << 127,
        (1 << 128) - 1,  # both halves negative
        _LAM,  # decomposes to (0, 1): the endomorphism itself
        _N - _LAM,  # (0, -1): the endomorphism, negated
        _N - 2,
        # a full-size scalar with no structure: the SHA256 of b"btclib"
        0x7118B2DE7044D38B8A6CCD65B64E18BCB451C61A6E2344341FC972F522B70FDA % _N,
    ] + [secrets.randbelow(_N) for _ in range(8)]
    for m in scalars:
        expected = _mult(m, ec.GJ, ec)
        assert ec.jac_equality(mult_endomorphism_secp256k1(m, ec.GJ, ec), expected)


def test_multiplier_decomposer() -> None:
    """Balanced length-two representation: short, signed, congruent.

    The three properties algorithm 3.74 promises, each of which the
    mod-p version broke (issue #215), plus the five decompositions that
    are exact by construction: the identities of the lattice. A negative
    or oversized m reduces mod n first, so every integer decomposes and
    the caller owns the sign handling.
    """
    # the identity decompositions, exact values rather than properties
    assert multiplier_decomposer(0) == (0, 0)
    assert multiplier_decomposer(1) == (1, 0)
    assert multiplier_decomposer(_N - 1) == (-1, 0)
    assert multiplier_decomposer(_LAM) == (0, 1)
    assert multiplier_decomposer(_N - _LAM) == (0, -1)
    # reduction mod n first: -7 is n - 7, whose balanced form is -7
    assert multiplier_decomposer(-7) == (-7, 0)
    assert multiplier_decomposer(_N + 42) == (42, 0)

    scalars = [1 << 127, (1 << 128) - 1, _N - 2, _LAM - 1, _LAM + 1] + [
        secrets.randbelow(_N) for _ in range(20)
    ]
    for m in scalars:
        m1, m2 = multiplier_decomposer(m)
        # congruent: m1 + m2*lambda is m mod n, which is the identity
        # making m1*Q + m2*(lambda*Q) equal m*Q
        assert (m1 + m2 * _LAM - m) % _N == 0
        # short and signed: both halves fit 129 bits, sign included,
        # against the 256 both reached when the results were % p
        assert m1.bit_length() <= 129
        assert m2.bit_length() <= 129


def test_double_mult_w_NAF() -> None:
    """Interleaved-wNAF double mult against the Shamir-Strauss one.

    Exhaustive over every (u, v) pair of two low-cardinality curves --
    including u or v of 0, whose wNAF is empty -- and for w of 1, where
    the tables collapse to the points themselves and every digit is +-1.
    """
    for ec in (low_card_curves["ec13_11"], ec23_31):
        HJ = ec.GJ
        QJ = _mult(3, ec.GJ, ec)
        for w in (1, 2, 4):
            for u in range(ec.n):
                for v in range(ec.n):
                    expected = _double_mult(u, HJ, v, QJ, ec)
                    got = double_mult_w_NAF(u, HJ, v, QJ, ec, w)
                    assert ec.jac_equality(got, expected), (u, v, w)

    ec = secp256k1
    assert ec.jac_equality(double_mult_w_NAF(0, ec.GJ, 0, ec.GJ, ec), INFJ)
    with pytest.raises(BTClibValueError, match="negative first coefficient: "):
        double_mult_w_NAF(-1, ec.GJ, 1, ec.GJ, ec)
    with pytest.raises(BTClibValueError, match="negative second coefficient: "):
        double_mult_w_NAF(1, ec.GJ, -1, ec.GJ, ec)
    with pytest.raises(BTClibValueError, match="non positive w: "):
        double_mult_w_NAF(1, ec.GJ, 1, ec.GJ, ec, 0)
