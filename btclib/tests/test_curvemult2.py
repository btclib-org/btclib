#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for `btclib.curvemult2` module."

import pytest

from btclib.alias import INF, INFJ
from btclib.curvemult import double_mult, mult
from btclib.curvemult2 import (
    _mult_base_3,
    _mult_fixed_window,
    _mult_mont_ladder,
    _mult_sliding_window,
    _mult_w_NAF,
    mult_base_3,
    mult_fixed_window,
    mult_mont_ladder,
    mult_sliding_window,
    mult_w_NAF,
)
from btclib.pedersen import second_generator
from btclib.tests.test_curves import low_card_curves

ec23_31 = low_card_curves["ec23_31"]


def test_mont_ladder() -> None:
    for ec in low_card_curves.values():
        assert ec._jac_equality(_mult_mont_ladder(0, ec.GJ, ec), INFJ)
        assert ec._jac_equality(_mult_mont_ladder(0, INFJ, ec), INFJ)

        assert ec._jac_equality(_mult_mont_ladder(1, INFJ, ec), INFJ)
        assert ec._jac_equality(_mult_mont_ladder(1, ec.GJ, ec), ec.GJ)

        PJ = _mult_mont_ladder(2, ec.GJ, ec)
        assert ec._jac_equality(PJ, ec._add_jac(ec.GJ, ec.GJ))

        PJ = _mult_mont_ladder(ec.n - 1, ec.GJ, ec)
        assert ec._jac_equality(ec.negate_jac(ec.GJ), PJ)

        assert ec._jac_equality(_mult_mont_ladder(ec.n - 1, INFJ, ec), INFJ)
        assert ec._jac_equality(ec._add_jac(PJ, ec.GJ), INFJ)
        assert ec._jac_equality(_mult_mont_ladder(ec.n, ec.GJ, ec), INFJ)

        with pytest.raises(ValueError, match="negative m: "):
            _mult_mont_ladder(-1, ec.GJ, ec)


def test_assorted_mult_mont_ladder() -> None:
    ec = ec23_31
    H = second_generator(ec)

    for k1 in range(-ec.n + 1, ec.n):

        m = k1 % ec.n
        assert mult_mont_ladder(k1, None, ec) == ec._aff_from_jac(
            _mult_mont_ladder(m, ec.GJ, ec)
        )

        K1 = mult_mont_ladder(k1, ec.G, ec)
        assert K1 == mult(k1, ec.G, ec)

        for k2 in range(ec.n):
            K2 = mult_mont_ladder(k2, H, ec)

            shamir = double_mult(k1, ec.G, k2, ec.G, ec)
            assert shamir == mult_mont_ladder(k1 + k2, ec.G, ec)

            shamir = double_mult(k1, INF, k2, H, ec)
            assert shamir == K2
            shamir = double_mult(k1, ec.G, k2, INF, ec)
            assert shamir == K1

            shamir = double_mult(k1, ec.G, k2, H, ec)
            K1K2 = ec.add(K1, K2)
            assert K1K2 == shamir


def test_mult_base_3() -> None:
    for ec in low_card_curves.values():
        assert ec._jac_equality(_mult_base_3(0, ec.GJ, ec), INFJ)
        assert ec._jac_equality(_mult_base_3(0, INFJ, ec), INFJ)

        assert ec._jac_equality(_mult_base_3(1, INFJ, ec), INFJ)
        assert ec._jac_equality(_mult_base_3(1, ec.GJ, ec), ec.GJ)

        PJ = _mult_base_3(2, ec.GJ, ec)
        assert ec._jac_equality(PJ, ec._add_jac(ec.GJ, ec.GJ))

        PJ = _mult_base_3(ec.n - 1, ec.GJ, ec)
        assert ec._jac_equality(ec.negate_jac(ec.GJ), PJ)

        assert ec._jac_equality(_mult_base_3(ec.n - 1, INFJ, ec), INFJ)
        assert ec._jac_equality(ec._add_jac(PJ, ec.GJ), INFJ)
        assert ec._jac_equality(_mult_base_3(ec.n, ec.GJ, ec), INFJ)

        with pytest.raises(ValueError, match="negative m: "):
            _mult_base_3(-1, ec.GJ, ec)


def test_assorted_mult_base_3() -> None:
    ec = ec23_31
    H = second_generator(ec)

    for k1 in range(-ec.n + 1, ec.n):

        m = k1 % ec.n
        assert mult_base_3(k1, None, ec) == ec._aff_from_jac(_mult_base_3(m, ec.GJ, ec))

        K1 = mult_base_3(k1, ec.G, ec)
        assert K1 == mult(k1, ec.G, ec)

        for k2 in range(ec.n):
            K2 = mult_base_3(k2, H, ec)

            shamir = double_mult(k1, ec.G, k2, ec.G, ec)
            assert shamir == mult_base_3(k1 + k2, ec.G, ec)

            shamir = double_mult(k1, INF, k2, H, ec)
            assert shamir == K2
            shamir = double_mult(k1, ec.G, k2, INF, ec)
            assert shamir == K1

            shamir = double_mult(k1, ec.G, k2, H, ec)
            K1K2 = ec.add(K1, K2)
            assert K1K2 == shamir


def test_mult_fixed_window() -> None:
    for k in range(1, 10):  # Actually it makes use of w=4 or w=5, only to check
        for ec in low_card_curves.values():
            assert ec._jac_equality(_mult_fixed_window(0, k, ec.GJ, ec), INFJ)
            assert ec._jac_equality(_mult_fixed_window(0, k, INFJ, ec), INFJ)

            assert ec._jac_equality(_mult_fixed_window(1, k, INFJ, ec), INFJ)
            assert ec._jac_equality(_mult_fixed_window(1, k, ec.GJ, ec), ec.GJ)

            PJ = _mult_fixed_window(2, k, ec.GJ, ec)
            assert ec._jac_equality(PJ, ec._add_jac(ec.GJ, ec.GJ))

            PJ = _mult_fixed_window(ec.n - 1, k, ec.GJ, ec)
            assert ec._jac_equality(ec.negate_jac(ec.GJ), PJ)

            assert ec._jac_equality(_mult_fixed_window(ec.n - 1, k, INFJ, ec), INFJ)
            assert ec._jac_equality(ec._add_jac(PJ, ec.GJ), INFJ)
            assert ec._jac_equality(_mult_fixed_window(ec.n, k, ec.GJ, ec), INFJ)

            with pytest.raises(ValueError, match="negative m: "):
                _mult_fixed_window(-1, k, ec.GJ, ec)

            with pytest.raises(ValueError, match="non positive w: "):
                _mult_fixed_window(1, -k, ec.GJ, ec)


def test_assorted_mult_fixed_window() -> None:
    ec = ec23_31
    H = second_generator(ec)

    for w in range(1, 10):
        for k1 in range(-ec.n + 1, ec.n):

            m = k1 % ec.n
            assert mult_fixed_window(k1, w, None, ec) == ec._aff_from_jac(
                _mult_fixed_window(m, w, ec.GJ, ec)
            )

            K1 = mult_fixed_window(k1, w, ec.G, ec)
            assert K1 == mult(k1, ec.G, ec)

            for k2 in range(ec.n):
                K2 = mult_fixed_window(k2, w, H, ec)

                shamir = double_mult(k1, ec.G, k2, ec.G, ec)
                assert shamir == mult_fixed_window(k1 + k2, w, ec.G, ec)

                shamir = double_mult(k1, INF, k2, H, ec)
                assert shamir == K2
                shamir = double_mult(k1, ec.G, k2, INF, ec)
                assert shamir == K1

                shamir = double_mult(k1, ec.G, k2, H, ec)
                K1K2 = ec.add(K1, K2)
                assert K1K2 == shamir


def test_mult_sliding_window() -> None:
    for k in range(1, 10):  # Actually it makes use of w=4 or w=5, only to check
        for ec in low_card_curves.values():
            assert ec._jac_equality(_mult_sliding_window(0, k, ec.GJ, ec), INFJ)
            assert ec._jac_equality(_mult_sliding_window(0, k, INFJ, ec), INFJ)

            assert ec._jac_equality(_mult_sliding_window(1, k, INFJ, ec), INFJ)
            assert ec._jac_equality(_mult_sliding_window(1, k, ec.GJ, ec), ec.GJ)

            PJ = _mult_sliding_window(2, k, ec.GJ, ec)
            assert ec._jac_equality(PJ, ec._add_jac(ec.GJ, ec.GJ))

            PJ = _mult_sliding_window(ec.n - 1, k, ec.GJ, ec)
            assert ec._jac_equality(ec.negate_jac(ec.GJ), PJ)

            assert ec._jac_equality(_mult_sliding_window(ec.n - 1, k, INFJ, ec), INFJ)
            assert ec._jac_equality(ec._add_jac(PJ, ec.GJ), INFJ)
            assert ec._jac_equality(_mult_sliding_window(ec.n, k, ec.GJ, ec), INFJ)

            with pytest.raises(ValueError, match="negative m: "):
                _mult_sliding_window(-1, k, ec.GJ, ec)

            with pytest.raises(ValueError, match="non positive w: "):
                _mult_sliding_window(1, -k, ec.GJ, ec)


def test_assorted_mult_sliding_window() -> None:
    ec = ec23_31
    H = second_generator(ec)

    for w in range(1, 10):
        for k1 in range(-ec.n + 1, ec.n):

            m = k1 % ec.n
            assert mult_sliding_window(k1, w, None, ec) == ec._aff_from_jac(
                _mult_sliding_window(m, w, ec.GJ, ec)
            )

            K1 = mult_sliding_window(k1, w, ec.G, ec)
            assert K1 == mult(k1, ec.G, ec)

            for k2 in range(ec.n):
                K2 = mult_sliding_window(k2, w, H, ec)

                shamir = double_mult(k1, ec.G, k2, ec.G, ec)
                assert shamir == mult_sliding_window(k1 + k2, w, ec.G, ec)

                shamir = double_mult(k1, INF, k2, H, ec)
                assert shamir == K2
                shamir = double_mult(k1, ec.G, k2, INF, ec)
                assert shamir == K1

                shamir = double_mult(k1, ec.G, k2, H, ec)
                K1K2 = ec.add(K1, K2)
                assert K1K2 == shamir


def test_mult_w_NAF() -> None:
    # it does NOT work for k=1
    for k in range(2, 10):
        for ec in low_card_curves.values():
            assert ec._jac_equality(_mult_w_NAF(0, k, ec.GJ, ec), INFJ)
            assert ec._jac_equality(_mult_w_NAF(0, k, INFJ, ec), INFJ)

            assert ec._jac_equality(_mult_w_NAF(1, k, INFJ, ec), INFJ)
            assert ec._jac_equality(_mult_w_NAF(1, k, ec.GJ, ec), ec.GJ)

            PJ = _mult_w_NAF(2, k, ec.GJ, ec)
            assert ec._jac_equality(PJ, ec._add_jac(ec.GJ, ec.GJ))

            PJ = _mult_w_NAF(ec.n - 1, k, ec.GJ, ec)
            assert ec._jac_equality(ec.negate_jac(ec.GJ), PJ)

            assert ec._jac_equality(_mult_w_NAF(ec.n - 1, k, INFJ, ec), INFJ)
            assert ec._jac_equality(ec._add_jac(PJ, ec.GJ), INFJ)
            assert ec._jac_equality(_mult_w_NAF(ec.n, k, ec.GJ, ec), INFJ)

            with pytest.raises(ValueError, match="negative m: "):
                _mult_w_NAF(-1, k, ec.GJ, ec)

            with pytest.raises(ValueError, match="non positive w: "):
                _mult_w_NAF(1, -k, ec.GJ, ec)


def test_assorted_mult_w_NAF() -> None:
    ec = ec23_31
    H = second_generator(ec)

    for w in range(2, 10):
        for k1 in range(-ec.n + 1, ec.n):

            m = k1 % ec.n
            assert mult_w_NAF(k1, w, None, ec) == ec._aff_from_jac(
                _mult_w_NAF(m, w, ec.GJ, ec)
            )

            K1 = mult_w_NAF(k1, w, ec.G, ec)
            assert K1 == mult(k1, ec.G, ec)

            for k2 in range(ec.n):
                K2 = mult_w_NAF(k2, w, H, ec)

                shamir = double_mult(k1, ec.G, k2, ec.G, ec)
                assert shamir == mult_w_NAF(k1 + k2, w, ec.G, ec)

                shamir = double_mult(k1, INF, k2, H, ec)
                assert shamir == K2
                shamir = double_mult(k1, ec.G, k2, INF, ec)
                assert shamir == K1

                shamir = double_mult(k1, ec.G, k2, H, ec)
                K1K2 = ec.add(K1, K2)
                assert K1K2 == shamir
