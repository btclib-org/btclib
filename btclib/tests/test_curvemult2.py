#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for `btclib.curvemult2` module."

import pytest

from btclib.alias import INFJ
from btclib.curvegroup import _mult_jac
from btclib.curvemult2 import (
    _mult_base_3,
    _mult_fixed_window,
    _mult_mont_ladder,
    _mult_sliding_window,
    _mult_w_NAF,
)
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

    ec = ec23_31
    for k1 in range(ec.n):
        K1 = _mult_mont_ladder(k1, ec.GJ, ec)
        assert ec._jac_equality(K1, _mult_jac(k1, ec.GJ, ec))


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

    ec = ec23_31
    for k1 in range(ec.n):
        K1 = _mult_base_3(k1, ec.GJ, ec)
        assert ec._jac_equality(K1, _mult_jac(k1, ec.GJ, ec))


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

    ec = ec23_31
    for w in range(1, 10):
        for k1 in range(ec.n):
            K1 = _mult_fixed_window(k1, w, ec.GJ, ec)
            assert ec._jac_equality(K1, _mult_jac(k1, ec.GJ, ec))


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

    ec = ec23_31
    for w in range(1, 10):
        for k1 in range(ec.n):
            K1 = _mult_sliding_window(k1, w, ec.GJ, ec)
            assert ec._jac_equality(K1, _mult_jac(k1, ec.GJ, ec))


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

    ec = ec23_31
    for w in range(2, 10):
        for k1 in range(ec.n):
            K1 = _mult_w_NAF(k1, w, ec.GJ, ec)
            assert ec._jac_equality(K1, _mult_jac(k1, ec.GJ, ec))
