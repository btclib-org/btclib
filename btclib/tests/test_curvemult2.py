#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for `btclib.curvemult2` module."

import pytest

from btclib.alias import INFJ
from btclib.curvemult2 import (
    _mult_jac_base_3,
    _mult_jac_fixed_window,
    _mult_jac_mont_ladder,
    _mult_jac_sliding_window,
    _mult_jac_w_NAF,
)
from btclib.tests.test_curves import low_card_curves

ec23_31 = low_card_curves["ec23_31"]


def test_mont_ladder():
    for ec in low_card_curves.values():
        assert _mult_jac_mont_ladder(0, ec.GJ, ec) == INFJ
        assert _mult_jac_mont_ladder(0, INFJ, ec) == INFJ

        assert _mult_jac_mont_ladder(1, INFJ, ec) == INFJ
        assert _mult_jac_mont_ladder(1, ec.GJ, ec) == ec.GJ

        PJ = ec._add_jac(ec.GJ, ec.GJ)
        assert PJ == _mult_jac_mont_ladder(2, ec.GJ, ec)

        PJ = _mult_jac_mont_ladder(ec.n - 1, ec.GJ, ec)
        assert ec._jac_equality(ec.negate_jac(ec.GJ), PJ)

        assert _mult_jac_mont_ladder(ec.n - 1, INFJ, ec) == INFJ
        assert ec._add_jac(PJ, ec.GJ) == INFJ
        assert _mult_jac_mont_ladder(ec.n, ec.GJ, ec) == INFJ

        with pytest.raises(ValueError, match="negative m: "):
            _mult_jac_mont_ladder(-1, ec.GJ, ec)


def test_mult_jac_base_3():
    for ec in low_card_curves.values():
        assert _mult_jac_base_3(0, ec.GJ, ec) == INFJ
        assert _mult_jac_base_3(0, INFJ, ec) == INFJ

        assert _mult_jac_base_3(1, INFJ, ec) == INFJ
        assert _mult_jac_base_3(1, ec.GJ, ec) == ec.GJ

        PJ = ec._add_jac(ec.GJ, ec.GJ)
        assert PJ == _mult_jac_base_3(2, ec.GJ, ec)

        PJ = _mult_jac_base_3(ec.n - 1, ec.GJ, ec)
        assert ec._jac_equality(ec.negate_jac(ec.GJ), PJ)

        assert _mult_jac_base_3(ec.n - 1, INFJ, ec) == INFJ
        assert ec._add_jac(PJ, ec.GJ) == INFJ
        assert _mult_jac_base_3(ec.n, ec.GJ, ec) == INFJ

        with pytest.raises(ValueError, match="negative m: "):
            _mult_jac_base_3(-1, ec.GJ, ec)


def test_mult_jac_fixed_window():
    for k in range(1, 10):  # Actually it makes use of w=4 or w=5, only to check
        for ec in low_card_curves.values():
            assert _mult_jac_fixed_window(0, k, ec.GJ, ec) == INFJ
            assert _mult_jac_fixed_window(0, k, INFJ, ec) == INFJ

            assert _mult_jac_fixed_window(1, k, INFJ, ec) == INFJ
            assert _mult_jac_fixed_window(1, k, ec.GJ, ec) == ec.GJ

            PJ = ec._add_jac(ec.GJ, ec.GJ)
            assert PJ == _mult_jac_fixed_window(2, k, ec.GJ, ec)

            PJ = _mult_jac_fixed_window(ec.n - 1, k, ec.GJ, ec)
            assert ec._jac_equality(ec.negate_jac(ec.GJ), PJ)

            assert _mult_jac_fixed_window(ec.n - 1, k, INFJ, ec) == INFJ
            assert ec._add_jac(PJ, ec.GJ) == INFJ
            assert _mult_jac_fixed_window(ec.n, k, ec.GJ, ec) == INFJ

            with pytest.raises(ValueError, match="negative m: "):
                _mult_jac_fixed_window(-1, k, ec.GJ, ec)


def test_mult_jac_sliding_window():
    for k in range(1, 10):  # Actually it makes use of w=4 or w=5, only to check
        for ec in low_card_curves.values():
            assert _mult_jac_sliding_window(0, k, ec.GJ, ec) == INFJ
            assert _mult_jac_sliding_window(0, k, INFJ, ec) == INFJ

            assert _mult_jac_sliding_window(1, k, INFJ, ec) == INFJ
            assert _mult_jac_sliding_window(1, k, ec.GJ, ec) == ec.GJ

            PJ = ec._add_jac(ec.GJ, ec.GJ)
            assert PJ == _mult_jac_sliding_window(2, k, ec.GJ, ec)

            PJ = _mult_jac_sliding_window(ec.n - 1, k, ec.GJ, ec)
            assert ec._jac_equality(ec.negate_jac(ec.GJ), PJ)

            assert _mult_jac_sliding_window(ec.n - 1, k, INFJ, ec) == INFJ
            assert ec._add_jac(PJ, ec.GJ) == INFJ
            assert _mult_jac_sliding_window(ec.n, k, ec.GJ, ec) == INFJ

            with pytest.raises(ValueError, match="negative m: "):
                _mult_jac_sliding_window(-1, k, ec.GJ, ec)


# it does NOT work for k=1
def test_mult_jac_w_NAF():
    for k in range(2, 10):
        for ec in low_card_curves.values():
            assert _mult_jac_w_NAF(0, k, ec.GJ, ec) == INFJ
            assert _mult_jac_w_NAF(0, k, INFJ, ec) == INFJ

            assert _mult_jac_w_NAF(1, k, INFJ, ec) == INFJ
            assert _mult_jac_w_NAF(1, k, ec.GJ, ec) == ec.GJ

            PJ = ec._add_jac(ec.GJ, ec.GJ)
            assert PJ == _mult_jac_w_NAF(2, k, ec.GJ, ec)

            PJ = _mult_jac_w_NAF(ec.n - 1, k, ec.GJ, ec)
            assert ec._jac_equality(ec.negate_jac(ec.GJ), PJ)

            assert _mult_jac_w_NAF(ec.n - 1, k, INFJ, ec) == INFJ
            assert ec._add_jac(PJ, ec.GJ) == INFJ
            assert _mult_jac_w_NAF(ec.n, k, ec.GJ, ec) == INFJ

            with pytest.raises(ValueError, match="negative m: "):
                _mult_jac_w_NAF(-1, k, ec.GJ, ec)
