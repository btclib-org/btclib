#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.curve_group_2` module."

import pytest

from btclib.alias import INFJ
from btclib.curve import secp256k1
from btclib.curve_group import _mult
from btclib.curve_group_2 import (
    _mult_endomorphism_secp256k1,
    _mult_sliding_window,
    _mult_w_NAF,
)
from btclib.exceptions import BTClibValueError
from btclib.tests.test_curve import low_card_curves

ec23_31 = low_card_curves["ec23_31"]


def test_mult_sliding_window() -> None:
    for w in range(1, 6):
        for ec in low_card_curves.values():
            assert ec._jac_equality(_mult_sliding_window(0, ec.GJ, ec, w), INFJ)
            assert ec._jac_equality(_mult_sliding_window(0, INFJ, ec, w), INFJ)

            assert ec._jac_equality(_mult_sliding_window(1, INFJ, ec, w), INFJ)
            assert ec._jac_equality(_mult_sliding_window(1, ec.GJ, ec, w), ec.GJ)

            PJ = _mult_sliding_window(2, ec.GJ, ec, w)
            assert ec._jac_equality(PJ, ec._add_jac(ec.GJ, ec.GJ))

            PJ = _mult_sliding_window(ec.n - 1, ec.GJ, ec, w)
            assert ec._jac_equality(ec.negate_jac(ec.GJ), PJ)

            assert ec._jac_equality(_mult_sliding_window(ec.n - 1, INFJ, ec, w), INFJ)
            assert ec._jac_equality(ec._add_jac(PJ, ec.GJ), INFJ)
            assert ec._jac_equality(_mult_sliding_window(ec.n, ec.GJ, ec, w), INFJ)

            with pytest.raises(BTClibValueError, match="negative m: "):
                _mult_sliding_window(-1, ec.GJ, ec, w)

            with pytest.raises(BTClibValueError, match="non positive w: "):
                _mult_sliding_window(1, ec.GJ, ec, -w)

    ec = ec23_31
    for w in range(1, 10):
        for k1 in range(ec.n):
            K1 = _mult_sliding_window(k1, ec.GJ, ec, w)
            assert ec._jac_equality(K1, _mult(k1, ec.GJ, ec))


def test_mult_w_NAF() -> None:
    for w in range(1, 6):
        for ec in low_card_curves.values():
            assert ec._jac_equality(_mult_w_NAF(0, ec.GJ, ec, w), INFJ)
            assert ec._jac_equality(_mult_w_NAF(0, INFJ, ec, w), INFJ)

            assert ec._jac_equality(_mult_w_NAF(1, INFJ, ec, w), INFJ)
            assert ec._jac_equality(_mult_w_NAF(1, ec.GJ, ec, w), ec.GJ)

            PJ = _mult_w_NAF(2, ec.GJ, ec, w)
            assert ec._jac_equality(PJ, ec._add_jac(ec.GJ, ec.GJ))

            PJ = _mult_w_NAF(ec.n - 1, ec.GJ, ec, w)
            assert ec._jac_equality(ec.negate_jac(ec.GJ), PJ)

            assert ec._jac_equality(_mult_w_NAF(ec.n - 1, INFJ, ec, w), INFJ)
            assert ec._jac_equality(ec._add_jac(PJ, ec.GJ), INFJ)
            assert ec._jac_equality(_mult_w_NAF(ec.n, ec.GJ, ec, w), INFJ)

            with pytest.raises(BTClibValueError, match="negative m: "):
                _mult_w_NAF(-1, ec.GJ, ec, w)

            with pytest.raises(BTClibValueError, match="non positive w: "):
                _mult_w_NAF(1, ec.GJ, ec, -w)

    ec = ec23_31
    for w in range(1, 10):
        for k1 in range(ec.n):
            K1 = _mult_w_NAF(k1, ec.GJ, ec, w)
            assert ec._jac_equality(K1, _mult(k1, ec.GJ, ec))


def test_mult_endomorphism_secp256k1() -> None:
    ec = secp256k1
    assert ec._jac_equality(_mult_endomorphism_secp256k1(0, ec.GJ, ec), INFJ)
    assert ec._jac_equality(_mult_endomorphism_secp256k1(0, INFJ, ec), INFJ)

    assert ec._jac_equality(_mult_endomorphism_secp256k1(1, INFJ, ec), INFJ)
    assert ec._jac_equality(_mult_endomorphism_secp256k1(1, ec.GJ, ec), ec.GJ)

    PJ = _mult_endomorphism_secp256k1(2, ec.GJ, ec)
    assert ec._jac_equality(PJ, ec._add_jac(ec.GJ, ec.GJ))

    PJ = _mult_endomorphism_secp256k1(ec.n - 1, ec.GJ, ec)
    assert ec._jac_equality(ec.negate_jac(ec.GJ), PJ)

    assert ec._jac_equality(_mult_endomorphism_secp256k1(ec.n - 1, INFJ, ec), INFJ)
    assert ec._jac_equality(ec._add_jac(PJ, ec.GJ), INFJ)
    assert ec._jac_equality(_mult_endomorphism_secp256k1(ec.n, ec.GJ, ec), INFJ)

    with pytest.raises(ValueError, match="negative m: "):
        _mult_endomorphism_secp256k1(-1, ec.GJ, ec)
