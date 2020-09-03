#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for `btclib.curvegroup` module."

import secrets

import pytest

from btclib.alias import INF, INFJ
from btclib.curve import Curve
from btclib.curvegroup import (
    _double_mult,
    _jac_from_aff,
    _mult,
    _mult_aff,
    _mult_jac,
    _multi_mult,
)
from btclib.pedersen import second_generator
from btclib.tests.test_curve import all_curves, low_card_curves

ec23_31 = low_card_curves["ec23_31"]


@pytest.mark.third
def test_mult_aff() -> None:
    for ec in all_curves.values():
        assert _mult_aff(0, ec.G, ec) == INF
        assert _mult_aff(0, INF, ec) == INF

        assert _mult_aff(1, INF, ec) == INF
        assert _mult_aff(1, ec.G, ec) == ec.G

        P = ec._add_aff(ec.G, ec.G)
        assert P == _mult_aff(2, ec.G, ec)

        P = _mult_aff(ec.n - 1, ec.G, ec)
        assert ec.negate(ec.G) == P
        assert _mult_aff(ec.n - 1, INF, ec) == INF

        assert ec._add_aff(P, ec.G) == INF
        assert _mult_aff(ec.n, ec.G, ec) == INF
        assert _mult_aff(ec.n, INF, ec) == INF

        with pytest.raises(ValueError, match="negative m: "):
            _mult_aff(-1, ec.G, ec)


def test_mult_jac() -> None:
    for ec in all_curves.values():
        assert ec._jac_equality(_mult_jac(0, ec.GJ, ec), INFJ)
        assert ec._jac_equality(_mult_jac(0, INFJ, ec), INFJ)

        assert ec._jac_equality(_mult_jac(1, INFJ, ec), INFJ)
        assert ec._jac_equality(_mult_jac(1, ec.GJ, ec), ec.GJ)

        PJ = ec._add_jac(ec.GJ, ec.GJ)
        assert ec._jac_equality(PJ, _mult_jac(2, ec.GJ, ec))

        PJ = _mult_jac(ec.n - 1, ec.GJ, ec)
        assert ec._jac_equality(ec.negate_jac(ec.GJ), PJ)
        assert ec._jac_equality(_mult_jac(ec.n - 1, INFJ, ec), INFJ)

        assert ec._jac_equality(ec._add_jac(PJ, ec.GJ), INFJ)
        assert ec._jac_equality(_mult_jac(ec.n, ec.GJ, ec), INFJ)

        with pytest.raises(ValueError, match="negative m: "):
            _mult_jac(-1, ec.GJ, ec)


def test_assorted_jac_mult() -> None:
    ec = ec23_31
    H = second_generator(ec)
    HJ = _jac_from_aff(H)
    for k1 in range(ec.n):
        K1J = _mult(k1, ec.GJ, ec)
        for k2 in range(ec.n):
            K2J = _mult(k2, HJ, ec)

            shamir = _double_mult(k1, ec.GJ, k2, ec.GJ, ec)
            assert ec.is_on_curve(ec._aff_from_jac(shamir))
            assert ec._jac_equality(shamir, _mult(k1 + k2, ec.GJ, ec))

            shamir = _double_mult(k1, INFJ, k2, HJ, ec)
            assert ec.is_on_curve(ec._aff_from_jac(shamir))
            assert ec._jac_equality(shamir, K2J)

            shamir = _double_mult(k1, ec.GJ, k2, INFJ, ec)
            assert ec.is_on_curve(ec._aff_from_jac(shamir))
            assert ec._jac_equality(shamir, K1J)

            shamir = _double_mult(k1, ec.GJ, k2, HJ, ec)
            assert ec.is_on_curve(ec._aff_from_jac(shamir))
            K1JK2J = ec._add_jac(K1J, K2J)
            assert ec._jac_equality(K1JK2J, shamir)

            k3 = 1 + secrets.randbelow(ec.n - 1)
            K3J = _mult(k3, ec.GJ, ec)
            K1JK2JK3J = ec._add_jac(K1JK2J, K3J)
            assert ec.is_on_curve(ec._aff_from_jac(K1JK2JK3J))
            boscoster = _multi_mult([k1, k2, k3], [ec.GJ, HJ, ec.GJ], ec)
            assert ec.is_on_curve(ec._aff_from_jac(boscoster))
            assert ec._aff_from_jac(K1JK2JK3J) == ec._aff_from_jac(boscoster), k3
            assert ec._jac_equality(K1JK2JK3J, boscoster)

            k4 = 1 + secrets.randbelow(ec.n - 1)
            K4J = _mult(k4, HJ, ec)
            K1JK2JK3JK4J = ec._add_jac(K1JK2JK3J, K4J)
            assert ec.is_on_curve(ec._aff_from_jac(K1JK2JK3JK4J))
            points = [ec.GJ, HJ, ec.GJ, HJ]
            boscoster = _multi_mult([k1, k2, k3, k4], points, ec)
            assert ec.is_on_curve(ec._aff_from_jac(boscoster))
            assert ec._aff_from_jac(K1JK2JK3JK4J) == ec._aff_from_jac(boscoster), k4
            assert ec._jac_equality(K1JK2JK3JK4J, boscoster)
            assert ec._jac_equality(K1JK2JK3J, _multi_mult([k1, k2, k3, 0], points, ec))
            assert ec._jac_equality(K1JK2J, _multi_mult([k1, k2, 0, 0], points, ec))
            assert ec._jac_equality(K1J, _multi_mult([k1, 0, 0, 0], points, ec))
            assert ec._jac_equality(INFJ, _multi_mult([0, 0, 0, 0], points, ec))

    err_msg = "mismatch between number of scalars and points: "
    with pytest.raises(ValueError, match=err_msg):
        _multi_mult([k1, k2, k3, k4], [ec.GJ, HJ, ec.GJ], ec)

    err_msg = "negative coefficient: "
    with pytest.raises(ValueError, match=err_msg):
        _multi_mult([k1, k2, -k3], [ec.GJ, HJ, ec.GJ], ec)

    with pytest.raises(ValueError, match="negative first coefficient: "):
        _double_mult(-5, HJ, 1, ec.GJ, ec)
    with pytest.raises(ValueError, match="negative second coefficient: "):
        _double_mult(1, HJ, -5, ec.GJ, ec)


def test_jac_equality() -> None:

    ec = Curve(13, 0, 2, (1, 9), 19, 1, False)
    assert ec._jac_equality(ec.GJ, _jac_from_aff(ec.G))

    # q in [2, n-1], as the difference with ec.GJ is checked below
    q = 2 + secrets.randbelow(ec.n - 2)
    Q = _mult_aff(q, ec.G, ec)
    QJ = _mult(q, ec.GJ, ec)
    assert ec._jac_equality(QJ, _jac_from_aff(Q))
    assert not ec._jac_equality(QJ, ec.negate_jac(QJ))
    assert not ec._jac_equality(QJ, ec.GJ)


def test_mult() -> None:
    for ec in low_card_curves.values():
        for q in range(ec.n):
            Q = _mult_aff(q, ec.G, ec)
            assert ec.is_on_curve(Q), f"{q}, {ec}"
            QJ = _mult(q, ec.GJ, ec)
            assert ec.is_on_curve(ec._aff_from_jac(QJ)), f"{q}, {ec}"
            assert Q == ec._aff_from_jac(QJ), f"{q}, {ec}"
        assert INF == _mult_aff(q, INF, ec), f"{q}, {ec}"
        assert ec._jac_equality(INFJ, _mult(q, INFJ, ec)), f"{q}, {ec}"
