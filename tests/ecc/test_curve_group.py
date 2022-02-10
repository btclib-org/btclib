#!/usr/bin/env python3

# Copyright (C) 2017-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.curve_group` module."

import secrets

import pytest

from btclib.alias import INF, INFJ
from btclib.ecc.curve import secp256k1
from btclib.ecc.curve_group import (
    MAX_W,
    _double_mult,
    _mult,
    _multi_mult,
    cached_multiples,
    jac_from_aff,
    mult_aff,
    mult_base_3,
    mult_fixed_window,
    mult_fixed_window_cached,
    mult_jac,
    mult_mont_ladder,
    mult_recursive_aff,
    mult_recursive_jac,
    multiples,
)
from btclib.ecc.pedersen import second_generator
from btclib.exceptions import BTClibValueError
from tests.ecc.test_curve import all_curves, low_card_curves

ec23_31 = low_card_curves["ec23_31"]


@pytest.mark.third
def test_mult_recursive_aff() -> None:
    for ec in all_curves.values():
        assert mult_recursive_aff(0, ec.G, ec) == INF
        assert mult_recursive_aff(0, INF, ec) == INF

        assert mult_recursive_aff(1, INF, ec) == INF
        assert mult_aff(1, ec.G, ec) == ec.G

        Q = ec.add_aff(ec.G, ec.G)
        assert Q == mult_recursive_aff(2, ec.G, ec)

        Q = mult_recursive_aff(ec.n - 1, ec.G, ec)
        assert ec.negate(ec.G) == Q
        assert mult_recursive_aff(ec.n - 1, INF, ec) == INF

        assert ec.add_aff(Q, ec.G) == INF
        assert mult_recursive_aff(ec.n, ec.G, ec) == INF
        assert mult_recursive_aff(ec.n, INF, ec) == INF

        with pytest.raises(BTClibValueError, match="negative m: "):
            mult_recursive_aff(-1, ec.G, ec)

    for ec in low_card_curves.values():
        for q in range(ec.n):
            Q = mult_recursive_aff(q, ec.G, ec)
            assert ec.is_on_curve(Q), f"{q}, {ec}"
            QJ = _mult(q, ec.GJ, ec)
            assert ec.is_on_curve(ec.aff_from_jac(QJ)), f"{q}, {ec}"
            assert Q == ec.aff_from_jac(QJ), f"{q}, {ec}"
            assert INF == mult_recursive_aff(q, INF, ec), f"{q}, {ec}"
            assert ec.jac_equality(INFJ, _mult(q, INFJ, ec)), f"{q}, {ec}"


def test_mult_recursive_jac() -> None:
    for ec in all_curves.values():
        assert ec.jac_equality(mult_recursive_jac(0, ec.GJ, ec), INFJ)
        assert ec.jac_equality(mult_recursive_jac(0, INFJ, ec), INFJ)

        assert ec.jac_equality(mult_recursive_jac(1, INFJ, ec), INFJ)
        assert ec.jac_equality(mult_recursive_jac(1, ec.GJ, ec), ec.GJ)

        PJ = ec.add_jac(ec.GJ, ec.GJ)
        assert ec.jac_equality(PJ, mult_recursive_jac(2, ec.GJ, ec))

        PJ = mult_recursive_jac(ec.n - 1, ec.GJ, ec)
        assert ec.jac_equality(ec.negate_jac(ec.GJ), PJ)
        assert ec.jac_equality(mult_recursive_jac(ec.n - 1, INFJ, ec), INFJ)

        assert ec.jac_equality(ec.add_jac(PJ, ec.GJ), INFJ)
        assert ec.jac_equality(mult_recursive_jac(ec.n, ec.GJ, ec), INFJ)
        assert ec.jac_equality(mult_recursive_jac(ec.n, INFJ, ec), INFJ)

        with pytest.raises(BTClibValueError, match="negative m: "):
            mult_recursive_jac(-1, ec.GJ, ec)

    ec = ec23_31
    for k1 in range(ec.n):
        K1 = mult_recursive_jac(k1, ec.GJ, ec)
        assert ec.jac_equality(K1, _mult(k1, ec.GJ, ec))


@pytest.mark.fourth
def test_mult_aff() -> None:
    for ec in all_curves.values():
        assert mult_aff(0, ec.G, ec) == INF
        assert mult_aff(0, INF, ec) == INF

        assert mult_aff(1, INF, ec) == INF
        assert mult_aff(1, ec.G, ec) == ec.G

        Q = ec.add_aff(ec.G, ec.G)
        assert Q == mult_aff(2, ec.G, ec)

        Q = mult_aff(ec.n - 1, ec.G, ec)
        assert ec.negate(ec.G) == Q
        assert mult_aff(ec.n - 1, INF, ec) == INF

        assert ec.add_aff(Q, ec.G) == INF
        assert mult_aff(ec.n, ec.G, ec) == INF
        assert mult_aff(ec.n, INF, ec) == INF

        with pytest.raises(BTClibValueError, match="negative m: "):
            mult_aff(-1, ec.G, ec)

    for ec in low_card_curves.values():
        for q in range(ec.n):
            Q = mult_aff(q, ec.G, ec)
            assert ec.is_on_curve(Q), f"{q}, {ec}"
            QJ = _mult(q, ec.GJ, ec)
            assert ec.is_on_curve(ec.aff_from_jac(QJ)), f"{q}, {ec}"
            assert Q == ec.aff_from_jac(QJ), f"{q}, {ec}"
            assert INF == mult_aff(q, INF, ec), f"{q}, {ec}"
            assert ec.jac_equality(INFJ, _mult(q, INFJ, ec)), f"{q}, {ec}"


def test_mult_jac() -> None:
    for ec in all_curves.values():
        assert ec.jac_equality(mult_jac(0, ec.GJ, ec), INFJ)
        assert ec.jac_equality(mult_jac(0, INFJ, ec), INFJ)

        assert ec.jac_equality(mult_jac(1, INFJ, ec), INFJ)
        assert ec.jac_equality(mult_jac(1, ec.GJ, ec), ec.GJ)

        PJ = ec.add_jac(ec.GJ, ec.GJ)
        assert ec.jac_equality(PJ, mult_jac(2, ec.GJ, ec))

        PJ = mult_jac(ec.n - 1, ec.GJ, ec)
        assert ec.jac_equality(ec.negate_jac(ec.GJ), PJ)
        assert ec.jac_equality(mult_jac(ec.n - 1, INFJ, ec), INFJ)

        assert ec.jac_equality(ec.add_jac(PJ, ec.GJ), INFJ)
        assert ec.jac_equality(mult_jac(ec.n, ec.GJ, ec), INFJ)
        assert ec.jac_equality(mult_jac(ec.n, INFJ, ec), INFJ)

        with pytest.raises(BTClibValueError, match="negative m: "):
            mult_jac(-1, ec.GJ, ec)

    ec = ec23_31
    for k1 in range(ec.n):
        K1 = mult_jac(k1, ec.GJ, ec)
        assert ec.jac_equality(K1, _mult(k1, ec.GJ, ec))


def test_mont_ladder() -> None:
    for ec in low_card_curves.values():
        assert ec.jac_equality(mult_mont_ladder(0, ec.GJ, ec), INFJ)
        assert ec.jac_equality(mult_mont_ladder(0, INFJ, ec), INFJ)

        assert ec.jac_equality(mult_mont_ladder(1, INFJ, ec), INFJ)
        assert ec.jac_equality(mult_mont_ladder(1, ec.GJ, ec), ec.GJ)

        PJ = mult_mont_ladder(2, ec.GJ, ec)
        assert ec.jac_equality(PJ, ec.add_jac(ec.GJ, ec.GJ))

        PJ = mult_mont_ladder(ec.n - 1, ec.GJ, ec)
        assert ec.jac_equality(ec.negate_jac(ec.GJ), PJ)
        assert ec.jac_equality(mult_mont_ladder(ec.n - 1, INFJ, ec), INFJ)

        assert ec.jac_equality(ec.add_jac(PJ, ec.GJ), INFJ)
        assert ec.jac_equality(mult_mont_ladder(ec.n, ec.GJ, ec), INFJ)
        assert ec.jac_equality(mult_mont_ladder(ec.n, INFJ, ec), INFJ)

        with pytest.raises(BTClibValueError, match="negative m: "):
            mult_mont_ladder(-1, ec.GJ, ec)

    ec = ec23_31
    for k1 in range(ec.n):
        K1 = mult_mont_ladder(k1, ec.GJ, ec)
        assert ec.jac_equality(K1, _mult(k1, ec.GJ, ec))


def test_mult_base_3() -> None:
    for ec in low_card_curves.values():
        assert ec.jac_equality(mult_base_3(0, ec.GJ, ec), INFJ)
        assert ec.jac_equality(mult_base_3(0, INFJ, ec), INFJ)

        assert ec.jac_equality(mult_base_3(1, INFJ, ec), INFJ)
        assert ec.jac_equality(mult_base_3(1, ec.GJ, ec), ec.GJ)

        PJ = mult_base_3(2, ec.GJ, ec)
        assert ec.jac_equality(PJ, ec.add_jac(ec.GJ, ec.GJ))

        PJ = mult_base_3(ec.n - 1, ec.GJ, ec)
        assert ec.jac_equality(ec.negate_jac(ec.GJ), PJ)
        assert ec.jac_equality(mult_base_3(ec.n - 1, INFJ, ec), INFJ)

        assert ec.jac_equality(ec.add_jac(PJ, ec.GJ), INFJ)
        assert ec.jac_equality(mult_base_3(ec.n, ec.GJ, ec), INFJ)
        assert ec.jac_equality(mult_mont_ladder(ec.n, INFJ, ec), INFJ)

        with pytest.raises(BTClibValueError, match="negative m: "):
            mult_base_3(-1, ec.GJ, ec)

    ec = ec23_31
    for k1 in range(ec.n):
        K1 = mult_base_3(k1, ec.GJ, ec)
        assert ec.jac_equality(K1, _mult(k1, ec.GJ, ec))


def test_cached_multiples() -> None:

    ec = secp256k1
    M = cached_multiples(ec.GJ, ec)
    assert len(M) == 2**MAX_W


def test_multiples() -> None:

    ec = secp256k1
    with pytest.raises(BTClibValueError, match="size too low: "):
        multiples(ec.GJ, 1, ec)

    T = [INFJ, ec.GJ]
    M = multiples(ec.GJ, 2, ec)
    assert len(M) == 2
    assert M == T

    T.append(ec.double_jac(ec.GJ))
    M = multiples(ec.GJ, 3, ec)
    assert len(M) == 3
    assert M == T

    T.append(ec.add_jac(T[-1], ec.GJ))
    M = multiples(ec.GJ, 4, ec)
    assert len(M) == 4
    assert M == T

    T.append(ec.double_jac(T[2]))
    M = multiples(ec.GJ, 5, ec)
    assert len(M) == 5
    assert M == T

    T.append(ec.add_jac(T[-1], ec.GJ))
    M = multiples(ec.GJ, 6, ec)
    assert len(M) == 6
    assert M == T

    T.append(ec.double_jac(T[3]))
    M = multiples(ec.GJ, 7, ec)
    assert len(M) == 7
    assert M == T

    T.append(ec.add_jac(T[-1], ec.GJ))
    M = multiples(ec.GJ, 8, ec)
    assert len(M) == 8
    assert M == T

    T.append(ec.double_jac(T[4]))
    M = multiples(ec.GJ, 9, ec)
    assert len(M) == 9
    assert M == T

    T.append(ec.add_jac(T[-1], ec.GJ))
    M = multiples(ec.GJ, 10, ec)
    assert len(M) == 10
    assert M == T


def test_mult_fixed_window() -> None:
    for w in range(1, MAX_W):
        for ec in low_card_curves.values():
            assert ec.jac_equality(mult_fixed_window(0, ec.GJ, ec, w), INFJ)
            assert ec.jac_equality(mult_fixed_window(0, INFJ, ec, w), INFJ)

            assert ec.jac_equality(mult_fixed_window(1, INFJ, ec, w), INFJ)
            assert ec.jac_equality(mult_fixed_window(1, ec.GJ, ec, w), ec.GJ)

            PJ = mult_fixed_window(2, ec.GJ, ec, w)
            assert ec.jac_equality(PJ, ec.add_jac(ec.GJ, ec.GJ))

            PJ = mult_fixed_window(ec.n - 1, ec.GJ, ec, w)
            assert ec.jac_equality(ec.negate_jac(ec.GJ), PJ)
            assert ec.jac_equality(mult_fixed_window(ec.n - 1, INFJ, ec, w), INFJ)

            assert ec.jac_equality(ec.add_jac(PJ, ec.GJ), INFJ)
            assert ec.jac_equality(mult_fixed_window(ec.n, ec.GJ, ec, w), INFJ)
            assert ec.jac_equality(mult_mont_ladder(ec.n, INFJ, ec), INFJ)

            with pytest.raises(BTClibValueError, match="negative m: "):
                mult_fixed_window(-1, ec.GJ, ec, w)

            with pytest.raises(BTClibValueError, match="non positive w: "):
                mult_fixed_window(1, ec.GJ, ec, -w)

    ec = ec23_31
    for w in range(1, 10):
        for k1 in range(ec.n):
            K1 = mult_fixed_window(k1, ec.GJ, ec, w)
            assert ec.jac_equality(K1, mult_jac(k1, ec.GJ, ec))


def test_mult_fixed_window_cached() -> None:
    for _ in range(1, MAX_W):
        for ec in low_card_curves.values():
            assert ec.jac_equality(mult_fixed_window_cached(0, ec.GJ, ec), INFJ)
            assert ec.jac_equality(mult_fixed_window_cached(0, INFJ, ec), INFJ)

            assert ec.jac_equality(mult_fixed_window_cached(1, INFJ, ec), INFJ)
            assert ec.jac_equality(mult_fixed_window_cached(1, ec.GJ, ec), ec.GJ)

            PJ = mult_fixed_window_cached(2, ec.GJ, ec)
            assert ec.jac_equality(PJ, ec.add_jac(ec.GJ, ec.GJ))

            PJ = mult_fixed_window_cached(ec.n - 1, ec.GJ, ec)
            assert ec.jac_equality(ec.negate_jac(ec.GJ), PJ)
            assert ec.jac_equality(mult_fixed_window_cached(ec.n - 1, INFJ, ec), INFJ)

            assert ec.jac_equality(ec.add_jac(PJ, ec.GJ), INFJ)
            assert ec.jac_equality(mult_fixed_window_cached(ec.n, ec.GJ, ec), INFJ)
            assert ec.jac_equality(mult_mont_ladder(ec.n, INFJ, ec), INFJ)

            with pytest.raises(BTClibValueError, match="negative m: "):
                mult_fixed_window_cached(-1, ec.GJ, ec)

            with pytest.raises(BTClibValueError, match="non positive w: "):
                mult_fixed_window_cached(1, ec.GJ, ec, -1)

    ec = ec23_31
    for w in range(1, 10):
        for k1 in range(ec.n):
            K1 = mult_fixed_window_cached(k1, ec.GJ, ec, w)
            assert ec.jac_equality(K1, mult_jac(k1, ec.GJ, ec))


def test_assorted_jac_mult() -> None:
    ec = ec23_31
    H = second_generator(ec)
    HJ = jac_from_aff(H)
    for k1 in range(ec.n):
        K1J = _mult(k1, ec.GJ, ec)
        for k2 in range(ec.n):
            K2J = _mult(k2, HJ, ec)

            shamir = _double_mult(k1, ec.GJ, k2, ec.GJ, ec)
            assert ec.is_on_curve(ec.aff_from_jac(shamir))
            assert ec.jac_equality(shamir, _mult(k1 + k2, ec.GJ, ec))

            shamir = _double_mult(k1, INFJ, k2, HJ, ec)
            assert ec.is_on_curve(ec.aff_from_jac(shamir))
            assert ec.jac_equality(shamir, K2J)

            shamir = _double_mult(k1, ec.GJ, k2, INFJ, ec)
            assert ec.is_on_curve(ec.aff_from_jac(shamir))
            assert ec.jac_equality(shamir, K1J)

            shamir = _double_mult(k1, ec.GJ, k2, HJ, ec)
            assert ec.is_on_curve(ec.aff_from_jac(shamir))
            K1JK2J = ec.add_jac(K1J, K2J)
            assert ec.jac_equality(K1JK2J, shamir)

            k3 = 1 + secrets.randbelow(ec.n - 1)
            K3J = _mult(k3, ec.GJ, ec)
            K1JK2JK3J = ec.add_jac(K1JK2J, K3J)
            assert ec.is_on_curve(ec.aff_from_jac(K1JK2JK3J))
            boscoster = _multi_mult([k1, k2, k3], [ec.GJ, HJ, ec.GJ], ec)
            assert ec.is_on_curve(ec.aff_from_jac(boscoster))
            assert ec.aff_from_jac(K1JK2JK3J) == ec.aff_from_jac(boscoster), k3
            assert ec.jac_equality(K1JK2JK3J, boscoster)

            k4 = 1 + secrets.randbelow(ec.n - 1)
            K4J = _mult(k4, HJ, ec)
            K1JK2JK3JK4J = ec.add_jac(K1JK2JK3J, K4J)
            assert ec.is_on_curve(ec.aff_from_jac(K1JK2JK3JK4J))
            points = [ec.GJ, HJ, ec.GJ, HJ]
            boscoster = _multi_mult([k1, k2, k3, k4], points, ec)
            assert ec.is_on_curve(ec.aff_from_jac(boscoster))
            assert ec.aff_from_jac(K1JK2JK3JK4J) == ec.aff_from_jac(boscoster), k4
            assert ec.jac_equality(K1JK2JK3JK4J, boscoster)
            assert ec.jac_equality(K1JK2JK3J, _multi_mult([k1, k2, k3, 0], points, ec))
            assert ec.jac_equality(K1JK2J, _multi_mult([k1, k2, 0, 0], points, ec))
            assert ec.jac_equality(K1J, _multi_mult([k1, 0, 0, 0], points, ec))
            assert ec.jac_equality(INFJ, _multi_mult([0, 0, 0, 0], points, ec))

            err_msg = "mismatch between number of scalars and points: "
            with pytest.raises(BTClibValueError, match=err_msg):
                _multi_mult([k1, k2, k3, k4], [ec.GJ, HJ, ec.GJ], ec)

            err_msg = "negative coefficient: "
            with pytest.raises(BTClibValueError, match=err_msg):
                _multi_mult([k1, k2, -k3], [ec.GJ, HJ, ec.GJ], ec)

    with pytest.raises(BTClibValueError, match="negative first coefficient: "):
        _double_mult(-5, HJ, 1, ec.GJ, ec)
    with pytest.raises(BTClibValueError, match="negative second coefficient: "):
        _double_mult(1, HJ, -5, ec.GJ, ec)


def test_jac_equality() -> None:

    ec = ec23_31
    assert ec.jac_equality(ec.GJ, jac_from_aff(ec.G))

    # q in [2, n-1], as the difference with ec.GJ is checked below
    q = 2 + secrets.randbelow(ec.n - 2)
    Q = mult_aff(q, ec.G, ec)
    QJ = _mult(q, ec.GJ, ec)
    assert ec.jac_equality(QJ, jac_from_aff(Q))
    assert not ec.jac_equality(QJ, ec.negate_jac(QJ))
    assert not ec.jac_equality(QJ, ec.GJ)


def test_INF() -> None:

    assert INF[1] == 0

    with pytest.raises(BTClibValueError, match="invalid x-coordinate: "):
        secp256k1.y(INF[0])
    with pytest.raises(BTClibValueError, match="invalid x-coordinate: "):
        secp256k1.y(INF[0] + secp256k1.n)
