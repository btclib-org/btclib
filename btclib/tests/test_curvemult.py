#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for `btclib.curvemult` module."

import secrets

import pytest

from btclib.alias import INF, INFJ
from btclib.curvegroup import (
    _double_mult,
    _jac_from_aff,
    _mult_aff,
    _mult_base_3,
    _mult_fixed_window,
    _mult_jac,
    _mult_mont_ladder,
    _multi_mult,
    multiples,
)
from btclib.curvemult import double_mult, mult, multi_mult
from btclib.curves import secp256k1
from btclib.pedersen import second_generator
from btclib.tests.test_curves import all_curves, low_card_curves

ec23_31 = low_card_curves["ec23_31"]


@pytest.mark.second
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

        with pytest.raises(ValueError, match="negative m: -0x"):
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

        with pytest.raises(ValueError, match="negative m: -0x"):
            _mult_jac(-1, ec.GJ, ec)


def test_mult() -> None:
    for ec in low_card_curves.values():
        for q in range(ec.n):
            Q = _mult_aff(q, ec.G, ec)
            assert ec.is_on_curve(Q), f"{q}, {ec}"
            QJ = _mult_fixed_window(q, ec.GJ, ec)
            assert ec.is_on_curve(ec._aff_from_jac(QJ)), f"{q}, {ec}"
            assert Q == ec._aff_from_jac(QJ), f"{q}, {ec}"
        assert INF == _mult_aff(q, INF, ec), f"{q}, {ec}"
        assert ec._jac_equality(INFJ, _mult_fixed_window(q, INFJ, ec)), f"{q}, {ec}"


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
        assert ec._jac_equality(K1, _mult_fixed_window(k1, ec.GJ, ec))


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
        assert ec._jac_equality(K1, _mult_fixed_window(k1, ec.GJ, ec))


def test_mult_fixed_window() -> None:
    for w in range(1, 10):  # Actually it makes use of w=4 or w=5, only to check
        for ec in low_card_curves.values():
            assert ec._jac_equality(_mult_fixed_window(0, ec.GJ, ec, w), INFJ)
            assert ec._jac_equality(_mult_fixed_window(0, INFJ, ec, w), INFJ)

            assert ec._jac_equality(_mult_fixed_window(1, INFJ, ec, w), INFJ)
            assert ec._jac_equality(_mult_fixed_window(1, ec.GJ, ec, w), ec.GJ)

            PJ = _mult_fixed_window(2, ec.GJ, ec, w)
            assert ec._jac_equality(PJ, ec._add_jac(ec.GJ, ec.GJ))

            PJ = _mult_fixed_window(ec.n - 1, ec.GJ, ec, w)
            assert ec._jac_equality(ec.negate_jac(ec.GJ), PJ)

            assert ec._jac_equality(_mult_fixed_window(ec.n - 1, INFJ, ec, w), INFJ)
            assert ec._jac_equality(ec._add_jac(PJ, ec.GJ), INFJ)
            assert ec._jac_equality(_mult_fixed_window(ec.n, ec.GJ, ec, w), INFJ)

            with pytest.raises(ValueError, match="negative m: "):
                _mult_fixed_window(-1, ec.GJ, ec, w)

            with pytest.raises(ValueError, match="non positive w: "):
                _mult_fixed_window(1, ec.GJ, ec, -w)

    ec = ec23_31
    for w in range(1, 10):
        for k1 in range(ec.n):
            K1 = _mult_fixed_window(k1, ec.GJ, ec, w)
            assert ec._jac_equality(K1, _mult_jac(k1, ec.GJ, ec))


@pytest.mark.fifth
def test_assorted_mult() -> None:
    ec = ec23_31
    H = second_generator(ec)
    HJ = _jac_from_aff(H)
    for k1 in range(ec.n):
        K1J = _mult_fixed_window(k1, ec.GJ, ec)
        for k2 in range(ec.n):
            K2J = _mult_fixed_window(k2, HJ, ec)

            shamir = _double_mult(k1, ec.GJ, k2, ec.GJ, ec)
            assert ec.is_on_curve(ec._aff_from_jac(shamir))
            assert ec._jac_equality(shamir, _mult_fixed_window(k1 + k2, ec.GJ, ec))

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
            K3J = _mult_fixed_window(k3, ec.GJ, ec)
            K1JK2JK3J = ec._add_jac(K1JK2J, K3J)
            assert ec.is_on_curve(ec._aff_from_jac(K1JK2JK3J))
            boscoster = _multi_mult([k1, k2, k3], [ec.GJ, HJ, ec.GJ], ec)
            assert ec.is_on_curve(ec._aff_from_jac(boscoster))
            assert ec._aff_from_jac(K1JK2JK3J) == ec._aff_from_jac(boscoster), k3
            assert ec._jac_equality(K1JK2JK3J, boscoster)

            k4 = 1 + secrets.randbelow(ec.n - 1)
            K4J = _mult_fixed_window(k4, HJ, ec)
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


@pytest.mark.fourth
def test_assorted_mult2() -> None:
    ec = ec23_31
    H = second_generator(ec)
    for k1 in range(-ec.n + 1, ec.n):
        K1 = mult(k1, ec.G, ec)
        for k2 in range(ec.n):
            K2 = mult(k2, H, ec)

            shamir = double_mult(k1, ec.G, k2, ec.G, ec)
            assert shamir == mult(k1 + k2, ec.G, ec)

            shamir = double_mult(k1, INF, k2, H, ec)
            assert ec.is_on_curve(shamir)
            assert shamir == K2

            shamir = double_mult(k1, ec.G, k2, INF, ec)
            assert ec.is_on_curve(shamir)
            assert shamir == K1

            shamir = double_mult(k1, ec.G, k2, H, ec)
            assert ec.is_on_curve(shamir)
            K1K2 = ec.add(K1, K2)
            assert K1K2 == shamir

            k3 = 1 + secrets.randbelow(ec.n - 1)
            K3 = mult(k3, ec.G, ec)
            K1K2K3 = ec.add(K1K2, K3)
            assert ec.is_on_curve(K1K2K3)
            boscoster = multi_mult([k1, k2, k3], [ec.G, H, ec.G], ec)
            assert ec.is_on_curve(boscoster)
            assert K1K2K3 == boscoster, k3

            k4 = 1 + secrets.randbelow(ec.n - 1)
            K4 = mult(k4, H, ec)
            K1K2K3K4 = ec.add(K1K2K3, K4)
            assert ec.is_on_curve(K1K2K3K4)
            points = [ec.G, H, ec.G, H]
            boscoster = multi_mult([k1, k2, k3, k4], points, ec)
            assert ec.is_on_curve(boscoster)
            assert K1K2K3K4 == boscoster, k4
            assert K1K2K3 == multi_mult([k1, k2, k3, 0], points, ec)
            assert K1K2 == multi_mult([k1, k2, 0, 0], points, ec)
            assert K1 == multi_mult([k1, 0, 0, 0], points, ec)
            assert INF == multi_mult([0, 0, 0, 0], points, ec)

    err_msg = "mismatch between number of scalars and points: "
    with pytest.raises(ValueError, match=err_msg):
        multi_mult([k1, k2, k3, k4], [ec.G, H, ec.G], ec)


def test_double_mult() -> None:
    H = second_generator(secp256k1)
    G = secp256k1.G

    # 0*G + 1*H
    T = double_mult(1, H, 0, G)
    assert T == H
    T = multi_mult([1, 0], [H, G])
    assert T == H

    # 0*G + 2*H
    exp = mult(2, H)
    T = double_mult(2, H, 0, G)
    assert T == exp
    T = multi_mult([2, 0], [H, G])
    assert T == exp

    # 0*G + 3*H
    exp = mult(3, H)
    T = double_mult(3, H, 0, G)
    assert T == exp
    T = multi_mult([3, 0], [H, G])
    assert T == exp

    # 1*G + 0*H
    T = double_mult(0, H, 1, G)
    assert T == G
    T = multi_mult([0, 1], [H, G])
    assert T == G

    # 2*G + 0*H
    exp = mult(2, G)
    T = double_mult(0, H, 2, G)
    assert T == exp
    T = multi_mult([0, 2], [H, G])
    assert T == exp

    # 3*G + 0*H
    exp = mult(3, G)
    T = double_mult(0, H, 3, G)
    assert T == exp
    T = multi_mult([0, 3], [H, G])
    assert T == exp

    # 0*G + 5*H
    exp = mult(5, H)
    T = double_mult(5, H, 0, G)
    assert T == exp
    T = multi_mult([5, 0], [H, G])
    assert T == exp

    # 0*G - 5*H
    exp = mult(-5, H)
    T = double_mult(-5, H, 0, G)
    assert T == exp
    T = multi_mult([-5, 0], [H, G])
    assert T == exp

    # 1*G - 5*H
    exp = secp256k1.add(G, T)
    T = double_mult(-5, H, 1, G)
    assert T == exp
    # FIXME
    # T = multi_mult([-5, 1], [H, G])
    # assert T == exp


def test_multiples() -> None:

    ec = secp256k1
    with pytest.raises(ValueError, match="size too low: "):
        multiples(ec.GJ, 1, ec)

    T = [INFJ, ec.GJ]
    M = multiples(ec.GJ, 2, ec)
    assert len(M) == 2
    assert M == T

    T.append(ec._double_jac(ec.GJ))
    M = multiples(ec.GJ, 3, ec)
    assert len(M) == 3
    assert M == T

    T.append(ec._add_jac(T[-1], ec.GJ))
    M = multiples(ec.GJ, 4, ec)
    assert len(M) == 4
    assert M == T

    T.append(ec._double_jac(T[2]))
    M = multiples(ec.GJ, 5, ec)
    assert len(M) == 5
    assert M == T

    T.append(ec._add_jac(T[-1], ec.GJ))
    M = multiples(ec.GJ, 6, ec)
    assert len(M) == 6
    assert M == T

    T.append(ec._double_jac(T[3]))
    M = multiples(ec.GJ, 7, ec)
    assert len(M) == 7
    assert M == T

    T.append(ec._add_jac(T[-1], ec.GJ))
    M = multiples(ec.GJ, 8, ec)
    assert len(M) == 8
    assert M == T

    T.append(ec._double_jac(T[4]))
    M = multiples(ec.GJ, 9, ec)
    assert len(M) == 9
    assert M == T

    T.append(ec._add_jac(T[-1], ec.GJ))
    M = multiples(ec.GJ, 10, ec)
    assert len(M) == 10
    assert M == T
