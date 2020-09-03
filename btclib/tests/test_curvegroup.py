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
    _mult_aff,
    _mult_jac,
    _multi_mult,
)
from btclib.numbertheory import mod_sqrt
from btclib.pedersen import second_generator
from btclib.tests.test_curve import all_curves, low_card_curves

ec23_31 = low_card_curves["ec23_31"]


@pytest.mark.fifth
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
        K1J = _mult_jac(k1, ec.GJ, ec)
        for k2 in range(ec.n):
            K2J = _mult_jac(k2, HJ, ec)

            shamir = _double_mult(k1, ec.GJ, k2, ec.GJ, ec)
            assert ec.is_on_curve(ec._aff_from_jac(shamir))
            assert ec._jac_equality(shamir, _mult_jac(k1 + k2, ec.GJ, ec))

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
            K3J = _mult_jac(k3, ec.GJ, ec)
            K1JK2JK3J = ec._add_jac(K1JK2J, K3J)
            assert ec.is_on_curve(ec._aff_from_jac(K1JK2JK3J))
            boscoster = _multi_mult([k1, k2, k3], [ec.GJ, HJ, ec.GJ], ec)
            assert ec.is_on_curve(ec._aff_from_jac(boscoster))
            assert ec._aff_from_jac(K1JK2JK3J) == ec._aff_from_jac(boscoster), k3
            assert ec._jac_equality(K1JK2JK3J, boscoster)

            k4 = 1 + secrets.randbelow(ec.n - 1)
            K4J = _mult_jac(k4, HJ, ec)
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

    # q in [2, n-1]
    q = 2 + secrets.randbelow(ec.n - 2)
    Q = _mult_aff(q, ec.G, ec)
    QJ = _mult_jac(q, ec.GJ, ec)
    assert ec._jac_equality(QJ, _jac_from_aff(Q))
    assert not ec._jac_equality(QJ, ec.negate_jac(QJ))
    assert not ec._jac_equality(QJ, ec.GJ)


def test_aff_jac_conversions() -> None:
    for ec in all_curves.values():

        # just a random point, not INF
        q = 1 + secrets.randbelow(ec.n - 1)
        Q = _mult_aff(q, ec.G, ec)
        QJ = _jac_from_aff(Q)
        assert Q == ec._aff_from_jac(QJ)
        x_Q = ec._x_aff_from_jac(QJ)
        assert Q[0] == x_Q

        assert INF == ec._aff_from_jac(_jac_from_aff(INF))

        # relevant for BIP340-Schnorr signature verification
        assert not ec.has_square_y(INF)
        with pytest.raises(ValueError, match="infinity point has no x-coordinate"):
            ec._x_aff_from_jac(INFJ)
        with pytest.raises(TypeError, match="not a point"):
            ec.has_square_y("notapoint")  # type: ignore


def test_add_double_aff() -> None:
    "Test self-consistency of add and double in affine coordinates."
    for ec in all_curves.values():

        # add G and the infinity point
        assert ec._add_aff(ec.G, INF) == ec.G
        assert ec._add_aff(INF, ec.G) == ec.G

        # double G
        G2 = ec._add_aff(ec.G, ec.G)
        assert G2 == ec._double_aff(ec.G)

        # double INF
        assert ec._add_aff(INF, INF) == INF
        assert ec._double_aff(INF) == INF

        # add G and minus G
        assert ec._add_aff(ec.G, ec.negate(ec.G)) == INF

        # add INF and "minus" INF
        assert ec._add_aff(INF, ec.negate(INF)) == INF


def test_add_double_jac() -> None:
    "Test self-consistency of add and double in Jacobian coordinates."
    for ec in all_curves.values():

        # add G and the infinity point
        assert ec._jac_equality(ec._add_jac(ec.GJ, INFJ), ec.GJ)
        assert ec._jac_equality(ec._add_jac(INFJ, ec.GJ), ec.GJ)

        # double G
        GJ2 = ec._add_jac(ec.GJ, ec.GJ)
        assert ec._jac_equality(GJ2, ec._double_jac(ec.GJ))

        # double INF
        assert ec._jac_equality(ec._add_jac(INFJ, INFJ), INFJ)
        assert ec._jac_equality(ec._double_jac(INFJ), INFJ)

        # add G and minus G
        assert ec._jac_equality(ec._add_jac(ec.GJ, ec.negate_jac(ec.GJ)), INFJ)

        # add INF and "minus" INF
        assert ec._jac_equality(ec._add_jac(INFJ, ec.negate_jac(INFJ)), INFJ)


def test_add_double_aff_jac() -> None:
    "Test consistency between affine and Jacobian add/double methods."
    for ec in all_curves.values():

        # just a random point, not INF
        q = 1 + secrets.randbelow(ec.n - 1)
        Q = _mult_aff(q, ec.G, ec)
        QJ = _jac_from_aff(Q)

        # add Q and G
        R = ec._add_aff(Q, ec.G)
        RJ = ec._add_jac(QJ, ec.GJ)
        assert R == ec._aff_from_jac(RJ)

        # double Q
        R = ec._double_aff(Q)
        RJ = ec._double_jac(QJ)
        assert R == ec._aff_from_jac(RJ)
        assert R == ec._add_aff(Q, Q)
        assert ec._jac_equality(RJ, ec._add_jac(QJ, QJ))


@pytest.mark.fourth
def test_ec_repr() -> None:
    for ec in all_curves.values():
        ec_repr = repr(ec)
        if ec in low_card_curves.values() or ec.psize < 24:
            ec_repr = ec_repr[:-1] + ", False)"
        ec2 = eval(ec_repr)
        assert str(ec) == str(ec2)


@pytest.mark.sixth
def test_is_on_curve() -> None:
    for ec in all_curves.values():

        with pytest.raises(ValueError, match="point must be a tuple"):
            ec.is_on_curve("not a point")  # type: ignore

        with pytest.raises(ValueError, match="x-coordinate not in 0..p-1: "):
            ec.y(ec.p)

        # just a random point, not INF
        q = 1 + secrets.randbelow(ec.n - 1)
        Q = _mult_aff(q, ec.G, ec)
        with pytest.raises(ValueError, match="y-coordinate not in 1..p-1: "):
            ec.is_on_curve((Q[0], ec.p))


def test_negate() -> None:
    for ec in all_curves.values():

        # just a random point, not INF
        q = 1 + secrets.randbelow(ec.n - 1)
        Q = _mult_aff(q, ec.G, ec)
        minus_Q = ec.negate(Q)
        assert ec.add(Q, minus_Q) == INF

        # Jacobian coordinates
        QJ = _jac_from_aff(Q)
        minus_QJ = ec.negate_jac(QJ)
        assert ec._jac_equality(ec._add_jac(QJ, minus_QJ), INFJ)

        # negate of INF is INF
        minus_INF = ec.negate(INF)
        assert minus_INF == INF

        # negate of INFJ is INFJ
        minus_INFJ = ec.negate_jac(INFJ)
        assert ec._jac_equality(minus_INFJ, INFJ)

    with pytest.raises(TypeError, match="not a point"):
        ec.negate(ec.GJ)  # type: ignore

    with pytest.raises(TypeError, match="not a Jacobian point"):
        ec.negate_jac(ec.G)  # type: ignore


def test_symmetry() -> None:
    """Methods to break simmetry: quadratic residue, odd/even, low/high"""
    for ec in low_card_curves.values():

        # just a random point, not INF
        q = 1 + secrets.randbelow(ec.n - 1)
        Q = _mult_aff(q, ec.G, ec)
        x_Q = Q[0]

        y_odd = ec.y_odd(x_Q)
        assert y_odd % 2 == 1
        y_even = ec.y_odd(x_Q, False)
        assert y_even % 2 == 0
        assert y_even == ec.p - y_odd

        y_low = ec.y_low(x_Q)
        y_high = ec.y_low(x_Q, False)
        assert y_low < y_high
        assert y_high == ec.p - y_low

        # compute quadratic residues
        hasRoot = {1}
        for i in range(2, ec.p):
            hasRoot.add(i * i % ec.p)

        if ec.p % 4 == 3:
            quad_res = ec.y_quadratic_residue(x_Q)
            not_quad_res = ec.y_quadratic_residue(x_Q, False)

            # in this case only quad_res is a quadratic residue
            assert quad_res in hasRoot
            root = mod_sqrt(quad_res, ec.p)
            assert quad_res == (root * root) % ec.p
            root = ec.p - root
            assert quad_res == (root * root) % ec.p

            assert not_quad_res == ec.p - quad_res
            assert not_quad_res not in hasRoot
            with pytest.raises(ValueError, match="no root for "):
                mod_sqrt(not_quad_res, ec.p)
        else:
            assert ec.p % 4 == 1
            # cannot use y_quadratic_residue in this case
            err_msg = "field prime is not equal to 3 mod 4: "
            with pytest.raises(ValueError, match=err_msg):
                ec.y_quadratic_residue(x_Q)
            with pytest.raises(ValueError, match=err_msg):
                ec.y_quadratic_residue(x_Q, False)

            # in this case neither or both y_Q are quadratic residues
            neither = y_odd not in hasRoot and y_even not in hasRoot
            both = y_odd in hasRoot and y_even in hasRoot
            assert neither or both
            if y_odd in hasRoot:  # both have roots
                root = mod_sqrt(y_odd, ec.p)
                assert y_odd == (root * root) % ec.p
                root = ec.p - root
                assert y_odd == (root * root) % ec.p
                root = mod_sqrt(y_even, ec.p)
                assert y_even == (root * root) % ec.p
                root = ec.p - root
                assert y_even == (root * root) % ec.p
            else:
                err_msg = "no root for "
                with pytest.raises(ValueError, match=err_msg):
                    mod_sqrt(y_odd, ec.p)
                with pytest.raises(ValueError, match=err_msg):
                    mod_sqrt(y_even, ec.p)

    # with the last curve
    with pytest.raises(ValueError, match="low1high0 must be bool or 1/0"):
        ec.y_low(x_Q, 2)
    with pytest.raises(ValueError, match="odd1even0 must be bool or 1/0"):
        ec.y_odd(x_Q, 2)
    with pytest.raises(ValueError, match="quad_res must be bool or 1/0"):
        ec.y_quadratic_residue(x_Q, 2)


def test_mult() -> None:
    for ec in low_card_curves.values():
        for q in range(ec.n):
            Q = _mult_aff(q, ec.G, ec)
            assert ec.is_on_curve(Q), f"{q}, {ec}"
            QJ = _mult_jac(q, ec.GJ, ec)
            assert ec.is_on_curve(ec._aff_from_jac(QJ)), f"{q}, {ec}"
            assert Q == ec._aff_from_jac(QJ), f"{q}, {ec}"
        assert INF == _mult_aff(q, INF, ec), f"{q}, {ec}"
        assert ec._jac_equality(INFJ, _mult_jac(q, INFJ, ec)), f"{q}, {ec}"
