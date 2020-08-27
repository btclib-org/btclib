#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for `btclib.curves` module."

import secrets
from typing import Dict

import pytest

from btclib.alias import INF, INFJ
from btclib.curve import Curve, _jac_from_aff, _mult_aff, _mult_jac
from btclib.curves import CURVES
from btclib.numbertheory import mod_sqrt

# FIXME Curve repr should use "dedbeef 00000000", not "0xdedbeef00000000"
# FIXME test curves when n>p


# test curves: very low cardinality
low_card_curves: Dict[str, Curve] = {}
# 13 % 4 = 1; 13 % 8 = 5
low_card_curves["ec13_11"] = Curve(13, 7, 6, (1, 1), 11, 1, False)
low_card_curves["ec13_19"] = Curve(13, 0, 2, (1, 9), 19, 1, False)
# 17 % 4 = 1; 17 % 8 = 1
low_card_curves["ec17_13"] = Curve(17, 6, 8, (0, 12), 13, 2, False)
low_card_curves["ec17_23"] = Curve(17, 3, 5, (1, 14), 23, 1, False)
# 19 % 4 = 3; 19 % 8 = 3
low_card_curves["ec19_13"] = Curve(19, 0, 2, (4, 16), 13, 2, False)
low_card_curves["ec19_23"] = Curve(19, 2, 9, (0, 16), 23, 1, False)
# 23 % 4 = 3; 23 % 8 = 7
low_card_curves["ec23_19"] = Curve(23, 9, 7, (5, 4), 19, 1, False)
low_card_curves["ec23_31"] = Curve(23, 5, 1, (0, 1), 31, 1, False)

all_curves: Dict[str, Curve] = {}
all_curves.update(low_card_curves)
all_curves.update(CURVES)


@pytest.mark.seventh
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


def test_add_aff() -> None:
    for ec in all_curves.values():

        # add G and the infinity point
        assert ec._add_aff(ec.G, INF) == ec.G
        assert ec._add_aff(INF, ec.G) == ec.G
        assert ec._add_aff(INF, INF) == INF

        # add G and minus G
        assert ec._add_aff(ec.G, ec.negate(ec.G)) == INF


def test_add_jac() -> None:
    for ec in all_curves.values():

        # add G and the infinity point
        assert ec._add_jac(ec.GJ, INFJ) == ec.GJ
        assert ec._add_jac(INFJ, ec.GJ) == ec.GJ
        assert ec._add_jac(INFJ, INFJ) == INFJ

        # add G and minus G
        assert ec._add_jac(ec.GJ, ec.negate_jac(ec.GJ)) == INFJ


@pytest.mark.eighth
def test_add() -> None:
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
        R = ec._add_aff(Q, Q)
        RJ = ec._add_jac(QJ, QJ)
        assert R == ec._aff_from_jac(RJ)


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
        assert ec._add_jac(QJ, minus_QJ) == INFJ

        # negate of INF is INF
        minus_INF = ec.negate(INF)
        assert minus_INF == INF

        # negate of INFJ is INFJ
        minus_INFJ = ec.negate_jac(INFJ)
        assert minus_INFJ == INFJ

    with pytest.raises(TypeError, match="not a point"):
        ec.negate("notapoint")  # type: ignore


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


@pytest.mark.fifth
def test_mult_aff_curves() -> None:
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


def test_mult_jac_curves() -> None:
    for ec in all_curves.values():
        assert _mult_jac(0, ec.GJ, ec) == INFJ
        assert _mult_jac(0, INFJ, ec) == INFJ

        assert _mult_jac(1, INFJ, ec) == INFJ
        assert _mult_jac(1, ec.GJ, ec) == ec.GJ

        PJ = ec._add_jac(ec.GJ, ec.GJ)
        assert PJ == _mult_jac(2, ec.GJ, ec)

        PJ = _mult_jac(ec.n - 1, ec.GJ, ec)
        assert ec._jac_equality(ec.negate_jac(ec.GJ), PJ)

        assert _mult_jac(ec.n - 1, INFJ, ec) == INFJ
        assert ec._add_jac(PJ, ec.GJ) == INFJ
        assert _mult_jac(ec.n, ec.GJ, ec) == INFJ

        with pytest.raises(ValueError, match="negative m: -0x"):
            _mult_jac(-1, ec.GJ, ec)


def test_mult() -> None:
    for ec in low_card_curves.values():
        for q in range(ec.n):
            Q = _mult_aff(q, ec.G, ec)
            QJ = _mult_jac(q, ec.GJ, ec)
            assert Q == ec._aff_from_jac(QJ)
        assert INF == _mult_aff(q, INF, ec)
        assert INFJ == _mult_jac(q, INFJ, ec)
