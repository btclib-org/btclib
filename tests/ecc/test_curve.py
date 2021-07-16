#!/usr/bin/env python3

# Copyright (C) 2017-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.curve` module."

import secrets
from typing import Dict

import pytest

from btclib.alias import INF, INFJ
from btclib.ecc.curve import CURVES, Curve, double_mult, mult, multi_mult, secp256k1
from btclib.ecc.curve_group import jac_from_aff
from btclib.ecc.number_theory import mod_sqrt
from btclib.ecc.pedersen import second_generator
from btclib.exceptions import BTClibTypeError, BTClibValueError

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

ec23_31 = low_card_curves["ec23_31"]


def test_exceptions() -> None:

    # good curve
    Curve(13, 0, 2, (1, 9), 19, 1, False)

    with pytest.raises(BTClibValueError, match="p is not prime: "):
        Curve(15, 0, 2, (1, 9), 19, 1, False)

    with pytest.raises(BTClibValueError, match="negative a: "):
        Curve(13, -1, 2, (1, 9), 19, 1, False)

    with pytest.raises(BTClibValueError, match="p <= a: "):
        Curve(13, 13, 2, (1, 9), 19, 1, False)

    with pytest.raises(BTClibValueError, match="negative b: "):
        Curve(13, 0, -2, (1, 9), 19, 1, False)

    with pytest.raises(BTClibValueError, match="p <= b: "):
        Curve(13, 0, 13, (1, 9), 19, 1, False)

    with pytest.raises(BTClibValueError, match="zero discriminant"):
        Curve(11, 7, 7, (1, 9), 19, 1, False)

    err_msg = "Generator must a be a sequence\\[int, int\\]"
    with pytest.raises(BTClibValueError, match=err_msg):
        Curve(13, 0, 2, (1, 9, 1), 19, 1, False)  # type: ignore

    with pytest.raises(BTClibValueError, match="Generator is not on the curve"):
        Curve(13, 0, 2, (2, 9), 19, 1, False)

    with pytest.raises(BTClibValueError, match="n is not prime: "):
        Curve(13, 0, 2, (1, 9), 20, 1, False)

    with pytest.raises(BTClibValueError, match="n not in "):
        Curve(13, 0, 2, (1, 9), 71, 1, False)

    with pytest.raises(BTClibValueError, match="INF point cannot be a generator"):
        Curve(13, 0, 2, INF, 19, 1, False)

    with pytest.raises(BTClibValueError, match="n is not the group order: "):
        Curve(13, 0, 2, (1, 9), 17, 1, False)

    with pytest.raises(BTClibValueError, match="invalid cofactor: "):
        Curve(13, 0, 2, (1, 9), 19, 2, False)

    # n=p -> weak curve
    # missing

    with pytest.raises(UserWarning, match="weak curve"):
        Curve(11, 2, 7, (6, 9), 7, 2, True)


def test_aff_jac_conversions() -> None:
    for ec in all_curves.values():

        # just a random point, not INF
        q = 1 + secrets.randbelow(ec.n - 1)
        Q = mult(q, ec.G, ec)
        QJ = jac_from_aff(Q)
        assert Q == ec.aff_from_jac(QJ)
        x_Q = ec.x_aff_from_jac(QJ)
        assert Q[0] == x_Q
        y_Q = ec.y_aff_from_jac(QJ)
        assert Q[1] == y_Q

        assert INF == ec.aff_from_jac(jac_from_aff(INF))

        with pytest.raises(BTClibValueError, match="INF has no x-coordinate"):
            ec.x_aff_from_jac(INFJ)

        with pytest.raises(BTClibValueError, match="INF has no y-coordinate"):
            ec.y_aff_from_jac(INFJ)


def test_add_double_aff() -> None:
    "Test self-consistency of add and double in affine coordinates."
    for ec in all_curves.values():

        # add G and the infinity point
        assert ec.add_aff(ec.G, INF) == ec.G
        assert ec.add_aff(INF, ec.G) == ec.G

        # double G
        G2 = ec.add_aff(ec.G, ec.G)
        assert G2 == ec.double_aff(ec.G)

        # double INF
        assert ec.add_aff(INF, INF) == INF
        assert ec.double_aff(INF) == INF

        # add G and minus G
        assert ec.add_aff(ec.G, ec.negate(ec.G)) == INF

        # add INF and "minus" INF
        assert ec.add_aff(INF, ec.negate(INF)) == INF


def test_add_double_jac() -> None:
    "Test self-consistency of add and double in Jacobian coordinates."
    for ec in all_curves.values():

        # add G and the infinity point
        assert ec.jac_equality(ec.add_jac(ec.GJ, INFJ), ec.GJ)
        assert ec.jac_equality(ec.add_jac(INFJ, ec.GJ), ec.GJ)

        # double G
        GJ2 = ec.add_jac(ec.GJ, ec.GJ)
        assert ec.jac_equality(GJ2, ec.double_jac(ec.GJ))

        # double INF
        assert ec.jac_equality(ec.add_jac(INFJ, INFJ), INFJ)
        assert ec.jac_equality(ec.double_jac(INFJ), INFJ)

        # add G and minus G
        assert ec.jac_equality(ec.add_jac(ec.GJ, ec.negate_jac(ec.GJ)), INFJ)

        # add INF and "minus" INF
        assert ec.jac_equality(ec.add_jac(INFJ, ec.negate_jac(INFJ)), INFJ)


def test_add_double_aff_jac() -> None:
    "Test consistency between affine and Jacobian add/double methods."
    for ec in all_curves.values():

        # just a random point, not INF
        q = 1 + secrets.randbelow(ec.n - 1)
        Q = mult(q, ec.G, ec)
        QJ = jac_from_aff(Q)

        # add Q and G
        R = ec.add_aff(Q, ec.G)
        RJ = ec.add_jac(QJ, ec.GJ)
        assert R == ec.aff_from_jac(RJ)

        # double Q
        R = ec.double_aff(Q)
        RJ = ec.double_jac(QJ)
        assert R == ec.aff_from_jac(RJ)
        assert R == ec.add_aff(Q, Q)
        assert ec.jac_equality(RJ, ec.add_jac(QJ, QJ))


def test_ec_repr() -> None:
    for ec in all_curves.values():
        ec_repr = repr(ec)
        if ec in low_card_curves.values() or ec.p_size < 24:
            ec_repr = ec_repr[:-1] + ", False)"
        ec2 = eval(ec_repr)  # pylint: disable=eval-used # nosec
        assert str(ec) == str(ec2)


def test_is_on_curve() -> None:
    for ec in all_curves.values():

        with pytest.raises(BTClibValueError, match="point must be a tuple"):
            ec.is_on_curve("not a point")  # type: ignore

        with pytest.raises(BTClibValueError, match="x-coordinate not in 0..p-1: "):
            ec.y(ec.p)

        # just a random point, not INF
        q = 1 + secrets.randbelow(ec.n - 1)
        Q = mult(q, ec.G, ec)
        with pytest.raises(BTClibValueError, match="y-coordinate not in 1..p-1: "):
            ec.is_on_curve((Q[0], ec.p))


def test_negate() -> None:
    for ec in all_curves.values():

        # just a random point, not INF
        q = 1 + secrets.randbelow(ec.n - 1)
        Q = mult(q, ec.G, ec)
        minus_Q = ec.negate(Q)
        assert ec.add(Q, minus_Q) == INF

        # Jacobian coordinates
        QJ = jac_from_aff(Q)
        minus_QJ = ec.negate_jac(QJ)
        assert ec.jac_equality(ec.add_jac(QJ, minus_QJ), INFJ)

        # negate of INF is INF
        minus_INF = ec.negate(INF)
        assert minus_INF == INF

        # negate of INFJ is INFJ
        minus_INFJ = ec.negate_jac(INFJ)
        assert ec.jac_equality(minus_INFJ, INFJ)

        with pytest.raises(BTClibTypeError, match="not a point"):
            ec.negate(ec.GJ)  # type: ignore

        with pytest.raises(BTClibTypeError, match="not a Jacobian point"):
            ec.negate_jac(ec.G)  # type: ignore


def test_symmetry() -> None:
    "Methods to break simmetry: quadratic residue, even/odd, low/high."
    for ec in low_card_curves.values():

        # just a random point, not INF
        q = 1 + secrets.randbelow(ec.n - 1)
        Q = mult(q, ec.G, ec)
        x_Q = Q[0]

        assert not ec.y_even(x_Q) % 2
        assert ec.y_low(x_Q) <= ec.p // 2

        # compute quadratic residues
        hasRoot = {1}
        for i in range(2, ec.p):
            hasRoot.add(i * i % ec.p)

        if ec.p % 4 == 3:
            quad_res = ec.y_quadratic_residue(x_Q)

            # in this case only quad_res is a quadratic residue
            assert quad_res in hasRoot
            root = mod_sqrt(quad_res, ec.p)
            assert quad_res == (root * root) % ec.p
            root = ec.p - root
            assert quad_res == (root * root) % ec.p

            assert ec.p - quad_res not in hasRoot
            with pytest.raises(BTClibValueError, match="no root for "):
                mod_sqrt(ec.p - quad_res, ec.p)
        else:
            assert ec.p % 4 == 1
            # cannot use y_quadratic_residue in this case
            err_msg = "field prime is not equal to 3 mod 4: "
            with pytest.raises(BTClibValueError, match=err_msg):
                ec.y_quadratic_residue(x_Q)

            y_even = ec.y_even(x_Q)
            y_odd = ec.p - y_even
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
                with pytest.raises(BTClibValueError, match=err_msg):
                    mod_sqrt(y_odd, ec.p)
                with pytest.raises(BTClibValueError, match=err_msg):
                    mod_sqrt(y_even, ec.p)

    with pytest.raises(BTClibValueError):
        secp256k1.y_even(INF[0])
    with pytest.raises(BTClibValueError):
        secp256k1.y_low(INF[0])
    with pytest.raises(BTClibValueError):
        secp256k1.y_quadratic_residue(INF[0])


@pytest.mark.fifth
def test_assorted_mult() -> None:
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
            with pytest.raises(BTClibValueError, match=err_msg):
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
