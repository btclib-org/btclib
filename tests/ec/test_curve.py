#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Tests for the `btclib.curve` module."""


import itertools
import json
from os import path

import pytest

from btclib.alias import INF, INFJ
from btclib.ec import (
    Curve,
    double_mult,
    jac_from_aff,
    libsecp256k1,
    mult,
    multi_mult,
    secp256k1,
)
from btclib.ec.curve import CURVES
from btclib.ecc import second_generator
from btclib.exceptions import BTClibRuntimeError, BTClibTypeError, BTClibValueError
from btclib.number_theory import mod_sqrt
from btclib.to_pub_key import pub_keyinfo_from_prv_key

# FIXME Curve repr should use "deadbeef 00000000", not "0xdeadbeef00000000"
# FIXME test curves when n>p

# test curves: very low cardinality
# 13 % 4 = 1; 13 % 8 = 5
low_card_curves = {"ec13_11": Curve(13, 7, 6, (1, 1), 11, 1, False)}
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

# with python>=3.9 use dict union operator
# all_curves = low_card_curves | CURVES
all_curves = low_card_curves.copy()
all_curves.update(CURVES)

ec23_31 = low_card_curves["ec23_31"]


def test_mult_on_secp256k1() -> None:
    assert mult(0) == INF

    G = mult(1)
    assert G[0] == 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    assert G[1] == 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

    G_ = mult(secp256k1.n - 1)
    assert G_[0] == 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    assert G_[1] == 0xB7C52588D95C3B9AA25B0403F1EEF75702E84BB7597AABE663B82F6F04EF2777

    if libsecp256k1.is_available():
        err_msg = (
            r"can't convert negative int to unsigned|secp256k1_ec_pubkey_create failure"
        )
        for invalid_prvkey in (-1, 0, secp256k1.n, secp256k1.p):
            with pytest.raises((OverflowError, BTClibRuntimeError), match=err_msg):
                libsecp256k1.pubkey_from_prvkey(invalid_prvkey)
            mult(invalid_prvkey)


def test_secp256k1_py_vectors() -> None:
    # https://github.com/rustyrussell/secp256k1-py/blob/master/tests/data/pubkey.json

    fname = "pubkey.json"
    filename = path.join(path.dirname(__file__), "_data", fname)

    with open(filename, encoding="ascii") as file_:
        test_vectors = json.load(file_)["vectors"]

    for vector in test_vectors:
        prv_key = bytes.fromhex(vector["seckey"])
        assert len(prv_key) == 32
        pubkey_uncp = bytes.fromhex(vector["pubkey"])
        assert len(pubkey_uncp) == 65
        pubkey_comp = bytes.fromhex(vector["compressed"])
        assert len(pubkey_comp) == 33

        assert pub_keyinfo_from_prv_key(prv_key, compressed=False)[0] == pubkey_uncp
        assert pub_keyinfo_from_prv_key(prv_key, compressed=True)[0] == pubkey_comp

        if libsecp256k1.is_available():
            assert (
                libsecp256k1.pubkey_from_prvkey(prv_key, compressed=False)
                == pubkey_uncp
            )
            assert libsecp256k1.pubkey_from_prvkey(prv_key) == pubkey_comp

    if libsecp256k1.is_available():
        err_msg = "secp256k1_ec_pubkey_create failure"
        with pytest.raises(BTClibRuntimeError, match=err_msg):
            libsecp256k1.pubkey_from_prvkey(secp256k1.n)


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

    err_msg = "generator must a be a sequence\\[int, int\\]"
    with pytest.raises(BTClibValueError, match=err_msg):
        Curve(13, 0, 2, (1, 9, 1), 19, 1, False)  # type: ignore[arg-type]

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
        # just a point, not INF
        Q = ec.G
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
    """Test self-consistency of add and double in affine coordinates."""
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
    """Test self-consistency of add and double in Jacobian coordinates."""
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
    """Test consistency between affine and Jacobian add/double methods."""
    for ec in all_curves.values():
        # just a point, not INF
        Q = ec.G
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
            ec_repr = f"{ec_repr[:-1]}, False)"
        ec2 = eval(ec_repr)  # pylint: disable=eval-used # nosec eval
        assert str(ec) == str(ec2)


def test_is_on_curve() -> None:
    for ec in all_curves.values():
        with pytest.raises(BTClibValueError, match="point must be a tuple"):
            ec.is_on_curve("not a point")  # type: ignore[arg-type]

        with pytest.raises(BTClibValueError, match="x-coordinate not in 0..p-1: "):
            ec.y(ec.p)

        # just a point, not INF
        Q = ec.G
        with pytest.raises(BTClibValueError, match="y-coordinate not in 1..p-1: "):
            ec.is_on_curve((Q[0], ec.p))


def test_negate() -> None:
    for ec in all_curves.values():
        # just a point, not INF
        Q = ec.G
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
            ec.negate(ec.GJ)  # type: ignore[arg-type]

        with pytest.raises(BTClibTypeError, match="not a Jacobian point"):
            ec.negate_jac(ec.G)  # type: ignore[arg-type]


def test_symmetry() -> None:
    """Methods to break simmetry: quadratic residue, even/odd, low/high."""
    for ec in low_card_curves.values():
        # just a point, not INF
        Q = ec.G
        x_Q = Q[0]

        assert not ec.y_even(x_Q) % 2
        assert ec.y_low(x_Q) <= ec.p // 2

        # compute all quadratic residues
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

    with pytest.raises(BTClibValueError, match="invalid x-coordinate: "):
        secp256k1.y_even(INF[0])
    with pytest.raises(BTClibValueError, match="invalid x-coordinate: "):
        secp256k1.y_low(INF[0])
    with pytest.raises(BTClibValueError, match="invalid x-coordinate: "):
        secp256k1.y_quadratic_residue(INF[0])


def test_assorted_mult() -> None:
    ec = ec23_31
    H = second_generator(ec)
    for k1 in range(-2, ec.n):
        K1 = mult(k1, ec.G, ec)
        for k2 in range(-2, ec.n):
            K2 = mult(k2, H, ec)

            shamir = double_mult(k1, ec.G, k2, ec.G, ec)
            assert shamir == mult(k1 + k2, None, ec)

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

            k3 = ec.n // 3  # just a random ponit, not INF
            K3 = mult(k3, ec.G, ec)
            K1K2K3 = ec.add(K1K2, K3)
            assert ec.is_on_curve(K1K2K3)
            boscoster = multi_mult([k1, k2, k3], [ec.G, H, ec.G], ec)
            assert ec.is_on_curve(boscoster)
            assert K1K2K3 == boscoster, k3

            k4 = ec.n // 4  # just a random ponit, not INF
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
    assert double_mult(0, G, 0, H) == INF
    assert double_mult(1, G, 0, H) == G
    assert double_mult(0, G, 1, H) == H
    for i, j in itertools.product(range(-1, 3), range(-1, 3)):
        exp = secp256k1.add(mult(i), mult(j, H))
        assert exp == double_mult(i, G, j, H)


def test_multi_mult() -> None:
    with pytest.raises(BTClibValueError, match="not a multi_mult"):
        multi_mult([1], [secp256k1.G])

    H = second_generator(secp256k1)
    G = secp256k1.G
    assert multi_mult([0, 0], [G, H]) == INF
    assert multi_mult([1, 0], [G, H]) == G
    assert multi_mult([0, 1], [G, H]) == H

    # FIXME it loop for negative coefficients
    # assert multi_mult([-1, 1], [G, H]) != INF
    # assert multi_mult([1, -1], [G, H]) != INF
    assert multi_mult([-1, 0], [G, H]) != INF
    assert multi_mult([0, -1], [G, H]) != INF

    for i, j in itertools.product(range(3), range(3)):
        exp = double_mult(i, G, j, H)
        assert exp == multi_mult([i, j], [G, H])
