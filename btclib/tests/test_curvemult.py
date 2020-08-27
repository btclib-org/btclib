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
from btclib.curve import _jac_from_aff, _mult_jac
from btclib.curvemult import (
    _double_mult,
    _multi_mult,
    double_mult,
    mult,
    multi_mult,
)
from btclib.curves import secp256k1
from btclib.pedersen import second_generator
from btclib.tests.test_curves import low_card_curves

ec23_31 = low_card_curves["ec23_31"]


def test_assorted_mult() -> None:
    ec = ec23_31
    H = second_generator(ec)
    HJ = _jac_from_aff(H)
    for k1 in range(ec.n):
        K1J = _mult_jac(k1, ec.GJ, ec)
        for k2 in range(ec.n):
            K2J = _mult_jac(k2, HJ, ec)

            shamir = _double_mult(k1, ec.GJ, k2, ec.GJ, ec)
            assert ec._jac_equality(shamir, _mult_jac(k1 + k2, ec.GJ, ec))

            shamir = _double_mult(k1, INFJ, k2, HJ, ec)
            assert ec._jac_equality(shamir, K2J)
            shamir = _double_mult(k1, ec.GJ, k2, INFJ, ec)
            assert ec._jac_equality(shamir, K1J)

            shamir = _double_mult(k1, ec.GJ, k2, HJ, ec)
            K1JK2J = ec._add_jac(K1J, K2J)
            assert ec._jac_equality(K1JK2J, shamir)

            k3 = 1 + secrets.randbelow(ec.n - 1)
            K3J = _mult_jac(k3, ec.GJ, ec)
            K1JK2JK3J = ec._add_jac(K1JK2J, K3J)
            boscoster = _multi_mult([k1, k2, k3], [ec.GJ, HJ, ec.GJ], ec)
            assert ec._jac_equality(K1JK2JK3J, boscoster)

            k4 = 1 + secrets.randbelow(ec.n - 1)
            K4J = _mult_jac(k4, HJ, ec)
            K1JK2JK3JK4J = ec._add_jac(K1JK2JK3J, K4J)
            points = [ec.GJ, HJ, ec.GJ, HJ]
            boscoster = _multi_mult([k1, k2, k3, k4], points, ec)
            assert ec._jac_equality(K1JK2JK3JK4J, boscoster)
            assert ec._jac_equality(K1JK2JK3J, _multi_mult([k1, k2, k3, 0], points, ec))
            assert ec._jac_equality(K1JK2J, _multi_mult([k1, k2, 0, 0], points, ec))
            assert ec._jac_equality(K1J, _multi_mult([k1, 0, 0, 0], points, ec))
            assert ec._jac_equality(INFJ, _multi_mult([0, 0, 0, 0], points, ec))

    err_msg = "mismatch between number of scalars and points: "
    with pytest.raises(ValueError, match=err_msg):
        _multi_mult([k1, k2, k3, k4], [ec.GJ, HJ, ec.GJ], ec)

    with pytest.raises(ValueError, match="negative first coefficient: "):
        _double_mult(-5, HJ, 1, ec.GJ, ec)
    with pytest.raises(ValueError, match="negative second coefficient: "):
        _double_mult(1, HJ, -5, ec.GJ, ec)


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
            assert shamir == K2
            shamir = double_mult(k1, ec.G, k2, INF, ec)
            assert shamir == K1

            shamir = double_mult(k1, ec.G, k2, H, ec)
            K1K2 = ec.add(K1, K2)
            assert K1K2 == shamir

            k3 = 1 + secrets.randbelow(ec.n - 1)
            K3 = mult(k3, ec.G, ec)
            K1K2K3 = ec.add(K1K2, K3)
            boscoster = multi_mult([k1, k2, k3], [ec.G, H, ec.G], ec)
            assert K1K2K3 == boscoster

            k4 = 1 + secrets.randbelow(ec.n - 1)
            K4 = mult(k4, H, ec)
            K1K2K3K4 = ec.add(K1K2K3, K4)
            points = [ec.G, H, ec.G, H]
            boscoster = multi_mult([k1, k2, k3, k4], points, ec)
            assert K1K2K3K4 == boscoster
            assert K1K2K3 == multi_mult([k1, k2, k3, 0], points, ec)
            assert K1K2 == multi_mult([k1, k2, 0, 0], points, ec)
            assert K1 == multi_mult([k1, 0, 0, 0], points, ec)
            assert INF == multi_mult([0, 0, 0, 0], points, ec)

    err_msg = "mismatch between number of scalars and points: "
    with pytest.raises(ValueError, match=err_msg):
        multi_mult([k1, k2, k3, k4], [ec.G, H, ec.G], ec)


def test_mult_double_mult() -> None:
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
