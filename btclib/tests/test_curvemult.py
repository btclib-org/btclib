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

from btclib.alias import INFJ
from btclib.curvemult import _double_mult, double_mult, mult, _multi_mult
from btclib.curve import _mult_jac, _jac_from_aff
from btclib.curves import secp256k1
from btclib.tests.test_curves import low_card_curves
from btclib.pedersen import second_generator

ec23_31 = low_card_curves["ec23_31"]


def test_assorted_mult():
    ec = ec23_31
    H = second_generator(ec)
    HJ = _jac_from_aff(H)
    for k1 in range(1, ec.n):
        k2 = 1 + secrets.randbelow(ec.n - 1)
        shamir = _double_mult(k1, ec.GJ, k2, ec.GJ, ec)
        assert ec._jac_equality(shamir, _mult_jac(k1 + k2, ec.GJ, ec))
        shamir = _double_mult(k1, INFJ, k2, ec.GJ, ec)
        assert ec._jac_equality(shamir, _mult_jac(k2, ec.GJ, ec))
        shamir = _double_mult(k1, ec.GJ, k2, INFJ, ec)
        assert ec._jac_equality(shamir, _mult_jac(k1, ec.GJ, ec))

        shamir = _double_mult(k1, ec.GJ, k2, HJ, ec)
        std = ec._add_jac(_mult_jac(k1, ec.GJ, ec), _mult_jac(k2, HJ, ec))
        assert ec._jac_equality(std, shamir)

        k3 = 1 + secrets.randbelow(ec.n - 1)
        std = ec._add_jac(std, _mult_jac(k3, ec.GJ, ec))
        boscoster = _multi_mult([k1, k2, k3], [ec.GJ, HJ, ec.GJ], ec)
        assert ec._jac_equality(std, boscoster)

        k4 = 1 + secrets.randbelow(ec.n - 1)
        std = ec._add_jac(std, _mult_jac(k4, HJ, ec))
        boscoster = _multi_mult([k1, k2, k3, k4], [ec.GJ, HJ, ec.GJ, HJ], ec)
        assert ec._jac_equality(std, boscoster)

    err_msg = "mismatch between number of scalars and points: "
    with pytest.raises(ValueError, match=err_msg):
        _multi_mult([k1, k2, k3, k4], [ec.GJ, HJ, ec.GJ], ec)


def test_mult_double_mult():
    H = second_generator(secp256k1)
    G = secp256k1.G

    # 0*G + 1*H
    T = double_mult(1, H, 0, G)
    assert T == H

    # 0*G + 2*H
    T = double_mult(2, H, 0, G)
    assert T == mult(2, H)

    # 0*G + 3*H
    T = double_mult(3, H, 0, G)
    assert T == mult(3, H)

    # 1*G + 0*H
    T = double_mult(0, H, 1, G)
    assert T == G

    # 2*G + 0*H
    T = double_mult(0, H, 2, G)
    assert T == mult(2, G)

    # 3*G + 0*H
    T = double_mult(0, H, 3, G)
    assert T == mult(3, G)

    # 0*G + 5*H
    T = double_mult(5, H, 0, G)
    assert T == mult(5, H)

    # 0*G - 5*H
    T = double_mult(-5, H, 0, G)
    assert T == mult(-5, H)

    # 1*G - 5*H
    U = double_mult(-5, H, 1, G)
    assert U == secp256k1.add(G, T)
