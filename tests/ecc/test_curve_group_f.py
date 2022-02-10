#!/usr/bin/env python3

# Copyright (C) 2020-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.curve_group_f` module."

import pytest

from btclib.ecc.curve_group import CurveGroup, mult_aff
from btclib.ecc.curve_group_f import find_all_points, find_subgroup_points
from btclib.exceptions import BTClibValueError


def test_ecf() -> None:
    ec = CurveGroup(9739, 497, 1768)

    # challenge = 'Point Negation'
    P = (8045, 6936)
    S = ec.negate(P)
    S_exp = (8045, 2803)
    assert S == S_exp

    # challenge = 'Point Addition'
    X = (5274, 2841)
    Y = (8669, 740)
    assert ec.add(X, Y) == (1024, 4440)
    assert ec.add(X, X) == (7284, 2107)
    P = (493, 5564)
    Q = (1539, 4742)
    R = (4403, 5202)
    S = ec.add(ec.add(ec.add(P, P), Q), R)
    ec.require_on_curve(S)
    S_exp = (4215, 2162)
    assert S == S_exp

    # challenge = 'Scalar Multiplication'
    X = (5323, 5438)
    assert mult_aff(1337, X, ec) == (1089, 6931)
    P = (2339, 2213)
    S = mult_aff(7863, P, ec)
    ec.require_on_curve(S)
    S_exp = (9467, 2742)
    assert S == S_exp

    # challenge = 'Curves and Logs'
    all_points = find_all_points(ec)
    assert len(all_points) == 9735
    G = (1804, 5368)
    points = find_subgroup_points(ec, G)
    assert len(points) == 9735
    # QA = (815, 3190)
    # nB = 1829
    # S = mult_aff(nB, QA, ec)
    # b = S[0].to_bytes(ec.p_size, byteorder="big", signed=False)
    # s = sha1(b).hexdigest()
    # print(f"{challenge}: {s}")


def test_ecf_exceptions() -> None:
    ec = CurveGroup(10007, 497, 1768)

    err_msg = "p is too big to count all group points: "
    with pytest.raises(BTClibValueError, match=err_msg):
        find_all_points(ec)

    err_msg = "p is too big to count all subgroup points: "
    with pytest.raises(BTClibValueError, match=err_msg):
        # p (10007) is too big to count all subgroup points
        G = (2, 3265)
        find_subgroup_points(ec, G)
