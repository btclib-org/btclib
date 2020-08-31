#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for `btclib.curvegroupf` module."

import pytest

from btclib.curvegroup import CurveGroup, _mult_aff
from btclib.curvegroupf import find_all_points, find_subgroup_points


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
    assert _mult_aff(1337, X, ec) == (1089, 6931)
    P = (2339, 2213)
    S = _mult_aff(7863, P, ec)
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
    # S = _mult_aff(nB, QA, ec)
    # b = S[0].to_bytes(ec.psize, 'big')
    # s = sha1(b).hexdigest()
    # print(f"{challenge}: {s}")


def test_ecf_exceptions() -> None:
    ec = CurveGroup(10007, 497, 1768)

    with pytest.raises(ValueError, match="p is too big to count all group points: "):
        find_all_points(ec)

    with pytest.raises(ValueError, match="p is too big to count all subgroup points: "):
        # p (10007) is too big to count all subgroup points
        G = (2, 3265)
        find_subgroup_points(ec, G)
