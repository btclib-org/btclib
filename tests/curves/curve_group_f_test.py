# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.curve_group_f` module."""

import pytest

from btclib.curves import CurveGroup, find_all_points, find_subgroup_points
from btclib.curves.curve_group import _mult_aff_var
from btclib.exceptions import BTClibValueError


def test_ecf() -> None:
    """Verify group arithmetic over F_9739 against precomputed points."""
    ec = CurveGroup(9739, 497, 1768)

    # Point Negation
    P = (8045, 6936)
    S = ec.negate(P)
    S_exp = (8045, 2803)
    assert S_exp == S

    # Point Addition
    X = (5274, 2841)
    Y = (8669, 740)
    assert ec.add_var(X, Y) == (1024, 4440)
    assert ec.add_var(X, X) == (7284, 2107)
    P = (493, 5564)
    Q = (1539, 4742)
    R = (4403, 5202)
    S = ec.add_var(ec.add_var(ec.add_var(P, P), Q), R)
    ec.require_on_curve(S)
    S_exp = (4215, 2162)
    assert S_exp == S

    # Scalar Multiplication
    X = (5323, 5438)
    assert _mult_aff_var(1337, X, ec) == (1089, 6931)
    P = (2339, 2213)
    S = _mult_aff_var(7863, P, ec)
    ec.require_on_curve(S)
    S_exp = (9467, 2742)
    assert S_exp == S

    # Curves and Logs
    all_points = find_all_points(ec)
    assert len(all_points) == 9735
    G = (1804, 5368)
    points = find_subgroup_points(ec, G)
    assert len(points) == 9735


def test_ecf_exceptions() -> None:
    """Refuse to enumerate points when the field prime is too big."""
    ec = CurveGroup(10007, 497, 1768)

    err_msg = "p is too big to count all group points: "
    with pytest.raises(BTClibValueError, match=err_msg):
        find_all_points(ec)

    err_msg = "p is too big to count all subgroup points: "
    with pytest.raises(BTClibValueError, match=err_msg):
        # p (10007) is too big to count all subgroup points
        G = (2, 3265)
        find_subgroup_points(ec, G)


def test_a_point_whose_y_is_zero_is_listed_once() -> None:
    """A point of order two is its own negative, and the walk knows it.

    `y != 0` is what stops `(x, p - y)` being appended beside `(x, y)`
    where the two are the same point, and F_9739 above has no such point
    to take that branch with. `b = 0` puts one at the origin -- the roots
    of `y**2 = x**3 + x` include x = 0 -- and the curve is non-singular
    there all the same, `4a**3 + 27b**2` being 4.
    """
    ec = CurveGroup(11, 1, 0)
    points = find_all_points(ec)

    ec.require_on_curve((0, 0))
    assert points.count((0, 0)) == 1
    # the ordinary case beside it: two distinct roots, both listed
    assert points.count((9, 1)) == points.count((9, 10)) == 1
    assert len(points) == len(set(points))
