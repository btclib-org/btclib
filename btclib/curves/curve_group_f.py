#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""CurveGroup explorer functions, for low-cardinality didactic curves.

Enumerating the points of a group is feasible only when the group is
tiny, which is what makes these useful in teaching and useless -- and
never used -- in the rest of the library.
"""

from __future__ import annotations

from btclib.alias import INF, Point
from btclib.curves.curve_group import CurveGroup
from btclib.exceptions import BTClibValueError


def find_all_points(ec: CurveGroup) -> list[Point]:
    """Attempt to find all group points, if p is low.

    Very unsofisticated walk-through approach, for didactic sake only.
    """
    if ec.p > 10000:
        err_msg = f"p is too big to count all group points: {ec.p}"
        raise BTClibValueError(err_msg)

    points: list[Point] = [INF]
    for x in range(ec.p):
        try:
            y = ec.y(x)
        except BTClibValueError:
            continue

        points.append((x, y))
        if y != 0:
            points.append((x, ec.p - y))

    return points


def find_subgroup_points(ec: CurveGroup, G: Point) -> list[Point]:
    """Attempt to count all G-generated subgroup points, if p is low.

    Very unsofisticated walk-through approach, for didactic sake only.
    """
    if ec.p > 10000:
        err_msg = f"p is too big to count all subgroup points: {ec.p}"
        raise BTClibValueError(err_msg)

    points = [G]
    while points[-1] != INF:
        Q = ec.add(points[-1], G)
        points.append(Q)

    return points
