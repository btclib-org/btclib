#!/usr/bin/env python3

# Copyright (C) 2020-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""CurveGroup explorer functions.

These functions are meant to explore low-cardinality CurveGroup,
for didactical (and fun) reason only.
"""

from typing import List

from btclib.alias import INF, Point
from btclib.ecc.curve import CurveGroup
from btclib.exceptions import BTClibValueError


def find_all_points(ec: CurveGroup) -> List[Point]:
    """Attemp to find all group points, if p is low.

    Very unsofisticated walk-through approach,
    for didactical sake only.
    """
    if ec.p > 10000:
        err_msg = f"p is too big to count all group points: {ec.p}"
        raise BTClibValueError(err_msg)

    points: List[Point] = [INF]
    for x in range(ec.p):
        try:
            y = ec.y(x)
        except BTClibValueError:
            continue

        points.append((x, y))
        if y != 0:
            points.append((x, ec.p - y))

    return points


def find_subgroup_points(ec: CurveGroup, G: Point) -> List[Point]:
    """Attemp to count all G-generated subgroup points, if p is low.

    Very unsofisticated walk-through approach,
    for didactical sake only.
    """
    if ec.p > 10000:
        err_msg = f"p is too big to count all subgroup points: {ec.p}"
        raise BTClibValueError(err_msg)

    points: List[Point] = [G]
    while points[-1] != INF:
        Q = ec.add(points[-1], G)
        points.append(Q)

    return points
