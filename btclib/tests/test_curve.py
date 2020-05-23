#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for `btclib.curve` module."

import pytest

from btclib.alias import INF
from btclib.curve import Curve


def test_exceptions():

    with pytest.raises(ValueError, match="p is not prime: "):
        Curve(15, 0, 2, (1, 9), 19, 1, False)

    with pytest.raises(ValueError, match="negative integer: "):
        Curve(13, -1, 2, (1, 9), 19, 1, False)

    with pytest.raises(ValueError, match="p <= a: "):
        Curve(13, 13, 2, (1, 9), 19, 1, False)

    with pytest.raises(ValueError, match="negative integer: "):
        Curve(13, 0, -2, (1, 9), 19, 1, False)

    with pytest.raises(ValueError, match="p <= b: "):
        Curve(13, 0, 13, (1, 9), 19, 1, False)

    with pytest.raises(ValueError, match="zero discriminant"):
        Curve(11, 7, 7, (1, 9), 19, 1, False)

    err_msg = "Generator must a be a sequence\\[int, int\\]"
    with pytest.raises(ValueError, match=err_msg):
        Curve(13, 0, 2, (1, 9, 1), 19, 1, False)

    with pytest.raises(ValueError, match="Generator is not on the curve"):
        Curve(13, 0, 2, (2, 9), 19, 1, False)

    with pytest.raises(ValueError, match="n is not prime: "):
        Curve(13, 0, 2, (1, 9), 20, 1, False)

    with pytest.raises(ValueError, match="n not in "):
        Curve(13, 0, 2, (1, 9), 71, 1, False)

    with pytest.raises(ValueError, match="INF point cannot be a generator"):
        Curve(13, 0, 2, INF, 19, 1, False)

    with pytest.raises(ValueError, match="n is not the group order: "):
        Curve(13, 0, 2, (1, 9), 17, 1, False)

    with pytest.raises(ValueError, match="invalid h: "):
        Curve(13, 0, 2, (1, 9), 19, 2, False)

    # n=p -> weak curve
    # missing

    with pytest.raises(UserWarning, match="weak curve"):
        Curve(11, 2, 7, (6, 9), 7, 2, True)

    # good curve
    ec = Curve(13, 0, 2, (1, 9), 19, 1, False)
    with pytest.raises(ValueError, match="x-coordinate not in 0..p-1: "):
        ec.y(ec.p)
