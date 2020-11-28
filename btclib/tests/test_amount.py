#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.amount` module."

from btclib import amount


def test_amount_conversion() -> None:
    v1 = 1.1
    v2 = 2.2
    vtot = v1 + v2
    # _NOT_ equal !!
    assert vtot != 3.3
    s_1 = amount.sat_from_float(v1)
    s_2 = amount.sat_from_float(v2)
    stot = s_1 + s_2
    assert stot == 330000000
    vtot = amount.float_from_sat(stot)
    # equal !!
    assert vtot == 3.3
