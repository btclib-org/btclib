#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.var_int` module."

import pytest

from btclib import var_int
from btclib.exceptions import BTClibValueError


def test_var_int_conversion() -> None:

    i = -1
    with pytest.raises(BTClibValueError, match="negative integer: "):
        var_int.serialize(i)

    i = 0x00
    b = var_int.serialize(i)
    assert len(b) == 1
    assert var_int.deserialize(b) == i

    i += 1
    b = var_int.serialize(i)
    assert len(b) == 1
    assert var_int.deserialize(b) == i

    i = 0xFC
    b = var_int.serialize(i)
    assert len(b) == 1
    assert var_int.deserialize(b) == i

    i += 1
    b = var_int.serialize(i)
    assert len(b) == 3
    assert var_int.deserialize(b) == i

    i = 0xFFFF
    b = var_int.serialize(i)
    assert len(b) == 3
    assert var_int.deserialize(b) == i

    i += 1
    b = var_int.serialize(i)
    assert len(b) == 5
    assert var_int.deserialize(b) == i

    i = 0xFFFFFFFF
    b = var_int.serialize(i)
    assert len(b) == 5
    assert var_int.deserialize(b) == i

    i += 1
    b = var_int.serialize(i)
    assert len(b) == 9
    assert var_int.deserialize(b) == i

    i = 0xFFFFFFFFFFFFFFFF
    b = var_int.serialize(i)
    assert len(b) == 9
    assert var_int.deserialize(b) == i

    i += 1
    with pytest.raises(
        BTClibValueError, match="integer too big for var_int encoding: "
    ):
        var_int.serialize(i)

    assert var_int.deserialize("6a") == 106
    assert var_int.deserialize("fd2602") == 550
    assert var_int.deserialize("fe703a0f00") == 998000
