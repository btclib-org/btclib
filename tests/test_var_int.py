#!/usr/bin/env python3

# Copyright (C) 2017-2022 The btclib developers
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

    int_ = -1
    with pytest.raises(BTClibValueError, match="negative integer: "):
        var_int.serialize(int_)

    int_ = 0x00
    bytes_ = var_int.serialize(int_)
    assert len(bytes_) == 1
    assert var_int.parse(bytes_) == int_

    int_ += 1
    bytes_ = var_int.serialize(int_)
    assert len(bytes_) == 1
    assert var_int.parse(bytes_) == int_

    int_ = 0xFC
    bytes_ = var_int.serialize(int_)
    assert len(bytes_) == 1
    assert var_int.parse(bytes_) == int_

    int_ += 1
    bytes_ = var_int.serialize(int_)
    assert len(bytes_) == 3
    assert var_int.parse(bytes_) == int_

    int_ = 0xFFFF
    bytes_ = var_int.serialize(int_)
    assert len(bytes_) == 3
    assert var_int.parse(bytes_) == int_

    int_ += 1
    bytes_ = var_int.serialize(int_)
    assert len(bytes_) == 5
    assert var_int.parse(bytes_) == int_

    int_ = 0xFFFFFFFF
    bytes_ = var_int.serialize(int_)
    assert len(bytes_) == 5
    assert var_int.parse(bytes_) == int_

    int_ += 1
    bytes_ = var_int.serialize(int_)
    assert len(bytes_) == 9
    assert var_int.parse(bytes_) == int_

    int_ = 0xFFFFFFFFFFFFFFFF
    bytes_ = var_int.serialize(int_)
    assert len(bytes_) == 9
    assert var_int.parse(bytes_) == int_

    int_ += 1
    with pytest.raises(
        BTClibValueError, match="integer too big for var_int encoding: "
    ):
        var_int.serialize(int_)

    assert var_int.parse("6a") == 106
    assert var_int.parse("fd2602") == 550
    assert var_int.parse("fe703a0f00") == 998000
