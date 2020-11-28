#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.varint` module."

import pytest

from btclib import varint
from btclib.exceptions import BTClibValueError


def test_varint_conversion() -> None:

    i = -1
    with pytest.raises(BTClibValueError, match="negative integer: "):
        varint.encode(i)

    i = 0x00
    b = varint.encode(i)
    assert len(b) == 1
    assert varint.decode(b) == i

    i += 1
    b = varint.encode(i)
    assert len(b) == 1
    assert varint.decode(b) == i

    i = 0xFC
    b = varint.encode(i)
    assert len(b) == 1
    assert varint.decode(b) == i

    i += 1
    b = varint.encode(i)
    assert len(b) == 3
    assert varint.decode(b) == i

    i = 0xFFFF
    b = varint.encode(i)
    assert len(b) == 3
    assert varint.decode(b) == i

    i += 1
    b = varint.encode(i)
    assert len(b) == 5
    assert varint.decode(b) == i

    i = 0xFFFFFFFF
    b = varint.encode(i)
    assert len(b) == 5
    assert varint.decode(b) == i

    i += 1
    b = varint.encode(i)
    assert len(b) == 9
    assert varint.decode(b) == i

    i = 0xFFFFFFFFFFFFFFFF
    b = varint.encode(i)
    assert len(b) == 9
    assert varint.decode(b) == i

    i += 1
    with pytest.raises(BTClibValueError, match="integer too big for varint encoding: "):
        varint.encode(i)

    assert varint.decode("6a") == 106
    assert varint.decode("fd2602") == 550
    assert varint.decode("fe703a0f00") == 998000
