#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the `btclib.var_int` module."""

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
    # above MAX_SIZE, so parsing it back takes an explicit max_size
    assert var_int.parse(bytes_, max_size=int_) == int_

    int_ += 1
    bytes_ = var_int.serialize(int_)
    assert len(bytes_) == 9
    assert var_int.parse(bytes_, max_size=int_) == int_

    int_ = 0xFFFFFFFFFFFFFFFF
    bytes_ = var_int.serialize(int_)
    assert len(bytes_) == 9
    assert var_int.parse(bytes_, max_size=int_) == int_

    int_ += 1
    with pytest.raises(
        BTClibValueError, match="integer too big for var_int encoding: "
    ):
        var_int.serialize(int_)

    assert var_int.parse("6a") == 106
    assert var_int.parse("fd2602") == 550
    assert var_int.parse("fe703a0f00") == 998000


def test_var_int_max_size() -> None:
    """The MAX_SIZE range check of Bitcoin Core's ReadCompactSize."""
    assert var_int.parse(var_int.serialize(var_int.MAX_SIZE)) == var_int.MAX_SIZE

    with pytest.raises(BTClibValueError, match="var_int too big: "):
        var_int.parse(var_int.serialize(var_int.MAX_SIZE + 1))

    # the cap is what keeps a count from driving an allocation: nine bytes
    # would otherwise ask for 2^64-1 elements
    with pytest.raises(BTClibValueError, match="var_int too big: "):
        var_int.parse(b"\xff" + b"\xff" * 8)

    # a caller can still raise it for a var_int that is neither a length
    # nor a count
    assert var_int.parse("fe00000004", max_size=0xFFFFFFFF) == 0x04000000


def test_var_int_non_canonical() -> None:
    """Only the shortest encoding is valid, as in Bitcoin Core."""
    # 1 fits in one byte, 0xfd in two, 0x10000 in four
    for encoding in ("fd0100", "fd0000", "fe01000000", "fefdff0000", "fefeff0000"):
        with pytest.raises(BTClibValueError, match="non-canonical var_int: "):
            var_int.parse(encoding)
    with pytest.raises(BTClibValueError, match="non-canonical var_int: "):
        var_int.parse(b"\xff" + (0xFFFFFFFF).to_bytes(8, "little"))

    # the boundary values are the shortest encoding of themselves
    assert var_int.parse("fcfd") == 0xFC  # 0xfc is a one byte integer
    assert var_int.parse("fdfd00") == 0xFD
    assert var_int.parse("fe00000100") == 0x0001_0000
    int_ = 0x1_0000_0000
    assert var_int.parse(b"\xff" + int_.to_bytes(8, "little"), max_size=int_) == int_


def test_var_int_truncated() -> None:
    """A read that comes up short is an error, not a zero."""
    # stream.read returns b"" past the end of the stream without raising,
    # and int.from_bytes(b"") is 0: without the length check, `fd` parses
    # as 0 and `fd01` as 1
    for encoding in (b"", b"\xfd", b"\xfd\x01", b"\xfe\x01\x00", b"\xff\x01"):
        with pytest.raises(
            BTClibValueError, match="not enough binary data for var_int"
        ):
            var_int.parse(encoding)
