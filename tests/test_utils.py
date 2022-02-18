#!/usr/bin/env python3

# Copyright (C) 2017-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.utils` module."

# Standard library imports
import secrets

# Third party imports
import pytest

# Library imports
from btclib.exceptions import BTClibValueError
from btclib.utils import decode_num, encode_num, hex_string, int_from_integer


def test_int_from_integer() -> None:
    for i in (
        secrets.randbits(256 - 8),
        0x0B6CA75B7D3076C561958CCED813797F6D2275C7F42F3856D007D587769A90,
    ):
        assert i == int_from_integer(i)
        assert i == int_from_integer(" " + hex(i).upper())
        assert -i == int_from_integer(hex(-i).upper() + " ")
        assert i == int_from_integer(hex_string(i))
        assert i == int_from_integer(i.to_bytes(32, byteorder="big", signed=False))


def test_hex_string() -> None:
    int_ = 34492435054806958080
    assert hex_string(int_) == "01 DEADBEEF 00000000"
    assert hex_string(hex(int_).lower()) == "01 DEADBEEF 00000000"

    a_str = "01de adbeef00000000"
    assert hex_string(a_str) == "01 DEADBEEF 00000000"
    a_bytes = bytes.fromhex(a_str)
    assert hex_string(a_bytes) == "01 DEADBEEF 00000000"

    # invalid hex-string: odd number of hex digits
    a_str = "1deadbeef00000000"
    with pytest.raises(ValueError, match="non-hexadecimal number found in fromhex"):
        hex_string(a_str)

    int_ = -1
    with pytest.raises(BTClibValueError, match="negative integer: "):
        hex_string(int_)


def test_encode_num() -> None:

    with pytest.raises(BTClibValueError, match="empty byte string"):
        decode_num(b"")

    # different representations of zero
    assert decode_num(b"\x00") == 0  # "positive" zero
    assert decode_num(b"\x80") == 0  # "negative" zero

    for i in range(-255, 256):
        assert decode_num(encode_num(i)) == i

    for i in [
        0x80FF,
        0xFFFF,
        0x80FFFF,
        0xFFFFFF,
        0x80FFFFFF,
        0xFFFFFFFF,
        0x80FFFFFFFF,
        0xFFFFFFFFFF,
    ]:
        assert decode_num(encode_num(i - 1)) == i - 1
        assert decode_num(encode_num(i)) == i
        assert decode_num(encode_num(i + 1)) == i + 1

        assert decode_num(encode_num(-i - 1)) == -i - 1
        assert decode_num(encode_num(-i)) == -i
        assert decode_num(encode_num(-i + 1)) == -i + 1

    # 7 bits + sign bit = 8 bits = 1 byte (plus 1 byte for length)
    i = 0b01111111
    assert len(encode_num(i)) == 1
    # 8 bits + sign bit = 9 bits = 2 byte (plus 1 byte for length)
    i = 0b11111111
    assert len(encode_num(i)) == 2
    # 15 bits + sign bit = 16 bits = 2 byte (plus 1 byte for length)
    i = 0b0111111111111111
    assert len(encode_num(i)) == 2
    # 16 bits + sign bit = 17 bits = 3 byte (plus 1 byte for length)
    i = 0b1111111111111111
    assert len(encode_num(i)) == 3
