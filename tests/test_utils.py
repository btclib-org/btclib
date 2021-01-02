#!/usr/bin/env python3

# Copyright (C) 2017-2021 The btclib developers
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
from btclib.utils import hash160, hash256, hex_string, int_from_integer
from tests.test_to_key import (
    net_unaware_compressed_pub_keys,
    net_unaware_uncompressed_pub_keys,
    plain_prv_keys,
)


def test_hash160_hash256() -> None:
    test_vectors = (
        plain_prv_keys
        + net_unaware_compressed_pub_keys
        + net_unaware_uncompressed_pub_keys
    )
    for hexstring in test_vectors:
        hash160(hexstring)
        hash256(hexstring)


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
