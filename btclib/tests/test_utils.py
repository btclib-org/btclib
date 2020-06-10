#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for `btclib.utils` module."

import secrets

import pytest

from btclib.tests.test_to_key import (
    net_unaware_compressed_pub_keys,
    net_unaware_uncompressed_pub_keys,
    plain_prv_keys,
)
from btclib.utils import (
    bytes_from_octets,
    hash160,
    hash256,
    hex_string,
    int_from_integer,
)


def test_hash160_hash256():
    test_vectors = (
        plain_prv_keys
        + net_unaware_compressed_pub_keys
        + net_unaware_uncompressed_pub_keys
    )
    for hexstring in test_vectors:
        b = bytes_from_octets(hexstring)
        s = b.hex()  # lower case, no spaces
        assert hash160(hexstring) == hash160(s)
        assert hash256(hexstring) == hash256(s)


def test_int_from_integer():
    for i in (
        secrets.randbits(256 - 8),
        0x0B6CA75B7D3076C561958CCED813797F6D2275C7F42F3856D007D587769A90,
    ):
        assert i == int_from_integer(i)
        assert i == int_from_integer(hex(i).upper())
        assert i == int_from_integer(hex_string(i))
        assert i == int_from_integer(i.to_bytes(32, "big"))


def test_hex_string():
    a = 34492435054806958080
    assert hex_string(a) == "01 DEADBEEF 00000000"
    assert hex_string(hex(a).lower()) == "01 DEADBEEF 00000000"
    assert hex_string(bin(a).lower()) == "01 DEADBEEF 00000000"

    a = "01de adbeef00000000"
    assert hex_string(a) == "01 DEADBEEF 00000000"
    a = bytes.fromhex(a)
    assert hex_string(a) == "01 DEADBEEF 00000000"

    # invalid hex-string: odd number of hex digits
    a = "1deadbeef00000000"
    with pytest.raises(ValueError, match="non-hexadecimal number found in fromhex"):
        hex_string(a)

    a = -1
    with pytest.raises(ValueError, match="negative integer: "):
        hex_string(a)
