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

from btclib.tests.test_to_key import (
    net_unaware_compressed_pub_keys,
    net_unaware_uncompressed_pub_keys,
    plain_prv_keys,
)
from btclib.utils import bytes_from_octets, hash160, hash256, int_from_integer


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
    i = secrets.randbits(256)
    assert i == int_from_integer(i)
    assert i == int_from_integer(i.to_bytes(32, "big"))
    assert i == int_from_integer(hex(i))
