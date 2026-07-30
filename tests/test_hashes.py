#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the `btclib.hashes` module."""

from hashlib import sha256

from btclib.hashes import hash160, hash256, magic_message
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


def test_magic_message_length_prefix() -> None:
    """The message length is a var_int, as Bitcoin Core serializes it.

    The expected length prefixes are spelled out here instead of being
    computed with var_int.serialize, so that the test pins the wire
    format rather than re-deriving it from the code under test: a
    one-byte length would agree up to 252 bytes, silently diverge from
    253 to 255, and overflow above that.
    """
    magic = b"\x18Bitcoin Signed Message:\n"
    test_vectors = (
        (0, b"\x00"),
        (1, b"\x01"),
        (252, b"\xfc"),
        (253, b"\xfd\xfd\x00"),
        (255, b"\xfd\xff\x00"),
        (256, b"\xfd\x00\x01"),
        (0xFFFF, b"\xfd\xff\xff"),
        (0x10000, b"\xfe\x00\x00\x01\x00"),
    )
    for length, prefix in test_vectors:
        msg = b"a" * length
        assert magic_message(msg) == sha256(magic + prefix + msg).digest()
