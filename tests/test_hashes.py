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

import pytest

from btclib.exceptions import BTClibValueError
from btclib.hashes import (
    hash160,
    hash256,
    magic_message,
    merkle_root,
    merkle_root_and_mutated,
)
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


def test_merkle_root_mutation() -> None:
    """A duplicated trailing subtree is flagged, padding is not.

    CVE-2012-2459: duplicating the trailing subtree of a level leaves the
    root unchanged, so the root alone does not commit to the list. The
    expected flags are spelled out per list rather than derived, because
    the failure being guarded against is exactly a wrong rule: flagging
    the padding of an odd level would reject the honest lists here.
    """
    a, b, c, d, e, f = (bytes([i]) * 32 for i in range(6))
    test_vectors = (
        ([a], False),
        ([a, b], False),
        ([a, b, c], False),  # c is padded with itself: honest
        ([a, b, c, c], True),  # ...and here duplicated: mutated
        ([a, b, c, d, e], False),
        ([a, b, c, d, e, f], False),
        # duplicating two leaves shows up one level up, not at the leaves
        ([a, b, c, d, e, f, e, f], True),
    )
    for data, mutated in test_vectors:
        assert merkle_root_and_mutated(data, hash256)[1] is mutated

    # the root cannot tell the mutation from the list it was built on
    assert merkle_root([a, b, c], hash256) == merkle_root([a, b, c, c], hash256)
    assert merkle_root([a, b, c, d, e, f], hash256) == merkle_root(
        [a, b, c, d, e, f, e, f], hash256
    )


def test_merkle_root_empty() -> None:
    # it used to loop forever, never reducing an empty level to a root
    with pytest.raises(BTClibValueError, match="empty merkle tree"):
        merkle_root([], hash256)
