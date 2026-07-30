#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the `btclib.psbt.psbt_utils` module."""

import pytest

from btclib.bip32 import BIP32KeyOrigin
from btclib.exceptions import BTClibValueError
from btclib.psbt import serialize_hd_key_paths
from btclib.psbt.psbt_utils import (
    deserialize_map,
    parse_taproot_bip32,
    serialize_taproot_bip32,
)


def test_invalid_serialize_hd_key_paths() -> None:
    with pytest.raises(BTClibValueError, match="invalid type marker length: "):
        serialize_hd_key_paths(b"\x01\x01", [])  # type: ignore[arg-type]


def test_parse_taproot_bip32() -> None:
    """A leaf hash is 32 bytes, not 4 (BIP-371)."""
    leaf_hashes = [bytes(range(32)), bytes(range(32, 64))]
    key_origin = BIP32KeyOrigin(b"\xde\xad\xbe\xef", "m/86h/1h/0h/0/0")
    v = b"\x02" + b"".join(leaf_hashes) + key_origin.serialize()

    assert parse_taproot_bip32(v) == (leaf_hashes, key_origin)

    # a 4-byte read would have left 60 bytes of leaf hash to be taken as
    # the master fingerprint and the derivation path
    pub_key = b"\x02" * 32
    dict_ = {pub_key: (leaf_hashes, key_origin)}
    assert serialize_taproot_bip32(b"\x16", dict_)[-len(v) :] == v


def test_parse_taproot_bip32_hostile_count() -> None:
    """A count is bounded by the data, not trusted (issue #133)."""
    # 0xfe0000_0400 is a count of 262144: without the bound, five bytes
    # cost a 262144-element list, and nine bytes never terminate
    for v in (b"\xfe\x00\x00\x04\x00", b"\xfe\x00\x00\x10\x00"):
        with pytest.raises(BTClibValueError, match="invalid number of leaf hashes: "):
            parse_taproot_bip32(v)

    with pytest.raises(BTClibValueError, match="var_int too big: "):
        parse_taproot_bip32(b"\xff" + b"\xff" * 8)

    # one leaf hash announced, one byte short of it
    with pytest.raises(BTClibValueError, match="invalid number of leaf hashes: "):
        parse_taproot_bip32(b"\x01" + b"\x00" * 31 + b"\xde\xad\xbe\xef")


def test_deserialize_map_short_read() -> None:
    """An announced size is bounded by the data, not taken on trust.

    BytesIO.read hands back whatever is left rather than what was asked
    for, so every buffer below used to deserialize to the very same map
    -- {b"A": b"B"} -- and serialize back to only one of them.
    """
    assert deserialize_map(b"\x01A\x01B\x00")[0] == {b"A": b"B"}

    err_msg = "malformed psbt: not enough data for the map value, "
    for announced_size in (b"\x02", b"\x05", b"\x09"):
        with pytest.raises(BTClibValueError, match=err_msg):
            deserialize_map(b"\x01A" + announced_size + b"B")

    err_msg = "malformed psbt: not enough data for the map key, "
    with pytest.raises(BTClibValueError, match=err_msg):
        deserialize_map(b"\x05AB")


def test_deserialize_map_unterminated() -> None:
    """Running out of buffer is not the 0x00 that ends a map.

    Reading the separator without checking that there was one to read
    answered a truncated psbt with an IndexError.
    """
    err_msg = "malformed psbt: unterminated map"
    with pytest.raises(BTClibValueError, match=err_msg):
        deserialize_map(b"\x01A\x01B")
