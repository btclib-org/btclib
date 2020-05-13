#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import pytest

from btclib import bip32
from btclib.alias import INF
from btclib.curves import CURVES
from btclib.secpoint import bytes_from_point
from btclib.tests.test_to_prvkey import (
    Q,
    compressed_prv_keys,
    compressed_pub_keys,
    invalid_prv_keys,
    prv_keys,
    uncompressed_prv_keys,
    uncompressed_pub_keys,
    xpub,
    xpub_dict,
)
from btclib.to_pubkey import (
    fingerprint,
    point_from_key,
    point_from_pubkey,
    pubkeyinfo_from_key,
    pubkeyinfo_from_pubkey,
)

not_a_pub_keys = [
    prv_keys,
    compressed_prv_keys,
    uncompressed_prv_keys,
    INF,
    b"\x02" + INF[0].to_bytes(32, "big"),
    b"\x04" + INF[0].to_bytes(32, "big") + INF[1].to_bytes(32, "big"),
    # INF as WIF
    # INF as xpub
    # INF as hex-string
]

invalid_pub_keys = []

# xprv with xpub_version and viceversa

secp256r1 = CURVES["secp256r1"]
# test wrong curve

# FIXME: fix error messages


def test_from_key():

    t = bytes_from_point(Q, compressed=True), "mainnet"
    for pubkey in [Q] + compressed_pub_keys:
        assert Q == point_from_pubkey(pubkey)
        assert t == pubkeyinfo_from_pubkey(pubkey)
        assert t == pubkeyinfo_from_pubkey(pubkey, "mainnet")
        assert t == pubkeyinfo_from_pubkey(pubkey, "mainnet", compressed=True)
        assert t == pubkeyinfo_from_pubkey(pubkey, compressed=True)
    for key in [Q] + compressed_pub_keys + prv_keys + compressed_prv_keys:
        assert Q == point_from_key(key)
        assert t == pubkeyinfo_from_key(key)
        assert t == pubkeyinfo_from_key(key, "mainnet")
        assert t == pubkeyinfo_from_key(key, "mainnet", compressed=True)
        assert t == pubkeyinfo_from_key(key, compressed=True)

    t = bytes_from_point(Q, compressed=False), "mainnet"
    for pubkey in uncompressed_pub_keys:
        assert Q == point_from_pubkey(pubkey)
        assert t == pubkeyinfo_from_pubkey(pubkey)
        assert t == pubkeyinfo_from_pubkey(pubkey, "mainnet", compressed=False)
        assert t == pubkeyinfo_from_pubkey(pubkey, compressed=False)
    for key in uncompressed_pub_keys + uncompressed_prv_keys:
        assert Q == point_from_key(key)
        assert t == pubkeyinfo_from_key(key)
        assert t == pubkeyinfo_from_key(key, "mainnet", compressed=False)
        assert t == pubkeyinfo_from_key(key, compressed=False)

    for pubkey in uncompressed_pub_keys:
        with pytest.raises(ValueError):
            pubkeyinfo_from_pubkey(pubkey)
            pubkeyinfo_from_pubkey(pubkey, "mainnet", compressed=True)
            pubkeyinfo_from_pubkey(pubkey, compressed=True)
    for key in uncompressed_pub_keys + uncompressed_prv_keys:
        with pytest.raises(ValueError):
            pubkeyinfo_from_pubkey(key)
            pubkeyinfo_from_pubkey(key, "mainnet", compressed=True)
            pubkeyinfo_from_pubkey(key, compressed=True)

    for pubkey in compressed_pub_keys:
        with pytest.raises(ValueError):
            pubkeyinfo_from_pubkey(pubkey, "mainnet", compressed=False)
            pubkeyinfo_from_pubkey(pubkey, compressed=False)
    for key in compressed_pub_keys + compressed_prv_keys:
        with pytest.raises(ValueError):
            pubkeyinfo_from_pubkey(key, "mainnet", compressed=False)
            pubkeyinfo_from_pubkey(key, compressed=False)

    for not_a_pub_key in not_a_pub_keys:
        with pytest.raises(ValueError):
            point_from_pubkey(not_a_pub_key)
            pubkeyinfo_from_pubkey(not_a_pub_key)
    for not_a_key in not_a_pub_keys:
        with pytest.raises(ValueError):
            point_from_key(not_a_key)
            pubkeyinfo_from_key(not_a_key)

    for invalid_pub_key in invalid_pub_keys:
        with pytest.raises(ValueError):
            point_from_pubkey(invalid_pub_key)
            pubkeyinfo_from_pubkey(invalid_pub_key)
    for invalid_key in invalid_pub_keys + invalid_prv_keys:
        with pytest.raises(ValueError):
            point_from_key(invalid_key)
            pubkeyinfo_from_key(invalid_key)

    for pubkey in compressed_pub_keys + uncompressed_pub_keys:
        with pytest.raises(ValueError):
            point_from_pubkey(pubkey, "testnet")
            pubkeyinfo_from_pubkey(pubkey, "testnet", compressed=True)
            pubkeyinfo_from_pubkey(pubkey, "testnet", compressed=False)
    for key in (
        compressed_pub_keys
        + uncompressed_pub_keys
        + compressed_prv_keys
        + uncompressed_prv_keys
    ):
        with pytest.raises(ValueError):
            point_from_key(key, "testnet")
            pubkeyinfo_from_key(key, "testnet", compressed=True)
            pubkeyinfo_from_key(key, "testnet", compressed=False)


def test_fingerprint():

    pf = fingerprint(xpub)
    # dict is used to increase code coverage
    child_key = bip32.derive(xpub_dict, b"\x00" * 4)
    pf2 = bip32.deserialize(child_key)["parent_fingerprint"]
    assert pf == pf2
