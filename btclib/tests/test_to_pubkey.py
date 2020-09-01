#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for `btclib.to_pubkey` module."

import pytest

from btclib.curve import CURVES
from btclib.secpoint import bytes_from_point
from btclib.tests.test_to_key import (
    INF,
    INF_xpub_dict,
    Q,
    compressed_prv_keys,
    compressed_pub_keys,
    invalid_prv_keys,
    invalid_pub_keys,
    net_aware_prv_keys,
    net_aware_pub_keys,
    net_unaware_prv_keys,
    net_unaware_pub_keys,
    not_a_pub_keys,
    plain_prv_keys,
    plain_pub_keys,
    q,
    q0,
    qn,
    uncompressed_prv_keys,
    uncompressed_pub_keys,
    xprv0_dict,
    xprv_dict,
    xprvn_dict,
    xpub_dict,
)
from btclib.to_pubkey import (
    point_from_key,
    point_from_pubkey,
    pubkeyinfo_from_key,
    pubkeyinfo_from_pubkey,
)

# FIXME: fix error messages


def test_from_key() -> None:

    secp256r1 = CURVES["secp256r1"]
    m_c = bytes_from_point(Q, compressed=True), "mainnet"
    m_unc = bytes_from_point(Q, compressed=False), "mainnet"
    t_c = bytes_from_point(Q, compressed=True), "testnet"
    t_unc = bytes_from_point(Q, compressed=False), "testnet"
    for pubkey in [Q] + plain_pub_keys:
        assert Q == point_from_pubkey(pubkey)
        with pytest.raises(ValueError):
            point_from_pubkey(pubkey, secp256r1)
        assert m_c == pubkeyinfo_from_pubkey(pubkey)
        assert m_c == pubkeyinfo_from_pubkey(pubkey, "mainnet")
        assert m_c == pubkeyinfo_from_pubkey(pubkey, "mainnet", compressed=True)
        assert m_c == pubkeyinfo_from_pubkey(pubkey, compressed=True)
        assert m_unc == pubkeyinfo_from_pubkey(pubkey, "mainnet", compressed=False)
        assert m_unc == pubkeyinfo_from_pubkey(pubkey, compressed=False)
        assert t_c == pubkeyinfo_from_pubkey(pubkey, "testnet")
        assert t_c == pubkeyinfo_from_pubkey(pubkey, "testnet", compressed=True)
        assert t_unc == pubkeyinfo_from_pubkey(pubkey, "testnet", compressed=False)

    for pubkey in [xpub_dict] + compressed_pub_keys:
        assert Q == point_from_pubkey(pubkey)
        with pytest.raises(ValueError):
            point_from_pubkey(pubkey, secp256r1)
        assert m_c == pubkeyinfo_from_pubkey(pubkey)
        assert m_c == pubkeyinfo_from_pubkey(pubkey, "mainnet")
        assert m_c == pubkeyinfo_from_pubkey(pubkey, "mainnet", compressed=True)
        assert m_c == pubkeyinfo_from_pubkey(pubkey, compressed=True)
        with pytest.raises(ValueError):
            pubkeyinfo_from_pubkey(pubkey, "mainnet", compressed=False)
        with pytest.raises(ValueError):
            pubkeyinfo_from_pubkey(pubkey, compressed=False)
        with pytest.raises(ValueError):
            pubkeyinfo_from_pubkey(pubkey, "testnet", compressed=False)

    for pubkey in uncompressed_pub_keys:
        assert Q == point_from_pubkey(pubkey)
        with pytest.raises(ValueError):
            point_from_pubkey(pubkey, secp256r1)
        assert m_unc == pubkeyinfo_from_pubkey(pubkey)
        assert m_unc == pubkeyinfo_from_pubkey(pubkey, "mainnet")
        with pytest.raises(ValueError):
            pubkeyinfo_from_pubkey(pubkey, "mainnet", compressed=True)
        with pytest.raises(ValueError):
            pubkeyinfo_from_pubkey(pubkey, compressed=True)
        assert m_unc == pubkeyinfo_from_pubkey(pubkey, "mainnet", compressed=False)
        assert m_unc == pubkeyinfo_from_pubkey(pubkey, compressed=False)
        with pytest.raises(ValueError):
            pubkeyinfo_from_pubkey(pubkey, "testnet", compressed=True)

    for pubkey in [xpub_dict] + net_aware_pub_keys:
        assert Q == point_from_pubkey(pubkey)
        with pytest.raises(ValueError):
            point_from_pubkey(pubkey, secp256r1)
        assert pubkeyinfo_from_pubkey(pubkey) in (m_c, m_unc)
        assert pubkeyinfo_from_pubkey(pubkey, "mainnet") in (m_c, m_unc)
        with pytest.raises(ValueError):
            pubkeyinfo_from_pubkey(pubkey, "testnet")

    for pubkey in net_unaware_pub_keys:
        assert Q == point_from_pubkey(pubkey)
        with pytest.raises(ValueError):
            point_from_pubkey(pubkey, secp256r1)
        assert pubkeyinfo_from_pubkey(pubkey) in (m_c, m_unc)
        assert pubkeyinfo_from_pubkey(pubkey, "mainnet") in (m_c, m_unc)
        assert pubkeyinfo_from_pubkey(pubkey, "testnet") in (t_c, t_unc)

    for invalid_pub_key in [INF, INF_xpub_dict] + invalid_pub_keys:
        with pytest.raises(ValueError):
            point_from_pubkey(invalid_pub_key)
        with pytest.raises(ValueError):
            pubkeyinfo_from_pubkey(invalid_pub_key)

    for not_a_pub_key in (
        [INF, INF_xpub_dict]
        + not_a_pub_keys
        + [q, q0, qn]
        + plain_prv_keys
        + [xprv_dict, xprv0_dict, xprvn_dict]
        + compressed_prv_keys
        + uncompressed_prv_keys
    ):
        with pytest.raises(ValueError):
            point_from_pubkey(not_a_pub_key)
        with pytest.raises(ValueError):
            pubkeyinfo_from_pubkey(not_a_pub_key)

    for key in [Q] + plain_pub_keys + [q] + plain_prv_keys:
        assert Q == point_from_key(key)
        assert m_c == pubkeyinfo_from_key(key)
        assert m_c == pubkeyinfo_from_key(key, "mainnet")
        assert m_c == pubkeyinfo_from_key(key, "mainnet", compressed=True)
        assert m_c == pubkeyinfo_from_key(key, compressed=True)
        assert m_unc == pubkeyinfo_from_key(key, "mainnet", compressed=False)
        assert m_unc == pubkeyinfo_from_key(key, compressed=False)
        assert t_c == pubkeyinfo_from_key(key, "testnet")
        assert t_c == pubkeyinfo_from_key(key, "testnet", compressed=True)
        assert t_unc == pubkeyinfo_from_key(key, "testnet", compressed=False)

    for key in compressed_pub_keys + [xpub_dict, xprv_dict] + compressed_prv_keys:
        assert Q == point_from_key(key)
        with pytest.raises(ValueError):
            point_from_key(key, secp256r1)
        assert m_c == pubkeyinfo_from_key(key)
        assert m_c == pubkeyinfo_from_key(key, "mainnet")
        assert m_c == pubkeyinfo_from_key(key, "mainnet", compressed=True)
        assert m_c == pubkeyinfo_from_key(key, compressed=True)
        with pytest.raises(ValueError):
            pubkeyinfo_from_key(key, "mainnet", compressed=False)
        with pytest.raises(ValueError):
            pubkeyinfo_from_key(key, compressed=False)

    for key in uncompressed_pub_keys + uncompressed_prv_keys:
        assert Q == point_from_key(key)
        with pytest.raises(ValueError):
            point_from_key(key, secp256r1)
        assert m_unc == pubkeyinfo_from_key(key)
        assert m_unc == pubkeyinfo_from_key(key, "mainnet")
        with pytest.raises(ValueError):
            pubkeyinfo_from_key(key, "mainnet", compressed=True)
        with pytest.raises(ValueError):
            pubkeyinfo_from_key(key, compressed=True)
        assert m_unc == pubkeyinfo_from_key(key, "mainnet", compressed=False)
        assert m_unc == pubkeyinfo_from_key(key, compressed=False)

    for key in net_aware_pub_keys + [xpub_dict, xprv_dict] + net_aware_prv_keys:
        assert Q == point_from_key(key)
        with pytest.raises(ValueError):
            point_from_key(key, secp256r1)
        assert pubkeyinfo_from_key(key) in (m_c, m_unc)
        assert pubkeyinfo_from_key(key, "mainnet") in (m_c, m_unc)
        with pytest.raises(ValueError):
            pubkeyinfo_from_key(key, "testnet")

    for key in [q] + net_unaware_prv_keys + net_unaware_pub_keys:
        assert Q == point_from_key(key)
        assert pubkeyinfo_from_key(key) in (m_c, m_unc)
        assert pubkeyinfo_from_key(key, "mainnet") in (m_c, m_unc)
        assert pubkeyinfo_from_key(key, "testnet") in (t_c, t_unc)

    for invalid_key in (
        [INF, INF_xpub_dict]
        + invalid_pub_keys
        + [q0, qn, xprv0_dict, xprvn_dict]
        + invalid_prv_keys
    ):
        with pytest.raises(ValueError):
            point_from_key(invalid_key)
        with pytest.raises(ValueError):
            pubkeyinfo_from_key(invalid_key)

    for not_a_key in [
        q0,
        qn,
        xprv0_dict,
        xprvn_dict,
        INF,
        INF_xpub_dict,
    ] + not_a_pub_keys:
        with pytest.raises(ValueError):
            point_from_key(not_a_key)
        with pytest.raises(ValueError):
            pubkeyinfo_from_key(not_a_key)
