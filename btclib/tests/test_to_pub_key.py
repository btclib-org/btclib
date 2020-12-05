#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.to_pub_key` module."

import pytest

from btclib.curve import CURVES
from btclib.exceptions import BTClibValueError
from btclib.sec_point import bytes_from_point
from btclib.tests.test_to_key import (
    INF,
    INF_xpub_data,
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
    xprv0_data,
    xprv_data,
    xprvn_data,
    xpub_data,
)
from btclib.to_pub_key import (
    point_from_key,
    point_from_pub_key,
    pub_keyinfo_from_key,
    pub_keyinfo_from_pub_key,
)

# FIXME: fix error messages


def test_from_key() -> None:

    secp256r1 = CURVES["secp256r1"]
    m_c = bytes_from_point(Q, compressed=True), "mainnet"
    m_unc = bytes_from_point(Q, compressed=False), "mainnet"
    t_c = bytes_from_point(Q, compressed=True), "testnet"
    t_unc = bytes_from_point(Q, compressed=False), "testnet"
    for pub_key in [Q] + plain_pub_keys:
        assert Q == point_from_pub_key(pub_key)
        with pytest.raises(BTClibValueError):
            point_from_pub_key(pub_key, secp256r1)
        assert m_c == pub_keyinfo_from_pub_key(pub_key)
        assert m_c == pub_keyinfo_from_pub_key(pub_key, "mainnet")
        assert m_c == pub_keyinfo_from_pub_key(pub_key, "mainnet", compressed=True)
        assert m_c == pub_keyinfo_from_pub_key(pub_key, compressed=True)
        assert m_unc == pub_keyinfo_from_pub_key(pub_key, "mainnet", compressed=False)
        assert m_unc == pub_keyinfo_from_pub_key(pub_key, compressed=False)
        assert t_c == pub_keyinfo_from_pub_key(pub_key, "testnet")
        assert t_c == pub_keyinfo_from_pub_key(pub_key, "testnet", compressed=True)
        assert t_unc == pub_keyinfo_from_pub_key(pub_key, "testnet", compressed=False)

    for pub_key in [xpub_data] + compressed_pub_keys:
        assert Q == point_from_pub_key(pub_key)
        with pytest.raises(BTClibValueError):
            point_from_pub_key(pub_key, secp256r1)
        assert m_c == pub_keyinfo_from_pub_key(pub_key)
        assert m_c == pub_keyinfo_from_pub_key(pub_key, "mainnet")
        assert m_c == pub_keyinfo_from_pub_key(pub_key, "mainnet", compressed=True)
        assert m_c == pub_keyinfo_from_pub_key(pub_key, compressed=True)
        with pytest.raises(BTClibValueError):
            pub_keyinfo_from_pub_key(pub_key, "mainnet", compressed=False)
        with pytest.raises(BTClibValueError):
            pub_keyinfo_from_pub_key(pub_key, compressed=False)
        with pytest.raises(BTClibValueError):
            pub_keyinfo_from_pub_key(pub_key, "testnet", compressed=False)

    for pub_key in uncompressed_pub_keys:
        assert Q == point_from_pub_key(pub_key)
        with pytest.raises(BTClibValueError):
            point_from_pub_key(pub_key, secp256r1)
        assert m_unc == pub_keyinfo_from_pub_key(pub_key)
        assert m_unc == pub_keyinfo_from_pub_key(pub_key, "mainnet")
        with pytest.raises(BTClibValueError):
            pub_keyinfo_from_pub_key(pub_key, "mainnet", compressed=True)
        with pytest.raises(BTClibValueError):
            pub_keyinfo_from_pub_key(pub_key, compressed=True)
        assert m_unc == pub_keyinfo_from_pub_key(pub_key, "mainnet", compressed=False)
        assert m_unc == pub_keyinfo_from_pub_key(pub_key, compressed=False)
        with pytest.raises(BTClibValueError):
            pub_keyinfo_from_pub_key(pub_key, "testnet", compressed=True)

    for pub_key in [xpub_data] + net_aware_pub_keys:
        assert Q == point_from_pub_key(pub_key)
        with pytest.raises(BTClibValueError):
            point_from_pub_key(pub_key, secp256r1)
        assert pub_keyinfo_from_pub_key(pub_key) in (m_c, m_unc)
        assert pub_keyinfo_from_pub_key(pub_key, "mainnet") in (m_c, m_unc)
        with pytest.raises(BTClibValueError):
            pub_keyinfo_from_pub_key(pub_key, "testnet")

    for pub_key in net_unaware_pub_keys:
        assert Q == point_from_pub_key(pub_key)
        with pytest.raises(BTClibValueError):
            point_from_pub_key(pub_key, secp256r1)
        assert pub_keyinfo_from_pub_key(pub_key) in (m_c, m_unc)
        assert pub_keyinfo_from_pub_key(pub_key, "mainnet") in (m_c, m_unc)
        assert pub_keyinfo_from_pub_key(pub_key, "testnet") in (t_c, t_unc)

    for invalid_pub_key in [INF, INF_xpub_data] + invalid_pub_keys:
        with pytest.raises(BTClibValueError):
            point_from_pub_key(invalid_pub_key)
        with pytest.raises(BTClibValueError):
            pub_keyinfo_from_pub_key(invalid_pub_key)

    for not_a_pub_key in (
        [INF, INF_xpub_data]
        + not_a_pub_keys
        + [q, q0, qn]
        + plain_prv_keys
        + [xprv_data, xprv0_data, xprvn_data]
        + compressed_prv_keys
        + uncompressed_prv_keys
    ):
        with pytest.raises(BTClibValueError):
            point_from_pub_key(not_a_pub_key)
        with pytest.raises(BTClibValueError):
            pub_keyinfo_from_pub_key(not_a_pub_key)

    for key in [Q] + plain_pub_keys + [q] + plain_prv_keys:
        assert Q == point_from_key(key)
        assert m_c == pub_keyinfo_from_key(key)
        assert m_c == pub_keyinfo_from_key(key, "mainnet")
        assert m_c == pub_keyinfo_from_key(key, "mainnet", compressed=True)
        assert m_c == pub_keyinfo_from_key(key, compressed=True)
        assert m_unc == pub_keyinfo_from_key(key, "mainnet", compressed=False)
        assert m_unc == pub_keyinfo_from_key(key, compressed=False)
        assert t_c == pub_keyinfo_from_key(key, "testnet")
        assert t_c == pub_keyinfo_from_key(key, "testnet", compressed=True)
        assert t_unc == pub_keyinfo_from_key(key, "testnet", compressed=False)

    for key in compressed_pub_keys + [xpub_data, xprv_data] + compressed_prv_keys:
        assert Q == point_from_key(key)
        with pytest.raises(BTClibValueError):
            point_from_key(key, secp256r1)
        assert m_c == pub_keyinfo_from_key(key)
        assert m_c == pub_keyinfo_from_key(key, "mainnet")
        assert m_c == pub_keyinfo_from_key(key, "mainnet", compressed=True)
        assert m_c == pub_keyinfo_from_key(key, compressed=True)
        with pytest.raises(BTClibValueError):
            pub_keyinfo_from_key(key, "mainnet", compressed=False)
        with pytest.raises(BTClibValueError):
            pub_keyinfo_from_key(key, compressed=False)

    for key in uncompressed_pub_keys + uncompressed_prv_keys:
        assert Q == point_from_key(key)
        with pytest.raises(BTClibValueError):
            point_from_key(key, secp256r1)
        assert m_unc == pub_keyinfo_from_key(key)
        assert m_unc == pub_keyinfo_from_key(key, "mainnet")
        with pytest.raises(BTClibValueError):
            pub_keyinfo_from_key(key, "mainnet", compressed=True)
        with pytest.raises(BTClibValueError):
            pub_keyinfo_from_key(key, compressed=True)
        assert m_unc == pub_keyinfo_from_key(key, "mainnet", compressed=False)
        assert m_unc == pub_keyinfo_from_key(key, compressed=False)

    for key in net_aware_pub_keys + [xpub_data, xprv_data] + net_aware_prv_keys:
        assert Q == point_from_key(key)
        with pytest.raises(BTClibValueError):
            point_from_key(key, secp256r1)
        assert pub_keyinfo_from_key(key) in (m_c, m_unc)
        assert pub_keyinfo_from_key(key, "mainnet") in (m_c, m_unc)
        with pytest.raises(BTClibValueError):
            pub_keyinfo_from_key(key, "testnet")

    for key in [q] + net_unaware_prv_keys + net_unaware_pub_keys:
        assert Q == point_from_key(key)
        assert pub_keyinfo_from_key(key) in (m_c, m_unc)
        assert pub_keyinfo_from_key(key, "mainnet") in (m_c, m_unc)
        assert pub_keyinfo_from_key(key, "testnet") in (t_c, t_unc)

    for invalid_key in (
        [INF, INF_xpub_data]
        + invalid_pub_keys
        + [q0, qn, xprv0_data, xprvn_data]
        + invalid_prv_keys
    ):
        with pytest.raises(BTClibValueError):
            point_from_key(invalid_key)
        with pytest.raises(BTClibValueError):
            pub_keyinfo_from_key(invalid_key)

    for not_a_key in [
        q0,
        qn,
        xprv0_data,
        xprvn_data,
        INF,
        INF_xpub_data,
    ] + not_a_pub_keys:
        with pytest.raises(BTClibValueError):
            point_from_key(not_a_key)
        with pytest.raises(BTClibValueError):
            pub_keyinfo_from_key(not_a_key)
