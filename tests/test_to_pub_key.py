#!/usr/bin/env python3

# Copyright (C) 2017-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.to_pub_key` module."

import pytest

from btclib.bip32.bip32 import BIP32KeyData, derive, rootxprv_from_seed
from btclib.ecc.curve import CURVES
from btclib.ecc.sec_point import bytes_from_point
from btclib.exceptions import BTClibValueError
from btclib.to_pub_key import (
    fingerprint,
    point_from_key,
    point_from_pub_key,
    pub_keyinfo_from_key,
    pub_keyinfo_from_pub_key,
)
from tests.test_to_key import (
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


def test_from_key() -> None:

    secp256r1 = CURVES["secp256r1"]
    m_c = bytes_from_point(Q, compressed=True), "mainnet"
    m_unc = bytes_from_point(Q, compressed=False), "mainnet"
    t_c = bytes_from_point(Q, compressed=True), "testnet"
    t_unc = bytes_from_point(Q, compressed=False), "testnet"
    for pub_key in [Q, *plain_pub_keys]:
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

    for prv_key2 in [xpub_data, *compressed_pub_keys]:
        assert Q == point_from_pub_key(prv_key2)
        with pytest.raises(BTClibValueError):
            point_from_pub_key(prv_key2, secp256r1)
        assert m_c == pub_keyinfo_from_pub_key(prv_key2)
        assert m_c == pub_keyinfo_from_pub_key(prv_key2, "mainnet")
        assert m_c == pub_keyinfo_from_pub_key(prv_key2, "mainnet", compressed=True)
        assert m_c == pub_keyinfo_from_pub_key(prv_key2, compressed=True)
        with pytest.raises(BTClibValueError):
            pub_keyinfo_from_pub_key(prv_key2, "mainnet", compressed=False)
        with pytest.raises(BTClibValueError):
            pub_keyinfo_from_pub_key(prv_key2, compressed=False)
        with pytest.raises(BTClibValueError):
            pub_keyinfo_from_pub_key(prv_key2, "testnet", compressed=False)

    for prv_key3 in uncompressed_pub_keys:
        assert Q == point_from_pub_key(prv_key3)
        with pytest.raises(BTClibValueError):
            point_from_pub_key(prv_key3, secp256r1)
        assert m_unc == pub_keyinfo_from_pub_key(prv_key3)
        assert m_unc == pub_keyinfo_from_pub_key(prv_key3, "mainnet")
        with pytest.raises(BTClibValueError):
            pub_keyinfo_from_pub_key(prv_key3, "mainnet", compressed=True)
        with pytest.raises(BTClibValueError):
            pub_keyinfo_from_pub_key(prv_key3, compressed=True)
        assert m_unc == pub_keyinfo_from_pub_key(prv_key3, "mainnet", compressed=False)
        assert m_unc == pub_keyinfo_from_pub_key(prv_key3, compressed=False)
        with pytest.raises(BTClibValueError):
            pub_keyinfo_from_pub_key(prv_key3, "testnet", compressed=True)

    for prv_key4 in [xpub_data, *net_aware_pub_keys]:
        assert Q == point_from_pub_key(prv_key4)
        with pytest.raises(BTClibValueError):
            point_from_pub_key(prv_key4, secp256r1)
        assert pub_keyinfo_from_pub_key(prv_key4) in (m_c, m_unc)
        assert pub_keyinfo_from_pub_key(prv_key4, "mainnet") in (m_c, m_unc)
        with pytest.raises(BTClibValueError):
            pub_keyinfo_from_pub_key(prv_key4, "testnet")

    for prv_key5 in net_unaware_pub_keys:
        assert Q == point_from_pub_key(prv_key5)
        with pytest.raises(BTClibValueError):
            point_from_pub_key(prv_key5, secp256r1)
        assert pub_keyinfo_from_pub_key(prv_key5) in (m_c, m_unc)
        assert pub_keyinfo_from_pub_key(prv_key5, "mainnet") in (m_c, m_unc)
        assert pub_keyinfo_from_pub_key(prv_key5, "testnet") in (t_c, t_unc)

    for invalid_pub_key in [INF, INF_xpub_data, *invalid_pub_keys]:
        with pytest.raises(BTClibValueError):
            point_from_pub_key(invalid_pub_key)  # type: ignore
        with pytest.raises(BTClibValueError):
            pub_keyinfo_from_pub_key(invalid_pub_key)  # type: ignore

    for not_a_pub_key in [
        INF,
        INF_xpub_data,
        *not_a_pub_keys,
        q,
        q0,
        qn,
        *plain_prv_keys,
        xprv_data,
        xprv0_data,
        xprvn_data,
        *compressed_prv_keys,
        *uncompressed_prv_keys,
    ]:
        with pytest.raises(BTClibValueError):
            point_from_pub_key(not_a_pub_key)  # type: ignore
        with pytest.raises(BTClibValueError):
            pub_keyinfo_from_pub_key(not_a_pub_key)  # type: ignore

    for key in [Q, *plain_pub_keys, q, *plain_prv_keys]:
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

    for key2 in [*compressed_pub_keys, xpub_data, xprv_data, *compressed_prv_keys]:
        assert Q == point_from_key(key2)
        with pytest.raises(BTClibValueError):
            point_from_key(key2, secp256r1)
        assert m_c == pub_keyinfo_from_key(key2)
        assert m_c == pub_keyinfo_from_key(key2, "mainnet")
        assert m_c == pub_keyinfo_from_key(key2, "mainnet", compressed=True)
        assert m_c == pub_keyinfo_from_key(key2, compressed=True)
        with pytest.raises(BTClibValueError):
            pub_keyinfo_from_key(key2, "mainnet", compressed=False)
        with pytest.raises(BTClibValueError):
            pub_keyinfo_from_key(key2, compressed=False)

    for key3 in [*uncompressed_pub_keys, *uncompressed_prv_keys]:
        assert Q == point_from_key(key3)
        with pytest.raises(BTClibValueError):
            point_from_key(key3, secp256r1)
        assert m_unc == pub_keyinfo_from_key(key3)
        assert m_unc == pub_keyinfo_from_key(key3, "mainnet")
        with pytest.raises(BTClibValueError):
            pub_keyinfo_from_key(key3, "mainnet", compressed=True)
        with pytest.raises(BTClibValueError):
            pub_keyinfo_from_key(key3, compressed=True)
        assert m_unc == pub_keyinfo_from_key(key3, "mainnet", compressed=False)
        assert m_unc == pub_keyinfo_from_key(key3, compressed=False)

    for key4 in [*net_aware_pub_keys, xpub_data, xprv_data, *net_aware_prv_keys]:
        assert Q == point_from_key(key4)
        with pytest.raises(BTClibValueError):
            point_from_key(key4, secp256r1)
        assert pub_keyinfo_from_key(key4) in (m_c, m_unc)
        assert pub_keyinfo_from_key(key4, "mainnet") in (m_c, m_unc)
        with pytest.raises(BTClibValueError):
            pub_keyinfo_from_key(key4, "testnet")

    for key5 in [q, *net_unaware_prv_keys, *net_unaware_pub_keys]:
        assert Q == point_from_key(key5)
        assert pub_keyinfo_from_key(key5) in (m_c, m_unc)
        assert pub_keyinfo_from_key(key5, "mainnet") in (m_c, m_unc)
        assert pub_keyinfo_from_key(key5, "testnet") in (t_c, t_unc)

    for invalid_key in [
        INF,
        INF_xpub_data,
        *invalid_pub_keys,
        q0,
        qn,
        xprv0_data,
        xprvn_data,
        *invalid_prv_keys,
    ]:
        with pytest.raises(BTClibValueError):
            point_from_key(invalid_key)  # type: ignore
        with pytest.raises(BTClibValueError):
            pub_keyinfo_from_key(invalid_key)  # type: ignore

    for not_a_key in [
        q0,
        qn,
        xprv0_data,
        xprvn_data,
        INF,
        INF_xpub_data,
        *not_a_pub_keys,
    ]:
        with pytest.raises(BTClibValueError):
            point_from_key(not_a_key)  # type: ignore
        with pytest.raises(BTClibValueError):
            pub_keyinfo_from_key(not_a_key)  # type: ignore


def test_fingerprint() -> None:
    seed = "bfc4cbaad0ff131aa97fa30a48d09ae7df914bcc083af1e07793cd0a7c61a03f65d622848209ad3366a419f4718a80ec9037df107d8d12c19b83202de00a40ad"
    xprv = rootxprv_from_seed(seed)
    pf = fingerprint(xprv)  # xprv is automatically converted to xpub
    child_key = derive(xprv, 0x80000000)
    pf2 = BIP32KeyData.b58decode(child_key).parent_fingerprint
    assert pf == pf2
